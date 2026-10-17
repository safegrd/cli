package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/runner"
	"github.com/safegrd/cli/pkg/storage"
)

// queryTimeout bounds the query itself, not the restore before it.
const queryTimeout = 5 * time.Minute

// queryKeptFor is how long --keep leaves a cluster the run started.
const queryKeptFor = 24 * time.Hour

// verifyQueryRun is `verify --query`: restore a database snapshot into a
// sandbox, run one read-only query there, and write its rows as CSV. It is a
// person reading rows out of a backup, so it reports no drill, and stdout
// carries the CSV alone; everything else goes to stderr.
type verifyQueryRun struct {
	snapshotID, key, sandboxURL, query, out string
	keep                                    bool
}

func (q verifyQueryRun) archive(ctx context.Context, provider storage.StorageProvider) error {
	sandbox, done, err := q.sandbox(ctx, provider, nil)
	if err != nil {
		return err
	}
	defer done()
	v := q.verifier(provider)
	fmt.Fprintf(os.Stderr, "Restoring %s into %s to run the query.\n", q.snapshotID, dump.RedactURL(sandbox))
	report, err := v.RunFireDrill(ctx, q.snapshotID, q.key, sandbox)
	if err != nil {
		return fmt.Errorf("restore of %s: %w", q.snapshotID, err)
	}
	return q.read(ctx, sandbox, report)
}

func (q verifyQueryRun) repo(ctx context.Context, rs *repoSnapshot) error {
	sandbox, done, err := q.sandbox(ctx, nil, rs.Meta)
	if err != nil {
		return err
	}
	defer done()
	v := q.verifier(nil)
	fmt.Fprintf(os.Stderr, "Restoring %s (epoch %s) into %s to run the query.\n", q.snapshotID, rs.Epoch.Epoch.EpochID, dump.RedactURL(sandbox))
	report, err := v.RunRepoDatabaseDrill(ctx, runner.RepoDrill{Backend: rs.Backend, Epoch: rs.Epoch, Meta: rs.Meta}, q.key, sandbox)
	if err != nil {
		return fmt.Errorf("restore of %s: %w", q.snapshotID, err)
	}
	return q.read(ctx, sandbox, report)
}

func (q verifyQueryRun) verifier(provider storage.StorageProvider) *runner.Verifier {
	v := runner.NewVerifier(provider, cfg.ServerURL)
	v.Unreported = true
	if cfg.ServerToken != "" {
		// For the remote server's record of the snapshot, which the restore
		// is checked against. The run sends no report.
		v.SetServerToken(cfg.ServerToken)
	}
	return v
}

// sandbox is --sandbox-target, or a PostgreSQL cluster started on this host
// for the run. done stops that cluster, or keeps it with --keep.
func (q verifyQueryRun) sandbox(ctx context.Context, provider storage.StorageProvider, known *model.SnapshotMetadata) (string, func(), error) {
	if q.sandboxURL != "" {
		return q.sandboxURL, func() {
			fmt.Fprintf(os.Stderr, "The sandbox at %s holds the restore. Empty it before the next drill into it.\n", dump.RedactURL(q.sandboxURL))
		}, nil
	}
	lp, _, err := startLocalSandbox(ctx, provider, q.snapshotID, known, resolveStateDir("", cfg))
	if err != nil {
		return "", nil, fmt.Errorf("could not start a PostgreSQL cluster on this host for the query: %w. Pass --sandbox-target with an empty database instead", err)
	}
	if lp == nil {
		return "", nil, fmt.Errorf("snapshot %s is not a PostgreSQL backup, so this host cannot start a sandbox for it. Pass --sandbox-target with an empty database of the same kind", q.snapshotID)
	}
	return lp.URL, func() {
		if !q.keep {
			lp.Stop()
			return
		}
		until := time.Now().Add(queryKeptFor)
		if err := lp.Keep(until); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not mark the sandbox as kept (%v); removing it.\n", err)
			lp.Stop()
			return
		}
		fmt.Fprintf(os.Stderr, "Kept the sandbox until %s: psql %q\n", until.UTC().Format("2006-01-02 15:04 UTC"), lp.URL)
	}, nil
}

// read runs the query and writes the CSV. A restore whose checks failed is
// still read, since the rows may be what the person needs, and the command
// then exits non-zero.
func (q verifyQueryRun) read(ctx context.Context, sandbox string, report *model.VerificationReport) error {
	failed := report.Status != model.VerificationStatusPassed
	if failed {
		for _, a := range report.Assertions {
			if !a.Passed {
				fmt.Fprintf(os.Stderr, "Warning: %s: %s (expected %s, got %s)\n", a.Name, a.Message, a.Expected, a.Actual)
			}
		}
		fmt.Fprintf(os.Stderr, "Warning: the restore of %s did not match its manifest: %s. The rows below come from what was restored.\n", q.snapshotID, report.ErrorMessage)
	}
	var w io.Writer = os.Stdout
	var f *os.File
	if q.out != "" {
		var err error
		f, err = os.OpenFile(q.out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("cannot write %s: %w", q.out, err)
		}
		w = f
	}
	n, err := runner.QueryToCSV(ctx, sandbox, q.query, queryTimeout, w)
	if f != nil {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		return fmt.Errorf("the query failed: %w", err)
	}
	if q.out != "" {
		fmt.Fprintf(os.Stderr, "Wrote %d %s from %s to %s.\n", n, pluralWord(n, "row", "rows"), q.snapshotID, q.out)
	} else {
		fmt.Fprintf(os.Stderr, "Read %d %s from %s.\n", n, pluralWord(n, "row", "rows"), q.snapshotID)
	}
	if failed {
		return fmt.Errorf("the restore of %s did not match its manifest: %s", q.snapshotID, report.ErrorMessage)
	}
	return nil
}
