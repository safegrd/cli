package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/check"
	"github.com/safegrd/cli/pkg/repo/larun"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/unseal"
)

// IsRepoLaravel reports whether a repository snapshot is a Laravel app.
func IsRepoLaravel(meta *model.SnapshotMetadata) bool {
	return meta != nil && meta.SurfaceType == model.SurfaceTypeLaravel
}

// inspectLaravelDatabase runs the drill of the engine the app's database is
// on over its archive.
func inspectLaravelDatabase(ctx context.Context, connection string, src io.Reader) (*dump.DryRestoreResult, error) {
	switch connection {
	case "mysql", "mariadb":
		return dump.InspectMySQLArchive(ctx, src)
	case "sqlite":
		return dump.InspectSQLiteArchive(ctx, src)
	case "pgsql":
		return dump.NewDryRestorer().InspectArchive(ctx, src)
	}
	return nil, fmt.Errorf("the snapshot records connection %q, which is not mysql, mariadb, pgsql or sqlite", connection)
}

// RunRepoLaravelDrill proves a Laravel app's snapshot restores, in memory:
//
//  1. every pack the snapshot names is present and agrees with its index;
//  2. the content root recomputed from its trees is the one recorded at
//     backup time, by the remote server when it can be asked;
//  3. the database passes its engine's drill;
//  4. every file reads back and matches its SHA-256;
//  5. the sealed .env holds an APP_KEY Laravel's encrypter takes, and the
//     dumped migrations table agrees with the migration files.
func (v *Verifier) RunRepoLaravelDrill(ctx context.Context, d RepoDrill, privateKey string) (*model.VerificationReport, error) {
	started := time.Now()
	meta := d.Meta
	report := &model.VerificationReport{
		VerificationID: "verif-dry-" + uuid.New().String()[:8],
		SnapshotID:     meta.SnapshotID,
		NodeID:         meta.NodeID,
		SurfaceType:    model.SurfaceTypeLaravel,
		DatabaseName:   meta.DatabaseName,
		StartedAt:      started,
		SandboxEngine:  "in-memory-dry-restore",
		Status:         model.VerificationStatusRunning,
	}
	fail := func(name, expected, actual, msg string) (*model.VerificationReport, error) {
		report.Assertions = append(report.Assertions, model.AssertionResult{Name: name, Passed: false, Expected: expected, Actual: actual, Message: msg})
		v.failEarly(ctx, report, started, msg)
		return report, nil
	}
	pass := func(name, expected, actual, msg string) {
		report.Assertions = append(report.Assertions, model.AssertionResult{Name: name, Passed: true, Expected: expected, Actual: actual, Message: msg})
	}

	ids, err := unseal.Identities(privateKey)
	if err != nil {
		return fail("DecryptionIntegrity", "a usable age identity", err.Error(), err.Error())
	}
	rep, err := check.Snapshot(ctx, d.Backend, d.Epoch, meta.SnapshotID, ids, check.Options{})
	if err != nil {
		return fail("RepositoryIntegrity", "every pack present and agreeing with its index", err.Error(), "the repository could not be read: "+err.Error())
	}
	if !rep.OK() {
		return fail("RepositoryIntegrity", "every pack present and agreeing with its index", rep.Problems[0], rep.Err().Error())
	}
	pass("DecryptionIntegrity", "the snapshot, its indexes and trees open with the identity", "they do", "")
	pass("RepositoryIntegrity", "every pack present and agreeing with its index",
		fmt.Sprintf("%d packs checked", rep.Packs), "Every pack the snapshot names is in storage, and its trailer agrees with the index")

	r := read.Open(d.Backend, d.Epoch, ids)
	snap, err := r.Snapshot(ctx, meta.SnapshotID)
	if err != nil {
		return fail("RestoreIntegrity", "the snapshot reads", err.Error(), err.Error())
	}
	idx, err := r.LoadIndex(ctx, snap)
	if err != nil {
		return fail("RestoreIntegrity", "the snapshot reads", err.Error(), err.Error())
	}
	root, _, err := r.ContentRoot(ctx, idx, snap)
	if err != nil {
		return fail("DigestIntegrity", "a content root from the snapshot's trees", err.Error(), err.Error())
	}
	rec := v.fetchRecord(ctx, meta.SnapshotID)
	expected, source := meta.Sha256Checksum, "backup manifest (sidecar)"
	if rec.record != nil {
		expected, source = rec.record.Sha256Checksum, "remote server record"
	}
	if expected == "" {
		return fail("DigestIntegrity", "a recorded content root", root,
			"no content root is recorded for this snapshot anywhere this run could consult ("+rec.why+"), so it cannot be verified")
	}
	if root != expected {
		return fail("DigestIntegrity", expected, root, "The content root of the snapshot does not match the "+source)
	}
	if rec.record != nil && meta.Sha256Checksum != rec.record.Sha256Checksum {
		return fail("RemoteServerRecord", rec.record.Sha256Checksum, meta.Sha256Checksum,
			fmt.Sprintf("the sidecar's content root (%s) is not the one the remote server recorded at backup time (%s): the sidecar at the sink has been changed",
				meta.Sha256Checksum, rec.record.Sha256Checksum))
	}
	if rec.record == nil {
		fmt.Fprintf(os.Stderr, "\nWarning: content root checked against the sidecar only: %s.\n"+
			"    It was not compared with SafeGrd's record from backup time; run this on an enrolled host to compare.\n", rec.why)
	}

	run, err := larun.Files(ctx, r, idx, snap)
	if err != nil {
		return fail("RestoreIntegrity", "a Laravel app", err.Error(), err.Error())
	}
	// The app's facts come from the snapshot's own manifest, which the
	// content root covers, not from the sidecar beside it.
	inner, err := larun.ReadManifest(ctx, r, idx, run)
	if err != nil {
		return fail("RestoreIntegrity", "the snapshot's manifest", err.Error(), err.Error())
	}
	if inner.Laravel == nil {
		return fail("RestoreIntegrity", "a manifest describing a Laravel app", "no laravel section", "the snapshot's manifest does not describe a Laravel app")
	}

	pr, pw := io.Pipe()
	archived := make(chan error, 1)
	go func() {
		err := larun.DatabaseArchive(ctx, r, idx, run, pw)
		_ = pw.CloseWithError(err)
		archived <- err
	}()
	db, inspectErr := inspectLaravelDatabase(ctx, inner.Laravel.Connection, pr)
	_, _ = io.Copy(io.Discard, pr) // every file is read to its end and checked before a result counts
	if err := <-archived; err != nil {
		return fail("RestoreIntegrity", "every file of the database matches its SHA-256", err.Error(), "the database could not be read back: "+err.Error())
	}
	if inspectErr != nil {
		return fail("RestoreIntegrity", "the database restores in memory", inspectErr.Error(), "dry restore archive inspection error: "+inspectErr.Error())
	}

	var fileBytes int64
	for _, it := range run.Files {
		if err := r.Cat(ctx, idx, it.Node, io.Discard); err != nil {
			return fail("FileIntegrity", "every file matches its SHA-256", err.Error(), fmt.Sprintf("%s could not be read back: %v", it.Path, err))
		}
		fileBytes += it.Node.Size
	}
	pass("DigestIntegrity", expected, root, "Every file matched its SHA-256, and the content root matches the "+source)
	pass("FileIntegrity", "every file matches its SHA-256", fmt.Sprintf("%d files, %d bytes", len(run.Files), fileBytes),
		"Every file of the app read back and matched its SHA-256")

	var env []byte
	if run.Env != nil {
		if env, err = larun.ReadFile(ctx, r, idx, *run.Env); err != nil {
			return fail("AppKey", "files/.env reads back", err.Error(), err.Error())
		}
	}
	report.Assertions = append(report.Assertions, db.Assertions...)
	report.Assertions = append(report.Assertions, dump.LaravelAssertions(inner.Laravel, db, env, run.Migrations)...)
	report.TotalItems, report.TotalContainers = db.TotalRows, db.TotalTables
	report.TablesRestored, report.RowsRestored = db.TotalTables, db.TotalRows
	report.CompletedAt = time.Now()
	report.DurationMs = drillMilliseconds(report.CompletedAt.Sub(started))
	passed := db.Passed
	for _, a := range report.Assertions {
		if !a.Passed {
			passed = false
			if report.ErrorMessage == "" {
				report.ErrorMessage = a.Message
			}
		}
	}
	if passed {
		report.Status = model.VerificationStatusPassed
		report.CertificateHash = computeCertificateHash(report)
	} else {
		report.Status = model.VerificationStatusFailed
		if report.ErrorMessage == "" {
			report.ErrorMessage = db.ErrorMessage
		}
		if report.ErrorMessage == "" {
			report.ErrorMessage = "One or more assertions failed during in-memory dry restore"
		}
	}
	attachReadKeys(report, d.Backend)
	v.submitReport(ctx, report)
	return report, nil
}
