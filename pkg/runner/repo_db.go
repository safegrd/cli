package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/safegrd/cli/pkg/diskspace"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/check"
	"github.com/safegrd/cli/pkg/repo/dbrun"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/unseal"
)

// IsRepoDatabase reports whether a repository snapshot is a database run.
func IsRepoDatabase(meta *model.SnapshotMetadata) bool {
	return meta != nil && meta.SurfaceType != "" && meta.SurfaceType.IsDatabase()
}

// RunRepoDatabaseDrill proves a database run of a repository restores:
//
//  1. every pack the run names is present and agrees with its index;
//  2. the content root recomputed from the run's trees is the one recorded
//     at backup time, by the remote server when it can be asked;
//  3. the run is read back as the archive a restore loads, every file
//     checked against its SHA-256 on the way;
//  4. that archive is restored: in memory when sandboxURL is empty, or into
//     the empty database sandboxURL names, and held to the manifest's tables
//     and row counts. A SQLite run's database is written out and opened by
//     the SQLite engine either way, as an archive's drill does.
func (v *Verifier) RunRepoDatabaseDrill(ctx context.Context, d RepoDrill, privateKey, sandboxURL string) (*model.VerificationReport, error) {
	started := time.Now()
	v.sandboxDrill = sandboxURL != ""
	meta := d.Meta
	kind := meta.SurfaceType
	if kind != model.SurfaceTypeSQLite {
		kind = model.SurfaceTypePostgres
	}
	if sandboxURL != "" {
		if dump.SurfaceTypeOfURL(sandboxURL) != kind {
			return nil, fmt.Errorf("snapshot %s is a %s snapshot; its sandbox must be a %s database too", meta.SnapshotID, kind, kind)
		}
		if err := CheckSandboxEmpty(ctx, sandboxURL); err != nil {
			return nil, err
		}
	}
	// A SQLite drill writes the database out and opens it, in the system
	// temporary directory, as an archive's does.
	if kind == model.SurfaceTypeSQLite && sandboxURL == "" {
		if err := diskspace.CheckFreeSpace(os.TempDir(), meta.RawSizeBytes, "a Fire Drill of "+meta.SnapshotID+", which writes the database out",
			"free some space, or set TMPDIR to a larger disk"); err != nil {
			return nil, &DrillBlockedError{Err: err}
		}
	}
	report := &model.VerificationReport{
		VerificationID: "verif-dry-" + uuid.New().String()[:8],
		SnapshotID:     meta.SnapshotID,
		NodeID:         meta.NodeID,
		SurfaceType:    kind,
		DatabaseName:   meta.DatabaseName,
		StartedAt:      started,
		SandboxEngine:  "in-memory-dry-restore",
		Status:         model.VerificationStatusRunning,
	}
	if sandboxURL != "" {
		report.VerificationID = "verif-" + uuid.New().String()[:8]
		report.SandboxEngine = "ephemeral-" + string(kind) + "-sandbox"
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
	pass("DecryptionIntegrity", "the run, its indexes and trees open with the identity", "they do", "")
	pass("RepositoryIntegrity", "every pack present and agreeing with its index",
		fmt.Sprintf("%d packs checked", rep.Packs), "Every pack the run names is in storage, and its trailer agrees with the index")

	r := read.Open(d.Backend, d.Epoch, ids)
	snap, err := r.Snapshot(ctx, meta.SnapshotID)
	if err != nil {
		return fail("RestoreIntegrity", "the run reads", err.Error(), err.Error())
	}
	idx, err := r.LoadIndex(ctx, snap)
	if err != nil {
		return fail("RestoreIntegrity", "the run reads", err.Error(), err.Error())
	}
	root, _, err := r.ContentRoot(ctx, idx, snap)
	if err != nil {
		return fail("DigestIntegrity", "a content root from the run's trees", err.Error(), err.Error())
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
		return fail("DigestIntegrity", expected, root, "The content root of the run does not match the "+source)
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

	files, err := dbrun.Files(ctx, r, idx, snap)
	if err != nil {
		return fail("RestoreIntegrity", "a database run", err.Error(), err.Error())
	}
	pr, pw := io.Pipe()
	archived := make(chan error, 1)
	go func() {
		err := dbrun.Archive(ctx, r, idx, files, pw)
		_ = pw.CloseWithError(err)
		archived <- err
	}()
	// Every file is read to its end and checked before a result counts.
	drain := func() error {
		_, _ = io.Copy(io.Discard, pr)
		return <-archived
	}

	if sandboxURL == "" {
		var res *dump.DryRestoreResult
		var inspectErr error
		if kind == model.SurfaceTypeSQLite {
			res, inspectErr = dump.InspectSQLiteArchive(ctx, pr)
		} else {
			res, inspectErr = dump.NewDryRestorer().InspectArchive(ctx, pr)
		}
		if err := drain(); err != nil {
			return fail("RestoreIntegrity", "every file of the run matches its SHA-256", err.Error(), "the run could not be read back: "+err.Error())
		}
		pass("DigestIntegrity", expected, root, "Every file matched its SHA-256, and the content root matches the "+source)
		if inspectErr != nil {
			return fail("RestoreIntegrity", "the run restores in memory", inspectErr.Error(), "dry restore archive inspection error: "+inspectErr.Error())
		}
		report.TotalItems, report.TotalContainers = res.TotalRows, res.TotalTables
		report.TablesRestored, report.RowsRestored = res.TotalTables, res.TotalRows
		report.ExtensionsBooted = res.Extensions
		report.Assertions = append(report.Assertions, res.Assertions...)
		report.CompletedAt = time.Now()
		report.DurationMs = drillMilliseconds(report.CompletedAt.Sub(started))
		if res.Passed {
			report.Status = model.VerificationStatusPassed
			report.CertificateHash = computeCertificateHash(report)
		} else {
			report.Status = model.VerificationStatusFailed
			report.ErrorMessage = res.ErrorMessage
			if report.ErrorMessage == "" {
				report.ErrorMessage = "One or more assertions failed during in-memory dry restore"
			}
		}
		v.submitReport(ctx, report)
		return report, nil
	}

	var archiveErr, restoreErr error
	drained := false
	if kind == model.SurfaceTypeSQLite {
		// The SQLite restorer reads the archive to its end before it puts
		// the file in place.
		_, restoreErr = dump.NewSQLiteRestorer(sandboxURL).Restore(ctx, pr)
	} else {
		restorer := dump.NewNativeRestorer(sandboxURL)
		restorer.BeforeCommit = func() error {
			drained = true
			archiveErr = drain()
			return archiveErr
		}
		v.createdRoles = nil
		_, restoreErr = restorer.Restore(ctx, pr)
		v.createdRoles = restorer.CreatedRoles
	}
	if !drained {
		archiveErr = drain()
	}
	if archiveErr != nil {
		return fail("RestoreIntegrity", "every file of the run matches its SHA-256", archiveErr.Error(), "the run could not be read back: "+archiveErr.Error())
	}
	pass("DigestIntegrity", expected, root, "Every file matched its SHA-256, and the content root matches the "+source)
	if restoreErr != nil {
		return fail("RestoreIntegrity", "the run restores into the sandbox", restoreErr.Error(), "restore execution failed: "+restoreErr.Error())
	}
	restored, err := inspectSandbox(ctx, sandboxURL, meta)
	if err != nil {
		return fail("RestoreIntegrity", "the sandbox can be counted", err.Error(), "sandbox inspection failed: "+err.Error())
	}
	allPassed := sandboxAssertions(report, meta, restored)
	failedChecks := v.runChecks(ctx, report, sandboxURL)
	report.CompletedAt = time.Now()
	report.DurationMs = drillMilliseconds(report.CompletedAt.Sub(started))
	if allPassed && len(failedChecks) == 0 {
		report.Status = model.VerificationStatusPassed
		report.CertificateHash = computeCertificateHash(report)
	} else {
		report.Status = model.VerificationStatusFailed
		report.ErrorMessage = drillFailureMessage(allPassed, failedChecks, len(v.Checks))
	}
	v.submitReport(ctx, report)
	return report, nil
}
