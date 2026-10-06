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
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/unseal"
	"github.com/safegrd/cli/pkg/repo/wprun"
)

// IsRepoWordPress reports whether a repository snapshot is a WordPress site.
func IsRepoWordPress(meta *model.SnapshotMetadata) bool {
	return meta != nil && meta.SurfaceType == model.SurfaceTypeWordPress
}

// RunRepoWordPressDrill proves a WordPress site's snapshot restores, in
// memory, with nothing written to disk however large the site:
//
//  1. every pack the snapshot names is present and agrees with its index;
//  2. the content root recomputed from its trees is the one recorded at
//     backup time, by the remote server when it can be asked;
//  3. the site is read back as its archive, every file checked against its
//     SHA-256 on the way, and inspected as one thing: the dump complete with
//     every table's rows, every file present, and every attachment the
//     database names among the files.
func (v *Verifier) RunRepoWordPressDrill(ctx context.Context, d RepoDrill, privateKey string) (*model.VerificationReport, error) {
	started := time.Now()
	meta := d.Meta
	report := &model.VerificationReport{
		VerificationID: "verif-dry-" + uuid.New().String()[:8],
		SnapshotID:     meta.SnapshotID,
		NodeID:         meta.NodeID,
		SurfaceType:    model.SurfaceTypeWordPress,
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

	run, err := wprun.Files(ctx, r, idx, snap)
	if err != nil {
		return fail("RestoreIntegrity", "a WordPress site", err.Error(), err.Error())
	}
	pr, pw := io.Pipe()
	archived := make(chan error, 1)
	go func() {
		err := wprun.Archive(ctx, r, idx, run, pw)
		_ = pw.CloseWithError(err)
		archived <- err
	}()
	res, inspectErr := dump.InspectWordPressArchive(ctx, pr)
	_, _ = io.Copy(io.Discard, pr) // every file is read to its end and checked before a result counts
	if err := <-archived; err != nil {
		return fail("RestoreIntegrity", "every file of the snapshot matches its SHA-256", err.Error(), "the snapshot could not be read back: "+err.Error())
	}
	pass("DigestIntegrity", expected, root, "Every file matched its SHA-256, and the content root matches the "+source)
	if inspectErr != nil {
		return fail("RestoreIntegrity", "the site restores in memory", inspectErr.Error(), "dry restore archive inspection error: "+inspectErr.Error())
	}
	report.TotalItems, report.TotalContainers = res.TotalRows, res.TotalTables
	report.TablesRestored, report.RowsRestored = res.TotalTables, res.TotalRows
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
