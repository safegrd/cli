package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/safegrd/cli/pkg/diskspace"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/check"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/unseal"
)

// RepoDrill is what RunRepoDrill needs to find a repository snapshot.
type RepoDrill struct {
	Backend sink.Backend
	Epoch   sink.EpochInfo
	// Meta is the snapshot's sidecar.
	Meta *model.SnapshotMetadata
	// Scratch is a directory the restore may fill and that is removed
	// afterwards; empty means a temporary directory.
	Scratch string
}

// RunRepoDrill proves a snapshot of an incremental repository restores:
//
//  1. every pack the snapshot names is present and agrees with its index;
//  2. the whole snapshot restores into a scratch directory, every file
//     checked against its SHA-256;
//  3. the content root is recomputed from the restored files on disk, by
//     code that shares nothing with the restore but the line format;
//  4. that root is compared with the one recorded at backup time, by the
//     remote server when it can be asked.
//
// It dispatches on the snapshot's format before any ciphertext digest is
// looked at: a repository snapshot has no single ciphertext, so its empty
// EncryptedSha256 means neither a legacy snapshot nor a tampered one.
func (v *Verifier) RunRepoDrill(ctx context.Context, d RepoDrill, privateKey string) (*model.VerificationReport, error) {
	started := time.Now()
	meta := d.Meta
	// The restore writes the whole tree to this host's disk before deleting
	// it. Checked before anything is restored or reported: a disk that
	// cannot hold the tree says nothing about the backup.
	scratchParent := d.Scratch
	if scratchParent == "" {
		scratchParent = os.TempDir()
	}
	if err := diskspace.CheckFreeSpace(scratchParent, RepoRestoreBytes(meta), "a Fire Drill of "+meta.SnapshotID+", which restores every file",
		"free some space, or set daemon.state_dir on a larger disk"); err != nil {
		if d.Scratch != "" {
			_ = os.RemoveAll(d.Scratch)
		}
		return nil, &DrillBlockedError{Err: err}
	}
	report := &model.VerificationReport{
		VerificationID: "verif-dry-" + uuid.New().String()[:8],
		SnapshotID:     meta.SnapshotID,
		NodeID:         meta.NodeID,
		SurfaceType:    model.SurfaceTypeFiles,
		StartedAt:      started,
		SandboxEngine:  "repository-restore",
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

	scratch := d.Scratch
	if scratch == "" {
		if scratch, err = os.MkdirTemp("", "safegrd-drill-"); err != nil {
			return fail("RestoreIntegrity", "a scratch directory", err.Error(), "no scratch directory for the restore: "+err.Error())
		}
	}
	defer os.RemoveAll(scratch)
	target := filepath.Join(scratch, "restore")
	r := read.Open(d.Backend, d.Epoch, ids)
	snap, err := r.Snapshot(ctx, meta.SnapshotID)
	if err != nil {
		return fail("RestoreIntegrity", "the whole snapshot restores", err.Error(), err.Error())
	}
	idx, err := r.LoadIndex(ctx, snap)
	if err != nil {
		return fail("RestoreIntegrity", "the whole snapshot restores", err.Error(), err.Error())
	}
	res, err := r.Restore(ctx, snap, idx, read.RestoreOptions{Target: target})
	if err != nil {
		return fail("RestoreIntegrity", "the whole snapshot restores", err.Error(), "the restore failed: "+err.Error())
	}
	pass("RestoreIntegrity", fmt.Sprintf("%d files", snap.Stats.Files), fmt.Sprintf("%d files, %d bytes", res.Files, res.Bytes),
		"Every file restored and matched its SHA-256")

	root, files, err := check.DirContentRoot(target)
	if err != nil {
		return fail("DigestIntegrity", "a content root from the restored files", err.Error(), "the restored files could not be read back: "+err.Error())
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
		return fail("DigestIntegrity", expected, root, "The content root of the restored files does not match the "+source)
	}
	pass("DigestIntegrity", expected, root, "The content root of the restored files matches the "+source+" exactly")
	if rec.record == nil {
		fmt.Fprintf(os.Stderr, "\n[!] Content root checked against the sidecar only: %s.\n"+
			"    It was not compared with SafeGrd's record from backup time; run this on an enrolled host to compare.\n", rec.why)
	} else if meta.Sha256Checksum != rec.record.Sha256Checksum {
		return fail("RemoteServerRecord", rec.record.Sha256Checksum, meta.Sha256Checksum,
			fmt.Sprintf("the sidecar's content root (%s) is not the one the remote server recorded at backup time (%s): the sidecar at the sink has been changed",
				meta.Sha256Checksum, rec.record.Sha256Checksum))
	} else {
		pass("RemoteServerRecord", rec.record.Sha256Checksum, root, "Sidecar and restored files match the content root recorded at backup time")
	}
	if meta.TotalItems > 0 && files != meta.TotalItems {
		return fail("FileCount", fmt.Sprint(meta.TotalItems), fmt.Sprint(files), "The restore holds a different number of files than the backup recorded")
	}
	pass("FileCount", fmt.Sprint(meta.TotalItems), fmt.Sprint(files), "")

	report.CompletedAt = time.Now()
	report.DurationMs = drillMilliseconds(report.CompletedAt.Sub(started))
	report.TotalItems, report.RowsRestored = files, files
	report.TotalContainers = int(res.Dirs)
	report.TablesRestored = int(res.Dirs)
	report.Status = model.VerificationStatusPassed
	report.CertificateHash = computeCertificateHash(report)
	v.submitReport(ctx, report)
	return report, nil
}

// RepoRestoreBytes is the disk a full restore of meta takes: the files'
// logical size, a tenth again, and a block for each file, which a tree of
// small files spends more on than on their contents.
func RepoRestoreBytes(meta *model.SnapshotMetadata) int64 {
	return meta.RawSizeBytes + meta.RawSizeBytes/10 + meta.TotalItems*4096
}

// DrillBlockedError is a drill this host cannot run, for a reason that says
// nothing about the backup, such as not enough disk. No report is sent: the
// daemon tells the remote server through its heartbeat instead.
type DrillBlockedError struct{ Err error }

func (e *DrillBlockedError) Error() string { return e.Err.Error() }
func (e *DrillBlockedError) Unwrap() error { return e.Err }
