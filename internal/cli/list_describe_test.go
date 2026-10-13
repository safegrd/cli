package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// `list` must describe a snapshot in the vocabulary of its own surface, and the
// numbers must come from the fields the backup path actually wrote.
//
// This test asserts that CalculateTotals populates surface-appropriate
// totals and that list describes files, email, and databases correctly.
func TestListDescribesEachSurfaceFromTheFieldsBackupWrote(t *testing.T) {
	for _, tc := range []struct {
		name string
		meta *model.SnapshotMetadata
		want string
	}{
		{
			name: "files",
			meta: &model.SnapshotMetadata{
				SurfaceType: model.SurfaceTypeFiles,
				FileStats:   &model.FileStatsSummary{TotalFiles: 2, TotalDirectories: 3},
			},
			want: "2 files, 3 dirs",
		},
		{
			name: "email",
			meta: &model.SnapshotMetadata{
				SurfaceType: model.SurfaceTypeEmail,
				EmailStats:  &model.EmailStatsSummary{TotalEmails: 512, TotalFolders: 7},
			},
			want: "512 emails, 7 folders",
		},
		{
			name: "postgres",
			meta: &model.SnapshotMetadata{
				SurfaceType: model.SurfaceTypePostgres,
				TableStats: []model.TableStat{
					{TableName: "users", RowCount: 1200},
					{TableName: "orders", RowCount: 4},
				},
			},
			want: "1204 rows, 2 tables",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.meta.CalculateTotals()

			got := describeContents(tc.meta)
			if got != tc.want {
				t.Errorf("describeContents = %q, want %q", got, tc.want)
			}
			if strings.HasPrefix(got, "0 ") {
				t.Errorf("a snapshot with contents was described as empty: %q", got)
			}
		})
	}
}

// The two reasons a snapshot cannot be described are different problems and
// were previously printed as the same six words. An absent sidecar is a
// snapshot written before it existed, or one whose UploadMetadata failed
// quietly; an unreadable one is a sink that will not answer.
func TestAnAbsentSidecarAndAnUnreachableOneAreNotTheSameMessage(t *testing.T) {
	absent := describeMissingMetadata(fmt.Errorf("metadata for snapshot snap-1 not found: %w", os.ErrNotExist))
	if absent != "no metadata sidecar" {
		t.Errorf("an absent sidecar reads as %q", absent)
	}

	unreadable := describeMissingMetadata(errors.New("dial tcp: connection refused"))
	if unreadable == absent {
		t.Fatal("a sink that will not answer is reported as an absent sidecar")
	}
	if !strings.Contains(unreadable, "connection refused") {
		t.Errorf("the cause is not in the message: %q", unreadable)
	}
}

// A sidecar written before the mode was recorded must not have a guess
// presented as a fact: it falls back to the config's mode and says so.
func TestDescribeRetentionNeverPrintsADateOverAnUnretainedSnapshot(t *testing.T) {
	until := time.Date(2026, 10, 21, 16, 1, 0, 0, time.UTC)
	none := config.StorageConfig{WORMMode: config.WORMModeNone}
	locked := config.StorageConfig{WORMMode: config.WORMModeCompliance}

	for _, tc := range []struct {
		name string
		mode string
		cfg  config.StorageConfig
		want string
	}{
		{"recorded NONE", "NONE", locked, "none (deletable)"},
		{"recorded COMPLIANCE", "COMPLIANCE", none, "COMPLIANCE until 2026-10-21 16:01 UTC"},
		{"legacy under a NONE config", "", none, "none (deletable; mode not recorded)"},
		{"legacy under a locked config", "", locked, "2026-10-21 16:01 UTC (mode not recorded)"},
	} {
		meta := &model.SnapshotMetadata{WORMMode: tc.mode, WORMRetentionUntil: until}
		if got := describeRetention(meta, tc.cfg); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A directory enforces no lock, whatever mode the sidecar recorded: the
// column must not read "COMPLIANCE until" over a file its owner can delete.
func TestDescribeRetentionOnLocalStorageNamesNoLock(t *testing.T) {
	until := time.Date(2026, 10, 21, 16, 1, 0, 0, time.UTC)
	local := config.StorageConfig{Type: config.StorageTypeLocal, WORMMode: config.WORMModeCompliance}
	meta := &model.SnapshotMetadata{WORMMode: "COMPLIANCE", WORMRetentionUntil: until}
	got := describeRetention(meta, local)
	if want := "kept until 2026-10-21 16:01 UTC (no Object Lock)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if label := wormLabel(local); strings.Contains(label, "WORM Object Lock") {
		t.Errorf("wormLabel for a local directory = %q, which claims a lock it does not have", label)
	}
}

// A recent run of a project that locks only its kept copies is written with
// no lock. The sidecar still records the bucket's mode and the date the run
// is deleted, and list printed "COMPLIANCE until" over objects anyone with
// the bucket's key could delete.
func TestDescribeRetentionSaysAnUnlockedRunIsNotLocked(t *testing.T) {
	until := time.Date(2026, 10, 14, 17, 43, 0, 0, time.UTC)
	hosted := config.StorageConfig{Type: config.StorageTypeHosted, WORMMode: config.WORMModeCompliance}
	meta := &model.SnapshotMetadata{WORMMode: "COMPLIANCE", WORMRetentionUntil: until, Unlocked: true}
	if got, want := describeRetention(meta, hosted), "kept until 2026-10-14 17:43 UTC, not locked"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if locked, why := snapshotLocked(meta, until.Add(-time.Hour)); locked {
		t.Errorf("guard counts an unlocked run as locked: %s", why)
	}
}

// A locked backup kept past its lock says both dates: on the free floor the
// RETENTION column gave the lock's end only, a day, for a backup kept a week.
func TestDescribeRetentionGivesTheKeepDatePastTheLock(t *testing.T) {
	lock := time.Date(2026, 10, 14, 17, 35, 0, 0, time.UTC)
	kept := lock.AddDate(0, 0, 6)
	meta := &model.SnapshotMetadata{WORMMode: "COMPLIANCE", WORMRetentionUntil: lock, KeptUntil: &kept}
	got := describeRetention(meta, config.StorageConfig{Type: config.StorageTypeHosted})
	if got != "COMPLIANCE until 2026-10-14 17:35 UTC, kept until 2026-10-20 17:35 UTC" {
		t.Fatalf("describeRetention = %q", got)
	}
}
