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
// The defect: `list` read TotalTables and TotalRows, which CalculateTotals sets
// only for Postgres, so a file backup of two files printed 0 tables and 0 rows
// — Postgres columns over a file surface, populated from fields nothing had
// written. The metadata here is built the way backup builds it and run
// through the same CalculateTotals, so the test pins the producer/consumer pair
// rather than a hand-written fixture that could encode the same misreading.
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
		{"recorded COMPLIANCE", "COMPLIANCE", none, "COMPLIANCE until 2026-10-21 16:01"},
		{"legacy under a NONE config", "", none, "none (deletable; mode not recorded)"},
		{"legacy under a locked config", "", locked, "2026-10-21 16:01 (mode not recorded)"},
	} {
		meta := &model.SnapshotMetadata{WORMMode: tc.mode, WORMRetentionUntil: until}
		if got := describeRetention(meta, tc.cfg); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
