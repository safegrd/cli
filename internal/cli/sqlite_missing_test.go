package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/safegrd/cli/pkg/config"
)

// A mistyped SQLite path fails before storage is touched, as a source
// failure. It used to open an epoch on the remote server, and print "Epoch
// opened (first backup)", before the dump found no file.
func TestAMissingSQLiteFileFailsBeforeStorageIsTouched(t *testing.T) {
	missing := "sqlite://" + filepath.Join(t.TempDir(), "nope.db")
	// No storage is configured, so reaching it would fail differently.
	_, _, err := runRepoDatabaseBackup(context.Background(), repoDBParams{SurfaceID: "sqlite-x", DatabaseURL: missing})
	if err == nil || !strings.Contains(err.Error(), "nope.db") || exitCodeOf(err) != exitSource {
		t.Fatalf("backup of a missing SQLite file: %v (exit %d)", err, exitCodeOf(err))
	}
}

// A MySQL or MongoDB surface on a host without its dump tool fails before
// storage is touched too. It opened an epoch first, so the next run, with
// the tool installed, read as an increment over the epoch's first complete
// run.
func TestAMissingDumpToolFailsBeforeAnEpochOpens(t *testing.T) {
	for _, tc := range []struct{ env, url string }{
		{"SAFEGRD_MYSQLDUMP", "mysql://app:pw@127.0.0.1:1/shop"},
		{"SAFEGRD_MONGODUMP", "mongodb://app:pw@127.0.0.1:1/shop"},
	} {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(tc.env, filepath.Join(t.TempDir(), "no-such-tool"))
			id, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			_, _, err = runRepoDatabaseBackup(context.Background(), repoDBParams{SurfaceID: "db-x", DatabaseURL: tc.url, Recipient: id.Recipient().String(),
				StorageCfg: config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: dir}, StateDir: t.TempDir(), SnapshotID: "snap-20261018-010000-abc123"})
			if err == nil || !strings.Contains(err.Error(), tc.env) || exitCodeOf(err) != exitSource {
				t.Fatalf("backup with no dump tool: %v (exit %d)", err, exitCodeOf(err))
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Errorf("storage holds %d entries after a backup that had no dump tool, want none", len(entries))
			}
		})
	}
}
