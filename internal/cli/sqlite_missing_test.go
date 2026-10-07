package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
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
