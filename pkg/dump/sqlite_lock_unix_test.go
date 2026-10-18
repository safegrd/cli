//go:build linux || darwin

package dump

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/safegrd/cli/internal/sqlitelocktest"
)

// A backup in the daemon's process leaves the locks the process already holds
// on the database alone: the daemon following its WAL holds SQLite's shared
// lock, and a backup that opened and closed the file to read its header
// dropped it.
func TestASQLiteBackupLeavesTheProcesssLocksAlone(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "app.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (x); INSERT INTO t VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	reader, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.ExecContext(ctx, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := reader.QueryRowContext(ctx, "SELECT count(*) FROM t").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if !sqlitelocktest.SharedHeld(t, path) {
		t.Fatal("a reader holds no shared lock on the database; the probe is not seeing SQLite's locks")
	}
	var out bytes.Buffer
	if _, err := NewSQLiteDumper("sqlite://"+path).Dump(ctx, "", &out); err != nil {
		t.Fatal(err)
	}
	if !sqlitelocktest.SharedHeld(t, path) {
		t.Fatal("after a backup this process holds no shared lock on the database")
	}
}
