//go:build linux || darwin

package wal

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/safegrd/cli/internal/sqlitelocktest"
)

// The follower keeps SQLite's shared lock on the database for as long as it
// follows. Closing a descriptor of its own on the file (copying a base used
// to) drops every POSIX lock the process holds on it. On Ubuntu, the sqlite3
// shell closing its last connection then took the database for its own,
// checkpointed and deleted the WAL under the follower, which started a new
// generation at every write.
func TestTheFollowerKeepsItsSharedLockAcrossABase(t *testing.T) {
	ctx := context.Background()
	a, _ := testArchive(t)
	a.Now = nil
	path := filepath.Join(t.TempDir(), "app.db")
	app, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Exec(`CREATE TABLE t (x)`); err != nil {
		t.Fatal(err)
	}
	app.Close()

	f := &SQLiteFollower{Archive: a, Path: path}
	if err := f.Start(ctx); err != nil { // takes the first base
		t.Fatal(err)
	}
	defer f.Close()
	if !sqlitelocktest.SharedHeld(t, path) {
		t.Fatal("after the first base the follower holds no shared lock on the database")
	}
	if err := f.newGeneration(ctx); err != nil {
		t.Fatal(err)
	}
	if !sqlitelocktest.SharedHeld(t, path) {
		t.Fatal("after a second base the follower holds no shared lock on the database")
	}
}
