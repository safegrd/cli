package dump

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A SQLite backup taken while the database is being written is one committed
// state, never a mixture, and includes transactions still in the WAL.
//
// The writer keeps an invariant every transaction preserves: it inserts ten
// rows into ledger and adds ten to the one row in totals. A copy that tore
// between pages, or caught half a transaction, breaks it. Autocheckpoint is
// off, so everything committed stays in the -wal file: a copy of the main
// database file alone would miss all of it.
func TestASQLiteBackupUnderWritesIsOneCommittedState(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	w, err := openSQLite(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for _, q := range []string{
		"PRAGMA journal_mode=WAL", "PRAGMA wal_autocheckpoint=0",
		"CREATE TABLE ledger (id INTEGER PRIMARY KEY, amount INTEGER NOT NULL, note TEXT)",
		"CREATE TABLE totals (id INTEGER PRIMARY KEY, n INTEGER NOT NULL)",
		"INSERT INTO totals VALUES (1, 0)",
	} {
		if _, err := w.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	commit := func() error {
		tx, err := w.Begin()
		if err != nil {
			return err
		}
		for i := 0; i < 10; i++ {
			if _, err := tx.Exec("INSERT INTO ledger (amount, note) VALUES (?, ?)", i, strings.Repeat("x", 200)); err != nil {
				tx.Rollback()
				return err
			}
		}
		if _, err := tx.Exec("UPDATE totals SET n = n + 10 WHERE id = 1"); err != nil {
			tx.Rollback()
			return err
		}
		return tx.Commit()
	}
	for i := 0; i < 200; i++ {
		if err := commit(); err != nil {
			t.Fatal(err)
		}
	}
	if fi, err := os.Stat(path + "-wal"); err != nil || fi.Size() == 0 {
		t.Fatalf("the committed rows are not in the WAL, so this test would prove nothing: %v", err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	var writes atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			if err := commit(); err != nil {
				t.Errorf("writer: %v", err)
				return
			}
			writes.Add(1)
		}
	}()
	time.Sleep(20 * time.Millisecond)
	var archive bytes.Buffer
	meta, err := NewSQLiteDumper("sqlite://"+path).Dump(ctx, "", &archive)
	stop.Store(true)
	wg.Wait()
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	if writes.Load() == 0 {
		t.Fatal("the writer committed nothing while the backup ran; the test proved nothing")
	}
	if meta.DatabaseName != "app.db" || meta.TotalTables != 2 || meta.SurfaceType != "sqlite" {
		t.Errorf("manifest = %+v", meta)
	}

	// The Fire Drill is a real restore: integrity and counts.
	drill, err := InspectSQLiteArchive(ctx, bytes.NewReader(archive.Bytes()))
	if err != nil || !drill.Passed {
		t.Fatalf("drill: %v %+v", err, drill)
	}

	target := filepath.Join(dir, "restored", "app.db")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSQLiteRestorer("sqlite://"+target).Restore(ctx, bytes.NewReader(archive.Bytes())); err != nil {
		t.Fatalf("restore: %v", err)
	}
	r, err := openSQLite(target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var rows, total int64
	if err := r.QueryRow("SELECT count(*) FROM ledger").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := r.QueryRow("SELECT n FROM totals WHERE id = 1").Scan(&total); err != nil {
		t.Fatal(err)
	}
	if rows != total || rows%10 != 0 {
		t.Fatalf("restored ledger has %d rows and totals says %d: the copy is not one committed state", rows, total)
	}
	if rows < 2000 {
		t.Errorf("restored %d rows, fewer than the 2000 committed before the backup began: WAL contents were lost", rows)
	}
	if rows != meta.TotalRows-1 {
		t.Errorf("restored %d ledger rows; the manifest counted %d rows in all tables", rows, meta.TotalRows)
	}

	// A restore never overwrites.
	if _, err := NewSQLiteRestorer("sqlite://"+target).Restore(ctx, bytes.NewReader(archive.Bytes())); err == nil || !strings.Contains(err.Error(), "never overwrites") {
		t.Errorf("a restore over an existing database: %v", err)
	}
}

func TestASQLiteBackupRefusesWhatIsNotADatabase(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(junk, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := NewSQLiteDumper("sqlite://"+junk).Dump(context.Background(), "", &out); err == nil || !strings.Contains(err.Error(), "not a SQLite 3 database") {
		t.Errorf("dump of a text file: %v", err)
	}
	if _, err := NewSQLiteDumper("sqlite://"+filepath.Join(dir, "missing.db")).Dump(context.Background(), "", &out); err == nil {
		t.Error("a missing database was backed up (as a new empty one?)")
	}
	if _, err := os.Stat(filepath.Join(dir, "missing.db")); err == nil {
		t.Error("backing up a missing database created it")
	}
}

func TestSQLiteURLs(t *testing.T) {
	for in, want := range map[string]string{"sqlite:///var/lib/app.db": "/var/lib/app.db", "SQLite:///x.db": "/x.db"} {
		if got, err := SQLitePath(in); err != nil || got != want {
			t.Errorf("SQLitePath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := SQLitePath("sqlite:///x.db?mode=rw"); err == nil {
		t.Error("options in a sqlite URL were accepted")
	}
	if !SameSQLiteDatabase("sqlite:///a/../b.db", "sqlite:///b.db") || SameSQLiteDatabase("sqlite:///a.db", "sqlite:///b.db") {
		t.Error("SameSQLiteDatabase")
	}
}

// A copy left by a process that was killed mid-backup is removed by the next
// run; one belonging to a live process is not.
func TestALeftoverSQLiteCopyIsSwept(t *testing.T) {
	parent := t.TempDir()
	dead := filepath.Join(parent, sqliteWorkPrefix+"999999-abc")
	live := filepath.Join(parent, sqliteWorkPrefix+strconv.Itoa(os.Getppid())+"-def")
	other := filepath.Join(parent, "unrelated")
	for _, d := range []string{dead, live, other} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "copy.sqlite"), []byte("plaintext"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := sqliteWorkDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("work dir %s: %v %v, want 0700", dir, fi, err)
	}
	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Error("a dead process's plaintext copy was left on disk")
	}
	for _, d := range []string{live, other} {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("%s was removed: %v", d, err)
		}
	}
}
