package wal

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A database written while the follower checkpoints it (the WAL restarted
// several times) restores to exactly what was committed, at the end and at a
// restore point taken half way.
func TestAFollowedSQLiteDatabaseRestoresExactly(t *testing.T) {
	ctx := context.Background()
	a, _ := testArchive(t)
	a.Now = nil
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	app, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if _, err := app.Exec(`CREATE TABLE ledger (id INTEGER PRIMARY KEY, pad BLOB)`); err != nil {
		t.Fatal(err)
	}
	f := &SQLiteFollower{Archive: a, Path: path, CheckpointBytes: 64 << 10}
	if err := f.Start(ctx); err != nil {
		t.Fatal(err)
	}
	insert := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := app.Exec(`INSERT INTO ledger (pad) VALUES (randomblob(3000))`); err != nil {
				t.Fatal(err)
			}
		}
	}
	restarts := 0
	salt := f.cur.Header.Salt1
	for round := 0; round < 12; round++ {
		insert(10)
		if err := f.Step(ctx); err != nil {
			t.Fatalf("step %d: %v", round, err)
		}
		if f.cur.Header.Salt1 != salt {
			restarts, salt = restarts+1, f.cur.Header.Salt1
		}
		if round == 5 {
			if err := f.checkpoint(ctx, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := f.Step(ctx); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if restarts < 2 {
		t.Fatalf("the WAL restarted %d times; the test needs it to restart under the follower", restarts)
	}
	gens, _, _ := a.Bases(ctx)
	if len(gens) != 1 {
		t.Fatalf("%d generations, want 1: a restart the follower made must continue its generation", len(gens))
	}

	out := filepath.Join(dir, "restored.db")
	if _, err := a.RestoreSQLite(ctx, SQLiteRestoreOptions{Out: out}); err != nil {
		t.Fatal(err)
	}
	got, err := SQLiteCounts(ctx, out)
	if err != nil {
		t.Fatal(err)
	}
	if got["ledger"] != 120 {
		t.Fatalf("restored %d ledger rows, want 120", got["ledger"])
	}

	points, err := a.RestorePoints(ctx)
	if err != nil || len(points) != 1 {
		t.Fatalf("restore points: %v %v", points, err)
	}
	out2 := filepath.Join(dir, "at-point.db")
	if _, err := a.RestoreSQLite(ctx, SQLiteRestoreOptions{Out: out2, Point: &points[0]}); err != nil {
		t.Fatal(err)
	}
	got, err = SQLiteCounts(ctx, out2)
	if err != nil {
		t.Fatal(err)
	}
	if exact, wrong := points[0].CheckCounts(got); len(wrong) > 0 || got["ledger"] != 60 || exact == 0 {
		t.Fatalf("at the point: %v rows %d, wrong %v", got, got["ledger"], wrong)
	}
	st, err := a.SQLiteStatus(ctx)
	if err != nil || !st.HasWindow || len(st.Gaps) != 0 {
		t.Fatalf("status %+v %v", st, err)
	}
	if !strings.HasPrefix(gens[0].Kind, "sqlite") || time.Since(st.WindowTo) > time.Minute {
		t.Fatalf("base kind %q, window to %s", gens[0].Kind, st.WindowTo)
	}
}

// A writer that keeps committing while the follower checkpoints: whatever it
// committed is in the archive, through every restart of the WAL.
func TestAConcurrentWriterLosesNothingAcrossCheckpoints(t *testing.T) {
	ctx := context.Background()
	a, _ := testArchive(t)
	a.Now = nil
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	app, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	app.SetMaxOpenConns(1)
	if _, err := app.Exec(`CREATE TABLE ledger (id INTEGER PRIMARY KEY, pad BLOB)`); err != nil {
		t.Fatal(err)
	}
	f := &SQLiteFollower{Archive: a, Path: path, CheckpointBytes: 32 << 10}
	if err := f.Start(ctx); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			if _, err := app.Exec(`INSERT INTO ledger (pad) VALUES (randomblob(2000))`); err != nil {
				done <- err
				return
			}
			// A writer that never lets go of the lock starves the follower's
			// checkpoint, which then waits for the next step; a pause this
			// short still lands commits inside every checkpoint.
			time.Sleep(time.Millisecond)
		}
	}()
	restarts, salt := 0, f.cur.Header.Salt1
	deadline := time.Now().Add(20 * time.Second)
	for restarts < 3 && time.Now().Before(deadline) {
		if err := f.Step(ctx); err != nil {
			t.Fatal(err)
		}
		if f.cur.Header.Salt1 != salt {
			restarts, salt = restarts+1, f.cur.Header.Salt1
		}
		time.Sleep(2 * time.Millisecond)
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := f.Step(ctx); err != nil {
		t.Fatal(err)
	}
	var want int64
	if err := app.QueryRow(`SELECT count(*) FROM ledger`).Scan(&want); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if restarts < 3 {
		t.Fatalf("the WAL restarted %d times under the writer; the test needs more", restarts)
	}
	if gens, _, _ := a.Bases(ctx); len(gens) != 1 {
		t.Fatalf("%d generations: a restart the follower made must not start another", len(gens))
	}
	out := filepath.Join(dir, "restored.db")
	if _, err := a.RestoreSQLite(ctx, SQLiteRestoreOptions{Out: out}); err != nil {
		t.Fatal(err)
	}
	got, err := SQLiteCounts(ctx, out)
	if err != nil {
		t.Fatal(err)
	}
	if got["ledger"] != want {
		t.Fatalf("restored %d ledger rows of %d committed, across %d restarts", got["ledger"], want, restarts)
	}
}

// A segment missing from the middle of a generation breaks its run. A
// restore to the end of the archive is refused, as one to a moment past the
// gap is, instead of writing the database as it was before the gap and
// saying nothing; the status names the gap.
func TestASQLiteRestoreToTheEndRefusesAGap(t *testing.T) {
	ctx := context.Background()
	a, _ := testArchive(t)
	a.Now = nil
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	app, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if _, err := app.Exec(`CREATE TABLE ledger (id INTEGER PRIMARY KEY, pad BLOB)`); err != nil {
		t.Fatal(err)
	}
	f := &SQLiteFollower{Archive: a, Path: path, CheckpointBytes: 64 << 10}
	if err := f.Start(ctx); err != nil {
		t.Fatal(err)
	}
	round := func() {
		t.Helper()
		for i := 0; i < 10; i++ {
			if _, err := app.Exec(`INSERT INTO ledger (pad) VALUES (randomblob(3000))`); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		round()
	}
	pushed, err := a.Pushed(ctx)
	if err != nil || len(pushed) < 3 {
		t.Fatalf("%d segments pushed (%v); the test needs a middle one to delete", len(pushed), err)
	}
	if err := a.Store.Delete(ctx, pushed[1].Key); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		round()
	}
	f.Close()

	_, err = a.RestoreSQLite(ctx, SQLiteRestoreOptions{Out: filepath.Join(dir, "end.db")})
	if err == nil || !strings.Contains(err.Error(), "missing WAL") || !strings.Contains(err.Error(), pushed[2].Name) {
		t.Fatalf("a restore to the end across a gap: %v", err)
	}
	_, err = a.RestoreSQLite(ctx, SQLiteRestoreOptions{Out: filepath.Join(dir, "later.db"), Target: time.Now().Add(time.Hour)})
	if err == nil || !strings.Contains(err.Error(), "missing WAL") {
		t.Fatalf("a restore to a moment past the gap: %v", err)
	}
	st, err := a.SQLiteStatus(ctx)
	if err != nil || len(st.Gaps) != 1 || st.Gaps[0].First != pushed[2].Name {
		t.Fatalf("status gaps %+v %v, want %s", st.Gaps, err, pushed[2].Name)
	}
}
