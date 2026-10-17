package wal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/crypto"
	_ "modernc.org/sqlite"
)

// A SQLite database's WAL is followed the way Litestream follows it, into the
// same archive PostgreSQL's WAL goes to. The follower keeps a read
// transaction open on the database, so the WAL cannot be restarted under it,
// and copies each newly committed frame every interval. When the WAL grows
// past CheckpointBytes it checkpoints itself, in an order that leaves no
// frame uncopied:
//
//  1. take the write lock (BEGIN IMMEDIATE), so nothing can append;
//  2. copy the WAL to its end;
//  3. let go of the read transaction;
//  4. checkpoint (PASSIVE), and stop here unless every frame was copied into
//     the database;
//  5. commit, releasing the write lock with nothing written;
//  6. write one row in a new transaction, which restarts the WAL because it
//     is fully copied, or appends to it if an application writer restarted it
//     first;
//  7. take the read transaction again, which now holds a frame of the new
//     WAL and so blocks the next restart.
//
// A write transaction begun before the checkpoint holds a place in the old
// WAL and never restarts it, which is why 5 and 6 are two transactions. Any
// restart the follower did not make (a salt it did not expect) means frames
// may be gone, and it starts a new generation: a copy of the database and the
// WAL from there.
//
// A generation's base is the database file copied while the read
// transaction is held. A checkpoint may copy frames into it while it is read,
// but only frames the WAL still holds from its start, so the base and every
// frame from the WAL's first give the database exactly.

// sqliteSegRe is a SQLite WAL segment's name: generation, the WAL's first salt,
// and the frames' start and end offsets in that WAL.
var sqliteSegRe = regexp.MustCompile(`^[0-9a-f]{16}-[0-9a-f]{8}-[0-9a-f]{12}-[0-9a-f]{12}$`)

// SQLiteSegment is one segment's place in its generation.
type SQLiteSegment struct {
	Generation string
	Salt1      uint32
	Start, End int64
}

func sqliteSegName(gen string, salt1 uint32, start, end int64) string {
	return fmt.Sprintf("%s-%08x-%012x-%012x", gen, salt1, start, end)
}

// ParseSQLiteSegment reads a segment name back.
func ParseSQLiteSegment(name string) (SQLiteSegment, bool) {
	if !sqliteSegRe.MatchString(name) {
		return SQLiteSegment{}, false
	}
	s1, _ := strconv.ParseUint(name[17:25], 16, 32)
	st, _ := strconv.ParseInt(name[26:38], 16, 64)
	en, _ := strconv.ParseInt(name[39:51], 16, 64)
	return SQLiteSegment{Generation: name[:16], Salt1: uint32(s1), Start: st, End: en}, true
}

// SQLiteFollowerStatus is what the follower last did, for the daemon to say.
type SQLiteFollowerStatus struct {
	Generation string
	Following  bool
	LastPush   time.Time
	LastError  string
}

// SQLiteFollower follows one database's WAL into an archive.
type SQLiteFollower struct {
	Archive *Archive
	Path    string
	// Interval is how often new frames are copied.
	Interval time.Duration
	// CheckpointBytes is the WAL size at which the follower checkpoints.
	CheckpointBytes int64
	// PointEvery is how often a restore point is recorded with the row
	// counts of every table; GenerationEvery how often a new base is taken.
	PointEvery      time.Duration
	GenerationEvery time.Duration
	Logf, Warnf     func(format string, args ...any)

	db      *sql.DB
	r, w, c *sql.Conn
	reading bool

	gen     string
	genAt   time.Time
	pointAt time.Time
	cur     WALCursor
	mu      sync.Mutex
	status  SQLiteFollowerStatus
}

// Status is what the follower last did.
func (f *SQLiteFollower) Status() SQLiteFollowerStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *SQLiteFollower) note(fn func(*SQLiteFollowerStatus)) {
	f.mu.Lock()
	fn(&f.status)
	f.mu.Unlock()
}

func (f *SQLiteFollower) logf(format string, args ...any) {
	if f.Logf != nil {
		f.Logf(format, args...)
	}
}

func (f *SQLiteFollower) walPath() string { return f.Path + "-wal" }

// OpenSQLiteForWAL opens a database for following and returns its archive
// identity, recorded in a table of its own (_safegrd_wal) so a copy restored
// elsewhere keeps it, as a PostgreSQL cluster keeps its system identifier.
func OpenSQLiteForWAL(ctx context.Context, path string) (*sql.DB, string, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, "", err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		return nil, "", err
	}
	fail := func(err error) (*sql.DB, string, error) { db.Close(); return nil, "", err }
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return fail(err)
	}
	if mode != "wal" {
		return fail(fmt.Errorf("%s is in journal_mode %s; following its WAL needs WAL mode. Run once: sqlite3 %s 'PRAGMA journal_mode=WAL'", path, mode, path))
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS _safegrd_wal (id INTEGER PRIMARY KEY CHECK (id = 1), db_id INTEGER NOT NULL, seq INTEGER NOT NULL)`); err != nil {
		return fail(fmt.Errorf("creating _safegrd_wal in %s: %w. The daemon needs write access to the database and its directory", path, err))
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return fail(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO _safegrd_wal (id, db_id, seq) VALUES (1, ?, 0)`, n.Int64()+1); err != nil {
		return fail(err)
	}
	var id int64
	if err := db.QueryRowContext(ctx, `SELECT db_id FROM _safegrd_wal WHERE id = 1`).Scan(&id); err != nil {
		return fail(err)
	}
	return db, strconv.FormatInt(id, 10), nil
}

// Run follows the database until ctx ends. A failure closes everything and
// starts again, with a new generation, after a pause.
func (f *SQLiteFollower) Run(ctx context.Context) {
	for ctx.Err() == nil {
		err := f.follow(ctx)
		f.close()
		if ctx.Err() != nil {
			return
		}
		f.note(func(s *SQLiteFollowerStatus) { s.Following, s.LastError = false, err.Error() })
		if f.Warnf != nil {
			f.Warnf("following %s: %v. Starting again in 30s, with a new generation", f.Path, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

// Start opens the database and begins a generation; Step then follows it
// and Close lets go. Run does all three.
func (f *SQLiteFollower) Start(ctx context.Context) error {
	db, id, err := OpenSQLiteForWAL(ctx, f.Path)
	if err != nil {
		return err
	}
	f.db = db
	f.Archive.SystemID = id
	for _, c := range []**sql.Conn{&f.r, &f.w, &f.c} {
		if *c, err = db.Conn(ctx); err != nil {
			return err
		}
	}
	return f.newGeneration(ctx)
}

// Close ends the read transaction and closes the database.
func (f *SQLiteFollower) Close() { f.close() }

func (f *SQLiteFollower) follow(ctx context.Context) error {
	if err := f.Start(ctx); err != nil {
		return err
	}
	t := time.NewTicker(f.interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		if err := f.Step(ctx); err != nil {
			return err
		}
	}
}

func (f *SQLiteFollower) interval() time.Duration {
	if f.Interval > 0 {
		return f.Interval
	}
	return time.Second
}

// Step copies what was committed since the last step, checkpoints when the
// WAL has grown, records a restore point and starts a new generation when
// each is due.
func (f *SQLiteFollower) Step(ctx context.Context) error {
	h, err := ReadSQLiteWALHeader(f.walPath())
	if err != nil && err != io.EOF {
		return err
	}
	if err == io.EOF || h.Salt1 != f.cur.Header.Salt1 || h.Salt2 != f.cur.Header.Salt2 {
		f.logf("%s: its WAL was restarted by something else; starting a new generation", f.Path)
		return f.newGeneration(ctx)
	}
	if err := f.copy(ctx); err != nil {
		return err
	}
	switch {
	case f.GenerationEvery > 0 && time.Since(f.genAt) >= f.GenerationEvery:
		return f.newGeneration(ctx)
	case f.PointEvery > 0 && time.Since(f.pointAt) >= f.PointEvery:
		return f.checkpoint(ctx, true)
	}
	if fi, err := os.Stat(f.walPath()); err == nil && fi.Size() > f.checkpointBytes() {
		return f.checkpoint(ctx, false)
	}
	return nil
}

func (f *SQLiteFollower) checkpointBytes() int64 {
	if f.CheckpointBytes > 0 {
		return f.CheckpointBytes
	}
	return 4 << 20
}

// copy pushes the frames committed since the cursor.
func (f *SQLiteFollower) copy(ctx context.Context) error {
	frames, next, err := ReadCommitted(f.walPath(), f.cur)
	if err != nil {
		return err
	}
	if len(frames) == 0 {
		return nil
	}
	name := sqliteSegName(f.gen, f.cur.Header.Salt1, f.cur.Offset, next.Offset)
	if err := f.Archive.PushNew(ctx, name, frames); err != nil {
		return err
	}
	f.cur = next
	f.note(func(s *SQLiteFollowerStatus) { s.LastPush, s.LastError = time.Now().UTC(), "" })
	return nil
}

func (f *SQLiteFollower) beginRead(ctx context.Context) error {
	if _, err := f.r.ExecContext(ctx, "BEGIN"); err != nil {
		return err
	}
	var seq int64
	if err := f.r.QueryRowContext(ctx, "SELECT seq FROM _safegrd_wal WHERE id = 1").Scan(&seq); err != nil {
		_, _ = f.r.ExecContext(context.Background(), "ROLLBACK")
		return err
	}
	f.reading = true
	return nil
}

func (f *SQLiteFollower) endRead() {
	if f.reading {
		_, _ = f.r.ExecContext(context.Background(), "ROLLBACK") // a read transaction: nothing to keep
		f.reading = false
	}
}

// checkpoint runs the sequence in the package comment. With point, the row
// counts of every table are taken under the write lock, where they are
// exactly the database at the end of the frames just copied.
func (f *SQLiteFollower) checkpoint(ctx context.Context, point bool) error {
	if _, err := f.w.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		// An application writer that commits without pause can hold the
		// write lock past the busy timeout. Nothing is lost by waiting: the
		// read transaction still holds the WAL, so try at the next step.
		if sqliteBusy(err) {
			return nil
		}
		return fmt.Errorf("taking the write lock: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = f.w.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	if err := f.copy(ctx); err != nil {
		return err
	}
	if point {
		if err := f.recordPoint(ctx); err != nil {
			f.logf("%s: no restore point: %v", f.Path, err)
		}
		f.pointAt = time.Now()
	}
	f.endRead()
	var busy, logFrames, done int
	if err := f.c.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &logFrames, &done); err != nil {
		return err
	}
	if _, err := f.w.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	committed = true
	if logFrames != done {
		// A reader of the application's still needs the WAL; try later.
		return f.beginRead(ctx)
	}
	// The write that restarts the WAL. When an application writer holds
	// the lock instead, that writer restarted it (the WAL was fully copied),
	// and the header read below sees the same.
	if err := f.restartWrite(ctx); err != nil && !sqliteBusy(err) {
		return err
	}
	if err := f.beginRead(ctx); err != nil {
		return err
	}
	h, err := ReadSQLiteWALHeader(f.walPath())
	if err != nil {
		return err
	}
	switch {
	case h.Salt1 == f.cur.Header.Salt1 && h.Salt2 == f.cur.Header.Salt2:
		return nil // appended, not restarted: the cursor carries on
	case h.Salt1 == f.cur.Header.Salt1+1:
		f.cur = StartCursor(h)
		return nil
	}
	f.logf("%s: its WAL was restarted twice during a checkpoint; starting a new generation", f.Path)
	return f.newGeneration(ctx)
}

// newGeneration checkpoints so the WAL holds a frame, then copies the
// database file under the read transaction as the generation's base, with
// the WAL from its first frame to follow.
func (f *SQLiteFollower) newGeneration(ctx context.Context) error {
	f.endRead()
	if _, err := f.w.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("taking the write lock: %w", err)
	}
	if _, err := f.w.ExecContext(ctx, "UPDATE _safegrd_wal SET seq = seq + 1 WHERE id = 1"); err != nil {
		_, _ = f.w.ExecContext(context.Background(), "ROLLBACK")
		return err
	}
	if _, err := f.w.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	if err := f.beginRead(ctx); err != nil {
		return err
	}
	h, err := ReadSQLiteWALHeader(f.walPath())
	if err != nil {
		return fmt.Errorf("reading the WAL header after a write: %w", err)
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	gen := hex.EncodeToString(b[:])
	if err := f.pushBase(ctx, gen, h); err != nil {
		return err
	}
	f.gen, f.genAt, f.cur = gen, time.Now(), StartCursor(h)
	f.note(func(s *SQLiteFollowerStatus) { s.Generation, s.Following, s.LastError = gen, true, "" })
	f.logf("%s: generation %s started", f.Path, gen)
	if f.PointEvery > 0 {
		return f.checkpoint(ctx, true)
	}
	return nil
}

// pushBase stores the database file as generation gen's base.
func (f *SQLiteFollower) pushBase(ctx context.Context, gen string, h SQLiteWALHeader) error {
	a := f.Archive
	src, err := os.Open(f.Path)
	if err != nil {
		return err
	}
	defer src.Close()
	started := a.now()
	info := BaseInfo{Version: 1, Kind: "sqlite", BaseID: newID("b", started, randomHex()), SurfaceID: a.SurfaceID, SystemID: a.SystemID,
		StartedAt: started, Generation: gen, WALSalt1: h.Salt1, WALSalt2: h.Salt2, PageSize: h.PageSize}
	if a.Store.Locks() {
		info.LockedUntil = started.Add(a.Window + a.BaseEvery + lockSlack)
	}
	var buf bytes.Buffer
	m, err := crypto.EncryptStream(src, &buf, a.Recipient)
	if err != nil {
		return fmt.Errorf("encrypting the base of %s: %w", f.Path, err)
	}
	info.TarBytes, info.TarSha256, info.StoredBytes = m.RawBytes, m.RawSha256, int64(buf.Len())
	if info.LockedUntil, err = a.Store.Put(ctx, a.baseKey(info.BaseID, "base.db.zst.age"), &buf, info.LockedUntil); err != nil {
		return err
	}
	info.EndedAt = a.now()
	body, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	if _, err := a.Store.Put(ctx, a.baseKey(info.BaseID, "base.json"), bytes.NewReader(body), info.LockedUntil); err != nil {
		return err
	}
	f.logf("%s: base %s (%s) for generation %s", f.Path, info.BaseID, fmtBytes(info.StoredBytes), gen)
	return nil
}

// recordPoint counts every table on the write connection, under the write
// lock, so the counts are the database at the frame the cursor is at.
func (f *SQLiteFollower) recordPoint(ctx context.Context) error {
	a := f.Archive
	now := a.now()
	rp := RestorePoint{Version: 1, Name: newID("r", now, randomHex()), SurfaceID: a.SurfaceID, SystemID: a.SystemID, At: now,
		Generation: f.gen, WALSalt1: f.cur.Header.Salt1, WALOffset: f.cur.Offset}
	rows, err := f.w.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		var c int64
		if err := f.w.QueryRowContext(ctx, "SELECT count(*) FROM "+quoteSQLite(n)).Scan(&c); err != nil {
			return err
		}
		rp.Tables = append(rp.Tables, TableCount{Table: n, Before: c, After: c})
	}
	body, err := json.MarshalIndent(rp, "", "  ")
	if err != nil {
		return err
	}
	var lock time.Time
	if a.Store.Locks() {
		lock = now.Add(a.Window + lockSlack)
	}
	if _, err := a.Store.Put(ctx, a.pointKey(rp.Name), bytes.NewReader(body), lock); err != nil {
		return err
	}
	f.logf("%s: restore point %s, %d tables counted", f.Path, rp.Name, len(rp.Tables))
	return nil
}

// restartWrite writes one row of _safegrd_wal in a transaction of its own.
func (f *SQLiteFollower) restartWrite(ctx context.Context) error {
	if _, err := f.w.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	if _, err := f.w.ExecContext(ctx, "UPDATE _safegrd_wal SET seq = seq + 1 WHERE id = 1"); err != nil {
		_, _ = f.w.ExecContext(context.Background(), "ROLLBACK")
		return err
	}
	_, err := f.w.ExecContext(ctx, "COMMIT")
	return err
}

// sqliteBusy says whether err is SQLite's "database is locked".
func sqliteBusy(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "SQLITE_BUSY") || strings.Contains(err.Error(), "database is locked"))
}

func (f *SQLiteFollower) close() {
	f.endRead()
	for _, c := range []*sql.Conn{f.r, f.w, f.c} {
		if c != nil {
			c.Close()
		}
	}
	f.r, f.w, f.c = nil, nil, nil
	if f.db != nil {
		f.db.Close()
		f.db = nil
	}
}

func quoteSQLite(s string) string {
	return `"` + string(bytes.ReplaceAll([]byte(s), []byte(`"`), []byte(`""`))) + `"`
}

func fmtBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// PushNew stores a WAL segment whose name is new by construction, without
// asking whether it is already there: a follower pushes one each interval.
func (a *Archive) PushNew(ctx context.Context, name string, data []byte) error {
	if err := ValidName(name); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	var buf bytes.Buffer
	if _, err := crypto.EncryptStream(bytes.NewReader(data), &buf, a.Recipient); err != nil {
		return fmt.Errorf("encrypting %s: %w", name, err)
	}
	_, err := a.Store.Put(ctx, segmentKey(a.prefix(), name, a.now(), hex.EncodeToString(sum[:])), &buf, time.Time{})
	return err
}
