// Package cache is the writer's local memory of one epoch: which files it has
// read, which blobs the epoch holds and where, which packs are uploaded, and
// what the last snapshot listed. It holds file names, so it is kept 0600 in a
// 0700 directory. It never holds a pack key, so it cannot decrypt anything.
//
// The repository is never read back to rebuild it. A cache that is missing,
// corrupt or of another epoch means the next run opens a new epoch and uploads
// the tree once.
package cache

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/safegrd/cli/pkg/repo/chunk"
	"github.com/safegrd/cli/pkg/repo/format"
	_ "modernc.org/sqlite" // the "sqlite" database/sql driver
)

const schema = `
CREATE TABLE IF NOT EXISTS epoch (
	id TEXT PRIMARY KEY, descriptor TEXT NOT NULL, polynomial INTEGER NOT NULL,
	opening_done INTEGER NOT NULL DEFAULT 0, runs_since_rescan INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS files (
	path BLOB PRIMARY KEY, dev INTEGER, ino INTEGER, size INTEGER, mtime_ns INTEGER,
	ctime_ns INTEGER, mode INTEGER, sha256 TEXT, blobs BLOB, last_run TEXT);
CREATE TABLE IF NOT EXISTS blobs (
	id BLOB PRIMARY KEY, type INTEGER, pack_id TEXT, offset INTEGER, length INTEGER,
	raw_length INTEGER, run_id TEXT, indexed INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS blobs_pack ON blobs (pack_id);
CREATE TABLE IF NOT EXISTS packs (
	id TEXT PRIMARY KEY, object_key TEXT, state TEXT, bytes INTEGER, run_id TEXT);
CREATE TABLE IF NOT EXISTS runs (
	id TEXT PRIMARY KEY, snapshot_id TEXT, started_at TEXT, state TEXT, class TEXT);
CREATE TABLE IF NOT EXISTS catalog (
	path BLOB PRIMARY KEY, type TEXT, value TEXT, size INTEGER, mtime_ns INTEGER, mode INTEGER);
CREATE TABLE IF NOT EXISTS pending (
	path BLOB PRIMARY KEY, type TEXT, value TEXT, size INTEGER, mtime_ns INTEGER, mode INTEGER);
CREATE TABLE IF NOT EXISTS refs (id BLOB PRIMARY KEY);
CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v BLOB);
`

// Cache is one epoch's cache file. Statements share one connection and one
// open transaction, committed in batches and at every state change that must
// survive a crash.
type Cache struct {
	mu      sync.Mutex
	db      *sql.DB
	tx      *sql.Tx
	ops     int
	path    string
	epoch   format.Epoch
	pol     chunk.Pol
	done    bool
	rescans int
}

// batch is how many row writes share a transaction before it is committed.
const batch = 2000

// Dir is where a surface's epoch caches live under the state directory.
func Dir(stateDir, surfaceID string) string {
	return filepath.Join(stateDir, "cache", surfaceID)
}

func dsn(path string) string {
	return "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)"
}

func open(path string) (*Cache, error) {
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Cache{db: db, tx: tx, path: path}, nil
}

// Create starts the cache of a new epoch with a fresh chunker polynomial.
func Create(dir string, e format.Epoch) (*Cache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
	pol, err := chunk.RandomPolynomial()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, e.EpochID+".db")
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("a cache for epoch %s already exists at %s", e.EpochID, path)
	}
	c, err := open(path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	desc, err := json.Marshal(e)
	if err != nil {
		c.Close()
		return nil, err
	}
	if _, err := c.tx.Exec(`INSERT INTO epoch (id, descriptor, polynomial) VALUES (?, ?, ?)`, e.EpochID, string(desc), int64(pol)); err != nil {
		c.Close()
		return nil, err
	}
	if err := c.commitLocked(); err != nil {
		c.Close()
		return nil, err
	}
	c.epoch, c.pol = e, pol
	return c, nil
}

// Current opens the newest readable epoch cache of a surface. It returns nil
// with lost set when caches exist but none is usable (each unusable file is
// moved aside, so it is reported once and not tripped over again), and nil
// with lost unset when there were none.
func Current(dir, surfaceID string) (c *Cache, lost bool, err error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, nil
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".db") && format.ValidEpochID(strings.TrimSuffix(e.Name(), ".db")) {
			names = append(names, e.Name())
		}
	}
	// Epoch ids start with the month they opened in; within a month the
	// descriptor's time decides.
	type cand struct {
		c  *Cache
		at time.Time
	}
	var best *cand
	for _, n := range names {
		p := filepath.Join(dir, n)
		cc, err := load(p, strings.TrimSuffix(n, ".db"), surfaceID)
		if err != nil {
			_ = os.Rename(p, p+".unusable-"+time.Now().UTC().Format("20060102T150405"))
			lost = true
			continue
		}
		if best == nil || cc.epoch.OpenedAt.After(best.at) {
			if best != nil {
				best.c.Close()
			}
			best = &cand{cc, cc.epoch.OpenedAt}
		} else {
			cc.Close()
		}
	}
	if best == nil {
		return nil, lost || len(names) > 0, nil
	}
	return best.c, false, nil
}

func load(path, epochID, surfaceID string) (*Cache, error) {
	c, err := open(path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Cache, error) { c.Close(); return nil, err }
	var check string
	if err := c.tx.QueryRow(`PRAGMA quick_check`).Scan(&check); err != nil || check != "ok" {
		return fail(fmt.Errorf("integrity check: %s %v", check, err))
	}
	var desc string
	var pol int64
	var done, rescans int
	if err := c.tx.QueryRow(`SELECT descriptor, polynomial, opening_done, runs_since_rescan FROM epoch WHERE id = ?`, epochID).
		Scan(&desc, &pol, &done, &rescans); err != nil {
		return fail(fmt.Errorf("no epoch row: %w", err))
	}
	if err := json.Unmarshal([]byte(desc), &c.epoch); err != nil {
		return fail(err)
	}
	if c.epoch.EpochID != epochID || c.epoch.SurfaceID != surfaceID {
		return fail(fmt.Errorf("the cache names epoch %s of %s", c.epoch.EpochID, c.epoch.SurfaceID))
	}
	c.pol, c.done, c.rescans = chunk.Pol(pol), done == 1, rescans
	if !c.pol.Irreducible() {
		return fail(fmt.Errorf("the stored polynomial is not usable"))
	}
	return c, nil
}

// Close commits what is pending and closes the file.
func (c *Cache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tx != nil {
		_ = c.tx.Commit()
		c.tx = nil
	}
	return c.db.Close()
}

// Path is the cache file.
func (c *Cache) Path() string { return c.path }

// Epoch is the epoch this cache belongs to.
func (c *Cache) Epoch() format.Epoch { return c.epoch }

// Polynomial is the epoch's chunker polynomial.
func (c *Cache) Polynomial() chunk.Pol { return c.pol }

// OpeningDone reports whether the epoch's first snapshot is complete.
func (c *Cache) OpeningDone() bool { return c.done }

// RunsSinceRescan counts the runs since one last read every file.
func (c *Cache) RunsSinceRescan() int { return c.rescans }

func (c *Cache) commitLocked() error {
	if err := c.tx.Commit(); err != nil {
		return err
	}
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	c.tx, c.ops = tx, 0
	return nil
}

func (c *Cache) execLocked(q string, args ...any) error {
	if _, err := c.tx.Exec(q, args...); err != nil {
		return err
	}
	c.ops++
	if c.ops >= batch {
		return c.commitLocked()
	}
	return nil
}

// Commit makes everything written so far durable.
func (c *Cache) Commit() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.commitLocked()
}

// Pack is a pack the cache knows.
type Pack struct {
	ID, Key, State, RunID string
	Bytes                 int64
}

// Resume drops what a crashed run sealed but never uploaded, and reports the
// packs earlier unfinished runs did upload, which this run adopts.
func (c *Cache) Resume() (adopted []Pack, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.execLocked(`DELETE FROM blobs WHERE pack_id IN (SELECT id FROM packs WHERE state = 'sealed')`); err != nil {
		return nil, err
	}
	if err := c.execLocked(`DELETE FROM packs WHERE state = 'sealed'`); err != nil {
		return nil, err
	}
	rows, err := c.tx.Query(`SELECT DISTINCT p.id, p.object_key, p.bytes, p.run_id FROM packs p JOIN blobs b ON b.pack_id = p.id
		WHERE p.state = 'uploaded' AND b.indexed = 0 ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		p := Pack{State: "uploaded"}
		if err := rows.Scan(&p.ID, &p.Key, &p.Bytes, &p.RunID); err != nil {
			return nil, err
		}
		adopted = append(adopted, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return adopted, c.commitLocked()
}

// Run states. A run is running from BeginRun, publishing from the moment its
// sidecar may exist in the store, complete once FinishRun has recorded it,
// and abandoned when a later run finished without it ever completing.
const (
	runRunning    = "running"
	runPublishing = "publishing"
	runComplete   = "complete"
	runAbandoned  = "abandoned"
)

// BeginRun records a run and clears the previous run's working tables.
func (c *Cache) BeginRun(runID, snapshotID, class string, at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, q := range []string{`DELETE FROM pending`, `DELETE FROM refs`} {
		if err := c.execLocked(q); err != nil {
			return err
		}
	}
	if err := c.execLocked(`INSERT INTO runs (id, snapshot_id, started_at, state, class) VALUES (?, ?, ?, ?, ?)`,
		runID, snapshotID, at.UTC().Format(time.RFC3339Nano), runRunning, class); err != nil {
		return err
	}
	return c.commitLocked()
}

// MarkPublishing records, durably, that the run is about to write its
// sidecar: from here its snapshot may exist in the store whether or not this
// process lives to finish the run.
func (c *Cache) MarkPublishing(runID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.execLocked(`UPDATE runs SET state = ? WHERE id = ?`, runPublishing, runID); err != nil {
		return err
	}
	return c.commitLocked()
}

// UnfinishedRun reports whether an earlier run reached its sidecar and never
// finished. Its snapshot may exist, and the catalog table does not describe
// it, so a delta against the table would skip what that run changed: the
// next catalog must list every path instead.
func (c *Cache) UnfinishedRun() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var n int
	if err := c.tx.QueryRow(`SELECT COUNT(*) FROM runs WHERE state = ?`, runPublishing).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// FileRow is what the cache remembers of one regular file.
type FileRow struct {
	Path                   string
	Dev, Ino               uint64
	Size, MTimeNs, CTimeNs int64
	Mode                   uint32
	SHA256                 string
	Blobs                  []format.ID
}

// File returns the row for path, if any.
func (c *Cache) File(path string) (*FileRow, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var r FileRow
	var dev, ino int64
	var blobs []byte
	err := c.tx.QueryRow(`SELECT dev, ino, size, mtime_ns, ctime_ns, mode, sha256, blobs FROM files WHERE path = ?`, []byte(path)).
		Scan(&dev, &ino, &r.Size, &r.MTimeNs, &r.CTimeNs, &r.Mode, &r.SHA256, &blobs)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(blobs)%32 != 0 {
		return nil, nil
	}
	r.Path, r.Dev, r.Ino = path, uint64(dev), uint64(ino)
	for i := 0; i < len(blobs); i += 32 {
		var id format.ID
		copy(id[:], blobs[i:i+32])
		r.Blobs = append(r.Blobs, id)
	}
	return &r, nil
}

// PutFile records what a run read of one file.
func (c *Cache) PutFile(r FileRow, runID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	blobs := make([]byte, 0, 32*len(r.Blobs))
	for _, id := range r.Blobs {
		blobs = append(blobs, id[:]...)
	}
	return c.execLocked(`INSERT OR REPLACE INTO files (path, dev, ino, size, mtime_ns, ctime_ns, mode, sha256, blobs, last_run)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		[]byte(r.Path), int64(r.Dev), int64(r.Ino), r.Size, r.MTimeNs, r.CTimeNs, r.Mode, r.SHA256, blobs, runID)
}

// Known reports whether the epoch holds a blob: it is in an uploaded pack.
func (c *Cache) Known(id format.ID) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var one int
	err := c.tx.QueryRow(`SELECT 1 FROM blobs b JOIN packs p ON p.id = b.pack_id WHERE b.id = ? AND p.state = 'uploaded'`, id[:]).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// SealPack records a pack and its blobs before it is uploaded, so a crash
// mid-upload leaves a row that the next run drops.
func (c *Cache) SealPack(packID, key, runID string, bytes int64, blobs []format.BlobEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.execLocked(`INSERT INTO packs (id, object_key, state, bytes, run_id) VALUES (?, ?, 'sealed', ?, ?)`, packID, key, bytes, runID); err != nil {
		return err
	}
	for _, b := range blobs {
		id, err := format.ParseID(b.ID)
		if err != nil {
			return err
		}
		if err := c.execLocked(`INSERT OR IGNORE INTO blobs (id, type, pack_id, offset, length, raw_length, run_id) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id[:], int(b.Type), packID, b.Offset, b.Length, b.RawLength, runID); err != nil {
			return err
		}
	}
	return c.commitLocked()
}

// MarkUploaded records that a pack is in the store. From here its blobs are
// known to the epoch.
func (c *Cache) MarkUploaded(packID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.execLocked(`UPDATE packs SET state = 'uploaded' WHERE id = ?`, packID); err != nil {
		return err
	}
	return c.commitLocked()
}

// Ref records that the snapshot being written references a blob.
func (c *Cache) Ref(id format.ID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.execLocked(`INSERT OR IGNORE INTO refs (id) VALUES (?)`, id[:])
}

// Entry is one path the run saw, for the content root and the catalog.
type Entry struct {
	Path    string // relative to /, no leading slash
	Type    byte   // format.ContentDir, ContentFile, ContentSymlink
	Value   string // format.ContentValue
	Size    int64
	MTimeNs int64
	Mode    uint32
}

// AddEntry records one path the run saw.
func (c *Cache) AddEntry(e Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.execLocked(`INSERT OR REPLACE INTO pending (path, type, value, size, mtime_ns, mode) VALUES (?, ?, ?, ?, ?, ?)`,
		[]byte(e.Path), string(e.Type), e.Value, e.Size, e.MTimeNs, e.Mode)
}

// Entries calls fn for every path of the run in raw byte order.
func (c *Cache) Entries(fn func(Entry) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.scanEntries(`SELECT path, type, value, size, mtime_ns, mode FROM pending ORDER BY path`, fn)
}

func (c *Cache) scanEntries(q string, fn func(Entry) error) error {
	rows, err := c.tx.Query(q)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var e Entry
		var p []byte
		var t string
		if err := rows.Scan(&p, &t, &e.Value, &e.Size, &e.MTimeNs, &e.Mode); err != nil {
			return err
		}
		e.Path = string(p)
		if len(t) == 1 {
			e.Type = t[0]
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Delta is the change of one path since the last complete snapshot.
type Delta struct {
	Entry
	Event string
}

// Deltas returns what changed since the last complete snapshot: every path
// when complete is set (an opening run), otherwise the added, changed and
// deleted ones, in raw byte order. A path is changed when its type or its
// content differs. A new mode, owner or mtime alone is no event: the tree
// of every snapshot carries its own, and a restore applies the tree's.
func (c *Cache) Deltas(complete bool) ([]Delta, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Delta
	add := func(event string) func(Entry) error {
		return func(e Entry) error { out = append(out, Delta{e, event}); return nil }
	}
	if complete {
		if err := c.scanEntries(`SELECT path, type, value, size, mtime_ns, mode FROM pending ORDER BY path`, add(format.EventPresent)); err != nil {
			return nil, err
		}
		return out, nil
	}
	if err := c.scanEntries(`SELECT p.path, p.type, p.value, p.size, p.mtime_ns, p.mode FROM pending p
		LEFT JOIN catalog k ON k.path = p.path WHERE k.path IS NULL`, add(format.EventAdded)); err != nil {
		return nil, err
	}
	if err := c.scanEntries(`SELECT p.path, p.type, p.value, p.size, p.mtime_ns, p.mode FROM pending p
		JOIN catalog k ON k.path = p.path WHERE k.type != p.type OR k.value != p.value`, add(format.EventChanged)); err != nil {
		return nil, err
	}
	if err := c.scanEntries(`SELECT k.path, k.type, '', 0, 0, 0 FROM catalog k
		LEFT JOIN pending p ON p.path = k.path WHERE p.path IS NULL`, add(format.EventDeleted)); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Unindexed returns every blob in an uploaded pack that no committed run has
// indexed yet, grouped by pack: this run's, and those adopted from runs that
// crashed after uploading.
func (c *Cache) Unindexed() ([]format.IndexPack, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rows, err := c.tx.Query(`SELECT p.id, p.bytes, b.id, b.type, b.offset, b.length, b.raw_length
		FROM blobs b JOIN packs p ON p.id = b.pack_id WHERE p.state = 'uploaded' AND b.indexed = 0 ORDER BY p.id, b.offset`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []format.IndexPack
	for rows.Next() {
		var packID string
		var bytes int64
		var id []byte
		var e format.BlobEntry
		var typ int
		if err := rows.Scan(&packID, &bytes, &id, &typ, &e.Offset, &e.Length, &e.RawLength); err != nil {
			return nil, err
		}
		var bid format.ID
		copy(bid[:], id)
		e.ID, e.Type = bid.String(), byte(typ)
		if len(out) == 0 || out[len(out)-1].PackID != packID {
			out = append(out, format.IndexPack{PackID: packID, Bytes: bytes, Blobs: []format.BlobEntry{}})
		}
		out[len(out)-1].Blobs = append(out[len(out)-1].Blobs, e)
	}
	return out, rows.Err()
}

// Referenced returns the packs holding blobs the snapshot references, and the
// runs whose indexes locate them. Blobs not yet indexed are this run's.
func (c *Cache) Referenced(thisRun string) (packs, runs []string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	collect := func(q string) ([]string, error) {
		rows, err := c.tx.Query(q)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, rows.Err()
	}
	var missing int
	if err := c.tx.QueryRow(`SELECT COUNT(*) FROM refs r LEFT JOIN blobs b ON b.id = r.id
		LEFT JOIN packs p ON p.id = b.pack_id WHERE b.id IS NULL OR p.state != 'uploaded'`).Scan(&missing); err != nil {
		return nil, nil, err
	}
	if missing > 0 {
		return nil, nil, fmt.Errorf("%d blobs the snapshot references are in no uploaded pack", missing)
	}
	if packs, err = collect(`SELECT DISTINCT b.pack_id FROM refs r JOIN blobs b ON b.id = r.id ORDER BY 1`); err != nil {
		return nil, nil, err
	}
	if runs, err = collect(`SELECT DISTINCT b.run_id FROM refs r JOIN blobs b ON b.id = r.id WHERE b.indexed = 1 ORDER BY 1`); err != nil {
		return nil, nil, err
	}
	runs = append(runs, thisRun)
	sort.Strings(runs)
	return packs, dedupe(runs), nil
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// State returns what the last finished run left under k for the next, or
// nil.
func (c *Cache) State(k string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var v []byte
	err := c.tx.QueryRow(`SELECT v FROM state WHERE k = ?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return v, err
}

// FinishRun records a run as complete in one transaction: its blobs are
// indexed under it, the catalog becomes what it saw, the opening class ends
// if this was the opening run, and state is what it leaves for the next.
func (c *Cache) FinishRun(runID string, rescanned bool, state map[string][]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	rescans := c.rescans + 1
	if rescanned {
		rescans = 0
	}
	stmts := []struct {
		q    string
		args []any
	}{
		{`UPDATE blobs SET indexed = 1, run_id = ? WHERE indexed = 0 AND pack_id IN (SELECT id FROM packs WHERE state = 'uploaded')`, []any{runID}},
		{`DELETE FROM catalog`, nil},
		{`INSERT INTO catalog SELECT path, type, value, size, mtime_ns, mode FROM pending`, nil},
		// Earlier runs that never finished are settled by this one: their
		// packs are indexed above, and the catalog now lists every path
		// when one of them may have published.
		{`UPDATE runs SET state = ? WHERE state IN (?, ?) AND id != ?`, []any{runAbandoned, runRunning, runPublishing, runID}},
		{`UPDATE runs SET state = ? WHERE id = ?`, []any{runComplete, runID}},
		{`UPDATE epoch SET opening_done = 1, runs_since_rescan = ? WHERE id = ?`, []any{rescans, c.epoch.EpochID}},
	}
	for k, v := range state {
		stmts = append(stmts, struct {
			q    string
			args []any
		}{`INSERT OR REPLACE INTO state (k, v) VALUES (?, ?)`, []any{k, v}})
	}
	for _, s := range stmts {
		if _, err := c.tx.Exec(s.q, s.args...); err != nil {
			return err
		}
	}
	if err := c.commitLocked(); err != nil {
		return err
	}
	c.done, c.rescans = true, rescans
	return nil
}

// MarkOpeningDone records that the remote server already holds the epoch's
// first complete snapshot, which a crash kept this cache from noting.
func (c *Cache) MarkOpeningDone() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.execLocked(`UPDATE epoch SET opening_done = 1 WHERE id = ?`, c.epoch.EpochID); err != nil {
		return err
	}
	c.done = true
	return c.commitLocked()
}

// RemoveOthers deletes the cache files of every other epoch of the surface,
// once this epoch's opening run is complete.
func RemoveOthers(dir, keepEpochID string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var firstErr error
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, keepEpochID+".db") {
			continue
		}
		if strings.Contains(name, ".db") {
			if err := os.Remove(filepath.Join(dir, name)); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
