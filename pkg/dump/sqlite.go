package dump

import (
	"archive/tar"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/model"
	_ "modernc.org/sqlite" // the "sqlite" database/sql driver, pure Go
)

// SQLite. A database that is being written cannot be copied as a file: cp
// reads pages from different moments (a torn copy), and in WAL mode the
// newest committed transactions live in the -wal file, not the database, so
// copying the main file alone loses them. The engine's own answer is to read
// the database inside one transaction and write that out: VACUUM INTO. It
// takes a single read transaction, so the copy is exactly one committed state,
// includes what is still in the WAL, does not block writers in WAL mode, and
// comes out compacted. The copy is then checked with PRAGMA integrity_check
// before a byte of it is uploaded.
//
// The snapshot is a tar of that database file and the manifest. Restoring it
// needs nothing from SafeGrd but the key: decrypt, untar, and it is a SQLite
// database.

const sqliteDBEntry = "sqlite/database.sqlite"

// sqliteHeader starts every SQLite 3 database file.
var sqliteHeader = []byte("SQLite format 3\x00")

// IsSQLiteURL reports whether u names a SQLite database: sqlite:///abs/path.db
// or sqlite:relative/path.db.
func IsSQLiteURL(u string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(u)), "sqlite:")
}

// SQLitePath is the file a sqlite: URL names, made absolute.
func SQLitePath(u string) (string, error) {
	u = strings.TrimSpace(u)
	if !IsSQLiteURL(u) {
		return "", fmt.Errorf("not a sqlite: URL: %q", u)
	}
	p := u[len("sqlite:"):]
	if strings.HasPrefix(p, "//") {
		p = p[2:] // sqlite:///abs -> /abs; sqlite://rel -> rel
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return "", fmt.Errorf("sqlite URL %q: options are not supported; name the database file only", u)
	}
	if p == "" {
		return "", fmt.Errorf("sqlite URL %q names no file", u)
	}
	return filepath.Abs(p)
}

// sqliteWorkPrefix names the private directories a backup, drill or restore
// writes its plaintext copy into, with the owning process id, so a later run
// can tell a leftover from one in use.
const sqliteWorkPrefix = ".safegrd-sqlite-"

// sqliteWorkMaxAge is when a leftover is removed even if its process cannot
// be checked.
const sqliteWorkMaxAge = 24 * time.Hour

// sqliteWorkDir makes a private (0700) directory under parent (the system
// temporary directory when empty) for one plaintext copy, after removing any
// left there by a process that is gone. A process killed mid-backup (SIGKILL,
// the OOM killer) never runs its deferred cleanup; without this sweep its
// copy of the database would stay on disk.
func sqliteWorkDir(parent string) (string, error) {
	if parent == "" {
		parent = os.TempDir()
	}
	sweepSQLiteWork(parent)
	return os.MkdirTemp(parent, fmt.Sprintf("%s%d-", sqliteWorkPrefix, os.Getpid()))
}

// sweepSQLiteWork removes work directories under parent whose process is no
// longer running, or that are older than sqliteWorkMaxAge.
func sweepSQLiteWork(parent string) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !strings.HasPrefix(name, sqliteWorkPrefix) {
			continue
		}
		pidPart, _, _ := strings.Cut(strings.TrimPrefix(name, sqliteWorkPrefix), "-")
		pid, err := strconv.Atoi(pidPart)
		stale := err == nil && pid != os.Getpid() && processGone(pid)
		if info, ierr := e.Info(); ierr == nil && time.Since(info.ModTime()) > sqliteWorkMaxAge {
			stale = true
		}
		if stale {
			_ = os.RemoveAll(filepath.Join(parent, name))
		}
	}
}

// openSQLite opens path through the pure-Go driver. readOnly never creates a
// file, and a busy timeout lets a backup wait out a writer holding a lock.
func openSQLite(path string, readOnly bool) (*sql.DB, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(30000)")
	if readOnly {
		q.Set("mode", "ro")
	}
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// checkSQLiteFile refuses anything that is not an existing SQLite database, so
// a typo is an error and not a new empty database.
func checkSQLiteFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("SQLite database %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("SQLite database %s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("SQLite database %s: %w", path, err)
	}
	defer f.Close()
	head := make([]byte, len(sqliteHeader))
	if _, err := io.ReadFull(f, head); err != nil || !bytes.Equal(head, sqliteHeader) {
		return fmt.Errorf("%s is not a SQLite 3 database (its first bytes are not the SQLite header)", path)
	}
	return nil
}

// sqliteIntegrity runs PRAGMA integrity_check and returns what it found, or
// "ok".
func sqliteIntegrity(ctx context.Context, db *sql.DB) (string, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var found []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return "", err
		}
		found = append(found, line)
		if len(found) == 10 {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return strings.Join(found, "; "), nil
}

func quoteSQLiteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// sqliteTables counts the rows of every user table, in name order.
func sqliteTables(ctx context.Context, db *sql.DB) ([]model.TableStat, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite\_%' ESCAPE '\' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	stats := make([]model.TableStat, 0, len(names))
	for _, n := range names {
		var count int64
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+quoteSQLiteIdent(n)).Scan(&count); err != nil {
			return nil, fmt.Errorf("counting %s: %w", n, err)
		}
		stats = append(stats, model.TableStat{Schema: "main", TableName: n, RowCount: count})
	}
	return stats, nil
}

// SQLiteDumper backs up one SQLite database file.
type SQLiteDumper struct {
	databaseURL string
	Warn        func(string)
}

// NewSQLiteDumper creates a dumper for a sqlite: URL.
func NewSQLiteDumper(databaseURL string) *SQLiteDumper {
	return &SQLiteDumper{databaseURL: databaseURL, Warn: func(msg string) { fmt.Fprintf(os.Stderr, "⚠️  %s\n", msg) }}
}

// Dump writes a consistent copy of the database and its manifest to dst.
func (d *SQLiteDumper) Dump(ctx context.Context, databaseName string, dst io.Writer) (*model.SnapshotMetadata, error) {
	started := time.Now().UTC()
	start := time.Now()
	path, err := SQLitePath(d.databaseURL)
	if err != nil {
		return nil, err
	}
	if err := checkSQLiteFile(path); err != nil {
		return nil, err
	}
	src, err := openSQLite(path, true)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	var journal, version string
	if err := src.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		return nil, fmt.Errorf("reading %s: %w (the backup needs read access to the database, and in WAL mode to its -shm file)", path, err)
	}
	_ = src.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&version)
	if !strings.EqualFold(journal, "wal") {
		d.Warn(fmt.Sprintf("%s is in %s journal mode: while the backup reads it, writers wait. WAL mode (PRAGMA journal_mode=WAL) lets them carry on.", path, journal))
	}

	// A private directory for the copy: it is the plaintext database.
	tmpDir, err := sqliteWorkDir("")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	copyPath := filepath.Join(tmpDir, "copy.sqlite")
	if _, err := src.ExecContext(ctx, "VACUUM INTO ?", copyPath); err != nil {
		return nil, fmt.Errorf("copying %s with VACUUM INTO: %w (it needs free space in %s about the size of the database; set TMPDIR to use another disk)", path, err, os.TempDir())
	}
	_ = src.Close()

	cp, err := openSQLite(copyPath, true)
	if err != nil {
		return nil, err
	}
	defer cp.Close()
	integrity, err := sqliteIntegrity(ctx, cp)
	if err != nil {
		return nil, fmt.Errorf("checking the copy of %s: %w", path, err)
	}
	if integrity != "ok" {
		return nil, fmt.Errorf("%s fails PRAGMA integrity_check (%s): the database is damaged, so this copy was not stored. "+
			"Earlier snapshots are unaffected; restore from the newest one that passed", path, integrity)
	}
	stats, err := sqliteTables(ctx, cp)
	if err != nil {
		return nil, err
	}
	_ = cp.Close()

	f, err := os.Open(copyPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(dst)
	if err := tw.WriteHeader(&tar.Header{Name: sqliteDBEntry, Mode: 0o600, Size: fi.Size(), ModTime: started, Typeflag: tar.TypeReg}); err != nil {
		return nil, err
	}
	if _, err := io.Copy(tw, f); err != nil {
		return nil, err
	}
	meta := &model.SnapshotMetadata{
		SurfaceType:   model.SurfaceTypeSQLite,
		CreatedAt:     started,
		DatabaseName:  databaseName,
		ServerVersion: "SQLite " + version,
		SchemaSource:  "sqlite VACUUM INTO",
		TableStats:    stats,
	}
	if meta.DatabaseName == "" {
		meta.DatabaseName = filepath.Base(path)
	}
	for i := range meta.TableStats {
		meta.TableStats[i].SizeBytes = 0
	}
	meta.CalculateTotals()
	meta.DurationMs = elapsedMilliseconds(start)
	manifest, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeTarEntry(tw, entryManifest, manifest); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return meta, nil
}

// sqliteArchive reads a SQLite snapshot: it writes the database entry to
// dbPath and returns the manifest.
func sqliteArchive(src io.Reader, dbPath string) (*model.SnapshotMetadata, bool, error) {
	var manifest *model.SnapshotMetadata
	sawDB := false
	tr := tar.NewReader(src)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return manifest, sawDB, err
		}
		switch hdr.Name {
		case sqliteDBEntry:
			f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return manifest, sawDB, err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return manifest, sawDB, err
			}
			if err := f.Sync(); err != nil {
				f.Close()
				return manifest, sawDB, err
			}
			if err := f.Close(); err != nil {
				return manifest, sawDB, err
			}
			sawDB = true
		case entryManifest:
			data, err := io.ReadAll(tr)
			if err != nil {
				return manifest, sawDB, err
			}
			var m model.SnapshotMetadata
			if err := json.Unmarshal(data, &m); err != nil {
				return manifest, sawDB, fmt.Errorf("the archive's manifest is unreadable: %w", err)
			}
			manifest = &m
		}
	}
	return manifest, sawDB, nil
}

// InspectSQLiteArchive is the Fire Drill for a SQLite snapshot, and it is a
// real restore: the database is written out, opened by the SQLite engine,
// checked with PRAGMA integrity_check, and every table's rows counted against
// the manifest.
func InspectSQLiteArchive(ctx context.Context, src io.Reader) (*DryRestoreResult, error) {
	start := time.Now()
	result := &DryRestoreResult{Passed: true}
	tmpDir, err := sqliteWorkDir("")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	dbPath := filepath.Join(tmpDir, "restored.sqlite")
	manifest, sawDB, err := sqliteArchive(src, dbPath)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		result.Passed = false
		result.ErrorMessage = fmt.Sprintf("failed reading the archive: %v", err)
		return result, nil
	}
	add := func(a model.AssertionResult) {
		result.Assertions = append(result.Assertions, a)
		if !a.Passed {
			result.Passed = false
		}
	}
	add(model.AssertionResult{Name: "Manifest Catalog Integrity", Passed: manifest != nil,
		Expected: "manifest.json present", Actual: fmt.Sprintf("present: %v", manifest != nil)})
	add(model.AssertionResult{Name: "Database Present", Passed: sawDB,
		Expected: sqliteDBEntry + " present", Actual: fmt.Sprintf("present: %v", sawDB)})
	if manifest == nil || !sawDB {
		result.ErrorMessage = "the archive is missing its manifest or its database"
		return result, nil
	}
	result.Manifest = manifest
	result.DatabaseName = manifest.DatabaseName
	add(SchemaFidelity(manifest))
	if err := checkSQLiteFile(dbPath); err != nil {
		add(model.AssertionResult{Name: "SQLite Header", Expected: "SQLite format 3", Actual: err.Error()})
		return result, nil
	}
	db, err := openSQLite(dbPath, true)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	integrity, err := sqliteIntegrity(ctx, db)
	if err != nil {
		integrity = err.Error()
	}
	add(model.AssertionResult{Name: "PRAGMA integrity_check", Passed: integrity == "ok", Expected: "ok", Actual: integrity})
	stats, err := sqliteTables(ctx, db)
	if err != nil {
		add(model.AssertionResult{Name: "Tables Readable", Expected: "every table counts", Actual: err.Error()})
		return result, nil
	}
	got := map[string]int64{}
	for _, t := range stats {
		got[t.TableName] = t.RowCount
		result.Tables = append(result.Tables, TableDryStats{Schema: t.Schema, TableName: t.TableName, RowCount: t.RowCount})
		result.TotalRows += t.RowCount
	}
	result.TotalTables = len(result.Tables)
	if fi, err := os.Stat(dbPath); err == nil {
		result.TotalDataBytes = fi.Size()
	}
	add(model.AssertionResult{Name: "Table Count Match", Passed: result.TotalTables == manifest.TotalTables,
		Expected: fmt.Sprintf("%d tables", manifest.TotalTables), Actual: fmt.Sprintf("%d tables", result.TotalTables)})
	add(model.AssertionResult{Name: "Total Row Count Match", Passed: result.TotalRows == manifest.TotalRows,
		Expected: fmt.Sprintf("%d rows", manifest.TotalRows), Actual: fmt.Sprintf("%d rows", result.TotalRows)})
	for _, t := range manifest.TableStats {
		n, ok := got[t.TableName]
		if !ok {
			add(model.AssertionResult{Name: "Table Existence: " + t.TableName, Expected: "table in the database", Actual: "missing"})
			continue
		}
		add(model.AssertionResult{Name: "Row Count: " + t.TableName, Passed: n == t.RowCount,
			Expected: fmt.Sprintf("%d rows", t.RowCount), Actual: fmt.Sprintf("%d rows", n)})
	}
	result.DurationMs = elapsedMilliseconds(start)
	return result, nil
}

// SQLiteRestorer writes a SQLite snapshot to a new database file.
type SQLiteRestorer struct {
	targetURL string
}

// NewSQLiteRestorer creates a restorer for a sqlite: URL.
func NewSQLiteRestorer(targetURL string) *SQLiteRestorer {
	return &SQLiteRestorer{targetURL: targetURL}
}

// Restore writes the snapshot's database to the target path, which must not
// exist: a restore never overwrites a database, and a leftover -wal beside it
// would be replayed into the restored file. It is written beside the target,
// checked, and renamed into place, so the target is either absent or whole.
func (r *SQLiteRestorer) Restore(ctx context.Context, src io.Reader) (*model.SnapshotMetadata, error) {
	target, err := SQLitePath(r.targetURL)
	if err != nil {
		return nil, err
	}
	if err := SQLiteCheckEmpty(target); err != nil {
		return nil, err
	}
	dir := filepath.Dir(target)
	tmpDir, err := sqliteWorkDir(dir)
	if err != nil {
		return nil, fmt.Errorf("restoring into %s: %w", dir, err)
	}
	defer os.RemoveAll(tmpDir)
	staged := filepath.Join(tmpDir, filepath.Base(target))
	manifest, sawDB, err := sqliteArchive(src, staged)
	if err != nil {
		return nil, err
	}
	if !sawDB {
		return nil, errors.New("the snapshot holds no SQLite database")
	}
	db, err := openSQLite(staged, true)
	if err != nil {
		return nil, err
	}
	integrity, err := sqliteIntegrity(ctx, db)
	db.Close()
	if err != nil {
		return nil, err
	}
	if integrity != "ok" {
		return nil, fmt.Errorf("the restored database fails PRAGMA integrity_check: %s", integrity)
	}
	if err := os.Rename(staged, target); err != nil {
		return nil, err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	if manifest == nil {
		manifest = &model.SnapshotMetadata{SurfaceType: model.SurfaceTypeSQLite}
	}
	return manifest, nil
}

// SQLiteCheckEmpty refuses a restore or sandbox target that already holds a
// database, or the journal of one.
func SQLiteCheckEmpty(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if fi, err := os.Stat(p); err == nil && (p != path || fi.Size() > 0) {
			return fmt.Errorf("%s already exists; a restore never overwrites a database. Name a new file, or move this one aside", p)
		}
	}
	return nil
}

// SQLiteResetDatabase deletes a sandbox database a drill restored.
func SQLiteResetDatabase(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// SQLiteCountRows counts the rows of the manifest's tables in a restored
// database.
func SQLiteCountRows(ctx context.Context, path string) (map[string]int64, error) {
	db, err := openSQLite(path, true)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	stats, err := sqliteTables(ctx, db)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(stats))
	for _, t := range stats {
		out[t.TableName] = t.RowCount
	}
	return out, nil
}

// SameSQLiteDatabase reports whether two sqlite: URLs name the same file.
func SameSQLiteDatabase(a, b string) bool {
	pa, errA := SQLitePath(a)
	pb, errB := SQLitePath(b)
	if errA != nil || errB != nil {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	if ra, err := filepath.EvalSymlinks(pa); err == nil {
		pa = ra
	}
	if rb, err := filepath.EvalSymlinks(pb); err == nil {
		pb = rb
	}
	return pa == pb
}

// PingSQLite opens a SQLite surface read-only and reads its schema version.
func PingSQLite(ctx context.Context, databaseURL string) error {
	path, err := SQLitePath(databaseURL)
	if err != nil {
		return err
	}
	if err := checkSQLiteFile(path); err != nil {
		return err
	}
	db, err := openSQLite(path, true)
	if err != nil {
		return err
	}
	defer db.Close()
	var v int
	return db.QueryRowContext(ctx, "PRAGMA schema_version").Scan(&v)
}

// SQLiteJournalMode reads a SQLite surface's journal mode.
func SQLiteJournalMode(ctx context.Context, databaseURL string) (string, error) {
	path, err := SQLitePath(databaseURL)
	if err != nil {
		return "", err
	}
	db, err := openSQLite(path, true)
	if err != nil {
		return "", err
	}
	defer db.Close()
	var mode string
	err = db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode)
	return mode, err
}
