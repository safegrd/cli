package dump

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/safegrd/cli/pkg/model"
)

// A MySQL or MariaDB snapshot is the output of the server's
// own dump tool, which knows every object the server has; the lesson of the Postgres
// engine is not to re-derive a schema. The archive is, in order:
//
//	mysql/dump.sql[.N] mysqldump (or mariadb-dump) output, in chunks
//	manifest.json      every table's exact row count, parsed from the dump
//
// The counts come from the dump itself rather than from COUNT(*) run beside
// it, because mysqldump reads in its own consistent snapshot and a count
// taken outside it disagrees with the archive on any busy table.
const (
	mysqlDumpEntry = "mysql/dump.sql"
	// mysqlDumpDone is the last line of every complete dump. Its absence is a
	// dump that stopped part way, however cleanly the process exited.
	mysqlDumpDone = "-- Dump completed"
)

// IsMySQLURL reports whether a connection string names a MySQL or MariaDB
// database: mysql://user:pass@host:3306/db or mariadb://…
func IsMySQLURL(u string) bool {
	return strings.HasPrefix(u, "mysql://") || strings.HasPrefix(u, "mariadb://")
}

// mysqlTarget is a parsed mysql:// URL.
type mysqlTarget struct {
	User, Password, Host string
	Port                 int
	Database             string
	TLS                  string // "", "true", "skip-verify", "preferred"
	CAFile               string
}

func parseMySQLURL(raw string) (*mysqlTarget, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "mysql" && u.Scheme != "mariadb") {
		return nil, fmt.Errorf("not a mysql:// URL")
	}
	t := &mysqlTarget{Host: u.Hostname(), Port: 3306, Database: strings.TrimPrefix(u.Path, "/")}
	if t.Host == "" {
		t.Host = "127.0.0.1"
	}
	if p := u.Port(); p != "" {
		if t.Port, err = strconv.Atoi(p); err != nil {
			return nil, fmt.Errorf("bad port %q", p)
		}
	}
	if u.User != nil {
		t.User = u.User.Username()
		t.Password, _ = u.User.Password()
	}
	q := u.Query()
	t.TLS, t.CAFile = q.Get("tls"), q.Get("ssl-ca")
	if t.CAFile != "" && t.TLS == "" {
		t.TLS = "true"
	}
	switch t.TLS {
	case "", "false", "true", "skip-verify", "preferred":
	default:
		return nil, fmt.Errorf("tls=%s: use true, skip-verify, preferred or false", t.TLS)
	}
	if t.Database == "" {
		return nil, fmt.Errorf("the URL names no database: mysql://user:password@host:3306/<database>")
	}
	return t, nil
}

var registerTLSOnce sync.Map

// open connects with the Go driver, for catalogue queries and counts.
func (t *mysqlTarget) open() (*sql.DB, error) {
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net = t.User, t.Password, "tcp"
	cfg.Addr = fmt.Sprintf("%s:%d", t.Host, t.Port)
	cfg.DBName = t.Database
	switch {
	case t.CAFile != "":
		name := "safegrd-" + t.CAFile
		if _, done := registerTLSOnce.LoadOrStore(name, true); !done {
			pem, err := os.ReadFile(t.CAFile)
			if err != nil {
				return nil, fmt.Errorf("reading ssl-ca %s: %w", t.CAFile, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("no certificates in ssl-ca %s", t.CAFile)
			}
			if err := mysql.RegisterTLSConfig(name, &tls.Config{RootCAs: pool, ServerName: t.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return nil, err
			}
		}
		cfg.TLSConfig = name
	case t.TLS != "" && t.TLS != "false":
		cfg.TLSConfig = t.TLS
	}
	return sql.Open("mysql", cfg.FormatDSN())
}

// defaultsFile writes the client's connection options, the password among
// them, to a 0600 file in a private directory, for --defaults-extra-file. A
// password on the command line is readable by every user on the host. Options
// only one of MySQL's and MariaDB's clients knows are written loose-, which
// the other skips instead of refusing to start.
func (t *mysqlTarget) defaultsFile() (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "safegrd-mysql-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	quote := func(v string) (string, error) {
		v = strings.ReplaceAll(v, `\`, `\\`)
		switch {
		case !strings.Contains(v, `"`):
			return `"` + v + `"`, nil
		case !strings.Contains(v, `'`):
			return `'` + v + `'`, nil
		}
		return "", fmt.Errorf("a MySQL password containing both ' and \" cannot be passed to the client safely")
	}
	var b strings.Builder
	b.WriteString("[client]\n")
	for k, v := range map[string]string{"user": t.User, "password": t.Password, "host": t.Host} {
		if v == "" {
			continue
		}
		q, err := quote(v)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		fmt.Fprintf(&b, "%s=%s\n", k, q)
	}
	fmt.Fprintf(&b, "port=%d\nprotocol=TCP\n", t.Port)
	// A row mysqldump could write (its default allows 24 MB) must be one the
	// mysql client can read back (its default is 16 MB). The server's own
	// max_allowed_packet still applies, and is the customer's to set.
	b.WriteString("loose-max-allowed-packet=1G\n")
	switch {
	case t.CAFile != "":
		fmt.Fprintf(&b, "loose-ssl-ca=%q\nloose-ssl-mode=VERIFY_IDENTITY\nloose-ssl=1\nloose-ssl-verify-server-cert=1\n", t.CAFile)
	case t.TLS == "true", t.TLS == "skip-verify":
		b.WriteString("loose-ssl-mode=REQUIRED\nloose-ssl=1\n")
	case t.TLS == "preferred":
		b.WriteString("loose-ssl-mode=PREFERRED\n")
	case t.TLS == "false":
		b.WriteString("loose-ssl-mode=DISABLED\nloose-skip-ssl=1\n")
	}
	// MySQL's mysqldump: no GTID_PURGED line a restore into a server with
	// GTIDs would refuse, and no column statistics MariaDB does not have.
	b.WriteString("[mysqldump]\nloose-set-gtid-purged=OFF\nloose-column-statistics=0\n")
	path = filepath.Join(dir, "client.cnf")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

// MySQLTool is a located mysqldump/mariadb-dump or mysql/mariadb client.
type MySQLTool struct {
	Path, Version string
	MariaDB       bool
}

func (t *MySQLTool) String() string {
	return filepath.Base(t.Path) + " " + t.Version
}

var mysqlToolVersionRe = regexp.MustCompile(`(?:Distrib |Ver |from )(\d+\.\d+(?:\.\d+)?)`)

// findMySQLTool finds a dump tool ("dump") or client ("client"), preferring
// one from the same project as the server: MySQL's mysqldump against MariaDB
// asks for column statistics MariaDB has not got, and the reverse misses
// MySQL 8's newer DDL.
func findMySQLTool(ctx context.Context, kind string, serverIsMariaDB bool) (*MySQLTool, error) {
	env, names := "SAFEGRD_MYSQLDUMP", []string{"mysqldump", "mariadb-dump"}
	if kind == "client" {
		env, names = "SAFEGRD_MYSQL", []string{"mysql", "mariadb"}
	}
	var candidates []string
	if p := os.Getenv(env); p != "" {
		candidates = []string{p}
	} else {
		for _, n := range names {
			if p, err := exec.LookPath(n); err == nil {
				candidates = append(candidates, p)
			}
		}
		var dirs []string
		if runtime.GOOS == "darwin" {
			dirs = append(dirs, "/opt/homebrew/opt/mysql-client/bin", "/opt/homebrew/opt/mysql-client@*/bin",
				"/opt/homebrew/opt/mariadb/bin", "/usr/local/opt/mysql-client/bin", "/usr/local/opt/mariadb/bin")
		}
		dirs = append(dirs, "/usr/bin", "/usr/local/mysql/bin")
		for _, d := range dirs {
			m, _ := filepath.Glob(d)
			for _, dir := range m {
				for _, n := range names {
					candidates = append(candidates, filepath.Join(dir, n))
				}
			}
		}
	}
	var found []*MySQLTool
	seen := map[string]bool{}
	for _, p := range candidates {
		real, err := filepath.EvalSymlinks(p)
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		out, err := exec.CommandContext(ctx, p, "--version").CombinedOutput()
		if err != nil {
			continue
		}
		v := ""
		if m := mysqlToolVersionRe.FindStringSubmatch(string(out)); m != nil {
			v = m[1]
		}
		found = append(found, &MySQLTool{Path: p, Version: v, MariaDB: strings.Contains(string(out), "MariaDB")})
	}
	if len(found) == 0 {
		if p := os.Getenv(env); p != "" {
			return nil, fmt.Errorf("%s=%s is not a working %s", env, p, names[0])
		}
		pkg := "the MySQL client (mysql-client, or mariadb-client for MariaDB)"
		return nil, fmt.Errorf("no %s found: install %s, or set %s", strings.Join(names, " or "), pkg, env)
	}
	sort.SliceStable(found, func(i, j int) bool {
		return found[i].MariaDB == serverIsMariaDB && found[j].MariaDB != serverIsMariaDB
	})
	return found[0], nil
}

// mysqlServer asks the server what it is.
func mysqlServer(ctx context.Context, db *sql.DB) (version string, mariaDB bool, err error) {
	if err = db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		return "", false, err
	}
	return version, strings.Contains(strings.ToLower(version), "mariadb"), nil
}

// MySQLDumper streams a MySQL or MariaDB database into a snapshot archive.
type MySQLDumper struct {
	databaseURL string
	Warn        func(string)
}

// NewMySQLDumper creates a dumper for a mysql:// URL.
func NewMySQLDumper(databaseURL string) *MySQLDumper {
	return &MySQLDumper{databaseURL: databaseURL, Warn: func(msg string) { fmt.Fprintf(os.Stderr, "⚠️  %s\n", msg) }}
}

// Dump runs the server's dump tool and streams its output into the archive,
// counting every table's rows as they pass.
func (d *MySQLDumper) Dump(ctx context.Context, databaseName string, dst io.Writer) (*model.SnapshotMetadata, error) {
	// When the snapshot was taken. The file and mail collectors always set it;
	// the database engines did not, so every database meta.json carried the
	// zero time and the remote server ordered those snapshots as year 1.
	started := time.Now().UTC()
	start := time.Now()
	target, err := parseMySQLURL(d.databaseURL)
	if err != nil {
		return nil, err
	}
	db, err := target.open()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	version, mariaDB, err := mysqlServer(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the database: %w", err)
	}
	sizes := map[string]int64{}
	if rows, err := db.QueryContext(ctx, `SELECT table_name, COALESCE(data_length, 0) + COALESCE(index_length, 0)
		FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'`); err == nil {
		for rows.Next() {
			var n string
			var sz int64
			if rows.Scan(&n, &sz) == nil {
				sizes[n] = sz
			}
		}
		rows.Close()
	}

	// A trigger created through a multi-statement API is stored with its
	// trailing ';', and mysqldump writes it back as "...; */;;", which no
	// server will load. The dump succeeds and the restore fails, so say so
	// now, by name, while it can still be fixed.
	if rows, err := db.QueryContext(ctx, `SELECT trigger_name FROM information_schema.triggers
		WHERE trigger_schema = DATABASE() AND TRIM(TRAILING '\n' FROM TRIM(action_statement)) LIKE '%;'`); err == nil {
		var bad []string
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				bad = append(bad, n)
			}
		}
		rows.Close()
		if len(bad) > 0 {
			d.Warn(fmt.Sprintf("trigger(s) %s end with ';' inside their body, which mysqldump writes out in a form no server "+
				"will restore: this snapshot's restore will fail at them. Recreate each without the trailing semicolon "+
				"(SHOW CREATE TRIGGER shows the body). A sandbox drill (drill.sandbox_url) catches this; the in-memory drill cannot",
				strings.Join(bad, ", ")))
		}
	}

	tool, err := findMySQLTool(ctx, "dump", mariaDB)
	if err != nil {
		return nil, err
	}
	if tool.MariaDB != mariaDB {
		d.Warn(fmt.Sprintf("dumping a %s server with %s: install the matching client for a dump its own server restores without surprises",
			map[bool]string{true: "MariaDB", false: "MySQL"}[mariaDB], tool))
	}
	cnf, cleanup, err := target.defaultsFile()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// --defaults-extra-file must come first, or the client ignores it.
	cmd := exec.CommandContext(ctx, tool.Path, "--defaults-extra-file="+cnf,
		"--single-transaction", "--quick", "--routines", "--triggers", "--events",
		"--hex-blob", "--no-tablespaces", "--default-character-set=utf8mb4",
		target.Database)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", tool, err)
	}
	tw := tar.NewWriter(dst)
	cw := &chunkWriter{tw: tw, name: mysqlChunkName}
	counter := newMySQLDumpCounter()
	_, copyErr := io.Copy(io.MultiWriter(cw, counter), stdout)
	waitErr := cmd.Wait()
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		return nil, fmt.Errorf("%s failed: %v: %s", tool, waitErr, msg)
	}
	if copyErr != nil {
		return nil, fmt.Errorf("writing the dump to the archive: %w", copyErr)
	}
	// mysqldump reports some failures on stderr and still exits 0 (MySQL 9
	// does, for masking policies a non-admin cannot read). Pass them on.
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		d.Warn(fmt.Sprintf("%s said, while succeeding: %s", tool, msg))
	}
	if !counter.Completed {
		return nil, fmt.Errorf("%s exited cleanly but its output ends before %q: the dump is incomplete", tool, mysqlDumpDone)
	}
	if err := cw.Close(); err != nil {
		return nil, err
	}

	meta := &model.SnapshotMetadata{
		SurfaceType:   model.SurfaceTypeMySQL,
		CreatedAt:     started,
		DatabaseName:  databaseName,
		ServerVersion: version,
		SchemaSource:  tool.String(),
	}
	if meta.DatabaseName == "" {
		meta.DatabaseName = target.Database
	}
	for _, t := range counter.Tables() {
		meta.TableStats = append(meta.TableStats, model.TableStat{
			Schema: target.Database, TableName: t, RowCount: counter.Rows[t], SizeBytes: sizes[t],
		})
	}
	meta.CalculateTotals()
	meta.DurationMs = time.Since(start).Milliseconds()
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

func mysqlChunkName(part int) string {
	if part == 0 {
		return mysqlDumpEntry
	}
	return mysqlDumpEntry + "." + strconv.Itoa(part)
}

func parseMySQLChunk(name string) (string, string, int, bool) {
	if name == mysqlDumpEntry {
		return "", "dump", 0, true
	}
	rest, ok := strings.CutPrefix(name, mysqlDumpEntry+".")
	if !ok {
		return "", "", 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 1 {
		return "", "", 0, false
	}
	return "", "dump", n, true
}

// mysqlDumpCounter reads mysqldump output as it streams past and counts each
// table's rows: every parenthesised tuple at the top level of an
// INSERT INTO `t` VALUES statement, outside quoted strings. It is an
// io.Writer so the dump, the drill and the restore can all feed it.
type mysqlDumpCounter struct {
	Rows      map[string]int64
	created   []string
	Completed bool
	// inRoutine is set between "DELIMITER ;;" and "DELIMITER ;", where
	// mysqldump writes routine, trigger and event bodies: an INSERT there is
	// code, not rows.
	inRoutine bool

	state  int
	line   []byte
	table  string
	depth  int
	quote  byte
	escape bool
	seek   int
}

const (
	mcLine    = iota // collecting the start of a line
	mcSkip           // ignoring the rest of a line
	mcSeek           // after INSERT INTO `t`, waiting for VALUES
	mcValues         // counting tuples
	mcTrailer        // after the statement's ';', until the newline
)

var mysqlValuesWord = []byte("VALUES")

func newMySQLDumpCounter() *mysqlDumpCounter {
	return &mysqlDumpCounter{Rows: map[string]int64{}}
}

// Tables lists every table the dump created, in order.
func (c *mysqlDumpCounter) Tables() []string { return c.created }

func (c *mysqlDumpCounter) Write(p []byte) (int, error) {
	for _, b := range p {
		switch c.state {
		case mcLine:
			if b == '\n' {
				c.endShortLine()
				continue
			}
			c.line = append(c.line, b)
			if len(c.line) > 512 {
				c.state = mcSkip
				c.line = c.line[:0]
				continue
			}
			if c.inRoutine {
				continue
			}
			if name, ok := insertTable(c.line); ok {
				c.table, c.state, c.seek = name, mcSeek, 0
				c.line = c.line[:0]
			}
		case mcSkip, mcTrailer:
			if b == '\n' {
				c.state = mcLine
			}
		case mcSeek:
			if b == mysqlValuesWord[c.seek] {
				c.seek++
				if c.seek == len(mysqlValuesWord) {
					c.state, c.depth, c.quote, c.escape = mcValues, 0, 0, false
				}
			} else if b == mysqlValuesWord[0] {
				c.seek = 1
			} else {
				c.seek = 0
			}
		case mcValues:
			switch {
			case c.quote != 0:
				if c.escape {
					c.escape = false
				} else if b == '\\' {
					c.escape = true
				} else if b == c.quote {
					c.quote = 0
				}
			case b == '\'' || b == '"':
				c.quote = b
			case b == '(':
				if c.depth == 0 {
					c.Rows[c.table]++
				}
				c.depth++
			case b == ')':
				c.depth--
			case b == ';' && c.depth == 0:
				c.state = mcTrailer
			}
		}
	}
	return len(p), nil
}

var createTableRe = regexp.MustCompile("^CREATE TABLE `((?:[^`]|``)+)` \\($")

func (c *mysqlDumpCounter) endShortLine() {
	line := string(c.line)
	c.line = c.line[:0]
	if strings.HasPrefix(line, mysqlDumpDone) {
		c.Completed = true
	}
	if strings.HasPrefix(line, "DELIMITER ") {
		c.inRoutine = strings.TrimSpace(line) != "DELIMITER ;"
	}
	if m := createTableRe.FindStringSubmatch(line); m != nil {
		name := strings.ReplaceAll(m[1], "``", "`")
		if _, seen := c.Rows[name]; !seen {
			c.Rows[name] = 0
			c.created = append(c.created, name)
		}
	}
}

// insertTable recognises "INSERT INTO `name`" once the closing backtick has
// arrived.
func insertTable(prefix []byte) (string, bool) {
	const head = "INSERT INTO `"
	if len(prefix) <= len(head) || string(prefix[:len(head)]) != head {
		return "", false
	}
	rest := prefix[len(head):]
	var name []byte
	for i := 0; i < len(rest); i++ {
		if rest[i] != '`' {
			name = append(name, rest[i])
			continue
		}
		if i+1 < len(rest) && rest[i+1] == '`' {
			name = append(name, '`')
			i++
			continue
		}
		if i+1 == len(rest) {
			return "", false // might be the first of a doubled backtick
		}
		return string(name), true
	}
	return "", false
}

// mysqlArchive reads a MySQL snapshot archive, handing the dump to consume as
// one stream and returning the manifest.
func mysqlArchive(src io.Reader, consume func(io.Reader) error) (*model.SnapshotMetadata, bool, error) {
	var manifest *model.SnapshotMetadata
	sawDump := false
	streams := &tableStreams{
		parse: parseMySQLChunk,
		consume: func(_, _ string, r io.Reader) error {
			sawDump = true
			return consume(r)
		},
		other: func(hdr *tar.Header, r io.Reader) error {
			if hdr.Name != entryManifest {
				return nil
			}
			data, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			var m model.SnapshotMetadata
			if err := json.Unmarshal(data, &m); err != nil {
				return fmt.Errorf("the archive's manifest is unreadable: %w", err)
			}
			manifest = &m
			return nil
		},
	}
	err := streams.Run(tar.NewReader(src))
	return manifest, sawDump, err
}

// InspectMySQLArchive is the in-memory Fire Drill for a MySQL snapshot: the
// dump is complete, every table the manifest names is in it, and every
// table's rows match the manifest exactly. Like the Postgres drill, it checks
// the data and not that the schema loads; a sandbox drill does that.
func InspectMySQLArchive(ctx context.Context, src io.Reader) (*DryRestoreResult, error) {
	start := time.Now()
	result := &DryRestoreResult{Passed: true}
	counter := newMySQLDumpCounter()
	var dumpBytes int64
	manifest, sawDump, err := mysqlArchive(src, func(r io.Reader) error {
		n, err := io.Copy(counter, r)
		dumpBytes = n
		return err
	})
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
	add(model.AssertionResult{Name: "Dump Present", Passed: sawDump,
		Expected: mysqlDumpEntry + " present", Actual: fmt.Sprintf("present: %v", sawDump)})
	add(model.AssertionResult{Name: "Dump Complete", Passed: counter.Completed,
		Expected: "the dump ends with its completion line", Actual: fmt.Sprintf("complete: %v", counter.Completed)})
	if manifest == nil {
		result.ErrorMessage = "archive is missing manifest.json"
		return result, nil
	}
	result.Manifest = manifest
	result.DatabaseName = manifest.DatabaseName
	add(SchemaFidelity(manifest))

	for _, t := range counter.Tables() {
		result.Tables = append(result.Tables, TableDryStats{Schema: manifest.DatabaseName, TableName: t, RowCount: counter.Rows[t]})
		result.TotalRows += counter.Rows[t]
	}
	result.TotalTables = len(result.Tables)
	result.TotalDataBytes = dumpBytes
	add(model.AssertionResult{Name: "Table Count Match", Passed: result.TotalTables == manifest.TotalTables,
		Expected: fmt.Sprintf("%d tables", manifest.TotalTables), Actual: fmt.Sprintf("%d tables", result.TotalTables)})
	add(model.AssertionResult{Name: "Total Row Count Match", Passed: result.TotalRows == manifest.TotalRows,
		Expected: fmt.Sprintf("%d rows", manifest.TotalRows), Actual: fmt.Sprintf("%d rows", result.TotalRows)})
	for _, t := range manifest.TableStats {
		got, ok := counter.Rows[t.TableName]
		if !ok {
			add(model.AssertionResult{Name: "Table Existence: " + t.TableName, Expected: "table in the dump", Actual: "missing"})
			continue
		}
		add(model.AssertionResult{Name: "Row Count: " + t.TableName, Passed: got == t.RowCount,
			Expected: fmt.Sprintf("%d rows", t.RowCount), Actual: fmt.Sprintf("%d rows", got)})
	}
	result.DurationMs = time.Since(start).Milliseconds()
	return result, nil
}

// MySQLRestorer loads a MySQL snapshot into an empty database.
type MySQLRestorer struct {
	targetURL string
	Warn      func(string)
}

// NewMySQLRestorer creates a restorer for a mysql:// URL.
func NewMySQLRestorer(targetURL string) *MySQLRestorer {
	return &MySQLRestorer{targetURL: targetURL, Warn: func(msg string) { fmt.Fprintf(os.Stderr, "⚠️  %s\n", msg) }}
}

// Restore pipes the dump into the server's own client, then holds every
// table's row count to the manifest. MySQL commits DDL as it goes, so unlike
// a Postgres restore a failure can leave part of the database behind; the
// error says so.
func (r *MySQLRestorer) Restore(ctx context.Context, src io.Reader) (*model.SnapshotMetadata, error) {
	target, err := parseMySQLURL(r.targetURL)
	if err != nil {
		return nil, err
	}
	db, err := target.open()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := MySQLCheckEmpty(ctx, db); err != nil {
		return nil, err
	}
	_, mariaDB, err := mysqlServer(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the restore target: %w", err)
	}
	tool, err := findMySQLTool(ctx, "client", mariaDB)
	if err != nil {
		return nil, err
	}
	cnf, cleanup, err := target.defaultsFile()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	counter := newMySQLDumpCounter()
	var stderr bytes.Buffer
	var definers *definerRewriter
	manifest, sawDump, err := mysqlArchive(src, func(dump io.Reader) error {
		cmd := exec.CommandContext(ctx, tool.Path, "--defaults-extra-file="+cnf,
			"--binary-mode", "--default-character-set=utf8mb4", "--database="+target.Database)
		definers = newDefinerRewriter(io.TeeReader(dump, counter))
		cmd.Stdin = definers
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			msg := strings.TrimSpace(stderr.String())
			if len(msg) > 500 {
				msg = msg[:500] + "..."
			}
			return fmt.Errorf("%s failed: %v: %s. The target may now hold part of the snapshot; drop and recreate it before retrying", tool, err, msg)
		}
		// Drain what the client did not read, so the archive can be finished.
		_, err := io.Copy(counter, dump)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !sawDump || manifest == nil {
		return nil, fmt.Errorf("the archive is not a MySQL snapshot: no dump or no manifest")
	}
	if !counter.Completed {
		return nil, fmt.Errorf("the snapshot's dump is incomplete: it ends before %q", mysqlDumpDone)
	}
	counts, err := MySQLCountRows(ctx, db, manifest)
	if err != nil {
		return nil, err
	}
	for _, t := range manifest.TableStats {
		if counts[t.TableName] != t.RowCount {
			return nil, fmt.Errorf("%s loaded %d rows; the snapshot recorded %d", t.TableName, counts[t.TableName], t.RowCount)
		}
	}
	if definers != nil && definers.rewritten > 0 && r.Warn != nil {
		r.Warn(fmt.Sprintf("%d view, trigger, routine or event definer(s) were set to the restoring user: they now run as it, "+
			"not as the account that created them. Recreating another account's definer needs SET_USER_ID, which managed servers do not grant", definers.rewritten))
	}
	return manifest, nil
}

var definerRe = regexp.MustCompile("DEFINER=`(?:[^`]|``)*`@`(?:[^`]|``)*`")

// definerRewriter sets every DEFINER in a dump to CURRENT_USER as it streams
// to the client. mysqldump keeps each view's, trigger's and routine's creator,
// and recreating an account other than your own needs SET_USER_ID, which RDS
// and its peers do not grant, so the restore fails at the first view. Data
// lines pass through untouched and unbuffered: a DEFINER inside a row is data.
type definerRewriter struct {
	br        *bufio.Reader
	pending   []byte
	inInsert  bool
	atStart   bool
	rewritten int
}

func newDefinerRewriter(r io.Reader) *definerRewriter {
	return &definerRewriter{br: bufio.NewReaderSize(r, 1<<20), atStart: true}
}

func (d *definerRewriter) Read(p []byte) (int, error) {
	for len(d.pending) == 0 {
		chunk, err := d.br.ReadSlice('\n')
		if len(chunk) > 0 {
			line := append([]byte(nil), chunk...)
			if d.atStart {
				d.inInsert = bytes.HasPrefix(line, []byte("INSERT INTO "))
			}
			complete := line[len(line)-1] == '\n'
			if !d.inInsert {
				// A non-data line is small; gather all of it before rewriting.
				for !complete && err == bufio.ErrBufferFull {
					var more []byte
					more, err = d.br.ReadSlice('\n')
					line = append(line, more...)
					complete = len(line) > 0 && line[len(line)-1] == '\n'
				}
				if n := len(definerRe.FindAllIndex(line, -1)); n > 0 {
					d.rewritten += n
					line = definerRe.ReplaceAll(line, []byte("DEFINER=CURRENT_USER"))
				}
			}
			d.atStart = complete
			d.pending = line
		}
		if err != nil && err != bufio.ErrBufferFull {
			if len(d.pending) == 0 {
				return 0, err
			}
			break
		}
	}
	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}

// OpenMySQL opens a mysql:// URL with the Go driver.
func OpenMySQL(databaseURL string) (*sql.DB, error) {
	t, err := parseMySQLURL(databaseURL)
	if err != nil {
		return nil, err
	}
	return t.open()
}

// MySQLCheckEmpty refuses a database that already holds tables or views.
func MySQLCheckEmpty(ctx context.Context, db *sql.DB) error {
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()`).Scan(&n); err != nil {
		return fmt.Errorf("could not inspect the target database: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("the target database already holds %d table(s) or view(s); restore into a new, empty database", n)
	}
	return nil
}

// MySQLCountRows counts every manifest table exactly.
func MySQLCountRows(ctx context.Context, db *sql.DB, m *model.SnapshotMetadata) (map[string]int64, error) {
	out := map[string]int64{}
	for _, t := range m.TableStats {
		var n int64
		q := "SELECT COUNT(*) FROM `" + strings.ReplaceAll(t.TableName, "`", "``") + "`"
		if err := db.QueryRowContext(ctx, q).Scan(&n); err != nil {
			return nil, fmt.Errorf("counting %s: %w", t.TableName, err)
		}
		out[t.TableName] = n
	}
	return out, nil
}

// MySQLResetDatabase drops everything a drill restored into its sandbox:
// tables, views, routines and events. It is only called after
// MySQLCheckEmpty passed, so everything there is the drill's.
func MySQLResetDatabase(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0"); err != nil {
		return err
	}
	type obj struct{ kind, name string }
	var objs []obj
	queries := map[string]string{
		"VIEW":      `SELECT table_name FROM information_schema.views WHERE table_schema = DATABASE()`,
		"TABLE":     `SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'`,
		"PROCEDURE": `SELECT routine_name FROM information_schema.routines WHERE routine_schema = DATABASE() AND routine_type = 'PROCEDURE'`,
		"FUNCTION":  `SELECT routine_name FROM information_schema.routines WHERE routine_schema = DATABASE() AND routine_type = 'FUNCTION'`,
		"EVENT":     `SELECT event_name FROM information_schema.events WHERE event_schema = DATABASE()`,
	}
	for _, kind := range []string{"VIEW", "TABLE", "PROCEDURE", "FUNCTION", "EVENT"} {
		rows, err := conn.QueryContext(ctx, queries[kind])
		if err != nil {
			return err
		}
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				objs = append(objs, obj{kind, n})
			}
		}
		rows.Close()
	}
	for _, o := range objs {
		if _, err := conn.ExecContext(ctx, "DROP "+o.kind+" IF EXISTS `"+strings.ReplaceAll(o.name, "`", "``")+"`"); err != nil {
			return fmt.Errorf("dropping %s %s: %w", strings.ToLower(o.kind), o.name, err)
		}
	}
	return nil
}

// SameMySQLDatabase reports whether two mysql:// URLs name one database.
func SameMySQLDatabase(a, b string) bool {
	ta, errA := parseMySQLURL(a)
	tb, errB := parseMySQLURL(b)
	if errA != nil || errB != nil {
		return false
	}
	norm := func(h string) string {
		if h == "localhost" {
			return "127.0.0.1"
		}
		return strings.ToLower(h)
	}
	return norm(ta.Host) == norm(tb.Host) && ta.Port == tb.Port && ta.Database == tb.Database
}

// MySQLToolsFor finds the dump tool and client for a database, for doctor.
func MySQLToolsFor(ctx context.Context, databaseURL string) (dumpTool, client *MySQLTool, server string, err error) {
	db, err := OpenMySQL(databaseURL)
	if err != nil {
		return nil, nil, "", err
	}
	defer db.Close()
	server, mariaDB, err := mysqlServer(ctx, db)
	if err != nil {
		return nil, nil, "", fmt.Errorf("could not reach the server: %w", err)
	}
	if dumpTool, err = findMySQLTool(ctx, "dump", mariaDB); err != nil {
		return nil, nil, server, err
	}
	if client, err = findMySQLTool(ctx, "client", mariaDB); err != nil {
		return nil, nil, server, err
	}
	return dumpTool, client, server, nil
}
