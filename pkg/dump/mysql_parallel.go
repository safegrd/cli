package dump

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// A MySQL run read over several connections. MySQL has no snapshot one
// session can hand another, so the readers start theirs while nothing can
// commit: one session takes FLUSH TABLES WITH READ LOCK, each reader opens
// START TRANSACTION WITH CONSISTENT SNAPSHOT, the dump tool writes the
// schema, routines, events and views with no rows, and the lock is let go.
// Writes wait for that long and no longer; the rows are then read, a table
// per reader at a time, each in its reader's snapshot, which is the same
// committed state for all of them.
//
// LOCK TABLES ... READ, which the backup account already holds, was tried
// first and is not used: it locks the tables one after another, and a
// transaction writing two of them deadlocks with it; the server then rolls
// back the customer's transaction (error 1213). The global lock has no order
// to deadlock on: a writer waits at its next statement until it is let go.
// It needs FLUSH_TABLES (MySQL 8.0.23 or newer) or RELOAD; an account
// without either is read over one connection, as before, and told so.
//
// Each table's section is the dump tool's section for it with the rows put
// where the tool puts them, after the table's structure and before its
// triggers, written as the tool writes them (--hex-blob: binary and spatial
// values in hex, everything else quoted, numbers bare), one INSERT per
// mysqlInsertMax bytes, with the column list, so a generated column is left
// to the server and an invisible one is kept.
const (
	// mysqlLockWait is how long the lock may wait for statements already
	// running on the server. Statements that start meanwhile queue behind
	// it, so a long wait is a stall; past it the run reads over one
	// connection.
	mysqlLockWait = 5
	// mysqlInsertMax is the size an INSERT statement is cut at, the dump
	// tool's default net_buffer_length. A row larger than it is a statement
	// of its own.
	mysqlInsertMax = 1046528
	// mysqlDataAfter is the line that ends a table's structure in the dump
	// tool's section; its rows follow it and one blank line.
	mysqlDataAfter = "/*!40101 SET character_set_client = @saved_cs_client */;\n"
)

// mysqlSchema is the dump tool's output with no rows, by section.
type mysqlSchema struct {
	head, tail []byte
	hasTail    bool
	// sections are the object sections by run entry, and order their
	// entries in the dump's order.
	sections map[string][]byte
	order    []string
	// created are the tables the dump created, in its order.
	created []string
}

// dumpParallel reads the database's tables over d.Parallel connections, as
// described above, writing the head, the tail and every section with no rows
// to tw and handing each table's section to d.Sections. ok is false, with
// nothing written, when the run is to be read over one connection instead:
// fewer than two tables, a kind of table this reader does not write, or a
// lock the server refused, which is said.
func (d *MySQLDumper) dumpParallel(ctx context.Context, target *mysqlTarget, db *sql.DB, tool *MySQLTool, args []string, tw *tar.Writer,
	sizes map[string]int64) (rows map[string]int64, schema *mysqlSchema, ok bool, err error) {
	var base []string
	q, err := db.QueryContext(ctx, `SELECT table_name, table_type FROM information_schema.tables WHERE table_schema = DATABASE()`)
	if err != nil {
		return nil, nil, false, nil
	}
	for q.Next() {
		var name, kind string
		if err := q.Scan(&name, &kind); err != nil {
			q.Close()
			return nil, nil, false, nil
		}
		switch kind {
		case "BASE TABLE":
			base = append(base, name)
		case "VIEW", "SYSTEM VIEW":
		default:
			// A MariaDB sequence's position and a system-versioned table's
			// history are written by the dump tool's own reader only.
			q.Close()
			d.Warn(fmt.Sprintf("%s holds %s, a %s, so its tables are read over one connection.", target.Database, name, strings.ToLower(kind)))
			return nil, nil, false, nil
		}
	}
	q.Close()
	n := min(d.Parallel, len(base))
	if n < 2 {
		return nil, nil, false, nil
	}

	lock, err := db.Conn(ctx)
	if err != nil {
		return nil, nil, false, fmt.Errorf("opening the connection that locks the tables: %w", err)
	}
	defer lock.Close()
	if _, err := lock.ExecContext(ctx, fmt.Sprintf("SET SESSION lock_wait_timeout = %d", mysqlLockWait)); err != nil {
		return nil, nil, false, fmt.Errorf("setting the lock's timeout: %w", err)
	}
	started := time.Now()
	if _, err := lock.ExecContext(ctx, "FLUSH TABLES WITH READ LOCK"); err != nil {
		if mysqlAccessDenied(err) {
			d.Warn(fmt.Sprintf("%s's tables are read over one connection: this account may not hold writes for the moment the readers start (%v). "+
				"Grant FLUSH_TABLES ON *.* (MySQL 8.0.23 or newer; RELOAD on MariaDB and older MySQL) to read them over %d at once.", target.Database, err, n))
		} else {
			d.Warn(fmt.Sprintf("%s's tables are read over one connection: the lock that holds writes while the readers start waited %ds for "+
				"statements already running and gave up (%v).", target.Database, mysqlLockWait, err))
		}
		return nil, nil, false, nil
	}
	locked := true
	unlock := func() {
		if locked {
			_, _ = lock.ExecContext(context.Background(), "UNLOCK TABLES")
			locked = false
			d.LockHeld = time.Since(started)
		}
	}
	defer unlock()

	readers := make([]*sql.Conn, 0, n)
	defer func() {
		for _, c := range readers {
			_, _ = c.ExecContext(context.Background(), "ROLLBACK")
			_ = c.Close()
		}
	}()
	for len(readers) < n {
		c, err := db.Conn(ctx)
		if err == nil {
			for _, s := range []string{"SET NAMES utf8mb4", "SET SESSION time_zone = '+00:00'", "SET SESSION net_write_timeout = 600",
				"SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ", "START TRANSACTION WITH CONSISTENT SNAPSHOT"} {
				if _, err = c.ExecContext(ctx, s); err != nil {
					err = fmt.Errorf("%s: %w", s, err)
					break
				}
			}
			if err != nil {
				_ = c.Close()
			}
		}
		if err != nil {
			if len(readers) >= 2 {
				break
			}
			d.Warn(fmt.Sprintf("a second connection to %s could not be opened to read it (%v), so its tables are read over one.", target.Database, err))
			return nil, nil, false, nil
		}
		readers = append(readers, c)
	}
	cols, err := mysqlInsertColumns(ctx, lock)
	if err != nil {
		return nil, nil, false, err
	}
	schema, err = d.dumpSchema(ctx, tool, args, target.Database)
	if err != nil {
		return nil, nil, false, err
	}
	for _, t := range base {
		sec, ok := schema.sections[MySQLTableEntry(t)]
		if !ok || !bytes.Contains(sec, []byte(mysqlDataAfter)) {
			unlock()
			d.Warn(fmt.Sprintf("the dump tool wrote %s's structure in a form this reader does not place rows in, so %s's tables are read over one connection.",
				t, target.Database))
			return nil, nil, false, nil
		}
	}
	unlock()

	// What has no rows goes into the stream as it is: the head, the views'
	// stand-ins, the tail.
	isBase := map[string]bool{}
	for _, t := range base {
		isBase[MySQLTableEntry(t)] = true
	}
	put := func(entry string, b []byte) error {
		cw := &chunkWriter{tw: tw, name: func(part int) string { return chunkedName(entry, part) }}
		if _, err := cw.Write(b); err != nil {
			return err
		}
		return cw.Close()
	}
	if err := put(MySQLHeadEntry, schema.head); err != nil {
		return nil, nil, false, err
	}
	for _, e := range schema.order {
		if !isBase[e] {
			if err := put(e, schema.sections[e]); err != nil {
				return nil, nil, false, err
			}
		}
	}
	if schema.hasTail {
		if err := put(MySQLTailEntry, schema.tail); err != nil {
			return nil, nil, false, err
		}
	}

	todo := append([]string(nil), base...)
	sort.SliceStable(todo, func(a, b int) bool { return sizes[todo[a]] > sizes[todo[b]] })
	d.ReadAtOnce, d.ReadOver = len(todo), len(readers)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	rows = map[string]int64{}
	var mu sync.Mutex
	var first error
	fail := func(err error) {
		mu.Lock()
		if first == nil {
			first = err
		}
		mu.Unlock()
		cancel()
	}
	work := make(chan string)
	var wg sync.WaitGroup
	for _, c := range readers {
		wg.Add(1)
		go func(c *sql.Conn) {
			defer wg.Done()
			for t := range work {
				if ctx.Err() != nil {
					continue
				}
				entry := MySQLTableEntry(t)
				var count int64
				err := d.Sections(ctx, entry, func(w io.Writer) error {
					var err error
					count, err = writeMySQLTableSection(ctx, c, t, cols[t], schema.sections[entry], w)
					return err
				})
				if err != nil {
					fail(fmt.Errorf("reading %s: %w", t, err))
					continue
				}
				mu.Lock()
				rows[t] = count
				mu.Unlock()
			}
		}(c)
	}
	for _, t := range todo {
		if ctx.Err() != nil {
			break
		}
		work <- t
	}
	close(work)
	wg.Wait()
	if first != nil {
		return nil, nil, false, first
	}
	return rows, schema, true, nil
}

// dumpSchema runs the dump tool with no rows and keeps its output by
// section, in memory: structure, routines, events and views only.
func (d *MySQLDumper) dumpSchema(ctx context.Context, tool *MySQLTool, args []string, database string) (*mysqlSchema, error) {
	var buf bytes.Buffer
	stw := tar.NewWriter(&buf)
	sw := newMySQLSectionWriter(stw)
	counter := newMySQLDumpCounter()
	a := append(append(append([]string(nil), args...), "--no-data"), database)
	stderr, err := runDumpTool(exec.CommandContext(ctx, tool.Path, a...), tool, io.MultiWriter(sw, counter))
	if err != nil {
		return nil, err
	}
	d.passOn(tool, stderr)
	if !counter.Completed {
		return nil, fmt.Errorf("%s exited cleanly but its output ends before %q: the dump is incomplete", tool, mysqlDumpDone)
	}
	if err := sw.Close(); err != nil {
		return nil, err
	}
	if err := stw.Close(); err != nil {
		return nil, err
	}
	s := &mysqlSchema{sections: map[string][]byte{}, created: counter.Tables()}
	err = ArchiveEntries(&buf, func(name string, r io.Reader) error {
		b, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		switch name {
		case MySQLHeadEntry:
			s.head = b
		case MySQLTailEntry:
			s.tail, s.hasTail = b, true
		default:
			s.sections[name] = b
			s.order = append(s.order, name)
		}
		return nil
	})
	return s, err
}

// mysqlInsertColumns is each table's columns an INSERT names, in order: all
// but the generated ones, which the server computes and refuses a value for.
func mysqlInsertColumns(ctx context.Context, c *sql.Conn) (map[string][]string, error) {
	rows, err := c.QueryContext(ctx, `SELECT table_name, column_name, extra FROM information_schema.columns
		WHERE table_schema = DATABASE() ORDER BY table_name, ordinal_position`)
	if err != nil {
		return nil, fmt.Errorf("reading the tables' columns: %w", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var t, col string
		var extra sql.NullString
		if err := rows.Scan(&t, &col, &extra); err != nil {
			return nil, err
		}
		if strings.Contains(strings.ToUpper(extra.String), "GENERATED") {
			continue
		}
		out[t] = append(out[t], col)
	}
	return out, rows.Err()
}

// writeMySQLTableSection writes one table's section: the dump tool's
// structure, the rows read on c, then what the tool wrote after them (the
// triggers). It returns how many rows it wrote.
func writeMySQLTableSection(ctx context.Context, c *sql.Conn, table string, cols []string, section []byte, w io.Writer) (int64, error) {
	at := bytes.Index(section, []byte(mysqlDataAfter)) + len(mysqlDataAfter)
	if at < len(section) && section[at] == '\n' {
		at++
	}
	bw := bufio.NewWriterSize(w, 1<<16)
	if _, err := bw.Write(section[:at]); err != nil {
		return 0, err
	}
	q := mysqlIdent(table)
	fmt.Fprintf(bw, "--\n-- Dumping data for table %s\n--\n\nLOCK TABLES %s WRITE;\n/*!40000 ALTER TABLE %s DISABLE KEYS */;\n", q, q, q)
	n, err := writeMySQLRows(ctx, c, table, cols, bw)
	if err != nil {
		return n, err
	}
	fmt.Fprintf(bw, "/*!40000 ALTER TABLE %s ENABLE KEYS */;\nUNLOCK TABLES;\n\n", q)
	if _, err := bw.Write(section[at:]); err != nil {
		return n, err
	}
	return n, bw.Flush()
}

// writeMySQLRows writes a table's rows as INSERT statements.
func writeMySQLRows(ctx context.Context, c *sql.Conn, table string, cols []string, w io.Writer) (int64, error) {
	if len(cols) == 0 {
		return 0, nil
	}
	list := make([]string, len(cols))
	for i, col := range cols {
		list[i] = mysqlIdent(col)
	}
	names := strings.Join(list, ",")
	// No arguments, so the driver reads the text protocol: every value as
	// the server writes it.
	rows, err := c.QueryContext(ctx, "SELECT "+names+" FROM "+mysqlIdent(table))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	types, err := rows.ColumnTypes()
	if err != nil {
		return 0, err
	}
	kinds := make([]mysqlValueKind, len(types))
	for i, ct := range types {
		kinds[i] = mysqlKindOf(ct.DatabaseTypeName())
	}
	vals := make([]sql.RawBytes, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	prefix := "INSERT INTO " + mysqlIdent(table) + " (" + names + ") VALUES "
	var stmt, tuple []byte
	var n int64
	flush := func() error {
		if len(stmt) == 0 {
			return nil
		}
		stmt = append(stmt, ";\n"...)
		_, err := w.Write(stmt)
		stmt = stmt[:0]
		return err
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return n, err
		}
		tuple = appendMySQLTuple(tuple[:0], vals, kinds)
		if len(stmt) > 0 && len(stmt)+1+len(tuple) > mysqlInsertMax {
			if err := flush(); err != nil {
				return n, err
			}
		}
		if len(stmt) == 0 {
			stmt = append(stmt, prefix...)
		} else {
			stmt = append(stmt, ',')
		}
		stmt = append(stmt, tuple...)
		n++
	}
	if err := rows.Err(); err != nil {
		return n, err
	}
	return n, flush()
}

type mysqlValueKind int

const (
	mysqlQuoted mysqlValueKind = iota
	mysqlBare
	mysqlHex
)

// mysqlKindOf is how the dump tool writes a value of the type the driver
// names: numbers bare, binary, bit and spatial values in hex (--hex-blob),
// everything else quoted.
func mysqlKindOf(dbType string) mysqlValueKind {
	switch strings.TrimPrefix(dbType, "UNSIGNED ") {
	case "TINYINT", "SMALLINT", "MEDIUMINT", "INT", "BIGINT", "DECIMAL", "FLOAT", "DOUBLE", "YEAR":
		return mysqlBare
	case "BIT", "BINARY", "VARBINARY", "TINYBLOB", "BLOB", "MEDIUMBLOB", "LONGBLOB", "GEOMETRY":
		return mysqlHex
	}
	return mysqlQuoted
}

// appendMySQLTuple appends one row as the dump tool writes it: (v1,v2,...).
func appendMySQLTuple(b []byte, vals []sql.RawBytes, kinds []mysqlValueKind) []byte {
	b = append(b, '(')
	for i, v := range vals {
		if i > 0 {
			b = append(b, ',')
		}
		switch {
		case v == nil:
			b = append(b, "NULL"...)
		case kinds[i] == mysqlBare:
			b = append(b, v...)
		case kinds[i] == mysqlHex && len(v) > 0:
			b = append(b, "0x"...)
			b = hex.AppendEncode(b, v)
			for j := len(b) - 2*len(v); j < len(b); j++ {
				if b[j] >= 'a' && b[j] <= 'f' {
					b[j] -= 'a' - 'A'
				}
			}
		default:
			b = appendMySQLQuoted(b, v)
		}
	}
	return append(b, ')')
}

// appendMySQLQuoted appends v as a quoted string literal, escaped as
// mysql_real_escape_string does.
func appendMySQLQuoted(b, v []byte) []byte {
	b = append(b, '\'')
	for _, c := range v {
		switch c {
		case 0:
			b = append(b, '\\', '0')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\\':
			b = append(b, '\\', '\\')
		case '\'':
			b = append(b, '\\', '\'')
		case '"':
			b = append(b, '\\', '"')
		case 0x1a:
			b = append(b, '\\', 'Z')
		default:
			b = append(b, c)
		}
	}
	return append(b, '\'')
}

// mysqlIdent quotes a name in backticks, doubling any inside.
func mysqlIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// MySQLParallelLimit caps n by the connections the server has free, keeping
// three for the rest of the backup and two for everyone else; at least 1.
func MySQLParallelLimit(ctx context.Context, databaseURL string, n int) int {
	if n <= 1 {
		return 1
	}
	target, err := parseMySQLURL(databaseURL)
	if err != nil {
		return 1
	}
	db, err := target.open()
	if err != nil {
		return 1
	}
	defer db.Close()
	var maxConns, perUser int64
	if err := db.QueryRowContext(ctx, "SELECT @@max_connections, @@max_user_connections").Scan(&maxConns, &perUser); err != nil {
		return n
	}
	var name string
	var connected int64
	if err := db.QueryRowContext(ctx, "SHOW GLOBAL STATUS LIKE 'Threads_connected'").Scan(&name, &connected); err == nil {
		if free := int(maxConns-connected) - 5; free < n {
			n = free
		}
	}
	if perUser > 0 && int(perUser)-3 < n {
		n = int(perUser) - 3
	}
	return max(n, 1)
}
