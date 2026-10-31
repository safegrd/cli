package dump

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"

	"github.com/safegrd/cli/pkg/model"
)

// mysqlLoader runs the server's own client over a dump, or a section of
// one, with every DEFINER set to the restoring user.
type mysqlLoader struct {
	ctx      context.Context
	tool     *MySQLTool
	cnf      string
	database string
	// leftBehind names what a failure part way may have left in the
	// target, for the error: MySQL commits DDL as it goes.
	leftBehind string
	// alone is a table loaded into a database that has other tables: its
	// section's DROP TABLE is left out, since the table was checked absent
	// or empty first and a drop would take what arrived since.
	alone     bool
	mu        sync.Mutex
	rewritten int
}

// load pipes in through the client. A section loaded beside others, or
// alone into a database that has other tables, drops its LOCK TABLES: it
// holds one table on its own connection, so the lock guards nothing, and
// MariaDB refuses a locked parent's rows when another connection created a
// child with a foreign key to it in between (ERROR 1100 "Table 'a_child'
// was not locked with LOCK TABLES"). A section loaded alone (l.alone) also
// drops its DROP TABLE, and rowsOnly its CREATE TABLE and triggers.
func (l *mysqlLoader) load(in io.Reader, what string, section bool) error {
	return l.loadWith(in, what, section, false)
}

func (l *mysqlLoader) loadWith(in io.Reader, what string, section, rowsOnly bool) error {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(l.ctx, l.tool.Path, "--defaults-extra-file="+l.cnf,
		"--binary-mode", "--default-character-set=utf8mb4", "--database="+l.database)
	definers := newDefinerRewriter(in)
	definers.dropLocks = section
	definers.dropTable, definers.skipStructure = l.alone, rowsOnly
	cmd.Stdin = definers
	cmd.Stderr = &stderr
	err := cmd.Run()
	l.mu.Lock()
	l.rewritten += definers.rewritten
	l.mu.Unlock()
	if err != nil {
		msg := toolMessage(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		return fmt.Errorf("%s failed%s: %v: %s. The target may now hold part of %s; drop it before retrying", l.tool, what, err, msg, l.leftBehind)
	}
	return nil
}

// definerWarning is what a restore says when it set definers to the
// restoring user.
func definerWarning(n int) string {
	return fmt.Sprintf("%d view, trigger, routine or event definer(s) were set to the restoring user: they now run as it, "+
		"not as the account that created them. Recreating another account's definer needs SET_USER_ID, which managed servers do not grant", n)
}

// RestoreMySQLTables loads chosen tables of a per-table dump into a
// database that may hold other tables. Each table's section is loaded
// behind the dump's head, which carries the session settings, through the
// server's own client, as a whole restore loads the dump. Before anything
// is written every chosen table is checked in the target: absent, or empty
// and defined as the manifest records it (the same hash over
// information_schema.columns the backup took). A table the target lacks is
// created as the section defines it, with its indexes and triggers; one
// the target has takes the rows alone and keeps its own definition,
// indexes and triggers. The section's DROP TABLE is never run: a drop
// would take rows that arrived since the check. After, each table's rows
// are counted against the manifest. MySQL commits DDL as it goes, so a
// failure part way leaves what loaded in the target, which the error says.
// created names the tables the target lacked.
func RestoreMySQLTables(ctx context.Context, targetURL string, head []byte, sections []TableData, stats []model.TableStat, warn func(string)) (created []string, rows int64, err error) {
	if len(sections) != len(stats) {
		return nil, 0, errors.New("each table needs its manifest entry")
	}
	target, err := parseMySQLURL(targetURL)
	if err != nil {
		return nil, 0, err
	}
	db, err := target.open()
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	_, mariaDB, err := mysqlServer(ctx, db)
	if err != nil {
		return nil, 0, fmt.Errorf("could not connect to the restore target: %w", err)
	}
	exists := map[string]bool{}
	for i, s := range sections {
		kind, cols, err := mysqlTableShape(ctx, db, s.Table)
		if err != nil {
			return nil, 0, fmt.Errorf("reading the definition of %s in the target: %w", s.Table, err)
		}
		switch {
		case kind == "":
			created = append(created, s.Table)
		case kind != "BASE TABLE":
			return nil, 0, fmt.Errorf("%s in the target is a %s, not a table; nothing was restored", s.Table, strings.ToLower(kind))
		default:
			if stats[i].SchemaHash == "" {
				return nil, 0, fmt.Errorf("the snapshot records no definition of %s to compare the target's with; restore the whole snapshot into an empty database instead", s.Table)
			}
			if model.ColumnsHash(cols) != stats[i].SchemaHash {
				return nil, 0, fmt.Errorf("%s in the target is not defined as it was in the backup (columns, types or keys differ); nothing was restored", s.Table)
			}
			held, err := mysqlHoldsRows(ctx, db, s.Table)
			if err != nil {
				return nil, 0, err
			}
			if held {
				return nil, 0, fmt.Errorf("%s in the target holds rows; a restore never writes over data. Empty it, or restore into another database", s.Table)
			}
			exists[s.Table] = true
		}
	}
	tool, err := findMySQLTool(ctx, "client", mariaDB)
	if err != nil {
		return nil, 0, err
	}
	cnf, cleanup, err := target.defaultsFile()
	if err != nil {
		return nil, 0, err
	}
	defer cleanup()
	for _, s := range sections {
		loader := &mysqlLoader{ctx: ctx, tool: tool, cnf: cnf, database: target.Database, leftBehind: s.Table, alone: true}
		pr, pw := io.Pipe()
		go func() { _ = pw.CloseWithError(s.Open(pw)) }()
		err := loader.loadWith(io.MultiReader(bytes.NewReader(head), pr), " loading "+s.Table, true, exists[s.Table])
		_ = pr.CloseWithError(io.ErrClosedPipe)
		if err != nil {
			return nil, 0, err
		}
		if loader.rewritten > 0 && warn != nil {
			warn(definerWarning(loader.rewritten))
		}
	}
	for i, s := range sections {
		var n int64
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+mysqlQuoteIdent(s.Table)).Scan(&n); err != nil {
			return nil, 0, fmt.Errorf("counting %s: %w", s.Table, err)
		}
		if n != stats[i].RowCount {
			return nil, 0, fmt.Errorf("%s loaded %d rows; the snapshot recorded %d. The target holds that table as loaded; drop it before retrying", s.Table, n, stats[i].RowCount)
		}
		rows += n
	}
	return created, rows, nil
}

// mysqlQuoteIdent quotes a name as MySQL does, a backtick doubled inside.
func mysqlQuoteIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// mysqlTableShape reads what the target has under a name: "" for nothing,
// else its information_schema table_type, and a base table's columns as
// the backup reads them.
func mysqlTableShape(ctx context.Context, db *sql.DB, table string) (kind string, cols []model.ColumnStat, err error) {
	err = db.QueryRowContext(ctx, `SELECT table_type FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?`, table).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	if kind != "BASE TABLE" {
		return kind, nil, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT column_name, column_type, is_nullable, column_key
		FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? ORDER BY ordinal_position`, table)
	if err != nil {
		return kind, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var col, typ, nullable, key string
		if err := rows.Scan(&col, &typ, &nullable, &key); err != nil {
			return kind, nil, err
		}
		cols = append(cols, model.ColumnStat{Name: col, Type: typ, NotNull: nullable == "NO", PrimaryKey: key == "PRI"})
	}
	return kind, cols, rows.Err()
}

// mysqlHoldsRows reports whether a table has any row.
func mysqlHoldsRows(ctx context.Context, db *sql.DB, table string) (bool, error) {
	var one int
	err := db.QueryRowContext(ctx, "SELECT 1 FROM "+mysqlQuoteIdent(table)+" LIMIT 1").Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading %s in the target: %w", table, err)
	}
	return true, nil
}
