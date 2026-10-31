package dump

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/safegrd/cli/pkg/model"
)

// sqlQuerier is what reads rows: a *sql.DB, a *sql.Conn or a *sql.Tx.
type sqlQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// RestoreSQLiteTables copies chosen tables of a snapshot into a database
// file that has other tables. A SQLite snapshot is the database file, so
// it is staged whole beside the target (in the work directory a whole
// restore uses), checked with PRAGMA integrity_check and attached. Then, in
// one transaction on the target, each chosen table is created from the
// staged copy's definition (the table, its indexes and its triggers) when
// the target lacks it, or checked empty and defined as the manifest records
// it, and its rows are copied with INSERT ... SELECT and counted against
// the manifest. A failure rolls the transaction back, so the target is as
// it was. created names the tables the target lacked.
func RestoreSQLiteTables(ctx context.Context, targetURL string, src io.Reader, stats []model.TableStat) (created []string, rows int64, err error) {
	target, err := SQLitePath(targetURL)
	if err != nil {
		return nil, 0, err
	}
	if err := checkSQLiteFile(target); err != nil {
		return nil, 0, fmt.Errorf("--table puts a table into a database the target has: %w", err)
	}
	dir := filepath.Dir(target)
	tmpDir, err := sqliteWorkDir(dir)
	if err != nil {
		return nil, 0, fmt.Errorf("staging the backup beside %s: %w", target, err)
	}
	defer os.RemoveAll(tmpDir)
	staged := filepath.Join(tmpDir, "backup.sqlite")
	_, sawDB, err := sqliteArchive(src, staged)
	if err != nil {
		return nil, 0, err
	}
	if !sawDB {
		return nil, 0, errors.New("the snapshot holds no SQLite database")
	}
	sdb, err := openSQLite(staged, true)
	if err != nil {
		return nil, 0, err
	}
	integrity, err := sqliteIntegrity(ctx, sdb)
	sdb.Close()
	if err != nil {
		return nil, 0, err
	}
	if integrity != "ok" {
		return nil, 0, fmt.Errorf("the backup's database fails PRAGMA integrity_check: %s", integrity)
	}

	db, err := openSQLite(target, false)
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	// One connection: ATTACH and the transaction live on it.
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "ATTACH DATABASE ? AS backup", staged); err != nil {
		return nil, 0, fmt.Errorf("attaching the backup to %s: %w", target, err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "DETACH DATABASE backup") }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return nil, 0, fmt.Errorf("opening a transaction on %s: %w", target, err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	for _, st := range stats {
		name := st.TableName
		var kind string
		err := conn.QueryRowContext(ctx, "SELECT type FROM main.sqlite_schema WHERE name = ?", name).Scan(&kind)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if err := sqliteCreateFromBackup(ctx, conn, name); err != nil {
				return nil, 0, err
			}
			created = append(created, name)
		case err != nil:
			return nil, 0, fmt.Errorf("reading the definition of %s in the target: %w", name, err)
		case kind != "table":
			return nil, 0, fmt.Errorf("%s in the target is not a table (it is a%s %s); nothing was restored", name, article(kind), kind)
		default:
			if st.SchemaHash == "" {
				return nil, 0, fmt.Errorf("the snapshot records no definition of %s to compare the target's with; restore the whole snapshot to a new file instead", name)
			}
			cols, err := sqliteColumnsIn(ctx, conn, "main", name)
			if err != nil {
				return nil, 0, fmt.Errorf("describing %s in the target: %w", name, err)
			}
			if model.ColumnsHash(cols) != st.SchemaHash {
				return nil, 0, fmt.Errorf("%s in the target is not defined as it was in the backup (columns, types or keys differ); nothing was restored", name)
			}
			var one int
			err = conn.QueryRowContext(ctx, "SELECT 1 FROM main."+quoteSQLiteIdent(name)+" LIMIT 1").Scan(&one)
			if err == nil {
				return nil, 0, fmt.Errorf("%s in the target holds rows; a restore never writes over data. Empty it, or restore into another database", name)
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return nil, 0, fmt.Errorf("reading %s in the target: %w", name, err)
			}
		}
		// Named columns, so a generated column, which SELECT * would read
		// and an INSERT may not set, is left to the target to compute.
		cols, err := sqliteStoredColumns(ctx, conn, "backup", name)
		if err != nil {
			return nil, 0, fmt.Errorf("describing %s in the backup: %w", name, err)
		}
		res, err := conn.ExecContext(ctx, "INSERT INTO main."+quoteSQLiteIdent(name)+" ("+cols+") SELECT "+cols+" FROM backup."+quoteSQLiteIdent(name))
		if err != nil {
			return nil, 0, fmt.Errorf("loading %s: %w; nothing was restored", name, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, 0, err
		}
		if n != st.RowCount {
			return nil, 0, fmt.Errorf("%s loaded %d rows, the backup recorded %d; nothing was restored", name, n, st.RowCount)
		}
		rows += n
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return nil, 0, fmt.Errorf("committing the restore: %w", err)
	}
	committed = true
	return created, rows, nil
}

// sqliteCreateFromBackup creates a table in main as the attached backup
// defines it, with its indexes and triggers.
func sqliteCreateFromBackup(ctx context.Context, conn *sql.Conn, name string) error {
	var ddl string
	err := conn.QueryRowContext(ctx, "SELECT sql FROM backup.sqlite_schema WHERE type = 'table' AND name = ?", name).Scan(&ddl)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("the backup holds no definition of %s", name)
	}
	if err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("creating %s as the backup defines it: %w; nothing was restored", name, err)
	}
	rows, err := conn.QueryContext(ctx, "SELECT sql FROM backup.sqlite_schema WHERE tbl_name = ? AND type IN ('index', 'trigger') AND sql IS NOT NULL ORDER BY rowid", name)
	if err != nil {
		return err
	}
	var extras []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return err
		}
		extras = append(extras, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, s := range extras {
		if _, err := conn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("creating an index or trigger of %s as the backup defines it: %w; nothing was restored", name, err)
		}
	}
	return nil
}

// sqliteStoredColumns lists a table's columns an INSERT sets, quoted and
// joined with commas: every column but a generated one.
func sqliteStoredColumns(ctx context.Context, q sqlQuerier, schema, table string) (string, error) {
	rows, err := q.QueryContext(ctx, "PRAGMA "+quoteSQLiteIdent(schema)+".table_xinfo("+quoteSQLiteIdent(table)+")")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var cid, notNull, pk, hidden int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk, &hidden); err != nil {
			return "", err
		}
		// hidden 2 and 3 are generated columns (virtual, stored).
		if hidden == 0 {
			cols = append(cols, quoteSQLiteIdent(name))
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(cols) == 0 {
		return "", fmt.Errorf("%s has no column an insert can set", table)
	}
	return strings.Join(cols, ", "), nil
}

// article is "n" before a word that starts with a vowel, else "".
func article(word string) string {
	if word != "" && strings.ContainsRune("aeiou", rune(word[0])) {
		return "n"
	}
	return ""
}
