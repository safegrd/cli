package runner

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/safegrd/cli/pkg/dump"
)

// QueryToCSV runs one query against a restored sandbox, in a read-only
// transaction, and writes every row it returns to w as CSV with the column
// names first. NULL is an empty field. It returns the number of rows written.
//
// This is how a person reads rows out of a backup without restoring the
// table they came from: the sandbox holds the restore, the query picks the
// rows, and nothing is written to the sandbox or anywhere else.
func QueryToCSV(ctx context.Context, sandboxURL, query string, timeout time.Duration, w io.Writer) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out := csv.NewWriter(w)
	var n int64
	var err error
	switch {
	case dump.IsMongoURL(sandboxURL):
		return 0, errors.New("a MongoDB sandbox takes no SQL query")
	case dump.IsSQLiteURL(sandboxURL):
		path, perr := dump.SQLitePath(sandboxURL)
		if perr != nil {
			return 0, perr
		}
		dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
		db, oerr := sql.Open("sqlite", dsn)
		if oerr != nil {
			return 0, oerr
		}
		defer db.Close()
		n, err = sqlRowsToCSV(ctx, db, query, nil, out)
	case dump.IsMySQLURL(sandboxURL):
		db, oerr := dump.OpenMySQL(sandboxURL)
		if oerr != nil {
			return 0, oerr
		}
		defer db.Close()
		n, err = sqlRowsToCSV(ctx, db, query, &sql.TxOptions{ReadOnly: true}, out)
	default:
		n, err = pgRowsToCSV(ctx, sandboxURL, query, timeout, out)
	}
	if err != nil {
		return n, err
	}
	out.Flush()
	return n, out.Error()
}

func pgRowsToCSV(ctx context.Context, sandboxURL, query string, timeout time.Duration, out *csv.Writer) (int64, error) {
	conn, err := pgx.Connect(ctx, sandboxURL)
	if err != nil {
		return 0, fmt.Errorf("cannot connect to the sandbox: %w", err)
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }() // read-only: nothing to keep
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = "+strconv.FormatInt(timeout.Milliseconds(), 10)); err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	fields := rows.FieldDescriptions()
	header := make([]string, len(fields))
	for i, f := range fields {
		header[i] = f.Name
	}
	if err := out.Write(header); err != nil {
		return 0, err
	}
	var n int64
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return n, err
		}
		if err := out.Write(csvRecord(vals)); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func sqlRowsToCSV(ctx context.Context, db *sql.DB, query string, opts *sql.TxOptions, out *csv.Writer) (int64, error) {
	tx, err := db.BeginTx(ctx, opts)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }() // read-only: nothing to keep
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	if err := out.Write(cols); err != nil {
		return 0, err
	}
	var n int64
	vals := make([]any, len(cols))
	dest := make([]any, len(cols))
	for i := range vals {
		dest[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			return n, err
		}
		if err := out.Write(csvRecord(vals)); err != nil {
			return n, err
		}
		n++
	}
	return n, rows.Err()
}

func csvRecord(vals []any) []string {
	rec := make([]string, len(vals))
	for i, v := range vals {
		if v != nil {
			rec[i] = checkValueText(v)
		}
	}
	return rec
}
