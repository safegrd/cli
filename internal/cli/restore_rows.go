package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// A row restore (--rows) puts chosen rows of one table back into a live
// table: the table's rows are loaded from the snapshot into a temporary
// table in the target's own transaction, and the ones the condition
// matches are written into the target's table by its primary key. A row
// the target already has is left as it is unless --overwrite says to
// replace it, since a restore never writes over data by default. The
// target's other rows, and its other tables, are untouched.

// rowsResult is what one table's row restore did.
type rowsResult struct {
	matched, inserted, updated, kept int64
}

// tableColumns reads the target table's columns in order, leaving out
// generated ones, which the target computes itself and an INSERT may not
// name; and its primary key's columns, in key order.
func tableColumns(ctx context.Context, tx pgx.Tx, ident string) (cols, pk []string, err error) {
	rows, err := tx.Query(ctx, `SELECT attname, attgenerated <> '' FROM pg_attribute
		WHERE attrelid = $1::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attnum`, ident)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var name string
		var generated bool
		if err := rows.Scan(&name, &generated); err != nil {
			rows.Close()
			return nil, nil, err
		}
		if !generated {
			cols = append(cols, name)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	keyRows, err := tx.Query(ctx, `SELECT a.attname FROM pg_index i
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
		WHERE i.indrelid = $1::regclass AND i.indisprimary
		ORDER BY array_position(i.indkey::int2[], a.attnum)`, ident)
	if err != nil {
		return nil, nil, err
	}
	defer keyRows.Close()
	for keyRows.Next() {
		var name string
		if err := keyRows.Scan(&name); err != nil {
			return nil, nil, err
		}
		pk = append(pk, name)
	}
	return cols, pk, keyRows.Err()
}

// rowsUpsertSQL is the statement that writes the matching rows of the
// temporary table into the target's table. It returns whether each row
// written was new (xmax = 0) or replaced; with overwrite off a row the
// target has is skipped and not returned.
func rowsUpsertSQL(ident, temp string, cols, pk []string, where string, overwrite bool) string {
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = pgx.Identifier{c}.Sanitize()
	}
	keys := make([]string, len(pk))
	for i, c := range pk {
		keys[i] = pgx.Identifier{c}.Sanitize()
	}
	list := strings.Join(quoted, ", ")
	action := "DO NOTHING"
	if overwrite {
		var sets []string
		for _, q := range quoted {
			sets = append(sets, q+" = EXCLUDED."+q)
		}
		action = "DO UPDATE SET " + strings.Join(sets, ", ")
	}
	return "INSERT INTO " + ident + " (" + list + ") SELECT " + list + " FROM " + temp + " WHERE (" + where + ")" +
		" ON CONFLICT (" + strings.Join(keys, ", ") + ") " + action + " RETURNING (xmax = 0) AS inserted"
}

// restoreRows writes the rows of one loaded temporary table that match
// the condition into the target's table.
func restoreRows(ctx context.Context, tx pgx.Tx, p tablePick, temp, where string, overwrite bool) (rowsResult, error) {
	var res rowsResult
	ident := pgx.Identifier{p.stat.Schema, p.stat.TableName}.Sanitize()
	cols, pk, err := tableColumns(ctx, tx, ident)
	if err != nil {
		return res, fmt.Errorf("reading the columns of %s in the target: %w", p.name, err)
	}
	if len(pk) == 0 {
		return res, fmt.Errorf("%s has no primary key, so a row of the backup cannot be matched to a row of the target; restore the whole table with --table alone into an empty table, or query the rows out with 'safegrd verify --query'", p.name)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+temp+" WHERE ("+where+")").Scan(&res.matched); err != nil {
		return res, fmt.Errorf("--rows %q on %s: %w", where, p.name, err)
	}
	if res.matched == 0 {
		return res, fmt.Errorf("no row of %s in the backup matches --rows %q; nothing was restored", p.name, where)
	}
	rows, err := tx.Query(ctx, rowsUpsertSQL(ident, temp, cols, pk, where, overwrite))
	if err != nil {
		return res, fmt.Errorf("writing the rows of %s: %w; nothing was restored", p.name, err)
	}
	defer rows.Close()
	for rows.Next() {
		var inserted bool
		if err := rows.Scan(&inserted); err != nil {
			return res, err
		}
		if inserted {
			res.inserted++
		} else {
			res.updated++
		}
	}
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("writing the rows of %s: %w; nothing was restored", p.name, err)
	}
	res.kept = res.matched - res.inserted - res.updated
	return res, nil
}
