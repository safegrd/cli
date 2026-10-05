package dump

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/model"
)

// freshnessColumns are the columns a table's newest row is read from, in the
// order they are preferred.
var freshnessColumns = []string{"updated_at", "modified_at", "created_at"}

// freshnessScanLimit is the largest table whose newest row is read without
// an index on the column: max() on an unindexed column reads the whole table
// a second time, which the backup has to read once already.
const freshnessScanLimit = 256 << 20

// sampleRows is how many rows, by primary key, the sample hash covers.
const sampleRows = 100

// freshnessQuery finds, per table, the first of freshnessColumns that is a
// timestamp, whether an index leads with it, and the primary key's columns.
const freshnessQuery = `
SELECT n.nspname, c.relname, pg_table_size(c.oid),
  (SELECT a.attname FROM pg_attribute a
     WHERE a.attrelid = c.oid AND NOT a.attisdropped AND a.attnum > 0
       AND a.attname = ANY($1) AND a.atttypid IN ('timestamp'::regtype, 'timestamptz'::regtype)
     ORDER BY array_position($1, a.attname::text) LIMIT 1) AS fresh_col,
  (SELECT array_agg(a.attname ORDER BY k.ord) FROM pg_index i
     CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord)
     JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
     WHERE i.indrelid = c.oid AND i.indisprimary) AS pk
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p') AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'`

// describeFreshness records, per table, the newest value of its updated_at,
// modified_at or created_at column and a SHA-256 of its first rows by
// primary key, both read under the backup's snapshot. A table with neither
// column has no freshness, and one with no primary key has no sample: there
// is no first hundred rows to hold steady between two backups.
func describeFreshness(ctx context.Context, tx pgx.Tx, stats []model.TableStat) error {
	byName := map[string]*model.TableStat{}
	for i := range stats {
		byName[stats[i].Schema+"."+stats[i].TableName] = &stats[i]
	}
	type plan struct {
		t     *model.TableStat
		size  int64
		fresh string
		pk    []string
	}
	var plans []plan
	// UTC for the newest value and the sample's timestamps, so two hosts in
	// two time zones hash the same rows alike; put back afterwards, for the
	// rest of the backup's transaction.
	var tz string
	if err := tx.QueryRow(ctx, "SELECT current_setting('TimeZone'), set_config('TimeZone', 'UTC', true)").Scan(&tz, new(string)); err != nil {
		return err
	}
	defer func() { _, _ = tx.Exec(ctx, "SELECT set_config('TimeZone', $1, true)", tz) }()
	rows, err := tx.Query(ctx, freshnessQuery, freshnessColumns)
	if err != nil {
		return fmt.Errorf("finding each table's timestamp column: %w", err)
	}
	for rows.Next() {
		var schema, name string
		var p plan
		var fresh *string
		if err := rows.Scan(&schema, &name, &p.size, &fresh, &p.pk); err != nil {
			rows.Close()
			return err
		}
		if p.t = byName[schema+"."+name]; p.t == nil {
			continue
		}
		if fresh != nil {
			p.fresh = *fresh
		}
		plans = append(plans, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range plans {
		ident := pgx.Identifier{p.t.Schema, p.t.TableName}.Sanitize()
		if p.fresh != "" {
			var indexed bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a
				ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
				WHERE i.indrelid = $1::regclass AND a.attname = $2)`, ident, p.fresh).Scan(&indexed); err != nil {
				return err
			}
			if indexed || p.size <= freshnessScanLimit {
				var newest *string
				q := fmt.Sprintf(`SELECT to_char(max(%s), 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') FROM %s`,
					pgx.Identifier{p.fresh}.Sanitize(), ident)
				if err := tx.QueryRow(ctx, q).Scan(&newest); err != nil {
					return fmt.Errorf("reading the newest %s of %s: %w", p.fresh, ident, err)
				}
				p.t.FreshnessColumn = p.fresh
				if newest != nil {
					p.t.FreshnessMax = *newest
				}
			}
		}
		if len(p.pk) > 0 {
			order := ""
			for i, c := range p.pk {
				if i > 0 {
					order += ", "
				}
				order += pgx.Identifier{c}.Sanitize()
			}
			h := sha256.New()
			q := fmt.Sprintf("COPY (SELECT * FROM %s ORDER BY %s LIMIT %d) TO STDOUT", ident, order, sampleRows)
			if _, err := tx.Conn().PgConn().CopyTo(ctx, h, q); err != nil {
				return fmt.Errorf("hashing the first rows of %s: %w", ident, err)
			}
			p.t.SampleHash = hex.EncodeToString(h.Sum(nil))
		}
	}
	return nil
}
