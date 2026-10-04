package dump

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/model"
)

// runIdentity reads the snapshot a backup's transaction reads under and the
// WAL position, each behind a savepoint: a role or server that refuses one
// leaves it empty and the backup goes on.
func runIdentity(ctx context.Context, tx pgx.Tx, serverVersionNum int) (snapshot, lsn string) {
	snapFn := "txid_current_snapshot()"
	if serverVersionNum >= 130000 {
		snapFn = "pg_current_snapshot()"
	}
	read := func(q string) string {
		if _, err := tx.Exec(ctx, "SAVEPOINT safegrd_identity"); err != nil {
			return ""
		}
		var v string
		if err := tx.QueryRow(ctx, q).Scan(&v); err != nil {
			_, _ = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT safegrd_identity")
			return ""
		}
		_, _ = tx.Exec(ctx, "RELEASE SAVEPOINT safegrd_identity")
		return v
	}
	snapshot = read("SELECT " + snapFn + "::text")
	if serverVersionNum >= 100000 {
		lsn = read("SELECT (CASE WHEN pg_is_in_recovery() THEN pg_last_wal_replay_lsn() ELSE pg_current_wal_lsn() END)::text")
	}
	return snapshot, lsn
}

// tableCatalogQuery returns, for every ordinary or partitioned table, an MD5
// of its definition as the catalog states it, the sequences its columns own
// and the tables its foreign keys point at.
const tableCatalogQuery = `
SELECT n.nspname, c.relname,
  md5(coalesce((SELECT string_agg(quote_ident(a.attname) || ' ' || format_type(a.atttypid, a.atttypmod)
          || CASE WHEN a.attnotnull THEN ' not null' ELSE '' END
          || coalesce(' default ' || pg_get_expr(ad.adbin, ad.adrelid), '')
          || CASE WHEN a.attidentity <> '' THEN ' identity ' || a.attidentity::text ELSE '' END, ', ' ORDER BY a.attnum)
        FROM pg_attribute a LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
        WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped), '')
      || ';' || coalesce((SELECT string_agg(quote_ident(co.conname) || ' ' || pg_get_constraintdef(co.oid), ', ' ORDER BY co.conname)
        FROM pg_constraint co WHERE co.conrelid = c.oid), '')),
  coalesce((SELECT array_agg(q ORDER BY q) FROM (
      SELECT quote_ident(sn.nspname) || '.' || quote_ident(s.relname) AS q
      FROM pg_depend d JOIN pg_class s ON s.oid = d.objid AND s.relkind = 'S'
      JOIN pg_namespace sn ON sn.oid = s.relnamespace
      WHERE d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass
        AND d.refobjid = c.oid AND d.deptype IN ('a', 'i')) owned), '{}'),
  coalesce((SELECT array_agg(DISTINCT quote_ident(fn.nspname) || '.' || quote_ident(f.relname))
      FROM pg_constraint co JOIN pg_class f ON f.oid = co.confrelid
      JOIN pg_namespace fn ON fn.oid = f.relnamespace
      WHERE co.conrelid = c.oid AND co.contype = 'f'), '{}')
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p') AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'`

// describeTables fills each table's schema hash, owned sequences and
// foreign key targets. It needs PostgreSQL 10 or newer (attidentity) and
// leaves the fields empty on an older server.
func describeTables(ctx context.Context, tx pgx.Tx, serverVersionNum int, stats []model.TableStat) error {
	if serverVersionNum < 100000 || len(stats) == 0 {
		return nil
	}
	byName := map[string]*model.TableStat{}
	for i := range stats {
		byName[stats[i].Schema+"."+stats[i].TableName] = &stats[i]
	}
	rows, err := tx.Query(ctx, tableCatalogQuery)
	if err != nil {
		return fmt.Errorf("failed to describe the tables: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var schema, table, hash string
		var owned, refs []string
		if err := rows.Scan(&schema, &table, &hash, &owned, &refs); err != nil {
			return fmt.Errorf("failed to describe the tables: %w", err)
		}
		if t, ok := byName[schema+"."+table]; ok {
			t.SchemaHash, t.OwnedSequences, t.References = hash, owned, refs
		}
	}
	return rows.Err()
}

// TableSchemaHash is the schema hash a backup records for one table, read
// from the database conn is connected to. ok is false when there is no such
// table.
func TableSchemaHash(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, schema, table string) (hash string, ok bool, err error) {
	var s, t string
	var owned, refs []string
	err = q.QueryRow(ctx, tableCatalogQuery+` AND n.nspname = $1 AND c.relname = $2`, schema, table).Scan(&s, &t, &hash, &owned, &refs)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return hash, true, nil
}

// TablePath is the file a run of a repository database backup keeps a
// table's rows in.
func TablePath(schema, table string) string { return copyEntryName(schema, table, 0) }
