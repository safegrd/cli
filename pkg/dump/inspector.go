package dump

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/safegrd/cli/pkg/model"
)

// Inspector queries live PostgreSQL catalog tables for health, schema, and volume stats.
type Inspector struct {
	db *sql.DB
}

// NewInspector creates an Inspector using a Postgres connection string.
func NewInspector(databaseURL string) (*Inspector, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	return &Inspector{db: db}, nil
}

// Close closes the underlying database connection pool.
func (i *Inspector) Close() error {
	return i.db.Close()
}

// GetVersion retrieves the PostgreSQL server version banner.
func (i *Inspector) GetVersion(ctx context.Context) (string, error) {
	var version string
	err := i.db.QueryRowContext(ctx, "SELECT version();").Scan(&version)
	if err != nil {
		return "", fmt.Errorf("failed to query postgres version: %w", err)
	}
	return strings.TrimSpace(version), nil
}

// GetExtensions lists all installed PostgreSQL extensions (e.g. pgvector, postgis, uuid-ossp).
func (i *Inspector) GetExtensions(ctx context.Context) ([]string, error) {
	query := "SELECT extname FROM pg_extension WHERE extname != 'plpgsql' ORDER BY extname;"
	rows, err := i.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query extensions: %w", err)
	}
	defer rows.Close()

	var extensions []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		extensions = append(extensions, name)
	}

	return extensions, rows.Err()
}

// GetTableStats scans user tables and collects row counts and byte sizes.
func (i *Inspector) GetTableStats(ctx context.Context) ([]model.TableStat, error) {
	// The same tables a backup copies (userTablesQuery), so a sandbox a
	// snapshot was restored into is counted like the database it came from.
	query := `
		SELECT n.nspname, c.relname, COALESCE(s.n_live_tup, 0), pg_total_relation_size(c.oid)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
		WHERE c.relkind = 'r' AND c.relpersistence <> 't'
		  AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
		  AND NOT EXISTS (SELECT 1 FROM pg_depend d
		                  WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
		ORDER BY n.nspname, c.relname`

	rows, err := i.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query table stats: %w", err)
	}
	defer rows.Close()

	var stats []model.TableStat
	for rows.Next() {
		var stat model.TableStat
		if err := rows.Scan(&stat.Schema, &stat.TableName, &stat.RowCount, &stat.SizeBytes); err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}

	// For small databases or if statistics haven't run ANALYZE, get exact count if est is small
	for idx := range stats {
		if stats[idx].RowCount < 10000 {
			var exactCount int64
			safeName := fmt.Sprintf(`"%s"."%s"`, stats[idx].Schema, stats[idx].TableName)
			err := i.db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", safeName)).Scan(&exactCount)
			if err == nil {
				stats[idx].RowCount = exactCount
			}
		}
	}

	return stats, rows.Err()
}

// CountRowsExactly replaces every table's row count with COUNT(*). The
// catalogue's estimate is fine for a status line and wrong for a drill,
// which must hold the restored rows to the snapshot's exact count.
func (i *Inspector) CountRowsExactly(ctx context.Context, m *model.SnapshotMetadata) error {
	for idx := range m.TableStats {
		t := &m.TableStats[idx]
		ident := `"` + strings.ReplaceAll(t.Schema, `"`, `""`) + `"."` + strings.ReplaceAll(t.TableName, `"`, `""`) + `"`
		if err := i.db.QueryRowContext(ctx, "SELECT count(*) FROM "+ident).Scan(&t.RowCount); err != nil {
			return fmt.Errorf("counting %s.%s: %w", t.Schema, t.TableName, err)
		}
	}
	m.CalculateTotals()
	return nil
}

// Inspect collects full pre-backup catalog telemetry.
func (i *Inspector) Inspect(ctx context.Context, databaseName string) (*model.SnapshotMetadata, error) {
	version, err := i.GetVersion(ctx)
	if err != nil {
		return nil, err
	}

	extensions, err := i.GetExtensions(ctx)
	if err != nil {
		return nil, err
	}

	tableStats, err := i.GetTableStats(ctx)
	if err != nil {
		return nil, err
	}

	meta := &model.SnapshotMetadata{
		DatabaseName:    databaseName,
		PostgresVersion: version,
		Extensions:      extensions,
		TableStats:      tableStats,
	}
	meta.CalculateTotals()

	return meta, nil
}
