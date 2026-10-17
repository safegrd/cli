package wal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// pointCountCap is the largest table, by the planner's estimate, a restore
// point counts. Counting is a full scan, twice a day; a larger table is
// named as left out instead.
const pointCountCap = 5_000_000

// TableCount is one table's rows just before and just after a restore point
// was created. A table nobody wrote in between has one count, and a restore
// to the point has exactly it; one that moved has the point's count between
// the two.
type TableCount struct {
	Table  string `json:"table"`
	Before int64  `json:"before"`
	After  int64  `json:"after"`
}

// RestorePoint is a named moment in the WAL, recorded with the row counts a
// point-in-time drill checks a restore to it against.
type RestorePoint struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	SurfaceID string    `json:"surface_id"`
	SystemID  string    `json:"system_id"`
	At        time.Time `json:"at"`
	LSN       string    `json:"lsn"`
	// Tables are the counted tables; Skipped those too large to count.
	Tables  []TableCount `json:"tables"`
	Skipped []string     `json:"skipped,omitempty"`
}

func (a *Archive) pointKey(name string) string { return path.Join(a.prefix(), "points", name+".json") }

// CreateRestorePoint asks the cluster for a restore point and records each
// table's row count on both sides of it. The role needs EXECUTE on
// pg_create_restore_point(text), which only a superuser has until granted.
func (a *Archive) CreateRestorePoint(ctx context.Context, connURL string) (RestorePoint, error) {
	now := a.now()
	rp := RestorePoint{Version: 1, Name: newID("r", now, randomHex()), SurfaceID: a.SurfaceID, SystemID: a.SystemID, At: now}
	conn, err := pgx.Connect(ctx, connURL)
	if err != nil {
		return rp, err
	}
	defer conn.Close(context.Background())
	tables, skipped, err := pointTables(ctx, conn)
	if err != nil {
		return rp, err
	}
	before, err := countTables(ctx, conn, tables)
	if err != nil {
		return rp, err
	}
	if err := conn.QueryRow(ctx, `SELECT pg_create_restore_point($1)::text`, rp.Name).Scan(&rp.LSN); err != nil {
		return rp, fmt.Errorf("creating restore point %s: %w. Grant it with: GRANT EXECUTE ON FUNCTION pg_create_restore_point(text) TO <role>", rp.Name, err)
	}
	rp.At = a.now()
	after, err := countTables(ctx, conn, tables)
	if err != nil {
		return rp, err
	}
	for i, t := range tables {
		rp.Tables = append(rp.Tables, TableCount{Table: t, Before: before[i], After: after[i]})
	}
	rp.Skipped = skipped
	body, err := json.MarshalIndent(rp, "", "  ")
	if err != nil {
		return rp, err
	}
	var lock time.Time
	if a.Store.Locks() {
		lock = rp.At.Add(a.Window + lockSlack)
	}
	if _, err := a.Store.Put(ctx, a.pointKey(rp.Name), bytes.NewReader(body), lock); err != nil {
		return rp, fmt.Errorf("recording restore point %s: %w", rp.Name, err)
	}
	return rp, nil
}

// pointTables lists the tables the role can read, quoted, and those too
// large to count.
func pointTables(ctx context.Context, conn *pgx.Conn) (tables, skipped []string, err error) {
	rows, err := conn.Query(ctx, `
		SELECT quote_ident(n.nspname) || '.' || quote_ident(c.relname), c.reltuples
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
		  AND has_table_privilege(c.oid, 'SELECT')
		ORDER BY 1`)
	if err != nil {
		return nil, nil, fmt.Errorf("listing tables: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var est float64
		if err := rows.Scan(&name, &est); err != nil {
			return nil, nil, err
		}
		if est > pointCountCap {
			skipped = append(skipped, name)
			continue
		}
		tables = append(tables, name)
	}
	return tables, skipped, rows.Err()
}

// countTables counts every table in one repeatable-read snapshot.
func countTables(ctx context.Context, conn *pgx.Conn, tables []string) ([]int64, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	out := make([]int64, len(tables))
	for i, t := range tables {
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+t).Scan(&out[i]); err != nil {
			return nil, fmt.Errorf("counting %s: %w", t, err)
		}
	}
	return out, tx.Commit(ctx)
}

// RestorePoints reads every recorded restore point, oldest first.
func (a *Archive) RestorePoints(ctx context.Context) ([]RestorePoint, error) {
	objs, err := a.Store.List(ctx, path.Join(a.prefix(), "points")+"/")
	if err != nil {
		return nil, err
	}
	var out []RestorePoint
	for _, o := range objs {
		name, ok := strings.CutSuffix(path.Base(o.Key), ".json")
		if !ok || !pointRe.MatchString(name) {
			continue
		}
		body, err := a.readAll(ctx, o.Key)
		if err != nil {
			return nil, err
		}
		var rp RestorePoint
		if err := json.Unmarshal(body, &rp); err != nil {
			return nil, fmt.Errorf("%s does not parse: %w", o.Key, err)
		}
		if rp.Name != name || rp.SystemID != a.SystemID {
			return nil, fmt.Errorf("%s names restore point %s of system %s", o.Key, rp.Name, rp.SystemID)
		}
		out = append(out, rp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

// CheckCounts compares a restore's row counts with the point's. It returns
// how many tables matched exactly (nobody wrote them around the point) and
// a description of each that came back outside its two counts.
func (rp RestorePoint) CheckCounts(got map[string]int64) (exact int, wrong []string) {
	for _, t := range rp.Tables {
		n, ok := got[t.Table]
		lo, hi := min(t.Before, t.After), max(t.Before, t.After)
		switch {
		case !ok:
			wrong = append(wrong, t.Table+" is missing")
		case n < lo || n > hi:
			if lo == hi {
				wrong = append(wrong, fmt.Sprintf("%s has %d rows, the restore point recorded %d", t.Table, n, lo))
			} else {
				wrong = append(wrong, fmt.Sprintf("%s has %d rows, the restore point recorded %d to %d", t.Table, n, lo, hi))
			}
		case lo == hi:
			exact++
		}
	}
	return exact, wrong
}
