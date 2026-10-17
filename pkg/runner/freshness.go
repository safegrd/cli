package runner

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/model"
)

// readSandboxNewestRows reads, for each table the backup recorded a newest
// row for, the same column's newest value in the sandbox, formatted as the
// backup formatted it, into restored's table stats. A table the backup
// recorded no newest row for is not read.
func readSandboxNewestRows(ctx context.Context, sandboxURL string, meta, restored *model.SnapshotMetadata) error {
	byName := map[string]*model.TableStat{}
	for i := range restored.TableStats {
		t := &restored.TableStats[i]
		byName[t.Schema+"."+t.TableName] = t
	}
	var want []model.TableStat
	for _, t := range meta.TableStats {
		if t.FreshnessColumn != "" && t.FreshnessMax != "" && byName[t.Schema+"."+t.TableName] != nil {
			want = append(want, t)
		}
	}
	if len(want) == 0 {
		return nil
	}
	conn, err := pgx.Connect(ctx, sandboxURL)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()
	// UTC, as the backup read it, so a timestamp without a time zone and one
	// with print the same text on both sides.
	if _, err := conn.Exec(ctx, "SET TimeZone = 'UTC'"); err != nil {
		return err
	}
	for _, t := range want {
		var newest *string
		q := fmt.Sprintf(`SELECT to_char(max(%s), 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') FROM %s`,
			pgx.Identifier{t.FreshnessColumn}.Sanitize(), pgx.Identifier{t.Schema, t.TableName}.Sanitize())
		if err := conn.QueryRow(ctx, q).Scan(&newest); err != nil {
			return fmt.Errorf("reading the newest %s of %s.%s in the sandbox: %w", t.FreshnessColumn, t.Schema, t.TableName, err)
		}
		r := byName[t.Schema+"."+t.TableName]
		r.FreshnessColumn = t.FreshnessColumn
		if newest != nil {
			r.FreshnessMax = *newest
		}
	}
	return nil
}

// newestRowAssertions holds each table's newest row in the sandbox to the one
// the backup recorded. Equal row counts with a different newest row are
// different rows. A table the backup recorded no newest row for has no
// assertion.
func newestRowAssertions(meta, restored *model.SnapshotMetadata) ([]model.AssertionResult, bool) {
	got := map[string]model.TableStat{}
	for _, t := range restored.TableStats {
		got[t.Schema+"."+t.TableName] = t
	}
	var out []model.AssertionResult
	passed := true
	for _, t := range meta.TableStats {
		key := t.Schema + "." + t.TableName
		r, ok := got[key]
		if t.FreshnessColumn == "" || t.FreshnessMax == "" || !ok {
			continue
		}
		a := model.AssertionResult{Name: "Newest Row: " + key, Expected: t.FreshnessColumn + " " + t.FreshnessMax,
			Actual: r.FreshnessColumn + " " + r.FreshnessMax, Passed: r.FreshnessMax == t.FreshnessMax}
		if r.FreshnessMax == "" {
			a.Actual = "no rows"
		}
		if !a.Passed {
			passed = false
			a.Message = "The table's newest row in the sandbox is not the one the backup recorded"
		}
		out = append(out, a)
	}
	return out, passed
}
