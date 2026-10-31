package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/dbrun"
)

// engineTablePicks matches each --table to the manifest of a MySQL, SQLite
// or MongoDB run, whose tables have no schema of their own: a bare name, or
// the backup's database and the name as the console spells it
// (shop.orders). A dot in a MongoDB collection's own name is tried first.
func engineTablePicks(kind model.SurfaceType, manifest *model.SnapshotMetadata, id string, tables []string) ([]model.TableStat, error) {
	_, tableWord, _, _ := runUnit(kind)
	byName := map[string]model.TableStat{}
	prefix := ""
	for _, t := range manifest.TableStats {
		byName[t.TableName] = t
		if prefix == "" {
			prefix = t.Schema
		}
	}
	var picks []model.TableStat
	seen := map[string]bool{}
	for _, name := range tables {
		stat, ok := byName[name]
		if !ok {
			if db, rest, found := strings.Cut(name, "."); found && db == prefix {
				stat, ok = byName[rest]
			} else if found && prefix != "" {
				return nil, fmt.Errorf("--table %s names database %s, and %s is a backup of %s. Give the %s's name alone", name, db, id, prefix, tableWord)
			}
		}
		if !ok {
			return nil, fmt.Errorf("snapshot %s holds no %s %s", id, tableWord, name)
		}
		if seen[stat.TableName] {
			return nil, fmt.Errorf("--table %s is given twice", name)
		}
		seen[stat.TableName] = true
		picks = append(picks, stat)
	}
	return picks, nil
}

// restoreRepoEngineTables loads chosen tables of a MySQL or SQLite run, or
// chosen collections of a MongoDB run, into a database that may hold other
// tables: each absent from the target, or empty and defined as the backup
// recorded it. The rows come from one run, so they are consistent with
// each other, as of the snapshot; the target's other tables are as the
// target has them.
func restoreRepoEngineTables(ctx context.Context, rs *repoSnapshot, privateKey, targetURL string, tables []string, db dbRestoreOptions) error {
	kind, id := rs.Meta.SurfaceType, rs.Meta.SnapshotID
	_, tableWord, tablesWord, rowsWord := runUnit(kind)
	if db.Rows != "" {
		return fmt.Errorf("--rows restores rows of a PostgreSQL table; a %s %s restores whole with --table", kind, tableWord)
	}
	if db.As != "" {
		return fmt.Errorf("--as restores a PostgreSQL table beside the live one; a %s %s restores under its own name", kind, tableWord)
	}
	r, idx, files, err := openRun(ctx, rs, privateKey)
	if err != nil {
		return err
	}
	manifest, err := dbrun.ReadManifest(ctx, r, idx, files)
	if err != nil {
		return err
	}
	picks, err := engineTablePicks(kind, manifest, id, tables)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(picks))
	for _, p := range picks {
		names = append(names, p.TableName)
	}
	fmt.Printf("Restoring %s from %s (epoch %s, %s) into %s\n", strings.Join(names, ", "), id, rs.Epoch.Epoch.EpochID, rs.SurfaceID, dump.RedactURL(targetURL))
	started := time.Now()
	warn := func(msg string) { fmt.Fprintf(os.Stderr, "Warning: %s\n", msg) }
	var created []string
	var rows int64
	switch kind {
	case model.SurfaceTypeMySQL:
		_, head, sections, err := dbrun.SplitMySQL(ctx, r, idx, files)
		if err != nil {
			return fmt.Errorf("reading the snapshot back: %w", err)
		}
		byTable := map[string]dump.TableData{}
		for _, s := range sections {
			byTable[s.Table] = s
		}
		chosen := make([]dump.TableData, 0, len(picks))
		for _, p := range picks {
			s, ok := byTable[p.TableName]
			if !ok {
				return fmt.Errorf("snapshot %s holds no rows for %s; nothing was restored", id, p.TableName)
			}
			chosen = append(chosen, s)
		}
		created, rows, err = dump.RestoreMySQLTables(ctx, targetURL, head, chosen, picks, warn)
		if err != nil {
			return fmt.Errorf("restore failed: %w", err)
		}
	case model.SurfaceTypeMongoDB:
		var prelude strings.Builder
		byColl := map[string]dump.MongoRunPart{}
		for _, it := range files {
			switch {
			case it.Path == dump.MongoPreludeEntry:
				if err := r.Cat(ctx, idx, it.Node, &prelude); err != nil {
					return fmt.Errorf("reading the snapshot back: %w", err)
				}
			case dump.MongoRunCollection(it.Path) != "":
				node := it.Node
				byColl[dump.MongoRunCollection(it.Path)] = dump.MongoRunPart{Collection: dump.MongoRunCollection(it.Path), Size: node.Size,
					Open: func(w io.Writer) error { return r.Cat(ctx, idx, node, w) }}
			}
		}
		if prelude.Len() == 0 {
			return fmt.Errorf("snapshot %s has no %s; nothing was restored", id, dump.MongoPreludeEntry)
		}
		parts := make([]dump.MongoRunPart, 0, len(picks))
		for _, p := range picks {
			part, ok := byColl[p.TableName]
			if !ok {
				return fmt.Errorf("snapshot %s holds no documents for %s; nothing was restored", id, p.TableName)
			}
			parts = append(parts, part)
		}
		created, rows, err = dump.RestoreMongoCollections(ctx, targetURL, []byte(prelude.String()), parts, picks, db.Parallel)
		if err != nil {
			return fmt.Errorf("restore failed: %w", err)
		}
	case model.SurfaceTypeSQLite:
		pr, pw := io.Pipe()
		archived := make(chan error, 1)
		go func() {
			err := dbrun.Archive(ctx, r, idx, files, pw)
			_ = pw.CloseWithError(err)
			archived <- err
		}()
		created, rows, err = dump.RestoreSQLiteTables(ctx, targetURL, pr, picks)
		_, _ = io.Copy(io.Discard, pr)
		if aerr := <-archived; aerr != nil && err == nil {
			err = fmt.Errorf("reading the snapshot back: %w", aerr)
		}
		if err != nil {
			return fmt.Errorf("restore failed: %w", err)
		}
	default:
		return fmt.Errorf("--table restores tables of a database snapshot; %s is a %s snapshot", id, kind)
	}
	noteRestored(ctx, len(picks), rows)
	fmt.Printf("Restored %d %s, %s %s, from %s in %s. Every %s matched its count.\n", len(picks),
		pluralWord(int64(len(picks)), tableWord, tablesWord), formatNumber(rows), rowsWord, id, shortDuration(time.Since(started)), tableWord)
	fmt.Printf("   As of %s. The target's other %s are as they were, and are not consistent with it.\n", rs.Meta.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"), tablesWord)
	for _, name := range created {
		switch kind {
		case model.SurfaceTypeMongoDB:
			fmt.Printf("   Created %s as it was in %s, with its options and indexes.\n", name, id)
		default:
			fmt.Printf("   Created %s as it was defined in %s, with its indexes and triggers.\n", name, id)
		}
	}
	if kind != model.SurfaceTypeMongoDB && len(created) > 0 {
		fmt.Printf("   A foreign key of a created %s points at the target's tables as they are now.\n", tableWord)
	}
	return nil
}
