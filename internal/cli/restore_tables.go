package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
)

// tableRestore loads chosen tables of one snapshot into tables of the same
// definition that are empty in the target, in one transaction. A table the
// target does not have (dropped, the case guard is for) is first created
// from the snapshot's own schema sections, with its sequences, constraints
// and indexes, and its sequences are set to where the backup left them. They
// are consistent with each other, as of the snapshot; the target's other
// tables are as the target has them, and it says which ones these point at.
// A run of a repository and an archive feed it their rows differently.
type tableRestore struct {
	id   string
	asOf time.Time
	// sections reads the snapshot's schema sections, only when a table has
	// to be created.
	sections func() (map[string]string, error)

	picks   []tablePick
	chosen  map[string]bool // by tablePath
	created map[string]dump.TableDDL
	rows    int64
	started time.Time
}

type tablePick struct {
	name string // schema.table as the manifest spells it
	path string // tablePath
	stat model.TableStat
}

// pick matches each --table to the manifest. holds reports whether the
// snapshot has rows stored for a table's path.
func (tr *tableRestore) pick(stats []model.TableStat, tables []string, holds func(path string) bool) error {
	tr.chosen = map[string]bool{}
	for _, name := range tables {
		p, err := tablePath(name)
		if err != nil {
			return err
		}
		if !holds(p) {
			return fmt.Errorf("snapshot %s holds no table %s", tr.id, name)
		}
		var stat *model.TableStat
		for i := range stats {
			t := &stats[i]
			if "data/"+t.Schema+"/"+t.TableName+".copy" == p {
				stat = t
			}
		}
		if stat == nil {
			return fmt.Errorf("the manifest of %s does not list %s", tr.id, name)
		}
		if tr.chosen[p] {
			return fmt.Errorf("--table %s is given twice", name)
		}
		tr.chosen[p] = true
		tr.picks = append(tr.picks, tablePick{name: stat.Schema + "." + stat.TableName, path: p, stat: *stat})
	}
	return nil
}

// begin connects to the target and opens the restore's transaction. done
// rolls it back unless commit ran, and closes the connection.
func (tr *tableRestore) begin(ctx context.Context, targetURL string) (pgx.Tx, func(), error) {
	cc, err := pgx.ParseConfig(targetURL)
	if err != nil {
		return nil, nil, fmt.Errorf("the restore target's URL: %w", err)
	}
	if cc.ConnectTimeout == 0 {
		cc.ConnectTimeout = 30 * time.Second
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return nil, nil, fmt.Errorf("could not connect to the restore target: %w", err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		conn.Close(context.Background())
		return nil, nil, err
	}
	tr.started = time.Now()
	return tx, func() {
		_ = tx.Rollback(context.Background())
		conn.Close(context.Background())
	}, nil
}

// prepare creates each chosen table the target lacks, and refuses one whose
// definition differs from the snapshot's or that holds rows.
func (tr *tableRestore) prepare(ctx context.Context, tx pgx.Tx) error {
	tr.created = map[string]dump.TableDDL{}
	var sections map[string]string
	for _, p := range tr.picks {
		ident := pgx.Identifier{p.stat.Schema, p.stat.TableName}.Sanitize()
		hash, ok, err := dump.TableSchemaHash(ctx, tx, p.stat.Schema, p.stat.TableName)
		if err != nil {
			return fmt.Errorf("reading the definition of %s in the target: %w", p.name, err)
		}
		if !ok {
			if sections == nil {
				if sections, err = tr.sections(); err != nil {
					return err
				}
			}
			ddl, found := dump.TableDefinition(sections["pre-data.sql"], sections["post-data.sql"], sections["sequences.sql"],
				p.stat.Schema, p.stat.TableName, p.stat.OwnedSequences)
			if !found {
				return fmt.Errorf("the target has no table %s, and %s holds no definition of it to create it from. Restore the whole snapshot into an empty database", p.name, tr.id)
			}
			// The table's schema may be missing from a database that has
			// other tables, and the table cannot be made without it.
			if _, err := tx.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{p.stat.Schema}.Sanitize()); err != nil {
				return fmt.Errorf("creating schema %s for %s: %w; nothing was restored", p.stat.Schema, p.name, err)
			}
			if _, err := tx.Exec(ctx, ddl.Create); err != nil {
				return fmt.Errorf("creating %s as %s defines it: %w; nothing was restored", p.name, tr.id, err)
			}
			tr.created[p.name] = ddl
		}
		if p.stat.SchemaHash == "" {
			return fmt.Errorf("snapshot %s records no definition of %s to compare the target's with; restore the whole snapshot into an empty database instead", tr.id, p.name)
		}
		// A table created here is compared once its foreign keys are in,
		// after the rows (commit).
		if _, made := tr.created[p.name]; !made && hash != p.stat.SchemaHash {
			return fmt.Errorf("%s in the target is not defined as it was in %s (columns, types, defaults or constraints differ); nothing was restored", p.name, tr.id)
		}
		var held bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+ident+")").Scan(&held); err != nil {
			return err
		}
		if held {
			return fmt.Errorf("%s in the target holds rows; a restore never writes over data. Empty it, or restore into another database", p.name)
		}
	}
	return nil
}

// load copies one table's binary COPY stream in and holds the count to the
// manifest.
func (tr *tableRestore) load(ctx context.Context, tx pgx.Tx, p tablePick, rows io.Reader) error {
	ident := pgx.Identifier{p.stat.Schema, p.stat.TableName}.Sanitize()
	tag, err := tx.Conn().PgConn().CopyFrom(ctx, rows, "COPY "+ident+" FROM STDIN (FORMAT binary)")
	if err != nil {
		return fmt.Errorf("loading %s: %w; nothing was restored", p.name, err)
	}
	if tag.RowsAffected() != p.stat.RowCount {
		return fmt.Errorf("%s loaded %d rows, the backup recorded %d; nothing was restored", p.name, tag.RowsAffected(), p.stat.RowCount)
	}
	tr.rows += p.stat.RowCount
	return nil
}

// commit sets the created tables' sequences, commits, and says what was
// restored and what it points at.
func (tr *tableRestore) commit(ctx context.Context, tx pgx.Tx) error {
	for _, p := range tr.picks {
		ddl, ok := tr.created[p.name]
		if !ok || ddl.ForeignKeys == "" {
			continue
		}
		if _, err := tx.Exec(ctx, ddl.ForeignKeys); err != nil {
			return fmt.Errorf("adding the foreign keys of %s: %w; nothing was restored. Restore the tables it points at with it, or into a target that has them", p.name, err)
		}
	}
	for _, p := range tr.picks {
		if _, ok := tr.created[p.name]; !ok {
			continue
		}
		hash, found, err := dump.TableSchemaHash(ctx, tx, p.stat.Schema, p.stat.TableName)
		if err != nil || !found {
			return fmt.Errorf("reading the definition of %s after creating it: %v; nothing was restored", p.name, err)
		}
		if hash != p.stat.SchemaHash {
			return fmt.Errorf("%s as created from %s is not defined as the backup recorded it; nothing was restored", p.name, tr.id)
		}
	}
	for _, p := range tr.picks {
		if ddl, ok := tr.created[p.name]; ok && ddl.Setvals != "" {
			if _, err := tx.Exec(ctx, ddl.Setvals); err != nil {
				return fmt.Errorf("setting the sequences of %s: %w; nothing was restored", p.name, err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing the restore: %w", err)
	}
	noteRestored(ctx, len(tr.picks), tr.rows)
	fmt.Printf("Restored %d %s, %s rows, from %s in %s. Every table matched its SHA-256 and its row count.\n", len(tr.picks),
		pluralWord(int64(len(tr.picks)), "table", "tables"), formatNumber(tr.rows), tr.id, shortDuration(time.Since(tr.started)))
	fmt.Printf("   As of %s. The target's other tables are as they were, and are not consistent with it.\n", tr.asOf.UTC().Format("2006-01-02 15:04:05 UTC"))
	for _, p := range tr.picks {
		if ddl, ok := tr.created[p.name]; ok {
			fmt.Printf("   Created %s as it was defined in %s (%d %s: the table, its sequences, constraints and indexes).\n",
				p.name, tr.id, ddl.Objects, pluralWord(int64(ddl.Objects), "object", "objects"))
		}
		var notLoaded []string
		for _, ref := range p.stat.References {
			if !tr.chosen["data/"+strings.Replace(ref, ".", "/", 1)+".copy"] {
				notLoaded = append(notLoaded, ref)
			}
		}
		if len(notLoaded) > 0 {
			fmt.Printf("   %s points at %s, which this restore did not load.\n", p.name, strings.Join(notLoaded, ", "))
		}
		if len(p.stat.OwnedSequences) > 0 {
			if ddl, ok := tr.created[p.name]; ok && ddl.Setvals != "" {
				fmt.Printf("   %s set to where the backup left %s.\n", strings.Join(p.stat.OwnedSequences, ", "), pluralWord(int64(len(p.stat.OwnedSequences)), "it", "them"))
			} else {
				fmt.Printf("   %s owns %s, which this restore did not move.\n", p.name, strings.Join(p.stat.OwnedSequences, ", "))
			}
		}
	}
	return nil
}
