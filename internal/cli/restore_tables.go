package cli

import (
	"context"
	"fmt"
	"io"
	"os"
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

	// noOwner creates a missing table without its owner and grants. Without
	// it, a role that is not a superuser creates the table as itself and
	// then tries each ownership statement on its own; skipped lists the
	// ones it may not run, as a whole restore does.
	noOwner bool
	skipped []string

	// where is a row restore's condition (restore_rows.go): each chosen
	// table is loaded into a temporary table and the rows it matches are
	// written into the target's table by primary key. overwrite replaces
	// a row the target has; without it that row is left as it is.
	where     string
	overwrite bool
	temp      map[string]string // the temporary table each pick loaded into, by name
	rowsDone  map[string]rowsResult

	// as, with one pick, restores it under this name beside the live
	// table: a table with the live one's columns, created here, that the
	// backup's rows load into. The live table stays as it is.
	as string
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
	super, superKnown := false, false
	for i, p := range tr.picks {
		ident := pgx.Identifier{p.stat.Schema, p.stat.TableName}.Sanitize()
		hash, ok, err := dump.TableSchemaHash(ctx, tx, p.stat.Schema, p.stat.TableName)
		if err != nil {
			return fmt.Errorf("reading the definition of %s in the target: %w", p.name, err)
		}
		if tr.where != "" {
			// Rows go into the table as the target has it: it has to be
			// there, defined as the backup recorded it, and may hold rows.
			if !ok {
				return fmt.Errorf("the target has no table %s to put rows into; restore the whole table with --table alone, which creates it", p.name)
			}
			if p.stat.SchemaHash == "" {
				return fmt.Errorf("snapshot %s records no definition of %s to compare the target's with; restore the whole table into an empty database instead", tr.id, p.name)
			}
			if hash != p.stat.SchemaHash {
				return fmt.Errorf("%s in the target is not defined as it was in %s (columns, types, defaults or constraints differ); nothing was restored", p.name, tr.id)
			}
			// INCLUDING GENERATED keeps a generated column generated, so the
			// backup's COPY stream, which leaves such columns out, loads
			// into it as it loads into the table itself.
			temp := pgx.Identifier{fmt.Sprintf("safegrd_rows_%d", i)}.Sanitize()
			if _, err := tx.Exec(ctx, "CREATE TEMPORARY TABLE "+temp+" (LIKE "+ident+" INCLUDING GENERATED) ON COMMIT DROP"); err != nil {
				return fmt.Errorf("making a temporary table for the rows of %s: %w; nothing was restored", p.name, err)
			}
			if tr.temp == nil {
				tr.temp = map[string]string{}
			}
			tr.temp[p.name] = temp
			continue
		}
		if tr.as != "" {
			// The copy takes the live table's columns, so the live table
			// has to be there, defined as the backup recorded it.
			if !ok {
				return fmt.Errorf("the target has no table %s to restore beside; restore it with --table alone, which creates it", p.name)
			}
			if p.stat.SchemaHash == "" {
				return fmt.Errorf("snapshot %s records no definition of %s to compare the target's with; restore the whole table into an empty database instead", tr.id, p.name)
			}
			if hash != p.stat.SchemaHash {
				return fmt.Errorf("%s in the target is not defined as it was in %s (columns, types, defaults or constraints differ), so a copy of it would not take the backup's rows; restore the table into another database", p.name, tr.id)
			}
			asSchema, asTable, _ := splitTableName(tr.as)
			if _, exists, err := dump.TableSchemaHash(ctx, tx, asSchema, asTable); err != nil {
				return fmt.Errorf("reading whether the target has %s: %w", tr.as, err)
			} else if exists {
				return fmt.Errorf("the target already has %s; --as names a table it does not have", tr.as)
			}
			if _, err := tx.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{asSchema}.Sanitize()); err != nil {
				return fmt.Errorf("creating schema %s for %s: %w; nothing was restored", asSchema, tr.as, err)
			}
			asIdent := pgx.Identifier{asSchema, asTable}.Sanitize()
			if _, err := tx.Exec(ctx, "CREATE TABLE "+asIdent+" (LIKE "+ident+" INCLUDING GENERATED)"); err != nil {
				return fmt.Errorf("creating %s with the columns of %s: %w; nothing was restored", tr.as, p.name, err)
			}
			if tr.temp == nil {
				tr.temp = map[string]string{}
			}
			tr.temp[p.name] = asIdent
			continue
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
			if !superKnown {
				if err := tx.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&super); err != nil {
					return fmt.Errorf("reading whether the restoring role is a superuser: %w", err)
				}
				superKnown = true
			}
			create, ownership := ddl.Create, []string(nil)
			switch {
			case tr.noOwner:
				create = dump.StripOwnership(create)
			case !super:
				// ALTER ... OWNER TO the backup's owner needs the right to
				// SET ROLE to it, which an ordinary role does not have:
				// create as this role, then try each statement alone.
				create, ownership = dump.SplitOwnership(create)
			}
			if _, err := tx.Exec(ctx, create); err != nil {
				return fmt.Errorf("creating %s as %s defines it: %w; nothing was restored", p.name, tr.id, err)
			}
			for _, stmt := range ownership {
				if _, err := tx.Exec(ctx, "SAVEPOINT safegrd_ownership"); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, stmt); err != nil {
					if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT safegrd_ownership"); err != nil {
						return err
					}
					tr.skipped = append(tr.skipped, strings.TrimSuffix(stmt, ";"))
				}
				if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT safegrd_ownership"); err != nil {
					return err
				}
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
	if temp, ok := tr.temp[p.name]; ok {
		ident = temp
	}
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
	if tr.where != "" {
		return tr.commitRows(ctx, tx)
	}
	if tr.as != "" {
		return tr.commitAs(ctx, tx)
	}
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
	if n := len(tr.skipped); n > 0 {
		shown := tr.skipped
		if len(shown) > 5 {
			shown = shown[:5]
		}
		fmt.Fprintf(os.Stderr, "Warning: %d ownership or privilege statements were skipped: the restoring role is not a superuser and may not run them.\n"+
			"   Those objects belong to the restoring role. Restore as a superuser to keep every owner and grant.\n     %s\n", n, strings.Join(shown, "\n     "))
	}
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

// commitAs commits the copy restored beside the live table and says what
// it is and is not.
func (tr *tableRestore) commitAs(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing the restore: %w", err)
	}
	p := tr.picks[0]
	noteRestored(ctx, 1, tr.rows)
	fmt.Printf("Restored %s rows of %s from %s as %s in %s. The rows matched the backup's count.\n", formatNumber(tr.rows), p.name, tr.id, tr.as, shortDuration(time.Since(tr.started)))
	fmt.Printf("   As of %s. %s is as it was.\n", tr.asOf.UTC().Format("2006-01-02 15:04:05 UTC"), p.name)
	fmt.Printf("   %s has the columns of %s and no indexes, constraints or defaults. Compare the two with SQL, copy back what you need, and drop %s after.\n", tr.as, p.name, tr.as)
	return nil
}

// commitRows writes each loaded table's matching rows into the target and
// says what was inserted, replaced and left alone.
func (tr *tableRestore) commitRows(ctx context.Context, tx pgx.Tx) error {
	tr.rowsDone = map[string]rowsResult{}
	for _, p := range tr.picks {
		res, err := restoreRows(ctx, tx, p, tr.temp[p.name], tr.where, tr.overwrite)
		if err != nil {
			return err
		}
		tr.rowsDone[p.name] = res
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing the restore: %w", err)
	}
	var written int64
	for _, p := range tr.picks {
		res := tr.rowsDone[p.name]
		written += res.inserted + res.updated
		fmt.Printf("Restored %s %s of %s from %s in %s: %s inserted, %s replaced.\n", formatNumber(res.inserted+res.updated),
			pluralWord(res.inserted+res.updated, "row", "rows"), p.name, tr.id, shortDuration(time.Since(tr.started)),
			formatNumber(res.inserted), formatNumber(res.updated))
		if res.kept > 0 {
			fmt.Printf("   %s matching %s the target already has %s left as %s. --overwrite replaces %s with the backup's.\n",
				formatNumber(res.kept), pluralWord(res.kept, "row", "rows"), pluralWord(res.kept, "is", "are"), pluralWord(res.kept, "it is", "they are"), pluralWord(res.kept, "it", "them"))
		}
		if len(p.stat.OwnedSequences) > 0 {
			fmt.Printf("   %s owns %s, which this restore did not move: a row put back past its value collides with the next insert until setval moves it.\n",
				p.name, strings.Join(p.stat.OwnedSequences, ", "))
		}
	}
	noteRestored(ctx, len(tr.picks), written)
	fmt.Printf("   As of %s. The table's other rows are as the target had them.\n", tr.asOf.UTC().Format("2006-01-02 15:04:05 UTC"))
	return nil
}
