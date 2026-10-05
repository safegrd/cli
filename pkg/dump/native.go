package dump

import (
	"archive/tar"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/safegrd/cli/pkg/model"
)

// A Postgres snapshot is a tar archive, written and read strictly in order:
//
//	roles.sql         pg_dumpall --roles-only, cut to the roles the schema names
//	                  (roles.go); absent when the schema names none
//	pre-data.sql      pg_dump --section=pre-data: types, tables, functions, views,
//	                  with their owners and privileges
//	                  (schema.sql instead, when no usable pg_dump was on the host)
//	data/<s>/<t>.copy each table's rows as binary COPY, in chunks (copy_stream.go)
//	post-data.sql     pg_dump --section=post-data: indexes, constraints, triggers
//	sequences.sql     every sequence's position, read after the rows
//	manifest.json     the catalogue, with every table's exact row count
//
// The rows, the schema and the counts all come from one exported snapshot, so
// a database that is being written to while it is backed up still produces a
// manifest that matches its archive exactly. The manifest comes last because
// the counts are only known once the rows are copied. Readers must not depend
// on its position: older archives put it first.
const (
	entryPreData   = "pre-data.sql"
	entryPostData  = "post-data.sql"
	entrySequences = "sequences.sql"
	entrySchema    = "schema.sql" // the native extractor's output: older archives, and the fallback
	entryManifest  = "manifest.json"
)

// SchemaSourceNative marks a snapshot whose schema was re-derived without
// pg_dump: it restores without foreign keys, views, triggers or enum types.
const SchemaSourceNative = "native"

// NativeDumper streams a Postgres database into a snapshot archive.
type NativeDumper struct {
	databaseURL string
	// Warn is told what a backup could not do properly and carried on without.
	// It prints to stderr unless replaced.
	Warn func(string)
	// Carry, when set, is asked once inside the backup's snapshot, after the
	// tables are listed and described and before any is read, which tables
	// to carry forward from an earlier backup instead of reading, keyed
	// schema.table, with the row count that backup recorded. Their rows are
	// not copied and they are marked Carried. filtered are the tables
	// row-level security filters for this role. An error is warned about
	// and every table is read.
	Carry func(ctx context.Context, tx pgx.Tx, meta *model.SnapshotMetadata, filtered map[string]int64, serverVersionNum int) (map[string]int64, error)
	// RolesWithoutPasswords leaves role passwords out of roles.sql. By
	// default they ride along, sealed with everything else, so a restored
	// role logs in as it did.
	RolesWithoutPasswords bool
}

// NewNativeDumper creates a dumper for databaseURL.
func NewNativeDumper(databaseURL string) *NativeDumper {
	return &NativeDumper{databaseURL: databaseURL, Warn: func(msg string) {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", msg)
	}}
}

// userTablesQuery lists the tables a backup copies: ordinary tables in user
// schemas, not another session's temporary tables, and not tables an
// extension creates and fills itself (restoring those rows would collide with
// the ones CREATE EXTENSION puts back).
const userTablesQuery = `
	SELECT n.nspname, c.relname, pg_total_relation_size(c.oid)
	FROM pg_class c
	JOIN pg_namespace n ON n.oid = c.relnamespace
	WHERE c.relkind = 'r' AND c.relpersistence <> 't'
	  AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
	  AND NOT EXISTS (SELECT 1 FROM pg_depend d
	                  WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
	ORDER BY n.nspname, c.relname`

// rowSecurityQuery lists the tables row-level security filters for the role
// taking the backup, with the statistics collector's estimate of their live
// rows. A policy applies unless the role is a superuser or has BYPASSRLS, or
// owns the table (directly or through a role it inherits) and the table does
// not FORCE row-level security. pg_read_all_data does not bypass it, so a
// read-only backup role copies only the rows its policies let it see, and
// COPY says nothing about the rest.
const rowSecurityQuery = `
	SELECT n.nspname, c.relname, COALESCE(s.n_live_tup, 0)
	FROM pg_class c
	JOIN pg_namespace n ON n.oid = c.relnamespace
	LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
	WHERE c.relkind = 'r' AND c.relrowsecurity
	  AND NOT EXISTS (SELECT 1 FROM pg_roles r
	                  WHERE r.rolname = current_user AND (r.rolsuper OR r.rolbypassrls))
	  AND (c.relforcerowsecurity OR NOT pg_has_role(current_user, c.relowner, 'USAGE'))`

// userSequencesQuery lists the sequences whose positions a restore needs.
const userSequencesQuery = `
	SELECT n.nspname, c.relname
	FROM pg_class c
	JOIN pg_namespace n ON n.oid = c.relnamespace
	WHERE c.relkind = 'S'
	  AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
	  AND NOT EXISTS (SELECT 1 FROM pg_depend d
	                  WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
	ORDER BY n.nspname, c.relname`

// Dump streams a complete snapshot archive of the database into dst.
func (d *NativeDumper) Dump(ctx context.Context, databaseName string, dst io.Writer) (*model.SnapshotMetadata, error) {
	// When the snapshot was taken. The file and mail collectors always set it;
	// the database engines did not, so every database meta.json carried the
	// zero time and the remote server ordered those snapshots as year 1.
	started := time.Now().UTC()
	startTime := time.Now()

	conn, err := connectPostgres(ctx, d.databaseURL)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the database: %w", err)
	}
	defer conn.Close(context.Background())

	// One snapshot for everything: the table list, the schema pg_dump reads,
	// the rows, and so the counts.
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("failed to start the snapshot transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	meta := &model.SnapshotMetadata{DatabaseName: databaseName, SurfaceType: model.SurfaceTypePostgres, CreatedAt: started}
	var serverVersionNum int
	var currentDB string
	if err := tx.QueryRow(ctx, "SELECT version(), current_setting('server_version_num')::int, current_database()").Scan(&meta.PostgresVersion, &serverVersionNum, &currentDB); err != nil {
		return nil, fmt.Errorf("failed to read the server version: %w", err)
	}
	if meta.DatabaseName == "" {
		meta.DatabaseName = currentDB
	}
	meta.PostgresVersion = strings.TrimSpace(meta.PostgresVersion)
	if meta.Extensions, err = queryStrings(ctx, tx, "SELECT extname FROM pg_extension WHERE extname <> 'plpgsql' ORDER BY extname"); err != nil {
		return nil, fmt.Errorf("failed to list extensions: %w", err)
	}
	rows, err := tx.Query(ctx, userTablesQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to list tables: %w", err)
	}
	for rows.Next() {
		var t model.TableStat
		if err := rows.Scan(&t.Schema, &t.TableName, &t.SizeBytes); err != nil {
			rows.Close()
			return nil, err
		}
		meta.TableStats = append(meta.TableStats, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to list tables: %w", err)
	}

	// What a backup records beyond its rows, which a one-table restore checks
	// against and two backups are ordered by. A server that will
	// not describe its tables still gets its backup, and is told.
	if _, err := tx.Exec(ctx, "SAVEPOINT safegrd_describe"); err == nil {
		if err := describeTables(ctx, tx, serverVersionNum, meta.TableStats); err != nil {
			_, _ = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT safegrd_describe")
			for i := range meta.TableStats {
				t := &meta.TableStats[i]
				t.SchemaHash, t.OwnedSequences, t.References = "", nil, nil
			}
			d.Warn(fmt.Sprintf("%v. The backup goes on without each table's schema hash, owned sequences and foreign key targets.", err))
		} else {
			_, _ = tx.Exec(ctx, "RELEASE SAVEPOINT safegrd_describe")
		}
	}
	// Each table's newest row and a hash of its first rows, which Threat
	// Shield compares between backups. A backup that cannot read them still
	// runs, and says so.
	if _, err := tx.Exec(ctx, "SAVEPOINT safegrd_freshness"); err == nil {
		if err := describeFreshness(ctx, tx, meta.TableStats); err != nil {
			_, _ = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT safegrd_freshness")
			for i := range meta.TableStats {
				t := &meta.TableStats[i]
				t.FreshnessColumn, t.FreshnessMax, t.SampleHash = "", "", ""
			}
			d.Warn(fmt.Sprintf("%v. The backup goes on without each table's newest row and sample hash.", err))
		} else {
			_, _ = tx.Exec(ctx, "RELEASE SAVEPOINT safegrd_freshness")
		}
	}
	meta.SourceSnapshot, meta.SourceLSN = runIdentity(ctx, tx, serverVersionNum)
	if meta.SourceSnapshot == "" {
		d.Warn("The server did not report the snapshot this backup reads under, so the backup records none.")
	}

	filtered, err := rowSecurityTables(ctx, tx)
	if err != nil {
		return nil, err
	}

	var carry map[string]int64
	if d.Carry != nil {
		if _, err := tx.Exec(ctx, "SAVEPOINT safegrd_carry"); err == nil {
			if carry, err = d.Carry(ctx, tx, meta, filtered, serverVersionNum); err != nil {
				_, _ = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT safegrd_carry")
				carry = nil
				d.Warn(fmt.Sprintf("The change log could not be read (%v). Every table is read.", err))
			} else {
				_, _ = tx.Exec(ctx, "RELEASE SAVEPOINT safegrd_carry")
			}
		}
	}

	tw := tar.NewWriter(dst)

	// The schema, from pg_dump under our snapshot when there is one that can
	// dump this server. Without one the backup still runs, because the rows
	// are the part that cannot be recreated, and it says what it lost.
	var postData []byte
	pgDump, findErr := FindPgDump(ctx, serverVersionNum/10000)
	if findErr == nil {
		var snapshot string
		if err := tx.QueryRow(ctx, "SELECT pg_export_snapshot()").Scan(&snapshot); err != nil {
			return nil, fmt.Errorf("failed to export the snapshot for pg_dump: %w", err)
		}
		preData, err := pgDump.Section(ctx, d.databaseURL, snapshot, "pre-data")
		if err != nil {
			return nil, err
		}
		if postData, err = pgDump.Section(ctx, d.databaseURL, snapshot, "post-data"); err != nil {
			return nil, err
		}
		// The roles the schema names, before the schema, so a restore meets
		// them first. A backup that cannot read them still runs, and says
		// what its restore will need.
		if meta.RolesNamed = namedRoles(preData, postData); len(meta.RolesNamed) > 0 {
			rolesSQL, source, warn := d.rolesEntry(ctx, pgDump, meta.RolesNamed)
			if warn != "" {
				d.Warn(warn)
			}
			if rolesSQL != nil {
				if err := writeTarEntry(tw, entryRoles, rolesSQL); err != nil {
					return nil, err
				}
				meta.RolesSource = source
			}
		}
		if err := writeTarEntry(tw, entryPreData, preData); err != nil {
			return nil, err
		}
		meta.SchemaSource = "pg_dump " + pgDump.Version
	} else {
		d.Warn(fmt.Sprintf("The schema of %s was captured WITHOUT pg_dump: %v.\n"+
			"   The rows are backed up in full, but a restore of this snapshot will be missing foreign keys,\n"+
			"   views, triggers, functions and enum types, and its Fire Drill will fail until pg_dump is installed.", databaseName, findErr))
		stdDB, err := sql.Open("pgx", d.databaseURL)
		if err != nil {
			return nil, err
		}
		ddl, err := NewSchemaExtractor(stdDB).ExtractDDL(ctx)
		stdDB.Close()
		if err != nil {
			return nil, fmt.Errorf("schema extraction failed: %w", err)
		}
		if err := writeTarEntry(tw, entrySchema, []byte(ddl)); err != nil {
			return nil, err
		}
		meta.SchemaSource = SchemaSourceNative
	}

	// The rows. The count is the one COPY reports, inside the snapshot, so it
	// is exact: an estimate here made every drill of a busy table a coin toss.
	pgConn := conn.PgConn()
	for i := range meta.TableStats {
		t := &meta.TableStats[i]
		if n, ok := carry[t.Schema+"."+t.TableName]; ok {
			t.RowCount, t.Carried = n, true
			continue
		}
		cw := newChunkWriter(tw, t.Schema, t.TableName)
		tag, err := pgConn.CopyTo(ctx, cw, "COPY "+pgx.Identifier{t.Schema, t.TableName}.Sanitize()+" TO STDOUT (FORMAT binary)")
		if err != nil {
			return nil, fmt.Errorf("failed to copy %s.%s: %w", t.Schema, t.TableName, err)
		}
		if err := cw.Close(); err != nil {
			return nil, fmt.Errorf("failed to write %s.%s to the archive: %w", t.Schema, t.TableName, err)
		}
		t.RowCount = tag.RowsAffected()
	}
	if msg := markRowSecurity(meta.TableStats, filtered); msg != "" {
		d.Warn(fmt.Sprintf("Row-level security hid rows of %s from this backup's role:\n%s"+
			"   Those tables are backed up with only the rows the role could see. Back up as the tables'\n"+
			"   owner or a role with BYPASSRLS (ALTER ROLE ... BYPASSRLS) to capture every row.", databaseName, msg))
	}

	if postData != nil {
		if err := writeTarEntry(tw, entryPostData, postData); err != nil {
			return nil, err
		}
	}

	// Sequences are not transactional, so reading them now, after the rows,
	// gives a position at or past every id that was copied.
	seqSQL, err := sequencePositions(ctx, tx)
	if err != nil {
		return nil, err
	}
	if err := writeTarEntry(tw, entrySequences, seqSQL); err != nil {
		return nil, err
	}

	meta.CalculateTotals()
	meta.DurationMs = elapsedMilliseconds(startTime)
	manifest, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeTarEntry(tw, entryManifest, manifest); err != nil {
		return nil, fmt.Errorf("failed writing the manifest to the archive: %w", err)
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close the archive: %w", err)
	}
	return meta, nil
}

// rolesEntry is roles.sql for the roles named, how it was taken, and a
// warning when something was not: no pg_dumpall, a role the dump lacks, or
// passwords the backup role may not read.
func (d *NativeDumper) rolesEntry(ctx context.Context, pgDump *PgDump, named []string) (sql []byte, source, warn string) {
	all, passwords, err := pgDump.Roles(ctx, d.databaseURL, !d.RolesWithoutPasswords)
	if err != nil {
		return nil, "", fmt.Sprintf("The roles this schema names (%s) were not backed up: %v.\n"+
			"   A restore into a cluster that lacks them fails until they are created there first.", strings.Join(named, ", "), err)
	}
	sql, missing := parseRolesSQL(all).only(named)
	source = "pg_dumpall " + pgDump.Version
	if !passwords {
		source += ", no passwords"
		if !d.RolesWithoutPasswords {
			warn = "The backup role may not read role passwords (pg_authid), so the roles this schema names are backed up without them.\n" +
				"   A restore creates them without a password; set one after the restore, or back up as a superuser."
		}
	}
	if len(missing) > 0 {
		warn = strings.TrimSpace(warn + fmt.Sprintf("\nThe schema names roles the cluster does not list: %s. A restore has to create them first.", strings.Join(missing, ", ")))
	}
	return sql, source, warn
}

// rowSecurityTables returns the live-row estimate of each table row-level
// security filters for this role, keyed "schema.table".
func rowSecurityTables(ctx context.Context, tx pgx.Tx) (map[string]int64, error) {
	rows, err := tx.Query(ctx, rowSecurityQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to list tables under row-level security: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var schema, name string
		var live int64
		if err := rows.Scan(&schema, &name, &live); err != nil {
			return nil, err
		}
		out[schema+"."+name] = live
	}
	return out, rows.Err()
}

// markRowSecurity flags each table row-level security filtered and returns
// one line per table for the warning, or "" when none was. Every such table is
// flagged, whatever its count: the role cannot tell how many rows it was not
// shown. The statistics collector's estimate is printed beside the count when
// it is larger, as a hint of how much is missing.
func markRowSecurity(stats []model.TableStat, filtered map[string]int64) string {
	var b strings.Builder
	for i := range stats {
		t := &stats[i]
		live, ok := filtered[t.Schema+"."+t.TableName]
		if !ok {
			continue
		}
		t.RowSecurity = true
		fmt.Fprintf(&b, "     %s.%s: %d rows copied", t.Schema, t.TableName, t.RowCount)
		if live > t.RowCount {
			fmt.Fprintf(&b, ", about %d in the table", live)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// sequencePositions writes a setval for every user sequence, as SQL.
func sequencePositions(ctx context.Context, tx pgx.Tx) ([]byte, error) {
	rows, err := tx.Query(ctx, userSequencesQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to list sequences: %w", err)
	}
	type seq struct{ schema, name string }
	var seqs []seq
	for rows.Next() {
		var s seq
		if err := rows.Scan(&s.schema, &s.name); err != nil {
			rows.Close()
			return nil, err
		}
		seqs = append(seqs, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("-- Sequence positions, read after the rows were copied.\n")
	for _, s := range seqs {
		ident := pgx.Identifier{s.schema, s.name}.Sanitize()
		var last int64
		var called bool
		if err := tx.QueryRow(ctx, "SELECT last_value, is_called FROM "+ident).Scan(&last, &called); err != nil {
			// A restore that starts a sequence over hands out ids that are
			// already taken, so a sequence that cannot be read fails the backup.
			return nil, fmt.Errorf("failed to read sequence %s.%s: %w", s.schema, s.name, err)
		}
		fmt.Fprintf(&b, "SELECT pg_catalog.setval(%s, %d, %t);\n", quoteLiteral(ident), last, called)
	}
	return []byte(b.String()), nil
}

func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func queryStrings(ctx context.Context, tx pgx.Tx, q string) ([]string, error) {
	rows, err := tx.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// NativeRestorer loads a snapshot archive into an empty database, or chosen
// schemas of it into a database that already has others.
type NativeRestorer struct {
	targetURL string
	// Schemas, when set, restores only these schemas: their objects and
	// their rows. DataOnlySchemas restores only the rows of these schemas,
	// into tables that already exist. With either set the target may hold
	// other tables: a managed database such as a Supabase project is never
	// empty, and its schemas are not the customer's to recreate.
	Schemas         map[string]bool
	DataOnlySchemas map[string]bool
	// NoOwner restores without ownership, privileges and default
	// privileges, as pg_restore --no-owner --no-acl would: every object
	// belongs to the restoring role. The roles roles.sql carries are still
	// created, because a policy names its roles and cannot be restored
	// without them.
	NoOwner bool
	// CreatedRoles are the roles the restore created on the target, in
	// order, because the schema names them and the target lacked them.
	CreatedRoles []string
	// SkippedOwnership are the ownership and privilege statements a
	// restoring role that is not a superuser could not run: an OWNER TO a
	// role it is not a member of, a privilege on an object it does not own.
	// Each is skipped under a savepoint and the objects belong to the
	// restoring role; Warn says so once.
	SkippedOwnership []string
	// Warn is told what the restore could not bring back. Stderr by default.
	Warn func(string)
	// BeforeCommit, if set, runs after everything is loaded and before the
	// transaction commits; an error rolls the whole restore back. The caller
	// checks the stream's digest there, so a snapshot that fails it never
	// becomes a database.
	BeforeCommit func() error
}

// NewNativeRestorer creates a restorer for targetURL.
func NewNativeRestorer(targetURL string) *NativeRestorer {
	return &NativeRestorer{targetURL: targetURL, Warn: func(msg string) {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", msg)
	}}
}

// Restore loads the archive in one transaction: a restore that fails part
// way leaves the target as empty as it found it, never half a database that
// looks like the real one. It refuses a target that already holds tables, and
// holds every table's loaded row count to the manifest.
func (r *NativeRestorer) Restore(ctx context.Context, src io.Reader) (*model.SnapshotMetadata, error) {
	conn, err := connectPostgres(ctx, r.targetURL)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the restore target: %w", err)
	}
	defer conn.Close(context.Background())
	filtered := len(r.Schemas) > 0 || len(r.DataOnlySchemas) > 0
	if !filtered {
		if err := checkTargetEmpty(ctx, conn); err != nil {
			return nil, err
		}
	}
	// wantRows and wantSQL say what of a schema the restore loads.
	wantRows := func(schema string) bool { return !filtered || r.Schemas[schema] || r.DataOnlySchemas[schema] }
	wantSQL := func(schema string) bool { return !filtered || r.Schemas[schema] }

	known, err := serverSettings(ctx, conn)
	if err != nil {
		return nil, err
	}

	pgConn := conn.PgConn()
	exec := func(what, sqlText string) error {
		if _, err := pgConn.Exec(ctx, sqlText).ReadAll(); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		return nil
	}
	if err := exec("starting the restore transaction", "BEGIN"); err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = pgConn.Exec(context.Background(), "ROLLBACK").ReadAll()
		}
	}()

	var manifest *model.SnapshotMetadata
	loaded := map[string]int64{}
	var sawSchema, sawSequences, legacySchema bool
	var super bool
	if err := conn.QueryRow(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&super); err != nil {
		return nil, fmt.Errorf("could not read the restoring role: %w", err)
	}

	streams := &tableStreams{
		consume: func(schema, table string, rd io.Reader) error {
			if !wantRows(schema) {
				_, err := io.Copy(io.Discard, rd)
				return err
			}
			tag, err := pgConn.CopyFrom(ctx, rd, "COPY "+pgx.Identifier{schema, table}.Sanitize()+" FROM STDIN (FORMAT binary)")
			if err != nil {
				if filtered && r.DataOnlySchemas[schema] {
					return fmt.Errorf("loading rows into %s.%s, which has to exist already with the backup's columns: %w", schema, table, err)
				}
				return fmt.Errorf("loading %s.%s: %w", schema, table, err)
			}
			loaded[schema+"."+table] += tag.RowsAffected()
			return nil
		},
		other: func(hdr *tar.Header, rd io.Reader) error {
			switch hdr.Name {
			case entryManifest:
				data, err := io.ReadAll(rd)
				if err != nil {
					return err
				}
				var m model.SnapshotMetadata
				if err := json.Unmarshal(data, &m); err != nil {
					return fmt.Errorf("the archive's manifest is unreadable: %w", err)
				}
				manifest = &m
			case entryRoles:
				data, err := io.ReadAll(rd)
				if err != nil {
					return err
				}
				return r.createRoles(ctx, conn, parseRolesSQL(data), super)
			case entryPreData, entrySchema, entryPostData, entrySequences:
				data, err := io.ReadAll(rd)
				if err != nil {
					return err
				}
				sqlText := stripPublicSchemaOwner(dropUnknownSettings(string(data), known))
				var ownership []string
				switch {
				case r.NoOwner:
					sqlText = stripOwnership(sqlText)
				case !super && hdr.Name != entrySequences:
					// A role that is not a superuser may own what it
					// creates and grant on what it owns, and no more. What
					// it cannot do is run afterwards, one statement at a
					// time, so one refusal does not end the restore.
					sqlText, ownership = splitOwnership(sqlText)
				}
				if filtered {
					if hdr.Name == entrySequences {
						sqlText = filterSequenceSQL(sqlText, wantSQL)
					} else {
						sqlText = filterSchemaSQL(sqlText, wantSQL)
					}
				}
				if err := exec("running "+hdr.Name, sqlText); err != nil {
					if filtered && hdr.Name != entrySequences {
						return fmt.Errorf("%w. The chosen schemas' objects have to be absent from the target: drop them first, or restore their rows only with --data-only-schema", err)
					}
					return err
				}
				for _, stmt := range ownership {
					if filtered && !ownershipStatementWanted(stmt, wantSQL) {
						continue
					}
					if err := exec("saving", "SAVEPOINT safegrd_ownership"); err != nil {
						return err
					}
					if _, err := pgConn.Exec(ctx, stmt).ReadAll(); err != nil {
						if err := exec("rolling back", "ROLLBACK TO SAVEPOINT safegrd_ownership"); err != nil {
							return err
						}
						r.SkippedOwnership = append(r.SkippedOwnership, strings.TrimSuffix(stmt, ";"))
						continue
					}
					if err := exec("releasing", "RELEASE SAVEPOINT safegrd_ownership"); err != nil {
						return err
					}
				}
				switch hdr.Name {
				case entrySchema:
					sawSchema, legacySchema = true, true
				case entryPreData:
					sawSchema = true
				case entrySequences:
					sawSequences = true
				}
			}
			return nil
		},
	}
	if err := streams.Run(tar.NewReader(src)); err != nil {
		return nil, err
	}
	if !sawSchema {
		return nil, fmt.Errorf("the archive holds no schema; it is not a Postgres snapshot")
	}
	if manifest == nil {
		return nil, fmt.Errorf("the archive holds no manifest.json")
	}
	// Current archives count exactly; before, a count at or above 10,000
	// rows was Postgres's estimate and cannot be held to.
	if manifest.SchemaSource != "" {
		for _, t := range manifest.TableStats {
			if !wantRows(t.Schema) {
				continue
			}
			if got := loaded[t.Schema+"."+t.TableName]; got != t.RowCount {
				return nil, fmt.Errorf("%s.%s loaded %d rows; the snapshot recorded %d", t.Schema, t.TableName, got, t.RowCount)
			}
		}
	}
	if r.BeforeCommit != nil {
		if err := r.BeforeCommit(); err != nil {
			return nil, fmt.Errorf("nothing was committed: %w", err)
		}
	}
	if err := exec("committing the restore", "COMMIT"); err != nil {
		return nil, err
	}
	committed = true

	switch {
	case legacySchema:
		r.Warn("This snapshot's schema was captured without pg_dump. The rows are restored in full, but foreign keys,\n" +
			"   views, triggers, functions and enum types are not, and a column type the old extractor did not know may differ.")
	}
	if n := len(r.SkippedOwnership); n > 0 {
		shown := r.SkippedOwnership
		if len(shown) > 5 {
			shown = shown[:5]
		}
		r.Warn(fmt.Sprintf("%d ownership or privilege statements were skipped: the restoring role is not a superuser and may not run them.\n"+
			"   Those objects belong to the restoring role. Restore as a superuser to keep every owner and grant.\n     %s", n, strings.Join(shown, "\n     ")))
	}
	if !sawSequences {
		r.Warn("This snapshot predates recorded sequence positions: every sequence starts over, so the next insert\n" +
			"   may reuse an existing id. Set each one past its column's maximum before the application writes.")
	}
	return manifest, nil
}

// createRoles creates, inside the restore's transaction, every role roles.sql
// carries that the target lacks, and records each. On a connection that is
// not a superuser the new role is granted to the restoring role, so the
// OWNER TO statements that follow, and the sandbox's cleanup, may act as it.
func (r *NativeRestorer) createRoles(ctx context.Context, conn *pgx.Conn, d *roleDump, super bool) error {
	have := map[string]bool{}
	rows, err := conn.Query(ctx, "SELECT rolname FROM pg_roles")
	if err != nil {
		return fmt.Errorf("could not list the target's roles: %w", err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		have[n] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	pgConn := conn.PgConn()
	created := map[string]bool{}
	for _, name := range d.names() {
		if have[name] {
			continue
		}
		for _, stmt := range d.createStatements(name, super) {
			if _, err := pgConn.Exec(ctx, stmt).ReadAll(); err != nil {
				return fmt.Errorf("creating role %s, which the snapshot's schema names and the target lacks: %w. "+
					"Restore as a superuser or a role with CREATEROLE, or create the role on the target first", name, err)
			}
		}
		if !super {
			if _, err := pgConn.Exec(ctx, "GRANT "+quoteRole(name)+" TO CURRENT_USER").ReadAll(); err != nil {
				return fmt.Errorf("granting the new role %s to the restoring role: %w", name, err)
			}
		}
		created[name] = true
		r.CreatedRoles = append(r.CreatedRoles, name)
	}
	// Memberships among the carried roles, for the roles created here. A
	// role the target already had keeps the memberships it has.
	for _, m := range d.members {
		if created[m[1]] && (have[m[0]] || created[m[0]]) {
			if _, err := pgConn.Exec(ctx, "GRANT "+quoteRole(m[0])+" TO "+quoteRole(m[1])).ReadAll(); err != nil {
				return fmt.Errorf("granting %s to %s as the snapshot had it: %w", m[0], m[1], err)
			}
		}
	}
	return nil
}

var sessionSetRe = regexp.MustCompile(`(?m)^SET ([a-z_]+) = [^;\n]*;\n`)

// tocHeaderRe matches the header pg_dump writes before each object in a
// plain-text dump:
//
//	--
//	-- Name: users; Type: TABLE; Schema: public; Owner: -
//	--
//
// Schema is "-" for an object outside any schema: a schema itself, an
// extension, an event trigger.
var tocHeaderRe = regexp.MustCompile(`(?m)^--\n-- Name: (.*?); Type: ([A-Z ]+); Schema: ([^;\n]*); Owner: [^\n]*\n--\n`)

// filterSchemaSQL keeps, of a pg_dump section, the preamble before the first
// object (session settings) and the objects of the schemas keep allows. Of
// the objects in no schema it keeps a schema's own CREATE when keep allows
// that schema, and extensions, which pg_dump writes as IF NOT EXISTS; it
// drops the rest, which belong to the whole database.
func filterSchemaSQL(sqlText string, keep func(schema string) bool) string {
	matches := tocHeaderRe.FindAllStringSubmatchIndex(sqlText, -1)
	if len(matches) == 0 {
		return sqlText
	}
	var b strings.Builder
	b.WriteString(sqlText[:matches[0][0]])
	for i, m := range matches {
		end := len(sqlText)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		name, typ, schema := sqlText[m[2]:m[3]], sqlText[m[4]:m[5]], sqlText[m[6]:m[7]]
		switch {
		case schema != "-":
			if !keep(schema) {
				continue
			}
		case typ == "SCHEMA":
			if !keep(name) {
				continue
			}
		case typ == "EXTENSION":
		default:
			continue
		}
		b.WriteString(sqlText[m[0]:end])
	}
	return b.String()
}

// setvalRe matches one line of sequences.sql and captures the sequence's
// schema, quoted or bare.
var setvalRe = regexp.MustCompile(`^SELECT pg_catalog\.setval\('(?:"((?:[^"]|"")+)"|([^".]+))\.`)

// filterSequenceSQL keeps the setval lines of the schemas keep allows.
func filterSequenceSQL(sqlText string, keep func(schema string) bool) string {
	var b strings.Builder
	for _, line := range strings.SplitAfter(sqlText, "\n") {
		m := setvalRe.FindStringSubmatch(line)
		if m == nil {
			b.WriteString(line)
			continue
		}
		schema := m[2]
		if m[1] != "" {
			schema = strings.ReplaceAll(m[1], `""`, `"`)
		}
		if keep(schema) {
			b.WriteString(line)
		}
	}
	return b.String()
}

// extensionCommentRe matches pg_dump's COMMENT ON EXTENSION lines. Only an
// extension's owner may comment on it, and on a managed database the provider
// installed the extension as its own superuser, so the line aborts the whole
// restore. The comment is the extension's stock description; nothing is lost.
var extensionCommentRe = regexp.MustCompile(`(?m)^COMMENT ON EXTENSION [^\n]*;\n`)

// dropUnknownSettings removes the session SETs pg_dump writes for a setting
// the target server does not have. pg_dump writes for its own version, not the
// server's: pg_dump 18 sets transaction_timeout, which a PostgreSQL 16 server
// rejects, and the whole restore is one transaction. psql shrugs such an
// error off; a restore that stops at the first error has to not send it.
func dropUnknownSettings(sqlText string, known map[string]bool) string {
	sqlText = extensionCommentRe.ReplaceAllString(sqlText, "")
	return sessionSetRe.ReplaceAllStringFunc(sqlText, func(line string) string {
		if known[sessionSetRe.FindStringSubmatch(line)[1]] {
			return line
		}
		return ""
	})
}

func serverSettings(ctx context.Context, conn *pgx.Conn) (map[string]bool, error) {
	rows, err := conn.Query(ctx, "SELECT name FROM pg_settings")
	if err != nil {
		return nil, fmt.Errorf("could not read the restore target's settings: %w", err)
	}
	defer rows.Close()
	known := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		known[n] = true
	}
	return known, rows.Err()
}

// checkTargetEmpty refuses a restore into a database that already holds
// tables. The archive's schema would collide with them part way through, and
// older restores appended the snapshot's rows to whatever was there.
func checkTargetEmpty(ctx context.Context, conn *pgx.Conn) error {
	var n int
	// Relations an extension owns do not count: a managed database arrives
	// with pg_stat_statements' view or PostGIS's spatial_ref_sys already in it.
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p', 'v', 'm') AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
		  AND NOT EXISTS (SELECT 1 FROM pg_depend d
		                  WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')`).Scan(&n); err != nil {
		return fmt.Errorf("could not inspect the restore target: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("the restore target already holds %d table(s) or view(s); restore into a new, empty database "+
			"(for example: createdb restored_copy) and point --target at it", n)
	}
	return nil
}

// defaultConnectTimeout bounds connecting to a database that does not answer.
// pgx waits for ever without one: a source that accepted the TCP connection
// and then said nothing held a backup open past five minutes, under the daemon
// with no failure reported and no alert. A connect_timeout in the URL wins.
const defaultConnectTimeout = 30 * time.Second

func connectPostgres(ctx context.Context, url string) (*pgx.Conn, error) {
	cfg, err := postgresConnConfig(url)
	if err != nil {
		return nil, err
	}
	return pgx.ConnectConfig(ctx, cfg)
}

func postgresConnConfig(url string) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = defaultConnectTimeout
	}
	return cfg, nil
}
