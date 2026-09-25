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
//	pre-data.sql      pg_dump --section=pre-data: types, tables, functions, views
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
}

// NewNativeDumper creates a dumper for databaseURL.
func NewNativeDumper(databaseURL string) *NativeDumper {
	return &NativeDumper{databaseURL: databaseURL, Warn: func(msg string) {
		fmt.Fprintf(os.Stderr, "⚠️  %s\n", msg)
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

	conn, err := pgx.Connect(ctx, d.databaseURL)
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

// NativeRestorer loads a snapshot archive into an empty database.
type NativeRestorer struct {
	targetURL string
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
		fmt.Fprintf(os.Stderr, "⚠️  %s\n", msg)
	}}
}

// Restore loads the archive in one transaction: a restore that fails part
// way leaves the target as empty as it found it, never half a database that
// looks like the real one. It refuses a target that already holds tables, and
// holds every table's loaded row count to the manifest.
func (r *NativeRestorer) Restore(ctx context.Context, src io.Reader) (*model.SnapshotMetadata, error) {
	conn, err := pgx.Connect(ctx, r.targetURL)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the restore target: %w", err)
	}
	defer conn.Close(context.Background())
	if err := checkTargetEmpty(ctx, conn); err != nil {
		return nil, err
	}

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

	streams := &tableStreams{
		consume: func(schema, table string, rd io.Reader) error {
			tag, err := pgConn.CopyFrom(ctx, rd, "COPY "+pgx.Identifier{schema, table}.Sanitize()+" FROM STDIN (FORMAT binary)")
			if err != nil {
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
			case entryPreData, entrySchema, entryPostData, entrySequences:
				data, err := io.ReadAll(rd)
				if err != nil {
					return err
				}
				if err := exec("running "+hdr.Name, dropUnknownSettings(string(data), known)); err != nil {
					return err
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
	if !sawSequences {
		r.Warn("This snapshot predates recorded sequence positions: every sequence starts over, so the next insert\n" +
			"   may reuse an existing id. Set each one past its column's maximum before the application writes.")
	}
	return manifest, nil
}

var sessionSetRe = regexp.MustCompile(`(?m)^SET ([a-z_]+) = [^;\n]*;\n`)

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
