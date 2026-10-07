package dump

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/safegrd/cli/pkg/model"
)

// The change log lets a backup of a repository database skip reading tables
// that were not written since the previous run. It is installed in the
// customer's database only when they ask for it:
//
//	safegrd.changes    one row per transaction and table written: the
//	                   table's oid and the transaction's id
//	safegrd.consumers  one row per backup that reads the log: the snapshot
//	                   its last finished run read under
//	safegrd.log_change the trigger function
//
// and on every table a statement-level AFTER INSERT OR UPDATE OR DELETE OR
// TRUNCATE trigger, safegrd_change_log, enabled ALWAYS so a session with
// session_replication_role = replica fires it too.
//
// A run carries a table forward from the previous run, without reading it,
// only when every one of these holds, read inside the run's own snapshot:
// the log holds no row for it (or a table it inherits from) that the
// previous run's snapshot could not see; its trigger was in place and
// enabled at both runs, and is the same trigger; its definition, oid and
// the database's are unchanged; row-level security does not filter it and
// logical replication does not write it; the previous run read it within the
// last week; and the database did not go back in time (a WAL position behind
// the previous run's, another timeline, another system). Any doubt reads the
// table. Statistics counters are never consulted: they are approximate, lag,
// and reset on failover, and a table skipped on a wrong signal restores
// missing rows with every check green.
//
// Each consumer compares the log with its own last snapshot instead of
// deleting what it read, because two surfaces may back up one database: a
// run that deleted the rows it had seen would hide them from the other.
// Rows are deleted once every consumer that ran in the last week has seen
// them; a consumer idle longer reads every table on its next run.

const (
	changeLogSchema  = "safegrd"
	changeLogTrigger = "safegrd_change_log"
	// changeLogFullRead is how long a table may be carried forward before a
	// run reads it again whatever the log says.
	changeLogFullRead = 7 * 24 * time.Hour
	// changeLogConsumerLife is how long a consumer that has not run keeps
	// the log's rows; changeLogConsumerFresh is how fresh its record must be
	// for it to carry anything, a day inside that.
	changeLogConsumerLife  = 7 * 24 * time.Hour
	changeLogConsumerFresh = 6 * 24 * time.Hour
)

const changeLogTables = `
CREATE TABLE IF NOT EXISTS safegrd.changes (relid oid NOT NULL, xid xid8 NOT NULL);
CREATE TABLE IF NOT EXISTS safegrd.consumers (id text PRIMARY KEY, snapshot pg_snapshot NOT NULL, at timestamptz NOT NULL DEFAULT now());`

// changeLogFunction logs a table once per transaction: the transaction-local
// setting remembers it was logged, and a rolled-back savepoint forgets it
// along with the row.
const changeLogFunction = `
CREATE OR REPLACE FUNCTION safegrd.log_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE
  x text := pg_current_xact_id()::text;
BEGIN
  IF current_setting('safegrd.logged_' || TG_RELID, true) IS DISTINCT FROM x THEN
    INSERT INTO safegrd.changes (relid, xid) VALUES (TG_RELID, x::xid8);
    PERFORM set_config('safegrd.logged_' || TG_RELID, x, true);
  END IF;
  RETURN NULL;
END
$f$`

// changeLogTriggersQuery is every table a backup may copy, with its change
// log trigger's oid and whether that trigger is the one this file installs,
// enabled ALWAYS: statement level, AFTER, on all four events, calling
// safegrd.log_change.
const changeLogTriggersQuery = `
SELECT n.nspname, c.relname, c.oid::bigint, coalesce(t.oid, 0)::bigint,
  coalesce(t.tgenabled = 'A' AND pn.nspname = 'safegrd' AND p.proname = 'log_change'
    AND (t.tgtype & 1) = 0 AND (t.tgtype & 66) = 0 AND (t.tgtype & 60) = 60, false)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_trigger t ON t.tgrelid = c.oid AND t.tgname = 'safegrd_change_log'
LEFT JOIN pg_proc p ON p.oid = t.tgfoid
LEFT JOIN pg_namespace pn ON pn.oid = p.pronamespace
WHERE c.relkind IN ('r', 'p') AND c.relpersistence <> 't'
  AND n.nspname NOT LIKE 'pg\_%' AND n.nspname NOT IN ('information_schema', 'safegrd')
  AND NOT EXISTS (SELECT 1 FROM pg_depend d
                  WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')`

// changeLogFingerprintQuery is what changes every table's rows without a
// statement on any of them: the server's version, enum labels, composite
// types' attributes and extension versions.
const changeLogFingerprintQuery = `
SELECT md5(concat_ws('|', current_setting('server_version_num'),
  (SELECT string_agg(e.enumtypid || ':' || e.enumsortorder || ':' || e.enumlabel, ',' ORDER BY e.enumtypid, e.enumsortorder) FROM pg_enum e),
  (SELECT string_agg(a.attrelid || ':' || a.attnum || ':' || a.attname || ':' || format_type(a.atttypid, a.atttypmod), ',' ORDER BY a.attrelid, a.attnum)
     FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid WHERE c.relkind = 'c' AND a.attnum > 0 AND NOT a.attisdropped),
  (SELECT string_agg(extname || ':' || extversion, ',' ORDER BY extname) FROM pg_extension)))`

// ChangeLogState is what one run of a database surface leaves for the next:
// the consumer it reads the log as, the snapshot it read under, the
// database it read, and each table as it found it.
type ChangeLogState struct {
	Consumer    string                    `json:"consumer"`
	Snapshot    string                    `json:"snapshot"`
	DatabaseOID uint32                    `json:"database_oid"`
	SystemID    string                    `json:"system_id,omitempty"`
	Timeline    string                    `json:"timeline,omitempty"`
	LSN         string                    `json:"lsn"`
	Fingerprint string                    `json:"fingerprint"`
	Tables      map[string]ChangeLogTable `json:"tables"`
}

// ChangeLogTable is one table as a run found it. Tracked is set when its
// trigger was in place and enabled ALWAYS inside the run's snapshot.
type ChangeLogTable struct {
	OID        uint32    `json:"oid"`
	TriggerOID uint32    `json:"trigger_oid"`
	Tracked    bool      `json:"tracked"`
	SchemaHash string    `json:"schema_hash"`
	RowCount   int64     `json:"row_count"`
	ReadAt     time.Time `json:"read_at"`
}

// NewChangeLogConsumer names a new reader of the log.
func NewChangeLogConsumer() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("dump: the system random source failed: " + err.Error())
	}
	return "c" + hex.EncodeToString(b[:])
}

// ChangeLogSetup is what SetupChangeLog did.
type ChangeLogSetup struct {
	// Installed are the tables whose trigger was put in place or enabled
	// ALWAYS again by this run, each logged as written so this run reads it.
	Installed []string
	// Untracked are the tables without a working trigger, and why. Each is
	// read in full every run.
	Untracked map[string]string
}

// SetupChangeLog puts the change log in place where it is missing and
// registers consumer, in its own transactions, before the run's snapshot is
// taken. A table whose trigger cannot be installed (another role owns it, a
// lock is held) is left untracked. An error means no table can be carried
// this run.
func SetupChangeLog(ctx context.Context, databaseURL, consumer string) (*ChangeLogSetup, error) {
	conn, err := connectPostgres(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the database: %w", err)
	}
	defer conn.Close(context.Background())
	var version int
	if err := conn.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&version); err != nil {
		return nil, err
	}
	if version < 130000 {
		return nil, fmt.Errorf("the change log needs PostgreSQL 13 or newer (pg_current_xact_id); this server is %d.%d", version/10000, version%10000/100)
	}
	var schemaExists bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'safegrd')").Scan(&schemaExists); err != nil {
		return nil, err
	}
	if !schemaExists {
		if _, err := conn.Exec(ctx, "CREATE SCHEMA safegrd"); err != nil {
			return nil, fmt.Errorf("creating schema safegrd: %w", err)
		}
	}
	if _, err := conn.Exec(ctx, changeLogTables); err != nil {
		return nil, fmt.Errorf("creating the change log's tables: %w", err)
	}
	if _, err := conn.Exec(ctx, changeLogFunction); err != nil {
		return nil, fmt.Errorf("creating safegrd.log_change: %w", err)
	}

	type table struct {
		schema, name string
		oid, tgoid   int64
		ok           bool
	}
	rows, err := conn.Query(ctx, changeLogTriggersQuery)
	if err != nil {
		return nil, fmt.Errorf("listing the tables: %w", err)
	}
	var tables []table
	for rows.Next() {
		var t table
		if err := rows.Scan(&t.schema, &t.name, &t.oid, &t.tgoid, &t.ok); err != nil {
			rows.Close()
			return nil, err
		}
		tables = append(tables, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := &ChangeLogSetup{Untracked: map[string]string{}}
	for _, t := range tables {
		if t.ok {
			continue
		}
		name := t.schema + "." + t.name
		ident := pgx.Identifier{t.schema, t.name}.Sanitize()
		// The table is logged as written in the same transaction, so this
		// run reads it whatever happened while it had no trigger.
		stmts := []string{"SET LOCAL lock_timeout = '2s'"}
		if t.tgoid != 0 {
			stmts = append(stmts, "DROP TRIGGER "+changeLogTrigger+" ON "+ident)
		}
		stmts = append(stmts,
			"CREATE TRIGGER "+changeLogTrigger+" AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON "+ident+
				" FOR EACH STATEMENT EXECUTE FUNCTION safegrd.log_change()",
			"ALTER TABLE "+ident+" ENABLE ALWAYS TRIGGER "+changeLogTrigger,
			"INSERT INTO safegrd.changes (relid, xid) VALUES ("+strconv.FormatInt(t.oid, 10)+", pg_current_xact_id())")
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			for _, s := range stmts {
				if _, err := tx.Exec(ctx, s); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			out.Untracked[name] = changeLogRefusal(err)
			continue
		}
		out.Installed = append(out.Installed, name)
	}
	// Registered before the run's snapshot is taken, at a snapshot no later
	// than it, so no other consumer deletes a row this one has not seen.
	if _, err := conn.Exec(ctx, `INSERT INTO safegrd.consumers (id, snapshot, at) VALUES ($1, pg_current_snapshot(), now())
		ON CONFLICT (id) DO UPDATE SET at = now()`, consumer); err != nil {
		return nil, fmt.Errorf("registering this backup with the change log: %w", err)
	}
	return out, nil
}

func changeLogRefusal(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "42501":
			return "this role does not own the table"
		case "55P03":
			return "the table was locked; tried again next run"
		}
		return pe.Message
	}
	return err.Error()
}

// ChangeLogPlan is what a run decided inside its snapshot.
type ChangeLogPlan struct {
	// Carry are the tables carried forward unread, with the row count the
	// previous run recorded, keyed schema.table.
	Carry map[string]int64
	// NoCarry says why nothing could be carried, when that was decided for
	// the whole run rather than table by table.
	NoCarry string
	next    *ChangeLogState
}

// PlanChangeLogInput is what PlanChangeLog decides from.
type PlanChangeLogInput struct {
	Meta *model.SnapshotMetadata
	// Filtered are the tables row-level security filters for this role.
	Filtered map[string]int64
	Prior    *ChangeLogState
	Consumer string
	// CanCarry reports whether the repository can carry a table's file
	// forward: it holds every chunk of the file as last written.
	CanCarry         func(path string) bool
	ServerVersionNum int
}

// PlanChangeLog decides, inside the run's snapshot, which tables to carry
// forward from the previous run. It reads; it writes nothing.
func PlanChangeLog(ctx context.Context, tx pgx.Tx, in PlanChangeLogInput) (*ChangeLogPlan, error) {
	plan := &ChangeLogPlan{Carry: map[string]int64{}}
	next := &ChangeLogState{Consumer: in.Consumer, Snapshot: in.Meta.SourceSnapshot, LSN: in.Meta.SourceLSN, Tables: map[string]ChangeLogTable{}}
	plan.next = next
	if in.ServerVersionNum < 130000 {
		plan.NoCarry = "the change log needs PostgreSQL 13 or newer"
		return plan, nil
	}
	if err := tx.QueryRow(ctx, "SELECT oid FROM pg_database WHERE datname = current_database()").Scan(&next.DatabaseOID); err != nil {
		return nil, err
	}
	if err := tx.QueryRow(ctx, changeLogFingerprintQuery).Scan(&next.Fingerprint); err != nil {
		return nil, err
	}
	optional := func(q string) string {
		if _, err := tx.Exec(ctx, "SAVEPOINT safegrd_changelog"); err != nil {
			return ""
		}
		var v string
		if err := tx.QueryRow(ctx, q).Scan(&v); err != nil {
			rollbackSavepoint(ctx, tx, "safegrd_changelog")
			return ""
		}
		_, _ = tx.Exec(ctx, "RELEASE SAVEPOINT safegrd_changelog")
		return v
	}
	next.SystemID = optional("SELECT system_identifier::text FROM pg_control_system()")
	next.Timeline = optional("SELECT substr(pg_walfile_name(pg_current_wal_lsn()), 1, 8)")

	rows, err := tx.Query(ctx, changeLogTriggersQuery)
	if err != nil {
		return nil, fmt.Errorf("reading the change log's triggers: %w", err)
	}
	type found struct {
		oid, tgoid uint32
		tracked    bool
	}
	byName := map[string]found{}
	for rows.Next() {
		var schema, name string
		var oid, tgoid int64
		var ok bool
		if err := rows.Scan(&schema, &name, &oid, &tgoid, &ok); err != nil {
			rows.Close()
			return nil, err
		}
		byName[schema+"."+name] = found{uint32(oid), uint32(tgoid), ok}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, t := range in.Meta.TableStats {
		key := t.Schema + "." + t.TableName
		f := byName[key]
		next.Tables[key] = ChangeLogTable{OID: f.oid, TriggerOID: f.tgoid, Tracked: f.tracked, SchemaHash: t.SchemaHash}
	}

	p := in.Prior
	switch {
	case p == nil || len(p.Tables) == 0:
		plan.NoCarry = "no earlier run of this surface read the change log"
	case p.Consumer != in.Consumer || p.Snapshot == "" || next.Snapshot == "":
		plan.NoCarry = "the earlier run recorded no snapshot to compare with"
	case p.DatabaseOID != next.DatabaseOID:
		plan.NoCarry = "the database is not the one the earlier run read"
	case p.SystemID != "" && next.SystemID != "" && p.SystemID != next.SystemID,
		p.Timeline != "" && next.Timeline != "" && p.Timeline != next.Timeline:
		plan.NoCarry = "the server is another system or timeline than at the earlier run (a restore or a failover)"
	case !lsnAtOrAfter(next.LSN, p.LSN):
		plan.NoCarry = "the server's WAL position is behind the earlier run's (a restore to an earlier point)"
	case p.Fingerprint != next.Fingerprint:
		plan.NoCarry = "the server's version, an enum, a composite type or an extension changed"
	}
	if plan.NoCarry != "" {
		return plan, nil
	}

	var snap string
	var fresh bool
	err = tx.QueryRow(ctx, "SELECT snapshot::text, at > now() - make_interval(secs => $2) FROM safegrd.consumers WHERE id = $1",
		in.Consumer, changeLogConsumerFresh.Seconds()).Scan(&snap, &fresh)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		plan.NoCarry = "this backup is not registered with the change log"
		return plan, nil
	case err != nil:
		return nil, err
	case snap != p.Snapshot:
		plan.NoCarry = "the change log's record of this backup is not the earlier run's"
		return plan, nil
	case !fresh:
		plan.NoCarry = "this backup has not read the change log for six days"
		return plan, nil
	}

	// Written since the earlier run: a row its snapshot could not see, on
	// the table or on a table it inherits from.
	changed := map[uint32]bool{}
	rows, err = tx.Query(ctx, `
		WITH RECURSIVE written AS (
		  SELECT DISTINCT relid FROM safegrd.changes WHERE NOT pg_visible_in_snapshot(xid, $1::pg_snapshot)
		  UNION
		  SELECT i.inhrelid FROM pg_inherits i JOIN written w ON i.inhparent = w.relid)
		SELECT relid::bigint FROM written`, p.Snapshot)
	if err != nil {
		return nil, fmt.Errorf("reading the change log: %w", err)
	}
	for rows.Next() {
		var oid int64
		if err := rows.Scan(&oid); err != nil {
			rows.Close()
			return nil, err
		}
		changed[uint32(oid)] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Logical replication's apply worker fires row triggers only.
	subscribed := map[uint32]bool{}
	v, ok := strings.CutPrefix(optional("SELECT 'ok:' || coalesce(string_agg(srrelid::text, ','), '') FROM pg_subscription_rel"), "ok:")
	if !ok {
		plan.NoCarry = "this role cannot read pg_subscription_rel, so it cannot tell which tables logical replication writes"
		return plan, nil
	}
	for _, s := range strings.Split(v, ",") {
		if n, err := strconv.ParseUint(s, 10, 32); err == nil {
			subscribed[uint32(n)] = true
		}
	}

	now := time.Now()
	for _, t := range in.Meta.TableStats {
		key := t.Schema + "." + t.TableName
		cur, prev := next.Tables[key], p.Tables[key]
		_, rls := in.Filtered[key]
		if !prev.Tracked || !cur.Tracked || prev.OID != cur.OID || prev.TriggerOID != cur.TriggerOID ||
			cur.SchemaHash == "" || prev.SchemaHash != cur.SchemaHash || changed[cur.OID] || subscribed[cur.OID] || rls ||
			prev.ReadAt.IsZero() || now.Sub(prev.ReadAt) >= changeLogFullRead ||
			in.CanCarry == nil || !in.CanCarry(copyEntryName(t.Schema, t.TableName, 0)) {
			continue
		}
		plan.Carry[key] = prev.RowCount
	}
	return plan, nil
}

// State is what this run leaves for the next, once its rows are counted.
func (p *ChangeLogPlan) State(meta *model.SnapshotMetadata, prior *ChangeLogState, now time.Time) *ChangeLogState {
	if p == nil || p.next == nil {
		return nil
	}
	s := *p.next
	s.Tables = map[string]ChangeLogTable{}
	for _, t := range meta.TableStats {
		key := t.Schema + "." + t.TableName
		ct := p.next.Tables[key]
		ct.RowCount, ct.ReadAt = t.RowCount, now.UTC()
		if t.Carried && prior != nil {
			ct.ReadAt = prior.Tables[key].ReadAt
		}
		s.Tables[key] = ct
	}
	return &s
}

// lsnAtOrAfter reports whether WAL position a is at or after b. Either empty
// is not.
func lsnAtOrAfter(a, b string) bool {
	pa, ok1 := parseLSN(a)
	pb, ok2 := parseLSN(b)
	return ok1 && ok2 && pa >= pb
}

func parseLSN(s string) (uint64, bool) {
	hi, lo, ok := strings.Cut(s, "/")
	if !ok {
		return 0, false
	}
	h, err1 := strconv.ParseUint(hi, 16, 32)
	l, err2 := strconv.ParseUint(lo, 16, 32)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return h<<32 | l, true
}

// AdvanceChangeLog records that consumer's run under snapshot finished and is
// kept, forgets consumers idle for a week, and deletes the rows every
// remaining consumer has seen. It runs after the run is committed and its
// state saved: before that, the rows it deletes may still be needed.
func AdvanceChangeLog(ctx context.Context, databaseURL, consumer, snapshot string) (deleted int64, err error) {
	conn, err := connectPostgres(ctx, databaseURL)
	if err != nil {
		return 0, fmt.Errorf("could not connect to the database: %w", err)
	}
	defer conn.Close(context.Background())
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE safegrd.consumers SET snapshot = $2::pg_snapshot, at = now() WHERE id = $1", consumer, snapshot)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("this backup is not registered with the change log")
		}
		if _, err := tx.Exec(ctx, "DELETE FROM safegrd.consumers WHERE at < now() - make_interval(secs => $1)", changeLogConsumerLife.Seconds()); err != nil {
			return err
		}
		tag, err = tx.Exec(ctx, `DELETE FROM safegrd.changes ch WHERE NOT EXISTS (
			SELECT 1 FROM safegrd.consumers c WHERE NOT pg_visible_in_snapshot(ch.xid, c.snapshot))`)
		if err != nil {
			return err
		}
		deleted = tag.RowsAffected()
		return nil
	})
	return deleted, err
}
