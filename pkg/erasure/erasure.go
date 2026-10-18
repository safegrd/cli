// Package erasure keeps a record of the rows deleted from the tables a
// surface names, so that a restore of a backup taken before a deletion
// deletes the row again before it commits.
//
// In the customer's database, installed only for the tables they name:
//
//	safegrd.erasures         one row per deleted row: the table, the row's
//	                         primary key as JSON, the deleting transaction's
//	                         id and the time. Never the row.
//	safegrd.record_erasure   the trigger function
//
// and on each named table a row-level AFTER DELETE trigger, safegrd_erasure,
// enabled ALWAYS so a session with session_replication_role = replica fires
// it too. DROP SCHEMA safegrd CASCADE removes it all.
//
// The rows do not stay there: a database that is lost takes them with it,
// and a backup carries only the deletions made before it, which are the ones
// that need no replaying. Ship moves them into sealed objects beside the
// backups, and Load reads them back for a restore.
package erasure

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/storage"
)

const (
	trigger = "safegrd_erasure"
	// marker is written once, when a surface's record starts: a restore
	// that finds the directory without it is reading the wrong storage, or
	// an export that does not carry the record, not a record with nothing
	// in it.
	marker = "record.json"
	// objectSuffix ends every object of the record.
	objectSuffix = ".json.age"
	// shipBatch is how many rows one object holds at most.
	shipBatch = 5000
	// skew is how far after a backup's start an erasure is replayed on its
	// time alone, for a record whose transaction ids cannot be compared with
	// the backup's (Window.Replays).
	skew = time.Hour
)

const setupSQL = `
CREATE SCHEMA IF NOT EXISTS safegrd;
CREATE TABLE IF NOT EXISTS safegrd.erasures (
  id bigserial PRIMARY KEY,
  rel text NOT NULL,
  key jsonb NOT NULL,
  xid bigint NOT NULL DEFAULT txid_current(),
  at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE OR REPLACE FUNCTION safegrd.record_erasure() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  INSERT INTO safegrd.erasures (rel, key)
  VALUES (quote_ident(TG_TABLE_SCHEMA) || '.' || quote_ident(TG_TABLE_NAME),
          (SELECT jsonb_object_agg(k, to_jsonb(OLD) -> k) FROM unnest(TG_ARGV) AS k));
  RETURN NULL;
END
$f$;`

// Record is one deleted row: its table, as schema.table quoted, and its
// primary key.
type Record struct {
	Rel string          `json:"rel"`
	Key json.RawMessage `json:"key"`
	XID int64           `json:"xid"`
	At  time.Time       `json:"at"`
}

// batch is one object of the record, before it is sealed.
type batch struct {
	Surface string   `json:"surface"`
	Records []Record `json:"records"`
}

// ParseTable splits schema.table, the form a surface names a table in.
func ParseTable(name string) (schema, table string, err error) {
	schema, table, ok := strings.Cut(strings.TrimSpace(name), ".")
	if !ok || schema == "" || table == "" || strings.Contains(table, ".") {
		return "", "", fmt.Errorf("erasures: %q is not schema.table (public.users)", name)
	}
	return schema, table, nil
}

// Install puts the record in place for tables, each schema.table with a
// primary key, and returns the tables whose trigger it created or replaced.
// A table already carrying the trigger this package installs, on its current
// primary key, is left alone: CREATE TRIGGER locks the table against writes.
func Install(ctx context.Context, databaseURL string, tables []string) ([]string, error) {
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("could not connect to put the erasure record in place: %w", err)
	}
	defer conn.Close(context.Background())
	type target struct {
		name  string // quoted, for SQL
		label string // as the surface names it
		oid   uint32
		key   []string
	}
	var need []target
	for _, name := range tables {
		schema, table, err := ParseTable(name)
		if err != nil {
			return nil, err
		}
		var oid uint32
		err = conn.QueryRow(ctx, `SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind IN ('r', 'p')`, schema, table).Scan(&oid)
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("erasures: the database has no table %s", name)
		} else if err != nil {
			return nil, err
		}
		var key []string
		rows, err := conn.Query(ctx, `SELECT a.attname FROM pg_index i
			JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
			WHERE i.indrelid = $1 AND i.indisprimary ORDER BY array_position(i.indkey, a.attnum)`, oid)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var col string
			if err := rows.Scan(&col); err != nil {
				rows.Close()
				return nil, err
			}
			key = append(key, col)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if len(key) == 0 {
			return nil, fmt.Errorf("erasures: %s has no primary key, so a deleted row cannot be named without copying it", name)
		}
		var args []byte
		for _, k := range key {
			args = append(append(args, k...), 0)
		}
		var current bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_trigger t
			JOIN pg_proc p ON p.oid = t.tgfoid JOIN pg_namespace pn ON pn.oid = p.pronamespace
			WHERE t.tgrelid = $1 AND t.tgname = $2 AND t.tgenabled = 'A' AND pn.nspname = 'safegrd'
			  AND p.proname = 'record_erasure' AND t.tgargs = $3)`, oid, trigger, args).Scan(&current); err != nil {
			return nil, err
		}
		if !current {
			need = append(need, target{pgx.Identifier{schema, table}.Sanitize(), schema + "." + table, oid, key})
		}
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, setupSQL); err != nil {
		return nil, fmt.Errorf("could not create the safegrd schema for the erasure record: %w", err)
	}
	var installed []string
	for _, t := range need {
		args := make([]string, len(t.key))
		for i, k := range t.key {
			args[i] = "'" + strings.ReplaceAll(k, "'", "''") + "'"
		}
		for _, q := range []string{
			"DROP TRIGGER IF EXISTS " + trigger + " ON " + t.name,
			"CREATE TRIGGER " + trigger + " AFTER DELETE ON " + t.name + " FOR EACH ROW EXECUTE FUNCTION safegrd.record_erasure(" + strings.Join(args, ", ") + ")",
			"ALTER TABLE " + t.name + " ENABLE ALWAYS TRIGGER " + trigger,
		} {
			if _, err := tx.Exec(ctx, q); err != nil {
				return nil, fmt.Errorf("could not put the erasure trigger on %s: %w", t.name, err)
			}
		}
		installed = append(installed, t.label)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return installed, nil
}

// Ship moves every row of safegrd.erasures into sealed objects under dir in
// objs, each locked until retainUntil, and returns how many it moved. A row
// is deleted only after the object holding it is written, and only the rows
// read: a deletion still in flight when the rows were read may hold a lower
// id than the highest read, and is moved next time.
func Ship(ctx context.Context, databaseURL string, objs storage.Objects, dir, surface, recipient string, retainUntil time.Time) (int, error) {
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return 0, fmt.Errorf("could not connect to read the erasure record: %w", err)
	}
	defer conn.Close(context.Background())
	var present bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('safegrd.erasures') IS NOT NULL").Scan(&present); err != nil || !present {
		return 0, err
	}
	moved := 0
	for {
		rows, err := conn.Query(ctx, "SELECT id, rel, key::text, xid, at FROM safegrd.erasures ORDER BY id LIMIT $1", shipBatch)
		if err != nil {
			return moved, fmt.Errorf("could not read safegrd.erasures: %w", err)
		}
		b := batch{Surface: surface}
		var ids []int64
		for rows.Next() {
			var id int64
			var r Record
			var key string
			if err := rows.Scan(&id, &r.Rel, &key, &r.XID, &r.At); err != nil {
				rows.Close()
				return moved, err
			}
			r.Key, r.At = json.RawMessage(key), r.At.UTC()
			ids = append(ids, id)
			b.Records = append(b.Records, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return moved, err
		}
		if len(ids) == 0 {
			return moved, nil
		}
		sealed, err := seal(b, recipient)
		if err != nil {
			return moved, err
		}
		if err := objs.PutObject(ctx, objectName(dir, b.Records), sealed, retainUntil); err != nil {
			return moved, err
		}
		if _, err := conn.Exec(ctx, "DELETE FROM safegrd.erasures WHERE id = ANY($1)", ids); err != nil {
			// The object is written; the rows are moved again next time,
			// and a key replayed twice deletes nothing the second time.
			return moved, fmt.Errorf("the erasures were written to storage, but could not be cleared from safegrd.erasures: %w", err)
		}
		moved += len(ids)
	}
}

// objectName is dir/<newest erasure's time>-<random>.json.age: the time
// first, so the names sort in time and prune can read an object's age from
// its name.
func objectName(dir string, recs []Record) string {
	var newest time.Time
	for _, r := range recs {
		if r.At.After(newest) {
			newest = r.At
		}
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s/%020d-%s%s", strings.TrimSuffix(dir, "/"), newest.UnixNano(), hex.EncodeToString(b[:]), objectSuffix)
}

// NewestIn is the time of the newest erasure an object of the record holds,
// read from its name.
func NewestIn(name string) (time.Time, bool) {
	base := name[strings.LastIndex(name, "/")+1:]
	stamp, _, ok := strings.Cut(base, "-")
	if !ok || !strings.HasSuffix(base, objectSuffix) {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, n).UTC(), true
}

func seal(b batch, recipient string) ([]byte, error) {
	plain, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if _, err := crypto.EncryptStream(bytes.NewReader(plain), &out, recipient); err != nil {
		return nil, fmt.Errorf("could not seal the erasure record: %w", err)
	}
	return out.Bytes(), nil
}

// Start writes the record's marker under dir, once.
func Start(ctx context.Context, objs storage.Objects, dir, surface string, retainUntil time.Time) error {
	name := strings.TrimSuffix(dir, "/") + "/" + marker
	if _, err := objs.GetObject(ctx, name); err == nil {
		return nil
	}
	data, err := json.Marshal(map[string]any{"surface": surface, "started": time.Now().UTC()})
	if err != nil {
		return err
	}
	return objs.PutObject(ctx, name, data, retainUntil)
}

// Load reads every object of the record under dir and returns the erasures
// in them, oldest object first. Any object it cannot read or open is an
// error: a restore that replayed part of the record would report success.
func Load(ctx context.Context, objs storage.Objects, dir, identity string) ([]Record, error) {
	names, err := objs.ListObjects(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("the erasure record at %s could not be listed: %w", dir, err)
	}
	started := false
	for _, name := range names {
		started = started || strings.HasSuffix(name, "/"+marker)
	}
	if !started {
		return nil, fmt.Errorf("no erasure record at %s in this storage (no %s)", dir, marker)
	}
	var out []Record
	for _, name := range names {
		if !strings.HasSuffix(name, objectSuffix) {
			continue
		}
		data, err := objs.GetObject(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("the erasure record's %s could not be read: %w", name, err)
		}
		var plain bytes.Buffer
		if _, err := crypto.DecryptStream(bytes.NewReader(data), &plain, identity); err != nil {
			return nil, fmt.Errorf("the erasure record's %s could not be opened with this key: %w", name, err)
		}
		var b batch
		if err := json.Unmarshal(plain.Bytes(), &b); err != nil {
			return nil, fmt.Errorf("the erasure record's %s is not readable: %w", name, err)
		}
		out = append(out, b.Records...)
	}
	return out, nil
}
