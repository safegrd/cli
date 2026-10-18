package erasure

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Window is what a backup read: the snapshot its transaction read under
// (xmin:xmax:xip,..., as pg_current_snapshot prints it) and when it started.
type Window struct {
	Snapshot string
	Started  time.Time
}

// Replays reports whether an erasure has to be replayed on a restore of the
// backup: its row is in the backup. That holds when the deleting transaction
// is one the backup's snapshot could not see. Transaction ids compare only
// within one server, so an erasure more than an hour after the backup
// started is replayed on its time alone, which covers a record kept on after
// a failover or a move to a new server. An erasure the backup saw is never
// replayed: its row is not in the backup, and a row with the same key
// inserted since is someone's new row.
func (w Window) Replays(r Record) bool {
	if r.At.After(w.Started.Add(skew)) {
		return true
	}
	xmin, xmax, xip, ok := parseSnapshot(w.Snapshot)
	if !ok {
		// No snapshot recorded: the time is all there is, with the same
		// hour of doubt on the other side.
		return !r.At.Before(w.Started.Add(-skew))
	}
	if r.XID < xmin {
		return false
	}
	if r.XID >= xmax {
		return true
	}
	return xip[r.XID]
}

func parseSnapshot(s string) (xmin, xmax int64, xip map[int64]bool, ok bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return 0, 0, nil, false
	}
	var err error
	if xmin, err = strconv.ParseInt(parts[0], 10, 64); err != nil {
		return 0, 0, nil, false
	}
	if xmax, err = strconv.ParseInt(parts[1], 10, 64); err != nil {
		return 0, 0, nil, false
	}
	xip = map[int64]bool{}
	if parts[2] != "" {
		for _, x := range strings.Split(parts[2], ",") {
			n, err := strconv.ParseInt(x, 10, 64)
			if err != nil {
				return 0, 0, nil, false
			}
			xip[n] = true
		}
	}
	return xmin, xmax, xip, true
}

// Result is what a replay did: how many erasures applied to the backup, the
// rows each table lost to them (ON DELETE CASCADE not counted), and the
// erasures of tables the target does not have.
type Result struct {
	Applied int
	Deleted map[string]int64
	Missing map[string]int
}

// Rows is every row the replay deleted.
func (r Result) Rows() int64 {
	var n int64
	for _, d := range r.Deleted {
		n += d
	}
	return n
}

// Replay deletes, on conn and inside whatever transaction it is in, the row
// of every erasure in recs that w replays. A table the target lacks is
// counted in Missing, not an error: a --schema restore leaves tables out.
func Replay(ctx context.Context, conn *pgx.Conn, recs []Record, w Window) (Result, error) {
	res := Result{Deleted: map[string]int64{}, Missing: map[string]int{}}
	// Grouped by table and by the key's columns, which change only when the
	// table's primary key did.
	type group struct {
		rel  string
		cols []string
		keys []json.RawMessage
	}
	groups := map[string]*group{}
	var order []string
	for _, r := range recs {
		if !w.Replays(r) {
			continue
		}
		var key map[string]json.RawMessage
		if err := json.Unmarshal(r.Key, &key); err != nil || len(key) == 0 {
			return res, fmt.Errorf("an erasure of %s has no key the restore can read", r.Rel)
		}
		cols := make([]string, 0, len(key))
		for c := range key {
			cols = append(cols, c)
		}
		sort.Strings(cols)
		id := r.Rel + "\x00" + strings.Join(cols, "\x00")
		g, ok := groups[id]
		if !ok {
			g = &group{rel: r.Rel, cols: cols}
			groups[id] = g
			order = append(order, id)
		}
		g.keys = append(g.keys, r.Key)
		res.Applied++
	}
	for _, id := range order {
		g := groups[id]
		// The table's name as the target quotes it, never the record's
		// text: the record names it, the catalogue spells it.
		var rel *string
		if err := conn.QueryRow(ctx, "SELECT to_regclass($1)::text", g.rel).Scan(&rel); err != nil {
			return res, fmt.Errorf("looking up %s for its erasures: %w", g.rel, err)
		}
		if rel == nil {
			res.Missing[g.rel] += len(g.keys)
			continue
		}
		// Results are keyed by the record's name, schema.table, which the
		// catalogue's text drops the schema from on the search path.
		conds := make([]string, len(g.cols))
		for i, c := range g.cols {
			q := pgx.Identifier{c}.Sanitize()
			conds[i] = "t." + q + " = k." + q
		}
		keys, err := json.Marshal(g.keys)
		if err != nil {
			return res, err
		}
		tag, err := conn.Exec(ctx, "DELETE FROM "+*rel+" t USING jsonb_populate_recordset(NULL::"+*rel+", $1::jsonb) k WHERE "+
			strings.Join(conds, " AND "), string(keys))
		if err != nil {
			return res, fmt.Errorf("replaying %d %s on %s: %w", len(g.keys), plural(len(g.keys), "erasure", "erasures"), *rel, err)
		}
		res.Deleted[g.rel] += tag.RowsAffected()
	}
	return res, nil
}

// ClearQueue empties a restored database's safegrd.erasures: the rows the
// backup caught there were waiting to be moved out, so their rows are
// already gone from it, and the live database moves them out itself. The
// replay's own deletions, which the trigger recorded, go with them.
func ClearQueue(ctx context.Context, conn *pgx.Conn) error {
	var present bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('safegrd.erasures') IS NOT NULL").Scan(&present); err != nil || !present {
		return err
	}
	_, err := conn.Exec(ctx, "DELETE FROM safegrd.erasures")
	return err
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
