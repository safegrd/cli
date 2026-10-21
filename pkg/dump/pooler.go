package dump

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ErrTransactionPooler is a connection through a pooler in transaction mode
// (PgBouncer pool_mode = transaction, Supavisor's transaction port). Such a
// pooler hands each statement whatever server connection is free, so a role
// taken with SET ROLE, and the snapshot the backup shares with pg_dump, do
// not hold from one statement to the next: the backup would leave tables out
// or read none.
var ErrTransactionPooler = errors.New("this database URL goes through a transaction pooler, which runs each statement on whichever server connection is free, " +
	"so the backup's role and snapshot do not hold between statements. Connect through the session pooler instead " +
	"(on Supabase, the pooler's port 5432; in PgBouncer, pool_mode = session) or to the database directly")

// probeQueries is how many statements the probe runs on each connection.
const probeQueries = 8

// refuseTransactionPooler tells a transaction pooler by what it does, not by
// its port: a session setting made on conn is seen by a second client
// connection, or conn's next statements run in another server process or
// without the setting. On a direct connection or a session pooler each
// client keeps one server process, and neither happens. A probe that cannot
// run decides nothing, and the backup goes on.
func refuseTransactionPooler(ctx context.Context, conn *pgx.Conn, url string) error {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil
	}
	mark := "probe-" + hex.EncodeToString(b)
	simple := pgx.QueryExecModeSimpleProtocol
	if _, err := conn.Exec(ctx, "SELECT set_config('safegrd.session_probe', '"+mark+"', false)", simple); err != nil {
		return nil
	}
	var pid int
	if err := conn.QueryRow(ctx, "SELECT pg_backend_pid()", simple).Scan(&pid); err != nil {
		return nil
	}
	if other, err := connectPostgres(ctx, url); err == nil {
		defer other.Close(context.Background())
		for i := 0; i < probeQueries; i++ {
			var seen string
			if err := other.QueryRow(ctx, "SELECT coalesce(current_setting('safegrd.session_probe', true), '')", simple).Scan(&seen); err != nil {
				break
			}
			if seen == mark {
				return ErrTransactionPooler
			}
		}
	}
	for i := 0; i < probeQueries; i++ {
		var seen string
		var now int
		if err := conn.QueryRow(ctx, "SELECT coalesce(current_setting('safegrd.session_probe', true), ''), pg_backend_pid()", simple).Scan(&seen, &now); err != nil {
			return nil
		}
		if seen != mark || now != pid {
			return ErrTransactionPooler
		}
	}
	// The setting stays on the session; a later reset is not needed, since
	// the name is SafeGrd's own and nothing reads it.
	return nil
}
