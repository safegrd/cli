package cli

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// libpqURLParams are the query parameters a PostgreSQL connection URL may
// carry: the ones libpq accepts, and so pg_dump. Anything else is refused by
// pg_dump as an invalid URI parameter, and pgx sends it to the server as a
// setting, which the server refuses in turn.
var libpqURLParams = map[string]bool{
	"host": true, "hostaddr": true, "port": true, "dbname": true, "user": true, "password": true,
	"passfile": true, "require_auth": true, "channel_binding": true, "connect_timeout": true,
	"client_encoding": true, "options": true, "application_name": true, "fallback_application_name": true,
	"keepalives": true, "keepalives_idle": true, "keepalives_interval": true, "keepalives_count": true,
	"tcp_user_timeout": true, "replication": true, "gssencmode": true, "sslmode": true, "requiressl": true,
	"sslnegotiation": true, "sslcompression": true, "sslcert": true, "sslkey": true, "sslpassword": true,
	"sslcertmode": true, "sslrootcert": true, "sslcrl": true, "sslcrldir": true, "sslsni": true,
	"requirepeer": true, "ssl_min_protocol_version": true, "ssl_max_protocol_version": true,
	"krbsrvname": true, "gsslib": true, "gssdelegation": true, "service": true,
	"target_session_attrs": true, "load_balance_hosts": true,
}

// ormURLParams are parameters an application's ORM puts in the same URL,
// named so the note says where they came from.
var ormURLParams = map[string]string{
	"schema":               "Prisma's; a backup takes every schema",
	"connection_limit":     "Prisma's",
	"pool_timeout":         "Prisma's",
	"pgbouncer":            "Prisma's",
	"socket_timeout":       "Prisma's",
	"statement_cache_size": "Prisma's",
}

// cleanPostgresURL leaves out of a PostgreSQL connection URL the query
// parameters PostgreSQL does not take, and names them. An app's connection
// string is often copied as it is, and one with ?schema=public failed every
// backup with "unrecognized configuration parameter". A URL that is not a
// postgres:// one, or does not parse, is returned as it is.
func cleanPostgresURL(raw string) (string, []string) {
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "postgres://") && !strings.HasPrefix(lower, "postgresql://") {
		return raw, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return raw, nil
	}
	q := u.Query()
	var dropped []string
	for k := range q {
		if !libpqURLParams[strings.ToLower(k)] {
			dropped = append(dropped, k)
			q.Del(k)
		}
	}
	if len(dropped) == 0 {
		return raw, nil
	}
	sort.Strings(dropped)
	u.RawQuery = q.Encode()
	return u.String(), dropped
}

// sayDroppedURLParams tells the operator which parameters were left out of
// a connection URL, and why, without printing the URL.
func sayDroppedURLParams(who string, dropped []string) {
	if len(dropped) == 0 {
		return
	}
	named := make([]string, 0, len(dropped))
	for _, k := range dropped {
		if why, ok := ormURLParams[strings.ToLower(k)]; ok {
			named = append(named, k+" ("+why+")")
		} else {
			named = append(named, k)
		}
	}
	fmt.Fprintf(os.Stderr, "⚠️  %s: its connection URL has parameters PostgreSQL does not take, so they are left out: %s.\n",
		who, strings.Join(named, ", "))
}
