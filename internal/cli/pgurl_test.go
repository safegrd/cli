package cli

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// An app's connection string copied as it is must not fail every backup: a
// Prisma URL's ?schema=public was sent to the server as a setting and refused.
// PostgreSQL's own parameters stay, and a URL that is not a PostgreSQL one is
// not touched.
func TestAConnectionURLKeepsOnlyWhatPostgreSQLTakes(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		dropped  []string
	}{
		{"postgresql://rick:@localhost:5432/money?schema=public", "postgresql://rick:@localhost:5432/money", []string{"schema"}},
		{"postgres://u:p@db/app?sslmode=require&schema=public&connection_limit=5", "postgres://u:p@db/app?sslmode=require", []string{"connection_limit", "schema"}},
		{"postgres://u:p@db/app?sslmode=verify-full&application_name=x", "postgres://u:p@db/app?sslmode=verify-full&application_name=x", nil},
		{"postgres://u:p@db/app", "postgres://u:p@db/app", nil},
		{"mysql://u:p@db/app?schema=x", "mysql://u:p@db/app?schema=x", nil},
	} {
		got, dropped := cleanPostgresURL(tc.in)
		// Compared parsed: the query's order is not part of the answer.
		g, _ := url.Parse(got)
		w, _ := url.Parse(tc.want)
		if g.Scheme != w.Scheme || g.User.String() != w.User.String() || g.Host != w.Host || g.Path != w.Path ||
			!reflect.DeepEqual(g.Query(), w.Query()) {
			t.Errorf("cleanPostgresURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if !reflect.DeepEqual(dropped, tc.dropped) {
			t.Errorf("cleanPostgresURL(%q) dropped %v, want %v", tc.in, dropped, tc.dropped)
		}
	}
	out := captureStderr(t, func() { sayDroppedURLParams("Surface moneydb", []string{"schema"}) })
	if !strings.Contains(out, "Surface moneydb: its connection URL has parameters PostgreSQL does not take, so they are left out: schema (Prisma's; a backup takes every schema)") {
		t.Errorf("the note does not say what was left out and why:\n%s", out)
	}
	if strings.Contains(out, "localhost") {
		t.Errorf("the note prints the URL: %s", out)
	}
}
