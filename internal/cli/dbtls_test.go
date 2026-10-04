package cli

import (
	"strings"
	"testing"
)

func TestDatabaseTLSWarningNamesTheModeToSet(t *testing.T) {
	cases := []struct {
		url  string
		want string // "" for no warning, else a fragment of it
	}{
		{"postgres://u:p@localhost:5432/db", ""},
		{"postgres://u:p@127.0.0.1/db?sslmode=disable", ""},
		{"postgres://u:p@[::1]:5432/db", ""},
		{"postgres:///db?host=/var/run/postgresql", ""},
		{"postgres://u:p@db.internal:5432/db?sslmode=verify-full", ""},
		{"postgres://u:p@db.internal:5432/db?sslmode=require", ""},
		{"postgres://u:p@db.internal:5432/db", "sslmode=verify-full"},
		{"postgres://u:p@db.internal:5432/db?sslmode=prefer", "sslmode=prefer"},
		{"postgres://u:p@db.internal:5432/db?sslmode=disable", "in the clear"},
		{"postgres://u:p@localhost,db.internal/db", "sslmode=verify-full"},
		{"postgres://u:p@localhost/db?host=db.internal", "sslmode=verify-full"},
		{"mysql://u:p@localhost:3306/db", ""},
		{"mysql://u:p@db.internal:3306/db?tls=true", ""},
		{"mysql://u:p@db.internal:3306/db?ssl-ca=/etc/ca.pem", ""},
		{"mysql://u:p@db.internal:3306/db", "tls=true"},
		{"mariadb://u:p@db.internal:3306/db?tls=skip-verify", "tls=skip-verify"},
		{"mysql://u:p@db.internal:3306/db?tls=preferred", "tls=preferred"},
		{"mongodb://u:p@db.internal/db", ""},
		{"sqlite:///tmp/x.db", ""},
	}
	for _, c := range cases {
		got := databaseTLSWarning(c.url)
		switch {
		case c.want == "" && got != "":
			t.Errorf("%s: unexpected warning %q", c.url, got)
		case c.want != "" && !strings.Contains(got, c.want):
			t.Errorf("%s: warning %q does not mention %q", c.url, got, c.want)
		}
		if strings.Contains(got, ":p@") {
			t.Errorf("%s: the warning printed the URL", c.url)
		}
	}
}
