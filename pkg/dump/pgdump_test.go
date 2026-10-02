package dump

import (
	"bytes"
	"strings"
	"testing"
)

// A line longer than any scanner buffer used to end the output there, and the
// backup still reported success with every later statement gone.
func TestStripPsqlMetaCommandsKeepsEverythingAfterALongLine(t *testing.T) {
	long := "CREATE FUNCTION f() RETURNS text LANGUAGE sql AS $$ SELECT '" + strings.Repeat("x", 70<<20) + "' $$;\n"
	in := []byte("\\restrict abc123\nCREATE TABLE a (id int);\n" + long + "CREATE TABLE z (id int);\n\\unrestrict abc123\n")
	out := stripPsqlMetaCommands(in)
	if !bytes.HasSuffix(out, []byte("CREATE TABLE z (id int);\n")) {
		t.Fatalf("statements after a %d-byte line were dropped: output is %d bytes", len(long), len(out))
	}
	if bytes.Contains(out, []byte("restrict abc123")) {
		t.Fatal("\\restrict / \\unrestrict survived")
	}
	if want := len(in) - len("\\restrict abc123\n") - len("\\unrestrict abc123\n"); len(out) != want {
		t.Fatalf("output is %d bytes, want %d", len(out), want)
	}
}

// pg_dump copies a function body verbatim inside dollar quotes, and a body
// line may start with a backslash. Only the two psql commands go.
func TestStripPsqlMetaCommandsKeepsBackslashLinesInsideFunctionBodies(t *testing.T) {
	in := "CREATE FUNCTION m(t text) RETURNS bool LANGUAGE plpgsql AS $$\nBEGIN\n\\d+match\nEND;\n$$;\n\\restricted_not_a_command\n"
	if out := string(stripPsqlMetaCommands([]byte(in))); out != in {
		t.Fatalf("a body line was removed:\n%q\nwant\n%q", out, in)
	}
}

func TestSplitPasswordKeepsThePasswordOutOfTheDSN(t *testing.T) {
	cases := []struct{ dsn, password string }{
		{"host=db user=alice password=s3cret", "s3cret"},
		{"HOST=db USER=alice PASSWORD=s3cret", "s3cret"},
		{"host=db Password = 's3 cret' user=alice", "s3 cret"},
		{"postgres://alice:s3cret@db:5432/app", "s3cret"},
		{"postgres://alice@db/app?password=s3cret", "s3cret"},
		// url.Parse refuses a bad percent-escape; the password still comes out.
		{"postgres://alice:s3cret%zz@db:5432/app", "s3cret%zz"},
	}
	for _, c := range cases {
		rest, pw := splitPassword(c.dsn)
		if pw != c.password {
			t.Errorf("splitPassword(%q) password = %q, want %q", c.dsn, pw, c.password)
		}
		if strings.Contains(rest, "s3") {
			t.Errorf("splitPassword(%q) left the password in %q", c.dsn, rest)
		}
		if got := RedactURL(c.dsn); strings.Contains(got, "s3") {
			t.Errorf("RedactURL(%q) = %q", c.dsn, got)
		}
	}
	if got := RedactURL("postgres://alice@db/app?sslmode=require"); got != "postgres://alice@db/app?sslmode=require" {
		t.Errorf("RedactURL changed a URL with no password: %q", got)
	}
}
