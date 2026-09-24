package dump

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// The schema of a Postgres snapshot comes from pg_dump. The native
// extractor it replaces re-derived DDL from
// information_schema and lost arrays, enums, foreign keys, views, triggers and
// numeric precision; a database with one array column could not be restored
// at all, while its in-memory drill passed. pg_dump is the one program that
// knows every object Postgres has, so the schema is taken from it, under the
// same exported snapshot the rows are copied in.

// PgDump is a located pg_dump binary.
type PgDump struct {
	Path    string
	Version string // "18.6"
	Major   int
}

var pgDumpVersionRe = regexp.MustCompile(`\(PostgreSQL\)\s+(\d+)(?:\.(\d+))?`)

// pgDumpCandidates lists where a pg_dump may live, the override first. Debian
// and Ubuntu keep every installed major under /usr/lib/postgresql, and
// Homebrew's libpq is keg-only, so neither is necessarily on PATH.
func pgDumpCandidates() []string {
	if p := os.Getenv("SAFEGRD_PG_DUMP"); p != "" {
		return []string{p}
	}
	var out []string
	if p, err := exec.LookPath("pg_dump"); err == nil {
		out = append(out, p)
	}
	globs := []string{"/usr/lib/postgresql/*/bin/pg_dump", "/usr/pgsql-*/bin/pg_dump"}
	if runtime.GOOS == "darwin" {
		globs = append(globs,
			"/opt/homebrew/opt/libpq/bin/pg_dump", "/opt/homebrew/opt/postgresql@*/bin/pg_dump",
			"/usr/local/opt/libpq/bin/pg_dump", "/usr/local/opt/postgresql@*/bin/pg_dump",
			"/Applications/Postgres.app/Contents/Versions/*/bin/pg_dump")
	}
	for _, g := range globs {
		m, _ := filepath.Glob(g)
		out = append(out, m...)
	}
	return out
}

// FindPgDump returns the newest pg_dump on this host that can dump a server of
// serverMajor, or an error that says what was found and what is needed. A
// pg_dump older than the server refuses to run against it, and a newer one
// dumps older servers correctly, so the newest wins.
func FindPgDump(ctx context.Context, serverMajor int) (*PgDump, error) {
	var found []*PgDump
	seen := map[string]bool{}
	for _, p := range pgDumpCandidates() {
		if seen[p] {
			continue
		}
		seen[p] = true
		out, err := exec.CommandContext(ctx, p, "--version").Output()
		if err != nil {
			continue
		}
		m := pgDumpVersionRe.FindStringSubmatch(string(out))
		if m == nil {
			continue
		}
		major, _ := strconv.Atoi(m[1])
		v := m[1]
		if m[2] != "" {
			v += "." + m[2]
		}
		found = append(found, &PgDump{Path: p, Version: v, Major: major})
	}
	if len(found) == 0 {
		if p := os.Getenv("SAFEGRD_PG_DUMP"); p != "" {
			return nil, fmt.Errorf("SAFEGRD_PG_DUMP=%s is not a working pg_dump", p)
		}
		return nil, fmt.Errorf("no pg_dump found: install the PostgreSQL %d client (or newer), or set SAFEGRD_PG_DUMP", serverMajor)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Major > found[j].Major })
	best := found[0]
	if serverMajor > 0 && best.Major < serverMajor {
		return nil, fmt.Errorf("the newest pg_dump here is %s (%s), older than the PostgreSQL %d server; "+
			"install the PostgreSQL %d client (or newer), or set SAFEGRD_PG_DUMP", best.Version, best.Path, serverMajor, serverMajor)
	}
	return best, nil
}

// Section runs pg_dump for one section of the schema under an exported
// snapshot, as plain SQL a single Exec can run.
func (p *PgDump) Section(ctx context.Context, databaseURL, snapshot, section string) ([]byte, error) {
	dsn, password := splitPassword(databaseURL)
	args := []string{"--dbname=" + dsn, "--section=" + section, "--no-owner", "--no-acl"}
	if snapshot != "" {
		args = append(args, "--snapshot="+snapshot)
	}
	cmd := exec.CommandContext(ctx, p.Path, args...)
	// The password travels in the environment, never in argv, where every
	// user on the host can read it from the process table.
	cmd.Env = os.Environ()
	if password != "" {
		cmd.Env = append(cmd.Env, "PGPASSWORD="+password)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		return nil, fmt.Errorf("pg_dump %s (--section=%s) failed: %v: %s", p.Version, section, err, msg)
	}
	return stripPsqlMetaCommands(stdout.Bytes()), nil
}

// stripPsqlMetaCommands removes the backslash commands pg_dump writes for
// psql (\restrict and \unrestrict since the August 2025 minor releases). They
// are not SQL, and the restore runs the file over the wire, not through psql.
func stripPsqlMetaCommands(sql []byte) []byte {
	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(sql))
	sc.Buffer(make([]byte, 0, 64<<10), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) > 0 && line[0] == '\\' {
			continue
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

var dsnPasswordRe = regexp.MustCompile(`(?:^|\s)password\s*=\s*('(?:[^'\\]|\\.)*'|\S+)`)

// splitPassword returns the connection string without its password, and the
// password, for either a URL or a keyword/value string.
func splitPassword(dsn string) (string, string) {
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return dsn, ""
		}
		password := ""
		if u.User != nil {
			if p, ok := u.User.Password(); ok {
				password = p
				u.User = url.User(u.User.Username())
			}
		}
		q := u.Query()
		if p := q.Get("password"); p != "" {
			password = p
			q.Del("password")
			u.RawQuery = q.Encode()
		}
		return u.String(), password
	}
	m := dsnPasswordRe.FindStringSubmatchIndex(dsn)
	if m == nil {
		return dsn, ""
	}
	val := dsn[m[2]:m[3]]
	if strings.HasPrefix(val, "'") {
		val = strings.NewReplacer(`\'`, `'`, `\\`, `\`).Replace(val[1 : len(val)-1])
	}
	return strings.TrimSpace(dsn[:m[0]] + " " + dsn[m[1]:]), val
}

// RedactURL hides the password in a connection string for printing.
func RedactURL(dsn string) string {
	rest, password := splitPassword(dsn)
	if password == "" {
		return dsn
	}
	if strings.Contains(rest, "://") {
		if u, err := url.Parse(rest); err == nil && u.User != nil {
			u.User = url.UserPassword(u.User.Username(), "xxxxx")
			return u.String()
		}
	}
	return rest + " password=xxxxx"
}
