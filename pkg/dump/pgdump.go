package dump

import (
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
	// The same bound as the connection above (connectPostgres); a
	// connect_timeout in the URL still wins over the environment.
	if os.Getenv("PGCONNECT_TIMEOUT") == "" {
		cmd.Env = append(cmd.Env, "PGCONNECT_TIMEOUT=30")
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
//
// Only those two, by name: a function body is copied verbatim inside dollar
// quotes and may have a line that starts with a backslash. And no line-length
// limit: a bufio.Scanner stops at its cap, and a long function body then
// dropped every statement after it from a backup that reported success.
func stripPsqlMetaCommands(sql []byte) []byte {
	out := make([]byte, 0, len(sql))
	for len(sql) > 0 {
		line := sql
		if i := bytes.IndexByte(sql, '\n'); i >= 0 {
			line, sql = sql[:i+1], sql[i+1:]
		} else {
			sql = nil
		}
		if isPsqlMetaCommand(line) {
			continue
		}
		out = append(out, line...)
	}
	return out
}

func isPsqlMetaCommand(line []byte) bool {
	line = bytes.TrimRight(line, "\r\n")
	for _, cmd := range []string{`\restrict`, `\unrestrict`} {
		if rest, ok := bytes.CutPrefix(line, []byte(cmd)); ok && (len(rest) == 0 || rest[0] == ' ' || rest[0] == '\t') {
			return true
		}
	}
	return false
}

// libpq reads keywords case-insensitively, so PASSWORD= is a password too.
var dsnPasswordRe = regexp.MustCompile(`(?i)(?:^|\s)password\s*=\s*('(?:[^'\\]|\\.)*'|\S+)`)

// splitPassword returns the connection string without its password, and the
// password, for either a URL or a keyword/value string.
func splitPassword(dsn string) (string, string) {
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			// Still take the password out of the userinfo, so it reaches
			// neither argv nor a printed message.
			return splitURLPasswordRaw(dsn)
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

// splitURLPasswordRaw cuts the password out of a URL's userinfo by position,
// for a URL that url.Parse refuses (a bad percent-escape, say).
func splitURLPasswordRaw(dsn string) (string, string) {
	scheme := strings.Index(dsn, "://") + len("://")
	authority := dsn[scheme:]
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return dsn, ""
	}
	colon := strings.Index(authority[:at], ":")
	if colon < 0 {
		return dsn, ""
	}
	return dsn[:scheme+colon] + dsn[scheme+at:], authority[colon+1 : at]
}

var urlQueryPasswordRe = regexp.MustCompile(`(?i)([?&]password=)[^&#]*`)

// RedactURL hides the password in a connection string for printing. It fails
// closed: a URL it cannot parse is printed with the password cut out by
// position, never as given.
func RedactURL(dsn string) string {
	rest, password := splitPassword(dsn)
	if strings.Contains(rest, "://") {
		u, err := url.Parse(rest)
		if err != nil {
			return urlQueryPasswordRe.ReplaceAllString(rest, "${1}xxxxx")
		}
		if password == "" {
			return dsn
		}
		if u.User != nil {
			u.User = url.UserPassword(u.User.Username(), "xxxxx")
		}
		return u.String()
	}
	if password == "" {
		return dsn
	}
	return rest + " password=xxxxx"
}
