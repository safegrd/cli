package dump

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The schema of a Postgres snapshot names roles: a table's owner, the
// grantees of its privileges, the roles a policy applies to. A fresh cluster
// has none of them, so a restore there failed at the first policy with
// "role does not exist" and left the database empty, while the in-memory
// drill passed. roles.sql carries those roles, as pg_dumpall --roles-only
// writes them, so a restore can create the ones its target lacks before the
// schema runs, and the in-memory drill can refuse a snapshot that names a
// role it does not carry.
//
// Only the roles the schema names are carried, never the whole cluster: a
// cluster's role list is the provider's business and most of it has nothing
// to do with this database. Role passwords (the hashes pg_authid holds) ride
// along unless the surface opts out, so a restored role can log in as it did.

// entryRoles is the archive entry, written before the schema sections so a
// streaming restore meets it first.
const entryRoles = "roles.sql"

// Roles runs pg_dumpall --roles-only from the directory this pg_dump was
// found in and returns its output, whether passwords are in it, and
// pg_dumpall's version string. Reading passwords needs pg_authid, which only
// a superuser may read; a role that may not (an RDS master user, Supabase's
// postgres) gets the roles without them, and the caller says so.
func (p *PgDump) Roles(ctx context.Context, databaseURL string, withPasswords bool) (sql []byte, passwords bool, err error) {
	bin := filepath.Join(filepath.Dir(p.Path), "pg_dumpall")
	if _, err := exec.LookPath(bin); err != nil {
		return nil, false, fmt.Errorf("no pg_dumpall beside %s: install the PostgreSQL client package, which carries both", p.Path)
	}
	args := []string{"--roles-only"}
	if !withPasswords {
		args = append(args, "--no-role-passwords")
	}
	out, stderr, err := p.run(ctx, bin, databaseURL, args)
	if err != nil && withPasswords && strings.Contains(stderr, "pg_authid") {
		out, stderr, err = p.run(ctx, bin, databaseURL, append(args, "--no-role-passwords"))
		withPasswords = false
	}
	if err != nil {
		return nil, false, fmt.Errorf("pg_dumpall --roles-only failed: %v: %s", err, stderr)
	}
	return stripPsqlMetaCommands(out), withPasswords, nil
}

// roleIdent matches one role name as pg_dump writes it: bare, or quoted with
// doubled inner quotes.
const roleIdent = `(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)`

var (
	roleList   = roleIdent + `(?:, ` + roleIdent + `)*`
	ownerToRe  = regexp.MustCompile(`(?m) OWNER TO (` + roleIdent + `);$`)
	granteesRe = regexp.MustCompile(`(?m)^(?:GRANT|REVOKE|ALTER DEFAULT PRIVILEGES) .*? (?:TO|FROM) (` + roleList + `)(?: WITH GRANT OPTION)?;$`)
	forRoleRe  = regexp.MustCompile(`(?m)^ALTER DEFAULT PRIVILEGES FOR ROLE (` + roleList + `) `)
	policyToRe = regexp.MustCompile(`(?m)^CREATE POLICY .*? TO (` + roleList + `)(?: USING | WITH CHECK |;)`)

	createRoleRe  = regexp.MustCompile(`^CREATE ROLE (` + roleIdent + `);$`)
	alterRoleRe   = regexp.MustCompile(`^ALTER ROLE (` + roleIdent + `) (WITH|SET|RESET|IN DATABASE) `)
	commentRoleRe = regexp.MustCompile(`^COMMENT ON ROLE (` + roleIdent + `) IS `)
	membershipRe  = regexp.MustCompile(`^GRANT (` + roleIdent + `) TO (` + roleIdent + `)(?: |;)`)
	superuserRe   = regexp.MustCompile(` (SUPERUSER|REPLICATION)\b`)
	// privilegedAttrRe matches the attributes a role may mention in ALTER
	// ROLE only when it holds them itself, even to turn them off (PostgreSQL
	// 16: "Only roles with the CREATEDB attribute may change the CREATEDB
	// attribute"). A restorer that is not a superuser leaves them all out.
	privilegedAttrRe = regexp.MustCompile(` (?:NO)?(?:SUPERUSER|REPLICATION|BYPASSRLS|CREATEDB|CREATEROLE)\b`)
)

// unquoteRole is the role's name as pg_roles has it.
func unquoteRole(ident string) string {
	if strings.HasPrefix(ident, `"`) && strings.HasSuffix(ident, `"`) && len(ident) >= 2 {
		return strings.ReplaceAll(ident[1:len(ident)-1], `""`, `"`)
	}
	return ident
}

// quoteRole is the name as SQL needs it.
func quoteRole(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// builtinRole reports a role every cluster has, which no dump carries: the
// pseudo-roles and PostgreSQL's own pg_ roles.
func builtinRole(name string) bool {
	switch strings.ToUpper(name) {
	case "PUBLIC", "CURRENT_USER", "CURRENT_ROLE", "SESSION_USER", "NONE":
		return true
	}
	return strings.HasPrefix(name, "pg_")
}

// namedRoles lists, sorted, the roles the schema sections name: owners,
// grantees, the roles default privileges are set for and the roles policies
// apply to. Built-in roles are left out.
func namedRoles(sections ...[]byte) []string {
	seen := map[string]bool{}
	add := func(list string) {
		for _, ident := range strings.Split(list, ", ") {
			if name := unquoteRole(strings.TrimSpace(ident)); name != "" && !builtinRole(name) {
				seen[name] = true
			}
		}
	}
	for _, s := range sections {
		text := string(s)
		for _, m := range ownerToRe.FindAllStringSubmatch(text, -1) {
			add(m[1])
		}
		for _, re := range []*regexp.Regexp{granteesRe, forRoleRe, policyToRe} {
			for _, m := range re.FindAllStringSubmatch(text, -1) {
				add(m[1])
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// roleDump is pg_dumpall --roles-only, parsed: each role's own statements
// in dump order, and the memberships between roles.
type roleDump struct {
	order []string
	stmts map[string][]string
	// members are GRANT role TO member pairs, by unquoted name.
	members [][2]string
}

// parseRolesSQL reads pg_dumpall's statements, one per line. A role's
// per-database settings (ALTER ROLE ... IN DATABASE ...) are dropped: the
// source database's name means nothing on the target.
func parseRolesSQL(sql []byte) *roleDump {
	d := &roleDump{stmts: map[string][]string{}}
	for _, line := range strings.Split(string(sql), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "--") || strings.HasPrefix(line, "SET "):
		case createRoleRe.MatchString(line):
			name := unquoteRole(createRoleRe.FindStringSubmatch(line)[1])
			if _, ok := d.stmts[name]; !ok {
				d.order = append(d.order, name)
			}
			d.stmts[name] = append(d.stmts[name], line)
		case alterRoleRe.MatchString(line):
			m := alterRoleRe.FindStringSubmatch(line)
			if m[2] == "IN DATABASE" {
				continue
			}
			name := unquoteRole(m[1])
			d.stmts[name] = append(d.stmts[name], line)
		case commentRoleRe.MatchString(line):
			name := unquoteRole(commentRoleRe.FindStringSubmatch(line)[1])
			d.stmts[name] = append(d.stmts[name], line)
		case membershipRe.MatchString(line):
			m := membershipRe.FindStringSubmatch(line)
			d.members = append(d.members, [2]string{unquoteRole(m[1]), unquoteRole(m[2])})
		}
	}
	return d
}

// only keeps the roles in names, and the memberships between them, and
// writes them back as SQL. Roles named by the schema that the dump does not
// have (a role dropped between the two reads, say) are returned.
func (d *roleDump) only(names []string) (sql []byte, missing []string) {
	keep := map[string]bool{}
	for _, n := range names {
		keep[n] = true
	}
	var b strings.Builder
	b.WriteString("-- Roles the schema names, as pg_dumpall --roles-only wrote them.\n")
	b.WriteString("-- A restore creates the ones its target lacks before the schema runs.\n")
	for _, n := range d.order {
		if !keep[n] {
			continue
		}
		for _, s := range d.stmts[n] {
			b.WriteString(s)
			b.WriteString("\n")
		}
	}
	for _, m := range d.members {
		if keep[m[0]] && keep[m[1]] {
			fmt.Fprintf(&b, "GRANT %s TO %s;\n", quoteRole(m[0]), quoteRole(m[1]))
		}
	}
	for _, n := range names {
		if _, ok := d.stmts[n]; !ok {
			missing = append(missing, n)
		}
	}
	return []byte(b.String()), missing
}

// names lists the roles the dump creates, in dump order.
func (d *roleDump) names() []string { return append([]string(nil), d.order...) }

// createStatements are the statements that create one role on a target that
// lacks it. SUPERUSER and REPLICATION are turned off: neither helps the
// schema load, and a restore should not mint a superuser from a hash in a
// backup. A restorer that is not a superuser may mention SUPERUSER,
// REPLICATION, BYPASSRLS, CREATEDB and CREATEROLE only if it holds them, not
// even to turn them off, so for it those words are left out and the
// target's defaults (all off) apply. Everything else, LOGIN and PASSWORD
// included, is as dumped.
func (d *roleDump) createStatements(name string, super bool) []string {
	var out []string
	for _, s := range d.stmts[name] {
		if strings.HasPrefix(s, "ALTER ROLE ") && strings.Contains(s, " WITH ") {
			if super {
				s = superuserRe.ReplaceAllString(s, " NO$1")
			} else {
				s = privilegedAttrRe.ReplaceAllString(s, "")
			}
		}
		out = append(out, s)
	}
	return out
}

// ownershipLineRe matches the statements --no-owner leaves out of a restore:
// ownership, privileges and default privileges. Each is one line in a
// pg_dump section.
var ownershipLineRe = regexp.MustCompile(`(?m)^(?:ALTER [A-Z ]+ .* OWNER TO [^\n]*|GRANT [^\n]*|REVOKE [^\n]*|ALTER DEFAULT PRIVILEGES [^\n]*);\n`)

// publicSchemaOwnerRe matches the ownership pg_dump writes for the public
// schema on PostgreSQL 15 and later. The target made its public schema
// itself, and only its database owner may change who owns it.
var publicSchemaOwnerRe = regexp.MustCompile(`(?m)^ALTER SCHEMA public OWNER TO [^\n]*;\n`)

// stripOwnership removes ownership and privilege statements from a section.
func stripOwnership(sql string) string {
	return ownershipLineRe.ReplaceAllString(sql, "")
}

// splitOwnership takes the ownership and privilege statements out of a
// section and returns them, in order, so they can run one at a time after
// the objects exist.
func splitOwnership(sql string) (rest string, statements []string) {
	for _, m := range ownershipLineRe.FindAllString(sql, -1) {
		statements = append(statements, strings.TrimSuffix(m, "\n"))
	}
	return ownershipLineRe.ReplaceAllString(sql, ""), statements
}

// ownershipStatementWanted says whether an ownership or privilege statement
// belongs to a schema keep allows. A statement on no schema (a database, a
// default privilege for every schema) is not wanted in a filtered restore.
func ownershipStatementWanted(stmt string, keep func(string) bool) bool {
	if strings.HasPrefix(stmt, "ALTER DEFAULT PRIVILEGES") {
		m := regexp.MustCompile(`IN SCHEMA (` + roleIdent + `) `).FindStringSubmatch(stmt)
		return m != nil && keep(unquoteRole(m[1]))
	}
	if m := regexp.MustCompile(`(?:ON (?:[A-Z ]+ )?|ALTER [A-Z ]+ (?:ONLY )?)(` + roleIdent + `)\.`).FindStringSubmatch(stmt); m != nil {
		return keep(unquoteRole(m[1]))
	}
	if m := regexp.MustCompile(`^(?:GRANT|REVOKE) .* ON SCHEMA (` + roleIdent + `) `).FindStringSubmatch(stmt); m != nil {
		return keep(unquoteRole(m[1]))
	}
	return false
}

func stripPublicSchemaOwner(sql string) string {
	return publicSchemaOwnerRe.ReplaceAllString(sql, "")
}

// run executes bin against databaseURL with the password in a 0600 PGPASSFILE,
// the way Section does, and returns stdout and trimmed stderr.
func (p *PgDump) run(ctx context.Context, bin, databaseURL string, args []string) ([]byte, string, error) {
	dsn, password := splitPassword(databaseURL)
	cmd := exec.CommandContext(ctx, bin, append([]string{"--dbname=" + dsn}, args...)...)
	env, cleanup, err := pgEnv(password)
	if err != nil {
		return nil, "", err
	}
	defer cleanup()
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	msg := toolMessage(stderr.String())
	if len(msg) > 500 {
		msg = msg[:500] + "..."
	}
	return stdout.Bytes(), msg, err
}
