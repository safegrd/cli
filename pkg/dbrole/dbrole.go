// Package dbrole says what the PostgreSQL role a backup connects as may do
// beyond reading. A backup only reads, so a credential that can write is one
// that, leaked, can change or delete the data it backs up.
package dbrole

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ReadOnlyRole is the read-only role to use instead, as one line.
const ReadOnlyRole = "CREATE ROLE safegrd_backup LOGIN PASSWORD '<password>'; GRANT pg_read_all_data TO safegrd_backup;"

// Facts is what the connecting role may do.
type Facts struct {
	Name                                   string
	Super, CreateRole, CreateDB, BypassRLS bool
	// Writable is every table the role may INSERT, UPDATE, DELETE or
	// TRUNCATE; RowSecurity every table whose rows row-level security
	// filters for it.
	Writable, RowSecurity []string
}

const userTables = `FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
	WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
	AND n.nspname NOT LIKE 'pg_toast%'`

// loginRoleRe is the login a managed database's sign-in hands out: on
// Supabase, cli_login_<role>, a member of <role> that does not inherit its
// privileges.
var loginRoleRe = regexp.MustCompile(`^cli_login_([a-z_][a-z0-9_]*)$`)

// TakeLoginRole switches conn to the role a cli_login_<role> login stands
// for, as Supabase's own CLI does with pg_dump --role. It returns the role
// taken, or "" when the session user is not such a login or the switch is
// refused. A backup reads as this role, so anything that judges what the
// backup can read has to take it first: judged as the login, every table
// behind row-level security looked hidden, while the role it switches to
// (supabase_read_only_user, BYPASSRLS) reads them all.
func TakeLoginRole(ctx context.Context, conn *pgx.Conn) string {
	var sessionUser string
	if err := conn.QueryRow(ctx, "SELECT session_user").Scan(&sessionUser); err != nil {
		return ""
	}
	m := loginRoleRe.FindStringSubmatch(sessionUser)
	if m == nil {
		return ""
	}
	if _, err := conn.Exec(ctx, "SET ROLE "+pgx.Identifier{m[1]}.Sanitize()); err != nil {
		return ""
	}
	return m[1]
}

// Inspect reads the facts from the catalogue over conn. It writes nothing.
func Inspect(ctx context.Context, conn *pgx.Conn) (Facts, error) {
	var f Facts
	if err := conn.QueryRow(ctx, `SELECT current_user, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls
		FROM pg_roles WHERE rolname = current_user`).Scan(&f.Name, &f.Super, &f.CreateRole, &f.CreateDB, &f.BypassRLS); err != nil {
		return f, err
	}
	var err error
	if f.Writable, err = names(ctx, conn, `SELECT n.nspname || '.' || c.relname `+userTables+`
		AND has_table_privilege(current_user, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE') ORDER BY 1`); err != nil {
		return f, err
	}
	// Row-level security applies to everyone but a superuser, a BYPASSRLS
	// role and the table's owner (unless the table forces it on the owner).
	if !f.Super && !f.BypassRLS {
		if f.RowSecurity, err = names(ctx, conn, `SELECT n.nspname || '.' || c.relname `+userTables+`
			AND c.relrowsecurity AND (c.relforcerowsecurity OR NOT pg_has_role(current_user, c.relowner, 'USAGE'))
			ORDER BY 1`); err != nil {
			return f, err
		}
	}
	return f, nil
}

func names(ctx context.Context, conn *pgx.Conn, query string) ([]string, error) {
	rows, err := conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// Finding is one thing worth saying about a role, with its fix.
type Finding struct {
	// Kind is "role" (it can do more than read) or "row_security" (rows
	// are hidden from it).
	Kind    string `json:"kind"`
	Message string `json:"message"`
	Fix     string `json:"fix"`
}

// Findings words the facts. None means the role reads and writes nothing,
// and sees every row.
func (f Facts) Findings() []Finding {
	var extra []string
	if f.CreateRole {
		extra = append(extra, "create roles")
	}
	if f.CreateDB {
		extra = append(extra, "create databases")
	}
	var out []Finding
	switch {
	case f.Super:
		out = append(out, Finding{Kind: "role", Message: fmt.Sprintf("connects as %s, a superuser; a read-only role is enough", f.Name), Fix: ReadOnlyRole})
	case len(f.Writable) > 0:
		msg := fmt.Sprintf("%s can write to %d table(s) (%s)", f.Name, len(f.Writable), Some(f.Writable))
		if len(extra) > 0 {
			msg += " and " + strings.Join(extra, " and ")
		}
		out = append(out, Finding{Kind: "role", Message: msg + "; a read-only role is enough", Fix: ReadOnlyRole})
	case len(extra) > 0:
		out = append(out, Finding{Kind: "role", Message: fmt.Sprintf("%s writes to no table but can %s; a read-only role is enough", f.Name, strings.Join(extra, " and ")), Fix: ReadOnlyRole})
	}
	if len(f.RowSecurity) > 0 {
		out = append(out, Finding{Kind: "row_security",
			Message: fmt.Sprintf("row-level security hides rows of %d table(s) (%s) from %s, so a backup holds only the rows it sees. "+
				"Each table's owner, or a role with BYPASSRLS, sees every row", len(f.RowSecurity), Some(f.RowSecurity), f.Name),
			Fix: fmt.Sprintf("ALTER ROLE %s BYPASSRLS; (run as a superuser; it reads every row and still writes nothing)", Ident(f.Name))})
	}
	return out
}

// Some names up to three items and says how many more there are.
func Some(items []string) string {
	if len(items) <= 3 {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:3], ", "), len(items)-3)
}

// Ident is a role's name as SQL, quoted only when it has to be.
func Ident(name string) string {
	plain := name != ""
	for i, r := range name {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (i > 0 && r >= '0' && r <= '9')) {
			plain = false
		}
	}
	if plain {
		return name
	}
	return pgx.Identifier{name}.Sanitize()
}
