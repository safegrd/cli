package cli

// The role check: what the role a PostgreSQL surface connects as may do
// beyond reading. A backup only reads, so a credential that can write is one
// that, leaked, can change or delete the data it backs up. Said by doctor and
// by claim, with the read-only role to use instead.

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/config"
)

// readOnlyRoleFix is the read-only role from
// safegrd.dev/docs/surfaces/databases#role, as one line.
const readOnlyRoleFix = "CREATE ROLE safegrd_backup LOGIN PASSWORD '<password>'; GRANT pg_read_all_data TO safegrd_backup; " +
	"then point the surface at it (PostgreSQL 13 and older: safegrd.dev/docs/surfaces/databases#role). " +
	"A role that is not a superuser cannot read password hashes, so roles are backed up without their passwords."

// roleFacts is what the connecting role may do.
type roleFacts struct {
	Name                                   string
	Super, CreateRole, CreateDB, BypassRLS bool
	// Writable is every table the role may INSERT, UPDATE, DELETE or
	// TRUNCATE; RowSecurity every table whose rows row-level security
	// filters for it.
	Writable, RowSecurity []string
}

func inspectRole(ctx context.Context, databaseURL string) (roleFacts, error) {
	var f roleFacts
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return f, err
	}
	defer conn.Close(ctx)
	if err := conn.QueryRow(ctx, `SELECT current_user, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls
		FROM pg_roles WHERE rolname = current_user`).Scan(&f.Name, &f.Super, &f.CreateRole, &f.CreateDB, &f.BypassRLS); err != nil {
		return f, err
	}
	const userTables = `FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		AND n.nspname NOT LIKE 'pg_toast%'`
	if f.Writable, err = tableNames(ctx, conn, `SELECT n.nspname || '.' || c.relname `+userTables+`
		AND has_table_privilege(current_user, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE') ORDER BY 1`); err != nil {
		return f, err
	}
	// Row-level security applies to everyone but a superuser, a BYPASSRLS
	// role and the table's owner (unless the table forces it on the owner).
	if !f.Super && !f.BypassRLS {
		if f.RowSecurity, err = tableNames(ctx, conn, `SELECT n.nspname || '.' || c.relname `+userTables+`
			AND c.relrowsecurity AND (c.relforcerowsecurity OR NOT pg_has_role(current_user, c.relowner, 'USAGE'))
			ORDER BY 1`); err != nil {
			return f, err
		}
	}
	return f, nil
}

func tableNames(ctx context.Context, conn *pgx.Conn, query string) ([]string, error) {
	rows, err := conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// someTables names up to three tables and says how many more there are.
func someTables(names []string) string {
	if len(names) <= 3 {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:3], ", "), len(names)-3)
}

// roleChecks words what a role may do as doctor lines: one for writing, and
// one when row-level security hides rows from it.
func roleChecks(surfaceID string, f roleFacts) []CheckResult {
	name := fmt.Sprintf("Surface %s role", surfaceID)
	var extra []string
	if f.CreateRole {
		extra = append(extra, "create roles")
	}
	if f.CreateDB {
		extra = append(extra, "create databases")
	}
	var out []CheckResult
	switch {
	case f.Super:
		out = append(out, CheckResult{Name: name, Status: "WARN",
			Message: fmt.Sprintf("connects as %s, a superuser; a read-only role is enough", f.Name), Fix: readOnlyRoleFix})
	case len(f.Writable) > 0:
		msg := fmt.Sprintf("%s can write to %d table(s) (%s)", f.Name, len(f.Writable), someTables(f.Writable))
		if len(extra) > 0 {
			msg += " and " + strings.Join(extra, " and ")
		}
		out = append(out, CheckResult{Name: name, Status: "WARN", Message: msg + "; a read-only role is enough", Fix: readOnlyRoleFix})
	case len(extra) > 0:
		out = append(out, CheckResult{Name: name, Status: "WARN",
			Message: fmt.Sprintf("%s writes to no table but can %s; a read-only role is enough", f.Name, strings.Join(extra, " and ")), Fix: readOnlyRoleFix})
	default:
		out = append(out, CheckResult{Name: name, Status: "PASS", Message: f.Name + " writes to no table"})
	}
	if len(f.RowSecurity) > 0 {
		out = append(out, CheckResult{Name: fmt.Sprintf("Surface %s row security", surfaceID), Status: "WARN",
			Message: fmt.Sprintf("row-level security hides rows of %d table(s) (%s) from %s, so a backup holds only the rows it sees. "+
				"Each table's owner, or a role with BYPASSRLS, sees every row", len(f.RowSecurity), someTables(f.RowSecurity), f.Name),
			Fix: fmt.Sprintf("ALTER ROLE %s BYPASSRLS; (run as a superuser; it reads every row and still writes nothing)", roleIdent(f.Name))})
	}
	return out
}

// roleIdent is a role's name as SQL, quoted only when it has to be.
func roleIdent(name string) string {
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

// surfaceRoleChecks runs the role check for every PostgreSQL surface this
// host can open. A surface whose URL does not resolve has been reported by
// the credential checks already.
func surfaceRoleChecks(c *config.CLIConfig, only map[string]bool) []CheckResult {
	var results []CheckResult
	for i := range c.Surfaces {
		s := &c.Surfaces[i]
		if strings.ToLower(s.Type) != "postgres" || (only != nil && !only[s.ID]) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), credentialCommandTimeout)
		u, err := resolveSurfaceDatabaseURLAsGiven(ctx, c, s)
		if err != nil || u == "" {
			cancel()
			continue
		}
		u, _ = cleanPostgresURL(u)
		f, err := inspectRole(ctx, u)
		cancel()
		if err != nil {
			// The connection check says why it would not open.
			continue
		}
		results = append(results, roleChecks(s.ID, f)...)
	}
	return results
}
