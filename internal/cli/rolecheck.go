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
	"github.com/safegrd/cli/pkg/dbrole"
)

// readOnlyRoleFix is the read-only role from
// safegrd.dev/docs/surfaces/databases#role, with what it costs.
const readOnlyRoleFix = dbrole.ReadOnlyRole + " Then point the surface at it (PostgreSQL 13 and older: safegrd.dev/docs/surfaces/databases#role). " +
	"A role that is not a superuser cannot read password hashes, so roles are backed up without their passwords."

func inspectRole(ctx context.Context, databaseURL string) (dbrole.Facts, error) {
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return dbrole.Facts{}, err
	}
	defer conn.Close(ctx)
	return dbrole.Inspect(ctx, conn)
}

// roleChecks words what a role may do as doctor lines: one for writing, and
// one when row-level security hides rows from it.
func roleChecks(surfaceID string, f dbrole.Facts) []CheckResult {
	name := fmt.Sprintf("Surface %s role", surfaceID)
	out := []CheckResult{{Name: name, Status: "PASS", Message: f.Name + " writes to no table"}}
	for _, fd := range f.Findings() {
		switch fd.Kind {
		case "role":
			out[0] = CheckResult{Name: name, Status: "WARN", Message: fd.Message, Fix: readOnlyRoleFix}
		case "row_security":
			out = append(out, CheckResult{Name: fmt.Sprintf("Surface %s row security", surfaceID), Status: "WARN", Message: fd.Message, Fix: fd.Fix})
		}
	}
	return out
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

// refuseHiddenRows is the backup's check of a role a sign-in made, before any
// table is read: a table row-level security filters for it would be backed up
// with only the rows it sees, and the role is not this host's to change. The
// remote server runs the same check when it can reach the database; a
// firewall that admits this machine and not the server leaves it to here.
func refuseHiddenRows(ctx context.Context, databaseURL, via string) error {
	f, err := inspectRole(ctx, databaseURL)
	if err != nil {
		// The dump says how the connection failed, in its own words.
		return nil
	}
	if len(f.RowSecurity) == 0 {
		return nil
	}
	fix := fmt.Sprintf("Run ALTER ROLE %s BYPASSRLS; as the database's owner, or hold a connection string for a role that reads every row.", dbrole.Ident(f.Name))
	if via == "supabase" {
		fix = "Type the project's database password instead: its postgres user reads every row."
	}
	return fmt.Errorf("row-level security hides rows of %d table(s) (%s) from %s, the role the %s sign-in gave this backup, so the backup would miss them. %s",
		len(f.RowSecurity), dbrole.Some(f.RowSecurity), f.Name, signInTitle(via), fix)
}

// signInTitle is a sign-in's name as the console shows it.
func signInTitle(via string) string {
	switch via {
	case "supabase":
		return "Supabase"
	case "digitalocean":
		return "DigitalOcean"
	case "heroku":
		return "Heroku"
	}
	return via
}
