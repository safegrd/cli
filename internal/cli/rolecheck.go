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
