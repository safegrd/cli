package cli

// The role check: what the role or account a PostgreSQL, MySQL or MongoDB
// surface connects as may do beyond reading. A backup only reads, so a credential that can write is one
// that, leaked, can change or delete the data it backs up. Said by doctor and
// by claim, with the read-only role to use instead.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/dbrole"
	"github.com/safegrd/cli/pkg/dump"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// readOnlyRoleFix is the read-only role from
// safegrd.dev/docs/surfaces/postgres#role, with what it costs.
const readOnlyRoleFix = dbrole.ReadOnlyRole + " Then point the surface at it (PostgreSQL 13 and older: safegrd.dev/docs/surfaces/postgres#role). " +
	"A role that is not a superuser cannot read password hashes, so roles are backed up without their passwords."

func inspectRole(ctx context.Context, databaseURL string) (dbrole.Facts, error) {
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		return dbrole.Facts{}, err
	}
	defer conn.Close(ctx)
	// Judge the role the backup reads as (dump takes it the same way).
	dbrole.TakeLoginRole(ctx, conn)
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

// surfaceRoleChecks runs the role check for every PostgreSQL, MySQL and
// MongoDB surface this host can open. A surface whose URL does not resolve
// has been reported by the credential checks already.
func surfaceRoleChecks(c *config.CLIConfig, only map[string]bool) []CheckResult {
	var results []CheckResult
	for i := range c.Surfaces {
		s := &c.Surfaces[i]
		kind := strings.ToLower(s.Type)
		if (kind != "postgres" && kind != "mysql" && kind != "mongodb") || (only != nil && !only[s.ID]) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), credentialCommandTimeout)
		u, err := resolveSurfaceDatabaseURLAsGiven(ctx, c, s)
		if err != nil || u == "" {
			cancel()
			continue
		}
		switch kind {
		case "mysql":
			if r, ok := mysqlAccountCheck(ctx, s.ID, u); ok {
				results = append(results, r)
			}
		case "mongodb":
			if r, ok := mongoAccountCheck(ctx, s.ID, u); ok {
				results = append(results, r)
			}
		default:
			u, _ = cleanPostgresURL(u)
			if f, err := inspectRole(ctx, u); err == nil {
				// On an error the connection check says why it would not open.
				results = append(results, roleChecks(s.ID, f)...)
			}
		}
		cancel()
	}
	return results
}

// mysqlReadOnlyFix is the account a MySQL surface backs up as, from
// safegrd.dev/docs/surfaces/mysql#grants.
const mysqlReadOnlyFix = "Back up as an account that only reads: CREATE USER 'safegrd_backup'@'%' IDENTIFIED BY '...'; " +
	"GRANT SELECT, SHOW VIEW, TRIGGER, LOCK TABLES, EVENT ON <database>.* TO 'safegrd_backup'@'%'; " +
	"and on MySQL 8.0.20 and newer GRANT SHOW_ROUTINE ON *.* TO 'safegrd_backup'@'%' (safegrd.dev/docs/surfaces/mysql#grants)."

// mongoReadOnlyFix is the user a MongoDB surface backs up as, from
// safegrd.dev/docs/surfaces/mongodb#grants.
const mongoReadOnlyFix = `Back up as a user that only reads: db.getSiblingDB("admin").createUser({user: "safegrd_backup", ` +
	`pwd: passwordPrompt(), roles: [{role: "read", db: "<database>"}]}) (safegrd.dev/docs/surfaces/mongodb#grants).`

// mysqlAccountCheck says what a MySQL surface's account may change, from its
// own SHOW GRANTS. false when it does not connect: the connection check says
// why.
func mysqlAccountCheck(ctx context.Context, surfaceID, databaseURL string) (CheckResult, bool) {
	db, err := dump.OpenMySQL(databaseURL)
	if err != nil {
		return CheckResult{}, false
	}
	defer db.Close()
	var user string
	if err := db.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&user); err != nil {
		return CheckResult{}, false
	}
	rows, err := db.QueryContext(ctx, "SHOW GRANTS")
	if err != nil {
		return CheckResult{}, false
	}
	defer rows.Close()
	var grants []string
	for rows.Next() {
		var g string
		if rows.Scan(&g) == nil {
			grants = append(grants, g)
		}
	}
	name := fmt.Sprintf("Surface %s account", surfaceID)
	if w := dbrole.MySQLWrites(grants); len(w) > 0 {
		return CheckResult{Name: name, Status: "WARN", Message: fmt.Sprintf("%s can write: %s; an account that only reads is enough",
			user, dbrole.Some(w)), Fix: mysqlReadOnlyFix}, true
	}
	return CheckResult{Name: name, Status: "PASS", Message: user + " changes nothing"}, true
}

// mongoAccountCheck says which of a MongoDB surface's user's built-in roles
// can change something, from connectionStatus.
func mongoAccountCheck(ctx context.Context, surfaceID, databaseURL string) (CheckResult, bool) {
	client, err := mongo.Connect(options.Client().ApplyURI(databaseURL).SetServerSelectionTimeout(10 * time.Second))
	if err != nil {
		return CheckResult{}, false
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	var status struct {
		AuthInfo struct {
			Users []struct {
				User string `bson:"user"`
				DB   string `bson:"db"`
			} `bson:"authenticatedUsers"`
			Roles []dbrole.MongoRole `bson:"authenticatedUserRoles"`
		} `bson:"authInfo"`
	}
	if err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "connectionStatus", Value: 1}}).Decode(&status); err != nil {
		return CheckResult{}, false
	}
	user := "the connection"
	if u := status.AuthInfo.Users; len(u) > 0 {
		user = u[0].User
	}
	name := fmt.Sprintf("Surface %s account", surfaceID)
	if len(status.AuthInfo.Users) == 0 {
		return CheckResult{Name: name, Status: "WARN", Message: "the connection signs in as no user, so it is whatever the server allows an unauthenticated client",
			Fix: mongoReadOnlyFix}, true
	}
	if w := dbrole.MongoWrites(status.AuthInfo.Roles); len(w) > 0 {
		return CheckResult{Name: name, Status: "WARN", Message: fmt.Sprintf("%s can write: %s; a user with the read role is enough",
			user, dbrole.Some(w)), Fix: mongoReadOnlyFix}, true
	}
	return CheckResult{Name: name, Status: "PASS", Message: user + " holds no role that writes"}, true
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
	return hiddenRowsRefusal(f.Name, f.RowSecurity, via)
}

// hiddenRowsRefusal is the error refuseHiddenRows returns. It exits
// exitSource: the database's own grants refused the role, and an exit 1
// read as a failure whose side nobody knew.
func hiddenRowsRefusal(role string, tables []string, via string) error {
	fix := fmt.Sprintf("Run ALTER ROLE %s BYPASSRLS; as the database's owner, or hold a connection string for a role that reads every row.", dbrole.Ident(role))
	if via == "supabase" {
		fix = "Type the project's database password instead: its postgres user reads every row."
	}
	return classed(exitSource, fmt.Errorf("row-level security hides rows of %d table(s) (%s) from %s, the role the %s sign-in gave this backup, so the backup would miss them. %s",
		len(tables), dbrole.Some(tables), role, signInTitle(via), fix))
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
