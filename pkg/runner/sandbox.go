package runner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
)

// A Fire Drill restores into a sandbox database. Pointed at the wrong
// database, that is a restore over live data, so a sandbox has to prove it is
// one: it holds no user tables before the drill, it is not the database the
// surface backs up, and after an unattended drill it is emptied again so the
// next one can prove the same thing.

// userSchemasQuery lists schemas that are not Postgres' own.
const userSchemasQuery = `SELECT nspname FROM pg_namespace
	WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema'`

// CheckSandboxEmpty refuses a sandbox that holds any user table.
func CheckSandboxEmpty(ctx context.Context, sandboxURL string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if dump.IsSQLiteURL(sandboxURL) {
		path, err := dump.SQLitePath(sandboxURL)
		if err != nil {
			return err
		}
		if err := dump.SQLiteCheckEmpty(path); err != nil {
			return fmt.Errorf("refusing to restore into the sandbox: %w. A Fire Drill sandbox must be a file "+
				"used for nothing else, absent before each drill; point drill.sandbox_url at one", err)
		}
		return nil
	}
	if dump.IsMongoURL(sandboxURL) {
		client, db, err := dump.OpenMongo(ctx, sandboxURL)
		if err != nil {
			return fmt.Errorf("cannot connect to the sandbox database: %w", err)
		}
		defer func() { _ = client.Disconnect(context.Background()) }()
		if err := dump.MongoCheckEmpty(ctx, db); err != nil {
			return fmt.Errorf("refusing to restore into the sandbox: %w. A Fire Drill sandbox must be a database "+
				"used for nothing else, empty before each drill; point drill.sandbox_url at one", err)
		}
		return nil
	}
	if dump.IsMySQLURL(sandboxURL) {
		db, err := dump.OpenMySQL(sandboxURL)
		if err != nil {
			return fmt.Errorf("cannot connect to the sandbox database: %w", err)
		}
		defer db.Close()
		if err := dump.MySQLCheckEmpty(ctx, db); err != nil {
			return fmt.Errorf("refusing to restore into the sandbox: %w. A Fire Drill sandbox must be a database "+
				"used for nothing else, empty before each drill; point drill.sandbox_url at one", err)
		}
		return nil
	}
	conn, err := pgx.Connect(ctx, sandboxURL)
	if err != nil {
		return fmt.Errorf("cannot connect to the sandbox database: %w", err)
	}
	defer conn.Close(context.Background())
	var tables int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p', 'v', 'm') AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
		  AND NOT EXISTS (SELECT 1 FROM pg_depend d
		                  WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')`).Scan(&tables); err != nil {
		return fmt.Errorf("cannot inspect the sandbox database: %w", err)
	}
	if tables > 0 {
		return fmt.Errorf("refusing to restore into the sandbox: it holds %d table(s). A Fire Drill sandbox must be a database "+
			"used for nothing else, empty before each drill; point drill.sandbox_url at one", tables)
	}
	return nil
}

// ResetSandbox drops everything a drill restored. It is only ever called after
// CheckSandboxEmpty passed, so everything in the database is the drill's.
func ResetSandbox(ctx context.Context, sandboxURL string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if dump.IsSQLiteURL(sandboxURL) {
		path, err := dump.SQLitePath(sandboxURL)
		if err != nil {
			return err
		}
		return dump.SQLiteResetDatabase(path)
	}
	if dump.IsMongoURL(sandboxURL) {
		client, db, err := dump.OpenMongo(ctx, sandboxURL)
		if err != nil {
			return err
		}
		defer func() { _ = client.Disconnect(context.Background()) }()
		return dump.MongoResetDatabase(ctx, db)
	}
	if dump.IsMySQLURL(sandboxURL) {
		db, err := dump.OpenMySQL(sandboxURL)
		if err != nil {
			return err
		}
		defer db.Close()
		return dump.MySQLResetDatabase(ctx, db)
	}
	conn, err := pgx.Connect(ctx, sandboxURL)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	// A role that is not a superuser drops what it owns in this database,
	// which is everything the drill restored and nothing the provider
	// installed: dropping the public schema instead would take a provider's
	// extension with it, and the next drill could not create it again.
	//
	// Not DROP OWNED BY: it reaches beyond this database, revoking privileges
	// granted to the role on shared objects (databases among them) wherever
	// the role is able to. Checked on PostgreSQL 16, a grant made by another
	// role survives it with a warning, but a reset has no business near the
	// grants on production, so this drops objects in this database only.
	var super bool
	if err := conn.QueryRow(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&super); err != nil {
		return err
	}
	if !super {
		return dropOwnedHere(ctx, conn)
	}
	rows, err := conn.Query(ctx, userSchemasQuery)
	if err != nil {
		return err
	}
	var schemas []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			schemas = append(schemas, n)
		}
	}
	rows.Close()
	for _, n := range schemas {
		if _, err := conn.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{n}.Sanitize()+" CASCADE"); err != nil {
			return fmt.Errorf("dropping schema %s: %w", n, err)
		}
	}
	_, err = conn.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS public")
	return err
}

// SameDatabase reports whether two connection URLs name the same database on
// the same server, so a sandbox can never be the surface it drills.
func SameDatabase(a, b string) bool {
	if dump.IsSQLiteURL(a) || dump.IsSQLiteURL(b) {
		return dump.SameSQLiteDatabase(a, b)
	}
	if dump.IsMongoURL(a) || dump.IsMongoURL(b) {
		return dump.SameMongoDatabase(a, b)
	}
	if dump.IsMySQLURL(a) || dump.IsMySQLURL(b) {
		return dump.SameMySQLDatabase(a, b)
	}
	ca, errA := pgx.ParseConfig(a)
	cb, errB := pgx.ParseConfig(b)
	if errA != nil || errB != nil {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	return strings.EqualFold(ca.Host, cb.Host) && ca.Port == cb.Port && ca.Database == cb.Database
}

// RunSandboxDrill is the unattended drill into a sandbox: refuse a sandbox
// with data, restore and count, then empty it for next time.
func (v *Verifier) RunSandboxDrill(ctx context.Context, snapshotID, privateKey, sandboxURL string) (*model.VerificationReport, error) {
	if err := CheckSandboxEmpty(ctx, sandboxURL); err != nil {
		return nil, err
	}
	report, err := v.RunFireDrill(ctx, snapshotID, privateKey, sandboxURL)
	if resetErr := ResetSandbox(ctx, sandboxURL); resetErr != nil && err == nil {
		err = fmt.Errorf("the drill ran, but the sandbox could not be emptied for the next one: %w", resetErr)
	}
	return report, err
}

// ownedHereQuery lists, in drop order, what the current role owns in this
// database and no extension does: its extensions, then schemas other than
// public, then the views, tables, sequences, routines and types it left in
// schemas it does not own.
const ownedHereQuery = `
WITH me AS (SELECT oid FROM pg_roles WHERE rolname = current_user),
not_ext AS (SELECT objid FROM pg_depend WHERE deptype = 'e')
SELECT 1, 'EXTENSION', quote_ident(extname) FROM pg_extension WHERE extowner = (SELECT oid FROM me)
UNION ALL
SELECT 2, 'SCHEMA', quote_ident(nspname) FROM pg_namespace
  WHERE nspowner = (SELECT oid FROM me) AND nspname <> 'public' AND nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema'
UNION ALL
SELECT 3, CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' WHEN 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,
  quote_ident(n.nspname) || '.' || quote_ident(c.relname)
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relowner = (SELECT oid FROM me) AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
    AND (n.nspowner <> (SELECT oid FROM me) OR n.nspname = 'public') AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
    AND c.oid NOT IN (SELECT objid FROM not_ext)
UNION ALL
SELECT 4, 'ROUTINE', p.oid::regprocedure::text
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE p.proowner = (SELECT oid FROM me) AND (n.nspowner <> (SELECT oid FROM me) OR n.nspname = 'public')
    AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' AND p.oid NOT IN (SELECT objid FROM not_ext)
UNION ALL
SELECT 5, 'TYPE', t.oid::regtype::text
  FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
  WHERE t.typowner = (SELECT oid FROM me) AND t.typtype IN ('e', 'd', 'r', 'c') AND t.typelem = 0
    AND (t.typtype <> 'c' OR (SELECT relkind FROM pg_class WHERE oid = t.typrelid) = 'c')
    AND (n.nspowner <> (SELECT oid FROM me) OR n.nspname = 'public') AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
    AND t.oid NOT IN (SELECT objid FROM not_ext)
ORDER BY 1`

func dropOwnedHere(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, ownedHereQuery)
	if err != nil {
		return err
	}
	type obj struct{ kind, name string }
	var objs []obj
	for rows.Next() {
		var order int
		var o obj
		if err := rows.Scan(&order, &o.kind, &o.name); err != nil {
			rows.Close()
			return err
		}
		objs = append(objs, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, o := range objs {
		// IF EXISTS: an earlier CASCADE may already have taken it.
		if _, err := conn.Exec(ctx, "DROP "+o.kind+" IF EXISTS "+o.name+" CASCADE"); err != nil {
			return fmt.Errorf("dropping %s %s: %w", strings.ToLower(o.kind), o.name, err)
		}
	}
	return nil
}
