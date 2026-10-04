package dump

import (
	"strings"
	"testing"
)

const rolesDumpFixture = `--
-- PostgreSQL database cluster dump
--

SET default_transaction_read_only = off;

CREATE ROLE "Odd Role";
ALTER ROLE "Odd Role" WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE app_ro;
ALTER ROLE app_ro WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE app_user;
ALTER ROLE app_user WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:abc==$def=:ghi=';
CREATE ROLE postgres;
ALTER ROLE postgres WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:x==$y=:z=';

--
-- User Config "app_user"
--

ALTER ROLE app_user SET search_path TO 'public';
ALTER ROLE app_user IN DATABASE shop SET work_mem TO '64MB';

--
-- Role memberships
--

GRANT app_ro TO app_user WITH INHERIT TRUE GRANTED BY postgres;
GRANT app_ro TO "Odd Role" GRANTED BY postgres;
`

const sectionsFixture = `--
-- Name: orders; Type: TABLE; Schema: public; Owner: app_owner
--

CREATE TABLE public.orders (
    id integer NOT NULL
);


ALTER TABLE public.orders OWNER TO app_owner;

ALTER SCHEMA public OWNER TO pg_database_owner;

CREATE POLICY own_rows ON public.orders FOR SELECT TO app_user, "Odd Role" USING ((id > 0));
CREATE POLICY everyone ON public.orders TO PUBLIC USING (true);
GRANT SELECT ON TABLE public.orders TO app_user;
GRANT ALL ON TABLE public.orders TO app_owner WITH GRANT OPTION;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON FUNCTION public.f(a text, b text) TO app_ro;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT SELECT ON TABLES TO reader;
`

// The roles the schema names are the owners, grantees, default-privilege
// roles and policy roles, without PUBLIC and PostgreSQL's own.
func TestNamedRolesReadsOwnersGranteesAndPolicies(t *testing.T) {
	got := strings.Join(namedRoles([]byte(sectionsFixture)), ",")
	if want := "Odd Role,app_owner,app_ro,app_user,reader"; got != want {
		t.Fatalf("namedRoles = %s, want %s", got, want)
	}
}

// roles.sql carries only the roles named, with their settings and the
// memberships among them, without the source database's per-database
// settings, and without the GRANTED BY the target cannot honour.
func TestRolesDumpIsCutToTheRolesNamed(t *testing.T) {
	d := parseRolesSQL([]byte(rolesDumpFixture))
	sql, missing := d.only([]string{"Odd Role", "app_ro", "app_user", "reader"})
	s := string(sql)
	for _, want := range []string{
		"CREATE ROLE app_user;", "PASSWORD 'SCRAM-SHA-256$4096:abc==$def=:ghi=';",
		"ALTER ROLE app_user SET search_path TO 'public';",
		`CREATE ROLE "Odd Role";`, `GRANT "app_ro" TO "app_user";`, `GRANT "app_ro" TO "Odd Role";`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("roles.sql lacks %q:\n%s", want, s)
		}
	}
	for _, unwanted := range []string{"postgres", "IN DATABASE", "GRANTED BY", "INHERIT TRUE"} {
		if strings.Contains(s, unwanted) {
			t.Errorf("roles.sql carries %q:\n%s", unwanted, s)
		}
	}
	if strings.Join(missing, ",") != "reader" {
		t.Errorf("missing = %v, want reader", missing)
	}
	// Parsing what was written gives the same roles back.
	again := parseRolesSQL(sql)
	if got := strings.Join(again.names(), ","); got != "Odd Role,app_ro,app_user" {
		t.Errorf("round trip names = %s", got)
	}
	if len(again.members) != 2 {
		t.Errorf("round trip memberships = %v", again.members)
	}
}

// A role created on a target never comes back as a superuser or a
// replication role, whatever the source said; LOGIN and PASSWORD stay.
func TestCreateStatementsTurnOffSuperuserAndReplication(t *testing.T) {
	d := parseRolesSQL([]byte(rolesDumpFixture))
	stmts := strings.Join(d.createStatements("postgres"), "\n")
	if !strings.Contains(stmts, "NOSUPERUSER") || !strings.Contains(stmts, "NOREPLICATION") || strings.Contains(stmts, " SUPERUSER") || strings.Contains(stmts, " REPLICATION") {
		t.Errorf("superuser survived: %s", stmts)
	}
	if !strings.Contains(stmts, " LOGIN ") || !strings.Contains(stmts, "PASSWORD 'SCRAM") {
		t.Errorf("login or password lost: %s", stmts)
	}
	if got := strings.Join(d.createStatements("app_user"), "\n"); strings.Contains(got, "IN DATABASE") || !strings.Contains(got, "SET search_path") {
		t.Errorf("app_user statements: %s", got)
	}
}

// --no-owner drops ownership, privileges and default privileges and keeps
// everything else; the public schema's owner is always dropped.
func TestStripOwnershipKeepsTheObjects(t *testing.T) {
	s := stripOwnership(stripPublicSchemaOwner(sectionsFixture))
	for _, gone := range []string{"OWNER TO", "GRANT SELECT", "REVOKE ALL", "ALTER DEFAULT PRIVILEGES", "GRANT ALL ON FUNCTION"} {
		if strings.Contains(s, gone) {
			t.Errorf("%q survived --no-owner:\n%s", gone, s)
		}
	}
	for _, kept := range []string{"CREATE TABLE public.orders", "CREATE POLICY own_rows", "-- Name: orders; Type: TABLE; Schema: public; Owner: app_owner"} {
		if !strings.Contains(s, kept) {
			t.Errorf("%q was dropped:\n%s", kept, s)
		}
	}
	if with := stripPublicSchemaOwner(sectionsFixture); strings.Contains(with, "ALTER SCHEMA public OWNER") || !strings.Contains(with, "OWNER TO app_owner") {
		t.Errorf("public schema owner handling: %s", with)
	}
}

// The in-memory drill holds the roles the schema names to roles.sql: a
// snapshot carrying none while its policy names one fails, one carrying
// them passes, and a schema naming no role has no assertion at all.
func TestRolesCarriedAssertion(t *testing.T) {
	if a := rolesCarriedAssertion(nil, false, nil); a != nil {
		t.Fatalf("a schema naming no role got an assertion: %+v", a)
	}
	a := rolesCarriedAssertion([]string{"app_user"}, false, nil)
	if a == nil || a.Passed || !strings.Contains(a.Message, "app_user") || !strings.Contains(a.Message, "carries no roles") {
		t.Fatalf("no roles.sql: %+v", a)
	}
	a = rolesCarriedAssertion([]string{"app_owner", "app_user"}, true, []string{"app_owner"})
	if a == nil || a.Passed || a.Actual != "missing: app_user" {
		t.Fatalf("one missing: %+v", a)
	}
	a = rolesCarriedAssertion([]string{"app_owner", "app_user"}, true, []string{"app_owner", "app_user", "extra"})
	if a == nil || !a.Passed || a.Actual != "2 carried" {
		t.Fatalf("all carried: %+v", a)
	}
}
