package dump

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/model"
)

func TestDotenvReadsWhatPhpdotenvReads(t *testing.T) {
	t.Setenv("SAFEGRD_TEST_HOST_FROM_PROCESS", "db.internal")
	env, err := ParseDotenv([]byte(`# a comment
APP_NAME="My Shop"
export APP_ENV=production
DB_HOST=${SAFEGRD_TEST_HOST_FROM_PROCESS}
DB_USERNAME=shop # the app's user
DB_PASSWORD='p#ss ${NOT_EXPANDED}'
DB_DATABASE="${APP_ENV}_db"
MULTI="line one
line two"
QUOTE="say \"hi\""
NULLED=null
`))
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"APP_NAME": "My Shop", "APP_ENV": "production", "DB_HOST": "db.internal", "DB_USERNAME": "shop",
		"DB_PASSWORD": "p#ss ${NOT_EXPANDED}", "DB_DATABASE": "production_db", "MULTI": "line one\nline two",
		"QUOTE": `say "hi"`, "NULLED": "", "UNSET": "",
	} {
		if got, err := env.Get(k); err != nil || got != want {
			t.Errorf("%s = %q (%v), want %q", k, got, err, want)
		}
	}
}

func TestDotenvRefusesAReferenceToNothing(t *testing.T) {
	env, err := ParseDotenv([]byte("DB_PASSWORD=${SAFEGRD_TEST_NEVER_SET_ANYWHERE}\nOTHER=x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.Get("DB_PASSWORD"); err == nil || !strings.Contains(err.Error(), "SAFEGRD_TEST_NEVER_SET_ANYWHERE") {
		t.Fatalf("an unresolved reference read as a value: %v", err)
	}
	if v, err := env.Get("OTHER"); err != nil || v != "x" {
		t.Fatalf("a key beside an unresolved one did not read: %q %v", v, err)
	}
	if _, err := ParseDotenv([]byte("KEY=\"open\n")); err == nil {
		t.Fatal("an unclosed double quote was accepted")
	}
}

func laravelApp(t *testing.T, env string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "artisan"), []byte("#!/usr/bin/env php\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if env != "" {
		if err := os.WriteFile(filepath.Join(root, ".env"), []byte(env), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const goodKey = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestDiscoverLaravelBuildsTheURLLaravelWouldConnectTo(t *testing.T) {
	for name, tc := range map[string]struct{ env, conn, url string }{
		"mysql": {"DB_CONNECTION=mysql\nDB_HOST=db\nDB_DATABASE=shop\nDB_USERNAME=shop\nDB_PASSWORD=p@ss:word\n", "mysql",
			"mysql://shop:p%40ss%3Aword@db:3306/shop"},
		"mariadb default host": {"DB_CONNECTION=mariadb\nDB_DATABASE=shop\nDB_USERNAME=root\nDB_PASSWORD=\n", "mariadb",
			"mariadb://root:@127.0.0.1:3306/shop"},
		"pgsql with sslmode": {"DB_CONNECTION=pgsql\nDB_HOST=pg\nDB_PORT=6432\nDB_DATABASE=shop\nDB_USERNAME=app\nDB_PASSWORD=x\nDB_SSLMODE=require\n", "pgsql",
			"postgres://app:x@pg:6432/shop?sslmode=require"},
		"DB_URL wins": {"DB_URL=pgsql://u:p@h:5432/d\nDB_CONNECTION=mysql\n", "pgsql", "postgres://u:p@h:5432/d"},
	} {
		t.Run(name, func(t *testing.T) {
			app, err := DiscoverLaravel(laravelApp(t, "APP_KEY="+goodKey+"\n"+tc.env))
			if err != nil {
				t.Fatal(err)
			}
			if app.Connection != tc.conn || app.DatabaseURL != tc.url {
				t.Fatalf("got %s %s, want %s %s", app.Connection, app.DatabaseURL, tc.conn, tc.url)
			}
			if app.AppKeyProblem != "" {
				t.Fatalf("a good APP_KEY was flagged: %s", app.AppKeyProblem)
			}
		})
	}
	root := laravelApp(t, "DB_CONNECTION=sqlite\n")
	app, err := DiscoverLaravel(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := "sqlite://" + filepath.Join(app.Root, "database", "database.sqlite"); app.DatabaseURL != want {
		t.Fatalf("an unset DB_DATABASE on sqlite is %s, want %s", app.DatabaseURL, want)
	}
	if app.AppKeyProblem == "" {
		t.Fatal("a .env with no APP_KEY was not flagged")
	}
}

func TestDiscoverLaravelRefusesWhatItCannotReadForCertain(t *testing.T) {
	for name, tc := range map[string]struct {
		root func(t *testing.T) string
		says string
	}{
		"no artisan":    {func(t *testing.T) string { return t.TempDir() }, "no artisan"},
		"no .env":       {func(t *testing.T) string { return laravelApp(t, "") }, "has no .env"},
		"no connection": {func(t *testing.T) string { return laravelApp(t, "DB_DATABASE=x\n") }, "no DB_CONNECTION"},
		"sqlsrv":        {func(t *testing.T) string { return laravelApp(t, "DB_CONNECTION=sqlsrv\n") }, "SQL Server"},
		"socket": {func(t *testing.T) string {
			return laravelApp(t, "DB_CONNECTION=mysql\nDB_DATABASE=x\nDB_SOCKET=/run/mysqld.sock\n")
		}, "DB_SOCKET"},
		"memory": {func(t *testing.T) string { return laravelApp(t, "DB_CONNECTION=sqlite\nDB_DATABASE=:memory:\n") }, ":memory:"},
		"unresolved": {func(t *testing.T) string {
			return laravelApp(t, "DB_CONNECTION=mysql\nDB_DATABASE=x\nDB_PASSWORD=${SAFEGRD_TEST_NOPE}\n")
		}, "SAFEGRD_TEST_NOPE"},
	} {
		t.Run(name, func(t *testing.T) {
			app, err := DiscoverLaravel(tc.root(t))
			if err == nil {
				_, _, err = app.Database()
			}
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("got %v, want an error saying %q", err, tc.says)
			}
		})
	}
}

func TestCheckLaravelAppKey(t *testing.T) {
	for key, ok := range map[string]bool{
		goodKey: true, "base64:AAAAAAAAAAAAAAAAAAAAAA==": true, "0123456789abcdef0123456789abcdef": true,
		"": false, "base64:not base64!": false, "base64:AAAA": false, "short": false,
	} {
		if err := CheckLaravelAppKey(key); (err == nil) != ok {
			t.Errorf("APP_KEY %q: %v", key, err)
		}
	}
}

func assertion(t *testing.T, as []model.AssertionResult, name string) model.AssertionResult {
	t.Helper()
	for _, a := range as {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("no %s assertion in %+v", name, as)
	return model.AssertionResult{}
}

func TestLaravelAssertions(t *testing.T) {
	db := func(rows int64) *DryRestoreResult {
		return &DryRestoreResult{Tables: []TableDryStats{{TableName: "users", RowCount: 3}, {TableName: "migrations", RowCount: rows}}}
	}
	files := []string{"0001_01_01_000000_create_users_table", "2026_10_01_000000_add_orders"}
	env := []byte("APP_KEY=" + goodKey + "\n")
	stats := func(ran int64, pending ...string) *model.LaravelStats {
		return &model.LaravelStats{MigrationsTable: "migrations", MigrationsRan: ran, Pending: pending}
	}

	as := LaravelAssertions(stats(2), db(2), env, files)
	if a := assertion(t, as, "AppKey"); !a.Passed {
		t.Errorf("AppKey failed on a good key: %s", a.Message)
	}
	if a := assertion(t, as, "Migrations"); !a.Passed {
		t.Errorf("Migrations failed when the table agrees: %s", a.Message)
	}
	// A package's own migrations add rows with no file.
	if a := assertion(t, LaravelAssertions(stats(5), db(5), env, files), "Migrations"); !a.Passed {
		t.Errorf("more rows than files failed: %s", a.Message)
	}
	if a := assertion(t, LaravelAssertions(stats(1, files[1]), db(1), env, files), "Migrations"); !a.Passed {
		t.Errorf("a migration pending at backup time failed the drill: %s", a.Message)
	}
	if a := assertion(t, LaravelAssertions(stats(1), db(1), env, files), "Migrations"); a.Passed {
		t.Error("two run migration files and one row passed")
	}
	if a := assertion(t, LaravelAssertions(stats(2), &DryRestoreResult{}, env, files), "Migrations"); a.Passed || !strings.Contains(a.Message, "no migrations table") {
		t.Errorf("a dump without the migrations table passed: %+v", a)
	}
	if a := assertion(t, LaravelAssertions(stats(2), db(2), nil, files), "AppKey"); a.Passed {
		t.Error("a snapshot with no .env passed AppKey")
	}
	if a := assertion(t, LaravelAssertions(stats(2), db(2), []byte("APP_KEY=\n"), files), "AppKey"); a.Passed || !strings.Contains(a.Actual, "no APP_KEY") {
		t.Errorf("an empty APP_KEY passed: %+v", a)
	}
}
