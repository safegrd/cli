package dump

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/model"
)

// A Laravel app is backed up as one snapshot: its database, stored as that
// engine's surface stores it under db/, and its .env, storage/app and
// migration files under files/. The connection is read from the app's .env
// at every backup, so a rotated password needs no change here.

// LaravelEnvFile, LaravelUploadsDir and the migration directories are the
// app's paths relative to its root, and the snapshot's under files/.
const (
	LaravelEnvFile       = ".env"
	LaravelUploadsDir    = "storage/app"
	LaravelMigrationsDir = "database/migrations"
	LaravelSchemaDir     = "database/schema"
	// LaravelMigrationsTable is the table Laravel records the migrations it
	// ran in, unless config/database.php names another.
	LaravelMigrationsTable = "migrations"
)

// LaravelLeftOut are left out of a Laravel app's storage/app, relative to its
// root: spatie/laravel-backup's working directory and Livewire's temporary
// uploads, which expire. Caches, sessions and logs are outside storage/app
// and never walked.
var LaravelLeftOut = []string{
	"storage/app/backup-temp",
	"storage/app/livewire-tmp",
	"storage/app/private/livewire-tmp",
}

// LaravelSpatieArchives is where spatie/laravel-backup keeps its archives
// when it writes to the local disk, relative to the app's root, when
// config/backup.php exists; "" when it does not. They are a second copy of
// what this backup takes, so they are left out.
func LaravelSpatieArchives(root, appName string) string {
	if _, err := os.Stat(filepath.Join(root, "config", "backup.php")); err != nil || appName == "" {
		return ""
	}
	if strings.ContainsAny(appName, "/\\*?[") {
		return ""
	}
	return LaravelUploadsDir + "/" + appName + "/*.zip"
}

// LaravelApp is what a backup reads from an app's root.
type LaravelApp struct {
	Root string
	// Connection is DB_CONNECTION, or the scheme of DB_URL.
	Connection string
	// DatabaseURL is the URL the engine's dumper takes. It holds the
	// password: it lives in memory for the run and is never written out.
	DatabaseURL    string
	AppName        string
	AppEnv         string
	FilesystemDisk string
	LaravelVersion string
	// AppKeyProblem says why the .env's APP_KEY cannot decrypt anything; ""
	// when it can.
	AppKeyProblem string
}

// DiscoverLaravel reads the Laravel app at root: its .env, the database it
// names, and the Laravel version composer.lock pins. It refuses what it
// cannot read for certain rather than guess.
func DiscoverLaravel(root string) (*LaravelApp, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", abs)
	}
	if _, err := os.Stat(filepath.Join(abs, "artisan")); err != nil {
		return nil, fmt.Errorf("%s is not a Laravel app: it has no artisan file. Point the surface's root at the app's root", abs)
	}
	raw, err := os.ReadFile(filepath.Join(abs, LaravelEnvFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s has no .env. A Laravel app's backup holds its .env, which has the APP_KEY its encrypted data needs; create it, or back up the database alone as a database surface", abs)
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filepath.Join(abs, LaravelEnvFile), err)
	}
	env, err := ParseDotenv(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(abs, LaravelEnvFile), err)
	}
	app := &LaravelApp{Root: abs}
	app.AppName, _ = env.Get("APP_NAME")
	app.AppEnv, _ = env.Get("APP_ENV")
	if disk, _ := env.Get("FILESYSTEM_DISK"); disk != "" && disk != "local" && disk != "public" {
		app.FilesystemDisk = disk
	}
	key, _ := env.Get("APP_KEY")
	if err := CheckLaravelAppKey(key); err != nil {
		app.AppKeyProblem = err.Error()
	}
	app.Connection, app.DatabaseURL, err = laravelDatabaseURL(env, abs)
	if err != nil {
		return nil, err
	}
	app.LaravelVersion = laravelVersion(abs)
	return app, nil
}

// LaravelConnectionOfURL is the DB_CONNECTION a database URL stands for.
func LaravelConnectionOfURL(u string) string {
	switch SurfaceTypeOfURL(u) {
	case model.SurfaceTypeSQLite:
		return "sqlite"
	case model.SurfaceTypeMySQL:
		if strings.HasPrefix(u, "mariadb:") {
			return "mariadb"
		}
		return "mysql"
	case model.SurfaceTypePostgres:
		if strings.HasPrefix(u, "postgres") {
			return "pgsql"
		}
	}
	return ""
}

// laravelDatabaseURL builds the URL of the database the .env names, the way
// Laravel's own config/database.php reads it: DB_URL first, then
// DB_CONNECTION and the DB_* keys.
func laravelDatabaseURL(env Dotenv, root string) (string, string, error) {
	get := func(k string) (string, error) {
		v, err := env.Get(k)
		if err != nil {
			return "", fmt.Errorf(".env: %w", err)
		}
		return v, nil
	}
	for _, k := range []string{"DB_URL", "DATABASE_URL"} {
		u, err := get(k)
		if err != nil {
			return "", "", err
		}
		if u == "" {
			continue
		}
		scheme, rest, ok := strings.Cut(u, ":")
		if !ok {
			return "", "", fmt.Errorf(".env: %s is not a URL", k)
		}
		switch strings.ToLower(scheme) {
		case "pgsql", "postgres", "postgresql":
			u = "postgres:" + rest
		case "mysql", "mariadb":
		case "sqlite":
			p, err := SQLitePath(u)
			if err != nil {
				return "", "", fmt.Errorf(".env: %s: %w", k, err)
			}
			u = "sqlite://" + p
		case "sqlsrv":
			return "", "", fmt.Errorf(".env: %s names a SQL Server database, which SafeGrd does not back up", k)
		default:
			return "", "", fmt.Errorf(".env: %s has scheme %s; SafeGrd backs up mysql, mariadb, pgsql and sqlite", k, scheme)
		}
		return LaravelConnectionOfURL(u), u, nil
	}
	conn, err := get("DB_CONNECTION")
	if err != nil {
		return "", "", err
	}
	host, _ := get("DB_HOST")
	port, _ := get("DB_PORT")
	db, err := get("DB_DATABASE")
	if err != nil {
		return "", "", err
	}
	user, err := get("DB_USERNAME")
	if err != nil {
		return "", "", err
	}
	pass, err := get("DB_PASSWORD")
	if err != nil {
		return "", "", err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	network := func(scheme, defPort string) (string, error) {
		if db == "" {
			return "", fmt.Errorf(".env sets DB_CONNECTION=%s and no DB_DATABASE", conn)
		}
		if port == "" {
			port = defPort
		}
		if _, err := strconv.Atoi(port); err != nil {
			return "", fmt.Errorf(".env: DB_PORT=%s is not a port", port)
		}
		u := url.URL{Scheme: scheme, Host: host + ":" + port, Path: "/" + db}
		if user != "" {
			u.User = url.UserPassword(user, pass)
		}
		return u.String(), nil
	}
	switch strings.ToLower(conn) {
	case "":
		return "", "", fmt.Errorf(".env sets no DB_CONNECTION. Laravel's default differs by version (mysql before 11, sqlite from 11), so set it, or set database_url on the surface")
	case "mysql", "mariadb":
		if sock, _ := get("DB_SOCKET"); sock != "" {
			return "", "", fmt.Errorf(".env connects through DB_SOCKET (%s); SafeGrd connects over TCP. Set database_url on the surface to mysql://user:password@127.0.0.1:3306/%s", sock, db)
		}
		u, err := network(strings.ToLower(conn), "3306")
		return strings.ToLower(conn), u, err
	case "pgsql":
		u, err := network("postgres", "5432")
		if err != nil {
			return "", "", err
		}
		if mode, _ := get("DB_SSLMODE"); mode != "" {
			u += "?sslmode=" + url.QueryEscape(mode)
		}
		return "pgsql", u, nil
	case "sqlite":
		p := db
		if p == "" {
			p = "database/database.sqlite"
		}
		if p == ":memory:" {
			return "", "", fmt.Errorf(".env sets DB_DATABASE=:memory:, which holds nothing between requests to back up")
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(root, p)
		}
		return "sqlite", "sqlite://" + filepath.Clean(p), nil
	case "sqlsrv":
		return "", "", fmt.Errorf(".env sets DB_CONNECTION=sqlsrv: SafeGrd does not back up SQL Server databases")
	}
	return "", "", fmt.Errorf(".env sets DB_CONNECTION=%s; SafeGrd backs up mysql, mariadb, pgsql and sqlite", conn)
}

// laravelVersion is the laravel/framework version composer.lock pins, or "".
func laravelVersion(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "composer.lock"))
	if err != nil {
		return ""
	}
	var lock struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return ""
	}
	for _, p := range lock.Packages {
		if p.Name == "laravel/framework" {
			return strings.TrimPrefix(p.Version, "v")
		}
	}
	return ""
}

// CheckLaravelAppKey refuses an APP_KEY Laravel's encrypter would refuse:
// AES-256 takes 32 bytes and AES-128 16, given raw or as base64:...
func CheckLaravelAppKey(key string) error {
	if key == "" {
		return errors.New("the .env has no APP_KEY")
	}
	raw := []byte(key)
	if b64, ok := strings.CutPrefix(key, "base64:"); ok {
		dec, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return errors.New("APP_KEY starts with base64: and is not base64")
		}
		raw = dec
	}
	if len(raw) != 32 && len(raw) != 16 {
		return fmt.Errorf("APP_KEY is %d bytes; Laravel's ciphers take 32 (AES-256) or 16 (AES-128)", len(raw))
	}
	return nil
}

// LaravelMigrationNames lists the migrations in dir: each *.php file's name
// without the extension, sorted, as Laravel records them. Subdirectories are
// not read, as `php artisan migrate` does not read them.
func LaravelMigrationNames(dir string) ([]string, error) {
	des, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, de := range des {
		if !de.IsDir() && strings.HasSuffix(de.Name(), ".php") {
			out = append(out, strings.TrimSuffix(de.Name(), ".php"))
		}
	}
	sort.Strings(out)
	return out, nil
}

var laravelTableName = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// LaravelMigrationsRan reads the names of the migrations the database has
// run. A database with no migrations table has run none.
func LaravelMigrationsRan(ctx context.Context, databaseURL, table string) ([]string, bool, error) {
	if !laravelTableName.MatchString(table) {
		return nil, false, fmt.Errorf("migrations table %q is not a plain table name", table)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var names []string
	switch SurfaceTypeOfURL(databaseURL) {
	case model.SurfaceTypePostgres:
		conn, err := pgx.Connect(ctx, databaseURL)
		if err != nil {
			return nil, false, err
		}
		defer conn.Close(context.Background())
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			return nil, false, err
		}
		if !exists {
			return nil, false, nil
		}
		rows, err := conn.Query(ctx, `SELECT migration FROM `+pgx.Identifier{table}.Sanitize())
		if err != nil {
			return nil, false, err
		}
		names, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return nil, false, err
		}
	case model.SurfaceTypeMySQL, model.SurfaceTypeSQLite:
		var db *sql.DB
		var err error
		var existsQ string
		if SurfaceTypeOfURL(databaseURL) == model.SurfaceTypeMySQL {
			db, err = OpenMySQL(databaseURL)
			existsQ = `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?`
		} else {
			var p string
			if p, err = SQLitePath(databaseURL); err == nil {
				db, err = openSQLite(p, true)
			}
			existsQ = `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`
		}
		if err != nil {
			return nil, false, err
		}
		defer db.Close()
		var n int
		if err := db.QueryRowContext(ctx, existsQ, table).Scan(&n); err != nil {
			return nil, false, err
		}
		if n == 0 {
			return nil, false, nil
		}
		rows, err := db.QueryContext(ctx, "SELECT migration FROM "+table)
		if err != nil {
			return nil, false, err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return nil, false, err
			}
			names = append(names, s)
		}
		if err := rows.Err(); err != nil {
			return nil, false, err
		}
	default:
		return nil, false, fmt.Errorf("a Laravel app's database is MySQL, MariaDB, PostgreSQL or SQLite")
	}
	sort.Strings(names)
	return names, true, nil
}

// LaravelAssertions are the drill's checks of a Laravel app beyond its
// database's own: the sealed .env holds a usable APP_KEY, and the dumped
// migrations table agrees with the migration files in the snapshot. env is
// the .env as the snapshot holds it, nil when it holds none; migrations
// are the migration files' names the snapshot holds.
func LaravelAssertions(m *model.LaravelStats, db *DryRestoreResult, env []byte, migrations []string) []model.AssertionResult {
	var out []model.AssertionResult
	switch {
	case env == nil:
		out = append(out, model.AssertionResult{Name: "AppKey", Passed: false, Expected: "files/.env with an APP_KEY", Actual: "no .env in the snapshot",
			Message: "The snapshot holds no .env, so the APP_KEY that decrypts the app's encrypted data is not in it"})
	default:
		parsed, err := ParseDotenv(env)
		key := ""
		if err == nil {
			key, err = parsed.Get("APP_KEY")
		}
		if err == nil {
			err = CheckLaravelAppKey(key)
		}
		if err != nil {
			out = append(out, model.AssertionResult{Name: "AppKey", Passed: false, Expected: "an APP_KEY Laravel's encrypter takes", Actual: err.Error(),
				Message: "The restored app could not decrypt its encrypted columns, cookies or signed URLs: " + err.Error()})
		} else {
			out = append(out, model.AssertionResult{Name: "AppKey", Passed: true, Expected: "an APP_KEY Laravel's encrypter takes", Actual: "present in the sealed .env",
				Message: "The .env in the snapshot holds an APP_KEY of the length its cipher takes"})
		}
	}

	table := LaravelMigrationsTable
	if m != nil && m.MigrationsTable != "" {
		table = m.MigrationsTable
	}
	var rows int64 = -1
	if db != nil {
		for _, t := range db.Tables {
			if t.TableName == table {
				rows = t.RowCount
			}
		}
	}
	pending := 0
	if m != nil {
		pending = len(m.Pending)
	}
	ran := int64(len(migrations) - pending)
	switch {
	case rows < 0 && len(migrations) == 0:
		out = append(out, model.AssertionResult{Name: "Migrations", Passed: true, Expected: "no migrations", Actual: "none in the snapshot",
			Message: "The app has no migration files and its database no migrations table"})
	case rows < 0:
		out = append(out, model.AssertionResult{Name: "Migrations", Passed: false, Expected: fmt.Sprintf("a %s table", table), Actual: "not in the dump",
			Message: fmt.Sprintf("The snapshot holds %d migration files and the dump has no %s table, so a restored app would run every migration again", len(migrations), table)})
	case m != nil && rows != m.MigrationsRan:
		out = append(out, model.AssertionResult{Name: "Migrations", Passed: false, Expected: fmt.Sprintf("%d rows", m.MigrationsRan), Actual: fmt.Sprintf("%d rows", rows),
			Message: fmt.Sprintf("The dumped %s table has %d rows; the backup read %d", table, rows, m.MigrationsRan)})
	case rows < ran:
		out = append(out, model.AssertionResult{Name: "Migrations", Passed: false, Expected: fmt.Sprintf("at least %d rows", ran), Actual: fmt.Sprintf("%d rows", rows),
			Message: fmt.Sprintf("%d migration files had run when the backup was taken and the dumped %s table records %d", ran, table, rows)})
	default:
		msg := fmt.Sprintf("The dumped %s table records %d migrations; the snapshot holds %d migration files", table, rows, len(migrations))
		if pending > 0 {
			msg += fmt.Sprintf(", %d of them not yet run when the backup was taken", pending)
		}
		out = append(out, model.AssertionResult{Name: "Migrations", Passed: true, Expected: fmt.Sprintf("at least %d rows", ran), Actual: fmt.Sprintf("%d rows", rows), Message: msg})
	}
	return out
}

// Dotenv is a parsed .env file.
type Dotenv struct {
	values map[string]string
	// unresolved names, per key, the ${VAR} references that named nothing.
	unresolved map[string]string
}

// Get returns a key's value, "" when it is not set. A value that is the
// word null is unset, as Laravel's env() reads it.
func (d Dotenv) Get(key string) (string, error) {
	if ref, ok := d.unresolved[key]; ok {
		return "", fmt.Errorf("%s refers to ${%s}, which the .env does not set", key, ref)
	}
	v := d.values[key]
	if strings.EqualFold(v, "null") || strings.EqualFold(v, "(null)") {
		return "", nil
	}
	return v, nil
}

var dotenvKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)
var dotenvRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// ParseDotenv reads a .env file as vlucas/phpdotenv, which Laravel uses,
// reads it: KEY=value lines, an optional export, # comments, single quotes
// taken literally, double quotes with escapes and lines that run on, and
// ${KEY} references to keys set above or in this process's environment.
func ParseDotenv(b []byte) (Dotenv, error) {
	d := Dotenv{values: map[string]string{}, unresolved: map[string]string{}}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		key, val, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !dotenvKey.MatchString(key) {
			return d, fmt.Errorf("line %d is not KEY=value", lineNo)
		}
		val = strings.TrimLeft(val, " \t")
		expand := true
		switch {
		case strings.HasPrefix(val, "'"):
			end := strings.Index(val[1:], "'")
			if end < 0 {
				return d, fmt.Errorf("line %d: %s opens a single quote it does not close", lineNo, key)
			}
			val, expand = val[1:1+end], false
		case strings.HasPrefix(val, `"`):
			body := val[1:]
			var out strings.Builder
			closed := false
			for !closed {
				for i := 0; i < len(body); i++ {
					c := body[i]
					if c == '\\' && i+1 < len(body) {
						i++
						switch body[i] {
						case 'n':
							out.WriteByte('\n')
						case 't':
							out.WriteByte('\t')
						case '"', '\\', '$':
							out.WriteByte(body[i])
						default:
							out.WriteByte('\\')
							out.WriteByte(body[i])
						}
						continue
					}
					if c == '"' {
						closed = true
						break
					}
					out.WriteByte(c)
				}
				if closed {
					break
				}
				if !sc.Scan() {
					return d, fmt.Errorf("line %d: %s opens a double quote it does not close", lineNo, key)
				}
				lineNo++
				out.WriteByte('\n')
				body = sc.Text()
			}
			val = out.String()
		default:
			if i := strings.Index(val, " #"); i >= 0 {
				val = val[:i]
			}
			val = strings.TrimSpace(val)
		}
		delete(d.unresolved, key)
		if expand {
			val = dotenvRef.ReplaceAllStringFunc(val, func(ref string) string {
				name := dotenvRef.FindStringSubmatch(ref)[1]
				if v, ok := d.values[name]; ok {
					return v
				}
				if v, ok := os.LookupEnv(name); ok {
					return v
				}
				d.unresolved[key] = name
				return ""
			})
		}
		d.values[key] = val
	}
	if err := sc.Err(); err != nil {
		return d, err
	}
	return d, nil
}
