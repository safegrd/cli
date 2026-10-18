package cli

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/dump"
)

// initLaravelSurface is the surface `init --laravel` writes: the app at
// root, read again at every backup. dbRef and migrationsTable are kept as
// given, a reference included; they override what the .env names, for an
// app whose connection is set outside its .env.
func initLaravelSurface(root, id, dbRef, migrationsTable string) (config.SurfaceConfig, string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return config.SurfaceConfig{}, "", err
	}
	app, err := dump.DiscoverLaravel(abs)
	if err != nil {
		return config.SurfaceConfig{}, "", fmt.Errorf("%w. Nothing was written", err)
	}
	if id != "" && surfaceIDCleaner.ReplaceAllString(strings.ToLower(id), "-") != id {
		return config.SurfaceConfig{}, "", fmt.Errorf("--surface-id %q: use lower-case letters, digits, '-', '_' and '.'. Nothing was written", id)
	}
	if migrationsTable != "" && !laravelPlainName(migrationsTable) {
		return config.SurfaceConfig{}, "", fmt.Errorf("--migrations-table %q is not a plain table name. Nothing was written", migrationsTable)
	}
	connection, dbURL, from := app.Connection, app.DatabaseURL, "read from "+filepath.Join(abs, dump.LaravelEnvFile)+" at every backup"
	if dbRef != "" {
		resolved, err := resolveConfigSecret("database-url", dbRef)
		switch {
		case err != nil || resolved == "":
			fmt.Fprintf(os.Stderr, "Warning: %s cannot be read now. Set it wherever the backup runs.\n", dbRef)
			connection, dbURL = "", ""
		case dump.LaravelConnectionOfURL(resolved) == "":
			return config.SurfaceConfig{}, "", fmt.Errorf("--database-url must be a MySQL, MariaDB, PostgreSQL or SQLite database. Nothing was written")
		default:
			connection, dbURL = dump.LaravelConnectionOfURL(resolved), resolved
		}
		from = "from " + dbRef
		if !strings.HasPrefix(dbRef, "env:") && !strings.HasPrefix(dbRef, "file:") {
			from = "from --database-url"
		}
	} else if _, _, err := app.Database(); err != nil {
		return config.SurfaceConfig{}, "", fmt.Errorf("%w. Nothing was written", err)
	}

	explicit := id != ""
	if !explicit {
		id = strings.Trim(surfaceIDCleaner.ReplaceAllString(strings.ToLower(app.AppName), "-"), "-.")
	}
	if !explicit && (id == "" || id == "laravel") {
		id = strings.Trim(surfaceIDCleaner.ReplaceAllString(strings.ToLower(filepath.Base(abs)), "-"), "-.")
	}
	if id == "" {
		id = "app"
	}
	name := app.AppName
	if name == "" {
		name = filepath.Base(abs)
	}
	s := config.SurfaceConfig{ID: id, Type: "laravel", Name: name, Roots: []string{abs}, DatabaseURL: dbRef, MigrationsTable: migrationsTable}

	found := fmt.Sprintf("Laravel %s", orUnknown(app.LaravelVersion))
	if connection != "" {
		found += " on " + connection + ", " + laravelDatabaseWords(dbURL)
	}
	return s, found + ", " + from, nil
}

// laravelPlainName is a table name the backup can put in a query as it is.
func laravelPlainName(s string) bool {
	for _, r := range s {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return s != ""
}

// laravelDatabaseWords names a database without its password: "database
// shop on db.internal:3306", or the SQLite file.
func laravelDatabaseWords(u string) string {
	if dump.IsSQLiteURL(u) {
		if p, err := dump.SQLitePath(u); err == nil {
			return "file " + p
		}
		return "a SQLite file"
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return "the database it names"
	}
	db := strings.Trim(parsed.Path, "/")
	if db == "" {
		return "server " + parsed.Host
	}
	return "database " + db + " on " + parsed.Host
}

// mergeLaravelSurface adds s to a config that already exists, leaving its
// key, node and storage as they are. It reports the surface's id in the
// config, and whether it was there already. An id the operator chose is
// refused when another surface has it; one derived from the app gets a
// number.
func mergeLaravelSurface(c *config.CLIConfig, s config.SurfaceConfig, explicitID bool) (string, bool, error) {
	ids := map[string]bool{}
	for _, have := range c.Surfaces {
		if strings.EqualFold(have.Type, "laravel") && len(have.Roots) == 1 && filepath.Clean(have.Roots[0]) == filepath.Clean(s.Roots[0]) {
			if explicitID && have.ID != s.ID {
				return "", false, fmt.Errorf("surface %s already backs up %s. Pass --surface-id %s, or remove it from the config first. Nothing was written", have.ID, s.Roots[0], have.ID)
			}
			return have.ID, true, nil
		}
		ids[have.ID] = true
	}
	if explicitID && ids[s.ID] {
		return "", false, fmt.Errorf("the config already has a surface %s. Choose another --surface-id. Nothing was written", s.ID)
	}
	base := s.ID
	for n := 2; ids[s.ID]; n++ {
		s.ID = fmt.Sprintf("%s-%d", base, n)
	}
	c.Surfaces = append(c.Surfaces, s)
	return s.ID, false, nil
}

// printLaravelSchedule says how to keep the surface backed up and drilled:
// a service, or Laravel's own scheduler for a host where the app's user
// cannot install one. A caller that runs the schedule itself, such as the
// SafeGrd Laravel package, sets SAFEGRD_SCHEDULED_BY and says so in its own
// words; these steps would tell its user to set up a second one.
func printLaravelSchedule(id string, enrolled bool) {
	if os.Getenv("SAFEGRD_SCHEDULED_BY") != "" {
		return
	}
	bin, err := os.Executable()
	if err != nil {
		bin = "safegrd"
	}
	conf := ""
	if cfgFile != "" {
		if abs, err := filepath.Abs(cfgFile); err == nil {
			conf = " --config " + abs
		}
	}
	fmt.Println("Next: check it opens, then take the first backup:")
	fmt.Printf("   safegrd%s doctor\n", conf)
	fmt.Printf("   safegrd%s backup --surface %s\n", conf, id)
	fmt.Println("Then keep it backed up and drilled on its schedule, as a service that starts at boot:")
	if enrolled {
		fmt.Println("   sudo safegrd daemon install (or safegrd daemon restart, when it runs already)")
	} else {
		fmt.Println("   sudo safegrd daemon install")
	}
	fmt.Println("or from Laravel's scheduler, in routes/console.php ($schedule->exec in app/Console/Kernel.php before Laravel 11):")
	fmt.Printf("   Schedule::exec('%s%s daemon run --once --interval 5m')->everyFiveMinutes()->withoutOverlapping();\n", bin, conf)
}

// isLaravelApp reports whether dir has an artisan file and a .env.
func isLaravelApp(dir string) bool {
	if dir == "" {
		return false
	}
	for _, f := range []string{"artisan", dump.LaravelEnvFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			return false
		}
	}
	return true
}
