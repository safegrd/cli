package cli

import (
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// The config's own database (here from the environment, as enroll suggests)
// is backed up by `backup`, by guard and by the daemon. All three must write
// one repository: `backup` named it after the URL and guard after the host,
// so one database had two histories and two full uploads.
func TestTheConfigsOwnDatabaseIsOneRepository(t *testing.T) {
	url := "postgres://postgres:pw@db.example.com:5432/shop?sslmode=require"
	c := &config.CLIConfig{NodeID: "node-94314597", DatabaseURL: url,
		Surfaces: []config.SurfaceConfig{{ID: "node-94314597", Type: "postgres", DatabaseURL: url}}}

	// backup has resolved the URL and dropped what it does not pass on.
	c.DatabaseURL = "postgres://postgres:pw@db.example.com:5432/shop"
	if got := adhocDatabaseSurfaceID(c); got != "node-94314597" {
		t.Fatalf("backup of the config's database writes repository %q; guard and the daemon write node-94314597", got)
	}

	// A different database named with --database-url keeps its own history.
	c.DatabaseURL = "postgres://postgres:pw@db.example.com:5432/other"
	if got := adhocDatabaseSurfaceID(c); got != repoDatabaseSurfaceID(c.DatabaseURL) {
		t.Fatalf("another database was written to %q", got)
	}

	// A configured surface that is not the implicit one is never borrowed.
	c.Surfaces[0].ID = "prod-db"
	c.DatabaseURL = url
	if got := adhocDatabaseSurfaceID(c); got != repoDatabaseSurfaceID(url) {
		t.Fatalf("a named surface's repository was borrowed: %q", got)
	}
}
