package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// A surface whose credential the remote server holds is written into the
// config as held, with no secret and no variable name.
func TestAClaimedSurfaceWithAHeldCredentialIsWrittenAsHeld(t *testing.T) {
	var s claimSurface
	s.Key, s.Name, s.SurfaceType = "app-db", "App DB", "postgres"
	s.Config.CredentialHeld = true
	sc := surfaceConfigFor(s)
	if !sc.CredentialHeld || sc.DatabaseURLEnv != "" || sc.DatabaseURL != "" {
		t.Errorf("a held database credential was written as %+v", sc)
	}
	s.SurfaceType = "email"
	if sc := surfaceConfigFor(s); !sc.CredentialHeld || sc.PasswordEnv != "" {
		t.Errorf("a held mailbox password was written as %+v", sc)
	}
}

// Anything set on the host wins over the held credential, and the held one is
// used only when nothing local provides one.
func TestAHeldSurfaceCredentialIsUsedAfterEveryLocalSource(t *testing.T) {
	ctx := context.Background()
	c := &config.CLIConfig{}
	s := &config.SurfaceConfig{ID: "app-db", Type: "postgres", CredentialHeld: true, HeldSecret: "postgres://held"}
	if got, _ := resolveSurfaceDatabaseURL(ctx, c, s); got != "postgres://held" {
		t.Errorf("with nothing local, the database URL resolved to %q", got)
	}
	t.Setenv("APP_DATABASE_URL", "postgres://local")
	s.DatabaseURLEnv = "APP_DATABASE_URL"
	if got, _ := resolveSurfaceDatabaseURL(ctx, c, s); got != "postgres://local" {
		t.Errorf("a variable set on the host lost to the held credential: %q", got)
	}
	m := &config.SurfaceConfig{ID: "support", Type: "email", CredentialHeld: true, HeldSecret: "held-pass"}
	if got, _ := surfaceEmailPassword(ctx, m); got != "held-pass" {
		t.Errorf("with nothing local, the mailbox password resolved to %q", got)
	}
}

// The fetched credential lives in memory only. Saving the config, which
// several commands do, must not write it: a credential on disk would keep
// working after the remote server withdrew it.
func TestAHeldSurfaceCredentialNeverReachesTheConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &config.CLIConfig{Surfaces: []config.SurfaceConfig{{ID: "app-db", Type: "postgres",
		CredentialHeld: true, HeldSecret: "postgres://app:s3cret@db/app"}}}
	if err := config.SaveCLIConfig(cfg, path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cret") {
		t.Fatalf("the held credential was written to the config file:\n%s", raw)
	}
	if !strings.Contains(string(raw), "credential_held: true") {
		t.Errorf("the config does not say the credential is held:\n%s", raw)
	}
}
