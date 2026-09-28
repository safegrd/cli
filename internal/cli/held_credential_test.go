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

// A held credential is used as held, and a surface that also names one on the
// host is refused: a credential has one origin.
func TestAHeldSurfaceCredentialHasOneOrigin(t *testing.T) {
	ctx := context.Background()
	c := &config.CLIConfig{DatabaseURL: "postgres://host-default"}
	s := &config.SurfaceConfig{ID: "app-db", Type: "postgres", CredentialHeld: true, HeldSecret: "postgres://held"}
	if got, err := resolveSurfaceDatabaseURL(ctx, c, s); err != nil || got != "postgres://held" {
		t.Errorf("a held database URL resolved to %q (%v), not the held one", got, err)
	}
	if credentialSourceOf(s) != "held" {
		t.Errorf("a held surface reports its source as %q", credentialSourceOf(s))
	}
	s.DatabaseURLEnv = "APP_DATABASE_URL"
	if _, err := resolveSurfaceDatabaseURL(ctx, c, s); err == nil || !strings.Contains(err.Error(), "one origin") {
		t.Errorf("a surface both held and named on the host was not refused: %v", err)
	}
	m := &config.SurfaceConfig{ID: "support", Type: "email", CredentialHeld: true, HeldSecret: "held-pass"}
	if got, _ := surfaceEmailPassword(ctx, m); got != "held-pass" {
		t.Errorf("a held mailbox password resolved to %q", got)
	}
	host := &config.SurfaceConfig{ID: "db", Type: "mysql", DatabaseURLEnv: "DB_URL"}
	if credentialSourceOf(host) != "host" || credentialSourceOf(&config.SurfaceConfig{Type: "files"}) != "" {
		t.Error("the credential source is not reported as the config says")
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
