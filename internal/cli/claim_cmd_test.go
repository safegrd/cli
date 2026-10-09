package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

func claimed(key, kind string, held bool, env string) claimSurface {
	var s claimSurface
	s.Key, s.Name, s.SurfaceType = key, key, kind
	s.Config.Schedule, s.Config.RetentionDays = "@daily", 14
	s.Config.CredentialHeld, s.Config.CredentialEnv = held, env
	return s
}

// Claiming appends to the config and changes nothing else in it: the
// operator's comments and surfaces stay as written, the previous file is kept
// beside it, and what was written loads.
func TestClaimAppendsToTheConfigAndKeepsTheRest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	orig := `# managed by hand; do not reorder
server:
  url: "https://safegrd.example"
  token: "sg_tok_x"
node:
  id: "node-1"
surfaces:
  # the app's main database
  - id: moneydb
    type: postgres
    credential:
      from: safegrd
`
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	backup, err := appendSurfacesToConfig(path, []claimSurface{
		claimed("otherdb", "postgres", true, ""),
		claimed("ledger", "mysql", false, "LEDGER_DB_URL"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(backup); string(b) != orig {
		t.Errorf("the backup is not the previous config:\n%s", b)
	}
	raw, _ := os.ReadFile(path)
	out := string(raw)
	for _, want := range []string{"# managed by hand; do not reorder", "# the app's main database", "id: moneydb"} {
		if !strings.Contains(out, want) {
			t.Errorf("the config lost %q:\n%s", want, out)
		}
	}
	cfg, err := config.LoadCLIConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Surfaces) != 3 || cfg.Surfaces[0].ID != "moneydb" || cfg.Surfaces[1].ID != "otherdb" || cfg.Surfaces[2].ID != "ledger" {
		t.Fatalf("surfaces after claiming: %+v", cfg.Surfaces)
	}
	if !cfg.Surfaces[1].FromSafeGrd() || cfg.Surfaces[2].CredentialFrom() != "env" || cfg.Surfaces[2].Credential.Name != "LEDGER_DB_URL" {
		t.Errorf("the claimed surfaces' credentials: %+v %+v", cfg.Surfaces[1].Credential, cfg.Surfaces[2].Credential)
	}
	if cfg.ServerURL != "https://safegrd.example" || cfg.NodeID != "node-1" {
		t.Errorf("the rest of the config changed: %+v", cfg)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("the config is %v; it must stay 0600", fi.Mode().Perm())
	}
}

// A config with no surfaces list gets one.
func TestClaimAddsASurfacesListWhenThereIsNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  url: \"https://safegrd.example\"\nsurfaces:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := appendSurfacesToConfig(path, []claimSurface{claimed("docs", "files", false, "")}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadCLIConfig(path)
	if err != nil || len(cfg.Surfaces) != 1 || cfg.Surfaces[0].ID != "docs" {
		t.Fatalf("%v %+v", err, cfg)
	}
}

// A result that would not load is not left behind: the previous config is put back.
func TestClaimPutsThePreviousConfigBackWhenTheResultDoesNotLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	orig := "server:\n  url: \"https://safegrd.example\"\nsurfaces:\n  - id: a\n    type: postgres\n    credential_held: true\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := appendSurfacesToConfig(path, []claimSurface{claimed("b", "files", false, "")}); err == nil || !strings.Contains(err.Error(), "put back") {
		t.Fatalf("a config that does not load after claiming: %v", err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != orig {
		t.Errorf("the previous config was not put back:\n%s", raw)
	}
}

// The backup type chosen in the console is written into the config as the
// surface's format, for the surfaces that have both; a MySQL surface gets
// none, whatever the claim says.
func TestAClaimedSurfaceKeepsTheBackupTypeChosenInTheConsole(t *testing.T) {
	for _, c := range []struct{ kind, format, want string }{
		{"sqlite", "tar", "tar"}, {"sqlite", "repo", "repo"}, {"postgres", "tar", "tar"},
		{"files", "repo", "repo"}, {"postgres", "", ""}, {"mysql", "repo", ""},
	} {
		var s claimSurface
		s.Key, s.SurfaceType = "s", c.kind
		s.Config.Path, s.Config.Format = "/var/lib/app.db", c.format
		if got := surfaceConfigFor(s).Format; got != c.want {
			t.Errorf("a %s surface claimed with format %q is written with %q, want %q", c.kind, c.format, got, c.want)
		}
	}
}
