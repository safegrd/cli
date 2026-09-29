package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A surface that names its credential the old way is refused with what
// replaced it. Ignored as an unknown key, a database surface would have had
// no credential and backed up whatever the host's database_url pointed at.
func TestAReplacedCredentialKeyIsRefusedWithItsReplacement(t *testing.T) {
	for old, want := range map[string]string{
		"credential_held: true":         "credential: {from: safegrd}",
		"database_url_env: APP_DB":      "credential: {from: env, name: VARIABLE}",
		"password_env: MAIL_PASS":       "credential: {from: env, name: VARIABLE}",
		"credential_command: op read x": "credential: {from: command",
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		body := "surfaces:\n  - id: db\n    type: postgres\n    " + old + "\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadCLIConfig(path)
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "no longer read") {
			t.Errorf("%s: %v, want a refusal naming %q", old, err, want)
		}
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "surfaces:\n  - id: db\n    type: postgres\n    credential:\n      from: env\n      name: APP_DB\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadCLIConfig(path)
	if err != nil || len(cfg.Surfaces) != 1 || cfg.Surfaces[0].CredentialFrom() != CredentialFromEnv || cfg.Surfaces[0].Credential.Name != "APP_DB" {
		t.Fatalf("the credential block did not load: %v %+v", err, cfg)
	}
	if len(cfg.UnknownKeys) != 0 {
		t.Errorf("the credential block reads as unknown keys: %v", cfg.UnknownKeys)
	}
}
