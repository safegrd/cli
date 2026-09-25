package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIConfigLoadSave(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "safegrd.yaml")

	cfg := &CLIConfig{
		NodeID:      "node-123",
		NodeName:    "prod-db-primary",
		ServerURL:   "http://localhost:8080",
		DatabaseURL: "postgres://user:pass@localhost:5432/testdb",
		Storage: StorageConfig{
			Type:          StorageTypeLocal,
			LocalPath:     filepath.Join(tempDir, "storage"),
			RetentionDays: 14,
			WORMMode:      WORMModeCompliance,
		},
		Encryption: EncryptionConfig{
			PublicKey: "age1testpublickey...",
		},
	}

	if err := SaveCLIConfig(cfg, configPath); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	loaded, err := LoadCLIConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if loaded.NodeID != cfg.NodeID {
		t.Errorf("expected NodeID %s, got %s", cfg.NodeID, loaded.NodeID)
	}
	if loaded.DatabaseURL != cfg.DatabaseURL {
		t.Errorf("expected DatabaseURL %s, got %s", cfg.DatabaseURL, loaded.DatabaseURL)
	}
	if loaded.Storage.RetentionDays != 14 {
		t.Errorf("expected RetentionDays 14, got %d", loaded.Storage.RetentionDays)
	}
}

func TestCLIConfigEnvOverrides(t *testing.T) {
	// 1. Verify default server URL is https://safegrd.dev
	defaultCfg := NewDefaultCLIConfig()
	if defaultCfg.ServerURL != DefaultServerURL {
		t.Errorf("expected default ServerURL %s, got %s", DefaultServerURL, defaultCfg.ServerURL)
	}

	// 2. Verify SAFEGRD_DATABASE_URL and SAFEGRD_SERVER_URL overrides
	os.Setenv("SAFEGRD_DATABASE_URL", "postgres://override:override@localhost:5432/overridedb")
	os.Setenv("SAFEGRD_SERVER_URL", "http://localhost:8080")
	defer func() {
		os.Unsetenv("SAFEGRD_DATABASE_URL")
		os.Unsetenv("SAFEGRD_SERVER_URL")
	}()

	cfg, err := LoadCLIConfig("")
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	if cfg.DatabaseURL != "postgres://override:override@localhost:5432/overridedb" {
		t.Errorf("expected overridden database URL, got %s", cfg.DatabaseURL)
	}
	if cfg.ServerURL != "http://localhost:8080" {
		t.Errorf("expected overridden ServerURL http://localhost:8080, got %s", cfg.ServerURL)
	}
}

func TestCLIConfigPrivateKeyNeverSavedToYAML(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")

	cfg := &CLIConfig{
		NodeID: "node-privkey-test",
		Encryption: EncryptionConfig{
			PublicKey:  "age1testrecipient...",
			PrivateKey: "AGE-SECRET-KEY-1SECRETPLAINTEXTNOTSAVED",
			KeyPath:    filepath.Join(tempDir, "keys", "agent.key"),
		},
	}

	if err := SaveCLIConfig(cfg, configPath); err != nil {
		t.Fatalf("SaveCLIConfig failed: %v", err)
	}

	rawBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed reading saved config: %v", err)
	}

	if strings.Contains(string(rawBytes), "AGE-SECRET-KEY") || strings.Contains(string(rawBytes), "private_key") {
		t.Fatalf("security violation: private key or private_key field written to YAML: %s", string(rawBytes))
	}
}

func TestCLIConfigInlinePrivateKeyMigration(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	targetKeyPath := filepath.Join(tempDir, "keys", "agent.key")

	// Simulate legacy insecure config file containing inline private_key
	legacyYAML := `node_id: node-mig-01
encryption:
  public_key: age1legacyrecipient...
  private_key: AGE-SECRET-KEY-1LEGACYMIGRATEKEY
  key_path: "` + targetKeyPath + `"
`
	if err := os.WriteFile(configPath, []byte(legacyYAML), 0600); err != nil {
		t.Fatalf("failed creating legacy config: %v", err)
	}

	loaded, err := LoadCLIConfig(configPath)
	if err != nil {
		t.Fatalf("LoadCLIConfig failed: %v", err)
	}

	// 1. Assert PrivateKey was resolved in-memory
	if loaded.Encryption.PrivateKey != "AGE-SECRET-KEY-1LEGACYMIGRATEKEY" {
		t.Fatalf("expected private key to be loaded into memory, got %s", loaded.Encryption.PrivateKey)
	}

	// 2. Assert key was extracted to key_path with 0600 permissions
	keyInfo, err := os.Stat(targetKeyPath)
	if err != nil {
		t.Fatalf("expected key file %s to exist: %v", targetKeyPath, err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on migrated key file, got %o", keyInfo.Mode().Perm())
	}
	keyContent, _ := os.ReadFile(targetKeyPath)
	if strings.TrimSpace(string(keyContent)) != "AGE-SECRET-KEY-1LEGACYMIGRATEKEY" {
		t.Fatalf("migrated key content mismatch, got %s", string(keyContent))
	}

	// 3. Assert private_key was stripped from the config file on disk
	migratedRaw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed reading migrated config: %v", err)
	}
	if strings.Contains(string(migratedRaw), "private_key") || strings.Contains(string(migratedRaw), "AGE-SECRET-KEY") {
		t.Fatalf("private key was not stripped from config file: %s", string(migratedRaw))
	}
}

func TestCLIConfigResolvesPrivateKeyFromKeyPath(t *testing.T) {
	tempDir := t.TempDir()
	keyDir := filepath.Join(tempDir, "keys")
	_ = os.MkdirAll(keyDir, 0700)
	keyPath := filepath.Join(keyDir, "agent.key")
	_ = os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-1FROMFILETEST\n"), 0600)

	configPath := filepath.Join(tempDir, "config.yaml")
	cleanYAML := `node_id: node-clean-01
encryption:
  public_key: age1cleanrecipient...
  key_path: "` + keyPath + `"
`
	_ = os.WriteFile(configPath, []byte(cleanYAML), 0600)

	loaded, err := LoadCLIConfig(configPath)
	if err != nil {
		t.Fatalf("LoadCLIConfig failed: %v", err)
	}

	if loaded.Encryption.PrivateKey != "AGE-SECRET-KEY-1FROMFILETEST" {
		t.Fatalf("expected key resolved from key_path, got %s", loaded.Encryption.PrivateKey)
	}
}

func TestCLIConfigInsecurePermissionsRejected(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "insecure_config.yaml")

	// Write config with world-readable permissions (0644)
	if err := os.WriteFile(configPath, []byte("node_id: insecure-node\n"), 0644); err != nil {
		t.Fatalf("failed to write insecure config: %v", err)
	}

	_, err := LoadCLIConfig(configPath)
	if err == nil {
		t.Fatalf("expected LoadCLIConfig to fail on 0644 file permissions, but it succeeded")
	}
	if !strings.Contains(err.Error(), "insecure config file permissions") {
		t.Fatalf("expected insecure permissions error, got: %v", err)
	}
}

func TestCLIConfigBackwardsCompatibilityV1(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "v1_config.yaml")

	v1YAML := `node_id: node-legacy-pg
node_name: Legacy Postgres
database_url: postgres://postgres:secret@localhost:5432/mydb
`
	if err := os.WriteFile(configPath, []byte(v1YAML), 0600); err != nil {
		t.Fatalf("failed writing v1 config: %v", err)
	}

	cfg, err := LoadCLIConfig(configPath)
	if err != nil {
		t.Fatalf("failed loading v1 config: %v", err)
	}

	if len(cfg.Surfaces) != 1 {
		t.Fatalf("expected 1 implicit surface, got %d", len(cfg.Surfaces))
	}
	s := cfg.Surfaces[0]
	if s.ID != "node-legacy-pg" {
		t.Errorf("expected surface ID node-legacy-pg, got %s", s.ID)
	}
	if s.Type != "postgres" {
		t.Errorf("expected surface type postgres, got %s", s.Type)
	}
	if s.DatabaseURL != "postgres://postgres:secret@localhost:5432/mydb" {
		t.Errorf("expected surface database URL populated, got %s", s.DatabaseURL)
	}
}

// TestResolveWORMModeRefusesAnythingUnrecognised asserts that any unrecognized
// or incorrectly-cased worm_mode value is rejected with an error.
// The case sensitivity is intentional to avoid silent mode misconfigurations.
func TestResolveWORMModeRefusesAnythingUnrecognised(t *testing.T) {
	cases := []struct {
		name    string
		in      WORMMode
		want    WORMMode
		wantErr bool
	}{
		{"unset means compliance, the strict default", "", WORMModeCompliance, false},
		{"exact compliance", WORMModeCompliance, WORMModeCompliance, false},
		{"exact governance", WORMModeGovernance, WORMModeGovernance, false},

		// The one an operator actually writes. YAML is habitually lowercase and
		// only a commented example says otherwise.
		{"lowercase governance is refused, not honoured", "governance", "", true},
		{"lowercase compliance is refused", "compliance", "", true},
		{"capitalised governance is refused", "Governance", "", true},

		// "none" is the dangerous one: an operator writing it means "no lock",
		// and silently getting fourteen days of undeletable objects is the
		// opposite of what they asked for.
		{"none is refused rather than read as a lock", "none", "", true},
		{"off is refused", "off", "", true},
		{"a typo is refused", "GOVERANCE", "", true},
		{"whitespace is not trimmed into a match", " COMPLIANCE", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &StorageConfig{WORMMode: tc.in}
			got, err := cfg.ResolveWORMMode()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ResolveWORMMode(%q) returned %q and no error; an unrecognised mode must be refused, "+
						"because both silent choices are wrong and one of them is irreversible", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveWORMMode(%q) errored: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ResolveWORMMode(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestValidateForBackupRejectsUnknownWORMMode proves the refusal reaches the
// CLI before anything is uploaded, not only at provider construction.
func TestValidateForBackupRejectsUnknownWORMMode(t *testing.T) {
	cfg := &CLIConfig{
		DatabaseURL: "postgres://localhost/x",
		Encryption:  EncryptionConfig{PublicKey: "age1example"},
		Storage:     StorageConfig{Type: StorageTypeS3, Bucket: "b", WORMMode: "governance"},
	}
	if err := cfg.ValidateForBackup(); err == nil {
		t.Fatal("ValidateForBackup accepted worm_mode \"governance\"; the backup would then be written under compliance-mode Object Lock the operator did not ask for")
	}
	cfg.Storage.WORMMode = WORMModeGovernance
	if err := cfg.ValidateForBackup(); err != nil {
		t.Fatalf("ValidateForBackup rejected the exact constant: %v", err)
	}
}

// TestSaveCLIConfigNeverWritesThePrivateKey pins the fix for what was, for a
// while, the blocking defect in this repository: `safegrd init` marshalled
// EncryptionConfig with no `yaml:"-"` on PrivateKey and wrote the Age identity
// into ~/.safegrd/config.yaml in plaintext.
//
// The whole product rests on the remote server never holding that key, so a
// test that reads the bytes on disk is worth more than the struct tag it
// checks: the tag can be dropped in a refactor and nothing else would notice.
func TestSaveCLIConfigNeverWritesThePrivateKey(t *testing.T) {
	const identity = "AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST"

	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := &CLIConfig{
		NodeID: "node-1",
		Encryption: EncryptionConfig{
			PublicKey:  "age1example",
			PrivateKey: identity,
			KeyPath:    "~/.safegrd/keys/agent.key",
		},
	}
	if err := SaveCLIConfig(cfg, path); err != nil {
		t.Fatalf("SaveCLIConfig: %v", err)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back the config: %v", err)
	}
	if strings.Contains(string(onDisk), identity) {
		t.Fatalf("the Age private key was written to %s in plaintext; it must live only at key_path", path)
	}
	if strings.Contains(string(onDisk), "private_key") {
		t.Fatalf("config.yaml carries a private_key field; the key must never be marshalled")
	}
	if !strings.Contains(string(onDisk), "key_path") {
		t.Fatal("config.yaml lost key_path, which is how the identity is resolved back")
	}
}
