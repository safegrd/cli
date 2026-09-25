package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeConfigWithKey writes a 0600 config.yaml naming a key file with mode.
func writeConfigWithKey(t *testing.T, mode os.FileMode) (cfgPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	keyPath = filepath.Join(dir, "agent.key")
	if err := os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-1TEST\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, mode); err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("encryption:\n  key_path: "+keyPath+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, keyPath
}

// The private key is held to the same rule as config.yaml: a copy other local
// users can read is refused, not loaded quietly.
func TestAPrivateKeyReadableByOthersIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	t.Setenv("SAFEGRD_PRIVATE_KEY", "")
	for _, mode := range []os.FileMode{0644, 0640, 0604} {
		cfgPath, keyPath := writeConfigWithKey(t, mode)
		_, err := LoadCLIConfig(cfgPath)
		if err == nil {
			t.Fatalf("a %04o key file loaded", mode)
		}
		if !strings.Contains(err.Error(), "chmod 600 "+keyPath) {
			t.Errorf("the refusal does not say how to fix it: %v", err)
		}
	}

	cfgPath, _ := writeConfigWithKey(t, 0600)
	cfg, err := LoadCLIConfig(cfgPath)
	if err != nil {
		t.Fatalf("a 0600 key file was refused: %v", err)
	}
	if cfg.Encryption.PrivateKey != "AGE-SECRET-KEY-1TEST" {
		t.Errorf("key not resolved from key_path: %q", cfg.Encryption.PrivateKey)
	}
}

// A host that only backs up may hold no private key at all, and one given in
// the environment does not need the file.
func TestAMissingOrOverriddenKeyFileIsNotAnError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	t.Setenv("SAFEGRD_PRIVATE_KEY", "")
	cfgPath, keyPath := writeConfigWithKey(t, 0600)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadCLIConfig(cfgPath); err != nil || cfg.Encryption.PrivateKey != "" {
		t.Fatalf("missing key file: %v, key %q", err, cfg.Encryption.PrivateKey)
	}

	cfgPath, _ = writeConfigWithKey(t, 0644)
	t.Setenv("SAFEGRD_PRIVATE_KEY", "AGE-SECRET-KEY-1FROMENV")
	cfg, err := LoadCLIConfig(cfgPath)
	if err != nil || cfg.Encryption.PrivateKey != "AGE-SECRET-KEY-1FROMENV" {
		t.Fatalf("with SAFEGRD_PRIVATE_KEY set: %v, key %q", err, cfg.Encryption.PrivateKey)
	}
}
