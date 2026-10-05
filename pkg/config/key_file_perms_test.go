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
	keyPath = filepath.Join(dir, "daemon.key")
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

// A config copied from a laptop to a CI runner names a key path the runner
// cannot reach. Backing up needs only the public key, so the config loads
// without the private key instead of failing (/root on GitHub's
// runners).
func TestAKeyFileBehindAnUnreadableDirectoryIsNotAnError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX permissions, as a user root's bypass does not apply to")
	}
	t.Setenv("SAFEGRD_PRIVATE_KEY", "")
	cfgPath, keyPath := writeConfigWithKey(t, 0600)
	locked := filepath.Join(filepath.Dir(keyPath), "locked")
	if err := os.Mkdir(locked, 0700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(locked, "daemon.key")
	if err := os.Rename(keyPath, inside); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("encryption:\n  key_path: "+inside+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0700) })
	cfg, err := LoadCLIConfig(cfgPath)
	if err != nil || cfg.Encryption.PrivateKey != "" {
		t.Fatalf("a key path behind a directory this user cannot enter: %v, key %q", err, cfg.Encryption.PrivateKey)
	}
}
