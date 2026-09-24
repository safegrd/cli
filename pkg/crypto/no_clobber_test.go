package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Age identity is the only thing that can decrypt a snapshot, and it used
// to be written with a plain os.WriteFile. Anything that generated a keypair
// replaced it silently: `safegrd init --config elsewhere.yaml` passed the
// config-exists guard and clobbered ~/.safegrd/keys/agent.key
// on the way past. Every snapshot already written was then sealed to a
// recipient nothing on the machine held, and the next backup still succeeded.
func TestSavePrivateKeyRefusesToOverwriteAnIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys", "agent.key")

	first, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := SavePrivateKey(first.PrivateKey, path); err != nil {
		t.Fatalf("first save should succeed: %v", err)
	}

	second, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	err = SavePrivateKey(second.PrivateKey, path)
	if err == nil {
		t.Fatal("SavePrivateKey overwrote an existing identity; every snapshot sealed to the " +
			"first key would now be unreadable, with nothing reporting it until a restore failed")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the refusal does not name the file the operator has to look at: %v", err)
	}

	// The bytes on disk are the ones that matter, not the error.
	onDisk, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read back: %v", readErr)
	}
	if strings.TrimSpace(string(onDisk)) != strings.TrimSpace(first.PrivateKey) {
		t.Fatal("the original identity did not survive the refused write")
	}

	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey after the refusal: %v", err)
	}
	if strings.TrimSpace(loaded) != strings.TrimSpace(first.PrivateKey) {
		t.Error("LoadPrivateKey returned something other than the original identity")
	}
}

// Replacing a key stays possible, but only by asking for it by name.
func TestOverwritePrivateKeyReplacesDeliberately(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.key")

	first, _ := GenerateKeyPair()
	if err := SavePrivateKey(first.PrivateKey, path); err != nil {
		t.Fatalf("save: %v", err)
	}
	second, _ := GenerateKeyPair()
	if err := OverwritePrivateKey(second.PrivateKey, path); err != nil {
		t.Fatalf("OverwritePrivateKey: %v", err)
	}
	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if strings.TrimSpace(loaded) != strings.TrimSpace(second.PrivateKey) {
		t.Error("OverwritePrivateKey did not replace the identity")
	}
}

// A refused write must not leave the key world-readable or half-written.
func TestSavePrivateKeyKeepsPermissionsTight(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys", "agent.key")

	kp, _ := GenerateKeyPair()
	if err := SavePrivateKey(kp.PrivateKey, path); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("identity written with mode %o, want 0600", perm)
	}
}
