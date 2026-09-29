package crypto

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
)

// A snapshot must open with the standard tools alone, `age -d | zstd -d`, as
// the recovery docs promise: Age on the outside, zstd inside, nothing else.
// This opens EncryptStream's output with the two libraries directly rather
// than through DecryptStream.
func TestASnapshotOpensWithAgeThenZstd(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("a tar archive, in practice\n"), 1000)
	var sealed bytes.Buffer
	if _, err := EncryptStream(bytes.NewReader(payload), &sealed, kp.PublicKey); err != nil {
		t.Fatal(err)
	}

	id, err := age.ParseX25519Identity(kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := age.Decrypt(&sealed, id)
	if err != nil {
		t.Fatalf("age -d: %v", err)
	}
	zr, err := zstd.NewReader(decrypted)
	if err != nil {
		t.Fatalf("zstd -d: %v", err)
	}
	defer zr.Close()
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("zstd -d: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("age -d | zstd -d gave %d bytes, want the %d that went in", len(got), len(payload))
	}
}

// An identity file from age-keygen carries comment lines above the key; one
// written by SafeGrd holds the key alone. Both load.
func TestAnAgeKeygenIdentityFileLoads(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"age-keygen": "# created: 2026-09-29T11:14:16+05:30\n# public key: " + kp.PublicKey + "\n" + kp.PrivateKey + "\n",
		"safegrd":    kp.PrivateKey + "\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadPrivateKey(path)
		if err != nil || got != kp.PrivateKey {
			t.Errorf("%s file: got %q, %v", name, got, err)
		}
	}
}
