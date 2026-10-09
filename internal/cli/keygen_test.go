package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/crypto"
)

func runKeygen(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newKeygenCmd()
	cmd.SetArgs(args)
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	return out, err
}

// keygen writes an identity at 0600, prints only its recipient, and
// --recipient reads the same recipient back from the file.
func TestKeygenWritesAnIdentityAndPrintsItsRecipient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "prod.key")
	out, err := runKeygen(t, "--out", path)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	identity := crypto.IdentityInFile(data)
	if !strings.HasPrefix(identity, "AGE-SECRET-KEY-1") {
		t.Fatalf("the file holds no age identity: %q", data)
	}
	if strings.Contains(out, "AGE-SECRET-KEY") {
		t.Fatalf("keygen printed the private key:\n%s", out)
	}
	var recipient string
	for _, line := range strings.Split(out, "\n") {
		if r, ok := strings.CutPrefix(line, "Public key:  "); ok {
			recipient = r
		}
	}
	if !strings.HasPrefix(recipient, "age1") {
		t.Fatalf("no recipient in the output:\n%s", out)
	}

	// The printed recipient opens what the identity seals: round-trip a
	// message through both rather than trusting the two strings to agree.
	r, err := crypto.ParseRecipient(recipient)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := crypto.ParseIdentities(identity)
	if err != nil {
		t.Fatal(err)
	}
	if !sealsToIdentity(t, r, ids) {
		t.Fatal("the printed recipient does not match the identity written")
	}

	back, err := runKeygen(t, "--recipient", path)
	if err != nil {
		t.Fatalf("keygen --recipient: %v", err)
	}
	if strings.TrimSpace(back) != recipient {
		t.Fatalf("--recipient = %q, want %q", strings.TrimSpace(back), recipient)
	}
}

// An identity that exists is never replaced: it may be the only key to
// backups already written.
func TestKeygenRefusesToOverwriteAnIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prod.key")
	if _, err := runKeygen(t, "--out", path); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runKeygen(t, "--out", path)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("second keygen: err = %v, want a refusal to overwrite", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the identity changed after a refused keygen")
	}
}

func sealsToIdentity(t *testing.T, r age.Recipient, ids []age.Identity) bool {
	t.Helper()
	var sealed bytes.Buffer
	w, err := age.Encrypt(&sealed, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("canary")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	rd, err := age.Decrypt(&sealed, ids...)
	if err != nil {
		return false
	}
	got, err := io.ReadAll(rd)
	return err == nil && string(got) == "canary"
}
