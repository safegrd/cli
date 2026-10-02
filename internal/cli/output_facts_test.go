package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
)

// captureStdout runs fn and returns what it wrote to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	defer func() { os.Stdout = orig }()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

// verify printed the first 16 characters of the identity, which are
// "AGE-SECRET-KEY-1" for every key there is. It names the key by the same
// fingerprint enroll prints and the console shows.
func TestVerifyNamesTheKeyByFingerprint(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	got := identityFingerprint(kp.PrivateKey)
	if got != crypto.Fingerprint(kp.PublicKey) {
		t.Errorf("identityFingerprint = %q, want the public key's fingerprint %q", got, crypto.Fingerprint(kp.PublicKey))
	}
	if strings.Contains(got, "AGE-SECRET-KEY") {
		t.Errorf("the fingerprint shows part of the identity: %q", got)
	}
}

// enroll printed the node token in full, which stayed in terminal scrollback
// and, when enrolment ran in CI, in the job log.
func TestEnrollPrintsOnlyTheEndOfTheNodeToken(t *testing.T) {
	tok := "sg_tok_8f3a9c2d7e6b5a4f1029384756abcdef"
	got := maskToken(tok)
	if got != "sg_tok_…cdef" {
		t.Errorf("maskToken = %q", got)
	}
	if strings.Contains(got, "8f3a9c2d") {
		t.Errorf("the masked token still carries its body: %q", got)
	}
	if short := maskToken("sg_tok_abc"); strings.Contains(short, "abc") {
		t.Errorf("a short token is printed whole: %q", short)
	}
}

// `enroll --config ./x.yaml` wrote the key under ~/.safegrd/keys and refused
// when one was already there, so two configs on one machine collided. The key
// and the local storage now go beside the config file.
func TestASetupWithConfigKeepsItsKeyBesideTheConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()

	oldCfg, oldFile := cfg, cfgFile
	t.Cleanup(func() { cfg, cfgFile = oldCfg, oldFile })
	cfg, cfgFile = nil, filepath.Join(dir, "x.yaml")

	if _, _, err := captureStdoutErr(t, func() error {
		_, _, err := ensureLocalSetup("test-host")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(dir, "keys", "daemon.key")
	if cfg.Encryption.KeyPath != want {
		t.Errorf("key_path = %s, want %s", cfg.Encryption.KeyPath, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Errorf("no key beside the config: %v", err)
	}
	if cfg.Storage.LocalPath != filepath.Join(dir, "storage") {
		t.Errorf("local storage = %s, want it beside the config", cfg.Storage.LocalPath)
	}
	if _, err := os.Stat(filepath.Join(home, ".safegrd")); !os.IsNotExist(err) {
		t.Errorf("the setup wrote under $HOME/.safegrd as well (stat: %v)", err)
	}
}

func captureStdoutErr(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()
	var err error
	var out string
	errOut := captureStderr(t, func() {
		out = captureStdout(t, func() { err = fn() })
	})
	return out, errOut, err
}

// `list --json` gave nothing parseable. It now prints one JSON array on stdout
// and nothing else there, so a drill job can pick the newest snapshot.
func TestListJSONIsParseable(t *testing.T) {
	dir := t.TempDir()
	oldCfg, oldFile := cfg, cfgFile
	t.Cleanup(func() { cfg, cfgFile = oldCfg, oldFile })
	// The command reloads the config from cfgFile when it starts, as it does
	// for a customer, so the test writes one.
	c := config.NewDefaultCLIConfig()
	c.ServerURL, c.ServerToken = "", ""
	c.NodeID = "node-json"
	c.Storage.LocalPath = dir
	cfgFile = filepath.Join(t.TempDir(), "config.yaml")
	if err := config.SaveCLIConfig(c, cfgFile); err != nil {
		t.Fatal(err)
	}

	st, err := storage.NewLocalStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.SetNodeID("node-json")
	ctx := context.Background()
	until := time.Now().Add(48 * time.Hour).UTC()
	if _, err := st.UploadSnapshot(ctx, "snap-1", strings.NewReader("ciphertext"), -1, until); err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC)
	if err := st.UploadMetadata(ctx, "snap-1", &model.SnapshotMetadata{
		SnapshotID: "snap-1", NodeID: "node-json", SurfaceType: model.SurfaceTypePostgres,
		Status: model.SnapshotStatusCompleted, CreatedAt: created, WORMMode: "COMPLIANCE",
		WORMRetentionUntil: until, TotalItems: 12, TotalContainers: 2, EncryptedSizeBytes: 10,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UploadSnapshot(ctx, "snap-2", strings.NewReader("ciphertext"), -1, until); err != nil {
		t.Fatal(err)
	}
	// A snapshot whose sidecar is gone.
	if err := os.Remove(filepath.Join(dir, "node-json", "snap-2.meta.json")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	cmd := newListCmd()
	cmd.SetArgs([]string{"--json"})
	out, _, err := captureStdoutErr(t, cmd.Execute)
	if err != nil {
		t.Fatal(err)
	}

	var got []listedSnapshot
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2:\n%s", len(got), out)
	}
	byID := map[string]listedSnapshot{}
	for _, e := range got {
		byID[e.SnapshotID] = e
	}
	one := byID["snap-1"]
	if one.Surface != "postgres" || one.Status != "completed" || one.CreatedAt != "2026-10-01T03:00:00Z" ||
		one.WORMMode != "COMPLIANCE" || one.TotalItems != 12 || one.LockedUntil == "" {
		t.Errorf("snap-1 = %+v", one)
	}
	// A directory on this host is not Object Lock, whatever the sidecar says.
	if one.Locked {
		t.Errorf("a local snapshot is reported locked")
	}
	if byID["snap-2"].MetadataError == "" {
		t.Errorf("a snapshot without a sidecar does not say so: %+v", byID["snap-2"])
	}
}
