package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// withTestKey trusts a fresh key for one test and returns its private half.
func withTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := testKey
	testKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { testKey = old })
	return priv
}

// archive writes a release archive holding bin as <dir>/safegrd and returns
// its path and checksums.txt.
func archive(t *testing.T, version string, bin []byte) (string, []byte) {
	t.Helper()
	dir := ArchiveDir(version, "linux", "amd64")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string][]byte{dir + "/README.md": []byte("readme"), dir + "/safegrd": bin} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(body)
	}
	tw.Close()
	gz.Close()
	p := filepath.Join(t.TempDir(), ArchiveName(version, "linux", "amd64"))
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return p, []byte(hex.EncodeToString(sum[:]) + "  " + filepath.Base(p) + "\n")
}

func TestAReleaseSignedWithATrustedKeyVerifiesAndItsBinaryExtracts(t *testing.T) {
	priv := withTestKey(t)
	path, sums := archive(t, "0.0.2", []byte("binary-0.0.2"))
	if err := Verify(sums, Sign(priv, sums), path, filepath.Base(path)); err != nil {
		t.Fatalf("a signed release did not verify: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "safegrd")
	if err := ExtractBinary(path, ArchiveDir("0.0.2", "linux", "amd64"), dest); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "binary-0.0.2" {
		t.Fatalf("extracted %q", b)
	}
}

func TestAReleaseIsRefusedWhenAnythingAboutItIsWrong(t *testing.T) {
	priv := withTestKey(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	path, sums := archive(t, "0.0.2", []byte("binary"))
	name := filepath.Base(path)

	cases := []struct {
		what      string
		sums, sig []byte
		archive   string
		words     string
	}{
		{"signed by another key", sums, Sign(other, sums), path, "not signed by a key this build trusts"},
		{"checksums changed after signing", []byte(strings.Replace(string(sums), "0", "1", 1)), Sign(priv, sums), path, "not signed by a key this build trusts"},
		{"no signature", sums, []byte("\n"), path, "not an Ed25519 signature"},
		{"an archive the checksums do not list", sums, Sign(priv, sums), path + ".other", "does not list"},
	}
	for _, c := range cases {
		n := name
		if strings.HasSuffix(c.archive, ".other") {
			n = name + ".other"
			os.WriteFile(c.archive, []byte("x"), 0o644)
		}
		err := Verify(c.sums, c.sig, c.archive, n)
		if err == nil || !strings.Contains(err.Error(), c.words) {
			t.Errorf("%s: %v, want an error saying %q", c.what, err, c.words)
		}
	}

	// The archive itself changed: the signed checksum no longer matches.
	os.WriteFile(path, []byte("tampered"), 0o644)
	if err := Verify(sums, Sign(priv, sums), path, name); err == nil || !strings.Contains(err.Error(), "lists") {
		t.Errorf("a tampered archive: %v", err)
	}
}

func TestABuildThatTrustsNoKeyChecksNothing(t *testing.T) {
	old := testKey
	testKey = ""
	t.Cleanup(func() { testKey = old })
	keys, err := TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		if err := VerifyChecksums([]byte("x"), []byte("eA==")); err != ErrNoTrustedKey {
			t.Fatalf("with no trusted key: %v, want ErrNoTrustedKey", err)
		}
	}
}

// install.sh checks the same signature with openssl, against its own copy of
// the keys. The two lists are the same keys.
func TestInstallShTrustsTheSameKeysAsTheBinary(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)SAFEGRD_RELEASE_KEYS="\n(.*?)"`).FindSubmatch(b)
	if m == nil {
		t.Fatal("install.sh has no SAFEGRD_RELEASE_KEYS")
	}
	var script, file []string
	for _, l := range strings.Split(string(m[1]), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			script = append(script, l)
		}
	}
	for _, l := range strings.Split(trustedKeysFile, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			file = append(file, l)
		}
	}
	if strings.Join(script, ",") != strings.Join(file, ",") {
		t.Fatalf("install.sh trusts %v, pkg/release/trusted_keys.txt %v", script, file)
	}
	for _, k := range file {
		if _, err := ParsePublicKey(k); err != nil {
			t.Errorf("trusted key %q: %v", k, err)
		}
	}
}
