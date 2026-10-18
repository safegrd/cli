// Package release checks a published safegrd release before anything runs it:
// the Ed25519 signature over its checksums.txt, the archive against that file,
// and the binary inside the archive.
//
// The keys a build trusts are in trusted_keys.txt, compiled in. install.sh
// carries the same keys (SAFEGRD_RELEASE_KEYS) and a test holds the two equal.
// A build that trusts no key checks a release against its checksums.txt only;
// a build with a key requires every release to be signed with one of them.
package release

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

//go:embed trusted_keys.txt
var trustedKeysFile string

// testKey is one more trusted key, set with -ldflags -X by the end-to-end
// suite's build so a test can sign releases it serves itself. Empty in every
// release build.
var testKey string

// Files a release publishes beside its archives.
const (
	ChecksumsFile = "checksums.txt"
	SignatureFile = "checksums.txt.sig"
)

// ErrNoTrustedKey is returned when this build trusts no key, so no signature
// can be checked.
var ErrNoTrustedKey = errors.New("this build of safegrd trusts no release signing key, so it cannot check a signature")

// Signed reports whether this build requires releases to be signed: it does
// once it trusts a key.
func Signed() bool {
	keys, err := TrustedKeys()
	return err != nil || len(keys) > 0
}

// TrustedKeys returns the public keys this build accepts a release from.
func TrustedKeys() ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	lines := strings.Split(trustedKeysFile, "\n")
	if testKey != "" {
		lines = append(lines, testKey)
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := ParsePublicKey(line)
		if err != nil {
			return nil, fmt.Errorf("trusted release key %q: %w", line, err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// ParsePublicKey reads a key as trusted_keys.txt holds it: the 32 bytes of an
// Ed25519 public key, base64.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%d bytes, not the %d of an Ed25519 public key", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Sign returns the signature file's contents for checksums: the raw Ed25519
// signature, base64, on one line. What `openssl pkeyutl -sign -rawin` writes,
// base64-encoded, is the same.
func Sign(key ed25519.PrivateKey, checksums []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, checksums)) + "\n")
}

// VerifyChecksums checks that sig is a signature over checksums by a key this
// build trusts.
func VerifyChecksums(checksums, sig []byte) error {
	keys, err := TrustedKeys()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return ErrNoTrustedKey
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("%s is not an Ed25519 signature", SignatureFile)
	}
	for _, k := range keys {
		if ed25519.Verify(k, checksums, raw) {
			return nil
		}
	}
	return fmt.Errorf("%s is not signed by a key this build trusts", ChecksumsFile)
}

// ArchiveName is the archive a release publishes for one platform, and
// ArchiveDir the directory the binary sits in inside it.
func ArchiveName(version, goos, goarch string) string {
	return ArchiveDir(version, goos, goarch) + ".tar.gz"
}

func ArchiveDir(version, goos, goarch string) string {
	return fmt.Sprintf("safegrd_%s_%s_%s", strings.TrimPrefix(version, "v"), goos, goarch)
}

// ExpectedSHA256 is the hex SHA-256 checksums lists for name.
func ExpectedSHA256(checksums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(checksums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			if _, err := hex.DecodeString(f[0]); err != nil || len(f[0]) != 64 {
				return "", fmt.Errorf("%s lists %s with %q, not a SHA-256", ChecksumsFile, name, f[0])
			}
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("%s does not list %s", ChecksumsFile, name)
}

// FileSHA256 is the hex SHA-256 of the file at p.
func FileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Verify checks a downloaded release for one platform: the signature over
// checksums when this build trusts a key, and the archive at archivePath
// against checksums.
func Verify(checksums, sig []byte, archivePath, archiveName string) error {
	if Signed() {
		if err := VerifyChecksums(checksums, sig); err != nil {
			return err
		}
	}
	want, err := ExpectedSHA256(checksums, archiveName)
	if err != nil {
		return err
	}
	got, err := FileSHA256(archivePath)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s has SHA-256 %s; %s lists %s", archiveName, got, ChecksumsFile, want)
	}
	return nil
}

// maxBinary bounds what is extracted, so a corrupt archive cannot fill the disk.
const maxBinary = 512 << 20

// ExtractBinary writes the safegrd binary from the archive at archivePath to
// dest, mode 0755. Only <dir>/safegrd is read, where dir is ArchiveDir.
func ExtractBinary(archivePath, dir, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%s is not gzip: %w", path.Base(archivePath), err)
	}
	tr := tar.NewReader(gz)
	want := dir + "/safegrd"
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("%s holds no %s", path.Base(archivePath), want)
		}
		if err != nil {
			return fmt.Errorf("reading %s: %w", path.Base(archivePath), err)
		}
		if path.Clean(h.Name) != want || h.Typeflag != tar.TypeReg {
			continue
		}
		if h.Size > maxBinary {
			return fmt.Errorf("%s in %s is %d bytes, more than any safegrd binary", want, path.Base(archivePath), h.Size)
		}
		tmp := dest + ".tmp"
		out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(tr, maxBinary)); err != nil {
			out.Close()
			os.Remove(tmp)
			return err
		}
		if err := out.Close(); err != nil {
			os.Remove(tmp)
			return err
		}
		return os.Rename(tmp, dest)
	}
}
