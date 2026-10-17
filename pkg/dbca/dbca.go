// Package dbca is where a database's own certificate authority meets its
// connection URL. A managed database (Aiven, DigitalOcean, Amazon RDS) signs
// its server certificate with a CA of its own, so verifying it takes that CA:
// PostgreSQL names it with sslrootcert, MySQL and MariaDB with ssl-ca, MongoDB
// with tlsCAFile. Each is a path. A host can put the file anywhere, but a
// machine that connects on a customer's behalf has no file of theirs, so the
// certificate travels as PEM and is written to a file here first.
//
// The certificate is not a secret: a server sends it to every client that
// connects. What this package guards against is a URL that asks for a CA and
// for no verification at once, which would leave the person who set the CA
// believing the server was checked when it was not.
package dbca

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// MaxPEMBytes bounds a CA bundle. Amazon RDS's global bundle, the largest a
// provider publishes, was 114 certificates in 171 KB on 2026-10-17.
const MaxPEMBytes = 512 << 10

// Check reads a PEM bundle and returns how many certificates it holds. It
// refuses anything but certificates: a private key pasted with a provider's
// client certificate is the mistake it is there to catch, since the bundle is
// stored and sent as plain text.
func Check(bundle string) (int, error) {
	if len(bundle) > MaxPEMBytes {
		return 0, fmt.Errorf("the CA certificate is %d KB; a bundle larger than %d KB is not a CA certificate", len(bundle)>>10, MaxPEMBytes>>10)
	}
	rest := []byte(strings.TrimSpace(bundle))
	if len(rest) == 0 {
		return 0, errors.New("the CA certificate is empty")
	}
	n := 0
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if n == 0 {
				return 0, errors.New("the CA certificate is not PEM: paste the text that starts with -----BEGIN CERTIFICATE-----")
			}
			if len(strings.TrimSpace(string(rest))) > 0 {
				return 0, fmt.Errorf("the CA certificate has text after certificate %d that is not PEM", n)
			}
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return 0, errors.New("the CA certificate includes a private key. Paste only the CA's certificate, never a key")
		}
		if block.Type != "CERTIFICATE" {
			return 0, fmt.Errorf("the CA certificate holds a %s block; only CERTIFICATE blocks belong in it", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return 0, fmt.Errorf("certificate %d could not be read: %v", n+1, err)
		}
		n++
		rest = []byte(strings.TrimSpace(string(rest)))
	}
	return n, nil
}

// CheckFile is Check on a file a host names.
func CheckFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return Check(string(data))
}

// WriteFile writes a bundle into dir as a 0600 file named by its content, and
// returns the path. Naming it by content means a CA replaced on the remote
// server lands in a new file, not under a path a running process has already
// read and cached.
func WriteFile(dir, bundle string) (string, error) {
	if _, err := Check(bundle); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(bundle))
	path := filepath.Join(dir, "ca-"+hex.EncodeToString(sum[:8])+".pem")
	if existing, err := os.ReadFile(path); err == nil && string(existing) == bundle {
		return path, nil
	}
	tmp, err := os.CreateTemp(dir, ".ca-*")
	if err != nil {
		return "", err
	}
	if _, err := tmp.WriteString(bundle); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return path, nil
}

// Apply writes caFile into a connection URL as the engine's own parameter and
// turns verification on: PostgreSQL gets sslrootcert and sslmode=verify-full
// (verify-ca is kept when the URL says it), MySQL and MariaDB get ssl-ca, which
// verifies the host name too, and MongoDB gets tlsCAFile with tls=true.
//
// It refuses a URL that already turns verification off (sslmode=disable,
// allow or prefer, tls=skip-verify, tlsInsecure) or names another CA file:
// either way the URL and the CA disagree about what is checked, and guessing
// which one was meant is how a connection ends up unverified. A URL for
// another engine is returned unchanged.
func Apply(raw, caFile string) (string, error) {
	if caFile == "" {
		return raw, nil
	}
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "postgres://"), strings.HasPrefix(lower, "postgresql://"):
		return applyPostgres(raw, caFile)
	case strings.HasPrefix(lower, "mysql://"), strings.HasPrefix(lower, "mariadb://"):
		return applyMySQL(raw, caFile)
	case strings.HasPrefix(lower, "mongodb://"), strings.HasPrefix(lower, "mongodb+srv://"):
		return applyMongo(raw, caFile)
	}
	return raw, nil
}

func parse(raw string) (*url.URL, url.Values, error) {
	u, err := url.Parse(raw)
	if err != nil {
		// The parser's error quotes the URL, password and all.
		return nil, nil, errors.New("the connection URL could not be read, so its CA could not be set")
	}
	return u, u.Query(), nil
}

// otherCA refuses a URL that names a CA file of its own, unless it is the
// same file.
func otherCA(q url.Values, key, caFile string) error {
	if have := q.Get(key); have != "" && have != caFile {
		return fmt.Errorf("the connection URL names its own %s; remove it to use the CA certificate set for this surface", key)
	}
	return nil
}

func applyPostgres(raw, caFile string) (string, error) {
	u, q, err := parse(raw)
	if err != nil {
		return "", err
	}
	if err := otherCA(q, "sslrootcert", caFile); err != nil {
		return "", err
	}
	switch mode := strings.ToLower(q.Get("sslmode")); mode {
	case "", "require", "verify-full":
		// require with a root certificate is verify-ca in libpq; the CA was
		// set to check the server, so the host name is checked too.
		q.Set("sslmode", "verify-full")
	case "verify-ca":
	default:
		return "", fmt.Errorf("the connection URL sets sslmode=%s, which does not verify the server; remove it to verify against the CA certificate", mode)
	}
	q.Set("sslrootcert", caFile)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func applyMySQL(raw, caFile string) (string, error) {
	u, q, err := parse(raw)
	if err != nil {
		return "", err
	}
	if err := otherCA(q, "ssl-ca", caFile); err != nil {
		return "", err
	}
	switch t := strings.ToLower(q.Get("tls")); t {
	case "", "true":
	default:
		return "", fmt.Errorf("the connection URL sets tls=%s, which does not verify the server; remove it to verify against the CA certificate", t)
	}
	switch m := strings.ToUpper(q.Get("ssl-mode")); m {
	case "", "REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY":
	default:
		return "", fmt.Errorf("the connection URL sets ssl-mode=%s, which does not verify the server; remove it to verify against the CA certificate", q.Get("ssl-mode"))
	}
	q.Set("ssl-ca", caFile)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func applyMongo(raw, caFile string) (string, error) {
	u, q, err := parse(raw)
	if err != nil {
		return "", err
	}
	if err := otherCA(q, "tlsCAFile", caFile); err != nil {
		return "", err
	}
	if err := otherCA(q, "sslCAFile", caFile); err != nil {
		return "", err
	}
	for _, k := range []string{"tlsInsecure", "tlsAllowInvalidCertificates", "tlsAllowInvalidHostnames", "sslAllowInvalidCertificates", "sslAllowInvalidHostnames"} {
		if strings.EqualFold(q.Get(k), "true") {
			return "", fmt.Errorf("the connection URL sets %s=true, which does not verify the server; remove it to verify against the CA certificate", k)
		}
	}
	for _, k := range []string{"tls", "ssl"} {
		if strings.EqualFold(q.Get(k), "false") {
			return "", fmt.Errorf("the connection URL sets %s=false; remove it to connect over TLS and verify against the CA certificate", k)
		}
	}
	q.Del("ssl")
	q.Set("tls", "true")
	q.Set("tlsCAFile", caFile)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// CAFileOf is the CA file a connection URL names, or "" when it names none.
func CAFileOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	q := u.Query()
	for _, k := range []string{"sslrootcert", "ssl-ca", "tlsCAFile", "sslCAFile"} {
		if v := q.Get(k); v != "" && v != "system" {
			return v
		}
	}
	return ""
}
