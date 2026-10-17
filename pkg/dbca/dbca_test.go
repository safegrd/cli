package dbca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCA(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
}

func TestCheckCountsCertificatesAndRefusesAKey(t *testing.T) {
	cert, key := testCA(t)
	if n, err := Check(cert + "\n" + cert); err != nil || n != 2 {
		t.Fatalf("a bundle of two: %d %v", n, err)
	}
	for name, tc := range map[string]struct{ in, words string }{
		"a key beside it": {cert + key, "private key"},
		"empty":           {"  \n", "empty"},
		"not PEM":         {"hello", "not PEM"},
		"another block":   {"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", "PUBLIC KEY block"},
		"text after":      {cert + "trailing words", "not PEM"},
		"too large":       {strings.Repeat("a", MaxPEMBytes+1), "larger than"},
	} {
		_, err := Check(tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.words) {
			t.Errorf("%s: %v, want an error saying %q", name, err, tc.words)
		}
	}
}

func TestWriteFileNamesTheFileByItsContent(t *testing.T) {
	cert, _ := testCA(t)
	dir := t.TempDir()
	p1, err := WriteFile(dir, cert)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := WriteFile(dir, cert); err != nil || again != p1 {
		t.Fatalf("the same CA twice: %s %v, want %s", again, err, p1)
	}
	other, _ := testCA(t)
	p2, err := WriteFile(dir, other)
	if err != nil || p2 == p1 {
		t.Fatalf("a replaced CA landed at %s (%v), the old path was %s", p2, err, p1)
	}
	info, err := os.Stat(p2)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", info, err)
	}
	if got, _ := os.ReadFile(p2); string(got) != other {
		t.Fatal("the file does not hold the CA")
	}
	if _, err := WriteFile(dir, "nonsense"); err == nil {
		t.Fatal("wrote a file that is not a certificate")
	}
}

func query(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func TestApplyWritesEachEnginesParameter(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	for _, tc := range []struct {
		in   string
		want map[string]string
	}{
		{"postgres://u:p@db.example.com:5432/app", map[string]string{"sslrootcert": ca, "sslmode": "verify-full"}},
		{"postgresql://u:p@db.example.com/app?sslmode=require", map[string]string{"sslrootcert": ca, "sslmode": "verify-full"}},
		{"postgres://u:p@db.example.com/app?sslmode=verify-ca", map[string]string{"sslrootcert": ca, "sslmode": "verify-ca"}},
		{"mysql://u:p@db.example.com:3306/shop", map[string]string{"ssl-ca": ca}},
		{"mysql://u:p@db.example.com:3306/shop?ssl-mode=REQUIRED", map[string]string{"ssl-ca": ca, "ssl-mode": "REQUIRED"}},
		{"mariadb://u:p@db.example.com/shop?tls=true", map[string]string{"ssl-ca": ca, "tls": "true"}},
		{"mongodb://u:p@db.example.com:27017/app?authSource=admin", map[string]string{"tlsCAFile": ca, "tls": "true", "authSource": "admin"}},
		{"mongodb+srv://u:p@cluster.example.com/app?ssl=true", map[string]string{"tlsCAFile": ca, "tls": "true", "ssl": ""}},
	} {
		out, err := Apply(tc.in, ca)
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		q := query(t, out)
		for k, v := range tc.want {
			if q.Get(k) != v {
				t.Errorf("%s: %s=%q, want %q (%s)", tc.in, k, q.Get(k), v, out)
			}
		}
		if u, _ := url.Parse(out); u.User.Username() != "u" {
			t.Errorf("%s: the user was lost: %s", tc.in, out)
		}
	}
}

func TestApplyRefusesAURLThatVerifiesNothing(t *testing.T) {
	ca := "/etc/ca.pem"
	for in, words := range map[string]string{
		"postgres://u:p@h/app?sslmode=disable":              "sslmode=disable",
		"postgres://u:p@h/app?sslmode=prefer":               "sslmode=prefer",
		"postgres://u:p@h/app?sslrootcert=/other.pem":       "its own sslrootcert",
		"mysql://u:p@h/shop?tls=skip-verify":                "tls=skip-verify",
		"mysql://u:p@h/shop?ssl-mode=PREFERRED":             "ssl-mode=PREFERRED",
		"mysql://u:p@h/shop?ssl-ca=/other.pem":              "its own ssl-ca",
		"mongodb://u:p@h/app?tlsInsecure=true":              "tlsInsecure=true",
		"mongodb://u:p@h/app?tlsAllowInvalidHostnames=true": "tlsAllowInvalidHostnames=true",
		"mongodb://u:p@h/app?tls=false":                     "tls=false",
		"mongodb://u:p@h/app?tlsCAFile=/other.pem":          "its own tlsCAFile",
	} {
		_, err := Apply(in, ca)
		if err == nil || !strings.Contains(err.Error(), words) {
			t.Errorf("%s: %v, want an error saying %q", in, err, words)
		}
		if err != nil && strings.Contains(err.Error(), "u:p@") {
			t.Errorf("%s: the error quotes the URL: %v", in, err)
		}
	}
	// The same file the URL already names is not a disagreement.
	if _, err := Apply("mysql://u:p@h/shop?ssl-ca="+ca, ca); err != nil {
		t.Fatalf("the URL's own file, set again: %v", err)
	}
}

func TestApplyLeavesOtherURLsAlone(t *testing.T) {
	for _, in := range []string{"sqlite:///var/app.db", "/var/app.db"} {
		if out, err := Apply(in, "/etc/ca.pem"); err != nil || out != in {
			t.Errorf("%s: %s %v", in, out, err)
		}
	}
	if out, err := Apply("postgres://u:p@h/app", ""); err != nil || out != "postgres://u:p@h/app" {
		t.Errorf("no CA: %s %v", out, err)
	}
}
