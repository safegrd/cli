package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

func heldTestCA(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "held CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// credentialsServer answers the credentials route with a connection string
// and the CA held beside it.
func credentialsServer(t *testing.T, dbURL, ca string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/credentials") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"node_id": "node-1", "database_url": dbURL, "ca_cert": ca})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func caParam(t *testing.T, raw, key string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}

// A CA the remote server holds beside a credential is written to this
// host's config directory and named in the URL with verification on, for the
// single-database form a hosted job runs and for a surface whose credential
// comes from SafeGrd. A URL that turns verification off is not used: the run
// stops rather than connect unverified. A host's own ca_file wins.
func TestAHeldCAIsWrittenAndVerifiesTheConnection(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ca := heldTestCA(t)

	// The single-database form, as a hosted backup job runs it.
	srv := credentialsServer(t, "postgres://backup:pw@db.example.com:5432/app", ca)
	cfg := &config.CLIConfig{ServerURL: srv.URL, NodeID: "node-1", ServerToken: "sg_tok_x",
		Encryption: config.EncryptionConfig{PublicKey: "age1x"}}
	st := cfg.Storage
	st.Type = config.StorageTypeHosted
	src := resolveRuntimeCredentials(context.Background(), cfg, &st, false)
	if src.CAErr != nil || src.CAFile == "" {
		t.Fatalf("the held CA was not applied: %v (%q)", src.CAErr, src.CAFile)
	}
	if got, err := os.ReadFile(src.CAFile); err != nil || string(got) != ca {
		t.Fatalf("the CA file: %v", err)
	}
	if caParam(t, cfg.DatabaseURL, "sslrootcert") != src.CAFile || caParam(t, cfg.DatabaseURL, "sslmode") != "verify-full" {
		t.Fatalf("the URL does not verify against the CA: %s", cfg.DatabaseURL)
	}

	// A held string that verifies nothing is refused with the CA, not used.
	srv = credentialsServer(t, "postgres://backup:pw@db.example.com:5432/app?sslmode=disable", ca)
	cfg = &config.CLIConfig{ServerURL: srv.URL, NodeID: "node-1", ServerToken: "sg_tok_x", Encryption: config.EncryptionConfig{PublicKey: "age1x"}}
	st = cfg.Storage
	st.Type = config.StorageTypeHosted
	src = resolveRuntimeCredentials(context.Background(), cfg, &st, false)
	if src.CAErr == nil || !strings.Contains(src.CAErr.Error(), "sslmode=disable") {
		t.Fatalf("a URL that verifies nothing beside a CA: %v", src.CAErr)
	}
	if strings.Contains(src.CAErr.Error(), "pw@") {
		t.Fatalf("the error quotes the URL: %v", src.CAErr)
	}

	// A surface whose credential SafeGrd holds: MySQL, through ssl-ca.
	srv = credentialsServer(t, "mysql://backup:pw@db.example.com:3306/shop", ca)
	c := &config.CLIConfig{ServerURL: srv.URL, NodeID: "node-1", ServerToken: "sg_tok_x"}
	s := &config.SurfaceConfig{ID: "shop", Type: "mysql", Credential: fromSafeGrd}
	fetchHeldSurfaceSecret(context.Background(), c, "node-1--shop", s)
	if s.CAFile == "" || s.HeldSecret == "" {
		t.Fatalf("the surface's CA: %q, credential held: %v", s.CAFile, s.HeldSecret != "")
	}
	u, err := resolveSurfaceDatabaseURL(context.Background(), c, s)
	if err != nil || caParam(t, u, "ssl-ca") != s.CAFile {
		t.Fatalf("the surface's URL: %v %s", err, u)
	}
	if w := databaseTLSWarning(u); w != "" {
		t.Errorf("a verified URL is still warned about: %s", w)
	}

	// The host's own ca_file is the one used.
	own := &config.SurfaceConfig{ID: "shop", Type: "mysql", Credential: fromSafeGrd, CAFile: "/etc/ssl/own-ca.pem"}
	fetchHeldSurfaceSecret(context.Background(), c, "node-1--shop", own)
	if own.CAFile != "/etc/ssl/own-ca.pem" {
		t.Errorf("the held CA replaced the host's own: %s", own.CAFile)
	}
}
