package cli

import (
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// A daemon email surface behind a private CA names the bundle in its own
// config; before ca_file only a one-off backup could trust one.
func TestADaemonEmailSurfaceTrustsItsOwnCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	caFile := filepath.Join(t.TempDir(), "mail-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)

	t.Setenv("SAFEGRD_EMAIL_CA_FILE", "/nonexistent/host-wide.pem")
	s := &config.SurfaceConfig{ID: "mail", Type: "email", CAFile: caFile}
	if got := emailCAFileFor(s); got != caFile {
		t.Fatalf("the surface's ca_file lost to the environment: %q", got)
	}
	dial := func(caFile string) error {
		cfg, err := emailTLSConfig("example.com", caFile)
		if err != nil {
			return err
		}
		conn, err := tls.Dial("tcp", u.Host, cfg)
		if err == nil {
			conn.Close()
		}
		return err
	}
	if err := dial(emailCAFileFor(s)); err != nil {
		t.Errorf("a mail server signed by the surface's CA did not verify: %v", err)
	}
	if err := dial(""); err == nil {
		t.Error("a private CA verified with no ca_file: the system roots alone must refuse it")
	}

	s.CAFile = ""
	if got := emailCAFileFor(s); got != "/nonexistent/host-wide.pem" {
		t.Errorf("with no ca_file the surface did not fall back to $SAFEGRD_EMAIL_CA_FILE: %q", got)
	}
}
