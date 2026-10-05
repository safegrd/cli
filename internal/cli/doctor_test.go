package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

func TestValidationChecks(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "config.yaml")

	c := config.NewDefaultCLIConfig()
	c.Encryption.PublicKey = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
	c.Storage.Type = config.StorageTypeLocal
	c.Storage.LocalPath = tempDir
	c.Surfaces = []config.SurfaceConfig{
		{
			ID:          "pg-prod",
			Type:        "postgres",
			DatabaseURL: "postgres://localhost:5432/db",
		},
		{
			ID:    "files-docs",
			Type:  "files",
			Roots: []string{tempDir},
		},
	}

	if err := config.SaveCLIConfig(c, cfgPath); err != nil {
		t.Fatalf("failed saving config: %v", err)
	}

	results := runValidationChecks(cfgPath, c)
	for _, r := range results {
		if r.Status == "FAIL" {
			t.Errorf("unexpected check failure: %s: %s", r.Name, r.Message)
		}
	}
}

func TestValidationChecks_MissingPublicKey(t *testing.T) {
	c := config.NewDefaultCLIConfig()
	c.Encryption.PublicKey = "" // Missing

	results := runValidationChecks("", c)
	var foundFail bool
	for _, r := range results {
		if r.Name == "Encryption Public Key" && r.Status == "FAIL" {
			foundFail = true
		}
	}
	if !foundFail {
		t.Errorf("expected FAIL for missing public key")
	}
}

func TestDoctorChecks_LocalWritability(t *testing.T) {
	tempDir := t.TempDir()
	c := config.NewDefaultCLIConfig()
	c.Encryption.PublicKey = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
	c.Storage.Type = config.StorageTypeLocal
	c.Storage.LocalPath = tempDir

	results := runDoctorChecks("", c)
	var localOk bool
	for _, r := range results {
		if r.Name == "Local Storage Writability" && r.Status == "PASS" {
			localOk = true
		}
	}
	if !localOk {
		t.Errorf("expected Local Storage Writability to PASS")
	}
}

// A refused config leaves the defaults in place, and the default local
// storage is ./safegrd-storage. Doctor used to carry on to its storage check
// and create that directory wherever it was run.
func TestDoctorStopsAtARefusedConfig(t *testing.T) {
	saved := cfgLoadErr
	t.Cleanup(func() { cfgLoadErr = saved })
	cfgLoadErr = errors.New("insecure mode 0644")

	c := config.NewDefaultCLIConfig()
	c.Storage.Type = config.StorageTypeLocal
	c.Storage.LocalPath = filepath.Join(t.TempDir(), "would-be-created")

	results := runDoctorChecks(filepath.Join(t.TempDir(), "config.yaml"), c)
	if _, err := os.Stat(c.Storage.LocalPath); err == nil {
		t.Errorf("doctor created %s from a config it refused", c.Storage.LocalPath)
	}
	if last := results[len(results)-1]; last.Name != "Configuration Load" || last.Status != "FAIL" {
		t.Errorf("last check = %s %s, want Configuration Load FAIL", last.Name, last.Status)
	}
}

// On an enrolled host doctor posts its results to the remote server under
// the host's token, so the console shows the host as checked; a host that is
// not enrolled has nowhere to report to.
func TestDoctorReportsItsChecksToTheRemoteServer(t *testing.T) {
	var got model.HostCheckReport
	var path, auth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	results := []CheckResult{{Name: "A", Status: "PASS", Message: "ok"}, {Name: "B", Status: "FAIL", Message: "no"}}
	c := config.NewDefaultCLIConfig()
	reportDoctorChecks(c, results, true)
	if path != "" {
		t.Fatalf("a host that is not enrolled reported to %s", path)
	}

	c.ServerURL, c.ServerToken, c.NodeID = ts.URL, "sg_tok_test", "node-7"
	reportDoctorChecks(c, results, true)
	if path != "/api/v1/nodes/node-7/checks" || auth != "Bearer sg_tok_test" {
		t.Fatalf("reported to %s as %q, want the node's checks route under its token", path, auth)
	}
	if len(got.Results) != 2 || got.Results[1].Status != "FAIL" || got.Results[1].Message != "no" {
		t.Fatalf("reported %+v, want both results as run", got.Results)
	}
}

// A host's own database surface was called by its node id in doctor, its
// repository id in backup and "The database" in the warnings. It has one
// name now, and the id beside it.
func TestTheImplicitSurfaceHasOneName(t *testing.T) {
	s := config.SurfaceConfig{ID: "node-90c34b36", Name: "marco-db", Type: "postgres"}
	if got := surfaceLabel(s); got != "marco-db (node-90c34b36)" {
		t.Errorf("label: %q", got)
	}
	if got := surfaceLabel(config.SurfaceConfig{ID: "app"}); got != "app" {
		t.Errorf("unnamed: %q", got)
	}
	cfg := &config.CLIConfig{Surfaces: []config.SurfaceConfig{s}}
	if got := implicitSurfaceName(cfg); got != "marco-db (node-90c34b36)" {
		t.Errorf("backup name: %q", got)
	}
	cfg.Surfaces[0].Type = "files"
	if got := implicitSurfaceName(cfg); got != "" {
		t.Errorf("a files surface named a database backup: %q", got)
	}
}

// A host enrolled only to restore has no surface. Doctor failed it twice for
// the credential of a database it does not have (a node id alone made an
// implicit surface); it may not fail any surface check on such a host.
func TestDoctorOnABareHostFailsNoSurface(t *testing.T) {
	c := config.NewDefaultCLIConfig()
	c.NodeID, c.NodeName = "node-bare", "bare"
	c.Encryption.PublicKey = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
	c.Storage.Type = config.StorageTypeLocal
	c.Storage.LocalPath = t.TempDir()
	if len(c.Surfaces) != 0 {
		t.Fatalf("fixture has %d surfaces", len(c.Surfaces))
	}
	for _, r := range runDoctorChecks("", c) {
		if strings.HasPrefix(r.Name, "Surface") && r.Status == "FAIL" {
			t.Errorf("a bare host failed %q: %s", r.Name, r.Message)
		}
	}
}
