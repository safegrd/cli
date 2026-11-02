package cli

import (
	"encoding/json"
	"errors"
	"net/http"
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
	if len(results) < 4 {
		t.Fatalf("validation ran %d checks: %+v", len(results), results)
	}
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
	const route = "/api/v1/nodes/node-7/checks"
	api := newFakeAPI(t, "sg_tok_test", map[string]http.HandlerFunc{"POST " + route: jsonReply(http.StatusOK, `{}`)})

	results := []CheckResult{{Name: "A", Status: "PASS", Message: "ok"}, {Name: "B", Status: "FAIL", Message: "no"}}
	c := config.NewDefaultCLIConfig()
	reportDoctorChecks(c, results, true)
	if n := len(api.Calls(route)); n != 0 {
		t.Fatalf("a host that is not enrolled reported %d times", n)
	}

	c.ServerURL, c.ServerToken, c.NodeID = api.URL(), "sg_tok_test", "node-7"
	out, errOut, _ := captureStdoutErr(t, func() error { reportDoctorChecks(c, results, false); return nil })
	calls := api.Calls(route)
	if len(calls) != 1 {
		t.Fatalf("reported %d times to the node's checks route, want once", len(calls))
	}
	var got model.HostCheckReport
	if err := json.Unmarshal(calls[0].Body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 2 || got.Results[1].Status != "FAIL" || got.Results[1].Message != "no" {
		t.Fatalf("reported %+v, want both results as run", got.Results)
	}
	if !strings.Contains(out, "Reported to "+api.URL()) || errOut != "" {
		t.Errorf("a delivered report: stdout %q, stderr %q", out, errOut)
	}
}

// A report that does not arrive leaves doctor's exit code alone and is said
// on stderr: the console will not show the host as checked.
func TestDoctorSaysWhenItsReportDidNotArrive(t *testing.T) {
	results := []CheckResult{{Name: "A", Status: "PASS", Message: "ok"}}
	refusing := newFakeAPI(t, "sg_tok_test", map[string]http.HandlerFunc{
		"POST /api/v1/nodes/node-7/checks": jsonReply(http.StatusInternalServerError, `{"error":"the database is down"}`)})
	for name, url := range map[string]string{"refused": refusing.URL(), "unreachable": "http://127.0.0.1:1"} {
		t.Run(name, func(t *testing.T) {
			c := config.NewDefaultCLIConfig()
			c.ServerURL, c.ServerToken, c.NodeID = url, "sg_tok_test", "node-7"
			out, errOut, _ := captureStdoutErr(t, func() error { reportDoctorChecks(c, results, false); return nil })
			if !strings.Contains(errOut, "Warning: could not report these checks to "+url) ||
				!strings.Contains(errOut, "will not show this host as checked") {
				t.Errorf("a report that did not arrive was not said on stderr:\n%s", errOut)
			}
			if strings.Contains(out, "Reported to") {
				t.Errorf("stdout claims the report arrived:\n%s", out)
			}
		})
	}
	if n := len(refusing.Calls("/api/v1/nodes/node-7/checks")); n == 0 {
		t.Error("the refusing server was never asked, so the refused case proved nothing")
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
	results := runDoctorChecks("", c)
	if len(results) == 0 {
		t.Fatal("doctor ran no checks")
	}
	for _, r := range results {
		if strings.HasPrefix(r.Name, "Surface") && r.Status == "FAIL" {
			t.Errorf("a bare host failed %q: %s", r.Name, r.Message)
		}
	}
}
