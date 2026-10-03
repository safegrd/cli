package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/safegrd/cli/pkg/config"
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
