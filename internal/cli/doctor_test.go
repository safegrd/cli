package cli

import (
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
