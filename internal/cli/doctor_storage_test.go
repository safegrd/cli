package cli

import (
	"path/filepath"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// With no config file, the storage line warns: "Local storage at
// ./safegrd-storage" passed for a default nobody chose.
func TestDoctorWarnsWhenNoStorageIsConfigured(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "config.yaml")
	c := &config.CLIConfig{Storage: config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: "./safegrd-storage"}}
	for _, r := range runValidationChecks(missing, c) {
		if r.Name == "Storage Configuration" {
			if r.Status != "WARN" {
				t.Fatalf("with no config file the storage line is %s: %s", r.Status, r.Message)
			}
			return
		}
	}
	t.Fatal("no Storage Configuration line")
}
