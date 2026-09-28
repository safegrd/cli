package cli

import (
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// The default local directory is a placeholder when enrollment wrote the
// config itself, and a decision when an operator did.
func TestLocalStorageKind(t *testing.T) {
	local := config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: "/root/.safegrd/storage"}
	for _, tc := range []struct {
		name            string
		st              config.StorageConfig
		created, chosen bool
		want            string
	}{
		{"defaults this enrollment wrote", local, true, false, "none"},
		{"a local directory the operator set up", local, false, false, "local"},
		{"hosted chosen on the command line", config.StorageConfig{Type: config.StorageTypeHosted}, true, true, "hosted"},
		{"hosted in an existing config", config.StorageConfig{Type: config.StorageTypeHosted}, false, false, "hosted"},
		{"a bucket", config.StorageConfig{Type: config.StorageTypeS3, Bucket: "b"}, false, false, "s3"},
		{"s3 with no bucket", config.StorageConfig{Type: config.StorageTypeS3}, false, false, "none"},
	} {
		if got := localStorageKind(tc.st, tc.created, tc.chosen); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}
