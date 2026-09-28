package cli

import (
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// A host's own storage, or a surface's, may not be a second origin for a
// bucket set up on the remote server: another bucket, or its own key where
// the server holds the key. A keyless console bucket with the key on the host
// is how that bucket works, and a bucket the hosts registered is theirs.
func TestAHostsOwnStorageIsNotASecondOrigin(t *testing.T) {
	console := func(bucket, endpoint string, held bool) *nodeSinkResponse {
		r := &nodeSinkResponse{ProjectName: "P", Configured: true, Origin: "console", KeyHeld: held}
		r.Sink = &struct {
			Bucket            string `json:"bucket"`
			Region            string `json:"region"`
			Endpoint          string `json:"endpoint"`
			Prefix            string `json:"prefix"`
			ForcePathStyle    bool   `json:"force_path_style"`
			UseWORMObjectLock bool   `json:"use_worm_object_lock"`
			WORMMode          string `json:"worm_mode"`
			RetentionDays     int    `json:"retention_days"`
		}{Bucket: bucket, Endpoint: endpoint}
		return r
	}
	own := func(bucket, endpoint, secret string) *config.StorageConfig {
		return &config.StorageConfig{Type: config.StorageTypeS3, Bucket: bucket, Endpoint: endpoint, SecretAccessKey: secret}
	}
	for _, tc := range []struct {
		name string
		resp *nodeSinkResponse
		st   *config.StorageConfig
		want string
	}{
		{"another bucket", console("b", "https://e", false), own("other", "https://e", "k"), "s3://b"},
		{"same bucket, another endpoint", console("b", "https://e", false), own("b", "https://f", "k"), "s3://b"},
		{"its own key where the server holds one", console("b", "https://e", true), own("b", "https://e", "k"), "holds the key"},
		{"the key for a keyless console bucket", console("b", "https://e/", false), own("b", "https://e", "k"), ""},
		{"the held bucket with no key of its own", console("b", "https://e", true), own("b", "https://e", ""), ""},
		{"local storage", console("b", "https://e", true), &config.StorageConfig{Type: config.StorageTypeLocal}, ""},
		{"a bucket the hosts registered", &nodeSinkResponse{Origin: "cli"}, own("other", "", "k"), ""},
	} {
		err := secondOrigin(tc.resp, tc.st)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want a refusal naming %q", tc.name, err, tc.want)
		}
	}
}
