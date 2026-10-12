package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// A host claimed into a project whose bucket was set up on the remote server
// has local storage in its config that it never writes to. The daemon probed
// that directory, said "unreachable between backups (storage: stat …: no such
// file or directory)", and the console marked the surface unreachable while
// every backup succeeded.
func TestProbeSinkLeavesAProjectBucketAlone(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/nodes/node-p/sink" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"node_id":"node-p","configured":true,"origin":"console","key_held":true,"sink":{"bucket":"byo-locked","endpoint":"http://minio:9000"}}`))
	}))
	defer ts.Close()
	missing := filepath.Join(t.TempDir(), "never-made")
	c := &config.CLIConfig{ServerURL: ts.URL, ServerToken: "sg_tok_x", NodeID: "node-p",
		Storage: config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: missing}}
	probed, err := probeSink(context.Background(), c, &config.SurfaceConfig{ID: "ledger"})
	if probed || err != nil {
		t.Fatalf("probed the claim's directory under a project bucket: probed=%v err=%v", probed, err)
	}
}
