package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// keep on an incremental snapshot says why it cannot, and what to do
// instead, before it asks for the irreversible --yes. It used to ask for
// --yes first and only then pass on the remote server's 409.
func TestKeepRefusesAnIncrementalSnapshotBeforeAskingToConfirm(t *testing.T) {
	lock := time.Date(2026, 10, 22, 4, 5, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(model.SnapshotMetadata{SnapshotID: "snap-20261007-041025-d732e3",
			Format: model.SnapshotFormatRepo, WORMRetentionUntil: lock})
	}))
	defer srv.Close()
	saved, savedFile := cfg, cfgFile
	t.Cleanup(func() { cfg, cfgFile = saved, savedFile })
	// Every command loads the config file first (cobra.OnInitialize).
	cfgFile = filepath.Join(t.TempDir(), "config.yaml")
	if err := config.SaveCLIConfig(&config.CLIConfig{ServerURL: srv.URL, ServerToken: "sg_tok_x", NodeID: "node-x"}, cfgFile); err != nil {
		t.Fatal(err)
	}

	cmd := newKeepCmd()
	cmd.SetArgs([]string{"--snapshot", "snap-20261007-041025-d732e3", "--until", time.Now().AddDate(0, 2, 0).Format("2006-01-02")})
	err := cmd.Execute()
	if err == nil || strings.Contains(err.Error(), "--yes") || !strings.Contains(err.Error(), "incremental") ||
		!strings.Contains(err.Error(), "2026-10-22") || !strings.Contains(err.Error(), "--format tar") {
		t.Fatalf("keep on an incremental snapshot: %v", err)
	}
}
