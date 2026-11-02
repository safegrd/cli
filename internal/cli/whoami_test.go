package cli

import (
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// The server's "role" is the account's role on the server, and every customer
// is "member", owners included. whoami printed it as though it were the
// person's role in their organization.
func TestWhoamiDoesNotCallAnOwnerAMember(t *testing.T) {
	var mu sync.Mutex
	role := "member"
	api := newFakeAPI(t, "sg_pat_test", map[string]http.HandlerFunc{
		"GET /api/v1/auth/me": func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			_, _ = w.Write([]byte(`{"id":"usr-1","email":"leo@example.com","name":"Leo","role":"` + role + `"}`))
		},
	})
	saved, savedFile := cfg, cfgFile
	t.Cleanup(func() { cfg, cfgFile = saved, savedFile })
	// Every command loads the config file first (cobra.OnInitialize).
	cfgFile = filepath.Join(t.TempDir(), "config.yaml")
	if err := config.SaveCLIConfig(&config.CLIConfig{ServerURL: api.URL(), ServerToken: "sg_pat_test"}, cfgFile); err != nil {
		t.Fatal(err)
	}
	whoami := func() string {
		cmd := newWhoamiCmd()
		cmd.SetArgs([]string{})
		return captureStdout(t, func() {
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
		})
	}
	out := whoami()
	if strings.Contains(out, "Role") || !strings.Contains(out, "leo@example.com") {
		t.Errorf("a customer's whoami:\n%s", out)
	}
	mu.Lock()
	role = "admin"
	mu.Unlock()
	out = whoami()
	if !strings.Contains(out, "Role:   server administrator") {
		t.Errorf("the server administrator's whoami:\n%s", out)
	}
}
