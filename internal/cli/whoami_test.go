package cli

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// The server's "role" is the account's role on the server, and every customer
// is "member", owners included. whoami printed it as though it were the
// person's role in their organization.
func TestWhoamiDoesNotCallAnOwnerAMember(t *testing.T) {
	role := "member"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"usr-1","email":"leo@example.com","name":"Leo","role":"` + role + `"}`))
	}))
	defer ts.Close()
	saved, savedFile := cfg, cfgFile
	t.Cleanup(func() { cfg, cfgFile = saved, savedFile })
	// Every command loads the config file first (cobra.OnInitialize).
	cfgFile = filepath.Join(t.TempDir(), "config.yaml")
	if err := config.SaveCLIConfig(&config.CLIConfig{ServerURL: ts.URL, ServerToken: "sg_pat_test"}, cfgFile); err != nil {
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
	role = "admin"
	out = whoami()
	if !strings.Contains(out, "Role:   server administrator") {
		t.Errorf("the server administrator's whoami:\n%s", out)
	}
}
