package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/model"
)

// Every way enroll ends leads to backups on a schedule: nothing backs up on
// one until the daemon runs. A host enrolled with nothing to protect was told
// to name it and run doctor, and the installer then suggested a one-off
// backup, so the host stopped at enrollment.
func TestEveryEnrollEndingLeadsToTheDaemon(t *testing.T) {
	for _, tc := range []struct {
		name        string
		hasSurfaces bool
		fromEnv     bool
		laravel     string
		want        []string
	}{
		{"surfaces named", true, false, "", []string{"safegrd doctor"}},
		{"a database from SAFEGRD_DATABASE_URL", true, true, "", []string{"SAFEGRD_DATABASE_URL", "https://safegrd.dev/docs/daemon#environment"}},
		{"a Laravel app here", false, false, "/var/www/app", []string{"safegrd init --laravel /var/www/app"}},
		{"nothing to protect yet", false, false, "", []string{"safegrd claim", "credential: {from: env, name: DATABASE_URL}",
			"safegrd doctor", "safegrd list", "safegrd restore --snapshot"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := enrollNextSteps(tc.hasSurfaces, tc.fromEnv, tc.laravel)
			for _, want := range append(tc.want, "safegrd daemon run --once", "sudo safegrd daemon install",
				"Nothing backs up\n   on a schedule until it runs") {
				if !strings.Contains(got, want) {
					t.Errorf("the steps do not say %q:\n%s", want, got)
				}
			}
			if strings.Contains(got, "backup --database-url") {
				t.Errorf("the steps end on a one-off backup:\n%s", got)
			}
			if strings.Count(got, "Next:") != 1 {
				t.Errorf("want one set of steps:\n%s", got)
			}
		})
	}
}

// enroll prints its steps once, after the config is saved, so they are the
// last thing the installer that ran it shows.
func TestEnrollPrintsItsNextStepsLastAndOnce(t *testing.T) {
	var api *fakeAPI
	api = newFakeAPI(t, "sg_pat_test", map[string]http.HandlerFunc{
		"GET /api/v1/orgs":                jsonReply(http.StatusOK, `[{"id":"org-1","name":"Acme"}]`),
		"GET /api/v1/orgs/org-1/projects": jsonReply(http.StatusOK, `[{"id":"proj-1","name":"Production","slug":"production"}]`),
		"POST /api/v1/nodes/register": func(w http.ResponseWriter, r *http.Request) {
			var req model.NodeRegisterRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ManagedIdentity != "" || req.NodeID == "" {
				http.Error(w, `{"error":"unexpected registration"}`, http.StatusBadRequest)
				return
			}
			// What follows enrolment goes under the node token it mints.
			api.accept("sg_tok_fake_test_token")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(model.NodeRegisterResponse{NodeID: req.NodeID, ProjectID: "proj-1", Token: "sg_tok_fake_test_token"})
		},
	})

	for _, tc := range []struct {
		name, config, last string
		want               []string
	}{
		{"a host with nothing to protect yet", "", "     safegrd restore --snapshot <id> --target env:TARGET_URL",
			[]string{"Next: name what this host protects", "safegrd claim", "safegrd daemon run --once", "sudo safegrd daemon install"}},
		{"a host whose config names a surface", "surfaces:\n  - {id: db, type: postgres, credential: {from: env, name: DATABASE_URL}}\n",
			"     sudo safegrd daemon install", []string{"Next: check every surface opens", "safegrd daemon run --once"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved, savedFile := cfg, cfgFile
			t.Cleanup(func() { cfg, cfgFile = saved, savedFile })
			dir := t.TempDir()
			t.Setenv("HOME", dir)
			t.Setenv("SAFEGRD_SERVER_URL", api.URL())
			t.Setenv("SAFEGRD_DATABASE_URL", "")
			cfgFile = filepath.Join(dir, ".safegrd", "config.yaml")
			if tc.config != "" {
				if err := os.MkdirAll(filepath.Dir(cfgFile), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cfgFile, []byte(tc.config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := newEnrollCmd()
			cmd.SetArgs([]string{"--token", "sg_pat_test", "--node-name", "web-1", "--storage", "local", "--key-custody", "local"})
			out, errOut, err := captureStdoutErr(t, cmd.Execute)
			if err != nil {
				t.Fatalf("enroll: %v\n%s\n%s", err, out, errOut)
			}
			if n := len(api.Calls("/api/v1/nodes/register")); n == 0 {
				t.Fatal("enroll registered no node with the remote server")
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("enroll does not say %q:\n%s", want, out)
				}
			}
			if n := strings.Count(out, "Next:"); n != 1 {
				t.Errorf("enroll printed %d sets of next steps, want one:\n%s", n, out)
			}
			if saved, next := strings.Index(out, "Saved to "), strings.Index(out, "Next:"); saved < 0 || next < saved {
				t.Errorf("the next steps are not after the config is saved:\n%s", out)
			}
			if got := strings.TrimRight(out, "\n"); !strings.HasSuffix(got, tc.last) {
				t.Errorf("enroll does not end with its steps (want the last line %q):\n%s", strings.TrimSpace(tc.last), out)
			}
		})
	}
}
