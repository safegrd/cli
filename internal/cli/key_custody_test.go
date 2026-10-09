package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// nodeServer answers GET /api/v1/nodes/{id} with a node record whose key is
// held by SafeGrd or not.
func nodeServer(t *testing.T, escrowed bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/nodes/node-1" || r.Header.Get("Authorization") != "Bearer tok" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(model.Node{ID: "node-1", KeyEscrowed: escrowed})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func statusConfig(t *testing.T) *config.CLIConfig {
	c := config.NewDefaultCLIConfig()
	c.Encryption.PublicKey = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
	c.Encryption.KeyPath = "/home/op/.safegrd/key.txt"
	c.Storage.Type = config.StorageTypeLocal
	c.Storage.LocalPath = t.TempDir()
	c.Storage.WORMMode = "NONE"
	return c
}

// A backup says the custody mode only when it fetches something from the
// remote server, so a Postgres host with a local credential was never told.
// status and doctor say it on every host.
func TestStatusAndDoctorSayTheKeyCustodyMode(t *testing.T) {
	cases := []struct {
		name     string
		enrolled bool
		escrowed bool
		want     string
	}{
		{"SafeGrd-managed", true, true, "SafeGrd-managed key. SafeGrd keeps your key sealed and releases it only to your enrolled hosts"},
		{"customer-managed, enrolled", true, false, "customer-managed key. Only you can decrypt these backups. Keep a copy of /home/op/.safegrd/key.txt somewhere safe"},
		{"standalone", false, false, "customer-managed key. Only you can decrypt these backups."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := statusConfig(t)
			if tc.enrolled {
				c.ServerURL = nodeServer(t, tc.escrowed).URL
				c.NodeID, c.ServerToken = "node-1", "tok"
			}

			old := cfg
			t.Cleanup(func() { cfg = old })
			cfg = c
			out, _, err := captureStdoutErr(t, func() error {
				cmd := newStatusCmd()
				cmd.SetContext(context.Background())
				return cmd.RunE(cmd, nil)
			})
			if err != nil {
				t.Fatalf("status failed: %v\n%s", err, out)
			}
			if !strings.Contains(out, "Key custody:       "+tc.want) {
				t.Errorf("status does not say %q:\n%s", tc.want, out)
			}

			got := keyCustodyCheck(context.Background(), c)
			if got.Status != "PASS" || !strings.Contains(got.Message, tc.want) {
				t.Errorf("doctor says %s %q, want PASS %q", got.Status, got.Message, tc.want)
			}
		})
	}
}

func TestDoctorWarnsWhenItCannotAskWhoHoldsTheKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := statusConfig(t)
	c.ServerURL, c.NodeID, c.ServerToken = srv.URL, "node-1", "tok"

	got := keyCustodyCheck(context.Background(), c)
	if got.Status != "WARN" || !strings.Contains(got.Message, "HTTP 403") {
		t.Errorf("doctor says %s %q, want a WARN naming HTTP 403", got.Status, got.Message)
	}
}
