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
// doctor says it on every host.
func TestDoctorSaysTheKeyCustodyMode(t *testing.T) {
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
			got := keyCustodyCheck(context.Background(), c)
			if got.Status != "PASS" || !strings.Contains(got.Message, tc.want) {
				t.Errorf("doctor says %s %q, want PASS %q", got.Status, got.Message, tc.want)
			}
		})
	}
}

// What status said and doctor did not, before status folded into it: a
// token the remote server refuses is a failure, not "online", and a newer
// CLI is named.
func TestDoctorFailsARefusedTokenAndNamesAnUpdate(t *testing.T) {
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(refusing.Close)
	c := statusConfig(t)
	c.ServerURL, c.NodeID, c.ServerToken = refusing.URL, "node-1", "tok"
	got := nodeRecordChecks(context.Background(), c)
	if len(got) != 1 || got[0].Status != "FAIL" || !strings.Contains(got[0].Message, "refused this host's token (HTTP 401)") || !strings.Contains(got[0].Fix, "safegrd enroll") {
		t.Errorf("a refused token: %+v", got)
	}

	newer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(model.Node{ID: "node-1", UpgradeAvailable: true, LatestCLIVersion: "9.9.9"})
	}))
	t.Cleanup(newer.Close)
	c.ServerURL = newer.URL
	got = nodeRecordChecks(context.Background(), c)
	if len(got) != 2 || got[1].Name != "CLI Update" || got[1].Status != "WARN" || !strings.Contains(got[1].Message, "v9.9.9 is available") {
		t.Errorf("an update: %+v", got)
	}
}

// A remote server that answers but cannot say (a 500) is a warning: the
// host may be fine. A refused token is the failure above.
func TestDoctorWarnsWhenItCannotAskWhoHoldsTheKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := statusConfig(t)
	c.ServerURL, c.NodeID, c.ServerToken = srv.URL, "node-1", "tok"

	got := keyCustodyCheck(context.Background(), c)
	if got.Status != "WARN" || !strings.Contains(got.Message, "HTTP 500") {
		t.Errorf("doctor says %s %q, want a WARN naming HTTP 500", got.Status, got.Message)
	}
}
