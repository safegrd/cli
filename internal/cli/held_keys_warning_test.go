package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/config"
)

// One key per release (M91). On production a host that kept its own key was
// sent every key the organization held on each restore and drill, and warned
// that its key "is not on this host" with the key file in place.
func TestARestoreAsksForTheOneKeyItNeeds(t *testing.T) {
	mine, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var lastQuery map[string][]string
	reply := func(w http.ResponseWriter, r *http.Request) {}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.Query()
		reply(w, r)
	}))
	defer srv.Close()
	cfg := &config.CLIConfig{ServerURL: srv.URL, NodeID: "node-1", ServerToken: "sg_tok_x",
		Encryption: config.EncryptionConfig{PublicKey: mine.Recipient().String(), KeyPath: "/root/.safegrd/keys/daemon.key"}}

	// The host's own key opens it: the server says so and releases nothing.
	reply = func(w http.ResponseWriter, r *http.Request) {
		for _, h := range r.URL.Query()["have"] {
			if h == mine.Recipient().String() {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		t.Errorf("the request did not say which key the host holds: %v", r.URL.Query())
	}
	var keys string
	stderr := captureStderr(t, func() {
		keys = withManagedIdentity(context.Background(), cfg, mine.String(), heldKeyQuery{snapshotID: "snap-1"}, false)
	})
	if keys != mine.String() || stderr != "" {
		t.Errorf("own key opens it: keys %q, stderr %q; want only the local key and no warning", keys, stderr)
	}
	if got := lastQuery["snapshot"]; len(got) != 1 || got[0] != "snap-1" {
		t.Errorf("the request did not name the snapshot: %v", lastQuery)
	}

	// A lost host's snapshot: the one held key comes back beside the local one.
	reply = func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"org_id":"org-1","identities":[{"public_key":"age1lost","identity":"AGE-SECRET-KEY-LOST"}]}`))
	}
	keys = withManagedIdentity(context.Background(), cfg, mine.String(), heldKeyQuery{snapshotID: "snap-2"}, false)
	if keys != mine.String()+"\nAGE-SECRET-KEY-LOST" {
		t.Errorf("key set %q, want the local key then the one held key", keys)
	}

	// No key here and SafeGrd holds none for it: say where the key was looked
	// for and what the server said, instead of "no identity matched" later.
	reply = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"This is sealed to SG:fbd2e622:3cb18453, a key SafeGrd does not hold."}`))
	}
	stderr = captureStderr(t, func() {
		keys = withManagedIdentity(context.Background(), cfg, "", heldKeyQuery{snapshotID: "snap-3"}, false)
	})
	if keys != "" || !strings.Contains(stderr, "/root/.safegrd/keys/daemon.key") || !strings.Contains(stderr, "SG:fbd2e622:3cb18453") {
		t.Errorf("missing key: keys %q, stderr %q; want the path looked in and the key it is sealed to", keys, stderr)
	}
}
