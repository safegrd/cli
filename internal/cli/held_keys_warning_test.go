package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// A host that keeps its own key, in an organization whose other hosts let the
// remote server hold theirs. verify printed "you hold this host's key, and it
// is not on this host" with the key file right there, then passed with it.
// The warning belongs only to a host that has no key of its own.
func TestTheMissingKeyWarningNeedsAMissingKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"org_id":"org-1","identities":[{"public_key":"age1other","identity":"AGE-SECRET-KEY-OTHER"}]}`))
	}))
	defer srv.Close()
	cfg := &config.CLIConfig{ServerURL: srv.URL, NodeID: "node-1", ServerToken: "sg_tok_x",
		Encryption: config.EncryptionConfig{PublicKey: "age1mine"}}

	var keys string
	stderr := captureStderr(t, func() { keys = withManagedIdentities(context.Background(), cfg, "AGE-SECRET-KEY-MINE", false) })
	if strings.Contains(stderr, "not on this host") {
		t.Errorf("warned that the key is missing while it was passed in:\n%s", stderr)
	}
	if !strings.HasPrefix(keys, "AGE-SECRET-KEY-MINE\n") || !strings.Contains(keys, "AGE-SECRET-KEY-OTHER") {
		t.Errorf("key set %q, want the local key first and the held ones after", keys)
	}

	stderr = captureStderr(t, func() { keys = withManagedIdentities(context.Background(), cfg, "", false) })
	if !strings.Contains(stderr, "not on this host") {
		t.Errorf("no warning for a host missing its own key:\n%s", stderr)
	}
}
