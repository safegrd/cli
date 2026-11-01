package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// A daemon pass asked the remote server for the node's bucket and
// credentials again for each surface, its erasures and its drill, and the
// credentials route allows 30 a minute. Within one pass each is asked once;
// outside one, every lookup asks, as before.
func TestAPassAsksForANodesBucketAndCredentialsOnce(t *testing.T) {
	var sinks, creds atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sink"):
			sinks.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"node_id": "node-1", "configured": true})
		case strings.HasSuffix(r.URL.Path, "/credentials"):
			creds.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"node_id": "node-1", "database_url": "postgres://h/db"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	ask := func(ctx context.Context) {
		t.Helper()
		for i := 0; i < 3; i++ {
			s, err := fetchNodeSink(ctx, srv.URL, "node-1", "tok")
			if err != nil || s.NodeID != "node-1" {
				t.Fatalf("sink: %+v, %v", s, err)
			}
			c, err := fetchNodeCredentials(ctx, srv.URL, "node-1", "tok")
			if err != nil || c.DatabaseURL != "postgres://h/db" {
				t.Fatalf("credentials: %+v, %v", c, err)
			}
			// A caller that changes its copy changes nobody else's.
			c.DatabaseURL = "changed"
		}
	}
	ask(withNodeMemo(context.Background()))
	if sinks.Load() != 1 || creds.Load() != 1 {
		t.Fatalf("one pass asked for the bucket %d times and the credentials %d times, want 1 and 1", sinks.Load(), creds.Load())
	}
	ask(context.Background())
	if sinks.Load() != 4 || creds.Load() != 4 {
		t.Fatalf("without a pass: %d and %d requests in all, want 4 and 4", sinks.Load(), creds.Load())
	}
}
