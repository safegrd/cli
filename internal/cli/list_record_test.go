package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/config"
)

// list reads the server's record of every snapshot in pages of 200. A page
// passed 1 MiB once records named their tables (an organization with 4,165
// snapshots sent pages of up to 1.5 MB), getJSON cut it at 1 MiB, and list
// warned the answer "does not parse" and fell back to reading each
// snapshot's sidecar from storage one at a time.
func TestListReadsARecordPageLargerThanOneMebibyte(t *testing.T) {
	pad := strings.Repeat("t", 8<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/snapshots" {
			http.NotFound(w, r)
			return
		}
		items := make([]string, 200)
		for i := range items {
			items[i] = fmt.Sprintf(`{"snapshot_id":"snap-20261102-000000-%06d","node_id":"node-1","tables_padding":%q}`, i, pad)
		}
		fmt.Fprintf(w, `{"items":[%s],"next_cursor":""}`, strings.Join(items, ","))
	}))
	defer srv.Close()

	saved := cfg
	defer func() { cfg = saved }()
	cfg = &config.CLIConfig{ServerURL: srv.URL, NodeID: "node-1", ServerToken: "sg_tok_x"}

	r, err := recordedSnapshots(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if r.by == nil {
		t.Fatal("the record page over 1 MiB was not read: list falls back to every sidecar")
	}
	if len(r.by) != 200 || r.by["snap-20261102-000000-000199"] == nil {
		t.Fatalf("read %d of 200 records", len(r.by))
	}
}

// An answer past the cap is refused in words that say so, not as JSON that
// "does not parse".
func TestGetJSONSaysWhenAnAnswerIsTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"items":["`))
		w.Write([]byte(strings.Repeat("x", maxGetJSONBytes)))
		w.Write([]byte(`"]}`))
	}))
	defer srv.Close()

	var out struct{}
	_, err := getJSON(context.Background(), &config.CLIConfig{ServerURL: srv.URL, ServerToken: "sg_tok_x"}, "/api/v1/snapshots?limit=200", &out)
	if err == nil || !strings.Contains(err.Error(), "/api/v1/snapshots is larger than 64 MiB") {
		t.Fatalf("got %v, want the answer refused as too large", err)
	}
}
