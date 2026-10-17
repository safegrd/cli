package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// The metrics are the daemon's state in Prometheus's text format: one series
// per surface for each value it has, and none for a time never reached.
func TestTheMetricsAreTheDaemonsState(t *testing.T) {
	at := time.Date(2026, 10, 18, 2, 0, 0, 0, time.UTC)
	st := &DaemonState{UpdatedAt: at, Surfaces: map[string]*SurfaceState{
		"db": {SurfaceID: "db", SurfaceType: "postgres", LastAttempt: at, LastSuccess: at, NextDue: at.Add(time.Hour),
			LastDurationMs: 2500, LastSizeBytes: 4096, LastDrillAttempt: at, DrillStatus: model.DrillStatusPassed},
		"docs": {SurfaceID: "docs", SurfaceType: "files", LastAttempt: at, ConsecutiveFailures: 3, DrillStatus: model.DrillStatusFailed},
	}}
	out := string(renderMetrics(st, at))
	for _, want := range []string{
		`safegrd_daemon_info{version="`,
		"safegrd_daemon_state_updated_timestamp_seconds 1792288800\n",
		`safegrd_surface_last_success_timestamp_seconds{surface="db",type="postgres"} 1792288800`,
		`safegrd_surface_consecutive_failures{surface="docs",type="files"} 3`,
		`safegrd_surface_last_backup_duration_seconds{surface="db",type="postgres"} 2.5`,
		`safegrd_surface_last_backup_size_bytes{surface="db",type="postgres"} 4096`,
		`safegrd_surface_drill_passed{surface="db",type="postgres"} 1`,
		`safegrd_surface_drill_passed{surface="docs",type="files"} 0`,
		"# TYPE safegrd_surface_next_due_timestamp_seconds gauge",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the metrics lack %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `last_success_timestamp_seconds{surface="docs"`) {
		t.Errorf("a surface that never succeeded has a success time:\n%s", out)
	}
	if n := strings.Count(out, "# TYPE safegrd_surface_consecutive_failures gauge"); n != 1 {
		t.Errorf("the failures series is declared %d times", n)
	}
}

// A ping goes to the check URL with the suffix and the line as its body.
// The URL is a credential for the check: a failure does not print it.
func TestAPingNamesTheChecksFieldNotItsURL(t *testing.T) {
	var mu sync.Mutex
	var got []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.Method+" "+r.URL.Path+" "+string(b))
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/refused") {
			http.Error(w, "no", http.StatusNotFound)
		}
	}))
	defer ts.Close()
	t.Setenv("SG_PING", ts.URL+"/ping/abc123/")
	if err := ping(context.Background(), "surfaces[db].ping_url", "env:SG_PING", "/start", ""); err != nil {
		t.Fatal(err)
	}
	if err := ping(context.Background(), "surfaces[db].ping_url", ts.URL+"/ping/abc123", "/fail", "Surface db: refused"); err != nil {
		t.Fatal(err)
	}
	if want := []string{"POST /ping/abc123/start ", "POST /ping/abc123/fail Surface db: refused"}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("pings: %q, want %q", got, want)
	}
	err := ping(context.Background(), "surfaces[db].ping_url", ts.URL+"/secret-uuid", "/refused", "")
	if err == nil || !strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "secret-uuid") {
		t.Fatalf("a refused ping: %v", err)
	}
	err = ping(context.Background(), "daemon.ping_url", "http://127.0.0.1:1/secret-uuid", "", "")
	if err == nil || strings.Contains(err.Error(), "secret-uuid") || !strings.Contains(err.Error(), "daemon.ping_url") {
		t.Fatalf("an unreachable check: %v", err)
	}
	if err := ping(context.Background(), "daemon.ping_url", "ftp://example.com/x", "", ""); err == nil {
		t.Fatal("an ftp URL was pinged")
	}
}
