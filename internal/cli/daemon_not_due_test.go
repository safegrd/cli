package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// A single pass says why each surface it skips was skipped: `daemon run
// --once` used to print its banner and exit, which reads as a run that hung
// or lost its output. And it retries a failed surface at once: the backoff is
// for the daemon, not for someone who has just fixed the problem.
func TestASinglePassRetriesAFailureAndSaysWhyItSkipsTheRest(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := &config.CLIConfig{
		Storage: config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: filepath.Join(dir, "worm"), RetentionDays: 1},
		Surfaces: []config.SurfaceConfig{
			{ID: "moneydb", Type: "postgres", Schedule: "@daily"},
			{ID: "docs", Type: "files", Schedule: "@daily", Roots: []string{dir}},
		},
	}
	now := time.Now().UTC()
	st := loadDaemonState(filepath.Join(stateDir, "daemon_state.json"))
	st.Surfaces["moneydb"] = &SurfaceState{SurfaceID: "moneydb", SurfaceType: "postgres", LastAttempt: now.Add(-time.Minute),
		ConsecutiveFailures: 1, LastError: "database URL unresolved for surface moneydb"}
	st.Surfaces["docs"] = &SurfaceState{SurfaceID: "docs", SurfaceType: "files", LastAttempt: now.Add(-time.Hour), LastSuccess: now.Add(-time.Hour)}
	if err := saveDaemonState(filepath.Join(stateDir, "daemon_state.json"), st); err != nil {
		t.Fatal(err)
	}

	run := func(tick time.Duration) string {
		orig := os.Stdout
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdout = w
		done := make(chan string, 1)
		go func() {
			var b strings.Builder
			buf := make([]byte, 4096)
			for {
				n, err := r.Read(buf)
				b.Write(buf[:n])
				if err != nil {
					break
				}
			}
			done <- b.String()
		}()
		_ = reconcileSurfaces(context.Background(), c, stateDir, tick, map[string]bool{})
		w.Close()
		os.Stdout = orig
		return <-done
	}

	out := run(0)
	if !strings.Contains(out, "Surface moneydb (postgres) is due for backup") {
		t.Errorf("a single pass did not retry a surface waiting out its backoff:\n%s", out)
	}
	if !strings.Contains(out, "Surface docs (files): not due; the next backup is at") {
		t.Errorf("a surface not yet due was skipped without saying so:\n%s", out)
	}
	// The daemon keeps the backoff, and does not repeat why
	// nothing is due on every tick.
	st = loadDaemonState(filepath.Join(stateDir, "daemon_state.json"))
	st.Surfaces["moneydb"].LastAttempt = time.Now().UTC().Add(-time.Minute)
	if err := saveDaemonState(filepath.Join(stateDir, "daemon_state.json"), st); err != nil {
		t.Fatal(err)
	}
	if out := run(time.Minute); strings.Contains(out, "is due for backup") || strings.Contains(out, "not due") {
		t.Errorf("the daemon retried inside its backoff, or said why nothing is due:\n%s", out)
	}
}

// A surface retired in the console is not backed up by the daemon,
// which says so when it first hears it, not on every tick.
func TestTheResidentDaemonStopsARetiredSurfaceAndSaysSoOnce(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/surfaces") {
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"error":"surface docs was retired in the console on 2026-09-29, so it is not backed up. Remove it from this host's config; to protect it again, give it a new id there"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := &config.CLIConfig{
		ServerURL: ts.URL, ServerToken: "tok", NodeID: "host-1",
		Storage:  config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: filepath.Join(dir, "worm"), RetentionDays: 1},
		Surfaces: []config.SurfaceConfig{{ID: "docs", Type: "files", Schedule: "@daily", Roots: []string{dir}}},
	}
	tick := func() string {
		return captureStderr(t, func() {
			_ = reconcileSurfaces(context.Background(), c, stateDir, time.Minute, map[string]bool{})
		})
	}
	if out := tick(); !strings.Contains(out, "Surface docs: surface docs was retired in the console") {
		t.Errorf("the daemon did not say the surface was retired:\n%s", out)
	}
	if out := tick(); strings.Contains(out, "retired") {
		t.Errorf("the daemon repeats that a surface is retired on every tick:\n%s", out)
	}
	st := loadDaemonState(filepath.Join(stateDir, "daemon_state.json"))
	if s := st.Surfaces["docs"]; s == nil || s.LastSnapshotID != "" || !s.LastAttempt.IsZero() || s.Retired == "" {
		t.Errorf("a retired surface was attempted or not recorded as retired: %+v", s)
	}
}
