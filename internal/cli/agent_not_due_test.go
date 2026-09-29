package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// A single pass says why each surface it skips was skipped: `agent run
// --once` used to print its banner and exit, which reads as a run that hung
// or lost its output. And it retries a failed surface at once: the backoff is
// for the resident agent, not for someone who has just fixed the problem.
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
	st := loadAgentState(filepath.Join(stateDir, "agent_state.json"))
	st.Surfaces["moneydb"] = &SurfaceState{SurfaceID: "moneydb", SurfaceType: "postgres", LastAttempt: now.Add(-time.Minute),
		ConsecutiveFailures: 1, LastError: "database URL unresolved for surface moneydb"}
	st.Surfaces["docs"] = &SurfaceState{SurfaceID: "docs", SurfaceType: "files", LastAttempt: now.Add(-time.Hour), LastSuccess: now.Add(-time.Hour)}
	if err := saveAgentState(filepath.Join(stateDir, "agent_state.json"), st); err != nil {
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
	// The resident agent keeps the backoff, and does not repeat why
	// nothing is due on every tick.
	st = loadAgentState(filepath.Join(stateDir, "agent_state.json"))
	st.Surfaces["moneydb"].LastAttempt = time.Now().UTC().Add(-time.Minute)
	if err := saveAgentState(filepath.Join(stateDir, "agent_state.json"), st); err != nil {
		t.Fatal(err)
	}
	if out := run(time.Minute); strings.Contains(out, "is due for backup") || strings.Contains(out, "not due") {
		t.Errorf("the resident agent retried inside its backoff, or said why nothing is due:\n%s", out)
	}
}
