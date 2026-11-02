package cli

import (
	"context"
	"net/http"
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
	forgetWhatTheDaemonSaid(t)
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	statePath := filepath.Join(stateDir, "daemon_state.json")
	if err := os.MkdirAll(filepath.Join(stateDir, "locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := &config.CLIConfig{
		Storage: config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: filepath.Join(dir, "worm"), RetentionDays: 1},
		Surfaces: []config.SurfaceConfig{
			{ID: "moneydb", Type: "postgres", Schedule: "@daily"},
			{ID: "docs", Type: "files", Format: "tar", Schedule: "@daily", Roots: []string{dir}},
		},
	}
	now := time.Now().UTC()
	st := loadDaemonState(statePath)
	st.Surfaces["moneydb"] = &SurfaceState{SurfaceID: "moneydb", SurfaceType: "postgres", LastAttempt: now.Add(-time.Minute),
		ConsecutiveFailures: 1, LastError: "database URL unresolved for surface moneydb"}
	st.Surfaces["docs"] = &SurfaceState{SurfaceID: "docs", SurfaceType: "files", LastAttempt: now.Add(-time.Hour), LastSuccess: now.Add(-time.Hour)}
	if err := saveDaemonState(statePath, st); err != nil {
		t.Fatal(err)
	}

	run := func(tick time.Duration) (string, error) {
		var err error
		out := captureStdout(t, func() {
			err = reconcileSurfaces(context.Background(), c, stateDir, tick, map[string]bool{})
		})
		return out, err
	}

	// moneydb has no database URL, so its retry fails and the pass says so.
	out, err := run(0)
	if err == nil {
		t.Errorf("a pass whose retry failed returned no error:\n%s", out)
	}
	if !strings.Contains(out, "Surface moneydb (postgres) is due for backup") {
		t.Errorf("a single pass did not retry a surface waiting out its backoff:\n%s", out)
	}
	if !strings.Contains(out, "Surface docs (files): not due. The next backup is at") {
		t.Errorf("a surface not yet due was skipped without saying so:\n%s", out)
	}
	if got := loadDaemonState(statePath).Surfaces["moneydb"].ConsecutiveFailures; got != 2 {
		t.Errorf("the retry was not recorded as the second failure: %d failures", got)
	}

	// The daemon keeps the backoff, and does not repeat why nothing is due
	// on every tick.
	st = loadDaemonState(statePath)
	attempted := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	st.Surfaces["moneydb"].LastAttempt = attempted
	if err := saveDaemonState(statePath, st); err != nil {
		t.Fatal(err)
	}
	out, err = run(time.Minute)
	if err != nil {
		t.Errorf("a tick with nothing due failed: %v\n%s", err, out)
	}
	if strings.Contains(out, "is due for backup") || strings.Contains(out, "not due") {
		t.Errorf("the daemon retried inside its backoff, or said why nothing is due:\n%s", out)
	}
	after := loadDaemonState(statePath).Surfaces["moneydb"]
	if !after.LastAttempt.Equal(attempted) || after.ConsecutiveFailures != 2 {
		t.Errorf("the daemon attempted moneydb inside its backoff: last attempt %s (was %s), %d failures",
			after.LastAttempt, attempted, after.ConsecutiveFailures)
	}
}

// A surface retired in the console is not backed up by the daemon,
// which says so when it first hears it, not on every tick.
func TestTheResidentDaemonStopsARetiredSurfaceAndSaysSoOnce(t *testing.T) {
	forgetWhatTheDaemonSaid(t)
	api := newFakeAPI(t, "tok", map[string]http.HandlerFunc{
		"POST /api/v1/nodes/host-1/surfaces": jsonReply(http.StatusGone,
			`{"error":"surface docs was retired in the console on 2026-09-29, so it is not backed up. Remove it from this host's config; to protect it again, give it a new id there"}`),
	})
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := &config.CLIConfig{
		ServerURL: api.URL(), ServerToken: "tok", NodeID: "host-1",
		Storage:  config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: filepath.Join(dir, "worm"), RetentionDays: 1},
		Surfaces: []config.SurfaceConfig{{ID: "docs", Type: "files", Format: "tar", Schedule: "@daily", Roots: []string{dir}}},
	}
	tick := func() string {
		return captureStderr(t, func() {
			// Every tick of a retired surface ends in an error; what it
			// prints is the subject here.
			_ = reconcileSurfaces(context.Background(), c, stateDir, time.Minute, map[string]bool{})
		})
	}
	if out := tick(); !strings.Contains(out, "Surface docs: surface docs was retired in the console") {
		t.Errorf("the daemon did not say the surface was retired:\n%s", out)
	}
	if out := tick(); strings.Contains(out, "retired") {
		t.Errorf("the daemon repeats that a surface is retired on every tick:\n%s", out)
	}
	if n := len(api.Calls("/api/v1/nodes/host-1/surfaces")); n != 2 {
		t.Errorf("the surface was registered %d times over two ticks, want 2", n)
	}
	st := loadDaemonState(filepath.Join(stateDir, "daemon_state.json"))
	if s := st.Surfaces["docs"]; s == nil || s.LastSnapshotID != "" || !s.LastAttempt.IsZero() || s.Retired == "" {
		t.Errorf("a retired surface was attempted or not recorded as retired: %+v", s)
	}
}
