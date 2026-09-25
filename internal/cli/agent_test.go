package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// A schedule below the floor runs at the floor, never at its own cadence: a
// "30m" surface backed up 40 minutes ago is not due. This test used to assert
// that "30m" meant thirty minutes, which under Object Lock is 48 undeletable
// objects a day.
func TestIsSurfaceDueNeverRunsBelowTheFloor(t *testing.T) {
	now := time.Now().UTC()
	surf := &config.SurfaceConfig{ID: "pg-floor", Type: "postgres", Schedule: "30m"}
	st := &SurfaceState{SurfaceID: surf.ID, LastSuccess: now.Add(-40 * time.Minute)}
	if due, next := isSurfaceDue(surf, st, now); due || !next.Equal(st.LastSuccess.Add(time.Hour)) {
		t.Errorf("a 30m schedule 40 minutes after a success: due=%t next=%v, want not due until the 1h floor", due, next)
	}
}

func TestEffectiveScheduleInheritsTheDefaults(t *testing.T) {
	c := &config.CLIConfig{Defaults: config.DefaultsConfig{Schedule: "@hourly"}}
	if got := effectiveSchedule(c, config.SurfaceConfig{ID: "a"}); got != "@hourly" {
		t.Errorf("a surface with no schedule got %q, want the defaults' @hourly", got)
	}
	if got := effectiveSchedule(c, config.SurfaceConfig{ID: "b", Schedule: "6h"}); got != "6h" {
		t.Errorf("a surface's own schedule was overridden: got %q", got)
	}
}

func TestIsSurfaceDue(t *testing.T) {
	now := time.Now().UTC()
	surf := &config.SurfaceConfig{
		ID:       "pg-due-test",
		Type:     "postgres",
		Schedule: "@hourly",
	}

	// 1. Never backed up -> Due immediately
	st1 := &SurfaceState{
		SurfaceID: surf.ID,
	}
	due, _ := isSurfaceDue(surf, st1, now)
	if !due {
		t.Errorf("expected surface never backed up to be due immediately")
	}

	// 2. Backed up 10 minutes ago -> Not due
	st2 := &SurfaceState{
		SurfaceID:   surf.ID,
		LastSuccess: now.Add(-10 * time.Minute),
	}
	due, nextDue := isSurfaceDue(surf, st2, now)
	if due {
		t.Errorf("expected surface backed up 10m ago to NOT be due for @hourly")
	}
	if nextDue.Before(now) {
		t.Errorf("expected nextDue in future, got %v", nextDue)
	}

	// 3. Backed up 2 hours ago -> Due now
	st3 := &SurfaceState{
		SurfaceID:   surf.ID,
		LastSuccess: now.Add(-2 * time.Hour),
	}
	due, _ = isSurfaceDue(surf, st3, now)
	if !due {
		t.Errorf("expected surface backed up 2h ago to be due for @hourly")
	}

	// 4. Consecutive failure backoff
	st4 := &SurfaceState{
		SurfaceID:           surf.ID,
		LastAttempt:         now.Add(-2 * time.Minute),
		ConsecutiveFailures: 1, // 5m backoff
	}
	due, _ = isSurfaceDue(surf, st4, now)
	if due {
		t.Errorf("expected surface in backoff window to NOT be due")
	}
}

func TestAgentLockingAndStaleRecovery(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "test.lock")

	// 1. Normal lock acquisition
	release, err := acquireLock(lockPath, "test-surf", "snap-001")
	if err != nil {
		t.Fatalf("failed to acquire lock: %v", err)
	}

	// Second acquisition by live PID must fail
	_, err = acquireLock(lockPath, "test-surf", "snap-002")
	if err == nil {
		t.Fatalf("expected error acquiring already held lock")
	}

	// Release lock
	release()

	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Errorf("expected lockfile to be removed upon release")
	}

	// 2. Stale lock recovery: write dead PID (e.g. 999999)
	staleLock := LockInfo{
		PID:        999999, // Unlikely to exist
		StartTime:  time.Now().UTC().Add(-3 * time.Hour),
		SnapshotID: "snap-stale",
		SurfaceID:  "test-surf",
	}
	data, _ := json.Marshal(staleLock)
	_ = os.WriteFile(lockPath, data, 0600)

	// Attempting acquisition should reclaim the stale lock
	release2, err := acquireLock(lockPath, "test-surf", "snap-new")
	if err != nil {
		t.Fatalf("expected stale lock to be reclaimed, got: %v", err)
	}
	release2()
}

func TestAgentStatePersistence(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "agent_state.json")

	state := loadAgentState(statePath)
	if state.AgentID == "" {
		t.Errorf("expected non-empty agent ID generated")
	}

	now := time.Now().UTC()
	state.Surfaces["surf-01"] = &SurfaceState{
		SurfaceID:      "surf-01",
		SurfaceType:    "files",
		LastSuccess:    now,
		LastSnapshotID: "snap-abc",
	}

	if err := saveAgentState(statePath, state); err != nil {
		t.Fatalf("failed to save agent state: %v", err)
	}

	// Reload state
	loaded := loadAgentState(statePath)
	if loaded.AgentID != state.AgentID {
		t.Errorf("expected agent ID %s, got %s", state.AgentID, loaded.AgentID)
	}
	surf := loaded.Surfaces["surf-01"]
	if surf == nil || surf.LastSnapshotID != "snap-abc" {
		t.Errorf("surface state did not persist properly: %+v", surf)
	}
}

// A host clock that jumps backwards must not stop backups until it catches
// up: the surface is due now.
func TestABackwardsClockDoesNotStallTheSchedule(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	s := &config.SurfaceConfig{ID: "db", Schedule: "1h"}
	st := &SurfaceState{LastSuccess: now.Add(72 * time.Hour), LastAttempt: now.Add(72 * time.Hour)}
	if due, _ := isSurfaceDue(s, st, now); !due {
		t.Error("a surface whose last success is three days in the future is not due")
	}
	st = &SurfaceState{LastSuccess: now.Add(-2 * time.Hour), LastAttempt: now.Add(48 * time.Hour), ConsecutiveFailures: 3}
	if due, _ := isSurfaceDue(s, st, now); !due {
		t.Error("a failure recorded in the future holds the backoff open")
	}
	st = &SurfaceState{LastSuccess: now.Add(-30 * time.Minute), LastAttempt: now.Add(-30 * time.Minute)}
	if due, _ := isSurfaceDue(s, st, now); due {
		t.Error("an hourly surface backed up 30 minutes ago is due")
	}
}

// A backup that finished inside a millisecond still took time. Truncating it to
// 0 wrote manifests that read as a backup that never ran, and the agent-loop
// end-to-end test caught one.
func TestBackupMillisecondsRoundsUpNeverDown(t *testing.T) {
	if got := backupMilliseconds(time.Now()); got < 1 {
		t.Errorf("a backup started just now took %d ms, want at least 1", got)
	}
	if got := backupMilliseconds(time.Now().Add(-1500 * time.Millisecond)); got < 1500 || got > 1600 {
		t.Errorf("a backup of 1.5 s took %d ms, want 1500 or a little over", got)
	}
	if got := backupMilliseconds(time.Now().Add(time.Hour)); got != 0 {
		t.Errorf("a start in the future gave %d ms, want 0", got)
	}
}
