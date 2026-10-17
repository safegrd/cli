package cli

import (
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// A wall clock that moves more than a tick beyond the time that passed is a
// step; ordinary jitter is not.
func TestAClockStepIsTheWallClockMovingBeyondTheTimeThatPassed(t *testing.T) {
	tick := 5 * time.Minute
	for _, c := range []struct {
		name          string
		wall, elapsed time.Duration
		want          time.Duration
	}{
		{"a normal tick", 5*time.Minute + time.Second, 5 * time.Minute, 0},
		{"forward an hour", time.Hour + 5*time.Minute, 5 * time.Minute, time.Hour},
		{"back a year", -365*24*time.Hour + 5*time.Minute, 5 * time.Minute, -365 * 24 * time.Hour},
		{"back less than a tick", 2 * time.Minute, 5 * time.Minute, 0},
	} {
		if got := stepBeyond(c.wall, c.elapsed, tick); got != c.want {
			t.Errorf("%s: step %s, want %s", c.name, got, c.want)
		}
	}
	// Real readings carry a monotonic clock that a step does not move.
	now := time.Now()
	if got := clockStep(now, now.Add(tick), tick); got != 0 {
		t.Errorf("a tick on the real clock read as a step of %s", got)
	}
}

// After the clock went back a year, a surface whose last backup is now in
// the future is due at once, not in a year.
func TestASurfaceIsDueAtOnceAfterTheClockWentBack(t *testing.T) {
	s := &config.SurfaceConfig{ID: "app", Type: "postgres", Schedule: "@daily"}
	now := time.Now().UTC()
	st := &SurfaceState{LastSuccess: now.AddDate(1, 0, 0), LastAttempt: now.AddDate(1, 0, 0)}
	if due, next := isSurfaceDue(s, st, now); !due || !next.Equal(now) {
		t.Errorf("due %v, next %s; want due now", due, next)
	}
}
