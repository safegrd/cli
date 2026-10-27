package cli

import (
	"fmt"
	"testing"
	"time"
)

// The rule an erasure record object is pruned by: kept while a snapshot
// older than its newest erasure (less an hour of skew) exists, then held
// until its lock and the grace have passed; the marker kept while the
// surface has any snapshot or any other object of the record.
func TestDecideErasureObject(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	oldest := now.Add(-48 * time.Hour) // the oldest snapshot left
	name := func(newest time.Time) string {
		return fmt.Sprintf("n/erasures/shop/%020d-0123456789ab.json.age", newest.UnixNano())
	}
	grace := 24 * time.Hour
	cases := []struct {
		what        string
		name        string
		anySnapshot bool
		lockEnds    time.Time
		othersLeft  bool
		want        erasurePruneDecision
	}{
		{"an erasure after the oldest snapshot is needed", name(oldest.Add(time.Hour)), true, now.Add(-30 * time.Hour), false, erasureKeep},
		{"an erasure inside the hour before it is needed", name(oldest.Add(-30 * time.Minute)), true, now.Add(-30 * time.Hour), false, erasureKeep},
		{"an erasure older than every snapshot, lock ended, goes", name(oldest.Add(-2 * time.Hour)), true, now.Add(-30 * time.Hour), false, erasureExpired},
		{"an erasure older than every snapshot, still locked, waits", name(oldest.Add(-2 * time.Hour)), true, now.Add(time.Hour), false, erasureLocked},
		{"with no lock the grace since the erasure decides", name(now.Add(-time.Hour)), false, time.Time{}, false, erasureLocked},
		{"with no lock and the grace passed it goes", name(now.Add(-2 * grace)), false, time.Time{}, false, erasureExpired},
		{"the marker stays while a snapshot exists", "n/erasures/shop/record.json", true, now.Add(-30 * time.Hour), false, erasureKeep},
		{"the marker stays while another object does", "n/erasures/shop/record.json", false, now.Add(-30 * time.Hour), true, erasureKeep},
		{"the marker goes last", "n/erasures/shop/record.json", false, now.Add(-30 * time.Hour), false, erasureExpired},
	}
	for _, c := range cases {
		if got := decideErasureObject(c.name, oldest, c.anySnapshot, c.lockEnds, now, grace, c.othersLeft); got != c.want {
			t.Errorf("%s: got %v, want %v", c.what, got, c.want)
		}
	}
}
