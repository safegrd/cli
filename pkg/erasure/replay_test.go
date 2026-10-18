package erasure

import (
	"testing"
	"time"
)

// What a backup saw is never replayed, and what it did not see always is.
func TestTheWindowReplaysWhatTheBackupDidNotSee(t *testing.T) {
	start := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	w := Window{Snapshot: "100:110:103,107", Started: start}
	for _, c := range []struct {
		name string
		r    Record
		want bool
	}{
		{"committed before the snapshot", Record{XID: 99, At: start.Add(-time.Minute)}, false},
		{"seen: below xmax, not in progress", Record{XID: 105, At: start}, false},
		{"in progress when the backup read", Record{XID: 103, At: start.Add(-time.Second)}, true},
		{"after the snapshot", Record{XID: 110, At: start.Add(time.Minute)}, true},
		{"another server's ids, hours later", Record{XID: 5, At: start.Add(3 * time.Hour)}, true},
	} {
		if got := w.Replays(c.r); got != c.want {
			t.Errorf("%s: replays %v, want %v", c.name, got, c.want)
		}
	}
	// No snapshot recorded: the time decides, with an hour of doubt before.
	w.Snapshot = ""
	if w.Replays(Record{At: start.Add(-2 * time.Hour)}) || !w.Replays(Record{At: start.Add(-30 * time.Minute)}) {
		t.Error("without a snapshot, the window is the backup's start less an hour")
	}
}

func TestAnObjectNameCarriesItsNewestErasure(t *testing.T) {
	at := time.Date(2026, 10, 18, 10, 0, 0, 5, time.UTC)
	name := objectName("node-1/erasures/shop", []Record{{At: at.Add(-time.Hour)}, {At: at}})
	if got, ok := NewestIn(name); !ok || !got.Equal(at) {
		t.Errorf("%s: newest %v %v, want %v", name, got, ok, at)
	}
}
