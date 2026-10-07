package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/write"
)

// A one-off backup plans two days, but every object of its run is locked
// until the epoch's lock for its class. The record and the closing line say
// the lock the bucket holds; they used to say the two days, so the console
// called a snapshot unlocked weeks before anything could delete it.
func TestARepoRunIsRecordedWithTheLockItsObjectsCarry(t *testing.T) {
	created := time.Date(2026, 10, 7, 4, 10, 0, 0, time.UTC)
	res := &write.Result{
		Snapshot: format.Snapshot{SnapshotID: "snap-x", CreatedAt: created, RetainUntil: created.Add(48 * time.Hour)},
		Epoch: format.Epoch{EpochID: "e202610-00000001", OpeningTier: format.TierBase,
			OpeningRetainUntil: time.Date(2026, 10, 22, 4, 5, 0, 0, time.UTC), LaterRetainUntil: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)},
		Class: format.ClassOpening,
	}
	if got := repoKeptUntil(res, true); !got.Equal(res.Epoch.OpeningRetainUntil) {
		t.Fatalf("a locked opening run is recorded until %s; its objects are locked until %s", got, res.Epoch.OpeningRetainUntil)
	}
	var out bytes.Buffer
	printRepoKept(&out, "[s]", res, true)
	if !strings.Contains(out.String(), "Immutable until 2026-10-22") {
		t.Fatalf("closing line: %q", out.String())
	}

	res.Class = format.ClassLater
	if got := repoKeptUntil(res, true); !got.Equal(res.Epoch.LaterRetainUntil) {
		t.Fatalf("a locked later run is recorded until %s; want %s", got, res.Epoch.LaterRetainUntil)
	}
	// Without a lock, it is how long the snapshot is kept.
	if got := repoKeptUntil(res, false); !got.Equal(res.Snapshot.RetainUntil) {
		t.Fatalf("an unlocked run is recorded until %s; want %s", got, res.Snapshot.RetainUntil)
	}
}
