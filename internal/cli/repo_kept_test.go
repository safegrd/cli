package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/write"
)

// In a project that locks only the copies it keeps, the remote server's
// decision is what the record and the closing line say: a scheduled run is
// locked until its lock, a recent run is kept until its keep date and is
// never called immutable.
func TestAKeptModeRunSaysWhatTheServerDecided(t *testing.T) {
	created := time.Date(2026, 10, 10, 2, 0, 0, 0, time.UTC)
	res := &write.Result{
		Snapshot: format.Snapshot{SnapshotID: "snap-r", CreatedAt: created, RetainUntil: created.AddDate(0, 0, 2), Unlocked: true},
		Epoch: format.Epoch{EpochID: "e202610-00000001", OpeningTier: format.TierBase,
			OpeningRetainUntil: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), LaterRetainUntil: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)},
		Class:    format.ClassLater,
		Decision: sink.RunDecision{Known: true, Locked: false, KeptUntil: created.AddDate(0, 0, 2)},
	}
	if got := repoKeptUntil(res, true); !got.Equal(created.AddDate(0, 0, 2)) {
		t.Fatalf("a recent run is recorded until its keep date, got %s", got)
	}
	if repoRunLocked(res, true) {
		t.Fatal("a recent run is not locked")
	}
	var out bytes.Buffer
	printRepoKept(&out, "[s]", res, true)
	if !strings.Contains(out.String(), "Kept until 2026-10-12, not locked") || strings.Contains(out.String(), "Immutable") {
		t.Fatalf("closing line: %q", out.String())
	}

	lock := created.AddDate(0, 0, 14)
	res.Snapshot.Unlocked = false
	res.Decision = sink.RunDecision{Known: true, Scheduled: true, Locked: true, LockUntil: lock}
	if got := repoKeptUntil(res, true); !got.Equal(lock) {
		t.Fatalf("a scheduled run is recorded until its lock, got %s", got)
	}
	out.Reset()
	printRepoKept(&out, "[s]", res, true)
	if !strings.Contains(out.String(), "Locked until 2026-10-24 (daily copy)") {
		t.Fatalf("closing line: %q", out.String())
	}
}

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
	if !strings.Contains(out.String(), "Locked until 2026-10-22") {
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

// When the remote server locks a run for less time than it keeps it, the
// closing line gives both dates, and the record keeps the lock.
func TestARunLockedShorterThanItIsKeptSaysBothDates(t *testing.T) {
	created := time.Date(2026, 10, 11, 2, 0, 0, 0, time.UTC)
	lock, kept := created.AddDate(0, 0, 1), created.AddDate(0, 0, 7)
	res := &write.Result{
		Snapshot: format.Snapshot{SnapshotID: "snap-f", CreatedAt: created, RetainUntil: lock},
		Epoch: format.Epoch{EpochID: "e202610-00000002", OpeningTier: format.TierBase, Reason: format.ReasonFull,
			OpeningRetainUntil: lock, LaterRetainUntil: lock},
		Class:    format.ClassOpening,
		Capped:   true,
		Decision: sink.RunDecision{Known: true, Scheduled: true, Locked: true, LockUntil: lock, KeptUntil: kept},
	}
	if got := repoKeptUntil(res, true); !got.Equal(lock) {
		t.Fatalf("the run is recorded until %s, want its lock %s", got, lock)
	}
	var out bytes.Buffer
	printRepoKept(&out, "[s]", res, true)
	got := out.String()
	if !strings.Contains(got, "Locked until 2026-10-12, kept until 2026-10-18.") || strings.Contains(got, "Immutable") || strings.Contains(got, "month") {
		t.Fatalf("closing line: %q", got)
	}
}

// "Once this month" is said only of an epoch that runs to its month's end.
func TestOnlyAMonthLongEpochSaysOnceThisMonth(t *testing.T) {
	opened := time.Date(2026, 10, 11, 2, 0, 0, 0, time.UTC)
	month := format.Epoch{OpenedAt: opened, PlannedEnd: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Reason: format.ReasonFirst}
	if got := onceThisMonth(month); got != " once this month" {
		t.Errorf("a month-long epoch says %q", got)
	}
	single := format.Epoch{OpenedAt: opened, PlannedEnd: opened.AddDate(0, 0, 1), Reason: format.ReasonFirst}
	if got := onceThisMonth(single); got != "" {
		t.Errorf("an epoch that ends with its one backup's lock says %q", got)
	}
	full := month
	full.Reason = format.ReasonFull
	if got := onceThisMonth(full); got != "" {
		t.Errorf("an epoch opened for a full copy says %q", got)
	}
}

// A 6-hour slot's locked copy was labelled "(daily copy)", and the unlocked
// line said the project locks "the day's first backup", on a plan that locks
// the first backup of every slot.
func TestASlotCopyIsNamedByItsSlot(t *testing.T) {
	for _, tc := range []struct{ slot, first, copy string }{
		{"2026-10-12", "the day's first backup", "daily copy"},
		{"2026-10-12T00", "the day's first backup", "daily copy"},
		{"2026-10-12T18", "the first backup from 18:00 UTC", "the first backup from 18:00 UTC"},
		{"", "the day's first backup", "daily copy"},
	} {
		if got := slotFirstWords(tc.slot); got != tc.first {
			t.Errorf("slotFirstWords(%q) = %q, want %q", tc.slot, got, tc.first)
		}
		if got := slotCopyWords(tc.slot); got != tc.copy {
			t.Errorf("slotCopyWords(%q) = %q, want %q", tc.slot, got, tc.copy)
		}
	}
}
