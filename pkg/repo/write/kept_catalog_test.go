package write_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/repo/catalog"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/write"
)

// In a project that locks only the copies it keeps, the runs between two
// kept copies are written unlocked and deleted once the epoch closes and
// their retention passes: their snapshot, sidecar and catalog go, and only
// the packs a kept copy references stay. A kept copy's catalog must then
// stand on its own: a delta against a deleted run replays to the wrong
// state, and the drill of the kept copy fails on a catalog that disagrees
// with its trees.
func TestAKeptCopyChecksAfterTheRecentRunsAroundItAreDeleted(t *testing.T) {
	h := newHarness(t)
	rule := &sink.KeptRule{}
	h.b = &sink.Direct{S: h.store, Rule: rule}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(h.src, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	scheduled := func(at time.Time) {
		*rule = sink.KeptRule{Scheduled: true, LockUntil: at.AddDate(0, 0, 14), KeptUntil: at.AddDate(0, 0, 14)}
	}
	recent := func(at time.Time) {
		*rule = sink.KeptRule{Scheduled: false, KeptUntil: at.AddDate(0, 0, 2)}
	}

	write("a.txt", "a, version one")
	write("b.txt", "b, version one")
	scheduled(h.now)
	first := h.backup(nil)

	// A recent run changes a.txt and adds c.txt; nothing after it touches
	// either, so only its catalog knows their current content.
	write("a.txt", "a, version two")
	write("c.txt", "c, new")
	recent(h.now)
	middle := h.backup(nil)
	if middle.Decision.Locked {
		t.Fatal("the recent run was written locked")
	}

	write("b.txt", "b, version two")
	scheduled(h.now)
	kept := h.backup(nil)
	if !kept.Decision.Locked {
		t.Fatal("the scheduled run was written unlocked")
	}
	e := h.epoch(first.Epoch.EpochID)

	// Cleanup: the recent run's own records go, the packs it wrote stay
	// because the kept copy references them.
	for _, kind := range []sink.Kind{sink.KindCatalog} {
		k, _ := sink.ObjectKey(e.Prefix, kind, middle.Snapshot.RunID)
		if err := h.store.Remove(k); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []sink.Kind{sink.KindSnapshot, sink.KindMeta} {
		k, _ := sink.ObjectKey(e.Prefix, kind, middle.Snapshot.SnapshotID)
		if err := h.store.Remove(k); err != nil {
			t.Fatal(err)
		}
	}

	if rep := h.check(e.Epoch.EpochID, kept.Snapshot.SnapshotID, true); !rep.OK() {
		t.Fatalf("the kept copy fails check once the recent run before it is gone: %v", rep.Problems)
	}
	if rep := h.check(e.Epoch.EpochID, first.Snapshot.SnapshotID, true); !rep.OK() {
		t.Fatalf("the opening copy fails check: %v", rep.Problems)
	}
	got, _, _ := h.restore(e.Epoch.EpochID, kept.Snapshot.SnapshotID, nil)
	if want := oracle(t, h.src); diffOracle(want, got) != "" {
		t.Fatalf("the kept copy does not restore as the source: %s", diffOracle(want, got))
	}

	// find reads the same chain, and names the versions the kept copies hold.
	src := catalog.Source{Backend: h.b, Epochs: []sink.EpochInfo{e}, IDs: h.ids}
	hs, _, err := src.Find(context.Background(), []string{"**/a.txt"}, false)
	if err != nil || len(hs) != 1 {
		t.Fatalf("find: %+v %v", hs, err)
	}
	if vs := hs[0].Versions; len(vs) != 2 || !vs[1].Current || vs[1].First.SnapshotID != kept.Snapshot.SnapshotID {
		t.Fatalf("a.txt's versions after the recent run is gone: %+v", vs)
	}
}

// A kept copy's catalog lists every path, so its check needs no earlier
// run; a recent run's catalog is the delta it always was.
func TestAScheduledRunUnderTheKeptRuleWritesACompleteCatalog(t *testing.T) {
	h := newHarness(t)
	rule := &sink.KeptRule{}
	h.b = &sink.Direct{S: h.store, Rule: rule}
	if err := os.WriteFile(filepath.Join(h.src, "f"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	*rule = sink.KeptRule{Scheduled: true, LockUntil: h.now.AddDate(0, 0, 14), KeptUntil: h.now.AddDate(0, 0, 14)}
	first := h.backup(nil)
	e := h.epoch(first.Epoch.EpochID)

	*rule = sink.KeptRule{Scheduled: false, KeptUntil: h.now.AddDate(0, 0, 2)}
	recent := h.backup(func(o *write.Options) { o.SnapshotID = "recent" })
	if c := readCatalog(t, h, e, recent.Snapshot.RunID); c.Complete {
		t.Fatal("a recent run wrote a complete catalog")
	}

	*rule = sink.KeptRule{Scheduled: true, LockUntil: h.now.AddDate(0, 0, 14), KeptUntil: h.now.AddDate(0, 0, 14)}
	kept := h.backup(func(o *write.Options) { o.SnapshotID = "kept" })
	if c := readCatalog(t, h, e, kept.Snapshot.RunID); !c.Complete || len(c.Entries) == 0 {
		t.Fatalf("a scheduled run under the kept rule wrote a delta: complete=%v, %d entries", c.Complete, len(c.Entries))
	}

	// Every run locked: a later run is a delta, as before.
	h2 := newHarness(t)
	if err := os.WriteFile(filepath.Join(h2.src, "f"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	h2.backup(nil)
	if err := os.WriteFile(filepath.Join(h2.src, "f"), []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	later := h2.backup(nil)
	if c := readCatalog(t, h2, h2.epoch(later.Epoch.EpochID), later.Snapshot.RunID); c.Complete {
		t.Fatal("a later run of a project that locks every backup wrote a complete catalog")
	}
}
