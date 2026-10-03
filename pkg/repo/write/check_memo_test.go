package write_test

import (
	"context"
	"math/rand"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/repo/check"
	"github.com/safegrd/cli/pkg/repo/sink"
)

// countingBackend counts what is read by key.
type countingBackend struct {
	sink.Backend
	gets  map[string]int
	lists int
}

func (c *countingBackend) Get(ctx context.Context, key string) ([]byte, error) {
	c.gets[key]++
	return c.Backend.Get(ctx, key)
}

func (c *countingBackend) List(ctx context.Context, e sink.EpochInfo, sub string) ([]sink.ObjectInfo, error) {
	c.lists++
	return c.Backend.List(ctx, e, sub)
}

// Checking every snapshot of an epoch through one memo reads each catalog,
// index and listing once, and finds what a fresh check of each snapshot
// finds, in whichever order the snapshots are asked for.
func TestCheckingAnEpochThroughAMemoReadsEachObjectOnce(t *testing.T) {
	h := newHarness(t)
	m := &mutator{rng: rand.New(rand.NewSource(5)), root: h.src}
	m.apply(t, 60)
	first := h.backup(nil)
	var ids []string
	ids = append(ids, first.Snapshot.SnapshotID)
	for i := 0; i < 5; i++ {
		m.apply(t, 12)
		ids = append(ids, h.backup(nil).Snapshot.SnapshotID)
	}
	e := h.epoch(first.Epoch.EpochID)

	fresh := map[string]string{}
	for _, id := range ids {
		rep := h.check(e.Epoch.EpochID, id, false)
		if !rep.OK() {
			t.Fatalf("snapshot %s fails a fresh check: %v", id, rep.Problems)
		}
		fresh[id] = rep.ContentRoot
	}

	for _, order := range [][]string{ids, reversed(ids), append(append([]string{}, ids[2], ids[0], ids[4]), ids...)} {
		cb := &countingBackend{Backend: h.b, gets: map[string]int{}}
		memo := check.NewMemo(cb, e, h.ids)
		for _, id := range order {
			rep, err := check.Snapshot(context.Background(), cb, e, id, h.ids, check.Options{Memo: memo})
			if err != nil {
				t.Fatal(err)
			}
			if !rep.OK() || rep.ContentRoot != fresh[id] {
				t.Fatalf("through the memo, snapshot %s: %v (root %s, fresh %s)", id, rep.Problems, rep.ContentRoot, fresh[id])
			}
		}
		if cb.lists != 2 { // packs once, snapshots once
			t.Errorf("the epoch was listed %d times, want 2", cb.lists)
		}
		// The sidecar is read per check; everything else once per epoch.
		for key, n := range cb.gets {
			if n == 1 || strings.HasSuffix(key, ".meta.json") {
				continue
			}
			if strings.Contains(key, "/catalog/") || strings.Contains(key, "/index/") || strings.Contains(key, "/snapshots/") {
				t.Errorf("%s was read %d times through the memo", key, n)
			}
		}
	}

	// A memo for another epoch is refused rather than consulted.
	other := e
	other.Epoch.EpochID = "e209912-00000000"
	if _, err := check.Snapshot(context.Background(), h.b, e, ids[0], h.ids, check.Options{Memo: check.NewMemo(h.b, other, h.ids)}); err == nil {
		t.Fatal("a memo of another epoch was used")
	}
}

func reversed(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}
