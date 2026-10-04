package write_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"

	"github.com/safegrd/cli/pkg/repo/cache"
	"github.com/safegrd/cli/pkg/repo/check"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/unseal"
	"github.com/safegrd/cli/pkg/repo/write"
)

// faulty fails every backend call from the n-th on, as a killed process
// would stop making them. n < 0 never fails.
type faulty struct {
	sink.Backend
	mu    sync.Mutex
	calls int
	n     int
	puts  map[string]int
}

var errKilled = errors.New("killed")

func (f *faulty) tick() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.n >= 0 && f.calls > f.n {
		return errKilled
	}
	return nil
}

func (f *faulty) OpenEpoch(ctx context.Context, r sink.OpenRequest) (sink.Opened, error) {
	if err := f.tick(); err != nil {
		return sink.Opened{}, err
	}
	return f.Backend.OpenEpoch(ctx, r)
}

func (f *faulty) Reserve(ctx context.Context, e format.Epoch, c string, o []sink.ObjectSpec) ([]sink.Slot, error) {
	if err := f.tick(); err != nil {
		return nil, err
	}
	return f.Backend.Reserve(ctx, e, c, o)
}

func (f *faulty) Put(ctx context.Context, s sink.Slot, b []byte) error {
	if err := f.tick(); err != nil {
		return err
	}
	f.mu.Lock()
	f.puts[s.Key]++
	f.mu.Unlock()
	return f.Backend.Put(ctx, s, b)
}

func (f *faulty) Uploaded(ctx context.Context, e format.Epoch, k []string) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.Backend.Uploaded(ctx, e, k)
}

func (f *faulty) Commit(ctx context.Context, e format.Epoch, c sink.RunCommit) error {
	if err := f.tick(); err != nil {
		return err
	}
	return f.Backend.Commit(ctx, e, c)
}

// blobsPerPack opens every pack's trailer with the identity.
func blobsPerPack(t *testing.T, h *harness, e sink.EpochInfo) map[string][]string {
	t.Helper()
	ctx := context.Background()
	objs, err := h.b.List(ctx, e, "packs")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, o := range objs {
		body, err := h.b.Get(ctx, o.Key)
		if err != nil {
			t.Fatal(err)
		}
		wrapped, hdr, err := format.ParsePackHeader(body)
		if err != nil {
			t.Fatal(err)
		}
		k, err := unseal.UnwrapKey(wrapped, h.ids)
		if err != nil {
			t.Fatal(err)
		}
		op, _ := unseal.NewOpener(k)
		tl, err := format.ParsePackFooter(body[len(body)-8:], int64(len(body)), hdr)
		if err != nil {
			t.Fatal(err)
		}
		packID := o.Key[strings.LastIndex(o.Key, "/")+1:]
		tr, err := op.Trailer(packID, body[len(body)-8-tl:len(body)-8])
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range tr.Blobs {
			out[packID] = append(out[packID], b.ID)
		}
	}
	return out
}

func TestAnInterruptedRunResumesAtEveryPoint(t *testing.T) {
	s := seed(t)
	// Count the calls of one clean run of the same shape.
	countRun := func(h *harness, m *mutator) int {
		f := &faulty{Backend: h.b, n: -1, puts: map[string]int{}}
		h.b = f
		h.backup(func(o *write.Options) { o.PackTargetBytes = 256 << 10; o.Concurrency = 1 })
		h.b = f.Backend
		return f.calls
	}
	probe := newHarness(t)
	pm := &mutator{rng: rand.New(rand.NewSource(s)), root: probe.src}
	pm.apply(t, 60)
	total := countRun(probe, pm)
	if total < 6 {
		t.Fatalf("a run made only %d backend calls", total)
	}
	step := 1
	if testing.Short() && total > 12 {
		step = total / 12
	}
	resumed := 0
	for _, opening := range []bool{true, false} {
		for n := 0; n < total+2; n += step {
			name := fmt.Sprintf("opening=%v/kill-after-%d", opening, n)
			h := newHarness(t)
			m := &mutator{rng: rand.New(rand.NewSource(s)), root: h.src}
			m.apply(t, 60)
			opts := func(o *write.Options) { o.PackTargetBytes = 256 << 10; o.Concurrency = 1 }
			if !opening {
				h.backup(opts)
				m.apply(t, 30)
			}
			f := &faulty{Backend: h.b, n: n, puts: map[string]int{}}
			h.b = f
			_, err := write.Run(context.Background(), f, h.opts(opts))
			h.b = f.Backend
			if err == nil && f.calls > n {
				t.Fatalf("%s (seed %d): the run did not fail", name, s)
			}
			// The tree changes between the death and the rerun: a catalog
			// that replayed the dead run's delta twice would still agree
			// with the trees, one that misses what changed since would not.
			m.apply(t, 10)
			want := oracle(t, h.src)
			adoptable := unindexedPacks(t, h)
			res := h.backup(opts)
			if res.Resumed {
				resumed++
			}
			// Packs the dead run uploaded and confirmed, but no index names
			// yet, are what a rerun must adopt rather than upload again.
			// Packs an index already names are not: the rerun dedups against
			// the index. Counting every pack put before the kill, with a guess
			// that indexes are written only in a run's last four calls,
			// failed for trees whose index was flushed earlier (CI, seed
			// 1791107398478961523), though nothing was uploaded twice.
			if adoptable > 0 && !res.Resumed {
				t.Fatalf("%s (seed %d): %d uploaded packs no index named were left behind, none adopted", name, s, adoptable)
			}
			if adoptable > 0 && res.AdoptedPacks != adoptable {
				t.Fatalf("%s (seed %d): %d packs to adopt, the rerun adopted %d", name, s, adoptable, res.AdoptedPacks)
			}
			got, _, _ := h.restore(res.Epoch.EpochID, res.Snapshot.SnapshotID, nil)
			if d := diffOracle(want, got); d != "" {
				t.Fatalf("%s (seed %d): the resumed run restores wrong: %s", name, s, d)
			}
			es, _ := h.b.Epochs(context.Background(), "files-test")
			for _, e := range es {
				ids, err := check.Snapshots(context.Background(), h.b, e)
				if err != nil {
					t.Fatal(err)
				}
				for _, id := range ids {
					rep, err := check.Snapshot(context.Background(), h.b, e, id, h.ids, check.Options{ReadData: true})
					if err != nil || !rep.OK() {
						t.Fatalf("%s (seed %d): snapshot %s fails check: %v %v", name, s, id, err, rep.Problems)
					}
				}
				// With one upload at a time, at most one pack's blobs were
				// uploaded twice: the one in flight when the run died.
				seen := map[string]string{}
				dup := map[string]bool{}
				for pack, blobs := range blobsPerPack(t, h, e) {
					for _, b := range blobs {
						if other, ok := seen[b]; ok && other != pack {
							dup[pack] = true
						}
						seen[b] = pack
					}
				}
				if len(dup) > 1 {
					t.Fatalf("%s (seed %d): %d packs hold blobs another pack already held", name, s, len(dup))
				}
			}
		}
	}
	if resumed == 0 {
		t.Fatalf("seed %d: no rerun adopted an uploaded pack", s)
	}
}

// unindexedPacks counts the packs the local cache holds as uploaded whose
// blobs no index names yet: what a rerun's Resume adopts.
func unindexedPacks(t *testing.T, h *harness) int {
	t.Helper()
	c, _, err := cache.Current(cache.Dir(h.state, "files-test"), "files-test")
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		return 0
	}
	defer c.Close()
	pending, err := c.Unindexed()
	if err != nil {
		t.Fatal(err)
	}
	return len(pending)
}
