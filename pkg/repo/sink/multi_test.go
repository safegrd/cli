package sink

import (
	"context"
	"errors"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/policy"
)

// failing is a store whose writes fail once armed.
type failing struct {
	Store
	armed bool
}

func (f *failing) Put(ctx context.Context, key string, body []byte, md5 [16]byte, until time.Time) error {
	if f.armed {
		return errors.New("bucket unreachable")
	}
	return f.Store.Put(ctx, key, body, md5, until)
}

func dirBackend(t *testing.T, root string) *Direct {
	t.Helper()
	d, err := NewDir(t.TempDir(), root)
	if err != nil {
		t.Fatal(err)
	}
	return NewDirect(d)
}

// run writes one run of two packs, an index, a catalog, a snapshot and its
// sidecar through b, the way the writer does, and returns the keys written.
func run(t *testing.T, b Backend, req OpenRequest, snap string) (format.Epoch, []string) {
	t.Helper()
	ctx := context.Background()
	opened, err := b.OpenEpoch(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	e := opened.Epoch
	runID := format.NewRandomID()
	specs := []ObjectSpec{{Kind: KindPack, Name: format.NewRandomID()}, {Kind: KindPack, Name: format.NewRandomID()},
		{Kind: KindIndex, Name: runID}, {Kind: KindCatalog, Name: runID}, {Kind: KindSnapshot, Name: snap}, {Kind: KindMeta, Name: snap}}
	slots, err := b.Reserve(ctx, e, format.ClassOpening, specs)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, s := range slots {
		if err := b.Put(ctx, s, []byte("body of "+s.Key)); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, s.Key)
	}
	if err := b.Commit(ctx, e, RunCommit{SnapshotID: snap, RunID: runID, Keys: keys}); err != nil {
		t.Fatal(err)
	}
	return e, keys
}

func holds(t *testing.T, d *Direct, e format.Epoch) map[string]bool {
	t.Helper()
	objs, err := d.S.List(context.Background(), EpochPrefix(d.S.Root(), e.SurfaceID, e.EpochID)+"/")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, o := range objs {
		out[o.Key[len(EpochPrefix(d.S.Root(), e.SurfaceID, e.EpochID)):]] = true
	}
	return out
}

func TestMultiWritesEveryObjectToEveryCopyAndPublishesLast(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	now := time.Now().UTC()
	req := OpenRequest{SurfaceID: "site", Decision: policy.Decision{Open: true, Reason: format.ReasonFirst},
		OpeningTier: "base", Retention: policy.Retention{Days: 7}, Recipient: id.Recipient().String(), Now: now}
	first := dirBackend(t, "node-a")
	ok := dirBackend(t, "node-a")
	broken := &failing{Store: dirBackend(t, "node-a").S}
	m := NewMulti(first, Named{Name: "offsite", D: ok, RetentionDays: 30}, Named{Name: "cold", D: NewDirect(broken), RetentionDays: 30})
	broken.armed = false
	e, _ := run(t, m, req, "snap-1")
	want := holds(t, first, e)
	got := holds(t, ok, e)
	if len(want) != 7 || len(got) != len(want) {
		t.Fatalf("the first store holds %v, the copy %v", want, got)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("the copy lacks %s", k)
		}
	}
	for _, r := range m.Results() {
		if !r.Held || r.Err != nil || r.Behind {
			t.Errorf("copy %s: %+v", r.Name, r)
		}
	}

	// A copy that fails mid-run is dropped: the run succeeds, the copy is
	// never published (no sidecar), and its result says why.
	cur := &policy.Current{Epoch: e, OpeningDone: true}
	broken.armed = true
	m2 := NewMulti(first, Named{Name: "offsite", D: ok, RetentionDays: 30}, Named{Name: "cold", D: NewDirect(broken), RetentionDays: 30})
	run(t, m2, OpenRequest{SurfaceID: "site", Current: cur, Now: now}, "snap-2")
	res := m2.Results()
	if !res[0].Held || res[1].Held || res[1].Err == nil {
		t.Fatalf("results after a copy failed: %+v", res)
	}
	if !holds(t, ok, e)["/snapshots/snap-2.meta.json"] {
		t.Error("the copy that took the run does not hold its sidecar")
	}

	// A copy that holds none of a continuing epoch is behind: nothing of the
	// run is published there, for the catch-up to copy whole.
	fresh := dirBackend(t, "node-a")
	m3 := NewMulti(first, Named{Name: "late", D: fresh, RetentionDays: 30})
	run(t, m3, OpenRequest{SurfaceID: "site", Current: cur, Now: now}, "snap-3")
	if r := m3.Results()[0]; !r.Behind || r.Held {
		t.Fatalf("a copy added mid-epoch: %+v", r)
	}
	if len(holds(t, fresh, e)) != 0 {
		t.Errorf("a copy behind was written: %v", holds(t, fresh, e))
	}
}
