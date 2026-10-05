package write_test

import (
	"context"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/repo/catalog"
	"github.com/safegrd/cli/pkg/repo/check"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/unseal"
	"github.com/safegrd/cli/pkg/repo/write"
)

// commitFails is a backend whose Commit fails the next n times, as a remote
// server that cannot be reached after the sidecar is already in the store.
type commitFails struct {
	sink.Backend
	n int
}

func (c *commitFails) Commit(ctx context.Context, e format.Epoch, rc sink.RunCommit) error {
	if c.n > 0 {
		c.n--
		return errors.New("the remote server could not be reached")
	}
	return c.Backend.Commit(ctx, e, rc)
}

func readCatalog(t *testing.T, h *harness, e sink.EpochInfo, runID string) format.Catalog {
	t.Helper()
	key, _ := sink.ObjectKey(e.Prefix, sink.KindCatalog, runID)
	body, err := h.b.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	var c format.Catalog
	if err := unseal.Object(body, h.ids, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// A run whose sidecar landed but whose commit did not is a snapshot every
// reader sees and the cache never recorded. The next run cannot diff against
// it, so it lists every path; otherwise a file added in the unfinished run
// and deleted before the next would stay in the catalog, and check would
// disagree with the trees.
func TestARunThatPublishedWithoutFinishingIsFollowedByACompleteCatalog(t *testing.T) {
	h := newHarness(t)
	w := func(name, body string) {
		if err := os.WriteFile(filepath.Join(h.src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("a.txt", "a")
	first := h.backup(nil)

	w("b.txt", "b")
	f := &commitFails{Backend: h.b, n: 1}
	_, err := write.Run(context.Background(), f, h.opts(nil))
	if err == nil || !strings.Contains(err.Error(), "recording the run") {
		t.Fatalf("a failed commit did not fail the run: %v", err)
	}
	e := h.epoch(first.Epoch.EpochID)
	ids, _ := check.Snapshots(context.Background(), h.b, e)
	if len(ids) != 2 {
		t.Fatalf("the unfinished run's snapshot is not in the store: %v", ids)
	}
	unfinished := ids[1]

	if err := os.Remove(filepath.Join(h.src, "b.txt")); err != nil {
		t.Fatal(err)
	}
	third := h.backup(nil)
	if c := readCatalog(t, h, e, third.Snapshot.RunID); !c.Complete {
		t.Fatal("the run after an unfinished one wrote a delta, not every path")
	}
	for _, id := range append(ids, third.Snapshot.SnapshotID) {
		if rep := h.check(e.Epoch.EpochID, id, false); !rep.OK() {
			t.Fatalf("snapshot %s fails check: %v", id, rep.Problems)
		}
	}
	src := catalog.Source{Backend: h.b, Epochs: []sink.EpochInfo{e}, IDs: h.ids}
	hs, _, err := src.Find(context.Background(), []string{strings.TrimPrefix(h.src, "/") + "/b.txt"}, false)
	if err != nil || len(hs) != 1 {
		t.Fatalf("find b.txt: %v %v", hs, err)
	}
	if b := hs[0]; !b.Deleted || b.Versions[0].Last.SnapshotID != unfinished {
		t.Fatalf("b.txt's history: %+v", b)
	}
	// The unfinished run is settled by the one that followed it: the next
	// catalog is a delta again.
	fourth := h.backup(nil)
	if c := readCatalog(t, h, e, fourth.Snapshot.RunID); c.Complete {
		t.Fatal("every run after an unfinished one lists every path")
	}
}

// A resumed opening run keeps the tier its epoch was opened at, and says so,
// so a schedule that offered a longer tier does not count its slot as taken.
func TestAResumedOpeningRunReportsTheEpochsTier(t *testing.T) {
	h := newHarness(t)
	m := &mutator{rng: rand.New(rand.NewSource(11)), root: h.src}
	m.apply(t, 60)
	small := func(o *write.Options) { o.PackTargetBytes = 256 << 10; o.Concurrency = 1 }
	f := &faulty{Backend: h.b, n: 4, puts: map[string]int{}}
	if _, err := write.Run(context.Background(), f, h.opts(small)); err == nil {
		t.Fatal("the opening run did not die")
	}
	h.retain.KeepMonthly = 12
	res := h.backup(func(o *write.Options) { small(o); o.Tier = format.TierMonthly })
	if !res.Resumed || res.Class != format.ClassOpening || res.Tier != format.TierBase {
		t.Fatalf("the resumed opening run: resumed %v, class %s, tier %s", res.Resumed, res.Class, res.Tier)
	}
	later := h.backup(func(o *write.Options) { o.Tier = format.TierWeekly })
	if later.Class != format.ClassLater || later.Tier != format.TierWeekly {
		t.Fatalf("a later run: class %s, tier %s", later.Class, later.Tier)
	}
}

// A new public key opens a new epoch: the packs of one epoch are all wrapped
// to one recipient, and each epoch restores with its own identity.
func TestAChangedRecipientOpensANewEpoch(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(filepath.Join(h.src, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := h.backup(nil)
	oldIDs := h.ids
	id2, _ := age.GenerateX25519Identity()
	h.rec, h.ids = id2.Recipient().String(), []age.Identity{id2}
	b := h.backup(nil)
	if b.Epoch.EpochID == a.Epoch.EpochID || b.Reason != format.ReasonRecipient || b.Class != format.ClassOpening {
		t.Fatalf("a changed recipient: epoch %s (was %s), reason %s, class %s", b.Epoch.EpochID, a.Epoch.EpochID, b.Reason, b.Class)
	}
	if got, _, _ := h.restore(b.Epoch.EpochID, b.Snapshot.SnapshotID, nil); got["f"].typ != "f" {
		t.Fatal("the new epoch does not restore with the new identity")
	}
	h.ids = oldIDs
	if got, _, _ := h.restore(a.Epoch.EpochID, a.Snapshot.SnapshotID, nil); got["f"].typ != "f" {
		t.Fatal("the old epoch does not restore with the old identity")
	}
}

// The recovery document goes beside the sidecar and into the commit's keys.
// One that cannot be built or written is a warning on a run that succeeded:
// the snapshot already exists.
func TestTheRecoveryDocumentSitsBesideTheSidecar(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(filepath.Join(h.src, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, sealed := range []bool{false, true} {
		res := h.backup(func(o *write.Options) {
			o.RecoveryDoc = func(r *write.Result) ([]byte, bool, error) {
				return []byte("restore " + o.SnapshotID), sealed, nil
			}
		})
		kind := sink.KindRecovery
		if sealed {
			kind = sink.KindRecoverySealed
		}
		key, _ := sink.ObjectKey(h.epoch(res.Epoch.EpochID).Prefix, kind, res.Snapshot.SnapshotID)
		body, err := h.b.Get(context.Background(), key)
		if err != nil || string(body) != "restore "+res.Snapshot.SnapshotID {
			t.Fatalf("sealed=%v: the recovery document at %s: %q %v", sealed, key, body, err)
		}
		if res.Keys[len(res.Keys)-1] != key || res.RecoveryWarning != "" {
			t.Errorf("sealed=%v: keys end %s, warning %q", sealed, res.Keys[len(res.Keys)-1], res.RecoveryWarning)
		}
	}
	res := h.backup(func(o *write.Options) {
		o.RecoveryDoc = func(*write.Result) ([]byte, bool, error) { return nil, false, errors.New("no metadata") }
	})
	if !strings.Contains(res.RecoveryWarning, "no metadata") {
		t.Errorf("a recovery document that failed left no warning: %q", res.RecoveryWarning)
	}
	if ids, err := check.Snapshots(context.Background(), h.b, h.epoch(res.Epoch.EpochID)); err != nil || len(ids) != 3 {
		t.Errorf("the snapshots listed beside recovery documents: %v %v", ids, err)
	}
}
