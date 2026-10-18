package write_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/write"
)

// lastSnapshot is a backend that, like the remote server, names the newest
// snapshot it committed into the epoch when the epoch is opened.
type lastSnapshot struct {
	sink.Backend
	id string
}

func (l *lastSnapshot) OpenEpoch(ctx context.Context, req sink.OpenRequest) (sink.Opened, error) {
	o, err := l.Backend.OpenEpoch(ctx, req)
	o.LastSnapshotID = l.id
	return o, err
}

// A run on a machine that is deleted after each run fetches the cache the
// run before kept on the remote server. When that run could not keep its
// cache, the fetched one is a run behind: its catalog does not describe the
// epoch's newest snapshot, so a delta against it would miss what that run
// changed. A run whose cache does not know the newest snapshot lists every
// path, and does not take an unchanged source for a skip.
func TestACacheBehindTheEpochsNewestSnapshotListsEveryPath(t *testing.T) {
	h := newHarness(t)
	w := func(name, body string) {
		if err := os.WriteFile(filepath.Join(h.src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("a.txt", "a")
	first := h.backup(nil)
	w("b.txt", "b")
	second := h.backup(nil)
	e := h.epoch(first.Epoch.EpochID)

	// The cache knows the second run: a later run's catalog is a delta.
	w("c.txt", "c")
	res, err := write.Run(context.Background(), &lastSnapshot{h.b, second.Snapshot.SnapshotID}, h.opts(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c := readCatalog(t, h, e, res.Snapshot.RunID); c.Complete || len(c.Entries) != 1 {
		t.Fatalf("with the cache current the catalog is complete=%v with %d entries, want a delta of one", c.Complete, len(c.Entries))
	}

	// The cache is behind what the backend holds: every path is listed,
	// and nothing is skipped as unchanged.
	res, err = write.Run(context.Background(), &lastSnapshot{h.b, "snap-the-cache-never-saw"}, h.opts(func(o *write.Options) { o.SkipIfUnchanged = true }))
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped {
		t.Fatal("a run whose cache is behind the epoch skipped as unchanged")
	}
	c := readCatalog(t, h, e, res.Snapshot.RunID)
	files := 0
	for _, en := range c.Entries {
		if strings.HasSuffix(en.Path, ".txt") {
			files++
		}
	}
	if !c.Complete || files != 3 {
		t.Fatalf("with the cache behind the catalog is complete=%v with %d files, want every path", c.Complete, files)
	}
}
