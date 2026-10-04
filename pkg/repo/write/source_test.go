package write_test

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/write"
)

// streams is a source emitting fixed contents.
func streams(files map[string][]byte) write.Source {
	return func(ctx context.Context, emit func(write.Entry) error) error {
		for p, b := range files {
			if err := emit(write.Entry{Path: p, Reader: bytes.NewReader(b)}); err != nil {
				return err
			}
		}
		return nil
	}
}

// catAll reads every file of a snapshot back through Cat.
func (h *harness) catAll(epochID, snapID string) map[string][]byte {
	h.t.Helper()
	ctx := context.Background()
	r := read.Open(h.b, h.epoch(epochID), h.ids)
	snap, err := r.Snapshot(ctx, snapID)
	if err != nil {
		h.t.Fatal(err)
	}
	idx, err := r.LoadIndex(ctx, snap)
	if err != nil {
		h.t.Fatal(err)
	}
	if root, _, err := r.ContentRoot(ctx, idx, snap); err != nil || root != snap.ContentRoot {
		h.t.Fatalf("the content root recomputed from the trees is %s (%v), the snapshot records %s", root, err, snap.ContentRoot)
	}
	rootTree, _ := format.ParseID(snap.RootTree)
	out := map[string][]byte{}
	err = r.Walk(ctx, idx, rootTree, func(it read.Item) error {
		if it.Node.Type != format.NodeFile {
			return nil
		}
		var b bytes.Buffer
		if err := r.Cat(ctx, idx, it.Node, &b); err != nil {
			return err
		}
		out[it.Path] = b.Bytes()
		return nil
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return out
}

func randomBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	rng.Read(b)
	return b
}

func TestASourceRunReadsBackByteForByteAndUploadsOnlyWhatMoved(t *testing.T) {
	h := newHarness(t)
	rng := rand.New(rand.NewSource(7))
	table := randomBytes(rng, 32<<20)
	files := map[string][]byte{
		"pre-data.sql":           []byte("CREATE TABLE t (id int);\n"),
		"data/public/t.copy":     table,
		"data/public/empty.copy": {},
		"data/other/static.copy": randomBytes(rng, 3<<20),
		"manifest.json":          []byte(`{"tables":3}`),
	}
	first := h.backup(func(o *write.Options) { o.Roots, o.Source = nil, streams(files) })
	if got := h.catAll(first.Epoch.EpochID, first.Snapshot.SnapshotID); len(got) != len(files) {
		t.Fatalf("%d files read back, %d emitted", len(got), len(files))
	} else {
		for p, want := range files {
			if !bytes.Equal(got[p], want) {
				t.Fatalf("%s did not read back as written", p)
			}
		}
	}
	if len(first.Snapshot.Roots) != 1 || first.Snapshot.Roots[0] != "/" {
		t.Errorf("a source run's roots are %v, want [/]", first.Snapshot.Roots)
	}
	if rep := h.check(first.Epoch.EpochID, first.Snapshot.SnapshotID, true); !rep.OK() {
		t.Fatalf("check: %v", rep.Err())
	}

	// A row inserted in the middle of the big table, and nothing else.
	mid := len(table) / 2
	files["data/public/t.copy"] = append(append(append([]byte{}, table[:mid]...), []byte("one more row")...), table[mid:]...)
	second := h.backup(func(o *write.Options) { o.Roots, o.Source = nil, streams(files) })
	if second.Epoch.EpochID != first.Epoch.EpochID {
		t.Fatalf("the second run opened epoch %s", second.Epoch.EpochID)
	}
	// A chunk is up to 8 MiB, so an insert re-uploads one or two of them,
	// never the stream.
	if second.WrittenBytes > first.WrittenBytes/2 {
		t.Errorf("an insert into one 32 MiB stream uploaded %d bytes, the first run %d", second.WrittenBytes, first.WrittenBytes)
	}
	got := h.catAll(second.Epoch.EpochID, second.Snapshot.SnapshotID)
	for p, want := range files {
		if !bytes.Equal(got[p], want) {
			t.Fatalf("%s did not read back as written in the second run", p)
		}
	}
}

func TestASourceRefusesPathsThatAreNotOneCleanTree(t *testing.T) {
	for name, files := range map[string][]string{
		"absolute":     {"/etc/passwd"},
		"climbing":     {"../x"},
		"unclean":      {"a//b"},
		"dot":          {"./a"},
		"twice":        {"a", "a"},
		"under a file": {"a", "a/b"},
		"a directory":  {"a/b", "a"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			src := func(ctx context.Context, emit func(write.Entry) error) error {
				for _, p := range files {
					if err := emit(write.Entry{Path: p, Reader: strings.NewReader("x")}); err != nil {
						return err
					}
				}
				return nil
			}
			if _, err := write.Run(context.Background(), h.b, h.opts(func(o *write.Options) { o.Roots, o.Source = nil, src })); err == nil {
				t.Fatalf("paths %q were stored", files)
			}
		})
	}
}

func TestARunTakesASourceOrRootsNotBoth(t *testing.T) {
	h := newHarness(t)
	_, err := write.Run(context.Background(), h.b, h.opts(func(o *write.Options) { o.Source = streams(map[string][]byte{"a": nil}) }))
	if err == nil {
		t.Fatal("a run with roots and a source was accepted")
	}
}

// A source that fails part way publishes nothing.
func TestASourceThatFailsPublishesNoSnapshot(t *testing.T) {
	h := newHarness(t)
	src := func(ctx context.Context, emit func(write.Entry) error) error {
		if err := emit(write.Entry{Path: "a", Reader: strings.NewReader("x")}); err != nil {
			return err
		}
		return io.ErrUnexpectedEOF
	}
	if _, err := write.Run(context.Background(), h.b, h.opts(func(o *write.Options) { o.Roots, o.Source = nil, src })); err == nil {
		t.Fatal("a failed source produced a snapshot")
	}
	es, _ := h.b.Epochs(context.Background(), "files-test")
	for _, e := range es {
		r := read.Open(h.b, e, h.ids)
		if _, err := r.Snapshot(context.Background(), "snap-0001"); err == nil {
			t.Fatal("the failed run's snapshot is readable")
		}
	}
}
