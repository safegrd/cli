package write_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/write"
)

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// restoreAt restores a snapshot, whole or by path, and returns the oracle of
// the target.
func restoreAt(t *testing.T, h *harness, epochID, snapID string, paths []string) (map[string]oracleEntry, *read.RestoreResult) {
	t.Helper()
	r := read.Open(h.b, h.epoch(epochID), h.ids)
	snap, err := r.Snapshot(context.Background(), snapID)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := r.LoadIndex(context.Background(), snap)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "out")
	res, err := r.Restore(context.Background(), snap, idx, read.RestoreOptions{Target: target, Paths: paths})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	return oracle(t, target), res
}

// Two roots are stored under one tree, each at its path from /, with the
// directories on the way to them; both restore exactly, and a path under
// the second restores on its own.
func TestTwoRootsRestoreAtTheirPaths(t *testing.T) {
	h := newHarness(t)
	second := filepath.Join(filepath.Dir(h.src), "etc-like")
	if err := os.Mkdir(second, 0o755); err != nil {
		t.Fatal(err)
	}
	second, _ = filepath.EvalSymlinks(second)
	mustWrite(t, filepath.Join(h.src, "www", "index.html"), "<p>hi</p>")
	mustWrite(t, filepath.Join(second, "nginx", "nginx.conf"), "server {}")
	mustWrite(t, filepath.Join(second, "hosts"), "127.0.0.1 localhost")
	res := h.backup(func(o *write.Options) { o.Roots = []string{h.src, second} })
	if rep := h.check(res.Epoch.EpochID, res.Snapshot.SnapshotID, true); !rep.OK() {
		t.Fatalf("check: %v", rep.Problems)
	}
	got, _ := restoreAt(t, h, res.Epoch.EpochID, res.Snapshot.SnapshotID, nil)
	for root, want := range map[string]map[string]oracleEntry{h.src: oracle(t, h.src), second: oracle(t, second)} {
		sub := map[string]oracleEntry{}
		for p, e := range got {
			if rel, ok := strings.CutPrefix(p, strings.TrimPrefix(root, "/")+"/"); ok {
				sub[rel] = e
			}
		}
		if d := diffOracle(want, sub); d != "" {
			t.Fatalf("root %s restores wrong: %s", root, d)
		}
	}
	if _, ok := got[strings.TrimPrefix(second, "/")]; !ok {
		t.Fatalf("the second root's directory is missing from %v", got)
	}
	one, rr := restoreAt(t, h, res.Epoch.EpochID, res.Snapshot.SnapshotID, []string{strings.TrimPrefix(second, "/") + "/nginx/nginx.conf"})
	var files int
	for _, e := range one {
		if e.typ == "f" {
			files++
		}
	}
	if files != 1 || rr.Files != 1 {
		t.Fatalf("restoring one path under the second root wrote %d files: %v", files, one)
	}
	// A root inside another is refused.
	if _, err := write.Run(context.Background(), h.b, h.opts(func(o *write.Options) { o.Roots = []string{h.src, filepath.Join(h.src, "www")} })); err == nil {
		t.Fatal("a root inside another was accepted")
	}
}

// Excludes: a glob on the name, a directory and everything in it, and an
// absolute path. What is excluded is neither stored nor in the content root.
func TestExcludesLeaveFilesOut(t *testing.T) {
	h := newHarness(t)
	mustWrite(t, filepath.Join(h.src, "keep.txt"), "kept")
	mustWrite(t, filepath.Join(h.src, "app.log"), "noise")
	mustWrite(t, filepath.Join(h.src, "deep", "trace.log"), "noise")
	mustWrite(t, filepath.Join(h.src, "node_modules", "x", "index.js"), "noise")
	mustWrite(t, filepath.Join(h.src, "cache", "blob"), "noise")
	mustWrite(t, filepath.Join(h.src, "deep", "data.bin"), "kept")
	res := h.backup(func(o *write.Options) {
		o.Excludes = []string{"*.log", "node_modules/*", filepath.Join(h.src, "cache")}
	})
	got, _ := restoreAt(t, h, res.Epoch.EpochID, res.Snapshot.SnapshotID, nil)
	rel := strings.TrimPrefix(h.src, "/")
	for _, p := range []string{"app.log", "deep/trace.log", "node_modules", "node_modules/x/index.js", "cache", "cache/blob"} {
		if _, ok := got[rel+"/"+p]; ok {
			t.Errorf("%s was stored although excluded", p)
		}
	}
	for _, p := range []string{"keep.txt", "deep/data.bin", "deep"} {
		if _, ok := got[rel+"/"+p]; !ok {
			t.Errorf("%s was left out", p)
		}
	}
	if res.Snapshot.Stats.Files != 2 {
		t.Errorf("the snapshot counts %d files, want 2", res.Snapshot.Stats.Files)
	}
	if rep := h.check(res.Epoch.EpochID, res.Snapshot.SnapshotID, false); !rep.OK() {
		t.Fatalf("check: %v", rep.Problems)
	}
}

// When the month turns, the next run opens a new epoch and uploads the tree
// again; the old epoch's snapshots still restore.
func TestTheMonthTurnOpensANewEpoch(t *testing.T) {
	h := newHarness(t)
	mustWrite(t, filepath.Join(h.src, "f"), "october")
	oct := h.backup(nil)
	if oct.Epoch.PlannedEnd != time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("planned end %s", oct.Epoch.PlannedEnd)
	}
	h.now = time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC)
	still := h.backup(nil)
	if still.Opened || still.Class != format.ClassLater {
		t.Fatalf("a run before the planned end opened a new epoch: %v %s", still.Opened, still.Class)
	}
	mustWrite(t, filepath.Join(h.src, "f"), "november")
	h.now = time.Date(2026, 11, 1, 0, 30, 0, 0, time.UTC)
	nov := h.backup(nil)
	if !nov.Opened || nov.Reason != format.ReasonMonth || nov.Class != format.ClassOpening || nov.Epoch.EpochID == oct.Epoch.EpochID {
		t.Fatalf("the month turn: opened %v, reason %s, class %s", nov.Opened, nov.Reason, nov.Class)
	}
	if !strings.HasPrefix(nov.Epoch.EpochID, "e202611-") {
		t.Fatalf("the new epoch is %s", nov.Epoch.EpochID)
	}
	if nov.ReadBytes == 0 {
		t.Fatal("the opening run of the new month read nothing")
	}
	old, _, _ := h.restore(oct.Epoch.EpochID, oct.Snapshot.SnapshotID, nil)
	fresh, _, _ := h.restore(nov.Epoch.EpochID, nov.Snapshot.SnapshotID, nil)
	if old["f"].value == fresh["f"].value {
		t.Fatal("the two epochs restore the same bytes")
	}
	// The cache of the old epoch is gone once the new one's opening run is
	// complete.
	left, _ := filepath.Glob(filepath.Join(h.state, "cache", "files-test", "*.db"))
	if len(left) != 1 {
		t.Fatalf("cache files left: %v", left)
	}
}
