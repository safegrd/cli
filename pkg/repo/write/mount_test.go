package write_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/write"
)

// An app's database streams in and its uploads are walked into the same
// snapshot: the walked files keep their modes, the excludes are matched from
// the app's root, and an unchanged upload is not read again.
func TestAMountIsWalkedIntoASourceRun(t *testing.T) {
	h := newHarness(t)
	app := filepath.Join(h.src, "app")
	uploads := filepath.Join(app, "storage", "app")
	for _, d := range []string{filepath.Join(uploads, "public"), filepath.Join(uploads, "backup-temp")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	photo := bytes.Repeat([]byte("jpeg"), 4096)
	if err := os.WriteFile(filepath.Join(uploads, "public", "photo.jpg"), photo, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uploads, "backup-temp", "half.zip"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := func(o *write.Options) {
		o.Roots = nil
		o.Source = streams(map[string][]byte{"db/dump.sql": []byte("CREATE TABLE t (id int);\n"), "files/.env": []byte("APP_KEY=x\n")})
		o.Mounts = []write.Mount{{Path: "files/storage/app", Dir: uploads, ExcludeBase: app}}
		o.Excludes = []string{"storage/app/backup-temp"}
	}
	first := h.backup(opts)
	got := h.catAll(first.Epoch.EpochID, first.Snapshot.SnapshotID)
	if !bytes.Equal(got["files/storage/app/public/photo.jpg"], photo) {
		t.Fatalf("the walked file did not read back; the snapshot holds %d files", len(got))
	}
	if string(got["files/.env"]) != "APP_KEY=x\n" || string(got["db/dump.sql"]) == "" {
		t.Fatal("the source's files did not read back beside the mount")
	}
	if _, ok := got["files/storage/app/backup-temp/half.zip"]; ok {
		t.Fatal("storage/app/backup-temp was stored: an exclude relative to the app's root did not match inside the mount")
	}
	if rep := h.check(first.Epoch.EpochID, first.Snapshot.SnapshotID, true); !rep.OK() {
		t.Fatalf("check: %v", rep.Err())
	}

	ctx := context.Background()
	r := read.Open(h.b, h.epoch(first.Epoch.EpochID), h.ids)
	snap, err := r.Snapshot(ctx, first.Snapshot.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := r.LoadIndex(ctx, snap)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := format.ParseID(snap.RootTree)
	var mode uint32
	_ = r.Walk(ctx, idx, root, func(it read.Item) error {
		if it.Path == "files/storage/app/public/photo.jpg" {
			mode = it.Node.Mode
		}
		return nil
	})
	if mode != 0o640 {
		t.Errorf("the walked file is stored with mode %o, it has 0640 on disk", mode)
	}

	second := h.backup(opts)
	// The two streams are read every run; the photo is carried by the cache.
	if second.ChangedFiles != 2 {
		t.Errorf("an unchanged mount read %d files again, want only the 2 streams", second.ChangedFiles)
	}
}

func TestAMountNeedsASourceAndAPlaceOfItsOwn(t *testing.T) {
	h := newHarness(t)
	if _, err := write.Run(context.Background(), h.b, h.opts(func(o *write.Options) {
		o.Mounts = []write.Mount{{Path: "files", Dir: h.src}}
	})); err == nil {
		t.Fatal("a run with roots and a mount was accepted")
	}
	if _, err := write.Run(context.Background(), h.b, h.opts(func(o *write.Options) {
		o.Roots, o.Source = nil, streams(map[string][]byte{"files/x": []byte("x")})
		o.Mounts = []write.Mount{{Path: "files/x", Dir: h.src}}
	})); err == nil {
		t.Fatal("a mount over a streamed file was accepted")
	}
}
