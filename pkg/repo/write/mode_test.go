package write_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/repo/catalog"
	"github.com/safegrd/cli/pkg/repo/sink"
)

// A chmod with the content unchanged is not a catalog event and not a
// version: the tree of each snapshot carries its own mode, and restoring a
// snapshot applies it.
func TestAChangeOfModeAloneIsNotAVersion(t *testing.T) {
	h := newHarness(t)
	p := filepath.Join(h.src, "secret.txt")
	if err := os.WriteFile(p, []byte("the same bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	first := h.backup(nil)
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	second := h.backup(nil)
	e := h.epoch(first.Epoch.EpochID)

	c := readCatalog(t, h, e, second.Snapshot.RunID)
	if c.Complete || len(c.Entries) != 0 {
		t.Fatalf("a chmod alone wrote catalog entries: complete=%v %+v", c.Complete, c.Entries)
	}
	for _, id := range []string{first.Snapshot.SnapshotID, second.Snapshot.SnapshotID} {
		if rep := h.check(e.Epoch.EpochID, id, true); !rep.OK() {
			t.Fatalf("snapshot %s fails check: %v", id, rep.Problems)
		}
	}
	rel := strings.TrimPrefix(h.src, "/") + "/secret.txt"
	src := catalog.Source{Backend: h.b, Epochs: []sink.EpochInfo{e}, IDs: h.ids}
	hs, _, err := src.Find(context.Background(), []string{rel}, false)
	if err != nil || len(hs) != 1 || len(hs[0].Versions) != 1 {
		t.Fatalf("find: %+v %v", hs, err)
	}
	if v := hs[0].Versions[0]; v.Snapshots != 2 || v.Mode != 0o644 || !v.Current {
		t.Fatalf("the one version: %+v", v)
	}
	for _, c := range []struct {
		id   string
		mode os.FileMode
	}{{first.Snapshot.SnapshotID, 0o644}, {second.Snapshot.SnapshotID, 0o600}} {
		got, _, _ := h.restore(e.Epoch.EpochID, c.id, nil)
		if got["secret.txt"].mode != c.mode {
			t.Fatalf("snapshot %s restores secret.txt as %o, want %o", c.id, got["secret.txt"].mode, c.mode)
		}
	}
}

// The tree keeps setuid, setgid and the sticky bit (0o7777), and a restore
// puts the sticky bit back always and setuid and setgid only when it put the
// owner back too. Perm() alone dropped all three, so a shared 1777 directory
// came back 0777, where anyone may delete anyone's files.
func TestSpecialModeBitsAreKept(t *testing.T) {
	h := newHarness(t)
	shared := filepath.Join(h.src, "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(h.src, "run.sh")
	if err := os.WriteFile(run, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(run, 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	snap := h.backup(nil)
	_, target, res := h.restore(snap.Epoch.EpochID, snap.Snapshot.SnapshotID, nil)
	base := filepath.Join(target, strings.TrimPrefix(h.src, "/"))
	fi, err := os.Lstat(filepath.Join(base, "shared"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSticky == 0 || fi.Mode().Perm() != 0o777 {
		t.Fatalf("shared restored as %v, want drwxrwxrwt", fi.Mode())
	}
	fi, err = os.Lstat(filepath.Join(base, "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if setuid := fi.Mode()&os.ModeSetuid != 0; setuid != res.OwnershipRestored {
		t.Fatalf("run.sh restored as %v with owners restored %v: setuid only with its owner", fi.Mode(), res.OwnershipRestored)
	}
}
