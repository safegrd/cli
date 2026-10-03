package catalog

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/policy"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/write"
)

func TestVersionsJoinAcrossEpochsBySHA256(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	src := t.TempDir()
	src, _ = filepath.EvalSymlinks(src)
	st, _ := sink.NewDir(t.TempDir(), "n")
	b := sink.NewDirect(st)
	state := t.TempDir()
	at := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	n := 0
	backup := func(newEpoch bool) {
		n++
		now := at.Add(time.Duration(n) * time.Hour)
		snap := "snap-" + string(rune('a'+n))
		_, err := write.Run(context.Background(), b, write.Options{
			SurfaceID: "s", Roots: []string{src}, StateDir: state, Recipient: id.Recipient().String(),
			Retention: policy.Retention{Days: 7}, Tier: format.TierBase, Planned: now.Add(7 * 24 * time.Hour),
			SnapshotID: snap, NewEpoch: newEpoch, Now: func() time.Time { return now },
			Sidecar: func(r *write.Result) ([]byte, error) { return json.Marshal(map[string]string{"snapshot_id": snap}) },
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	w := func(name, body string) {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("same.conf", "unchanged")
	w("nginx.conf", "v1")
	w("gone.txt", "bye")
	backup(false) // b
	w("nginx.conf", "v2")
	backup(false) // c
	_ = os.Remove(filepath.Join(src, "gone.txt"))
	backup(true) // d, a new epoch
	w("nginx.conf", "v3")
	backup(false) // e

	es, _ := b.Epochs(context.Background(), "s")
	if len(es) != 2 {
		t.Fatalf("%d epochs", len(es))
	}
	srcRel := strings.TrimPrefix(src, "/")
	cache := filepath.Join(t.TempDir(), "cat")
	s := Source{Backend: b, Epochs: es, IDs: []age.Identity{id}, CacheDir: cache}
	hs, snaps, err := s.Find(context.Background(), []string{srcRel + "/*"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 4 {
		t.Fatalf("%d snapshots", len(snaps))
	}
	by := map[string]History{}
	for _, h := range hs {
		by[filepath.Base(h.Path)] = h
	}
	same := by["same.conf"]
	if len(same.Versions) != 1 || same.Versions[0].Snapshots != 4 || same.Versions[0].Epochs != 2 || !same.Versions[0].Current {
		t.Fatalf("an unchanged file across epochs: %+v", same)
	}
	ng := by["nginx.conf"]
	if len(ng.Versions) != 3 || ng.Versions[1].Snapshots != 2 || ng.Versions[1].Epochs != 2 || ng.Versions[2].Last.SnapshotID != "snap-e" {
		t.Fatalf("nginx.conf: %+v", ng)
	}
	gone := by["gone.txt"]
	if !gone.Deleted || gone.Versions[0].Last.SnapshotID != "snap-c" {
		t.Fatalf("a deleted file: %+v", gone)
	}
	del, _, err := s.Find(context.Background(), []string{srcRel + "/"}, true)
	if err != nil || len(del) != 1 || filepath.Base(del[0].Path) != "gone.txt" {
		t.Fatalf("--deleted: %+v %v", del, err)
	}
	// The second search opens nothing: every snapshot and catalog is cached.
	entries, _ := os.ReadDir(cache)
	if len(entries) != 4 {
		t.Fatalf("%d cached runs", len(entries))
	}
}
