//go:build unix

package read_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/policy"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/write"
)

// As root, a restore gives every file, directory and link back its owner,
// after which the mode is set again (a chown can clear permission bits).
func TestOwnersAreRestoredAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("restoring ownership needs root")
	}
	src := t.TempDir()
	src, _ = filepath.EvalSymlinks(src)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(src, "app"), 0o750))
	must(os.WriteFile(filepath.Join(src, "app", "conf"), []byte("x"), 0o640))
	must(os.Symlink("conf", filepath.Join(src, "app", "link")))
	must(os.Lchown(filepath.Join(src, "app"), 1001, 1002))
	must(os.Lchown(filepath.Join(src, "app", "conf"), 1003, 1004))
	must(os.Lchown(filepath.Join(src, "app", "link"), 1005, 1006))
	must(os.Chmod(filepath.Join(src, "app", "conf"), 0o2640&0o777|0o640))

	id, _ := age.GenerateX25519Identity()
	st, _ := sink.NewDir(t.TempDir(), "n")
	b := sink.NewDirect(st)
	now := time.Now()
	res, err := write.Run(context.Background(), b, write.Options{
		SurfaceID: "s", Roots: []string{src}, StateDir: t.TempDir(), Recipient: id.Recipient().String(),
		Retention: policy.Retention{Days: 1}, Tier: format.TierBase, Planned: now.Add(24 * time.Hour), SnapshotID: "snap-1",
		Sidecar: func(*write.Result) ([]byte, error) { return json.Marshal(map[string]string{}) },
	})
	if err != nil {
		t.Fatal(err)
	}
	es, _ := b.Epochs(context.Background(), "s")
	r := read.Open(b, es[0], []age.Identity{id})
	snap, _ := r.Snapshot(context.Background(), res.Snapshot.SnapshotID)
	idx, _ := r.LoadIndex(context.Background(), snap)
	target := filepath.Join(t.TempDir(), "out")
	rr, err := r.Restore(context.Background(), snap, idx, read.RestoreOptions{Target: target})
	if err != nil {
		t.Fatal(err)
	}
	if !rr.OwnershipRestored {
		t.Fatalf("as root, owners were not reapplied: %s", rr.OwnershipNote)
	}
	base := filepath.Join(target, strings.TrimPrefix(src, "/"))
	for p, want := range map[string][2]uint32{"app": {1001, 1002}, "app/conf": {1003, 1004}, "app/link": {1005, 1006}} {
		fi, err := os.Lstat(filepath.Join(base, p))
		if err != nil {
			t.Fatal(err)
		}
		s := fi.Sys().(*syscall.Stat_t)
		if s.Uid != want[0] || s.Gid != want[1] {
			t.Errorf("%s restored as %d:%d, backed up as %d:%d", p, s.Uid, s.Gid, want[0], want[1])
		}
	}
	if fi, _ := os.Stat(filepath.Join(base, "app", "conf")); fi.Mode().Perm() != 0o640 {
		t.Errorf("app/conf restored as %o after its owner", fi.Mode().Perm())
	}
}
