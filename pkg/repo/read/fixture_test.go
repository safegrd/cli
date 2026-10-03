package read_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/repo/check"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/policy"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/write"
)

// The committed fixture is a version 1 epoch with two snapshots, written once
// by the writer of the release that froze the format. Every later release
// must restore it exactly: snapshots are kept for years, and a reader that
// stops understanding them has lost them.
//
// To regenerate it, which is only ever right when the format version
// changes and a new directory is added beside this one:
//
//	REPO_FIXTURE_WRITE=1 go test ./pkg/repo/read/ -run TestCommittedFixture
const fixtureDir = "../testdata/v1"

type fixtureEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	Mode   uint32 `json:"mode"`
	Target string `json:"target,omitempty"`
}

type fixtureSnapshot struct {
	SnapshotID  string         `json:"snapshot_id"`
	EpochID     string         `json:"epoch_id"`
	Root        string         `json:"root"`
	ContentRoot string         `json:"content_root"`
	Entries     []fixtureEntry `json:"entries"`
}

func walkFixture(t *testing.T, root string) []fixtureEntry {
	t.Helper()
	var out []fixtureEntry
	err := filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
		if err != nil || p == root {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fi, _ := os.Lstat(p)
		e := fixtureEntry{Path: filepath.ToSlash(rel), Mode: uint32(fi.Mode().Perm())}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			e.Type, e.Mode = "l", 0
			e.Target, _ = os.Readlink(p)
		case fi.IsDir():
			e.Type = "d"
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			s := sha256.Sum256(b)
			e.Type, e.Value = "f", hex.EncodeToString(s[:])
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func writeFixture(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	_ = os.RemoveAll(fixtureDir)
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "identity.txt"), []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "src")
	at := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	mk := func(p string, body []byte, mode fs.FileMode) {
		full := filepath.Join(src, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, body, mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(full, at, at)
	}
	big := make([]byte, 1600<<10)
	for i := range big {
		big[i] = byte(i * 7 % 251)
	}
	mk("etc/hosts", []byte("127.0.0.1 localhost\n"), 0o644)
	mk("etc/secret.conf", []byte("token=fixture\n"), 0o600)
	mk("var/www/index.html", []byte("<h1>café</h1>\n"), 0o644)
	mk("var/www/big.bin", big, 0o644)
	mk("var/www/empty.txt", nil, 0o644)
	mk("日本語/ファイル.txt", []byte("unicode\n"), 0o640)
	_ = os.MkdirAll(filepath.Join(src, "empty-dir"), 0o750)
	_ = os.Symlink("../etc/hosts", filepath.Join(src, "var/hosts-link"))
	_ = os.Chmod(filepath.Join(src, "etc"), 0o700)

	src, _ = filepath.EvalSymlinks(src)
	st, err := sink.NewDir(filepath.Join(fixtureDir, "sink"), "node-fixture")
	if err != nil {
		t.Fatal(err)
	}
	b := sink.NewDirect(st)
	state := t.TempDir()
	var snaps []fixtureSnapshot
	for i, mutate := range []func(){
		func() {},
		func() {
			mk("etc/hosts", []byte("127.0.0.1 localhost\n10.0.0.2 db\n"), 0o644)
			_ = os.Remove(filepath.Join(src, "var/www/empty.txt"))
			big[1<<20] ^= 0xff
			mk("var/www/big.bin", big, 0o644)
		},
	} {
		mutate()
		now := at.Add(time.Duration(i) * time.Hour)
		snapID := []string{"snap-fixture-opening", "snap-fixture-later"}[i]
		res, err := write.Run(context.Background(), b, write.Options{
			SurfaceID: "files-fixture", Roots: []string{src}, StateDir: state, Recipient: id.Recipient().String(),
			Retention: policy.Retention{Days: 7}, Tier: format.TierBase, Planned: now.Add(7 * 24 * time.Hour),
			SnapshotID: snapID, Host: "fixture-host", Now: func() time.Time { return now },
			Sidecar: func(r *write.Result) ([]byte, error) {
				return json.Marshal(map[string]any{"snapshot_id": snapID, "format": format.SidecarFormat,
					"epoch_id": r.Epoch.EpochID, "object_class": r.Class, "sha256_checksum": r.Snapshot.ContentRoot,
					"worm_retention_until": r.Snapshot.RetainUntil})
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		snaps = append(snaps, fixtureSnapshot{SnapshotID: snapID, EpochID: res.Epoch.EpochID, Root: src,
			ContentRoot: res.Snapshot.ContentRoot, Entries: walkFixture(t, src)})
	}
	body, _ := json.MarshalIndent(snaps, "", "  ")
	if err := os.WriteFile(filepath.Join(fixtureDir, "oracle.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	// Committed files are read-write in git; the store wrote them 0400.
	_ = filepath.WalkDir(fixtureDir, func(p string, de fs.DirEntry, err error) error {
		if err == nil && !de.IsDir() {
			_ = os.Chmod(p, 0o644)
		}
		return nil
	})
}

func TestCommittedFixtureStillRestores(t *testing.T) {
	if os.Getenv("REPO_FIXTURE_WRITE") == "1" {
		writeFixture(t)
	}
	keyBytes, err := os.ReadFile(filepath.Join(fixtureDir, "identity.txt"))
	if err != nil {
		t.Fatalf("the committed fixture is missing: %v", err)
	}
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(keyBytes)))
	if err != nil {
		t.Fatal(err)
	}
	var snaps []fixtureSnapshot
	body, err := os.ReadFile(filepath.Join(fixtureDir, "oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &snaps); err != nil {
		t.Fatal(err)
	}
	st, err := sink.NewDir(filepath.Join(fixtureDir, "sink"), "node-fixture")
	if err != nil {
		t.Fatal(err)
	}
	b := sink.NewDirect(st)
	es, err := b.Epochs(context.Background(), "files-fixture")
	if err != nil || len(es) != 1 {
		t.Fatalf("epochs: %v %v", es, err)
	}
	ids := []age.Identity{id}
	for _, want := range snaps {
		r := read.Open(b, es[0], ids)
		snap, err := r.Snapshot(context.Background(), want.SnapshotID)
		if err != nil {
			t.Fatal(err)
		}
		if snap.ContentRoot != want.ContentRoot {
			t.Fatalf("%s: content root %s, the fixture recorded %s", want.SnapshotID, snap.ContentRoot, want.ContentRoot)
		}
		idx, err := r.LoadIndex(context.Background(), snap)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "out")
		if _, err := r.Restore(context.Background(), snap, idx, read.RestoreOptions{Target: target}); err != nil {
			t.Fatalf("%s: %v", want.SnapshotID, err)
		}
		got := walkFixture(t, filepath.Join(target, strings.TrimPrefix(want.Root, "/")))
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(want.Entries)
		if string(gj) != string(wj) {
			t.Fatalf("%s restores differently:\n got %s\nwant %s", want.SnapshotID, gj, wj)
		}
		root, _, err := check.DirContentRoot(target)
		if err != nil || root != want.ContentRoot {
			t.Fatalf("%s: the restored files give content root %s (%v), the fixture %s", want.SnapshotID, root, err, want.ContentRoot)
		}
		rep, err := check.Snapshot(context.Background(), b, es[0], want.SnapshotID, ids, check.Options{ReadData: true})
		if err != nil || !rep.OK() {
			t.Fatalf("%s: check: %v %v", want.SnapshotID, err, rep.Problems)
		}
	}
}
