package write_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/rand"
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

// oracleEntry is what the test's own walk sees: no engine code is involved.
type oracleEntry struct {
	typ   string
	value string
	mode  fs.FileMode
}

func oracle(t *testing.T, root string) map[string]oracleEntry {
	t.Helper()
	out := map[string]oracleEntry{}
	err := filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			tgt, _ := os.Readlink(p)
			out[rel] = oracleEntry{"l", tgt, 0}
		case fi.IsDir():
			out[rel] = oracleEntry{"d", "", fi.Mode().Perm()}
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			s := sha256.Sum256(b)
			out[rel] = oracleEntry{"f", hex.EncodeToString(s[:]), fi.Mode().Perm()}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func diffOracle(want, got map[string]oracleEntry) string {
	var b strings.Builder
	for p, w := range want {
		g, ok := got[p]
		if !ok {
			fmt.Fprintf(&b, "missing %q; ", p)
			continue
		}
		if g != w {
			fmt.Fprintf(&b, "%q: want %+v got %+v; ", p, w, g)
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			fmt.Fprintf(&b, "extra %q; ", p)
		}
	}
	return b.String()
}

type harness struct {
	t        *testing.T
	src      string
	state    string
	b        sink.Backend
	store    *sink.Dir
	rec, key string
	ids      []age.Identity
	retain   policy.Retention
	now      time.Time
	seq      int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	src, _ = filepath.EvalSymlinks(src)
	st, err := sink.NewDir(filepath.Join(dir, "sink"), "node-1")
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, src: src, state: filepath.Join(dir, "state"), b: sink.NewDirect(st), store: st,
		rec: id.Recipient().String(), key: id.String(), ids: []age.Identity{id},
		retain: policy.Retention{Days: 7}, now: time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)}
}

func sidecarFor(r *write.Result) ([]byte, error) {
	return json.Marshal(map[string]any{
		"snapshot_id": r.Snapshot.SnapshotID, "format": format.SidecarFormat, "epoch_id": r.Epoch.EpochID,
		"object_class": r.Class, "sha256_checksum": r.Snapshot.ContentRoot, "worm_retention_until": r.Snapshot.RetainUntil,
	})
}

func (h *harness) opts(extra func(*write.Options)) write.Options {
	h.seq++
	h.now = h.now.Add(time.Hour)
	at := h.now
	o := write.Options{
		SurfaceID: "files-test", Roots: []string{h.src}, StateDir: h.state, Recipient: h.rec,
		Retention: h.retain, Tier: format.TierBase, Planned: at.Add(7 * 24 * time.Hour),
		SnapshotID: fmt.Sprintf("snap-%04d", h.seq), Host: "test", Now: func() time.Time { return at },
		Sidecar: sidecarFor, Concurrency: 2,
	}
	if extra != nil {
		extra(&o)
	}
	return o
}

func (h *harness) backup(extra func(*write.Options)) *write.Result {
	h.t.Helper()
	res, err := write.Run(context.Background(), h.b, h.opts(extra))
	if err != nil {
		h.t.Fatalf("backup: %v", err)
	}
	return res
}

func (h *harness) epoch(id string) sink.EpochInfo {
	h.t.Helper()
	es, err := h.b.Epochs(context.Background(), "files-test")
	if err != nil {
		h.t.Fatal(err)
	}
	for _, e := range es {
		if e.Epoch.EpochID == id {
			return e
		}
	}
	h.t.Fatalf("epoch %s not listed", id)
	return sink.EpochInfo{}
}

// restore restores a whole snapshot and returns the oracle of the source
// root's copy inside the target.
func (h *harness) restore(epochID, snapID string, paths []string) (map[string]oracleEntry, string, *read.RestoreResult) {
	h.t.Helper()
	e := h.epoch(epochID)
	r := read.Open(h.b, e, h.ids)
	snap, err := r.Snapshot(context.Background(), snapID)
	if err != nil {
		h.t.Fatal(err)
	}
	idx, err := r.LoadIndex(context.Background(), snap)
	if err != nil {
		h.t.Fatal(err)
	}
	target := filepath.Join(h.t.TempDir(), "out")
	res, err := r.Restore(context.Background(), snap, idx, read.RestoreOptions{Target: target, Paths: paths})
	if err != nil {
		h.t.Fatalf("restore %s: %v", snapID, err)
	}
	return oracle(h.t, filepath.Join(target, strings.TrimPrefix(h.src, "/"))), target, res
}

func (h *harness) check(epochID, snapID string, readData bool) *check.Report {
	h.t.Helper()
	rep, err := check.Snapshot(context.Background(), h.b, h.epoch(epochID), snapID, h.ids, check.Options{ReadData: readData})
	if err != nil {
		h.t.Fatal(err)
	}
	return rep
}

// mutator applies seeded random operations to a tree.
type mutator struct {
	rng      *rand.Rand
	root     string
	rawNames bool
}

func (m *mutator) files() []string {
	var out []string
	_ = filepath.WalkDir(m.root, func(p string, de fs.DirEntry, err error) error {
		if err == nil && de.Type().IsRegular() {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func (m *mutator) dirs() []string {
	out := []string{m.root}
	_ = filepath.WalkDir(m.root, func(p string, de fs.DirEntry, err error) error {
		if err == nil && de.IsDir() && p != m.root {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func (m *mutator) name() string {
	names := []string{"a", "b.txt", "data.bin", "café", "日本語", "with space", "100%", "UPPER", "z-last", ".hidden", "a-c", "a.c"}
	n := names[m.rng.Intn(len(names))]
	if m.rawNames && m.rng.Intn(10) == 0 {
		n = "raw\xe9\xff"
	}
	return fmt.Sprintf("%s%d", n, m.rng.Intn(50))
}

func (m *mutator) content(n int) []byte {
	b := make([]byte, n)
	if m.rng.Intn(3) == 0 {
		for i := range b {
			b[i] = byte('a' + i%7)
		}
		return b
	}
	m.rng.Read(b)
	return b
}

func (m *mutator) size() int {
	switch m.rng.Intn(10) {
	case 0:
		return 0
	case 1:
		return 1
	case 2, 3:
		return 600<<10 + m.rng.Intn(3<<20)
	default:
		return m.rng.Intn(64 << 10)
	}
}

func (m *mutator) pick(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[m.rng.Intn(len(xs))]
}

func (m *mutator) apply(t *testing.T, ops int) {
	t.Helper()
	modes := []fs.FileMode{0o600, 0o644, 0o640, 0o755, 0o700}
	for i := 0; i < ops; i++ {
		files, dirs := m.files(), m.dirs()
		switch m.rng.Intn(12) {
		case 0, 1: // create
			p := filepath.Join(m.pick(dirs), m.name())
			if _, err := os.Lstat(p); err == nil {
				continue
			}
			_ = os.WriteFile(p, m.content(m.size()), modes[m.rng.Intn(len(modes))])
		case 2: // append
			if f := m.pick(files); f != "" {
				fh, err := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0)
				if err == nil {
					fh.Write(m.content(1 + m.rng.Intn(70<<10)))
					fh.Close()
				}
			}
		case 3: // insert in the middle
			if f := m.pick(files); f != "" {
				b, _ := os.ReadFile(f)
				at := 0
				if len(b) > 0 {
					at = m.rng.Intn(len(b))
				}
				nb := append(append(append([]byte{}, b[:at]...), m.content(1+m.rng.Intn(100))...), b[at:]...)
				_ = os.WriteFile(f, nb, 0)
			}
		case 4: // truncate
			if f := m.pick(files); f != "" {
				fi, _ := os.Stat(f)
				if fi != nil && fi.Size() > 0 {
					_ = os.Truncate(f, m.rng.Int63n(fi.Size()))
				}
			}
		case 5: // rewrite the same size, keeping the mtime
			if f := m.pick(files); f != "" {
				fi, _ := os.Stat(f)
				if fi != nil && fi.Size() > 0 {
					_ = os.WriteFile(f, m.content(int(fi.Size())), 0)
					_ = os.Chtimes(f, fi.ModTime(), fi.ModTime())
				}
			}
		case 6: // rename
			if f := m.pick(files); f != "" {
				dst := filepath.Join(m.pick(dirs), m.name())
				if _, err := os.Lstat(dst); err != nil {
					_ = os.Rename(f, dst)
				}
			}
		case 7: // delete
			if f := m.pick(files); f != "" {
				_ = os.Remove(f)
			}
		case 8: // chmod
			if f := m.pick(files); f != "" {
				_ = os.Chmod(f, modes[m.rng.Intn(len(modes))])
			}
		case 9: // symlink create or retarget
			p := filepath.Join(m.pick(dirs), "link"+fmt.Sprint(m.rng.Intn(5)))
			_ = os.Remove(p)
			targets := []string{"../elsewhere", "b.txt", "/etc/passwd", "dangling/target", "日本"}
			_ = os.Symlink(targets[m.rng.Intn(len(targets))], p)
		case 10: // directories: empty, deep, chmod
			d := m.pick(dirs)
			switch m.rng.Intn(3) {
			case 0:
				_ = os.Mkdir(filepath.Join(d, "empty"+fmt.Sprint(m.rng.Intn(5))), 0o755)
			case 1:
				deep := d
				for j := 0; j < 1+m.rng.Intn(12); j++ {
					deep = filepath.Join(deep, fmt.Sprintf("d%d", j))
				}
				_ = os.MkdirAll(deep, 0o755)
				_ = os.WriteFile(filepath.Join(deep, "leaf"), m.content(m.rng.Intn(4096)), 0o644)
			case 2:
				if d != m.root {
					_ = os.Chmod(d, []fs.FileMode{0o755, 0o700, 0o750}[m.rng.Intn(3)])
				}
			}
		case 11: // remove a directory tree
			if d := m.pick(dirs); d != m.root && m.rng.Intn(3) == 0 {
				_ = os.RemoveAll(d)
			}
		}
	}
}

func canMakeRawNames(t *testing.T) bool {
	p := filepath.Join(t.TempDir(), "raw\xe9")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		return false
	}
	return true
}

func seed(t *testing.T) int64 {
	s := time.Now().UnixNano()
	if v := os.Getenv("REPO_SEED"); v != "" {
		fmt.Sscan(v, &s)
	}
	t.Logf("seed %d (rerun with REPO_SEED=%d)", s, s)
	return s
}

func TestEveryGenerationRestoresExactly(t *testing.T) {
	s := seed(t)
	h := newHarness(t)
	m := &mutator{rng: rand.New(rand.NewSource(s)), root: h.src, rawNames: canMakeRawNames(t)}
	gens := 20
	if testing.Short() {
		gens = 6
	}
	type gen struct {
		epoch, snap string
		want        map[string]oracleEntry
	}
	var all []gen
	for g := 0; g < gens; g++ {
		m.apply(t, 25)
		want := oracle(t, h.src)
		res := h.backup(nil)
		all = append(all, gen{res.Epoch.EpochID, res.Snapshot.SnapshotID, want})
		if g == 0 && res.Class != format.ClassOpening {
			t.Fatalf("seed %d: the first run was of class %s", s, res.Class)
		}
		if g > 0 && res.Class != format.ClassLater {
			t.Fatalf("seed %d: run %d was of class %s", s, g, res.Class)
		}
	}
	for i, g := range all {
		got, _, _ := h.restore(g.epoch, g.snap, nil)
		if d := diffOracle(g.want, got); d != "" {
			t.Fatalf("seed %d: generation %d restores wrong: %s", s, i, d)
		}
		if rep := h.check(g.epoch, g.snap, i == len(all)-1); !rep.OK() {
			t.Fatalf("seed %d: generation %d fails check: %v", s, i, rep.Problems)
		}
	}
}

// R3: an unchanged file is not read, and an unchanged tree uploads nothing
// but the run's metadata.
func TestAnUnchangedTreeUploadsOnlyMetadata(t *testing.T) {
	h := newHarness(t)
	m := &mutator{rng: rand.New(rand.NewSource(1)), root: h.src}
	m.apply(t, 60)
	first := h.backup(nil)
	if first.ReadBytes == 0 {
		t.Fatal("the opening run read nothing")
	}
	second := h.backup(nil)
	if second.ReadBytes != 0 || second.ChangedFiles != 0 {
		t.Fatalf("an unchanged tree read %d bytes of %d files", second.ReadBytes, second.ChangedFiles)
	}
	if second.Snapshot.Stats.NewPacks > 1 {
		t.Fatalf("an unchanged tree wrote %d packs", second.Snapshot.Stats.NewPacks)
	}
	if second.Snapshot.ContentRoot != first.Snapshot.ContentRoot {
		t.Fatal("the content root of an unchanged tree changed")
	}
}

func TestAOneByteChangeStoresOneChunk(t *testing.T) {
	h := newHarness(t)
	big := make([]byte, 20<<20)
	rand.New(rand.NewSource(3)).Read(big)
	p := filepath.Join(h.src, "big.bin")
	if err := os.WriteFile(p, big, 0o644); err != nil {
		t.Fatal(err)
	}
	h.backup(nil)
	big[10<<20] ^= 0xff
	if err := os.WriteFile(p, big, 0o644); err != nil {
		t.Fatal(err)
	}
	res := h.backup(nil)
	// One data pack holding the changed chunk, one tree pack.
	if res.Snapshot.Stats.NewPacks > 2 {
		t.Fatalf("a one-byte change wrote %d packs", res.Snapshot.Stats.NewPacks)
	}
	var packBytes int64
	objs, _ := h.b.List(context.Background(), h.epoch(res.Epoch.EpochID), "packs")
	for _, o := range objs {
		packBytes += o.Size
	}
	if res.WrittenBytes > 9<<20 {
		t.Fatalf("a one-byte change wrote %d bytes", res.WrittenBytes)
	}
}

func TestSinglePathRestoreFetchesOnlyItsFile(t *testing.T) {
	h := newHarness(t)
	rng := rand.New(rand.NewSource(5))
	for i := 0; i < 12; i++ {
		b := make([]byte, 3<<20)
		rng.Read(b)
		_ = os.MkdirAll(filepath.Join(h.src, fmt.Sprintf("d%d", i)), 0o755)
		if err := os.WriteFile(filepath.Join(h.src, fmt.Sprintf("d%d", i), "f.bin"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res := h.backup(nil)
	rel := strings.TrimPrefix(h.src, "/") + "/d7/f.bin"
	got, _, rr := h.restore(res.Epoch.EpochID, res.Snapshot.SnapshotID, []string{rel})
	if len(got) != 2 || got["d7/f.bin"].typ != "f" {
		t.Fatalf("restored %v", got)
	}
	if rr.FetchedBytes > 4<<20 || rr.Fetches > 3 {
		t.Fatalf("one 3 MiB file fetched %d bytes in %d ranges", rr.FetchedBytes, rr.Fetches)
	}
}

func TestADamagedPackFailsCheckAndRestoreLeavesTheTargetUntouched(t *testing.T) {
	h := newHarness(t)
	m := &mutator{rng: rand.New(rand.NewSource(9)), root: h.src}
	m.apply(t, 40)
	res := h.backup(nil)
	e := h.epoch(res.Epoch.EpochID)
	objs, _ := h.b.List(context.Background(), e, "packs")
	// Flip one byte in the middle of the biggest pack: inside a blob record.
	sort.Slice(objs, func(i, j int) bool { return objs[i].Size > objs[j].Size })
	p, _ := h.store.Path(objs[0].Key)
	_ = os.Chmod(p, 0o600)
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 1
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	rep := h.check(res.Epoch.EpochID, res.Snapshot.SnapshotID, true)
	if rep.OK() {
		t.Fatal("check passed over a flipped byte")
	}
	r := read.Open(h.b, e, h.ids)
	snap, _ := r.Snapshot(context.Background(), res.Snapshot.SnapshotID)
	idx, _ := r.LoadIndex(context.Background(), snap)
	target := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Restore(context.Background(), snap, idx, read.RestoreOptions{Target: target}); err == nil {
		t.Fatal("a restore over a flipped byte succeeded")
	}
	left, _ := os.ReadDir(target)
	if len(left) != 0 {
		t.Fatalf("a failed restore left %d entries in the target", len(left))
	}
	// A missing pack is named.
	_ = os.Remove(p)
	rep = h.check(res.Epoch.EpochID, res.Snapshot.SnapshotID, false)
	if rep.OK() || !strings.Contains(strings.Join(rep.Problems, " "), "missing") {
		t.Fatalf("a missing pack: %v", rep.Problems)
	}
}

func TestANewEpochOpensWhenAskedAndOnRetentionIncrease(t *testing.T) {
	h := newHarness(t)
	_ = os.WriteFile(filepath.Join(h.src, "f"), []byte("x"), 0o644)
	a := h.backup(nil)
	b := h.backup(func(o *write.Options) { o.NewEpoch = true })
	if b.Epoch.EpochID == a.Epoch.EpochID || b.Reason != format.ReasonRequested || b.Class != format.ClassOpening {
		t.Fatalf("--new-epoch: %s %s %s", b.Epoch.EpochID, b.Reason, b.Class)
	}
	h.retain.Days = 30
	c := h.backup(nil)
	if c.Epoch.EpochID == b.Epoch.EpochID || c.Reason != format.ReasonRetentionIncreased {
		t.Fatalf("retention increase: %s %s", c.Epoch.EpochID, c.Reason)
	}
	// The cache of the earlier epochs is gone once the new one's opening run
	// completes.
	left, _ := filepath.Glob(filepath.Join(h.state, "cache", "files-test", "*.db"))
	if len(left) != 1 {
		t.Fatalf("cache files left: %v", left)
	}
	// A lost cache opens a new epoch, said as such.
	_ = os.RemoveAll(filepath.Join(h.state, "cache"))
	d := h.backup(nil)
	if d.Reason != format.ReasonCacheLost {
		t.Fatalf("lost cache: reason %s", d.Reason)
	}
	got, _, _ := h.restore(a.Epoch.EpochID, a.Snapshot.SnapshotID, nil)
	if got["f"].typ != "f" {
		t.Fatal("the first epoch no longer restores")
	}
}

func TestAFileChangingDuringTheBackupIsReported(t *testing.T) {
	h := newHarness(t)
	p := filepath.Join(h.src, "growing.log")
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), 4<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
		defer f.Close()
		for {
			select {
			case <-stop:
				return
			default:
				f.Write([]byte("line\n"))
			}
		}
	}()
	res := h.backup(nil)
	close(stop)
	<-done
	if len(res.Snapshot.Inconsistent) != 1 || !strings.HasSuffix(string(res.Snapshot.Inconsistent[0]), "growing.log") {
		t.Fatalf("inconsistent %v", res.Snapshot.Inconsistent)
	}
	// What is restored is exactly one read: a prefix of the file as it is now.
	_, target, _ := h.restore(res.Epoch.EpochID, res.Snapshot.SnapshotID, nil)
	got, _ := os.ReadFile(filepath.Join(target, strings.TrimPrefix(p, "/")))
	now, _ := os.ReadFile(p)
	if !bytes.HasPrefix(now, got) {
		t.Fatal("the restored file is not a read of the file")
	}
}
