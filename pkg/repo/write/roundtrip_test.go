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
	"reflect"
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
// The time is to the millisecond, the precision a tree records.
type oracleEntry struct {
	typ   string
	value string
	mode  fs.FileMode
	mtime int64
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
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		mt := fi.ModTime().UnixMilli()
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			tgt, err := os.Readlink(p)
			if err != nil {
				return err
			}
			out[rel] = oracleEntry{"l", tgt, 0, mt}
		case fi.IsDir():
			out[rel] = oracleEntry{"d", "", fi.Mode().Perm(), mt}
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			s := sha256.Sum256(b)
			out[rel] = oracleEntry{"f", hex.EncodeToString(s[:]), fi.Mode().Perm(), mt}
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
				b, _ := os.ReadFile(f) // ignored: a file another operation removed is a case the mutator may produce
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

// sha256Hex is the oracle's value for a file holding s.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// flipMiddleByte changes one byte in the middle of a stored object, inside a
// blob record for a pack of any size, and returns its path.
func flipMiddleByte(t *testing.T, h *harness, key string) string {
	t.Helper()
	p, err := h.store.Path(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 1
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
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
	// The chunk holding the byte is stored again, and with it at most the
	// chunk a moved boundary merged into it: never more than one chunk of
	// the maximum size, against 20 MiB of file.
	if res.Snapshot.Stats.NewBytes == 0 || res.Snapshot.Stats.NewBytes > int64(format.DefaultChunker.Max) {
		t.Fatalf("a one-byte change stored %d new bytes of chunks", res.Snapshot.Stats.NewBytes)
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
	if want := oracle(t, h.src)["d7/f.bin"]; len(got) != 2 || got["d7/f.bin"] != want {
		t.Fatalf("restored %v, want d7 and d7/f.bin as %+v", got, want)
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
	objs, err := h.b.List(context.Background(), e, "packs")
	if err != nil || len(objs) == 0 {
		t.Fatalf("packs: %v %v", objs, err)
	}
	// Flip one byte in the middle of the biggest pack: inside a blob record.
	sort.Slice(objs, func(i, j int) bool { return objs[i].Size > objs[j].Size })
	p := flipMiddleByte(t, h, objs[0].Key)
	rep := h.check(res.Epoch.EpochID, res.Snapshot.SnapshotID, true)
	if rep.OK() {
		t.Fatal("check passed over a flipped byte")
	}
	r := read.Open(h.b, e, h.ids)
	snap, err := r.Snapshot(context.Background(), res.Snapshot.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := r.LoadIndex(context.Background(), snap)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Restore(context.Background(), snap, idx, read.RestoreOptions{Target: target}); err == nil || !strings.Contains(err.Error(), "does not authenticate") {
		t.Fatalf("a restore over a flipped byte: %v, want the blob refused", err)
	}
	left, err := os.ReadDir(target)
	if err != nil || len(left) != 0 {
		t.Fatalf("a failed restore left %d entries in the target", len(left))
	}
	// A missing pack is named.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	rep = h.check(res.Epoch.EpochID, res.Snapshot.SnapshotID, false)
	if rep.OK() || !strings.Contains(strings.Join(rep.Problems, " "), "missing") {
		t.Fatalf("a missing pack: %v", rep.Problems)
	}
}

func TestANewEpochOpensWhenAskedAndOnRetentionIncrease(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(filepath.Join(h.src, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
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
	left, err := filepath.Glob(filepath.Join(h.state, "cache", "files-test", "*.db"))
	if err != nil || len(left) != 1 {
		t.Fatalf("cache files left: %v", left)
	}
	// A lost cache opens a new epoch, said as such.
	_ = os.RemoveAll(filepath.Join(h.state, "cache"))
	d := h.backup(nil)
	if d.Reason != format.ReasonCacheLost {
		t.Fatalf("lost cache: reason %s", d.Reason)
	}
	got, _, _ := h.restore(a.Epoch.EpochID, a.Snapshot.SnapshotID, nil)
	if got["f"].value != sha256Hex("x") {
		t.Fatalf("the first epoch no longer restores: %+v", got["f"])
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
	writeErr := make(chan error, 1)
	go func() {
		defer close(done)
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			writeErr <- err
			return
		}
		defer f.Close()
		for {
			select {
			case <-stop:
				return
			default:
				if _, err := f.Write([]byte("line\n")); err != nil {
					writeErr <- err
					return
				}
			}
		}
	}()
	res := h.backup(nil)
	close(stop)
	<-done
	select {
	case err := <-writeErr:
		t.Fatalf("the writer stopped: %v", err)
	default:
	}
	if len(res.Snapshot.Inconsistent) != 1 || !strings.HasSuffix(string(res.Snapshot.Inconsistent[0]), "growing.log") {
		t.Fatalf("inconsistent %v", res.Snapshot.Inconsistent)
	}
	// What is restored is exactly one read: a prefix of the file as it is now.
	_, target, _ := h.restore(res.Epoch.EpochID, res.Snapshot.SnapshotID, nil)
	got, err := os.ReadFile(filepath.Join(target, strings.TrimPrefix(p, "/")))
	if err != nil {
		t.Fatalf("the changing file was not restored: %v", err)
	}
	now, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 4<<20 || !bytes.HasPrefix(now, got) {
		t.Fatalf("the restored file (%d bytes) is not a read of the file (%d bytes now, 4 MiB before the run)", len(got), len(now))
	}
}

// A run asked to skip when nothing changed writes nothing and leaves the
// cache as it was: the next run that does change something is a normal run,
// and every snapshot restores.
func TestARunWithNothingChangedWritesNothingWhenAskedTo(t *testing.T) {
	h := newHarness(t)
	m := &mutator{rng: rand.New(rand.NewSource(5)), root: h.src}
	m.apply(t, 40)
	skip := func(o *write.Options) { o.SkipIfUnchanged = true }
	count := func() int {
		n := 0
		_ = filepath.WalkDir(filepath.Join(filepath.Dir(h.state), "sink"), func(_ string, d os.DirEntry, _ error) error {
			if d != nil && !d.IsDir() {
				n++
			}
			return nil
		})
		return n
	}
	first := h.backup(skip)
	if first.Skipped {
		t.Fatal("the opening run of an epoch was skipped")
	}
	before := count()
	// A file written next to the root moves its parent's time, which is
	// not part of the backup.
	if err := os.WriteFile(filepath.Join(filepath.Dir(h.src), "sibling"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := h.backup(skip)
	if !second.Skipped {
		t.Fatalf("an unchanged tree was not skipped: %d new packs", second.Snapshot.Stats.NewPacks)
	}
	if after := count(); after != before {
		t.Fatalf("a skipped run wrote %d objects", after-before)
	}
	m.apply(t, 5)
	third := h.backup(skip)
	if third.Skipped {
		t.Fatal("a changed tree was skipped")
	}
	got, _, _ := h.restore(third.Epoch.EpochID, third.Snapshot.SnapshotID, nil)
	if want := oracle(t, h.src); !reflect.DeepEqual(got, want) {
		t.Fatal("the run after a skipped one does not restore as the source")
	}
}

// A renamed directory is read again, since the cache is by path, and its
// files store nothing new: they are counted as read again, not changed. A
// file written in the same run is counted as changed.
func TestARenamedDirectoryIsReadAgainNotChanged(t *testing.T) {
	h := newHarness(t)
	dir := filepath.Join(h.src, "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("r%d.txt", i)), bytes.Repeat([]byte{byte('a' + i)}, 4096), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h.backup(nil)
	if err := os.Rename(dir, filepath.Join(h.src, "archive")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.src, "new.txt"), []byte("written after the first run"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := h.backup(nil)
	if second.ChangedFiles != 1 || second.ReReadFiles != 5 {
		t.Fatalf("after renaming a directory of 5 files and writing one: %d changed, %d read again; want 1 and 5",
			second.ChangedFiles, second.ReReadFiles)
	}
}

// A salvage restore brings back every file that verifies when one pack is
// altered or gone, leaves the rest out of the target, and names each with
// its reason. Without it the same restore writes nothing.
func TestASalvageRestoreKeepsWhatVerifiesAndNamesTheRest(t *testing.T) {
	h := newHarness(t)
	rng := rand.New(rand.NewSource(11))
	want := map[string][]byte{}
	for i := 0; i < 12; i++ {
		b := make([]byte, 3<<20)
		rng.Read(b)
		rel := fmt.Sprintf("d%02d/f.bin", i)
		_ = os.MkdirAll(filepath.Join(h.src, filepath.Dir(rel)), 0o755)
		if err := os.WriteFile(filepath.Join(h.src, rel), b, 0o644); err != nil {
			t.Fatal(err)
		}
		want[rel] = b
	}
	res := h.backup(nil)
	e := h.epoch(res.Epoch.EpochID)
	objs, err := h.b.List(context.Background(), e, "packs")
	if err != nil || len(objs) < 3 {
		t.Fatalf("%d packs; the tree is sized for two data packs and a tree pack", len(objs))
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].Size > objs[j].Size })
	p := flipMiddleByte(t, h, objs[0].Key)

	r := read.Open(h.b, e, h.ids)
	snap, err := r.Snapshot(context.Background(), res.Snapshot.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := r.LoadIndex(context.Background(), snap)
	if err != nil {
		t.Fatal(err)
	}
	base := strings.TrimPrefix(h.src, "/")
	salvage := func(what string) {
		t.Helper()
		target := filepath.Join(t.TempDir(), "out")
		rr, err := r.Restore(context.Background(), snap, idx, read.RestoreOptions{Target: target, Base: base, Salvage: true})
		if err != nil {
			t.Fatalf("%s: a salvage restore failed: %v", what, err)
		}
		if len(rr.Damaged) == 0 || len(rr.Damaged) >= len(want) || int(rr.Files)+len(rr.Damaged) != len(want) {
			t.Fatalf("%s: restored %d and left out %d of %d files", what, rr.Files, len(rr.Damaged), len(want))
		}
		left := map[string]bool{}
		for _, d := range rr.Damaged {
			left[d.Path] = true
			if !strings.Contains(d.Reason, "pack ") {
				t.Errorf("%s: %s left out for %q, which names no pack", what, d.Path, d.Reason)
			}
		}
		for rel, content := range want {
			got, err := os.ReadFile(filepath.Join(target, rel))
			switch {
			case left[rel] && err == nil:
				t.Errorf("%s: %s was left out and is in the target", what, rel)
			case !left[rel] && (err != nil || !bytes.Equal(got, content)):
				t.Errorf("%s: %s did not come back whole: %v", what, rel, err)
			}
		}
		if leftovers, err := filepath.Glob(filepath.Join(target, ".safegrd-restore-*")); err != nil || len(leftovers) != 0 {
			t.Errorf("%s: the staging directory was left: %v", what, leftovers)
		}
	}
	salvage("a flipped byte")

	target := filepath.Join(t.TempDir(), "plain")
	if _, err := r.Restore(context.Background(), snap, idx, read.RestoreOptions{Target: target, Base: base}); err == nil || !strings.Contains(err.Error(), "does not authenticate") {
		t.Fatalf("a restore without salvage over a flipped byte: %v, want the blob refused", err)
	}
	if left, err := os.ReadDir(target); err != nil && !os.IsNotExist(err) || len(left) != 0 {
		t.Fatalf("a failed restore left %d entries", len(left))
	}

	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	salvage("a missing pack")
}
