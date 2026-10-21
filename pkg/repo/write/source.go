package write

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/repo/cache"
	"github.com/safegrd/cli/pkg/repo/format"
)

// sourceDir is one directory of a source's tree while the source runs.
type sourceDir struct {
	files map[string]format.Node
	dirs  map[string]*sourceDir
	// mounted are directories walked from this host, stored whole.
	mounted map[string]format.Node
}

func newSourceDir() *sourceDir {
	return &sourceDir{files: map[string]format.Node{}, dirs: map[string]*sourceDir{}, mounted: map[string]format.Node{}}
}

// Streamed files and the directories that hold them have no stat of their
// own: they carry the run's start time and these modes.
const (
	sourceFileMode = 0o600
	sourceDirMode  = 0o700
)

// source stores every file the source emits, then walks each mount into
// the tree, and returns the root tree. A source may emit from several
// goroutines at once: each stream is read and chunked on its own, and what
// they share is taken under w.mu.
func (w *walker) source(src Source, mounts []Mount, started time.Time) (format.ID, error) {
	top := newSourceDir()
	err := src(w.ctx, func(e Entry) error {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		segs, err := sourcePath(e.Path)
		if err != nil {
			return err
		}
		if e.Reader == nil && !e.Carry {
			return fmt.Errorf("source entry %s has no reader", e.Path)
		}
		w.mu.Lock()
		locked := true
		defer func() {
			if locked {
				w.mu.Unlock()
			}
		}()
		d := top
		for _, s := range segs[:len(segs)-1] {
			if _, clash := d.files[s]; clash {
				return fmt.Errorf("source entry %s is under a file", e.Path)
			}
			sub, ok := d.dirs[s]
			if !ok {
				sub = newSourceDir()
				d.dirs[s] = sub
			}
			d = sub
		}
		name := segs[len(segs)-1]
		if _, dup := d.files[name]; dup {
			return fmt.Errorf("source entry %s is emitted twice", e.Path)
		}
		if _, clash := d.dirs[name]; clash {
			return fmt.Errorf("source entry %s is a directory", e.Path)
		}
		var n format.Node
		if e.Carry {
			n, err = w.carry(e.Path, name, started)
		} else {
			// Reserved, so a second emit of the path is refused, and
			// streamed without the lock.
			d.files[name] = format.Node{}
			w.mu.Unlock()
			locked = false
			n, err = w.stream(e.Path, name, e.Reader, started)
			w.mu.Lock()
			locked = true
		}
		if err != nil {
			return err
		}
		d.files[name] = n
		return nil
	})
	if err != nil {
		return format.ID{}, err
	}
	for _, m := range mounts {
		if err := w.mount(top, m); err != nil {
			return format.ID{}, err
		}
	}
	return w.sourceTree("", top, started)
}

// mount walks one directory into the source's tree at its path.
func (w *walker) mount(top *sourceDir, m Mount) error {
	segs, err := sourcePath(m.Path)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(m.Dir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", m.Dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", m.Dir)
	}
	d := top
	for _, s := range segs[:len(segs)-1] {
		if _, clash := d.files[s]; clash {
			return fmt.Errorf("mount %s is under a file", m.Path)
		}
		if _, clash := d.mounted[s]; clash {
			return fmt.Errorf("mount %s is inside another mount", m.Path)
		}
		sub, ok := d.dirs[s]
		if !ok {
			sub = newSourceDir()
			d.dirs[s] = sub
		}
		d = sub
	}
	name := segs[len(segs)-1]
	_, f := d.files[name]
	_, sd := d.dirs[name]
	_, md := d.mounted[name]
	if f || sd || md {
		return fmt.Errorf("mount %s is already in the tree", m.Path)
	}
	w.root = m.Dir
	if m.ExcludeBase != "" {
		w.root = m.ExcludeBase
	}
	id, err := w.dir(m.Dir, m.Path, sysStat(fi).dev)
	if err != nil {
		return err
	}
	d.mounted[name] = w.dirNode(name, fi, id)
	return w.entry(m.Path, format.ContentDir, "-", fi, 0)
}

// sourcePath splits a source path into its segments and refuses one that is
// absolute, empty or climbs out.
func sourcePath(p string) ([]string, error) {
	if p == "" || strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return nil, fmt.Errorf("source entry %q is not a clean relative path", p)
	}
	segs := strings.Split(p, "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return nil, fmt.Errorf("source entry %q is not a clean relative path", p)
		}
	}
	return segs, nil
}

// stream chunks one emitted file, storing every chunk the epoch lacks. It
// is called without w.mu, with its own chunker, and takes the lock for
// what the run shares.
func (w *walker) stream(rel, name string, r io.Reader, started time.Time) (format.Node, error) {
	n := format.Node{Name: name, Type: format.NodeFile, Mode: sourceFileMode, ModTime: started.UTC()}
	ch, err := w.newChunker()
	if err != nil {
		return n, err
	}
	h := sha256.New()
	w.mu.Lock()
	if w.newBytes == nil {
		w.newBytes = map[string]int64{}
	}
	w.newBytes[rel] = 0
	w.mu.Unlock()
	ch.Reset(r)
	for {
		if err := w.ctx.Err(); err != nil {
			return n, err
		}
		b, err := ch.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, fmt.Errorf("reading %s: %w", rel, err)
		}
		h.Write(b)
		n.Size += int64(len(b))
		id := format.Hash(b)
		n.Content = append(n.Content, id)
		w.mu.Lock()
		w.readBytes += int64(len(b))
		added, err := w.storeNew(w.data, id, b)
		if added {
			w.newBytes[rel] += int64(len(b))
		}
		w.mu.Unlock()
		if err != nil {
			return n, err
		}
	}
	n.SHA256 = hex.EncodeToString(h.Sum(nil))
	w.mu.Lock()
	defer w.mu.Unlock()
	w.changed++
	row := cache.FileRow{Path: rel, Size: n.Size, MTimeNs: n.ModTime.UnixNano(), Mode: n.Mode, SHA256: n.SHA256, Blobs: n.Content}
	if err := w.cache.PutFile(row, w.runID); err != nil {
		return n, err
	}
	return n, w.counted(rel, n, nil)
}

// carry stores one file as the epoch last stored it, without reading it.
func (w *walker) carry(rel, name string, started time.Time) (format.Node, error) {
	n := format.Node{Name: name, Type: format.NodeFile, Mode: sourceFileMode, ModTime: started.UTC()}
	row, err := w.cache.File(rel)
	if err != nil {
		return n, err
	}
	if row == nil {
		return n, fmt.Errorf("%s: %w", rel, ErrNotCarried)
	}
	for _, id := range row.Blobs {
		if w.inRun[id] {
			continue
		}
		known, err := w.cache.Known(id)
		if err != nil {
			return n, err
		}
		if !known {
			return n, fmt.Errorf("%s: %w", rel, ErrNotCarried)
		}
	}
	for _, id := range row.Blobs {
		if err := w.cache.Ref(id); err != nil {
			return n, err
		}
	}
	n.Size, n.SHA256, n.Content = row.Size, row.SHA256, row.Blobs
	if w.newBytes == nil {
		w.newBytes = map[string]int64{}
	}
	w.newBytes[rel] = 0
	return n, w.counted(rel, n, nil)
}

// sourceTree stores the trees of d and everything under it, children first.
func (w *walker) sourceTree(rel string, d *sourceDir, started time.Time) (format.ID, error) {
	var t format.Tree
	for _, n := range d.files {
		t.Entries = append(t.Entries, n)
	}
	for _, n := range d.mounted {
		t.Entries = append(t.Entries, n)
	}
	for name, sub := range d.dirs {
		childRel := joinRel(rel, name)
		id, err := w.sourceTree(childRel, sub, started)
		if err != nil {
			return format.ID{}, err
		}
		w.dirs++
		t.Entries = append(t.Entries, format.Node{Name: name, Type: format.NodeDir, Mode: sourceDirMode, ModTime: started.UTC(), Subtree: id})
		if err := w.cache.AddEntry(cache.Entry{Path: childRel, Type: format.ContentDir, Value: "-",
			MTimeNs: started.UTC().UnixNano(), Mode: sourceDirMode}); err != nil {
			return format.ID{}, err
		}
	}
	sort.Slice(t.Entries, func(i, j int) bool { return t.Entries[i].Name < t.Entries[j].Name })
	return w.storeTree(t)
}
