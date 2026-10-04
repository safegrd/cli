package write

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
}

func newSourceDir() *sourceDir {
	return &sourceDir{files: map[string]format.Node{}, dirs: map[string]*sourceDir{}}
}

// Streamed files and the directories that hold them have no stat of their
// own: they carry the run's start time and these modes.
const (
	sourceFileMode = 0o600
	sourceDirMode  = 0o700
)

// source stores every file the source emits and returns the root tree.
func (w *walker) source(src Source, started time.Time) (format.ID, error) {
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
			n, err = w.stream(e.Path, name, e.Reader, started)
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
	return w.sourceTree("", top, started)
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

// stream chunks one emitted file, storing every chunk the epoch lacks.
func (w *walker) stream(rel, name string, r io.Reader, started time.Time) (format.Node, error) {
	n := format.Node{Name: name, Type: format.NodeFile, Mode: sourceFileMode, ModTime: started.UTC()}
	h := sha256.New()
	if w.newBytes == nil {
		w.newBytes = map[string]int64{}
	}
	w.newBytes[rel] = 0
	w.ch.Reset(r)
	for {
		if err := w.ctx.Err(); err != nil {
			return n, err
		}
		b, err := w.ch.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, fmt.Errorf("reading %s: %w", rel, err)
		}
		h.Write(b)
		n.Size += int64(len(b))
		w.readBytes += int64(len(b))
		id := format.Hash(b)
		n.Content = append(n.Content, id)
		added, err := w.storeNew(w.data, id, b)
		if err != nil {
			return n, err
		}
		if added {
			w.newBytes[rel] += int64(len(b))
		}
	}
	n.SHA256 = hex.EncodeToString(h.Sum(nil))
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
