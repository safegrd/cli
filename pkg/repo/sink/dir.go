package sink

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Dir is a store in a local directory. It has no lock: objects are written
// read-only and never replaced, and the dates go into each snapshot's
// sidecar like everywhere else.
type Dir struct {
	base string
	root string
}

// NewDir returns a store under base whose repository keys start with root
// (for instance the host's node id), which may be empty.
func NewDir(base, root string) (*Dir, error) {
	abs, err := filepath.Abs(base)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", abs, err)
	}
	return &Dir{base: abs, root: strings.Trim(root, "/")}, nil
}

func (d *Dir) Root() string     { return d.root }
func (d *Dir) Describe() string { return d.base }

// Path is where key lives on disk.
func (d *Dir) Path(key string) (string, error) {
	clean := path.Clean("/" + key)
	if clean == "/" || clean != "/"+key {
		return "", fmt.Errorf("key %q is not clean", key)
	}
	return filepath.Join(d.base, filepath.FromSlash(clean[1:])), nil
}

func (d *Dir) Put(_ context.Context, key string, body []byte, _ [16]byte, _ time.Time) error {
	p, err := d.Path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".put-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o400); err != nil {
		return err
	}
	// A hard link fails when the name exists, which a rename would not.
	if err := os.Link(tmp.Name(), p); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists, and an object is never written twice", key)
		}
		return err
	}
	return nil
}

func (d *Dir) Get(_ context.Context, key string) (io.ReadCloser, error) {
	p, err := d.Path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", key, ErrNotFound)
	}
	return f, err
}

func (d *Dir) GetRange(_ context.Context, key string, off, n int64) ([]byte, error) {
	p, err := d.Path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", key, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	got, err := f.ReadAt(buf, off)
	if err == io.EOF {
		err = nil
	}
	return buf[:got], err
}

func (d *Dir) List(_ context.Context, prefix string) ([]ObjectInfo, error) {
	var out []ObjectInfo
	start := filepath.Join(d.base, filepath.FromSlash(strings.TrimSuffix(prefix, "/")))
	if strings.HasSuffix(prefix, "/") || prefix == "" {
		// a directory prefix: walk it
	} else {
		start = filepath.Dir(start)
	}
	err := filepath.WalkDir(start, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if de.IsDir() || strings.HasPrefix(de.Name(), ".put-") {
			return nil
		}
		rel, err := filepath.Rel(d.base, p)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if !strings.HasPrefix(key, prefix) {
			return nil
		}
		info, err := de.Info()
		if err != nil {
			return err
		}
		out = append(out, ObjectInfo{Key: key, Size: info.Size()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, err
}

// Remove deletes one object. Only prune calls it.
func (d *Dir) Remove(key string) error {
	p, err := d.Path(key)
	if err != nil {
		return err
	}
	return os.Remove(p)
}
