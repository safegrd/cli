package sink

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"github.com/safegrd/cli/pkg/sftpdial"
)

// SFTP is a store in a directory on an SSH server. Like a local directory it
// has no lock: an object is written once under a temporary name and renamed
// into place, which SFTP refuses over an existing name, and the dates go
// into each snapshot's sidecar.
type SFTP struct {
	Conn *sftpdial.Conn
	// Base is the directory on the server; Prefix the key prefix every
	// repository key starts with below it (the host's node id), may be "".
	Base   string
	Prefix string
}

func (s *SFTP) Root() string     { return strings.Trim(s.Prefix, "/") }
func (s *SFTP) Describe() string { return strings.TrimSuffix(s.Conn.URI(s.Root()), "/") }

// path is where key lives on the server.
func (s *SFTP) path(key string) (string, error) {
	clean := path.Clean("/" + key)
	if clean == "/" || clean != "/"+key {
		return "", fmt.Errorf("key %q is not clean", key)
	}
	return path.Join(s.Base, clean[1:]), nil
}

func notExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist)
}

func (s *SFTP) Put(ctx context.Context, key string, body []byte, _ [16]byte, _ time.Time) error {
	p, err := s.path(key)
	if err != nil {
		return err
	}
	c, done, err := s.Conn.Use(ctx)
	if err != nil {
		return err
	}
	defer done()
	if err := c.MkdirAll(path.Dir(p)); err != nil {
		return fmt.Errorf("creating %s: %w", path.Dir(p), err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:]) // crypto/rand does not fail on supported platforms
	tmp := path.Join(path.Dir(p), ".put-"+hex.EncodeToString(b[:]))
	f, err := c.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return fmt.Errorf("creating %s: %w", tmp, err)
	}
	if _, err := f.ReadFrom(bytes.NewReader(body)); err != nil {
		f.Close()
		_ = c.Remove(tmp) // the write already failed; this only tidies
		return fmt.Errorf("writing %s: %w", key, err)
	}
	if err := f.Close(); err != nil {
		_ = c.Remove(tmp)
		return fmt.Errorf("writing %s: %w", key, err)
	}
	if err := c.Rename(tmp, p); err != nil {
		_ = c.Remove(tmp)
		if _, statErr := c.Stat(p); statErr == nil {
			return fmt.Errorf("%s already exists, and an object is never written twice", key)
		}
		return fmt.Errorf("renaming %s into place: %w", key, err)
	}
	return nil
}

type sftpBody struct {
	*sftp.File
	done func()
}

func (b *sftpBody) Close() error {
	err := b.File.Close()
	b.done()
	return err
}

func (s *SFTP) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	p, err := s.path(key)
	if err != nil {
		return nil, err
	}
	c, done, err := s.Conn.Use(ctx)
	if err != nil {
		return nil, err
	}
	f, err := c.Open(p)
	if err != nil {
		done()
		if notExist(err) {
			return nil, fmt.Errorf("%s: %w", key, ErrNotFound)
		}
		return nil, err
	}
	return &sftpBody{File: f, done: done}, nil
}

func (s *SFTP) GetRange(ctx context.Context, key string, off, n int64) ([]byte, error) {
	rc, err := s.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	buf := make([]byte, n)
	got, err := rc.(*sftpBody).ReadAt(buf, off)
	if err == io.EOF {
		err = nil
	}
	return buf[:got], err
}

// List returns the objects under prefix, recursively. A prefix that does
// not end in "/" matches names starting with it, as a bucket's does.
func (s *SFTP) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	c, done, err := s.Conn.Use(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	dir := strings.TrimSuffix(prefix, "/")
	if !strings.HasSuffix(prefix, "/") && prefix != "" {
		dir = path.Dir(dir)
	}
	start := path.Join(s.Base, dir)
	var out []ObjectInfo
	w := c.Walk(start)
	for w.Step() {
		if err := w.Err(); err != nil {
			if notExist(err) {
				continue
			}
			return nil, fmt.Errorf("listing %s: %w", w.Path(), err)
		}
		fi := w.Stat()
		if fi.IsDir() || strings.HasPrefix(fi.Name(), ".put-") {
			continue
		}
		key := strings.TrimPrefix(strings.TrimPrefix(w.Path(), s.Base), "/")
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		out = append(out, ObjectInfo{Key: key, Size: fi.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Children lists the directories directly under prefix.
func (s *SFTP) Children(ctx context.Context, prefix string) ([]string, error) {
	c, done, err := s.Conn.Use(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	des, err := c.ReadDir(path.Join(s.Base, strings.Trim(prefix, "/")))
	if notExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, de := range des {
		if de.IsDir() {
			out = append(out, de.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// sftpVersion stands for the one copy of a file the server keeps.
const sftpVersion = "current"

// Versions lists every object under prefix as its one version, for prune.
func (s *SFTP) Versions(ctx context.Context, prefix string) ([]Version, error) {
	objs, err := s.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make([]Version, 0, len(objs))
	for _, o := range objs {
		out = append(out, Version{Key: o.Key, VersionID: sftpVersion, Size: o.Size})
	}
	return out, nil
}

// Retention is always zero: nothing on the server locks an object, so
// prune goes by the dates in the snapshots' sidecars.
func (s *SFTP) Retention(context.Context, string, string) (time.Time, error) {
	return time.Time{}, nil
}

// DeleteVersion deletes one object. Only prune calls it.
func (s *SFTP) DeleteVersion(ctx context.Context, key, versionID string) error {
	if versionID != sftpVersion {
		return fmt.Errorf("refusing to delete %s: version %q is not one this store listed", key, versionID)
	}
	p, err := s.path(key)
	if err != nil {
		return err
	}
	c, done, err := s.Conn.Use(ctx)
	if err != nil {
		return err
	}
	defer done()
	return c.Remove(p)
}
