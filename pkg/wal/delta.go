package wal

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// A delta restore writes a base over an existing data directory of the same
// cluster, and rewrites only what differs. Nothing on the target is
// trusted: every file the base holds is read whole and compared byte for
// byte with the base's own bytes as they stream past. Files the base does
// not have are removed inside PostgreSQL's own directories, where
// PostgreSQL would read them as the cluster's state, and kept and named
// anywhere else.

// DeltaResult is what a delta restore did to the target.
type DeltaResult struct {
	// Rewritten are the files written, because they were missing, of
	// another size, or held other bytes; RewrittenBytes their size.
	Rewritten      []string
	RewrittenBytes int64
	// Unchanged counts the files that matched the base, ReadBytes their size.
	Unchanged int
	ReadBytes int64
	// Removed are the target's files and directories the base does not
	// have, inside PostgreSQL's own directories. Kept are the ones outside
	// them, left in place.
	Removed []string
	Kept    []string
	// ControlUnread says global/pg_control could not be read, so the
	// system it belongs to was not checked.
	ControlUnread bool
}

// pgOwnedDirs are the data directory's subdirectories PostgreSQL reads as
// the cluster's state.
var pgOwnedDirs = map[string]bool{
	"base": true, "global": true, "pg_wal": true, "pg_xact": true, "pg_multixact": true,
	"pg_commit_ts": true, "pg_subtrans": true, "pg_twophase": true, "pg_logical": true,
	"pg_replslot": true, "pg_tblspc": true, "pg_stat": true, "pg_stat_tmp": true,
	"pg_notify": true, "pg_serial": true, "pg_snapshots": true, "pg_dynshmem": true,
}

// pgOwnedFiles are PostgreSQL's own files at the top of the data directory.
var pgOwnedFiles = map[string]bool{
	"postmaster.pid": true, "postmaster.opts": true, "backup_label": true, "backup_label.old": true,
	"backup_manifest": true, "tablespace_map": true, "tablespace_map.old": true,
	"recovery.signal": true, "standby.signal": true, "current_logfiles": true,
	"postgresql.auto.conf.tmp": true, "PG_VERSION": true,
}

func pgOwned(rel string) bool {
	top, _, nested := strings.Cut(rel, "/")
	if nested {
		return pgOwnedDirs[top]
	}
	return pgOwnedDirs[top] || pgOwnedFiles[top]
}

// checkDeltaTarget refuses a directory a delta restore must not write over:
// one PostgreSQL is running on, one that is not a data directory of the
// base's major version, or another cluster's. It says empty for a directory
// that is missing or holds nothing, which an ordinary restore takes.
func checkDeltaTarget(dir string, b BaseInfo, systemID string) (empty, controlUnread bool, err error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(ents) == 0) {
		return true, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if pid, err := os.ReadFile(filepath.Join(dir, "postmaster.pid")); err == nil {
		first, _, _ := strings.Cut(string(pid), "\n")
		if n, err := strconv.Atoi(strings.TrimSpace(first)); err == nil && n > 0 && processAlive(n) {
			return false, false, fmt.Errorf("PostgreSQL is running on %s (postmaster.pid names process %d). Stop it first (pg_ctl -D %s stop); a restore under a running server would corrupt it", dir, n, dir)
		}
	}
	v, err := os.ReadFile(filepath.Join(dir, "PG_VERSION"))
	if err != nil {
		return false, false, fmt.Errorf("%s holds no PG_VERSION, so it is not a PostgreSQL data directory. --delta restores over one; for any other directory, restore into an empty one without --delta", dir)
	}
	if got := strings.TrimSpace(string(v)); got != strconv.Itoa(b.Major()) {
		return false, false, fmt.Errorf("%s is a PostgreSQL %s data directory and base %s is PostgreSQL %d. Restore into an empty directory without --delta", dir, got, b.BaseID, b.Major())
	}
	head := make([]byte, 12)
	f, err := os.Open(filepath.Join(dir, "global", "pg_control"))
	if err == nil {
		_, err = io.ReadFull(f, head)
		f.Close()
	}
	var sys string
	if err == nil {
		sys, err = systemIDFromControl(head, "the target's global/pg_control")
	}
	if err != nil {
		return false, true, nil
	}
	if sys != systemID {
		return false, false, fmt.Errorf("%s is cluster %s, and the archive is of cluster %s. A delta restore writes only over the same cluster; restore into an empty directory without --delta", dir, sys, systemID)
	}
	return false, false, nil
}

// deltaWriter applies a base's entries to the target directory.
type deltaWriter struct {
	dir  string
	res  *DeltaResult
	seen map[string]bool
	buf  [2][]byte
}

func newDeltaWriter(dir string, res *DeltaResult) *deltaWriter {
	return &deltaWriter{dir: dir, res: res, seen: map[string]bool{}, buf: [2][]byte{make([]byte, 1<<20), make([]byte, 1<<20)}}
}

// relName cleans a tar or walk name, refusing one outside the directory.
func relName(name string) (string, error) {
	rel := path.Clean(strings.TrimPrefix(name, "./"))
	if path.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("the base holds %q, outside the data directory", name)
	}
	return rel, nil
}

func (d *deltaWriter) mkdir(rel string) error {
	d.seen[rel] = true
	dst := filepath.Join(d.dir, filepath.FromSlash(rel))
	fi, err := os.Lstat(dst)
	switch {
	case err == nil && fi.IsDir():
		return nil
	case err == nil && fi.Mode()&fs.ModeSymlink != 0:
		// pg_wal on another disk, as initdb --waldir links it, is kept;
		// its contents are compared like the rest.
		if st, err := os.Stat(dst); err == nil && st.IsDir() && rel == "pg_wal" {
			return nil
		}
		if err := os.Remove(dst); err != nil {
			return err
		}
	case err == nil:
		if err := os.Remove(dst); err != nil {
			return err
		}
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	return os.MkdirAll(dst, 0o700)
}

// file makes the target's rel hold the size bytes r gives, writing only
// when they differ.
func (d *deltaWriter) file(rel string, size int64, r io.Reader) error {
	d.seen[rel] = true
	dst := filepath.Join(d.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dst)
	if err == nil && !fi.Mode().IsRegular() {
		if err := os.RemoveAll(dst); err != nil {
			return err
		}
		err = os.ErrNotExist
	}
	rewritten := func() {
		d.res.Rewritten = append(d.res.Rewritten, rel)
		d.res.RewrittenBytes += size
	}
	if errors.Is(err, os.ErrNotExist) {
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, r)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		rewritten()
		return err
	}
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if fi.Mode().Perm()&0o077 != 0 {
		if err := f.Chmod(0o600); err != nil {
			return err
		}
	}
	if fi.Size() != size {
		if err := f.Truncate(0); err != nil {
			return err
		}
		if _, err := io.Copy(f, r); err != nil {
			return err
		}
		rewritten()
		return f.Close()
	}
	// The same size: compare to the end, and rewrite from the first byte
	// that differs.
	var off int64
	for off < size {
		want := d.buf[0][:min(int64(len(d.buf[0])), size-off)]
		if _, err := io.ReadFull(r, want); err != nil {
			return err
		}
		have := d.buf[1][:len(want)]
		if _, err := io.ReadFull(f, have); err != nil {
			return fmt.Errorf("reading %s on the target: %w", rel, err)
		}
		if bytes.Equal(want, have) {
			off += int64(len(want))
			continue
		}
		i := 0
		for want[i] == have[i] {
			i++
		}
		if _, err := f.WriteAt(want[i:], off+int64(i)); err != nil {
			return err
		}
		if _, err := f.Seek(off+int64(len(want)), io.SeekStart); err != nil {
			return err
		}
		if _, err := io.Copy(f, r); err != nil {
			return err
		}
		rewritten()
		return f.Close()
	}
	d.res.Unchanged++
	d.res.ReadBytes += size
	return nil
}

// fromTar applies a base's tar.
func (d *deltaWriter) fromTar(r io.Reader) error {
	tr := tar.NewReader(r)
	manifestRead := false
	for {
		h, err := tr.Next()
		if err == io.EOF || (errors.Is(err, io.ErrUnexpectedEOF) && manifestRead) {
			return nil // PostgreSQL 13 and 14 end the tar after the manifest (scanTar)
		}
		if err != nil {
			return err
		}
		manifestRead = false
		rel, err := relName(h.Name)
		if err != nil {
			return err
		}
		if rel == "." {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			err = d.mkdir(rel)
		case tar.TypeReg:
			err = d.file(rel, h.Size, tr)
			manifestRead = rel == "backup_manifest"
		case tar.TypeSymlink:
			err = fmt.Errorf("the base holds a symbolic link %q; pg_basebackup writes none into a tar on stdout, so this is not one of its backups", h.Name)
		default:
			err = fmt.Errorf("the base holds %q of tar type %q", h.Name, h.Typeflag)
		}
		if err != nil {
			return err
		}
	}
}

// fromDir applies a data directory pg_combinebackup wrote, global/pg_control
// last, as pg_basebackup sends it.
func (d *deltaWriter) fromDir(src string) error {
	one := func(rel string, size int64) error {
		f, err := os.Open(filepath.Join(src, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		defer f.Close()
		return d.file(rel, size, f)
	}
	var control int64 = -1
	err := filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		r, err := filepath.Rel(src, p)
		if err != nil || r == "." {
			return err
		}
		rel := filepath.ToSlash(r)
		switch {
		case e.IsDir():
			return d.mkdir(rel)
		case e.Type().IsRegular():
			fi, err := e.Info()
			if err != nil {
				return err
			}
			if rel == "global/pg_control" {
				control = fi.Size()
				return nil
			}
			return one(rel, fi.Size())
		}
		return fmt.Errorf("pg_combinebackup wrote %s, which is not a file or a directory", rel)
	})
	if err != nil {
		return err
	}
	if control < 0 {
		return errors.New("pg_combinebackup wrote no global/pg_control")
	}
	return one("global/pg_control", control)
}

// sweep removes what the base does not have inside PostgreSQL's own
// directories and names what it leaves elsewhere.
func (d *deltaWriter) sweep() error {
	var visit func(rel string) error
	visit = func(rel string) error {
		ents, err := os.ReadDir(filepath.Join(d.dir, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		for _, e := range ents {
			r := e.Name()
			if rel != "" {
				r = rel + "/" + e.Name()
			}
			if d.seen[r] {
				isDir := e.IsDir()
				if e.Type()&fs.ModeSymlink != 0 && r == "pg_wal" {
					isDir = true
				}
				if isDir {
					if err := visit(r); err != nil {
						return err
					}
				}
				continue
			}
			if !pgOwned(r) {
				d.res.Kept = append(d.res.Kept, r)
				continue
			}
			if err := os.RemoveAll(filepath.Join(d.dir, filepath.FromSlash(r))); err != nil {
				return err
			}
			d.res.Removed = append(d.res.Removed, r)
		}
		return nil
	}
	err := visit("")
	sort.Strings(d.res.Removed)
	sort.Strings(d.res.Kept)
	return err
}

// deltaChain makes dir hold base b, rewriting only what differs: the base's
// tar for a full base, and for an incremental the directory
// pg_combinebackup rebuilds beside dir.
func (a *Archive) deltaChain(ctx context.Context, bases []BaseInfo, b BaseInfo, dir string) (*DeltaResult, error) {
	full, err := chainFull(bases, b)
	if err != nil {
		return nil, err
	}
	res := &DeltaResult{}
	d := newDeltaWriter(dir, res)
	// pg_control comes last. Without it PostgreSQL will not start, so a
	// delta restore that stops partway leaves nothing that runs on a mix of
	// two states; running it again finishes it.
	if err := os.Remove(filepath.Join(dir, "global", "pg_control")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if full == nil {
		if err := a.streamBase(ctx, b, d.fromTar); err != nil {
			return nil, err
		}
	} else {
		bin, err := FindPgTool(ctx, "pg_combinebackup", b.Major(), true)
		if err != nil {
			return nil, fmt.Errorf("base %s is incremental and is rebuilt with pg_combinebackup: %w", b.BaseID, err)
		}
		work, err := os.MkdirTemp(filepath.Dir(filepath.Clean(dir)), "."+filepath.Base(dir)+".combine-")
		if err != nil {
			return nil, fmt.Errorf("making a work directory beside %s to combine the incremental base in: %w", dir, err)
		}
		defer os.RemoveAll(work)
		fullDir, incrDir, out := filepath.Join(work, "full"), filepath.Join(work, "incremental"), filepath.Join(work, "combined")
		for _, x := range []string{fullDir, incrDir} {
			if err := os.Mkdir(x, 0o700); err != nil {
				return nil, err
			}
		}
		if err := a.unpackBase(ctx, *full, fullDir); err != nil {
			return nil, err
		}
		if err := a.unpackBase(ctx, b, incrDir); err != nil {
			return nil, err
		}
		if msg, err := exec.CommandContext(ctx, bin, fullDir, incrDir, "-o", out).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("pg_combinebackup could not rebuild base %s from full base %s: %w\n%s", b.BaseID, full.BaseID, err, strings.TrimSpace(string(msg)))
		}
		if err := d.fromDir(out); err != nil {
			return nil, err
		}
	}
	if err := d.sweep(); err != nil {
		return nil, fmt.Errorf("removing what the base does not have: %w", err)
	}
	return res, nil
}
