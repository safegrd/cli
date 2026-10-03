package read

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/sink"
)

// RestoreOptions configure a restore.
type RestoreOptions struct {
	// Target must be empty or absent.
	Target string
	// Paths select what to restore, relative to /; none means everything.
	Paths []string
	// Concurrency is how many ranges are fetched at once; zero means 16.
	Concurrency int
	// MergeGap joins ranges of one pack closer than this; zero means 1 MiB.
	MergeGap int64
}

// RestoreResult is what a restore wrote.
type RestoreResult struct {
	Files, Dirs, Symlinks int64
	Bytes                 int64
	// Fetches and FetchedBytes count the reads from the store.
	Fetches      int64
	FetchedBytes int64
	// OwnershipRestored is set when owners were reapplied, which needs root.
	OwnershipRestored bool
	OwnershipNote     string
}

type occurrence struct {
	file int
	off  int64
}

type rangeFetch struct {
	pack       string
	start, end int64
	blobs      []format.ID
}

// Restore writes the selected entries of a snapshot under the target. Every
// file is written into a staging directory inside the target and checked
// against its SHA-256 first; only when all of them match are the entries moved
// into place and their modes, times and (as root) owners applied, directories
// last and deepest first. On any failure the staging directory is removed, the
// target is left as it was, and the error names the file.
func (r *Repo) Restore(ctx context.Context, s format.Snapshot, idx Index, o RestoreOptions) (res *RestoreResult, err error) {
	if o.Concurrency <= 0 {
		o.Concurrency = 16
	}
	if o.MergeGap <= 0 {
		o.MergeGap = 1 << 20
	}
	items, err := r.Select(ctx, idx, s, o.Paths)
	if err != nil {
		return nil, err
	}
	if len(o.Paths) > 0 && len(items) == 0 {
		return nil, fmt.Errorf("nothing in snapshot %s matches %s", s.SnapshotID, strings.Join(o.Paths, ", "))
	}

	target, created, err := prepareTarget(o.Target)
	if err != nil {
		return nil, err
	}
	stage := filepath.Join(target, ".safegrd-restore-"+randomHex())
	if err := os.Mkdir(stage, 0o700); err != nil {
		return nil, fmt.Errorf("creating the staging directory: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(stage)
			if created {
				_ = os.Remove(target)
			}
		}
	}()

	res = &RestoreResult{}
	var files []Item
	occ := map[format.ID][]occurrence{}
	for _, it := range items {
		dst := filepath.Join(stage, filepath.FromSlash(it.Path))
		switch it.Node.Type {
		case format.NodeDir:
			if err := os.MkdirAll(dst, 0o700); err != nil {
				return nil, fmt.Errorf("creating %s: %w", it.Path, err)
			}
		case format.NodeFile:
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return nil, fmt.Errorf("creating the directory of %s: %w", it.Path, err)
			}
			f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return nil, fmt.Errorf("creating %s: %w", it.Path, err)
			}
			terr := f.Truncate(it.Node.Size)
			if cerr := f.Close(); terr == nil {
				terr = cerr
			}
			if terr != nil {
				return nil, fmt.Errorf("creating %s: %w", it.Path, terr)
			}
			var off int64
			for _, id := range it.Node.Content {
				loc, ok := idx[id]
				if !ok {
					return nil, fmt.Errorf("%s: blob %s is in no index the snapshot lists", it.Path, id)
				}
				if format.BlobKind(loc.Entry.Type) != format.BlobData {
					return nil, fmt.Errorf("%s: blob %s is a tree, not data", it.Path, id)
				}
				occ[id] = append(occ[id], occurrence{file: len(files), off: off})
				off += loc.Entry.RawLength
			}
			if off != it.Node.Size {
				return nil, fmt.Errorf("%s: its blobs hold %d bytes, the tree says %d", it.Path, off, it.Node.Size)
			}
			files = append(files, it)
		}
	}

	// Plan: the blobs each pack must give, as merged ranges.
	byPack := map[string][]format.ID{}
	for id := range occ {
		byPack[idx[id].Pack] = append(byPack[idx[id].Pack], id)
	}
	var plan []rangeFetch
	packs := make([]string, 0, len(byPack))
	for p := range byPack {
		packs = append(packs, p)
	}
	sort.Strings(packs)
	for _, p := range packs {
		ids := byPack[p]
		sort.Slice(ids, func(i, j int) bool { return idx[ids[i]].Entry.Offset < idx[ids[j]].Entry.Offset })
		var cur *rangeFetch
		for _, id := range ids {
			e := idx[id].Entry
			if cur != nil && e.Offset-cur.end <= o.MergeGap {
				if end := e.Offset + e.Length; end > cur.end {
					cur.end = end
				}
				cur.blobs = append(cur.blobs, id)
				continue
			}
			plan = append(plan, rangeFetch{pack: p, start: e.Offset, end: e.Offset + e.Length, blobs: []format.ID{id}})
			cur = &plan[len(plan)-1]
		}
	}

	if err := r.fetch(ctx, plan, idx, occ, files, stage, o.Concurrency, res); err != nil {
		return nil, err
	}

	// Every file must match its SHA-256 before anything takes its place.
	for _, it := range files {
		if err := checkFile(filepath.Join(stage, filepath.FromSlash(it.Path)), it.Node); err != nil {
			return nil, fmt.Errorf("%s: %w", it.Path, err)
		}
		res.Files++
		res.Bytes += it.Node.Size
	}
	for _, it := range items {
		if it.Node.Type != format.NodeSymlink {
			continue
		}
		dst := filepath.Join(stage, filepath.FromSlash(it.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, err
		}
		if err := os.Symlink(it.Node.Target, dst); err != nil {
			return nil, fmt.Errorf("creating symlink %s: %w", it.Path, err)
		}
		res.Symlinks++
	}

	// Into place.
	tops, err := os.ReadDir(stage)
	if err != nil {
		return nil, err
	}
	for _, t := range tops {
		if err := os.Rename(filepath.Join(stage, t.Name()), filepath.Join(target, t.Name())); err != nil {
			return nil, fmt.Errorf("moving %s into place: %w", t.Name(), err)
		}
	}
	if err := os.Remove(stage); err != nil {
		return nil, err
	}

	// Modes, times and owners: files and links first, directories last and
	// deepest first, so a 0500 directory does not block its own children and
	// writing a child does not reset its time.
	chown := canChown()
	owners := false
	var dirs []Item
	for _, it := range items {
		if it.Node.UID != nil {
			owners = true
		}
		dst := filepath.Join(target, filepath.FromSlash(it.Path))
		switch it.Node.Type {
		case format.NodeDir:
			dirs = append(dirs, it)
		case format.NodeFile:
			if err := applyMeta(dst, it.Node, chown, true); err != nil {
				return res, err
			}
		case format.NodeSymlink:
			if chown && it.Node.UID != nil && it.Node.GID != nil {
				if err := os.Lchown(dst, int(*it.Node.UID), int(*it.Node.GID)); err != nil {
					return res, fmt.Errorf("restoring the owner of %s: %w", it.Path, err)
				}
			}
		}
	}
	sort.SliceStable(dirs, func(i, j int) bool { return depth(dirs[i].Path) > depth(dirs[j].Path) })
	for _, d := range dirs {
		if err := applyMeta(filepath.Join(target, filepath.FromSlash(d.Path)), d.Node, chown, true); err != nil {
			return res, err
		}
		res.Dirs++
	}
	switch {
	case !owners:
		res.OwnershipNote = "this snapshot recorded no owners, so files belong to whoever ran the restore"
	case !chown:
		res.OwnershipNote = "owners were recorded but not reapplied: that needs root, so files belong to whoever ran the restore"
	default:
		res.OwnershipRestored = true
	}
	return res, nil
}

func randomHex() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// prepareTarget accepts an empty or absent directory, and returns its real
// path and whether this restore created it.
func prepareTarget(t string) (string, bool, error) {
	if t == "" {
		return "", false, fmt.Errorf("no target directory")
	}
	abs, err := filepath.Abs(t)
	if err != nil {
		return "", false, err
	}
	created := false
	fi, err := os.Lstat(abs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(abs, 0o700); err != nil {
			return "", false, fmt.Errorf("creating %s: %w", abs, err)
		}
		created = true
	case err != nil:
		return "", false, err
	case !fi.IsDir():
		return "", false, fmt.Errorf("%s is not a directory", abs)
	default:
		des, err := os.ReadDir(abs)
		if err != nil {
			return "", false, err
		}
		if len(des) > 0 {
			return "", false, fmt.Errorf("%s is not empty: restore into an empty or new directory", abs)
		}
	}
	// The target may be reached through a symlink (/tmp on macOS); nothing
	// inside it is one until this restore makes it.
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	return abs, created, nil
}

func (r *Repo) fetch(ctx context.Context, plan []rangeFetch, idx Index, occ map[format.ID][]occurrence, files []Item,
	stage string, n int, res *RestoreResult) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan rangeFetch)
	var mu sync.Mutex
	var first error
	fail := func(err error) {
		mu.Lock()
		if first == nil {
			first = err
		}
		mu.Unlock()
		cancel()
	}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rf := range jobs {
				if ctx.Err() != nil {
					continue
				}
				if err := r.fetchOne(ctx, rf, idx, occ, files, stage, res, &mu); err != nil {
					fail(err)
				}
			}
		}()
	}
	for _, rf := range plan {
		select {
		case jobs <- rf:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	if first != nil {
		return first
	}
	return ctx.Err()
}

func (r *Repo) fetchOne(ctx context.Context, rf rangeFetch, idx Index, occ map[format.ID][]occurrence, files []Item,
	stage string, res *RestoreResult, mu *sync.Mutex) error {
	o, hdr, err := r.opener(ctx, rf.pack)
	if err != nil {
		return err
	}
	if rf.start < int64(hdr) {
		return fmt.Errorf("pack %s: a blob starts inside the header", rf.pack)
	}
	data, err := r.B.GetRange(ctx, r.key(sink.KindPack, rf.pack), rf.start, rf.end-rf.start)
	if err != nil {
		return fmt.Errorf("pack %s: %w", rf.pack, err)
	}
	mu.Lock()
	res.Fetches++
	res.FetchedBytes += int64(len(data))
	mu.Unlock()
	if int64(len(data)) != rf.end-rf.start {
		return fmt.Errorf("pack %s is shorter than its index says (%d of %d bytes at %d)", rf.pack, len(data), rf.end-rf.start, rf.start)
	}
	for _, id := range rf.blobs {
		e := idx[id].Entry
		rec := data[e.Offset-rf.start : e.Offset-rf.start+e.Length]
		plain, err := o.Blob(rec, e)
		if err != nil {
			it := files[occ[id][0].file]
			return fmt.Errorf("%s: pack %s: %w", it.Path, rf.pack, err)
		}
		for _, oc := range occ[id] {
			it := files[oc.file]
			dst := filepath.Join(stage, filepath.FromSlash(it.Path))
			f, err := os.OpenFile(dst, os.O_WRONLY, 0)
			if err != nil {
				return fmt.Errorf("%s: %w", it.Path, err)
			}
			_, werr := f.WriteAt(plain, oc.off)
			if cerr := f.Close(); werr == nil {
				werr = cerr
			}
			if werr != nil {
				return fmt.Errorf("%s: %w", it.Path, werr)
			}
		}
	}
	return nil
}

func checkFile(p string, n format.Node) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	got, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if got != n.Size {
		return fmt.Errorf("restored %d bytes, the snapshot holds %d", got, n.Size)
	}
	if sum := hex.EncodeToString(h.Sum(nil)); sum != n.SHA256 {
		return fmt.Errorf("its SHA-256 is %s, the snapshot recorded %s", sum, n.SHA256)
	}
	return nil
}

func applyMeta(p string, n format.Node, chown, times bool) error {
	if chown && n.UID != nil && n.GID != nil {
		if err := os.Lchown(p, int(*n.UID), int(*n.GID)); err != nil {
			return fmt.Errorf("restoring the owner of %s: %w", p, err)
		}
	}
	// After the owner: a chown may clear permission bits.
	if err := os.Chmod(p, fs.FileMode(n.Mode).Perm()); err != nil {
		return fmt.Errorf("setting the mode of %s: %w", p, err)
	}
	if times && !n.ModTime.IsZero() {
		if err := os.Chtimes(p, n.ModTime, n.ModTime); err != nil {
			return fmt.Errorf("setting the time of %s: %w", p, err)
		}
	}
	return nil
}
