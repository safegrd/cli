// Package read restores from a repository: it plans which byte ranges of
// which packs a restore needs, fetches only those, checks every blob against
// its id and every file against its SHA-256, and writes nothing into the
// target until all of it matches.
package read

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/unseal"
)

// Repo reads one epoch.
type Repo struct {
	B     sink.Backend
	Epoch sink.EpochInfo
	IDs   []age.Identity

	mu      sync.Mutex
	keys    map[string]*unseal.Opener
	headers map[string]int
	trees   map[string][]byte
	sizes   map[string]int64
}

// Open returns a reader for one epoch.
func Open(b sink.Backend, e sink.EpochInfo, ids []age.Identity) *Repo {
	return &Repo{B: b, Epoch: e, IDs: ids, keys: map[string]*unseal.Opener{}, headers: map[string]int{},
		trees: map[string][]byte{}, sizes: map[string]int64{}}
}

func (r *Repo) key(kind sink.Kind, name string) string {
	k, _ := sink.ObjectKey(r.Epoch.Prefix, kind, name)
	return k
}

// Snapshot fetches and opens one snapshot object.
func (r *Repo) Snapshot(ctx context.Context, snapshotID string) (format.Snapshot, error) {
	var s format.Snapshot
	if err := sink.ValidSnapshotName(snapshotID); err != nil {
		return s, err
	}
	body, err := r.B.Get(ctx, r.key(sink.KindSnapshot, snapshotID))
	if err != nil {
		return s, fmt.Errorf("snapshot %s: %w", snapshotID, err)
	}
	if err := unseal.Object(body, r.IDs, &s); err != nil {
		return s, fmt.Errorf("snapshot %s: %w", snapshotID, err)
	}
	if err := s.Validate(); err != nil {
		return s, err
	}
	if s.SnapshotID != snapshotID || s.EpochID != r.Epoch.Epoch.EpochID {
		return s, fmt.Errorf("snapshot object %s names snapshot %s of epoch %s", snapshotID, s.SnapshotID, s.EpochID)
	}
	return s, nil
}

// Location is where one blob is.
type Location struct {
	Pack  string
	Bytes int64
	Entry format.BlobEntry
}

// Index is the union of the indexes of a snapshot's runs.
type Index map[format.ID]Location

// LoadIndex fetches the index of every run the snapshot lists.
func (r *Repo) LoadIndex(ctx context.Context, s format.Snapshot) (Index, error) {
	idx := Index{}
	for _, run := range s.Runs {
		body, err := r.B.Get(ctx, r.key(sink.KindIndex, run))
		if err != nil {
			return nil, fmt.Errorf("the index of run %s: %w", run, err)
		}
		var x format.Index
		if err := unseal.Object(body, r.IDs, &x); err != nil {
			return nil, fmt.Errorf("the index of run %s: %w", run, err)
		}
		if err := x.Validate(); err != nil {
			return nil, err
		}
		if x.RunID != run || x.EpochID != s.EpochID {
			return nil, fmt.Errorf("index %s names run %s of epoch %s", run, x.RunID, x.EpochID)
		}
		for _, p := range x.Packs {
			r.mu.Lock()
			r.sizes[p.PackID] = p.Bytes
			r.mu.Unlock()
			for _, b := range p.Blobs {
				id, _ := format.ParseID(b.ID)
				idx[id] = Location{Pack: p.PackID, Bytes: p.Bytes, Entry: b}
			}
		}
	}
	return idx, nil
}

// opener returns the key of a pack, reading its header once.
func (r *Repo) opener(ctx context.Context, pack string) (*unseal.Opener, int, error) {
	r.mu.Lock()
	if o, ok := r.keys[pack]; ok {
		h := r.headers[pack]
		r.mu.Unlock()
		return o, h, nil
	}
	r.mu.Unlock()
	key := r.key(sink.KindPack, pack)
	head, err := r.B.GetRange(ctx, key, 0, format.PackHeaderProbe)
	if err != nil {
		return nil, 0, fmt.Errorf("pack %s: %w", pack, err)
	}
	n, err := format.PackHeaderLen(head)
	if err != nil {
		return nil, 0, fmt.Errorf("pack %s: %w", pack, err)
	}
	if n > len(head) {
		if head, err = r.B.GetRange(ctx, key, 0, int64(n)); err != nil {
			return nil, 0, fmt.Errorf("pack %s: %w", pack, err)
		}
	}
	wrapped, _, err := format.ParsePackHeader(head)
	if err != nil {
		return nil, 0, fmt.Errorf("pack %s: %w", pack, err)
	}
	k, err := unseal.UnwrapKey(wrapped, r.IDs)
	if err != nil {
		return nil, 0, fmt.Errorf("pack %s: %w", pack, err)
	}
	o, err := unseal.NewOpener(k)
	if err != nil {
		return nil, 0, err
	}
	r.mu.Lock()
	r.keys[pack], r.headers[pack] = o, n
	r.mu.Unlock()
	return o, n, nil
}

// Tree fetches one tree blob. Tree packs are small and dense, so each is
// fetched whole, once.
func (r *Repo) Tree(ctx context.Context, idx Index, id format.ID) (format.Tree, error) {
	loc, ok := idx[id]
	if !ok {
		return format.Tree{}, fmt.Errorf("tree %s is in no index the snapshot lists", id)
	}
	if format.BlobKind(loc.Entry.Type) != format.BlobTree {
		return format.Tree{}, fmt.Errorf("blob %s is named as a tree but stored as data", id)
	}
	r.mu.Lock()
	body, ok := r.trees[loc.Pack]
	r.mu.Unlock()
	if !ok {
		var err error
		body, err = r.B.Get(ctx, r.key(sink.KindPack, loc.Pack))
		if err != nil {
			return format.Tree{}, fmt.Errorf("pack %s: %w", loc.Pack, err)
		}
		if int64(len(body)) != loc.Bytes {
			return format.Tree{}, fmt.Errorf("pack %s is %d bytes, its index says %d", loc.Pack, len(body), loc.Bytes)
		}
		r.mu.Lock()
		r.trees[loc.Pack] = body
		r.mu.Unlock()
	}
	o, hdr, err := r.opener(ctx, loc.Pack)
	if err != nil {
		return format.Tree{}, err
	}
	if loc.Entry.Offset < int64(hdr) || loc.Entry.Offset+loc.Entry.Length > int64(len(body)) {
		return format.Tree{}, fmt.Errorf("tree %s lies outside pack %s", id, loc.Pack)
	}
	plain, err := o.Blob(body[loc.Entry.Offset:loc.Entry.Offset+loc.Entry.Length], loc.Entry)
	if err != nil {
		return format.Tree{}, fmt.Errorf("pack %s: %w", loc.Pack, err)
	}
	return format.DecodeTree(plain)
}

// Item is one entry of a snapshot, at its path relative to /.
type Item struct {
	Path string
	Node format.Node
}

// Walk lists every entry under the snapshot's root tree, depth first in
// tree order. fn may return SkipDir for a directory.
func (r *Repo) Walk(ctx context.Context, idx Index, root format.ID, fn func(Item) error) error {
	seen := map[format.ID]int{}
	var walk func(id format.ID, prefix string, depth int) error
	walk = func(id format.ID, prefix string, depth int) error {
		if depth > 4096 {
			return fmt.Errorf("trees nest deeper than 4096 levels at %s", prefix)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		t, err := r.Tree(ctx, idx, id)
		if err != nil {
			return err
		}
		seen[id]++
		for _, n := range t.Entries {
			p := n.Name
			if prefix != "" {
				p = prefix + "/" + n.Name
			}
			err := fn(Item{Path: p, Node: n})
			if err == SkipDir {
				continue
			}
			if err != nil {
				return err
			}
			if n.Type == format.NodeDir {
				if err := walk(n.Subtree, p, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(root, "", 0)
}

// SkipDir tells Walk not to descend.
var SkipDir = fmt.Errorf("skip this directory")

// Match reports whether p (relative to /) is selected by the patterns, and
// whether something below a directory at p could be. A pattern selects a
// path it matches, segment by segment with "*", "?" and "[...]" and with
// "**" for any number of segments, and everything below a path it selects.
// A trailing "/" is ignored.
func Match(patterns []string, p string) (selected, below bool) {
	if len(patterns) == 0 {
		return true, true
	}
	segs := strings.Split(p, "/")
	for _, pat := range patterns {
		pat = strings.Trim(path.Clean("/"+strings.TrimSpace(pat)), "/")
		if pat == "" {
			return true, true
		}
		ps := strings.Split(pat, "/")
		if m := matchSegs(ps, segs); m {
			return true, true
		}
		// A pattern matching an ancestor of p selects p.
		for i := len(segs) - 1; i >= 1; i-- {
			if matchSegs(ps, segs[:i]) {
				return true, true
			}
		}
		if prefixCouldMatch(ps, segs) {
			below = true
		}
	}
	return false, below
}

func matchSegs(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if matchSegs(pat[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	if ok, _ := path.Match(pat[0], segs[0]); !ok {
		return false
	}
	return matchSegs(pat[1:], segs[1:])
}

// prefixCouldMatch reports whether some path below the directory segs could
// match pat.
func prefixCouldMatch(pat, segs []string) bool {
	if len(segs) == 0 {
		return true
	}
	if len(pat) == 0 {
		return false
	}
	if pat[0] == "**" {
		return true
	}
	if ok, _ := path.Match(pat[0], segs[0]); !ok {
		return false
	}
	return prefixCouldMatch(pat[1:], segs[1:])
}

// Select lists the entries a restore of patterns covers: every selected
// entry, and every directory on the way to one. Directories come before
// their contents.
func (r *Repo) Select(ctx context.Context, idx Index, s format.Snapshot, patterns []string) ([]Item, error) {
	root, err := format.ParseID(s.RootTree)
	if err != nil {
		return nil, err
	}
	var out []Item
	var pendingDirs []Item // ancestors not yet emitted
	err = r.Walk(ctx, idx, root, func(it Item) error {
		// Drop pending ancestors that are not ancestors of this entry.
		for len(pendingDirs) > 0 {
			last := pendingDirs[len(pendingDirs)-1].Path
			if strings.HasPrefix(it.Path, last+"/") {
				break
			}
			pendingDirs = pendingDirs[:len(pendingDirs)-1]
		}
		sel, below := Match(patterns, it.Path)
		if sel {
			out = append(out, pendingDirs...)
			pendingDirs = pendingDirs[:0]
			out = append(out, it)
			return nil
		}
		if it.Node.Type == format.NodeDir && below {
			pendingDirs = append(pendingDirs, it)
			return nil
		}
		if it.Node.Type == format.NodeDir {
			return SkipDir
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// The walk visits each directory before its contents; emitted
	// ancestors may repeat when two selections share them.
	seen := map[string]bool{}
	uniq := out[:0]
	for _, it := range out {
		if !seen[it.Path] {
			seen[it.Path] = true
			uniq = append(uniq, it)
		}
	}
	sort.SliceStable(uniq, func(i, j int) bool { return depth(uniq[i].Path) < depth(uniq[j].Path) })
	return uniq, nil
}

func depth(p string) int { return strings.Count(p, "/") }
