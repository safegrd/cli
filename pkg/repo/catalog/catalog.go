// Package catalog answers "which versions of this file are kept, and in
// which snapshots" by replaying the catalog deltas of every retained epoch of
// a surface in snapshot order. Across epochs, versions are joined by the
// file's SHA-256, never by chunk id. It runs where the identity is; the
// catalog is derived data, and a restore always checks bytes against trees.
package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/repo/check"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/unseal"
)

// Snapshot is one retained snapshot, in the order versions are counted.
type Snapshot struct {
	SnapshotID string    `json:"snapshot_id"`
	EpochID    string    `json:"epoch_id"`
	RunID      string    `json:"run_id"`
	CreatedAt  time.Time `json:"created_at"`
	Class      string    `json:"class"`
}

// Version is one content of one path, kept by a run of consecutive
// snapshots.
type Version struct {
	N      int    `json:"version"`
	Type   string `json:"type"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode,omitempty"`
	// First and Last are the first and last snapshots that hold it.
	First Snapshot `json:"first"`
	Last  Snapshot `json:"last"`
	// Snapshots counts the retained snapshots that hold it; Epochs, the
	// epochs they are in.
	Snapshots int `json:"snapshots"`
	Epochs    int `json:"epochs"`
	// Current is set when the newest snapshot holds this version.
	Current bool `json:"current"`
}

// History is every kept version of one path, oldest first.
type History struct {
	Path     string    `json:"path"`
	Versions []Version `json:"versions"`
	// Deleted is set when the newest snapshot no longer holds the path.
	Deleted bool `json:"deleted"`
}

// Source is the epochs of one surface, and where to cache what was opened.
type Source struct {
	Backend sink.Backend
	Epochs  []sink.EpochInfo
	IDs     []age.Identity
	// CacheDir, when set, keeps the opened snapshots and catalogs, which
	// never change, so the second search reads nothing from storage. It
	// holds file names, so it is created 0700.
	CacheDir string
}

type cachedRun struct {
	Snapshot Snapshot       `json:"snapshot"`
	Catalog  format.Catalog `json:"catalog"`
}

// load returns every retained snapshot of the source with its catalog, in
// snapshot order.
func (s Source) load(ctx context.Context) ([]cachedRun, error) {
	var runs []cachedRun
	if s.CacheDir != "" {
		if err := os.MkdirAll(s.CacheDir, 0o700); err != nil {
			return nil, err
		}
	}
	for _, e := range s.Epochs {
		ids, err := check.Snapshots(ctx, s.Backend, e)
		if err != nil {
			return nil, err
		}
		r := read.Open(s.Backend, e, s.IDs)
		for _, id := range ids {
			cachePath := ""
			if s.CacheDir != "" {
				cachePath = filepath.Join(s.CacheDir, e.Epoch.EpochID+"-"+id+".json")
				if b, err := os.ReadFile(cachePath); err == nil {
					var cr cachedRun
					if json.Unmarshal(b, &cr) == nil && cr.Snapshot.SnapshotID == id {
						runs = append(runs, cr)
						continue
					}
				}
			}
			snap, err := r.Snapshot(ctx, id)
			if err != nil {
				return nil, err
			}
			key, _ := sink.ObjectKey(e.Prefix, sink.KindCatalog, snap.RunID)
			body, err := s.Backend.Get(ctx, key)
			if errors.Is(err, sink.ErrNotFound) {
				return nil, fmt.Errorf("snapshot %s has no catalog in storage", id)
			}
			if err != nil {
				return nil, err
			}
			var c format.Catalog
			if err := unseal.Object(body, s.IDs, &c); err != nil {
				return nil, fmt.Errorf("the catalog of %s: %w", id, err)
			}
			if err := c.Validate(); err != nil {
				return nil, err
			}
			if c.SnapshotID != id || c.RunID != snap.RunID {
				return nil, fmt.Errorf("the catalog of run %s names snapshot %s, not %s", snap.RunID, c.SnapshotID, id)
			}
			cr := cachedRun{Snapshot: Snapshot{SnapshotID: id, EpochID: e.Epoch.EpochID, RunID: snap.RunID, CreatedAt: snap.CreatedAt, Class: snap.Class}, Catalog: c}
			if cachePath != "" {
				if b, err := json.Marshal(cr); err == nil {
					_ = os.WriteFile(cachePath, b, 0o600) // a cache: the next search reads storage again without it
				}
			}
			runs = append(runs, cr)
		}
	}
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].Snapshot.CreatedAt.Before(runs[j].Snapshot.CreatedAt) })
	return runs, nil
}

type open struct {
	v      Version
	first  int
	epochs map[string]bool
}

// Find returns the history of every path the patterns select, as `restore
// --path` selects them. With deleted set, only paths the newest snapshot no
// longer holds.
func (s Source) Find(ctx context.Context, patterns []string, deleted bool) ([]History, []Snapshot, error) {
	runs, err := s.load(ctx)
	if err != nil {
		return nil, nil, err
	}
	snaps := make([]Snapshot, len(runs))
	for i, r := range runs {
		snaps[i] = r.Snapshot
	}
	cur := map[string]*open{}
	hist := map[string][]Version{}
	closeAt := func(p string, last int) {
		o := cur[p]
		if o == nil {
			return
		}
		o.v.Last = snaps[last]
		o.v.Snapshots = last - o.first + 1
		o.v.Epochs = len(o.epochs)
		hist[p] = append(hist[p], o.v)
		delete(cur, p)
	}
	for i, r := range runs {
		c := r.Catalog
		if c.Complete {
			present := map[string]bool{}
			for _, e := range c.Entries {
				present[e.Path] = true
			}
			for p := range cur {
				if !present[p] {
					closeAt(p, i-1)
				}
			}
		}
		for _, e := range c.Entries {
			if ok, _ := read.Match(patterns, e.Path); !ok {
				continue
			}
			if e.Event == format.EventDeleted {
				closeAt(e.Path, i-1)
				continue
			}
			sha := e.SHA256
			if o := cur[e.Path]; o != nil && o.v.Type == e.Type && o.v.SHA256 == sha {
				o.epochs[r.Snapshot.EpochID] = true
				continue
			}
			if cur[e.Path] != nil {
				closeAt(e.Path, i-1)
			}
			cur[e.Path] = &open{v: Version{Type: e.Type, SHA256: sha, Size: e.Size, Mode: e.Mode, First: r.Snapshot},
				first: i, epochs: map[string]bool{r.Snapshot.EpochID: true}}
		}
	}
	for p := range cur {
		closeAt(p, len(snaps)-1)
		hist[p][len(hist[p])-1].Current = true
	}
	var out []History
	for p, vs := range hist {
		sort.Slice(vs, func(i, j int) bool { return vs[i].First.CreatedAt.Before(vs[j].First.CreatedAt) })
		for i := range vs {
			vs[i].N = i + 1
		}
		h := History{Path: p, Versions: vs, Deleted: !vs[len(vs)-1].Current}
		if deleted && !h.Deleted {
			continue
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, snaps, nil
}
