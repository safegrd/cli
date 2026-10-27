package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/erasure"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/storage"
)

// Pruning the erasure record. An object of a surface's record matters while
// a snapshot older than its newest erasure exists: a restore of that
// snapshot replays it. Prune deletes an object once its lock has ended and
// no snapshot of its surface is older than the newest erasure it holds
// (erasure.NeededBy reads that from the object's name). The marker,
// record.json, stays while the surface has any snapshot at all: a restore
// that finds the directory without it stops. A bucket with no Object Lock
// and a local directory have no lock to wait for, so the snapshot rule and
// the grace decide alone. Hosted storage is pruned by the remote server
// under the same rule.

// oldestRepoSnapshot is when the oldest snapshot of a surface's repository
// was taken, read from the sidecars, and false when it has none.
func oldestRepoSnapshot(ctx context.Context, d *sink.Direct, surface string) (time.Time, bool, error) {
	epochs, err := d.Epochs(ctx, surface)
	if err != nil {
		return time.Time{}, false, err
	}
	var oldest time.Time
	found := false
	for _, e := range epochs {
		objs, err := d.List(ctx, e, "snapshots")
		if err != nil {
			return time.Time{}, false, err
		}
		for _, o := range objs {
			if !strings.HasSuffix(o.Key, ".meta.json") {
				continue
			}
			body, err := d.Get(ctx, o.Key)
			if err != nil {
				return time.Time{}, false, err
			}
			var m model.SnapshotMetadata
			if err := json.Unmarshal(body, &m); err != nil {
				return time.Time{}, false, fmt.Errorf("the sidecar %s does not parse, so the erasure record is not pruned: %w", o.Key, err)
			}
			if !found || m.CreatedAt.Before(oldest) {
				oldest, found = m.CreatedAt, true
			}
		}
	}
	return oldest, found, nil
}

// erasurePruneDecision says what to do with one object of the record.
type erasurePruneDecision int

const (
	erasureKeep    erasurePruneDecision = iota // a snapshot still needs it
	erasureLocked                              // nothing needs it; its lock has not ended
	erasureExpired                             // delete it
)

// decideErasureObject applies the rule to one object. lockEnds is the
// object's lock, zero where the storage has none; written is when the object
// was written, read from its name, for the grace on storage with no lock.
func decideErasureObject(name string, oldest time.Time, anySnapshot bool, lockEnds time.Time, now time.Time, grace time.Duration, othersLeft bool) erasurePruneDecision {
	if erasure.IsMarker(name) {
		if anySnapshot || othersLeft {
			return erasureKeep
		}
	} else if anySnapshot && erasure.NeededBy(name, oldest) {
		return erasureKeep
	}
	if !lockEnds.IsZero() {
		if lockEnds.Add(grace).After(now) {
			return erasureLocked
		}
		return erasureExpired
	}
	if newest, ok := erasure.NewestIn(name); ok && newest.Add(grace).After(now) {
		return erasureLocked
	}
	return erasureExpired
}

// sayErasuresPruned prints one surface's outcome.
func sayErasuresPruned(out pruneWriters, surface string, deleted, locked, kept int, dryRun bool) {
	if deleted == 0 {
		return
	}
	verb := "deleted"
	if dryRun {
		verb = "would delete"
	}
	fmt.Fprintf(out.Out, "   Surface %s: %s %d erasure record %s no backup needs (%d still locked, %d kept)\n",
		surface, verb, deleted, pluralWord(int64(deleted), "object", "objects"), locked, kept)
}

// pruneErasuresIn prunes every surface's record under one node's prefix in
// a bucket or on an SFTP server. d reads the node's repositories, for the
// oldest snapshot of each surface.
func pruneErasuresIn(ctx context.Context, st repoPruneStore, d *sink.Direct, prefix string, now time.Time, grace time.Duration, dryRun bool, out pruneWriters, r *pruneReport) error {
	surfaces, err := st.Children(ctx, path.Join(prefix, "erasures"))
	if err != nil {
		return err
	}
	sort.Strings(surfaces)
	for _, sf := range surfaces {
		oldest, any, err := oldestRepoSnapshot(ctx, d, sf)
		if err != nil {
			fmt.Fprintf(out.Err, "Error: Surface %s: erasure record not pruned: %v\n", sf, err)
			r.Failed++
			continue
		}
		versions, err := st.Versions(ctx, path.Join(prefix, "erasures", sf)+"/")
		if err != nil {
			fmt.Fprintf(out.Err, "Error: Surface %s: erasure record not listed: %v\n", sf, err)
			r.Failed++
			continue
		}
		byKey := map[string][]sink.Version{}
		for _, v := range versions {
			byKey[v.Key] = append(byKey[v.Key], v)
		}
		keys := make([]string, 0, len(byKey))
		for k := range byKey {
			keys = append(keys, k)
		}
		// Objects first, the marker last, so it goes only once nothing else
		// is left.
		sort.Slice(keys, func(i, j int) bool {
			mi, mj := erasure.IsMarker(keys[i]), erasure.IsMarker(keys[j])
			if mi != mj {
				return mj
			}
			return keys[i] < keys[j]
		})
		var deleted, locked, kept int
		left := map[string]bool{}
		for _, k := range keys {
			left[k] = true
		}
		for _, k := range keys {
			othersLeft := false
			for o := range left {
				if o != k {
					othersLeft = true
					break
				}
			}
			var markers []sink.Version
			remaining := 0
			for _, v := range byKey[k] {
				if v.IsMarker {
					markers = append(markers, v)
					continue
				}
				lock, err := st.Retention(ctx, k, v.VersionID)
				if err != nil {
					fmt.Fprintf(out.Err, "Error: %s: could not read its lock: %v\n", k, err)
					r.Failed++
					remaining++
					continue
				}
				switch decideErasureObject(k, oldest, any, lock, now, grace, othersLeft) {
				case erasureKeep:
					kept++
					remaining++
				case erasureLocked:
					locked++
					remaining++
				default:
					if err := deleteVersion(ctx, st, k, v.VersionID, dryRun, out); err != nil {
						r.Failed++
						remaining++
						continue
					}
					deleted++
				}
			}
			if remaining > 0 {
				continue
			}
			gone := true
			for _, m := range markers {
				if err := deleteVersion(ctx, st, k, m.VersionID, dryRun, out); err != nil {
					r.Failed++
					gone = false
					break
				}
			}
			if gone && !dryRun {
				delete(left, k)
			}
		}
		sayErasuresPruned(out, sf, deleted, locked, kept, dryRun)
		if dryRun {
			r.WouldDeleteErasures += deleted
		} else {
			r.Erasures += deleted
		}
	}
	return nil
}

// pruneLocalErasures prunes the erasure records in a local directory. The
// snapshots there are not pruned: a directory has no lock or clock to judge
// by. A record object has no lock either, so it goes once no snapshot of its
// surface is older than its newest erasure and the grace has passed since
// that erasure.
func pruneLocalErasures(ctx context.Context, c *config.CLIConfig, storageCfg config.StorageConfig, grace time.Duration, dryRun bool, out pruneWriters) (pruneReport, error) {
	var r pruneReport
	base := storageCfg.LocalPath
	if base == "" {
		base = "./safegrd-storage"
	}
	objs, err := storage.NewLocalStorage(base)
	if err != nil {
		return r, err
	}
	dirs, err := filepath.Glob(filepath.Join(base, "*", "erasures", "*"))
	if err != nil {
		return r, err
	}
	fmt.Fprintf(out.Out, "   Snapshots on local storage are not pruned (a directory has no lock to judge by); the erasure record is.\n")
	now := time.Now()
	sort.Strings(dirs)
	for _, dir := range dirs {
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		sf := filepath.Base(dir)
		node := filepath.Base(filepath.Dir(filepath.Dir(dir)))
		nc := storageCfg
		nc.NodeID = node
		b, err := repoBackend(ctx, c, nc)
		if err != nil {
			return r, err
		}
		d, ok := b.(*sink.Direct)
		if !ok {
			return r, fmt.Errorf("local storage's repositories could not be read for node %s", node)
		}
		oldest, any, err := oldestRepoSnapshot(ctx, d, sf)
		if err != nil {
			fmt.Fprintf(out.Err, "Error: Surface %s: erasure record not pruned: %v\n", sf, err)
			r.Failed++
			continue
		}
		rel := erasureRecordPath(node, sf)
		names, err := objs.ListObjects(ctx, rel)
		if err != nil {
			fmt.Fprintf(out.Err, "Error: Surface %s: erasure record not listed: %v\n", sf, err)
			r.Failed++
			continue
		}
		left := map[string]bool{}
		for _, n := range names {
			left[n] = true
		}
		// The marker last.
		sort.SliceStable(names, func(i, j int) bool { return !erasure.IsMarker(names[i]) && erasure.IsMarker(names[j]) })
		var deleted, locked, kept int
		for _, n := range names {
			othersLeft := false
			for o := range left {
				if o != n {
					othersLeft = true
					break
				}
			}
			switch decideErasureObject(n, oldest, any, time.Time{}, now, grace, othersLeft) {
			case erasureKeep:
				kept++
			case erasureLocked:
				locked++
			default:
				if dryRun {
					fmt.Fprintf(out.Out, "   would delete %s\n", n)
					deleted++
					continue
				}
				if err := objs.DeleteObject(ctx, n); err != nil {
					fmt.Fprintf(out.Err, "Error: %s: %v\n", n, err)
					r.Failed++
					continue
				}
				delete(left, n)
				deleted++
			}
		}
		sayErasuresPruned(out, sf, deleted, locked, kept, dryRun)
		if dryRun {
			r.WouldDeleteErasures += deleted
		} else {
			r.Erasures += deleted
		}
	}
	return r, nil
}
