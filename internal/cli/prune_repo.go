package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/aws/smithy-go"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/sink"
)

// isRepoKey reports whether a key, relative to the storage prefix, is an
// incremental repository's: <node>/repo/… or repo/….
func isRepoKey(rel string) bool {
	parts := strings.Split(rel, "/")
	return (len(parts) > 1 && parts[0] == "repo") || (len(parts) > 2 && parts[1] == "repo")
}

// repoPruneStore is what pruning a repository needs from the bucket.
type repoPruneStore interface {
	sink.Store
	sink.Children
	Versions(ctx context.Context, prefix string) ([]sink.Version, error)
	Retention(ctx context.Context, key, versionID string) (time.Time, error)
	DeleteVersion(ctx context.Context, key, versionID string) error
}

// Repository objects are deleted by class of their epoch, without the
// identity: the sidecars are plaintext and say each snapshot's class and
// retain-until, and an object's class is read from its lock date, which is
// the epoch's opening or later date. An object whose class cannot be read
// that way (no lock: worm_mode NONE) is treated as opening, which keeps it
// longer, never shorter. An epoch holding the newest snapshot of its surface,
// or one the remote server keeps as last known good, keeps everything.
//
// later objects go when every non-opening snapshot of the epoch is past its
// retain-until; opening objects when every snapshot is. Either way only once
// the bucket says the lock has ended, with the grace on top. Packs, indexes,
// catalogs and snapshot objects go first, sidecars after them, epoch.json
// last, and each key's delete markers after its versions.
func pruneRepos(ctx context.Context, st repoPruneStore, keepFor func(node string) (map[string]bool, error),
	now time.Time, grace time.Duration, dryRun bool, out io.Writer, r *pruneReport) error {
	root := strings.Trim(st.Root(), "/")
	nodes, err := st.Children(ctx, root)
	if err != nil {
		return err
	}
	type place struct{ node, prefix string }
	var places []place
	if names, _ := st.Children(ctx, path.Join(root, "repo")); len(names) > 0 {
		places = append(places, place{"", root})
	}
	for _, n := range nodes {
		if n == "repo" {
			continue
		}
		if names, _ := st.Children(ctx, path.Join(root, n, "repo")); len(names) > 0 {
			places = append(places, place{n, path.Join(root, n)})
		}
	}
	for _, pl := range places {
		keep, err := keepFor(pl.node)
		if err != nil {
			fmt.Fprintf(out, "Warning: Node %s: incremental snapshots not pruned, because the remote server could not say which snapshot it keeps as last known good: %v\n", pl.node, err)
			r.Failed++
			continue
		}
		d := sink.NewDirect(&rootedStore{repoPruneStore: st, root: pl.prefix})
		surfaces, err := d.Surfaces(ctx)
		if err != nil {
			return err
		}
		for _, sf := range surfaces {
			if err := pruneSurfaceRepo(ctx, st, d, sf, keep, now, grace, dryRun, out, r); err != nil {
				fmt.Fprintf(out, "Error: Surface %s: %v\n", sf, err)
				r.Failed++
			}
		}
	}
	return nil
}

// rootedStore is a store whose repository keys start at root.
type rootedStore struct {
	repoPruneStore
	root string
}

func (s *rootedStore) Root() string { return s.root }

type sidecarInfo struct {
	key     string
	id      string
	class   string
	until   time.Time
	created time.Time
}

func pruneSurfaceRepo(ctx context.Context, st repoPruneStore, d *sink.Direct, surface string, keep map[string]bool,
	now time.Time, grace time.Duration, dryRun bool, out io.Writer, r *pruneReport) error {
	epochs, err := d.Epochs(ctx, surface)
	if err != nil {
		return err
	}
	sidecars := map[string][]sidecarInfo{}
	var newest sidecarInfo
	for _, e := range epochs {
		objs, err := d.List(ctx, e, "snapshots")
		if err != nil {
			return err
		}
		for _, o := range objs {
			if !strings.HasSuffix(o.Key, ".meta.json") {
				continue
			}
			body, err := d.Get(ctx, o.Key)
			if err != nil {
				return err
			}
			var m model.SnapshotMetadata
			if err := json.Unmarshal(body, &m); err != nil {
				return fmt.Errorf("the sidecar %s does not parse, so its epoch is not pruned: %w", o.Key, err)
			}
			si := sidecarInfo{key: o.Key, id: m.SnapshotID, class: m.ObjectClass, until: m.WORMRetentionUntil, created: m.CreatedAt}
			sidecars[e.Epoch.EpochID] = append(sidecars[e.Epoch.EpochID], si)
			if si.created.After(newest.created) {
				newest = si
			}
		}
	}
	for _, e := range epochs {
		ep := e.Epoch
		sc := sidecars[ep.EpochID]
		held := false
		laterDone, allDone := true, true
		for _, s := range sc {
			if s.id == newest.id || keep[s.id] {
				held = true
			}
			expired := !s.until.IsZero() && s.until.Add(grace).Before(now)
			if !expired {
				allDone = false
				if s.class != format.ClassOpening {
					laterDone = false
				}
			}
		}
		if len(sc) == 0 && now.Before(ep.PlannedEnd.Add(grace)) {
			// No snapshot yet: an opening run may still be uploading.
			continue
		}
		if held {
			r.Kept++
			continue
		}
		if !laterDone {
			r.Locked++
			continue
		}
		versions, err := st.Versions(ctx, e.Prefix+"/")
		if err != nil {
			return err
		}
		byKey := map[string][]sink.Version{}
		for _, v := range versions {
			byKey[v.Key] = append(byKey[v.Key], v)
		}
		keys := make([]string, 0, len(byKey))
		for k := range byKey {
			keys = append(keys, k)
		}
		// Data first, then sidecars, then the descriptor.
		rank := func(k string) int {
			switch {
			case strings.HasSuffix(k, "/epoch.json"):
				return 2
			case strings.HasSuffix(k, ".meta.json"):
				return 1
			}
			return 0
		}
		sort.Slice(keys, func(i, j int) bool {
			if rank(keys[i]) != rank(keys[j]) {
				return rank(keys[i]) < rank(keys[j])
			}
			return keys[i] < keys[j]
		})
		var deleted, locked, kept, failed int
		gone := map[string]bool{}
		for _, k := range keys {
			if rank(k) == 2 && len(gone) < len(keys)-1 {
				kept++
				continue
			}
			left := 0
			var markers []sink.Version
			for _, v := range byKey[k] {
				if v.IsMarker {
					markers = append(markers, v)
					continue
				}
				lock, err := st.Retention(ctx, k, v.VersionID)
				if err != nil {
					fmt.Fprintf(out, "Error: %s: could not read its lock: %v\n", k, err)
					failed++
					left++
					continue
				}
				class := format.ClassOpening
				if !lock.IsZero() && lock.Sub(ep.LaterRetainUntil).Abs() < time.Second {
					class = format.ClassLater
				}
				if class == format.ClassOpening && !allDone {
					kept++
					left++
					continue
				}
				if !lock.IsZero() && lock.Add(grace).After(now) {
					locked++
					left++
					continue
				}
				if err := deleteVersion(ctx, st, k, v.VersionID, dryRun, out); err != nil {
					failed++
					left++
					continue
				}
				deleted++
			}
			if left > 0 {
				continue
			}
			ok := true
			for _, m := range markers {
				if err := deleteVersion(ctx, st, k, m.VersionID, dryRun, out); err != nil {
					failed++
					ok = false
					break
				}
			}
			if ok {
				gone[k] = true
			}
		}
		r.Failed += failed
		if deleted > 0 {
			what := "later objects"
			if allDone {
				what = "objects"
			}
			verb := "deleted"
			if dryRun {
				verb = "would delete"
			}
			fmt.Fprintf(out, "   Surface %s, epoch %s: %s %d %s (%d still locked, %d kept)\n", surface, ep.EpochID, verb, deleted, what, locked, kept)
			if dryRun {
				r.WouldDelete++
			} else {
				r.Deleted++
			}
		} else if locked > 0 {
			r.Locked++
		}
	}
	return nil
}

func deleteVersion(ctx context.Context, st repoPruneStore, key, versionID string, dryRun bool, out io.Writer) error {
	if dryRun {
		fmt.Fprintf(out, "   would delete %s (%s)\n", key, versionID)
		return nil
	}
	if err := st.DeleteVersion(ctx, key, versionID); err != nil {
		var api smithy.APIError
		if errors.As(err, &api) && api.ErrorCode() == "AccessDenied" {
			fmt.Fprintf(out, "Error: %s: the bucket refused the delete. Pruning needs s3:DeleteObjectVersion and s3:GetObjectRetention "+
				"on this host's key (the recommended policy denies them).\n", key)
		} else {
			fmt.Fprintf(out, "Error: %s: %v\n", key, err)
		}
		return err
	}
	return nil
}
