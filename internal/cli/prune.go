package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/aws/smithy-go"
	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

// Expiry in the customer's own bucket, opt-in (storage.expire_after_lock, or
// `safegrd prune` by hand). A snapshot goes once its Object Lock has ended,
// with a day of grace, and only then. The bucket decides: its lock, read per
// version, and its clock (the Date of its own answer), never this host's.
// Deletes name a version; delete markers go last; a snapshot's metadata goes
// only after the snapshot. Two snapshots per surface are never deleted: the
// newest one, and the last known good one before an open Threat Shield
// anomaly, which the remote server names. If it cannot be asked, nothing is
// pruned.

// pruneGrace is how long after a lock ends a snapshot is kept anyway.
const pruneGrace = 24 * time.Hour

// pruneEvery is how often the agent prunes when expire_after_lock is on.
const pruneEvery = 24 * time.Hour

type pruneReport struct {
	Deleted     int
	WouldDelete int
	Locked      int
	Kept        int
	Held        int
	Failed      int
}

func (r pruneReport) String() string {
	if r.WouldDelete > 0 {
		return fmt.Sprintf("%d would be deleted, %d still locked, %d kept (newest or last known good), %d held, %d failed",
			r.WouldDelete, r.Locked, r.Kept, r.Held, r.Failed)
	}
	return fmt.Sprintf("%d deleted, %d still locked, %d kept (newest or last known good), %d held, %d failed",
		r.Deleted, r.Locked, r.Kept, r.Held, r.Failed)
}

// pruneBucket is the bucket's side of pruning.
type pruneBucket interface {
	SnapshotVersions(ctx context.Context) ([]storage.VersionInfo, error)
	VersionLock(ctx context.Context, key, versionID string) (time.Time, bool, error)
	DeleteVersion(ctx context.Context, key, versionID string) error
	BucketNow(ctx context.Context) (time.Time, error)
	Prefix() string
	LockDisabled() bool
}

// pruneSnapshot is one snapshot's objects in the bucket.
type pruneSnapshot struct {
	id, node string
	data     []storage.VersionInfo // the .safegrd key's versions and markers
	meta     []storage.VersionInfo // the .meta.json key's
	dataKey  string
	metaKey  string
	newest   time.Time
}

// runPrune deletes (or, dryRun, lists) what has expired. keepFor returns
// the snapshot ids the remote server keeps for a node; retainUntil reads the
// "kept until" date recorded in the metadata at a listed key, which decides
// under worm_mode NONE.
func runPrune(ctx context.Context, b pruneBucket, keepFor func(node string) (map[string]bool, error),
	retainUntil func(metaKey string) (time.Time, error), dryRun bool, out io.Writer) (pruneReport, error) {
	return runPruneWithGrace(ctx, b, keepFor, retainUntil, pruneGrace, dryRun, out)
}

func runPruneWithGrace(ctx context.Context, b pruneBucket, keepFor func(node string) (map[string]bool, error),
	retainUntil func(metaKey string) (time.Time, error), grace time.Duration, dryRun bool, out io.Writer) (pruneReport, error) {
	var r pruneReport
	now, err := b.BucketNow(ctx)
	if err != nil {
		return r, err
	}
	versions, err := b.SnapshotVersions(ctx)
	if err != nil {
		return r, err
	}
	prefix := strings.TrimSuffix(b.Prefix(), "/")
	snaps := map[string]*pruneSnapshot{}
	for _, v := range versions {
		rel := strings.TrimPrefix(v.Key, prefix+"/")
		name := path.Base(rel)
		var id string
		isMeta := false
		switch {
		case strings.HasSuffix(name, ".safegrd"):
			id = strings.TrimSuffix(name, ".safegrd")
		case strings.HasSuffix(name, ".meta.json"):
			id, isMeta = strings.TrimSuffix(name, ".meta.json"), true
		default:
			continue
		}
		node := ""
		if dir := path.Dir(rel); dir != "." {
			node = path.Base(dir)
		}
		k := node + "/" + id
		s := snaps[k]
		if s == nil {
			s = &pruneSnapshot{id: id, node: node}
			snaps[k] = s
		}
		if isMeta {
			s.meta, s.metaKey = append(s.meta, v), v.Key
		} else {
			s.data, s.dataKey = append(s.data, v), v.Key
			if !v.IsMarker && v.LastModified.After(s.newest) {
				s.newest = v.LastModified
			}
		}
	}

	// Per surface: the newest snapshot, and what the remote server keeps.
	byNode := map[string][]*pruneSnapshot{}
	for _, s := range snaps {
		byNode[s.node] = append(byNode[s.node], s)
	}
	nodes := make([]string, 0, len(byNode))
	for n := range byNode {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	for _, node := range nodes {
		list := byNode[node]
		sort.Slice(list, func(i, j int) bool { return list[i].newest.After(list[j].newest) })
		keep, err := keepFor(node)
		if err != nil {
			fmt.Fprintf(out, "⚠️  Surface %s: not pruned, because the remote server could not say which snapshot it keeps as last known good: %v\n", node, err)
			r.Failed++
			continue
		}
		for i, s := range list {
			if (i == 0 && !s.newest.IsZero()) || keep[s.id] {
				r.Kept++
				continue
			}
			pruneOne(ctx, b, s, now, grace, retainUntil, dryRun, out, &r)
		}
	}
	return r, nil
}

// pruneOne deletes one snapshot's expired versions, its markers once nothing
// is under them, and then its metadata the same way. The report counts
// snapshots, as its other columns do, not the objects each one is made of.
func pruneOne(ctx context.Context, b pruneBucket, s *pruneSnapshot, now time.Time, grace time.Duration,
	retainUntil func(string) (time.Time, error), dryRun bool, out io.Writer, r *pruneReport) {
	expired := func(v storage.VersionInfo) bool {
		var until time.Time
		if b.LockDisabled() {
			if s.metaKey == "" {
				r.Held++
				return false
			}
			t, err := retainUntil(s.metaKey)
			if err != nil || t.IsZero() {
				r.Held++
				return false
			}
			until = t
		} else {
			t, hold, err := b.VersionLock(ctx, v.Key, v.VersionID)
			switch {
			case err != nil:
				fmt.Fprintf(out, "❌ %s: could not read its lock: %v\n", v.Key, err)
				r.Failed++
				return false
			case hold:
				r.Held++
				return false
			case t.IsZero():
				// Every snapshot is written locked; one that is not is for a
				// person to look at, not for pruning to clean up.
				fmt.Fprintf(out, "⚠️  %s has no Object Lock; not deleted\n", v.Key)
				r.Held++
				return false
			}
			until = t
		}
		if until.Add(grace).After(now) {
			r.Locked++
			return false
		}
		return true
	}
	removed := 0
	del := func(v storage.VersionInfo) bool {
		if dryRun {
			fmt.Fprintf(out, "   would delete %s (%s)\n", v.Key, v.VersionID)
			removed++
			return true
		}
		if err := b.DeleteVersion(ctx, v.Key, v.VersionID); err != nil {
			var api smithy.APIError
			if errors.As(err, &api) && api.ErrorCode() == "AccessDenied" {
				fmt.Fprintf(out, "❌ %s: the bucket refused the delete. Pruning needs s3:DeleteObjectVersion and s3:GetObjectRetention "+
					"on this host's key (the recommended policy denies them).\n", v.Key)
			} else {
				fmt.Fprintf(out, "❌ %s: %v\n", v.Key, err)
			}
			r.Failed++
			return false
		}
		removed++
		return true
	}
	// purge deletes a key's expired versions, then its markers when nothing
	// real is left; it reports whether the key is gone.
	purge := func(vs []storage.VersionInfo) bool {
		left := 0
		var markers []storage.VersionInfo
		for _, v := range vs {
			if v.IsMarker {
				markers = append(markers, v)
				continue
			}
			if !expired(v) || !del(v) {
				left++
			}
		}
		if left > 0 {
			return false
		}
		for _, m := range markers {
			if !del(m) {
				return false
			}
		}
		return true
	}
	defer func() {
		if removed == 0 {
			return
		}
		if dryRun {
			r.WouldDelete++
		} else {
			r.Deleted++
		}
	}()
	if !purge(s.data) {
		return
	}
	purge(s.meta)
}

// serverKeepList asks the remote server which snapshots of a surface it
// keeps: the last known good one of each open anomaly.
func serverKeepList(ctx context.Context, c *config.CLIConfig, node string) (map[string]bool, error) {
	if !hostIsEnrolled(c) {
		return nil, errors.New("this host is not enrolled (no server_url and server_token)")
	}
	if node == "" {
		node = c.NodeID
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.ServerURL, "/")+"/api/v1/nodes/"+url.PathEscape(node)+"/anomalies", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.ServerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var list []struct {
		FrozenSnapshotID string     `json:"frozen_snapshot_id"`
		ResolvedAt       *time.Time `json:"resolved_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, a := range list {
		if a.ResolvedAt == nil && a.FrozenSnapshotID != "" {
			keep[a.FrozenSnapshotID] = true
		}
	}
	return keep, nil
}

// pruneOwnBucket prunes the configured S3 bucket.
func pruneOwnBucket(ctx context.Context, c *config.CLIConfig, grace time.Duration, dryRun bool, out io.Writer) (pruneReport, error) {
	storageCfg := resolveStorageRouting(ctx, c, "", "", "", "", false)
	if storageCfg.Type != config.StorageTypeS3 {
		return pruneReport{}, fmt.Errorf("prune works on your own S3 bucket (storage.type: s3), not %q: hosted storage expires on its own, "+
			"and a local directory has no lock or clock to judge by", storageCfg.Type)
	}
	resolveRuntimeCredentials(ctx, c, &storageCfg, false)
	sp, err := openStorage(ctx, c, storageCfg)
	if err != nil {
		return pruneReport{}, err
	}
	b, ok := sp.(*storage.S3StorageProvider)
	if !ok {
		return pruneReport{}, errors.New("prune needs the S3 provider")
	}
	retainUntil := func(metaKey string) (time.Time, error) { return b.RecordedRetainUntil(ctx, metaKey) }
	return runPruneWithGrace(ctx, b, func(node string) (map[string]bool, error) { return serverKeepList(ctx, c, node) }, retainUntil, grace, dryRun, out)
}

func newPruneCmd() *cobra.Command {
	var dryRun bool
	var grace time.Duration
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Delete snapshots from your own bucket once their Object Lock has ended",
		Long: `Delete snapshots from your own S3 bucket whose Object Lock ended more than a day ago,
by the bucket's clock. Never the newest snapshot of a surface, and never the last known
good one the remote server keeps while Threat Shield has an open anomaly on it.

Needs s3:DeleteObjectVersion and s3:GetObjectRetention on this host's key, which the
recommended bucket policy denies. Set storage.expire_after_lock: true for the agent to
prune once a day.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if grace < 0 {
				return errors.New("--grace cannot be negative")
			}
			r, err := pruneOwnBucket(context.Background(), cfg, grace, dryRun, os.Stdout)
			if err != nil {
				return err
			}
			fmt.Printf("Prune: %s\n", r)
			if r.Failed > 0 {
				return fmt.Errorf("%d could not be pruned; see above", r.Failed)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "List what would be deleted, and delete nothing")
	cmd.Flags().DurationVar(&grace, "grace", pruneGrace, "How long after a lock ends a snapshot is kept anyway (the bucket refuses a locked one regardless)")
	return cmd
}
