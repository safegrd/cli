package cli

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

// newExportCmd copies every snapshot, as ciphertext, from this host's storage
// to a directory or to another bucket.
//
// It is the exit. A snapshot in hosted storage lives in SafeGrd's bucket, and
// leaving must never need SafeGrd's cooperation beyond a read lease, which the
// remote server never refuses. Nothing is decrypted: the key is not needed,
// and the copy is exactly what was written, which export proves by holding
// each object's SHA-256 to the digest recorded at backup time.
func newExportCmd() *cobra.Command {
	var toDir, toBucket, toEndpoint, toRegion, toPrefix, toWORM string
	var onlySnapshots, onlyNodes []string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Copy every snapshot, still encrypted, to a directory or your own bucket",
		Long: `Copy every snapshot and its metadata, still encrypted, out of this host's
storage: to a local directory (--to-dir) or to a bucket you own (--to-bucket).

Use it to move from hosted storage to your own bucket, or to keep an offline
copy. Nothing is decrypted and no key is needed. Each copied object is checked
against the digest recorded when it was backed up. A snapshot already at the
destination is skipped, so an interrupted export resumes on rerun.

--snapshot and --node narrow it to those snapshots, or to the snapshots of
those nodes. Both can be repeated or given as a comma-separated list.
Restore from an export with 'safegrd restore --from'.

Incremental (--format repo) backups are copied a whole epoch at a time, since
a snapshot needs every object of its epoch; --snapshot copies the epoch that
holds it.

Credentials for --to-bucket come from the standard AWS environment
(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, or a profile). A copy into a bucket
keeps each snapshot's lock: it is locked there until the same date. A
repository's objects are locked until their epoch's longest date, the one its
first run's objects carry.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if (toDir == "") == (toBucket == "") {
				return fmt.Errorf("choose one destination: --to-dir or --to-bucket")
			}

			srcCfg, routeErr := resolveStorageRouting(ctx, cfg, "", "", "", "", false)
			if routeErr != nil {
				return routeErr
			}
			if _, err := resolveHostedStorage(ctx, cfg, &srcCfg, false); err != nil {
				return err
			}
			resolveRuntimeCredentials(ctx, cfg, &srcCfg, false)
			if cfg.NodeID != "" && srcCfg.NodeID == "" {
				srcCfg.NodeID = cfg.NodeID
			}
			src, err := openStorage(ctx, cfg, srcCfg)
			if err != nil {
				return fmt.Errorf("source storage: %w", err)
			}

			var dstCfg config.StorageConfig
			if toDir != "" {
				dstCfg = config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: toDir}
			} else {
				dstCfg = config.StorageConfig{
					Type: config.StorageTypeS3, Bucket: toBucket, Endpoint: toEndpoint, Region: toRegion,
					Prefix: toPrefix, WORMMode: config.WORMMode(toWORM), RetentionDays: 1,
				}
			}
			dst, err := openStorage(ctx, cfg, dstCfg)
			if err != nil {
				return fmt.Errorf("destination storage: %w", err)
			}

			// Incremental repositories go first, whole epochs at a time: a
			// snapshot needs every object of its epoch.
			rCopied, rSkipped, rFailed, rMatched, rErr := exportRepos(ctx, srcCfg, dstCfg, onlySnapshots, onlyNodes)
			if rErr != nil {
				return rErr
			}

			ids, err := src.ListSnapshots(ctx)
			if err != nil {
				return fmt.Errorf("listing snapshots: %w", err)
			}
			sort.Strings(ids)
			nodes := map[string]string{}
			if loc, ok := src.(storage.NodeLocator); ok {
				if m, err := loc.SnapshotNodes(ctx); err == nil {
					nodes = m
				}
			}

			var unmatched []string
			for _, id := range onlySnapshots {
				if !rMatched[strings.TrimSpace(id)] {
					unmatched = append(unmatched, id)
				}
			}
			if len(onlySnapshots) > 0 && len(unmatched) == 0 {
				ids = nil
			} else if len(ids) > 0 || len(onlySnapshots) > 0 || rCopied+rSkipped+rFailed == 0 {
				if len(onlySnapshots) > 0 {
					onlySnapshots = unmatched
				}
				ids, err = filterExport(ids, nodes, srcCfg.NodeID, onlySnapshots, onlyNodes)
				if err != nil && rCopied+rSkipped+rFailed == 0 {
					return err
				} else if err != nil {
					ids = nil
				}
			}

			copied, skipped, failed := 0, 0, 0
			for _, id := range ids {
				node := nodes[id]
				setNode(src, node, srcCfg.NodeID)
				setNode(dst, node, srcCfg.NodeID)
				if ok, err := dst.SnapshotExists(ctx, id); err == nil && ok {
					fmt.Printf("   %s already exported\n", id)
					skipped++
					continue
				}
				if err := exportOne(ctx, src, dst, id); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s: %v\n", id, err)
					failed++
					continue
				}
				fmt.Printf("   %s exported\n", id)
				copied++
			}
			copied, skipped, failed = copied+rCopied, skipped+rSkipped, failed+rFailed
			fmt.Printf("\nExported %d, already there %d, failed %d.\n", copied, skipped, failed)
			if failed > 0 {
				return fmt.Errorf("%d snapshot(s) were not exported", failed)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&toDir, "to-dir", "", "Export into this local directory")
	cmd.Flags().StringVar(&toBucket, "to-bucket", "", "Export into this S3 bucket (yours)")
	cmd.Flags().StringVar(&toEndpoint, "to-endpoint", "", "S3 endpoint of --to-bucket (MinIO, B2, R2, ...)")
	cmd.Flags().StringVar(&toRegion, "to-region", "us-east-1", "Region of --to-bucket")
	cmd.Flags().StringVar(&toPrefix, "to-prefix", "safegrd/snapshots", "Key prefix in --to-bucket")
	cmd.Flags().StringVar(&toWORM, "to-worm-mode", "COMPLIANCE", "Object Lock mode in --to-bucket: COMPLIANCE, GOVERNANCE or NONE")
	cmd.Flags().StringSliceVar(&onlySnapshots, "snapshot", nil, "Export only this snapshot ID (repeatable)")
	cmd.Flags().StringSliceVar(&onlyNodes, "node", nil, "Export only this node's snapshots (repeatable)")
	return cmd
}

// filterExport keeps the snapshots --snapshot and --node ask for. A snapshot
// asked for by ID that is not in storage is an error, not an empty export.
func filterExport(ids []string, nodes map[string]string, fallbackNode string, onlySnapshots, onlyNodes []string) ([]string, error) {
	if len(onlySnapshots) == 0 && len(onlyNodes) == 0 {
		return ids, nil
	}
	wantID := map[string]bool{}
	for _, id := range onlySnapshots {
		wantID[strings.TrimSpace(id)] = true
	}
	wantNode := map[string]bool{}
	for _, n := range onlyNodes {
		wantNode[strings.TrimSpace(n)] = true
	}
	var kept []string
	found := map[string]bool{}
	for _, id := range ids {
		node := nodes[id]
		if node == "" {
			node = fallbackNode
		}
		if len(wantID) > 0 && !wantID[id] {
			continue
		}
		if len(wantNode) > 0 && !wantNode[node] {
			continue
		}
		kept = append(kept, id)
		found[id] = true
	}
	var missing []string
	for id := range wantID {
		if !found[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		where := "not in this host's storage"
		if len(wantNode) > 0 {
			where += " under --node " + strings.Join(onlyNodes, ", ")
		}
		return nil, fmt.Errorf("%s: %s", where, strings.Join(missing, ", "))
	}
	if len(kept) == 0 {
		return nil, fmt.Errorf("no snapshots in this host's storage belong to --node %s", strings.Join(onlyNodes, ", "))
	}
	return kept, nil
}

// setNode points a provider at the node a snapshot was filed under.
func setNode(p storage.StorageProvider, node, fallback string) {
	if node == "" {
		node = fallback
	}
	if s, ok := p.(interface{ SetNodeID(string) }); ok {
		s.SetNodeID(node)
	}
}

// exportOne copies one snapshot and its metadata, and holds the copy to the
// digest recorded at backup time.
func exportOne(ctx context.Context, src, dst storage.StorageProvider, id string) error {
	meta, err := src.DownloadMetadata(ctx, id)
	if err != nil {
		return fmt.Errorf("reading its metadata: %w", err)
	}
	body, err := src.DownloadSnapshot(ctx, id)
	if err != nil {
		return fmt.Errorf("reading it: %w", err)
	}
	defer body.Close()

	// Keep the lock it had, where it still has one; an expired lock gets the
	// destination's default rather than a date in the past.
	until := meta.WORMRetentionUntil
	if !until.After(time.Now().Add(time.Minute)) {
		until = time.Time{}
	}
	sum := sha256.New()
	uri, err := dst.UploadSnapshot(ctx, id, io.TeeReader(body, sum), -1, until)
	if err != nil {
		return fmt.Errorf("writing it: %w", err)
	}
	if got := hex.EncodeToString(sum.Sum(nil)); meta.EncryptedSha256 != "" && got != meta.EncryptedSha256 {
		return fmt.Errorf("the ciphertext read (%s) is not what was written at backup time (%s); the copy at the destination must not be trusted", got, meta.EncryptedSha256)
	}
	meta.StorageURI = uri
	if !until.IsZero() {
		meta.WORMRetentionUntil = until
	}
	if err := dst.UploadMetadata(ctx, id, meta); err != nil {
		return fmt.Errorf("writing its metadata: %w", err)
	}
	return nil
}

// exportRepos copies every incremental repository epoch from src to dst,
// keeping the layout, so 'restore --from' and a bucket used as storage read
// it as they would the original. An epoch already at the destination is
// skipped object by object. It returns the epochs copied, skipped and failed,
// and the snapshot ids --snapshot asked for that it found.
func exportRepos(ctx context.Context, srcCfg, dstCfg config.StorageConfig, onlySnapshots, onlyNodes []string) (copied, skipped, failed int, matched map[string]bool, err error) {
	matched = map[string]bool{}
	backends, err := repoBackendsAll(ctx, srcCfg)
	if err != nil {
		return 0, 0, 0, matched, fmt.Errorf("listing incremental repositories: %w", err)
	}
	wantNode := map[string]bool{}
	for _, n := range onlyNodes {
		wantNode[strings.TrimSpace(n)] = true
	}
	for _, b := range backends {
		rows, err := repoSnapshots(ctx, b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: the repository in %s could not be listed: %v\n", b.Describe(), err)
			failed++
			continue
		}
		type epochKey struct{ surface, epoch string }
		epochs := map[epochKey]repoSnapshot{}
		for _, r := range rows {
			if len(wantNode) > 0 && !wantNode[r.Meta.NodeID] {
				continue
			}
			if len(onlySnapshots) > 0 {
				hit := false
				for _, id := range onlySnapshots {
					if strings.TrimSpace(id) == r.Meta.SnapshotID {
						hit, matched[r.Meta.SnapshotID] = true, true
					}
				}
				if !hit {
					continue
				}
			}
			epochs[epochKey{r.SurfaceID, r.Epoch.Epoch.EpochID}] = r
		}
		for k, r := range epochs {
			node := r.Meta.NodeID
			if node == "" {
				node = srcCfg.NodeID
			}
			dc := dstCfg
			dc.NodeID = node
			dst, err := repoBackend(ctx, cfg, dc)
			if err != nil {
				return copied, skipped, failed, matched, fmt.Errorf("destination storage: %w", err)
			}
			d, ok := dst.(*sink.Direct)
			if !ok {
				return copied, skipped, failed, matched, fmt.Errorf("an incremental repository can be exported to a directory or a bucket")
			}
			n, already, err := exportEpoch(ctx, r.Backend, r.Epoch, d, k.surface)
			label := fmt.Sprintf("%s epoch %s (%d objects)", k.surface, k.epoch, n+already)
			switch {
			case err != nil:
				fmt.Fprintf(os.Stderr, "Error: %s: %v\n", label, err)
				failed++
			case n == 0:
				fmt.Printf("   %s already exported\n", label)
				skipped++
			default:
				fmt.Printf("   %s exported\n", label)
				copied++
			}
		}
	}
	return copied, skipped, failed, matched, nil
}

// exportEpoch copies one epoch's objects, epoch.json last so a reader never
// finds a descriptor over a half-copied epoch. It holds every copy to the
// source object's length; the bytes are sealed, and a restore or check of
// the copy proves them.
func exportEpoch(ctx context.Context, src sink.Backend, e sink.EpochInfo, dst *sink.Direct, surface string) (copied, already int, err error) {
	objs, err := src.List(ctx, e, "")
	if err != nil {
		return 0, 0, err
	}
	dstPrefix := sink.EpochPrefix(dst.S.Root(), surface, e.Epoch.EpochID)
	have := map[string]int64{}
	if existing, err := dst.S.List(ctx, dstPrefix+"/"); err == nil {
		for _, o := range existing {
			have[o.Key] = o.Size
		}
	}
	lock := e.Epoch.OpeningRetainUntil
	if min := time.Now().Add(24 * time.Hour); lock.Before(min) {
		lock = min
	}
	sort.Slice(objs, func(i, j int) bool {
		return !strings.HasSuffix(objs[i].Key, "/epoch.json") && strings.HasSuffix(objs[j].Key, "/epoch.json")
	})
	for _, o := range objs {
		rel := strings.TrimPrefix(o.Key, e.Prefix)
		key := dstPrefix + rel
		if size, ok := have[key]; ok && size == o.Size {
			already++
			continue
		}
		body, err := src.Get(ctx, o.Key)
		if err != nil {
			return copied, already, fmt.Errorf("%s: %w", o.Key, err)
		}
		if int64(len(body)) != o.Size {
			return copied, already, fmt.Errorf("%s: read %d bytes, storage lists %d", o.Key, len(body), o.Size)
		}
		if err := dst.S.Put(ctx, key, body, md5.Sum(body), lock); err != nil {
			return copied, already, fmt.Errorf("%s: %w", key, err)
		}
		copied++
	}
	return copied, already, nil
}
