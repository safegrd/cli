package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/safegrd/cli/pkg/config"
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
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Copy every snapshot, still encrypted, to a directory or your own bucket",
		Long: `Copy every snapshot and its metadata, still encrypted, out of this host's
storage: to a local directory (--to-dir) or to a bucket you own (--to-bucket).

Use it to move from hosted storage to your own bucket, or to keep an offline
copy. Nothing is decrypted and no key is needed. Each copied object is checked
against the digest recorded when it was backed up. A snapshot already at the
destination is skipped, so an interrupted export can simply be run again.

Credentials for --to-bucket come from the standard AWS environment
(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, or a profile). A copy into a bucket
keeps each snapshot's lock: it is locked there until the same date.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			if (toDir == "") == (toBucket == "") {
				return fmt.Errorf("choose one destination: --to-dir or --to-bucket")
			}

			srcCfg := resolveStorageRouting(ctx, cfg, "", "", "", "", false)
			if _, err := resolveHostedStorage(ctx, cfg, &srcCfg, false); err != nil {
				return err
			}
			resolveRuntimeCredentials(ctx, cfg, &srcCfg, false)
			if cfg.NodeID != "" && srcCfg.NodeID == "" {
				srcCfg.NodeID = cfg.NodeID
			}
			src, err := storage.NewProvider(ctx, srcCfg)
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
			dst, err := storage.NewProvider(ctx, dstCfg)
			if err != nil {
				return fmt.Errorf("destination storage: %w", err)
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

			copied, skipped, failed := 0, 0, 0
			for _, id := range ids {
				node := nodes[id]
				setNode(src, node, srcCfg.NodeID)
				setNode(dst, node, srcCfg.NodeID)
				if ok, err := dst.SnapshotExists(ctx, id); err == nil && ok {
					fmt.Printf("   ⏭️  %s already exported\n", id)
					skipped++
					continue
				}
				if err := exportOne(ctx, src, dst, id); err != nil {
					fmt.Fprintf(os.Stderr, "❌ %s: %v\n", id, err)
					failed++
					continue
				}
				fmt.Printf("   ✅ %s\n", id)
				copied++
			}
			fmt.Printf("\n📦 Exported %d, already there %d, failed %d.\n", copied, skipped, failed)
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
	return cmd
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
