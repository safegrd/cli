package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List immutable snapshots stored in WORM storage",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			// Routed and credentialed like backup and restore. A node enrolled
			// under Journey A has no bucket or sink secret locally, so reading
			// cfg.Storage directly means this command cannot reach the bucket
			// at all on exactly the hosts central configuration exists for.
			storageCfg := resolveStorageRouting(ctx, cfg, "", "", "", "", false)
			resolveRuntimeCredentials(ctx, cfg, &storageCfg, false)
			if cfg.NodeID != "" && storageCfg.NodeID == "" {
				storageCfg.NodeID = cfg.NodeID
			}
			storageProvider, err := storage.NewProvider(ctx, storageCfg)
			if err != nil {
				return fmt.Errorf("storage error: %w", err)
			}

			snapshots, err := storageProvider.ListSnapshots(ctx)
			if err != nil {
				return fmt.Errorf("failed to list snapshots: %w", err)
			}

			// Checked before the empty case, because "no snapshots" and "your
			// snapshots were deleted and Object Lock saved them" are very
			// different situations that used to print the same sentence.
			shadowed := warnAboutShadowedSnapshots(ctx, storageProvider)

			if len(snapshots) == 0 {
				if shadowed == 0 {
					fmt.Println("No snapshots found in storage.")
				}
				return nil
			}

			// The node each snapshot was filed under: restore needs it, and on
			// a machine rebuilding a lost host nothing else says what it is.
			var nodes map[string]string
			if loc, ok := storageProvider.(storage.NodeLocator); ok {
				nodes, _ = loc.SnapshotNodes(ctx)
			}
			setNode, canSetNode := storageProvider.(interface{ SetNodeID(string) })

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "SNAPSHOT ID\tNODE\tSURFACE\tCONTENTS\tENC SIZE\tRETENTION\tSTATUS")

			var undescribed int
			for _, snapID := range snapshots {
				node, known := nodes[snapID]
				if known && canSetNode {
					setNode.SetNodeID(node)
				}
				if node == "" {
					node = "-"
				}
				meta, err := storageProvider.DownloadMetadata(ctx, snapID)
				if err != nil {
					// A row of dashes and "[metadata unavailable]" said neither
					// what was missing nor whether the snapshot was still any
					// good, and listing is the one thing a person runs this
					// command for.
					undescribed++
					fmt.Fprintf(w, "%s\t%s\t?\t?\t?\t?\t%s\n", snapID, node, describeMissingMetadata(err))
					continue
				}

				status := string(meta.Status)
				if meta.IsPoisonPillFrozen {
					status = "🚨 ANOMALOUS"
				}

				surface := string(meta.SurfaceType)
				if surface == "" {
					surface = "unknown"
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%.2f MB\t%s\t%s\n",
					meta.SnapshotID,
					node,
					surface,
					describeContents(meta),
					float64(meta.EncryptedSizeBytes)/(1024*1024),
					describeRetention(meta, storageCfg),
					status,
				)
			}

			w.Flush()

			if undescribed > 0 {
				// Said after the table rather than in it, because it is about
				// the sidecar and not about the backup: the manifest itself is
				// sealed inside the encrypted archive, so a snapshot
				// nothing here can describe still restores and still verifies.
				fmt.Fprintf(os.Stderr,
					"\n⚠️  %d snapshot(s) above could not be described. The sidecar beside the object is\n"+
						"   what this table reads; it is routing data, not the backup. The manifest is sealed\n"+
						"   inside the encrypted archive, so those snapshots still restore — run\n"+
						"   'safegrd verify --snapshot <id>' with the identity to read what is in them.\n",
					undescribed)
			}
			return nil
		},
	}
}

// describeContents says what is in a snapshot in the vocabulary of its own
// surface.
//
// It reads TotalItems and TotalContainers — the surface-neutral pair that
// CalculateTotals populates for every surface — rather than TotalTables and
// TotalRows, which are set only for Postgres. Reading the Postgres-only pair is
// why a file backup of two files listed as 0 tables and 0 rows: the columns were
// not merely mislabelled, they were reading fields nothing had written.
func describeContents(meta *model.SnapshotMetadata) string {
	switch meta.SurfaceType {
	case model.SurfaceTypeFiles:
		return fmt.Sprintf("%d files, %d dirs", meta.TotalItems, meta.TotalContainers)
	case model.SurfaceTypeEmail:
		return fmt.Sprintf("%d emails, %d folders", meta.TotalItems, meta.TotalContainers)
	case model.SurfaceTypeMongoDB:
		return fmt.Sprintf("%d documents, %d collections", meta.TotalItems, meta.TotalContainers)
	case model.SurfaceTypePostgres, model.SurfaceTypeMySQL:
		return fmt.Sprintf("%d rows, %d tables", meta.TotalItems, meta.TotalContainers)
	default:
		return fmt.Sprintf("%d items, %d containers", meta.TotalItems, meta.TotalContainers)
	}
}

// describeRetention says what, if anything, retains a snapshot.
//
// The column was "WORM RETENTION" and printed the date unconditionally, so a
// snapshot written at worm_mode NONE — which nothing retains, and which backup
// had just said "WORM Locked: NO" about — listed as retained until next month.
// That is the product's central claim made falsely in the command an operator
// checks afterwards.
//
// The sidecar now records the mode it was written under. One written before it
// did falls back to the mode this config resolves to, and says the mode was not
// recorded rather than presenting a guess as a fact.
func describeRetention(meta *model.SnapshotMetadata, storageCfg config.StorageConfig) string {
	mode := meta.WORMMode
	recorded := mode != ""
	if !recorded {
		if resolved, err := storageCfg.ResolveWORMMode(); err == nil {
			mode = string(resolved)
		}
	}
	if mode == string(config.WORMModeNone) {
		if recorded {
			return "none (deletable)"
		}
		return "none (deletable; mode not recorded)"
	}
	if meta.WORMRetentionUntil.IsZero() {
		return "unknown"
	}
	until := meta.WORMRetentionUntil.Format("2006-01-02 15:04")
	if !recorded {
		return until + " (mode not recorded)"
	}
	return mode + " until " + until
}

// describeMissingMetadata names why a snapshot could not be described.
//
// "[metadata unavailable]" covered an absent sidecar and an unreadable one
// alike, and the two are different problems: the first is a snapshot written
// before the sidecar existed, or one whose UploadMetadata failed silently; the
// second is a sink that will not answer.
func describeMissingMetadata(err error) string {
	if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "not found") {
		return "no metadata sidecar"
	}
	return "sidecar unreadable: " + err.Error()
}
