package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List snapshots in storage and when each lock ends",
		Long: `Lists the snapshots in this host's storage, with what each holds and when its lock ends.

--json prints a JSON array on stdout, one object per snapshot, and sends every
other line to stderr, so the output can be piped to jq.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if jsonOut {
				// Routing, credential and deleted-snapshot notices print on
				// stdout. They still matter, so they move to stderr rather
				// than being dropped, and stdout carries the JSON alone.
				stdout := os.Stdout
				os.Stdout = os.Stderr
				defer func() { os.Stdout = stdout }()
				return listJSON(ctx, stdout)
			}
			// Routed and credentialed like backup and restore. A node enrolled
			// with a centrally-managed sink has no bucket or sink secret locally, so reading
			// cfg.Storage directly means this command cannot reach the bucket
			// on hosts configured centrally.
			storageCfg, routeErr := resolveStorageRouting(ctx, cfg, "", "", "", "", false)
			if routeErr != nil {
				return routeErr
			}
			if _, err := resolveHostedStorage(ctx, cfg, &storageCfg, false); err != nil {
				return err
			}
			resolveRuntimeCredentials(ctx, cfg, &storageCfg, false)
			if cfg.NodeID != "" && storageCfg.NodeID == "" {
				storageCfg.NodeID = cfg.NodeID
			}
			storageProvider, err := openStorage(ctx, cfg, storageCfg)
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

			repoRows := listRepoSnapshots(ctx, storageCfg)
			if len(repoRows) > 0 {
				defer printRepoTable(repoRows, storageCfg)
			}
			if len(snapshots) == 0 {
				if shadowed == 0 && len(repoRows) == 0 {
					fmt.Println(noSnapshotsLine(storageCfg))
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
					status = "ANOMALOUS"
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
					"\nWarning: %d snapshot(s) above could not be described. The sidecar beside the object is\n"+
						"   what this table reads; it is routing data, not the backup. The manifest is sealed\n"+
						"   inside the encrypted archive, so those snapshots still restore: run\n"+
						"   'safegrd verify --snapshot <id>' with the identity to read what is in them.\n",
					undescribed)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Print the snapshots as a JSON array on stdout")
	return cmd
}

// listedSnapshot is one entry of `list --json`. The field names are the
// output's contract with scripts and hooks; add fields, never rename them.
type listedSnapshot struct {
	SnapshotID string `json:"snapshot_id"`
	NodeID     string `json:"node_id,omitempty"`
	Surface    string `json:"surface,omitempty"`
	Database   string `json:"database,omitempty"`
	Status     string `json:"status,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
	// CompletedAt is when the upload finished.
	CompletedAt        string `json:"completed_at,omitempty"`
	EncryptedSizeBytes int64  `json:"encrypted_size_bytes"`
	TotalItems         int64  `json:"total_items"`
	TotalContainers    int    `json:"total_containers"`
	// WORMMode is COMPLIANCE, GOVERNANCE or NONE; empty when the snapshot
	// predates the field.
	WORMMode    string `json:"worm_mode,omitempty"`
	LockedUntil string `json:"locked_until,omitempty"`
	// Locked is true while Object Lock still holds the snapshot.
	Locked    bool `json:"locked"`
	Anomalous bool `json:"anomalous"`
	// MetadataError says why the snapshot could not be described. The
	// snapshot itself may still restore.
	MetadataError string `json:"metadata_error,omitempty"`
	// Format is "repo-v1" for a snapshot in an incremental repository, which
	// is filed under RepoSurface and EpochID. For it EncryptedSizeBytes is
	// what that run uploaded, and LogicalSizeBytes the whole tree's size.
	Format           string `json:"format,omitempty"`
	RepoSurface      string `json:"repo_surface,omitempty"`
	EpochID          string `json:"epoch_id,omitempty"`
	ObjectClass      string `json:"object_class,omitempty"`
	LogicalSizeBytes int64  `json:"logical_size_bytes,omitempty"`
}

// listRepoSnapshots reads every repository snapshot under this storage. A
// failure is said and leaves the rest of the listing in place.
func listRepoSnapshots(ctx context.Context, storageCfg config.StorageConfig) []repoSnapshot {
	bs, err := repoBackendsAll(ctx, storageCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not list the incremental repositories: %v\n", err)
		return nil
	}
	var out []repoSnapshot
	for _, b := range bs {
		rows, err := repoSnapshots(ctx, b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not list the repository in %s: %v\n", b.Describe(), err)
			continue
		}
		out = append(out, rows...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Meta.CreatedAt.Before(out[j].Meta.CreatedAt) })
	return out
}

// printRepoTable lists repository snapshots: new is what each run uploaded,
// logical the whole tree it holds.
func printRepoTable(rows []repoSnapshot, storageCfg config.StorageConfig) {
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "INCREMENTAL SNAPSHOT\tSURFACE\tEPOCH\tCLASS\tCONTENTS\tLOGICAL\tNEW\tRETENTION\tSTATUS")
	for _, r := range rows {
		m := r.Meta
		status := string(m.Status)
		if m.IsPoisonPillFrozen {
			status = "ANOMALOUS"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", m.SnapshotID, r.SurfaceID, m.EpochID, m.ObjectClass,
			describeContents(m), formatBytes(m.RawSizeBytes), formatBytes(m.EncryptedSizeBytes), describeRetention(m, storageCfg), status)
	}
	w.Flush()
}

// listJSON writes every snapshot as one JSON array to out.
func listJSON(ctx context.Context, out io.Writer) error {
	storageCfg, routeErr := resolveStorageRouting(ctx, cfg, "", "", "", "", false)
	if routeErr != nil {
		return routeErr
	}
	if _, err := resolveHostedStorage(ctx, cfg, &storageCfg, false); err != nil {
		return err
	}
	resolveRuntimeCredentials(ctx, cfg, &storageCfg, false)
	if cfg.NodeID != "" && storageCfg.NodeID == "" {
		storageCfg.NodeID = cfg.NodeID
	}
	storageProvider, err := openStorage(ctx, cfg, storageCfg)
	if err != nil {
		return fmt.Errorf("storage error: %w", err)
	}
	snapshots, err := storageProvider.ListSnapshots(ctx)
	if err != nil {
		return fmt.Errorf("failed to list snapshots: %w", err)
	}
	warnAboutShadowedSnapshots(ctx, storageProvider)

	var nodes map[string]string
	if loc, ok := storageProvider.(storage.NodeLocator); ok {
		var locErr error
		if nodes, locErr = loc.SnapshotNodes(ctx); locErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not read which node each snapshot belongs to: %v\n", locErr)
		}
	}
	setNode, canSetNode := storageProvider.(interface{ SetNodeID(string) })

	now := time.Now()
	entries := make([]listedSnapshot, 0, len(snapshots))
	for _, snapID := range snapshots {
		e := listedSnapshot{SnapshotID: snapID, NodeID: nodes[snapID]}
		if e.NodeID != "" && canSetNode {
			setNode.SetNodeID(e.NodeID)
		}
		meta, err := storageProvider.DownloadMetadata(ctx, snapID)
		if err != nil {
			e.MetadataError = describeMissingMetadata(err)
			entries = append(entries, e)
			continue
		}
		e.Surface = string(meta.SurfaceType)
		e.Database = meta.DatabaseName
		e.Status = string(meta.Status)
		if !meta.CreatedAt.IsZero() {
			e.CreatedAt = meta.CreatedAt.UTC().Format(time.RFC3339)
		}
		if meta.CompletedAt != nil {
			e.CompletedAt = meta.CompletedAt.UTC().Format(time.RFC3339)
		}
		e.EncryptedSizeBytes = meta.EncryptedSizeBytes
		e.TotalItems = meta.TotalItems
		e.TotalContainers = meta.TotalContainers
		e.WORMMode = meta.WORMMode
		e.Anomalous = meta.IsPoisonPillFrozen
		if e.WORMMode != string(config.WORMModeNone) && !meta.WORMRetentionUntil.IsZero() {
			e.LockedUntil = meta.WORMRetentionUntil.UTC().Format(time.RFC3339)
			e.Locked = meta.WORMRetentionUntil.After(now) && storageCfg.Type != config.StorageTypeLocal
		}
		entries = append(entries, e)
	}

	for _, rs := range listRepoSnapshots(ctx, storageCfg) {
		meta := rs.Meta
		e := listedSnapshot{SnapshotID: meta.SnapshotID, NodeID: meta.NodeID, Surface: string(meta.SurfaceType),
			Status: string(meta.Status), EncryptedSizeBytes: meta.EncryptedSizeBytes, TotalItems: meta.TotalItems,
			TotalContainers: meta.TotalContainers, WORMMode: meta.WORMMode, Anomalous: meta.IsPoisonPillFrozen,
			Format: meta.Format, EpochID: meta.EpochID, ObjectClass: meta.ObjectClass, RepoSurface: rs.SurfaceID,
			LogicalSizeBytes: meta.RawSizeBytes}
		if !meta.CreatedAt.IsZero() {
			e.CreatedAt = meta.CreatedAt.UTC().Format(time.RFC3339)
		}
		if meta.CompletedAt != nil {
			e.CompletedAt = meta.CompletedAt.UTC().Format(time.RFC3339)
		}
		if e.WORMMode != string(config.WORMModeNone) && !meta.WORMRetentionUntil.IsZero() {
			e.LockedUntil = meta.WORMRetentionUntil.UTC().Format(time.RFC3339)
			e.Locked = meta.WORMRetentionUntil.After(now) && storageCfg.Type != config.StorageTypeLocal
		}
		entries = append(entries, e)
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

// describeContents says what is in a snapshot in the vocabulary of its own
// surface.
//
// It reads TotalItems and TotalContainers (the surface-neutral pair that
// CalculateTotals populates for every surface) rather than TotalTables and TotalRows.
func describeContents(meta *model.SnapshotMetadata) string {
	switch meta.SurfaceType {
	case model.SurfaceTypeFiles:
		return fmt.Sprintf("%d files, %d dirs", meta.TotalItems, meta.TotalContainers)
	case model.SurfaceTypeEmail:
		return fmt.Sprintf("%d emails, %d folders", meta.TotalItems, meta.TotalContainers)
	case model.SurfaceTypeMongoDB:
		return fmt.Sprintf("%d documents, %d collections", meta.TotalItems, meta.TotalContainers)
	case model.SurfaceTypePostgres, model.SurfaceTypeMySQL, model.SurfaceTypeSQLite:
		return fmt.Sprintf("%d rows, %d tables", meta.TotalItems, meta.TotalContainers)
	default:
		return fmt.Sprintf("%d items, %d containers", meta.TotalItems, meta.TotalContainers)
	}
}

// describeRetention says what, if anything, retains a snapshot.
//
// The column was previously printed unconditionally. A snapshot written
// at worm_mode NONE has no WORM lock applied.
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
	// One clock for every row: archive sidecars carried the host's local
	// time and repository ones UTC, so one table mixed the two unlabelled.
	until := meta.WORMRetentionUntil.UTC().Format("2006-01-02 15:04") + " UTC"
	if storageCfg.Type == config.StorageTypeLocal {
		// The sidecar may say COMPLIANCE (the config's default mode), but a
		// directory enforces nothing: only safegrd's own refusal to delete.
		return "kept until " + until + " (no Object Lock)"
	}
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

// noSnapshotsLine says where list looked when it found nothing. A recovery
// config with the wrong prefix printed "No snapshots found in storage" over a
// bucket full of them, and nothing said the prefix was the thing to check.
func noSnapshotsLine(c config.StorageConfig) string {
	switch c.Type {
	case config.StorageTypeS3:
		return fmt.Sprintf("No snapshots under s3://%s/%s. If the bucket holds backups under another prefix, set storage.prefix to it.",
			c.Bucket, strings.Trim(c.Prefix, "/"))
	case config.StorageTypeLocal:
		return fmt.Sprintf("No snapshots in %s.", c.LocalPath)
	}
	return "No snapshots found in storage."
}
