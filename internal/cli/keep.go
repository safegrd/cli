package cli

// safegrd keep: keep one snapshot longer by extending its lock, the one
// direction Object Lock allows. In the host's own bucket the host extends it
// and tells the remote server; on hosted storage the remote server extends
// it. A lock cannot be shortened afterwards by anyone, so the date is capped
// at 13 months from today and the command asks for --yes.

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

// keepCeiling is the latest a lock may be extended to, from now. The remote
// server holds the same ceiling.
func keepCeiling(now time.Time) time.Time { return now.UTC().AddDate(0, 13, 0) }

// parseKeepDate reads a date as the end of that day in UTC, or an RFC 3339
// time as it is.
func parseKeepDate(v string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t.Add(24*time.Hour - time.Second).UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("--until must be a date (2027-01-31) or an RFC 3339 time, not %q", v)
}

// repoKeepRefusal says why an incremental snapshot cannot be kept alone and
// what keeps a copy longer instead.
func repoKeepRefusal(rec *model.SnapshotMetadata) string {
	locked := ""
	if !rec.WORMRetentionUntil.IsZero() {
		locked = fmt.Sprintf(" Its objects are locked until %s.", rec.WORMRetentionUntil.UTC().Format("2006-01-02"))
	}
	return fmt.Sprintf("%s is an incremental snapshot: its data is shared with the other snapshots of its month, "+
		"so it is kept as long as they are and cannot be kept on its own.%s "+
		"To keep a copy longer, take a one-archive backup and keep that: safegrd backup --format tar, "+
		"then safegrd keep --snapshot <its id> --until <date>", rec.SnapshotID, locked)
}

func newKeepCmd() *cobra.Command {
	var snapshotID, untilArg string
	var yes bool
	cmd := &cobra.Command{
		Use:   "keep --snapshot <id> --until <date>",
		Short: "Keep one snapshot longer by extending its lock",
		Long: `Extends one snapshot's lock to --until: its backup file, its metadata and its
recovery document. A lock can be extended and never shortened, by anyone, so
the date can be at most 13 months from today, and the command needs --yes.

In your own bucket this host extends the lock with its key, which needs
s3:PutObjectRetention and s3:GetObjectRetention, and tells the remote server.
On hosted storage the remote server extends it. An incremental snapshot is
kept as long as its epoch and cannot be kept on its own.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if snapshotID == "" || untilArg == "" {
				return errors.New("--snapshot and --until are required")
			}
			if err := storage.ValidateSnapshotID(snapshotID); err != nil {
				return err
			}
			until, err := parseKeepDate(untilArg)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			if ceiling := keepCeiling(now); until.After(ceiling) {
				return fmt.Errorf("%s is past %s: a snapshot can be kept at most 13 months from today, because the lock cannot be shortened afterwards",
					until.Format("2006-01-02"), ceiling.Format("2006-01-02"))
			}
			if !until.After(now) {
				return fmt.Errorf("--until %s is in the past", untilArg)
			}
			// An incremental snapshot shares its epoch's objects, so it is
			// said before --yes is asked for: the confirmation used to come
			// first, and the refusal only after it.
			if rec := recordedSnapshot(ctx, cfg, snapshotID); rec != nil && rec.IsRepo() {
				return errors.New(repoKeepRefusal(rec))
			}
			if !yes {
				return fmt.Errorf("this locks %s until %s, and nobody can shorten that lock afterwards, SafeGrd included. Run it again with --yes",
					snapshotID, until.Format(time.RFC3339))
			}

			storageCfg, err := resolveStorageRouting(ctx, cfg, "", "", "", "", false)
			if err != nil {
				return err
			}
			if storageCfg.Type == config.StorageTypeHosted {
				if !canReport(cfg) {
					return errors.New("hosted storage is reached through the remote server, and this host is not enrolled")
				}
				var resp struct {
					RetentionUntil time.Time `json:"retention_until"`
				}
				if _, err := postJSON(ctx, cfg, "/api/v1/snapshots/"+url.PathEscape(snapshotID)+"/keep",
					map[string]string{"until": until.Format(time.RFC3339)}, &resp); err != nil {
					return fmt.Errorf("the remote server did not extend the lock: %w", err)
				}
				fmt.Printf("Kept %s on hosted storage until %s\n", snapshotID, resp.RetentionUntil.UTC().Format(time.RFC3339))
				return nil
			}

			resolveSinkCredentials(ctx, cfg, &storageCfg)
			if cfg.NodeID != "" && storageCfg.NodeID == "" {
				storageCfg.NodeID = cfg.NodeID
			}
			if recorded := recordedNodeID(ctx, cfg, snapshotID); recorded != "" {
				storageCfg.NodeID = recorded
			}
			provider, err := openStorage(ctx, cfg, storageCfg)
			if err != nil {
				return fmt.Errorf("storage error: %w", err)
			}
			storage.LocateSnapshot(ctx, provider, snapshotID)
			ext, ok := provider.(storage.RetentionExtender)
			if !ok {
				return fmt.Errorf("%s storage has no lock this host can extend", provider.Type())
			}
			if err := ext.ExtendRetention(ctx, snapshotID, until); err != nil {
				if errors.Is(err, storage.ErrLockLater) {
					return fmt.Errorf("%v. A lock can be extended, never shortened", err)
				}
				return err
			}
			fmt.Printf("Kept %s until %s\n", snapshotID, until.Format(time.RFC3339))
			if !canReport(cfg) {
				return nil
			}
			if _, err := postJSON(ctx, cfg, "/api/v1/snapshots/"+url.PathEscape(snapshotID)+"/keep",
				map[string]any{"until": until.Format(time.RFC3339), "applied": true}, nil); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: the lock is extended in the bucket, and the remote server was not told (%v). "+
					"The console shows the old date until this runs again.\n", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&snapshotID, "snapshot", "", "The snapshot to keep longer")
	cmd.Flags().StringVar(&untilArg, "until", "", "The new lock end: a date (kept to the end of that day, UTC) or an RFC 3339 time, at most 13 months away")
	cmd.Flags().BoolVar(&yes, "yes", false, "Extend the lock; it cannot be shortened afterwards")
	return cmd
}
