package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

// shadowLister and snapshotUndeleter are satisfied only by the S3 provider.
// Local WORM storage has no versioning, so it has no delete markers to report
// or remove, and implementing these there would be inventing an answer.
type shadowLister interface {
	ListShadowedSnapshots(ctx context.Context) ([]storage.ShadowedSnapshot, error)
}

type snapshotUndeleter interface {
	UndeleteSnapshot(ctx context.Context, snapshotID string) (int, error)
}

// warnAboutShadowedSnapshots prints a warning for snapshots hidden behind a
// delete marker, and returns how many there were.
//
// This runs on the read commands because a delete marker is the single loudest
// signal of attack this product can receive. It used to present as
// "No snapshots found in storage" — which reads like nothing was ever
// configured, at the exact moment somebody is trying to recover.
func warnAboutShadowedSnapshots(ctx context.Context, provider storage.StorageProvider) int {
	lister, ok := provider.(shadowLister)
	if !ok {
		return 0
	}
	shadowed, err := lister.ListShadowedSnapshots(ctx)
	if err != nil || len(shadowed) == 0 {
		return 0
	}

	fmt.Printf("\n🚨 %d snapshot(s) have been DELETED from the bucket.\n", len(shadowed))
	fmt.Println("   Object Lock preserved the data — the encrypted versions are intact and still")
	fmt.Println("   immutable — but a delete marker is hiding them. SafeGrd is reading past it.")
	fmt.Println("   Someone or something issued a DELETE against your backups. Investigate.")
	for _, s := range shadowed {
		fmt.Printf("   - %s  (deleted %s)\n", s.SnapshotID, s.DeletedAt.Format("2006-01-02 15:04 UTC"))
	}
	fmt.Println("\n   Clear the delete markers with:  safegrd undelete --snapshot <id>")
	fmt.Println("   Then deny s3:DeleteObject on this bucket — that is what makes the WORM")
	fmt.Println("   guarantee true in practice, not just on the object.")
	return len(shadowed)
}

func newUndeleteCmd() *cobra.Command {
	var snapshotID string
	var all bool

	cmd := &cobra.Command{
		Use:   "undelete",
		Short: "Remove delete markers hiding snapshots in versioned S3 storage",
		Long: `Restores visibility of snapshots that were DELETEd from a versioned bucket.

Under S3 Object Lock a plain DELETE cannot destroy a locked backup. It writes a
delete marker as the current version, which hides the data from every ordinary
read without removing a single byte. This command removes those markers.

It only ever deletes delete markers, addressed by version id. It cannot remove a
version holding data, which is why it is safe to run.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			storageCfg := resolveStorageRouting(ctx, cfg, "", "", "", "", true)
			if _, err := resolveHostedStorage(ctx, cfg, &storageCfg, false); err != nil {
				return err
			}
			resolveRuntimeCredentials(ctx, cfg, &storageCfg, true)

			provider, err := storage.NewProvider(ctx, storageCfg)
			if err != nil {
				return fmt.Errorf("storage error: %w", err)
			}

			undeleter, ok := provider.(snapshotUndeleter)
			if !ok {
				return fmt.Errorf("this storage backend has no versioning, so it has no delete markers to remove")
			}

			targets := []string{}
			switch {
			case snapshotID != "":
				targets = append(targets, snapshotID)
			case all:
				lister, ok := provider.(shadowLister)
				if !ok {
					return fmt.Errorf("this storage backend cannot report shadowed snapshots")
				}
				shadowed, err := lister.ListShadowedSnapshots(ctx)
				if err != nil {
					return fmt.Errorf("failed to find shadowed snapshots: %w", err)
				}
				for _, s := range shadowed {
					targets = append(targets, s.SnapshotID)
				}
			default:
				return fmt.Errorf("specify --snapshot <id>, or --all to clear every delete marker found")
			}

			if len(targets) == 0 {
				fmt.Println("✅ No snapshots are hidden behind a delete marker.")
				return nil
			}

			total, unknown := 0, 0
			for _, id := range targets {
				removed, err := undeleter.UndeleteSnapshot(ctx, id)
				if err != nil {
					return fmt.Errorf("failed to undelete %s: %w", id, err)
				}
				if removed == 0 {
					// A ✅ over zero markers removed is the silent-failure shape
					// this project forbids: the command did nothing and said it succeeded,
					// in the one command someone runs during an incident. The
					// two ways it happens are not the same problem, so they do
					// not get the same sentence.
					exists, existsErr := provider.SnapshotExists(ctx, id)
					if existsErr == nil && exists {
						fmt.Printf("ℹ️  %s: no delete markers — this snapshot is already visible.\n", id)
						continue
					}
					unknown++
					fmt.Fprintf(os.Stderr,
						"⚠️  %s: nothing to undelete, and no snapshot by that id is in this bucket.\n"+
							"   Looked in s3://%s/%s (node %q). Nothing was changed. Check the snapshot id\n"+
							"   against 'safegrd list', and check this is the sink it was written to.\n",
						id, storageCfg.Bucket, storageCfg.Prefix, storageCfg.NodeID)
					continue
				}
				total += removed
				fmt.Printf("✅ %s: removed %d delete marker(s)\n", id, removed)
			}

			if total > 0 {
				fmt.Printf("\n   %d marker(s) removed across %d snapshot(s). The encrypted data was never gone.\n", total, len(targets))
				fmt.Println("   Deny s3:DeleteObject on this bucket so it cannot happen again.")
			}
			if unknown > 0 {
				// Non-zero exit, because the operator named a snapshot that is
				// not here. Under pressure that is a typo or the wrong profile,
				// and a zero exit would read as "recovered".
				return fmt.Errorf("%d of the %d snapshot(s) named are not in this bucket, so nothing was recovered for them",
					unknown, len(targets))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&snapshotID, "snapshot", "", "Snapshot ID to make visible again")
	cmd.Flags().BoolVar(&all, "all", false, "Clear delete markers from every hidden snapshot")
	return cmd
}

// wormLabel describes the retention actually applied, for the "Target Storage"
// line. It exists so the CLI cannot print "WORM Object Lock" over a bucket that
// has none.
func wormLabel(storageCfg config.StorageConfig) string {
	if mode, err := storageCfg.ResolveWORMMode(); err == nil && mode == config.WORMModeNone {
		return "NO Object Lock"
	}
	return "WORM Object Lock"
}

// recordRetention writes the retention a snapshot was stored under into its
// sidecar: the date, and the mode that does or does not enforce it. Every path
// that writes a sidecar goes through here, so `list` can never again show a
// date over a snapshot that nothing retains while `backup` said, two lines
// earlier, that nothing did.
func recordRetention(meta *model.SnapshotMetadata, storageCfg config.StorageConfig, retainUntil time.Time) {
	meta.WORMRetentionUntil = retainUntil
	if mode, err := storageCfg.ResolveWORMMode(); err == nil {
		meta.WORMMode = string(mode)
	}
}

// printRetentionLine reports what protects this snapshot, or states plainly
// that nothing does.
//
// The honest version of this line matters more than the reassuring one. A
// backup written with worm_mode: NONE is still encrypted, still checksummed and
// still attested — but it is a copy, not a proof, and an attacker who reaches
// the bucket can delete it. Printing "Immutable until ..." over that would make
// the product's central claim false in the one place an operator actually looks.
func printRetentionLine(storageCfg config.StorageConfig, retainUntil time.Time) {
	if mode, err := storageCfg.ResolveWORMMode(); err == nil && mode == config.WORMModeNone {
		fmt.Printf("   WORM Locked:     ⚠️  NO — worm_mode is NONE, so this bucket applies no Object Lock.\n")
		fmt.Printf("                    The backup is encrypted and attested, but it can be deleted.\n")
		return
	}
	fmt.Printf("   WORM Locked:     Immutable until %s\n", retainUntil.Format("2006-01-02 15:04:05 UTC"))
}

// warnIfManifestFailed reports a manifest that did not reach the sink.
//
// All six call sites used to discard this error with `_ =`. The manifest is
// what `list` reads to describe a snapshot and what `verify` checks the digest
// against, so losing it turns a proven backup into an opaque blob: the run
// still says "Backup Completed Successfully", `safegrd list` prints
// "[metadata unavailable]", and a Fire Drill has nothing to compare.
//
// The backup itself is genuinely fine — the ciphertext is in the sink and the
// remote server has the attestation — so this warns rather than failing. But it
// warns, which is the whole point: this was the third silent-failure path
// found, after the unrecorded attestation and the unrecorded
// Fire Drill.
func warnIfManifestFailed(err error, snapshotID string) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr,
		"   Manifest:        NOT WRITTEN for %s: %v\n"+
			"                    The encrypted backup is in the sink and the remote server has the\n"+
			"                    attestation, but without the manifest `safegrd list` cannot describe\n"+
			"                    this snapshot and `verify` has no digest to check it against.\n",
		snapshotID, err)
}
