package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/repo/check"
	"github.com/safegrd/cli/pkg/repo/unseal"
	"github.com/spf13/cobra"
)

// resolveIdentity finds the private key the way restore and verify do: the
// flag, the config, key_path, then (for a managed organization) the remote
// server, for this command only.
func resolveIdentity(ctx context.Context, keyPath, privKey string) (string, error) {
	key := privKey
	if key != "" {
		resolved, err := ResolveSecretRef("private-key", key)
		if err != nil {
			return "", err
		}
		key = resolved
	}
	if key == "" {
		key = cfg.Encryption.PrivateKey
	}
	if key == "" {
		p := keyPath
		if p == "" {
			p = cfg.Encryption.KeyPath
		}
		if p != "" {
			if loaded, err := crypto.LoadPrivateKey(p); err == nil {
				key = loaded
			}
		}
	}
	// A whole repository has no one snapshot to name: ask for the key this
	// host backs up to, when it has none of its own.
	if key == "" {
		key = withManagedIdentity(ctx, cfg, "", heldKeyQuery{recipient: strings.TrimSpace(cfg.Encryption.PublicKey)}, true)
	}
	if key == "" {
		return "", fmt.Errorf("decryption key required: specify --private-key or configure ~/.safegrd/keys/daemon.key")
	}
	return key, nil
}

func newCheckCmd() *cobra.Command {
	var (
		snapshotID, epochID string
		all, readData       bool
		keyPath, privKey    string
	)
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check an incremental repository: every pack present, every index, tree and catalog consistent",
		Long: `Checks snapshots of incremental (--format repo) file backups without restoring them:
every pack a snapshot names is in storage and agrees with its index, every tree
decodes and names only indexed blobs, the content root recomputed from the trees
matches the one recorded, and the catalog agrees with the trees.

--read-data also opens every blob the snapshot references and checks its SHA-256,
which downloads the snapshot's data. It needs the private key.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			given := 0
			for _, b := range []bool{snapshotID != "", epochID != "", all} {
				if b {
					given++
				}
			}
			if given != 1 {
				return fmt.Errorf("give one of --snapshot, --epoch or --all")
			}
			ctx := cmd.Context()
			key, err := resolveIdentity(ctx, keyPath, privKey)
			if err != nil {
				return err
			}
			ids, err := unseal.Identities(key)
			if err != nil {
				return err
			}
			storageCfg, err := resolveStorageRouting(ctx, cfg, "", "", "", "", false)
			if err != nil {
				return err
			}
			if _, err := resolveHostedStorage(ctx, cfg, &storageCfg, false); err != nil {
				return err
			}
			resolveRuntimeCredentials(ctx, cfg, &storageCfg, false)
			if cfg.NodeID != "" && storageCfg.NodeID == "" {
				storageCfg.NodeID = cfg.NodeID
			}
			rows := listRepoSnapshots(ctx, storageCfg)
			checked, failed := 0, 0
			// One memo per epoch: the rows are in snapshot order, so the
			// catalog is replayed once across an epoch's snapshots, and its
			// listing, indexes and trailers are read once.
			memos := map[string]*check.Memo{}
			for _, rs := range rows {
				id := rs.Meta.SnapshotID
				if snapshotID != "" && id != snapshotID || epochID != "" && rs.Epoch.Epoch.EpochID != epochID {
					continue
				}
				checked++
				mk := rs.Backend.Describe() + "\x00" + rs.Epoch.Prefix
				if memos[mk] == nil {
					memos[mk] = check.NewMemo(rs.Backend, rs.Epoch, ids)
				}
				rep, err := check.Snapshot(ctx, rs.Backend, rs.Epoch, id, ids, check.Options{ReadData: readData, Memo: memos[mk]})
				if err != nil {
					failed++
					fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", id, err)
					continue
				}
				if !rep.OK() {
					failed++
					fmt.Printf("FAIL %s (epoch %s)\n", id, rs.Epoch.Epoch.EpochID)
					for _, p := range rep.Problems {
						fmt.Printf("     %s\n", p)
					}
					continue
				}
				extra := ""
				if readData {
					extra = fmt.Sprintf(", %d blobs read", rep.BlobsRead)
				}
				fmt.Printf("OK   %s (epoch %s, %d packs%s)\n", id, rs.Epoch.Epoch.EpochID, rep.Packs, extra)
			}
			switch {
			case checked == 0 && snapshotID != "":
				return fmt.Errorf("no incremental snapshot %s in this storage", snapshotID)
			case checked == 0 && epochID != "":
				return fmt.Errorf("no snapshot of epoch %s in this storage", epochID)
			case checked == 0:
				fmt.Println("No incremental snapshots in this storage.")
			case failed > 0:
				return fmt.Errorf("%d of %d snapshots failed the check", failed, checked)
			default:
				fmt.Printf("Checked %d %s.\n", checked, pluralWord(int64(checked), "snapshot", "snapshots"))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&snapshotID, "snapshot", "", "Check this snapshot")
	cmd.Flags().StringVar(&epochID, "epoch", "", "Check every snapshot of this epoch")
	cmd.Flags().BoolVar(&all, "all", false, "Check every incremental snapshot in storage")
	cmd.Flags().BoolVar(&readData, "read-data", false, "Also open every blob and check its SHA-256 (downloads the data)")
	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to the age identity file")
	cmd.Flags().StringVar(&privKey, "private-key", "", "Age identity (AGE-SECRET-KEY-1...), as env:VAR, file:/path or the key")
	return cmd
}
