package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/spf13/cobra"
)

// newKeygenCmd makes an age key pair without the age tools installed. The
// identity is written with the same refusal to overwrite that init and enroll
// use, because it is the only thing that can decrypt what is sealed to it.
func newKeygenCmd() *cobra.Command {
	var out, recipientOf, snapshotID string
	var held bool
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an age key pair, or print the public key of one you have",
		Long: `Generate an age key pair for a customer-managed key.

The private key (identity) is written to --out at mode 0600 and never printed.
The public key (recipient) is printed: put it in encryption.public_key on the
hosts that back up. They can then encrypt but not decrypt. Keep a copy of the
identity somewhere safe, such as a password manager: it is the only key that
opens these backups.

With --held, write a copy of a SafeGrd-managed key instead: this host's own,
or with --snapshot the key that snapshot was sealed to, such as a surface
SafeGrd backs up or a host you lost. Run it on an enrolled host. SafeGrd keeps
holding the key, and the copy is listed in the key access record in the console.

  safegrd keygen --out ~/.safegrd/keys/prod.key
  safegrd keygen --recipient ~/.safegrd/keys/prod.key
  safegrd keygen --held --snapshot snap-... --out ~/keys/orders.key`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if held {
				return writeHeldKeyCopy(cmd.Context(), out, snapshotID)
			}
			if snapshotID != "" {
				return fmt.Errorf("--snapshot goes with --held")
			}
			if recipientOf != "" {
				data, err := os.ReadFile(recipientOf)
				if err != nil {
					return fmt.Errorf("could not read %s: %w", recipientOf, err)
				}
				ids, err := crypto.ParseIdentities(crypto.IdentityInFile(data))
				if err != nil || len(ids) == 0 {
					return fmt.Errorf("%s holds no age identity (AGE-SECRET-KEY-1...)", recipientOf)
				}
				for _, id := range ids {
					x, ok := id.(*age.X25519Identity)
					if !ok {
						return fmt.Errorf("%s holds an identity that is not an X25519 age key", recipientOf)
					}
					fmt.Println(x.Recipient().String())
				}
				return nil
			}

			path := out
			if path == "" {
				dir, err := setupDir()
				if err != nil {
					return err
				}
				path = filepath.Join(dir, "keys", "daemon.key")
			}
			path, err := expandHome(path)
			if err != nil {
				return err
			}
			kp, err := crypto.GenerateKeyPair()
			if err != nil {
				return err
			}
			if err := crypto.SavePrivateKey(kp.PrivateKey, path); err != nil {
				return err
			}
			fmt.Printf("Private key: %s (mode 0600). Keep a copy somewhere safe.\n", path)
			fmt.Printf("Public key:  %s\n", kp.PublicKey)
			fmt.Printf("Fingerprint: %s\n", crypto.Fingerprint(kp.PublicKey))
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "Where to write the private key (default ~/.safegrd/keys/daemon.key); an existing file is never overwritten")
	cmd.Flags().StringVar(&recipientOf, "recipient", "", "Print the public key of the identity in this file, and generate nothing")
	cmd.Flags().BoolVar(&held, "held", false, "Write a copy of the key SafeGrd holds for this host to --out, and generate nothing")
	cmd.Flags().StringVar(&snapshotID, "snapshot", "", "With --held: the key this snapshot was sealed to, instead of this host's")
	return cmd
}

// writeHeldKeyCopy writes the key SafeGrd holds for this host, or for one
// snapshot, to out. The person asked for a file of their own, so unlike a
// restore, which keeps a fetched key in memory only, this one is written; it
// goes only where --out says, never to key_path by default.
func writeHeldKeyCopy(ctx context.Context, out, snapshotID string) error {
	if out == "" {
		return fmt.Errorf("--held needs --out: the file to write the copy to")
	}
	if cfg == nil || cfg.NodeID == "" || cfg.ServerToken == "" {
		return fmt.Errorf("this host is not enrolled, and SafeGrd releases a key only to an enrolled host. Run safegrd enroll first")
	}
	hq := heldKeyQuery{snapshotID: strings.TrimSpace(snapshotID), purpose: "key-copy"}
	if hq.snapshotID == "" {
		hq.recipient = strings.TrimSpace(cfg.Encryption.PublicKey)
		if hq.recipient == "" {
			return fmt.Errorf("this host's config has no encryption.public_key, so it names no key. Pass --snapshot to copy the key of one snapshot")
		}
	}
	path, err := expandHome(out)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; it is never overwritten. Choose another --out", path)
	}
	res, err := fetchManagedIdentity(ctx, resolveServerURL(), cfg.NodeID, cfg.ServerToken, hq)
	if errors.Is(err, errNoManagedKey) {
		if hq.snapshotID == "" {
			if cfg.Encryption.KeyPath != "" {
				return fmt.Errorf("SafeGrd holds no key for this host. It uses a customer-managed key, kept at %s", cfg.Encryption.KeyPath)
			}
			return fmt.Errorf("SafeGrd holds no key for this host. It uses a customer-managed key")
		}
		return fmt.Errorf("SafeGrd holds no key for snapshot %s%s", hq.snapshotID, strings.TrimPrefix(err.Error(), errNoManagedKey.Error()))
	}
	if err != nil {
		return fmt.Errorf("could not fetch the key from the remote server: %w", err)
	}
	if len(res.Identities) != 1 {
		return fmt.Errorf("the remote server released %d keys, want one", len(res.Identities))
	}
	got := res.Identities[0]
	// The key is checked against the public key it was released as, so a
	// copy that would not open those backups is never written.
	ids, err := crypto.ParseIdentities(got.Identity)
	if err != nil || len(ids) != 1 {
		return fmt.Errorf("the remote server released a key that is not an age identity")
	}
	x, ok := ids[0].(*age.X25519Identity)
	if !ok || x.Recipient().String() != strings.TrimSpace(got.PublicKey) {
		return fmt.Errorf("the remote server released a key that does not match its public key %s", crypto.Fingerprint(got.PublicKey))
	}
	if hq.recipient != "" && x.Recipient().String() != hq.recipient {
		return fmt.Errorf("the remote server released %s, not this host's key %s", crypto.Fingerprint(got.PublicKey), crypto.Fingerprint(hq.recipient))
	}
	if err := crypto.SavePrivateKey(got.Identity, path); err != nil {
		return err
	}
	fmt.Printf("Private key: %s (mode 0600), a copy of the SafeGrd-managed key.\n", path)
	fmt.Printf("Public key:  %s\n", got.PublicKey)
	fmt.Printf("Fingerprint: %s\n", crypto.Fingerprint(got.PublicKey))
	fmt.Println("SafeGrd still holds this key and releases it only to your enrolled hosts. Keep this copy somewhere safe: it opens every backup sealed to this key.")
	return nil
}

// expandHome resolves a leading ~/ in a path.
func expandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, path[2:]), nil
}
