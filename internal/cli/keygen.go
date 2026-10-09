package cli

import (
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
	var out, recipientOf string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an age key pair, or print the public key of one you have",
		Long: `Generate an age key pair for a customer-managed key.

The private key (identity) is written to --out at mode 0600 and never printed.
The public key (recipient) is printed: put it in encryption.public_key on the
hosts that back up. They can then encrypt but not decrypt. Keep a copy of the
identity somewhere safe, such as a password manager: it is the only key that
opens these backups.

  safegrd keygen --out ~/.safegrd/keys/prod.key
  safegrd keygen --recipient ~/.safegrd/keys/prod.key`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
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
			if strings.HasPrefix(path, "~/") {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				path = filepath.Join(home, path[2:])
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
	return cmd
}
