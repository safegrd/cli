package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/google/uuid"
	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
)

// ensureLocalSetup makes sure this machine has the two things every other
// command assumes: a node identity, and an Age keypair to encrypt with.
//
// It exists because the two onboarding commands each half-assumed the other had
// run. `enroll` read cfg.NodeID and cfg.Storage straight out of a config that
// LoadCLIConfig will happily invent from defaults when no file exists — so
// enrolling before init registered a node with an empty ID and no key, which
// then could not encrypt a single byte. Meanwhile `init --register` tried to
// register over an unauthenticated POST that the remote server has required
// auth on for some time, failed with 401, and reported it as "could not reach
// remote server (running headless mode)" — blaming the network for an
// authorization failure.
//
// So the split is kept, because generating a private key and talking to a
// server really are different acts with different failure modes, but the
// ordering is no longer something the reader has to know: whichever command
// runs first does the local half.
//
// Returns whether it generated anything, and whether it adopted an Age identity
// that was already on disk. The caller needs the two apart: a key this command
// generated may be escrowed, and a key it merely found may not be.
func ensureLocalSetup(nodeName string) (created bool, adopted bool, err error) {
	if cfg == nil {
		cfg = config.NewDefaultCLIConfig()
	}

	// A keypair already resolved from key_path or the environment, plus an
	// identity, means the local half is done.
	if cfg.NodeID != "" && cfg.Encryption.PublicKey != "" {
		return false, false, nil
	}

	configDir, err := config.DefaultConfigDir()
	if err != nil {
		return false, false, err
	}

	if cfg.Encryption.PublicKey == "" {
		keyPath := filepath.Join(configDir, "keys", "agent.key")

		// Adopt an identity that is already there before generating one.
		//
		// This is the retry after a failed enrollment, and it used to be
		// impossible. `enroll` writes the config LAST, so an enrollment that
		// failed for any reason — the remote server refusing, a 400, a dropped
		// connection — left the key on disk and no config naming it. The next
		// run therefore saw no public key, tried to generate a fresh one, and
		// SavePrivateKey's O_EXCL refused: "refusing to overwrite the existing
		// Age identity". Correctly, and fatally. The host could never enrol
		// again without the operator deleting a key file they had just been
		// told never to lose.
		//
		// The local half really is done in that state, so this finds it rather
		// than inventing a second one. It is an adoption, not a generation, so
		// `created` stays false and the caller's custody decision still reads
		// this as a key that existed before the enrollment — which it did.
		if identity, err := crypto.LoadPrivateKey(keyPath); err == nil {
			recipient, recErr := recipientFor(identity)
			if recErr != nil {
				return false, false, fmt.Errorf("the Age identity at %s could not be read: %w", keyPath, recErr)
			}
			cfg.Encryption.PublicKey = recipient
			cfg.Encryption.PrivateKey = identity
			cfg.Encryption.KeyPath = keyPath
			adopted = true
			fmt.Printf("🔑 Using the Age identity already at %s\n", keyPath)
		} else {
			kp, genErr := crypto.GenerateKeyPair()
			if genErr != nil {
				return false, false, fmt.Errorf("failed generating asymmetric keypair: %w", genErr)
			}
			if saveErr := crypto.SavePrivateKey(kp.PrivateKey, keyPath); saveErr != nil {
				return false, false, fmt.Errorf("failed saving private key: %w", saveErr)
			}
			cfg.Encryption.PublicKey = kp.PublicKey
			cfg.Encryption.PrivateKey = kp.PrivateKey
			cfg.Encryption.KeyPath = keyPath

			fmt.Printf("🔑 Generated Age X25519 asymmetric keypair\n")
			fmt.Printf("   Public Key:  %s\n", kp.PublicKey)
			fmt.Printf("   Private Key: %s (locked to 0600)\n", keyPath)
			fmt.Printf("   Back this file up now. Without it no snapshot can ever be read again.\n")
			created = true
		}
	}

	if cfg.NodeID == "" {
		cfg.NodeID = "node-" + uuid.New().String()[:8]
		created = true
	}
	if cfg.NodeName == "" {
		if nodeName != "" {
			cfg.NodeName = nodeName
		} else {
			cfg.NodeName = "pg-node-primary"
		}
	}
	if cfg.Storage.Type == config.StorageTypeLocal && cfg.Storage.LocalPath == "" {
		cfg.Storage.LocalPath = filepath.Join(configDir, "storage")
	}

	return created, adopted, nil
}

// saveConfig writes the config back to wherever it was read from.
func saveConfig() (string, error) {
	target := cfgFile
	if target == "" {
		var err error
		target, err = config.DefaultConfigFile()
		if err != nil {
			return "", err
		}
	}
	if err := config.SaveCLIConfig(cfg, target); err != nil {
		return "", fmt.Errorf("failed to save config file: %w", err)
	}
	return target, nil
}

// recipientFor derives the public recipient of an Age identity string.
//
// Kept here rather than added to pkg/crypto because pkg/crypto is one of the
// hand-mirrored twins: a helper there has to land identically in two
// repositories, and this is needed by exactly one caller.
func recipientFor(identity string) (string, error) {
	parsed, err := age.ParseX25519Identity(strings.TrimSpace(identity))
	if err != nil {
		return "", err
	}
	return parsed.Recipient().String(), nil
}
