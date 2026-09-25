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
// It ensures that both a node identity and an Age keypair are present before
// operations proceed. Whichever setup command runs first performs the local initialization.
//
// Returns whether it generated anything, and whether it adopted an Age identity
// that was already on disk.
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

		// Adopt an identity that is already present before generating one.
		// This handles the retry scenario after a previously interrupted enrollment.
		// If an identity already exists on disk, adopt it rather than failing
		// on key file overwrite.
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
