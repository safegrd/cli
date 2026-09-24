package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var (
		dbURL         string
		storageType   string
		s3Bucket      string
		s3Region      string
		s3Endpoint    string
		localPath     string
		retentionDays int
		nodeName      string
		initForce     bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize SafeGrd node, asymmetric keys, and storage settings",
		Long: `Generates a zero-knowledge Age asymmetric keypair and writes local configuration.

Nothing leaves this machine: init is the offline half of setup, and a node set up
this way can back up and restore standalone. To register it with a remote server
so the console can track it, run 'safegrd enroll' — which will run this step for
you if you have not already, so either order works.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			serverURL := resolveServerURL()

			// Refuse to overwrite an existing config.
			//
			// init used to write a fresh default config over whatever was
			// there: database_url, bucket, endpoint, credentials, node_id and
			// retention_days discarded, worm_mode reset from GOVERNANCE to
			// COMPLIANCE, and key_path repointed at a NEWLY GENERATED key.
			//
			// That last part is the one that loses data. The old key file stays
			// on disk, but nothing in the config refers to it any more, and
			// every snapshot written before that moment is sealed to a
			// recipient the config no longer names. Someone who then follows
			// the "back up your key" advice backs up the wrong key.
			//
			// This is the command a confused operator runs twice, so it refuses
			// rather than merging: a merge would still have to decide what to
			// do about a key that already exists, and quietly deciding is what
			// caused the problem.
			targetPath := cfgFile
			if targetPath == "" {
				defaultPath, err := config.DefaultConfigFile()
				if err != nil {
					return err
				}
				targetPath = defaultPath
			}
			if !initForce && fileExists(targetPath) {
				return fmt.Errorf(
					"refusing to overwrite the existing config at %s\n"+
						"  init writes a fresh config, which would discard the database URL, storage\n"+
						"  settings and credentials already there — and repoint key_path at a newly\n"+
						"  generated key, leaving every existing snapshot sealed to a key the config\n"+
						"  no longer names.\n\n"+
						"  Edit that file directly, or pass --force if you really mean to start over\n"+
						"  (back up the key it currently names first)", targetPath)
			}

			fmt.Println("🛡️  Initializing SafeGrd node...")

			configDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}

			// 1. Generate asymmetric Age keypair
			kp, err := crypto.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("failed generating asymmetric keypair: %w", err)
			}

			keyPath := filepath.Join(configDir, "keys", "agent.key")
			// --force means "replace the config", and it has always also meant
			// "replace the key" — the flag's own help text says so. Routed
			// through the explicit call so the no-clobber default protects the
			// case nobody asked for: a second config at a different path
			// quietly taking the identity with it.
			save := crypto.SavePrivateKey
			if initForce {
				save = crypto.OverwritePrivateKey
			}
			if err := save(kp.PrivateKey, keyPath); err != nil {
				return fmt.Errorf("failed saving private key: %w", err)
			}
			fmt.Printf("🔑 Generated Age X25519 asymmetric keypair\n")
			fmt.Printf("   Public Key:  %s\n", kp.PublicKey)
			fmt.Printf("   Private Key: %s (locked to 0600)\n", keyPath)

			// 2. Prepare Config
			nodeID := "node-" + uuid.New().String()[:8]
			if nodeName == "" {
				nodeName = "pg-node-primary"
			}

			cfg = &config.CLIConfig{
				NodeID:      nodeID,
				NodeName:    nodeName,
				ServerURL:   serverURL,
				DatabaseURL: dbURL,
				Storage: config.StorageConfig{
					Type:          config.StorageType(storageType),
					Bucket:        s3Bucket,
					Region:        s3Region,
					Endpoint:      s3Endpoint,
					Prefix:        "safegrd/snapshots",
					RetentionDays: retentionDays,
					WORMMode:      config.WORMModeCompliance,
					LocalPath:     localPath,
				},
				Encryption: config.EncryptionConfig{
					PublicKey:  kp.PublicKey,
					PrivateKey: kp.PrivateKey,
					KeyPath:    keyPath,
				},
			}

			switch cfg.Storage.Type {
			case config.StorageTypeLocal, config.StorageTypeS3:
			case config.StorageTypeHosted:
				// The lease supplies the bucket, the prefix, the credential and
				// the plan's retention; nothing about it belongs in the file.
				cfg.Storage = config.StorageConfig{Type: config.StorageTypeHosted, WORMMode: config.WORMModeCompliance}
			default:
				return fmt.Errorf("--storage %q: want local, s3 or hosted", storageType)
			}

			if cfg.Storage.Type == config.StorageTypeLocal && cfg.Storage.LocalPath == "" {
				cfg.Storage.LocalPath = filepath.Join(configDir, "storage")
			}

			// Verify S3 Object Lock if S3 storage is configured
			if cfg.Storage.Type == config.StorageTypeS3 && cfg.Storage.Bucket != "" {
				fmt.Printf("🔒 Verifying S3 bucket '%s' WORM Object Lock...\n", cfg.Storage.Bucket)
				if s3Prov, err := storage.NewS3Storage(cmd.Context(), cfg.Storage); err == nil {
					if err := s3Prov.VerifyBucketObjectLock(cmd.Context()); err == nil {
						fmt.Printf("   ✅ S3 Object Lock Compliance Mode verified on bucket\n")
					} else {
						fmt.Printf("   ⚠️  Object Lock verification notice: %v\n", err)
					}
				}
			}

			// 4. Save Config File
			targetConfig := cfgFile
			if targetConfig == "" {
				targetConfig, _ = config.DefaultConfigFile()
			}
			if err := config.SaveCLIConfig(cfg, targetConfig); err != nil {
				return fmt.Errorf("failed to save config file: %w", err)
			}
			fmt.Printf("💾 Configuration written to: %s\n\n", targetConfig)
			fmt.Println("🚀 Local setup complete.")
			fmt.Println("   Back up the private key above: without it no snapshot can ever be read again.")
			fmt.Println()
			if cfg.Storage.Type == config.StorageTypeHosted {
				fmt.Println("   Hosted storage is leased from the remote server, so enrol this host before")
				fmt.Println("   the first backup:")
				fmt.Println("     safegrd enroll --token <your access token>")
				return nil
			}
			fmt.Println("   To protect this surface from the console, enrol it:")
			fmt.Println("     safegrd enroll --token <your access token>")
			fmt.Println("   Or stay standalone and run a backup right now:")
			fmt.Println("     safegrd backup")
			return nil
		},
	}

	cmd.Flags().StringVar(&dbURL, "database-url", "", "PostgreSQL connection URL")
	cmd.Flags().StringVar(&storageType, "storage", "local", "Storage type: 'local', 's3', or 'hosted' (SafeGrd's locked bucket, leased per run)")
	cmd.Flags().StringVar(&s3Bucket, "s3-bucket", "", "S3 bucket for WORM storage")
	cmd.Flags().StringVar(&s3Region, "s3-region", "us-east-1", "S3 bucket region")
	cmd.Flags().StringVar(&s3Endpoint, "s3-endpoint", "", "S3 custom endpoint (for MinIO / R2)")
	cmd.Flags().StringVar(&localPath, "local-path", "", "Local storage directory path")
	cmd.Flags().IntVar(&retentionDays, "retention-days", 14, "WORM immutability retention in days")
	cmd.Flags().StringVar(&nodeName, "node-name", "", "Human-readable name for this database node")
	cmd.Flags().BoolVar(&initForce, "force", false,
		"Overwrite an existing config. This discards the settings in it and generates a NEW "+
			"keypair, after which snapshots taken under the old key can only be read with the "+
			"old key — back it up first.")

	return cmd
}

// fileExists reports whether a path is present. An error other than
// "not found" is treated as present: if we cannot tell, refusing is the safe
// answer for a command that would otherwise overwrite.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}
