package cli

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var (
		dbURL         string
		storageType   string
		s3Bucket      string
		s3Prefix      string
		s3Region      string
		s3Endpoint    string
		localPath     string
		retentionDays int
		wormMode      string
		nodeName      string
		initForce     bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Set up this host: generate a keypair and write the config",
		Long: `Generates an age keypair and writes the local configuration.

Nothing leaves this machine: init is the offline half of setup, and a node set up
this way can back up and restore standalone. To register it with a remote server
so the console can track it, run 'safegrd enroll' (which will run this step for
you if you have not already).`,
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
						"  settings and credentials already there, and repoint key_path at a newly\n"+
						"  generated key, leaving every existing snapshot sealed to a key the config\n"+
						"  no longer names.\n\n"+
						"  Edit that file directly, or pass --force if you really mean to start over\n"+
						"  (back up the key it currently names first)", targetPath)
			}

			configDir, err := setupDir()
			if err != nil {
				return err
			}

			// 1. Generate asymmetric Age keypair
			kp, err := crypto.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("failed generating asymmetric keypair: %w", err)
			}

			keyPath := filepath.Join(configDir, "keys", "daemon.key")
			// --force means "replace the config", and replaces the key as well.
			save := crypto.SavePrivateKey
			if initForce {
				save = crypto.OverwritePrivateKey
			}
			if err := save(kp.PrivateKey, keyPath); err != nil {
				return fmt.Errorf("failed saving private key: %w", err)
			}
			fmt.Printf("Generated an age X25519 keypair\n")
			fmt.Printf("   Public key:  %s\n", kp.PublicKey)
			fmt.Printf("   Private key: %s (mode 0600)\n", keyPath)

			// 2. Prepare Config
			nodeID := "node-" + uuid.New().String()[:8]
			if nodeName == "" {
				nodeName = defaultNodeName()
			}

			cfg = &config.CLIConfig{
				NodeID:      nodeID,
				NodeName:    nodeName,
				ServerURL:   serverURL,
				Storage: config.StorageConfig{
					Type:          config.StorageType(storageType),
					Bucket:        s3Bucket,
					Region:        s3Region,
					Endpoint:      s3Endpoint,
					Prefix:        s3Prefix,
					RetentionDays: retentionDays,
					WORMMode:      config.WORMMode(wormMode),
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

			if cfg.Storage.Type == config.StorageTypeS3 {
				if _, err := cfg.Storage.ResolveWORMMode(); err != nil {
					return fmt.Errorf("--worm-mode: %w. Nothing was written", err)
				}
			}

			// Verify S3 Object Lock if S3 storage is configured
			if cfg.Storage.Type == config.StorageTypeS3 && cfg.Storage.Bucket != "" {
				s3Prov, err := storage.NewS3Storage(cmd.Context(), cfg.Storage)
				if err == nil {
					err = s3Prov.VerifyBucketObjectLock(cmd.Context())
				}
				switch {
				case cfg.Storage.WORMMode == config.WORMModeNone:
					// The check passes without asking under NONE; "compliance
					// mode is on" here would claim a lock nothing applies.
					fmt.Printf("Object Lock: none (worm_mode: NONE). Backups in bucket %s can be deleted.\n", cfg.Storage.Bucket)
				case err == nil:
					fmt.Printf("Object Lock: %s mode is on for bucket %s\n", strings.ToLower(string(cfg.Storage.WORMMode)), cfg.Storage.Bucket)
				default:
					fmt.Fprintf(os.Stderr, "Warning: could not confirm Object Lock on bucket %s: %v\n   %s.\n",
						cfg.Storage.Bucket, err, objectLockAdvice(err))
				}
			}

			// The database is a surface: every backup source in the file is.
			if dbURL != "" {
				cfg.Surfaces = []config.SurfaceConfig{initDatabaseSurface(dbURL)}
			}

			// 4. Save Config File
			targetConfig, err := saveConfig()
			if err != nil {
				return err
			}
			fmt.Printf("Saved to %s\n\n", targetConfig)
			fmt.Println("Local setup complete.")
			fmt.Println("   Keep a copy of the private key file somewhere safe. It is the key that opens these backups.")
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

	cmd.Flags().StringVar(&dbURL, "database-url", "", "The database to protect, written to the config as its first surface: a URL, or env:VAR / file:/path")
	cmd.Flags().StringVar(&storageType, "storage", "local", "Storage type: 'local', 's3', or 'hosted' (SafeGrd's locked bucket, leased per run)")
	cmd.Flags().StringVar(&s3Bucket, "s3-bucket", "", "S3 bucket, with Object Lock enabled")
	cmd.Flags().StringVar(&s3Prefix, "s3-prefix", "safegrd/snapshots", "Key prefix in the S3 bucket")
	cmd.Flags().StringVar(&s3Region, "s3-region", "us-east-1", "S3 bucket region")
	cmd.Flags().StringVar(&s3Endpoint, "s3-endpoint", "", "S3 endpoint, for MinIO, R2 or another S3-compatible store")
	cmd.Flags().StringVar(&localPath, "local-path", "", "Directory for --storage local (default ~/.safegrd/storage)")
	cmd.Flags().IntVar(&retentionDays, "retention-days", 14, "Days each backup is locked (Object Lock retention)")
	cmd.Flags().StringVar(&wormMode, "worm-mode", "COMPLIANCE", "Object Lock mode for --storage s3: COMPLIANCE, GOVERNANCE, or NONE for a bucket with no Object Lock (DigitalOcean Spaces)")
	cmd.Flags().StringVar(&nodeName, "node-name", "", "Name this host is shown under (default: the hostname)")
	cmd.Flags().BoolVar(&initForce, "force", false,
		"Overwrite an existing config. This discards the settings in it and generates a NEW "+
			"keypair, after which snapshots taken under the old key can only be read with the "+
			"old key; back it up first.")

	return cmd
}

// fileExists reports whether a path is present. An error other than
// "not found" is treated as present: if we cannot tell, refusing is the safe
// answer for a command that would otherwise overwrite.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}

// initDatabaseSurface is the surface `init --database-url` writes. The URL
// is kept as given, a reference included; it is resolved here only to tell
// the engine and name the surface after its database.
func initDatabaseSurface(ref string) config.SurfaceConfig {
	resolved, _ := resolveConfigSecret("database-url", ref)
	kind := string(dump.SurfaceTypeOfURL(resolved))
	if resolved == "" || kind == "" {
		kind = string(model.SurfaceTypePostgres)
	}
	id := "db"
	if dump.IsSQLiteURL(resolved) {
		if p, err := dump.SQLitePath(resolved); err == nil {
			id = strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
		}
	} else if u, err := url.Parse(resolved); err == nil && strings.Trim(u.Path, "/") != "" {
		id = strings.Trim(u.Path, "/")
	}
	id = surfaceIDCleaner.ReplaceAllString(strings.ToLower(id), "-")
	if id == "" || id == "-" {
		id = "db"
	}
	return config.SurfaceConfig{ID: id, Type: kind, Name: id, DatabaseURL: ref}
}

var surfaceIDCleaner = regexp.MustCompile(`[^a-z0-9_.-]+`)
