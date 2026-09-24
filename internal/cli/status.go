package cli

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check connectivity, storage immutability, and encryption keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			fmt.Println("🔍 Checking SafeGrd Node Status...")

			// 1. Database connectivity
			if cfg.DatabaseURL != "" {
				label, ping := "Postgres DB:      ", func() error { return pingSQL("pgx", cfg.DatabaseURL) }
				switch {
				case dump.IsMongoURL(cfg.DatabaseURL):
					label, ping = "MongoDB:          ", func() error {
						client, _, err := dump.OpenMongo(ctx, cfg.DatabaseURL)
						if err != nil {
							return err
						}
						defer func() { _ = client.Disconnect(ctx) }()
						return client.Ping(ctx, nil)
					}
				case dump.IsMySQLURL(cfg.DatabaseURL):
					label, ping = "MySQL DB:         ", func() error {
						db, err := dump.OpenMySQL(cfg.DatabaseURL)
						if err != nil {
							return err
						}
						defer db.Close()
						return db.PingContext(ctx)
					}
				}
				if err := ping(); err == nil {
					fmt.Printf("   %s ✅ Connected\n", label)
				} else {
					fmt.Printf("   %s ❌ Failed to connect (%v)\n", label, err)
				}
			} else {
				fmt.Printf("   Database:          ⚠️  Not configured (set database_url)\n")
			}

			// 2. Encryption Keys
			if cfg.Encryption.PublicKey != "" {
				_, err := crypto.ParseRecipient(cfg.Encryption.PublicKey)
				if err == nil {
					fmt.Printf("   Public Key:        ✅ Valid (%s...)\n", cfg.Encryption.PublicKey[:16])
				} else {
					fmt.Printf("   Public Key:        ❌ Invalid format\n")
				}
			} else {
				fmt.Printf("   Public Key:        ❌ Missing (run 'safegrd init')\n")
			}

			// 3. Storage Provider Connectivity & Immutability Verification
			// Routed and credentialed like backup and restore. A node enrolled
			// under Journey A has no bucket or sink secret locally, so reading
			// cfg.Storage directly means this command cannot reach the bucket
			// at all on exactly the hosts central configuration exists for.
			storageCfg := resolveStorageRouting(ctx, cfg, "", "", "", "", false)
			if _, err := resolveHostedStorage(ctx, cfg, &storageCfg, false); err != nil {
				return err
			}
			resolveRuntimeCredentials(ctx, cfg, &storageCfg, false)
			if cfg.NodeID != "" && storageCfg.NodeID == "" {
				storageCfg.NodeID = cfg.NodeID
			}
			storageProvider, err := storage.NewProvider(ctx, storageCfg)
			if err == nil {
				snaps, err := storageProvider.ListSnapshots(ctx)
				if err == nil {
					fmt.Printf("   Storage (%s):    ✅ Accessible (%d snapshots stored)\n", cfg.Storage.Type, len(snaps))
				} else {
					fmt.Printf("   Storage (%s):    ❌ Error listing snapshots: %v\n", cfg.Storage.Type, err)
				}

				if s3Prov, ok := storageProvider.(*storage.S3StorageProvider); ok {
					if err := s3Prov.VerifyBucketObjectLock(ctx); err == nil {
						fmt.Printf("   WORM Object Lock:  ✅ Verified enabled on bucket %s\n", cfg.Storage.Bucket)
					} else {
						fmt.Printf("   WORM Object Lock:  ⚠️  Not enabled or unverified on bucket %s: %v\n", cfg.Storage.Bucket, err)
					}
				}
			} else {
				fmt.Printf("   Storage:           ❌ Provider error: %v\n", err)
			}

			// 4. remote server Connectivity
			if cfg.ServerToken == "" {
				// Not enrolled: pinging the default remote server would report
				// on a service this host does not use.
				fmt.Printf("   Remote Server:     Standalone (not enrolled; run 'safegrd enroll' to report to the console)\n")
			} else if cfg.ServerURL != "" {
				client := &http.Client{Timeout: 3 * time.Second}
				resp, err := client.Get(cfg.ServerURL + "/healthz")
				if err == nil && resp.StatusCode == http.StatusOK {
					fmt.Printf("   Remote Server:     ✅ Online (%s)\n", cfg.ServerURL)
					resp.Body.Close()
				} else {
					fmt.Printf("   Remote Server:     ⚠️  Unreachable (%s)\n", cfg.ServerURL)
				}
			}

			return nil
		},
	}
}

func pingSQL(driver, dsn string) error {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Ping()
}
