package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check the database, key, storage and remote server this host uses",
		Long: `Checks the database, the encryption key, the storage and the remote server this
host is configured for, one line each. Exits 1 if any check fails.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			failed := 0
			fail := func(format string, args ...any) {
				failed++
				fmt.Printf(format, args...)
			}

			// 1. Database connectivity
			if cfg.DatabaseURL != "" {
				label, ping := "PostgreSQL:       ", func() error { return pingSQL("pgx", cfg.DatabaseURL) }
				switch {
				case dump.IsSQLiteURL(cfg.DatabaseURL):
					label, ping = "SQLite:           ", func() error { return dump.PingSQLite(ctx, cfg.DatabaseURL) }
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
					label, ping = "MySQL:            ", func() error {
						db, err := dump.OpenMySQL(cfg.DatabaseURL)
						if err != nil {
							return err
						}
						defer db.Close()
						return db.PingContext(ctx)
					}
				}
				if err := ping(); err == nil {
					fmt.Printf("%s connected\n", label)
				} else {
					fail("%s FAILED: could not connect (%v)\n", label, err)
				}
			} else if len(cfg.Surfaces) > 0 {
				// Each surface names its own database; `daemon status` shows them.
				fmt.Printf("Surfaces:          %d configured (see 'safegrd daemon status')\n", len(cfg.Surfaces))
			} else {
				fmt.Printf("Database:          not configured (set database_url)\n")
			}

			// 2. Encryption Keys
			if cfg.Encryption.PublicKey != "" {
				_, err := crypto.ParseRecipient(cfg.Encryption.PublicKey)
				if err == nil {
					fmt.Printf("Public key:        valid (%s)\n", crypto.Fingerprint(cfg.Encryption.PublicKey))
				} else {
					fail("Public key:        FAILED: not an age recipient (%v)\n", err)
				}
			} else {
				fail("Public key:        FAILED: missing (run 'safegrd init')\n")
			}

			// 3. Storage Provider Connectivity & Immutability Verification
			// Routed and credentialed like backup and restore. A node enrolled
			// with a centrally-managed sink has no bucket or sink secret locally, so reading
			// cfg.Storage directly means this command cannot reach the bucket
			// on hosts configured centrally.
			storageCfg, routeErr := resolveStorageRouting(ctx, cfg, "", "", "", "", false)
			if routeErr != nil {
				return routeErr
			}
			if _, err := resolveHostedStorage(ctx, cfg, &storageCfg, false); err != nil {
				return err
			}
			resolveRuntimeCredentials(ctx, cfg, &storageCfg, false)
			if cfg.NodeID != "" && storageCfg.NodeID == "" {
				storageCfg.NodeID = cfg.NodeID
			}
			storageProvider, err := openStorage(ctx, cfg, storageCfg)
			if err == nil {
				snaps, err := storageProvider.ListSnapshots(ctx)
				if err == nil {
					// Incremental runs live in repositories beside the
					// single-archive snapshots, and are the default format:
					// counting only the latter said 0 after a backup.
					n := len(snaps) + len(listRepoSnapshots(ctx, storageCfg))
					fmt.Printf("Storage:           %s, readable (%d snapshots)\n", storageCfg.Type, n)
				} else {
					fail("Storage:           FAILED: could not list snapshots in %s storage: %v\n", storageCfg.Type, err)
				}

				if storageProvider.Type() == "hosted" {
					fmt.Printf("Object Lock:       compliance mode, set by the remote server on every hosted object\n")
				}
				if s3Prov, ok := storageProvider.(*storage.S3StorageProvider); ok {
					if err := s3Prov.VerifyBucketObjectLock(ctx); err == nil {
						fmt.Printf("Object Lock:       on for bucket %s\n", storageCfg.Bucket)
					} else {
						fail("Object Lock:       FAILED: not confirmed on bucket %s: %v\n", storageCfg.Bucket, err)
					}
				}
			} else {
				fail("Storage:           FAILED: %v\n", err)
			}

			// 4. remote server Connectivity
			if cfg.ServerToken == "" {
				// Not enrolled: pinging the default remote server would report
				// on a service this host does not use.
				fmt.Printf("Remote server:     none (standalone; run 'safegrd enroll' to report to the console)\n")
			} else if cfg.ServerURL != "" {
				client := &http.Client{Timeout: 3 * time.Second}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.ServerURL+"/api/v1/nodes/"+cfg.NodeID, nil)
				if err == nil && cfg.NodeID != "" {
					req.Header.Set("Authorization", "Bearer "+cfg.ServerToken)
					req.Header.Set("User-Agent", UserAgent())
					resp, err := client.Do(req)
					if err == nil {
						defer resp.Body.Close()
						switch {
						case resp.StatusCode == http.StatusOK:
							fmt.Printf("Remote server:     online, node %s accepted (%s)\n", cfg.NodeID, cfg.ServerURL)
							var n model.Node
							if err := json.NewDecoder(resp.Body).Decode(&n); err == nil && n.UpgradeAvailable {
								fmt.Printf("CLI update:        v%s is available (installed: %s)\n", n.LatestCLIVersion, Version)
							}
						case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
							// The server is up and said no. Reporting that as
							// "online" is how a revoked token went unnoticed.
							fail("Remote server:     FAILED: %s refused this host's token (HTTP %d). Re-run 'safegrd enroll'\n", cfg.ServerURL, resp.StatusCode)
						default:
							fail("Remote server:     FAILED: %s answered HTTP %d\n", cfg.ServerURL, resp.StatusCode)
						}
					} else {
						fail("Remote server:     FAILED: could not reach %s (%v)\n", cfg.ServerURL, err)
					}
				} else {
					resp, err := client.Get(cfg.ServerURL + "/healthz")
					switch {
					case err != nil:
						fail("Remote server:     FAILED: could not reach %s (%v)\n", cfg.ServerURL, err)
					case resp.StatusCode != http.StatusOK:
						resp.Body.Close()
						fail("Remote server:     FAILED: %s answered HTTP %d\n", cfg.ServerURL, resp.StatusCode)
					default:
						resp.Body.Close()
						fmt.Printf("Remote server:     online (%s); this config names no node_id\n", cfg.ServerURL)
					}
				}
			}

			if failed > 0 {
				return fmt.Errorf("%d %s failed", failed, pluralWord(int64(failed), "check", "checks"))
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
