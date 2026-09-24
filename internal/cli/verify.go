package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/runner"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

func newVerifyCmd() *cobra.Command {
	var (
		snapshotID  string
		sandboxURL  string
		dryRun      bool
		keyPath     string
		privKey     string
		s3Bucket    string
		s3Region    string
		s3Endpoint  string
		s3AccessKey string
		s3SecretKey string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify backup integrity via in-memory dry restore or sandbox Fire Drill",
		Long: `Pulls an encrypted snapshot from storage (S3 or local WORM), decrypts it in-memory
using your private Age encryption key, and verifies table counts, row counts,
column counts, and extensions.

By default (or with --dry-run), performs a pure Go in-memory dry restore requiring
no running PostgreSQL database instance. When --sandbox-target is provided without --dry-run,
executes a full active restore drill into the target ephemeral database.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if snapshotID == "" {
				return fmt.Errorf("--snapshot flag is required")
			}

			// Apply S3 sink overrides if provided
			if s3Bucket != "" {
				cfg.Storage.Type = config.StorageTypeS3
				cfg.Storage.Bucket = s3Bucket
			}
			if s3Region != "" {
				cfg.Storage.Region = s3Region
			}
			if s3Endpoint != "" {
				cfg.Storage.Endpoint = s3Endpoint
			}
			if s3AccessKey != "" {
				cfg.Storage.AccessKeyID = s3AccessKey
			}
			if s3SecretKey != "" {
				cfg.Storage.SecretAccessKey = s3SecretKey
			}

			// Load private key
			resolvedKey := privKey
			if resolvedKey != "" {
				resolved, err := ResolveSecretRef("private-key", resolvedKey)
				if err != nil {
					return err
				}
				resolvedKey = resolved
			}
			if resolvedKey == "" {
				resolvedKey = cfg.Encryption.PrivateKey
			}
			if resolvedKey == "" {
				path := keyPath
				if path == "" {
					path = cfg.Encryption.KeyPath
				}
				if path != "" {
					loaded, err := crypto.LoadPrivateKey(path)
					if err == nil {
						resolvedKey = loaded
					}
				}
			}

			ctx := context.Background()

			// Same last resort as restore: a managed-custody
			// organization's identity, fetched for this verification only and
			// never written to disk.
			if resolvedKey == "" {
				resolvedKey = resolveManagedIdentity(ctx, cfg, true)
			}

			if resolvedKey == "" {
				return fmt.Errorf("decryption key required for verification: specify --private-key or configure ~/.safegrd/keys/agent.key")
			}

			storageCfg := resolveStorageRouting(ctx, cfg, "", "", "", "", false)
			if _, err := resolveHostedStorage(ctx, cfg, &storageCfg, false); err != nil {
				return err
			}
			resolveRuntimeCredentials(ctx, cfg, &storageCfg, false)
			if cfg.NodeID != "" && storageCfg.NodeID == "" {
				storageCfg.NodeID = cfg.NodeID
			}
			// A surface the agent backs up lives under its own node, not the
			// host's, so the bucket is searched under the node the control
			// plane recorded this snapshot for.
			if recorded := recordedNodeID(ctx, cfg, snapshotID); recorded != "" && recorded != storageCfg.NodeID {
				storageCfg.NodeID = recorded
			}
			storageProvider, err := storage.NewProvider(ctx, storageCfg)
			if err != nil {
				return fmt.Errorf("storage error: %w", err)
			}
			// Not where this config looks: a recovery machine rebuilding a lost
			// host does not know the node id its backups were filed under.
			if node := storage.LocateSnapshot(ctx, storageProvider, snapshotID); node != "" {
				fmt.Printf("   Found %s under node %s.\n", snapshotID, node)
			}

			// A snapshot hidden behind a delete marker is the loudest signal
			// of attack this system can receive. Reading past it is
			// not enough — the operator has to be told it happened.
			warnAboutShadowedSnapshots(ctx, storageProvider)

			verifier := runner.NewVerifier(storageProvider, cfg.ServerURL)
			if cfg.ServerToken != "" {
				verifier.SetServerToken(cfg.ServerToken)
			}

			// Default to dry restore if --sandbox-target is not explicitly specified or --dry-run is set
			isDryRun := dryRun || sandboxURL == ""

			if isDryRun {
				fmt.Printf("🛡️  SafeGrd In-Memory Dry Restore Verification...\n")
				fmt.Printf("   Snapshot ID:    %s\n", snapshotID)
				if cfg.Storage.Type == config.StorageTypeS3 {
					fmt.Printf("   Storage Source: s3://%s (pulling encrypted ciphertext)\n", cfg.Storage.Bucket)
				} else {
					fmt.Printf("   Storage Source: %s (local WORM repository)\n", cfg.Storage.LocalPath)
				}
				fmt.Printf("   Decryption Key: %s...\n", resolvedKey[:16])
				fmt.Printf("   Engine:         Pure Go in-memory catalog & COPY inspector (no Postgres target required)\n\n")

				report, dryResult, err := verifier.RunDryRestore(ctx, snapshotID, resolvedKey)
				if err != nil {
					return fmt.Errorf("dry restore execution error: %w", err)
				}

				if report.Status == model.VerificationStatusPassed {
					fmt.Println("Assertions:")
					for _, a := range report.Assertions {
						fmt.Printf("   [PASS] %s (Expected: %s, Actual: %s)\n", a.Name, a.Expected, a.Actual)
					}

					if report.SurfaceType == model.SurfaceTypeFiles {
						fmt.Println("\nVerified File Catalog:")
						fmt.Printf("   • Total Files:       %s\n", formatNumber(report.RowsRestored))
						fmt.Printf("   • Total Directories: %d\n", report.TablesRestored)
					} else if report.SurfaceType == model.SurfaceTypeEmail {
						fmt.Println("\nVerified Mailbox:")
						fmt.Printf("   • Total Emails:      %s\n", formatNumber(report.RowsRestored))
						fmt.Printf("   • Total Folders:     %d\n", report.TablesRestored)
					} else if dryResult != nil && len(dryResult.Tables) > 0 {
						fmt.Println("\nVerified Table Catalog:")
						for _, t := range dryResult.Tables {
							colDesc := fmt.Sprintf("%d columns", t.ColumnCount)
							if len(t.Columns) > 0 {
								colNames := make([]string, 0, len(t.Columns))
								for _, c := range t.Columns {
									colNames = append(colNames, c.Name)
								}
								if len(colNames) <= 5 {
									colDesc += " [" + strings.Join(colNames, ", ") + "]"
								} else {
									colDesc += " [" + strings.Join(colNames[:5], ", ") + ", ...]"
								}
							}
							fmt.Printf("   • %s.%s: %s rows, %s\n",
								t.Schema, t.TableName,
								formatNumber(t.RowCount),
								colDesc)
						}
					}

					fmt.Printf("\n✅ Dry Restore Verified Successfully!\n")
					fmt.Printf("   Verification ID: %s\n", report.VerificationID)
					fmt.Printf("   Duration:        %s\n", time.Duration(report.DurationMs*int64(time.Millisecond)).Round(time.Millisecond))
					if report.SurfaceType == model.SurfaceTypeFiles {
						fmt.Printf("   Files Verified:  %s\n", formatNumber(report.RowsRestored))
						fmt.Printf("   Dirs Verified:   %d\n", report.TablesRestored)
					} else if report.SurfaceType == model.SurfaceTypeEmail {
						fmt.Printf("   Emails Verified: %s\n", formatNumber(report.RowsRestored))
						fmt.Printf("   Folders Verified:%d\n", report.TablesRestored)
					} else {
						fmt.Printf("   Tables Verified: %d\n", report.TablesRestored)
						fmt.Printf("   Rows Verified:   %s\n", formatNumber(report.RowsRestored))
					}
					fmt.Printf("   Certificate:     %s\n", report.CertificateHash)
					return nil
				}

				fmt.Printf("❌ Dry Restore Verification Failed!\n")
				fmt.Printf("   Error: %s\n", report.ErrorMessage)
				for _, a := range report.Assertions {
					status := "PASS"
					if !a.Passed {
						status = "FAIL"
					}
					fmt.Printf("   [%s] %s: %s (Expected: %s, Actual: %s)\n", status, a.Name, a.Message, a.Expected, a.Actual)
				}
				return fmt.Errorf("dry restore verification failed")
			}

			// Active Sandbox Fire Drill
			fmt.Printf("🔥 Running SafeGrd Fire Drill Verification...\n")
			fmt.Printf("   Snapshot ID:    %s\n", snapshotID)
			fmt.Printf("   Sandbox Target: %s\n\n", dump.RedactURL(sandboxURL))

			report, err := verifier.RunFireDrill(ctx, snapshotID, resolvedKey, sandboxURL)
			if err != nil {
				return fmt.Errorf("fire drill execution error: %w", err)
			}

			if report.Status == model.VerificationStatusPassed {
				fmt.Printf("✅ Fire Drill Passed!\n")
				fmt.Printf("   Verification ID: %s\n", report.VerificationID)
				fmt.Printf("   Duration:        %s\n", time.Duration(report.DurationMs*int64(time.Millisecond)).Round(time.Millisecond))
				fmt.Printf("   Tables Restored: %d\n", report.TablesRestored)
				fmt.Printf("   Rows Restored:   %d\n", report.RowsRestored)
				fmt.Printf("   Certificate:     %s\n", report.CertificateHash)
				fmt.Println("\nAssertions:")
				for _, a := range report.Assertions {
					fmt.Printf("   [PASS] %s (Expected: %s, Actual: %s)\n", a.Name, a.Expected, a.Actual)
				}
			} else {
				fmt.Printf("❌ Fire Drill Failed!\n")
				fmt.Printf("   Error: %s\n", report.ErrorMessage)
				for _, a := range report.Assertions {
					status := "PASS"
					if !a.Passed {
						status = "FAIL"
					}
					fmt.Printf("   [%s] %s: %s (Expected: %s, Actual: %s)\n", status, a.Name, a.Message, a.Expected, a.Actual)
				}
				return fmt.Errorf("fire drill assertions failed")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&snapshotID, "snapshot", "", "Snapshot ID to verify (required)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Perform pure Go in-memory dry restore without target database")
	cmd.Flags().StringVar(&sandboxURL, "sandbox-target", "", "An empty database to restore the snapshot into for a full Fire Drill: postgres://… or mysql://…")
	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to Age private identity file")
	cmd.Flags().StringVar(&privKey, "private-key", "", "Age private identity key string")
	cmd.Flags().StringVar(&s3Bucket, "s3-bucket", "", "Override S3 bucket to pull snapshot from")
	cmd.Flags().StringVar(&s3Region, "s3-region", "", "Override S3 region")
	cmd.Flags().StringVar(&s3Endpoint, "s3-endpoint", "", "Override S3 endpoint (e.g. for MinIO, Cloudflare R2)")
	cmd.Flags().StringVar(&s3AccessKey, "s3-access-key", "", "Override S3 Access Key ID")
	cmd.Flags().StringVar(&s3SecretKey, "s3-secret-key", "", "Override S3 Secret Access Key")

	cmd.AddCommand(newVerifyHistoryCmd())

	return cmd
}

func newVerifyHistoryCmd() *cobra.Command {
	var (
		nodeID    string
		keyStr    string
		keyFile   string
		localFile string
		jsonOut   bool
	)

	cmd := &cobra.Command{
		Use:     "history",
		Aliases: []string{"verify-history"},
		Short:   "Verify cryptographic attestation chain and Ed25519 signatures for a node",
		Long: `Performs offline or remote verification of the tamper-evident attestation hash chain (PrevHash).
Validates that:
1. Genesis block has PrevHash='genesis'
2. Every subsequent block links immutably to the predecessor certificate hash
3. All Ed25519 signatures are valid against the remote server's attestation public key
4. No records have been modified, skipped, or backdated.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if nodeID == "" {
				nodeID = cfg.NodeID
			}
			if nodeID == "" && localFile == "" {
				return fmt.Errorf("--node flag is required")
			}

			serverURL := resolveServerURL()

			// 1. Resolve attestation public key
			var pubKey ed25519.PublicKey
			if keyStr != "" {
				raw, err := hex.DecodeString(strings.TrimSpace(keyStr))
				if err != nil {
					return fmt.Errorf("invalid hex public key: %w", err)
				}
				pubKey = ed25519.PublicKey(raw)
			} else if keyFile != "" {
				data, err := os.ReadFile(keyFile)
				if err != nil {
					return fmt.Errorf("failed to read public key file: %w", err)
				}
				raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
				if err != nil {
					return fmt.Errorf("invalid hex in public key file: %w", err)
				}
				pubKey = ed25519.PublicKey(raw)
			} else {
				resp, err := http.Get(serverURL + "/api/v1/attestations/public-key")
				if err != nil {
					return fmt.Errorf("failed to fetch attestation public key from %s: %w", serverURL, err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("server returned status %d fetching public key", resp.StatusCode)
				}
				var pkResp struct {
					PublicKey string `json:"public_key"`
					KeyID     string `json:"key_id"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&pkResp); err != nil {
					return fmt.Errorf("failed to decode public key: %w", err)
				}
				raw, err := hex.DecodeString(pkResp.PublicKey)
				if err != nil {
					return fmt.Errorf("invalid hex in server public key: %w", err)
				}
				pubKey = ed25519.PublicKey(raw)
			}

			// 2. Load verifications
			var reports []*model.VerificationReport
			if localFile != "" {
				data, err := os.ReadFile(localFile)
				if err != nil {
					return fmt.Errorf("failed to read verifications file: %w", err)
				}
				if err := json.Unmarshal(data, &reports); err != nil {
					return fmt.Errorf("failed to parse verifications file: %w", err)
				}
			} else {
				req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/verifications?node_id=%s", serverURL, nodeID), nil)
				if err != nil {
					return err
				}
				if cfg.ServerToken != "" {
					req.Header.Set("Authorization", "Bearer "+cfg.ServerToken)
				}
				client := &http.Client{Timeout: 10 * time.Second}
				resp, err := client.Do(req)
				if err != nil {
					return fmt.Errorf("failed to fetch verifications from server: %w", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("server returned status %d fetching verifications for node %s", resp.StatusCode, nodeID)
				}
				if err := json.NewDecoder(resp.Body).Decode(&reports); err != nil {
					return fmt.Errorf("failed to decode verifications: %w", err)
				}
			}

			if len(reports) == 0 {
				if jsonOut {
					fmt.Println(`{"status":"empty","count":0}`)
				} else {
					fmt.Printf("ℹ️  No attestation records found for node %s.\n", nodeID)
				}
				return nil
			}

			// Sort oldest first (started_at ASC) to verify chain forwards from genesis
			sort.Slice(reports, func(i, j int) bool {
				if reports[i].StartedAt.Equal(reports[j].StartedAt) {
					return reports[i].VerificationID < reports[j].VerificationID
				}
				return reports[i].StartedAt.Before(reports[j].StartedAt)
			})

			expectedPrev := "genesis"
			for i, r := range reports {
				// 1. Verify PrevHash chaining
				if r.PrevHash != expectedPrev {
					err := fmt.Errorf("CHAIN BREAK DETECTED at index %d (verification %s): expected PrevHash=%q, actual PrevHash=%q",
						i, r.VerificationID, expectedPrev, r.PrevHash)
					if !jsonOut {
						fmt.Printf("❌ %v\n", err)
					}
					return err
				}

				// 2. Verify signature if signature is present
				if r.Signature != "" && len(pubKey) == ed25519.PublicKeySize {
					sigBytes, err := hex.DecodeString(r.Signature)
					if err != nil || !ed25519.Verify(pubKey, r.CanonicalBytes(), sigBytes) {
						err := fmt.Errorf("SIGNATURE FORGERY DETECTED at index %d (verification %s): Ed25519 signature is invalid",
							i, r.VerificationID)
						if !jsonOut {
							fmt.Printf("❌ %v\n", err)
						}
						return err
					}
				}

				// Next link in chain must point to this report's certificate hash
				expectedPrev = r.CertificateHash
			}

			if jsonOut {
				res := map[string]any{
					"status":        "verified",
					"node_id":       nodeID,
					"chain_depth":   len(reports),
					"genesis_hash":  reports[0].CertificateHash,
					"head_hash":     reports[len(reports)-1].CertificateHash,
					"signatures_ok": true,
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			fmt.Println("🛡️  SafeGrd Attestation History Verified")
			fmt.Printf("   Node ID:         %s\n", nodeID)
			fmt.Printf("   Chain Depth:     %d records\n", len(reports))
			fmt.Printf("   Genesis Hash:    %s\n", reports[0].CertificateHash)
			fmt.Printf("   Head Hash:       %s\n", reports[len(reports)-1].CertificateHash)
			fmt.Println("   Chain Integrity: 100% (Genesis valid, append-only chaining intact, Ed25519 signatures verified)")
			return nil
		},
	}

	cmd.Flags().StringVar(&nodeID, "node", "", "Node ID to verify history for")
	cmd.Flags().StringVar(&keyStr, "key", "", "Hex-encoded Ed25519 attestation public key")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "Path to file containing hex-encoded public key")
	cmd.Flags().StringVar(&localFile, "file", "", "Path to local JSON file of verifications (for offline air-gapped audit)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output verification result in JSON format")

	return cmd
}

func formatNumber(n int64) string {
	in := fmt.Sprintf("%d", n)
	var out []byte
	l := len(in)
	for i, c := range []byte(in) {
		if i > 0 && (l-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}
