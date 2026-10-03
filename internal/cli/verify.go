package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
		s3Prefix    string
		s3Region    string
		s3Endpoint  string
		s3AccessKey string
		s3SecretKey string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Test a backup by restoring it in memory, or into a sandbox database",
		Long: `Reads a snapshot from storage, decrypts it on this host with the private key,
and checks its tables, row counts, columns and extensions.

By default (or with --dry-run) the restore is parsed in memory and needs no
database. With --sandbox-target it is restored into that empty database, which
is the full Fire Drill. Either way the result is reported to the remote server
when this host is enrolled.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if snapshotID == "" {
				return fmt.Errorf("--snapshot is required")
			}

			// Apply S3 sink overrides if provided
			if s3Bucket != "" {
				cfg.Storage.Type = config.StorageTypeS3
				cfg.Storage.Bucket = s3Bucket
			}
			if s3Prefix != "" {
				cfg.Storage.Prefix = s3Prefix
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
				resolved, err := ResolveSecretRef("s3-secret-key", s3SecretKey)
				if err != nil {
					return err
				}
				cfg.Storage.SecretAccessKey = resolved
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

			ctx := cmd.Context()

			// Same key set as restore: the host's own key and a
			// managed-custody organization's keys, fetched for this
			// verification only and never written to disk.
			resolvedKey = withManagedIdentities(ctx, cfg, resolvedKey, true)

			if resolvedKey == "" {
				return fmt.Errorf("decryption key required for verification: specify --private-key or configure ~/.safegrd/keys/daemon.key")
			}

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
			// A surface the daemon backs up lives under its own node, not the
			// host's, so the bucket is searched under the node the remote
			// server recorded this snapshot for.
			if recorded := recordedNodeID(ctx, cfg, snapshotID); recorded != "" && recorded != storageCfg.NodeID {
				storageCfg.NodeID = recorded
			}
			rs, err := locateRepoSnapshot(ctx, storageCfg, snapshotID)
			if err != nil {
				// Said, and not fatal: the snapshot may be an archive, which
				// does not need the repositories to be readable.
				fmt.Fprintf(os.Stderr, "Warning: could not look among the incremental repositories: %v\n", err)
			}
			if rs != nil {
				if sandboxURL != "" && !dryRun {
					return fmt.Errorf("snapshot %s is a files snapshot; it is proven by restoring it, so leave out --sandbox-target", snapshotID)
				}
				return verifyRepoSnapshot(ctx, rs, resolvedKey)
			}
			storageProvider, err := openStorage(ctx, cfg, storageCfg)
			if err != nil {
				return fmt.Errorf("storage error: %w", err)
			}
			// Not where this config looks: a recovery machine rebuilding a lost
			// host does not know the node id its backups were filed under.
			if node := storage.LocateSnapshot(ctx, storageProvider, snapshotID); node != "" {
				fmt.Printf("   Found %s under node %s.\n", snapshotID, node)
			}

			// A snapshot hidden behind a delete marker is a clear signal
			// of attack. Reading past it is not enough; the operator
			// has to be told it happened.
			warnAboutShadowedSnapshots(ctx, storageProvider)

			verifier := runner.NewVerifier(storageProvider, cfg.ServerURL)
			if cfg.ServerToken != "" {
				verifier.SetServerToken(cfg.ServerToken)
			}

			// Default to dry restore if --sandbox-target is not explicitly specified or --dry-run is set
			isDryRun := dryRun || sandboxURL == ""

			if isDryRun {
				fmt.Printf("Dry restore of %s: decrypting and reading it in memory\n", snapshotID)
				fmt.Printf("   Snapshot ID:    %s\n", snapshotID)
				// The storage this run reads, after routing: a hosted or
				// console-set bucket is not in cfg.Storage.
				switch storageCfg.Type {
				case config.StorageTypeS3:
					fmt.Printf("   Storage:        s3://%s\n", storageCfg.Bucket)
				case config.StorageTypeHosted:
					fmt.Printf("   Storage:        SafeGrd hosted storage\n")
				default:
					fmt.Printf("   Storage:        %s (a directory on this host)\n", storageCfg.LocalPath)
				}
				fmt.Printf("   Key:            %s\n", identityFingerprint(resolvedKey))
				fmt.Printf("   Method:         schema and COPY data parsed in memory; no database needed\n\n")

				report, dryResult, err := verifier.RunDryRestore(ctx, snapshotID, resolvedKey)
				if err != nil {
					return fmt.Errorf("dry restore of %s: %w", snapshotID, err)
				}

				if report.Status == model.VerificationStatusPassed {
					fmt.Println("Assertions:")
					for _, a := range report.Assertions {
						fmt.Printf("   [PASS] %s (Expected: %s, Actual: %s)\n", a.Name, a.Expected, a.Actual)
					}

					if report.SurfaceType == model.SurfaceTypeFiles {
						fmt.Println("\nFiles read:")
						fmt.Printf("   Files:       %s\n", formatNumber(report.RowsRestored))
						fmt.Printf("   Directories: %d\n", report.TablesRestored)
					} else if report.SurfaceType == model.SurfaceTypeEmail {
						fmt.Println("\nMailbox read:")
						fmt.Printf("   Emails:      %s\n", formatNumber(report.RowsRestored))
						fmt.Printf("   Folders:     %d\n", report.TablesRestored)
					} else if dryResult != nil && len(dryResult.Tables) > 0 {
						fmt.Println("\nTables read:")
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
							fmt.Printf("   %s.%s: %s rows, %s\n",
								t.Schema, t.TableName,
								formatNumber(t.RowCount),
								colDesc)
						}
					}

					fmt.Printf("\nDry restore verified\n")
					fmt.Printf("   Verification ID: %s\n", report.VerificationID)
					fmt.Printf("   Duration:        %s\n", time.Duration(report.DurationMs*int64(time.Millisecond)).Round(time.Millisecond))
					if report.SurfaceType == model.SurfaceTypeFiles {
						fmt.Printf("   Files:           %s\n", formatNumber(report.RowsRestored))
						fmt.Printf("   Directories:     %d\n", report.TablesRestored)
					} else if report.SurfaceType == model.SurfaceTypeEmail {
						fmt.Printf("   Emails:          %s\n", formatNumber(report.RowsRestored))
						fmt.Printf("   Folders:         %d\n", report.TablesRestored)
					} else {
						fmt.Printf("   Tables:          %d\n", report.TablesRestored)
						fmt.Printf("   Rows:            %s\n", formatNumber(report.RowsRestored))
					}
					fmt.Printf("   Certificate:     %s\n", report.CertificateHash)
					return nil
				}

				fmt.Printf("Dry restore failed\n")
				for _, a := range report.Assertions {
					status := "PASS"
					if !a.Passed {
						status = "FAIL"
					}
					fmt.Printf("   [%s] %s: %s (Expected: %s, Actual: %s)\n", status, a.Name, a.Message, a.Expected, a.Actual)
				}
				return fmt.Errorf("dry restore of %s failed: %s", snapshotID, report.ErrorMessage)
			}

			// Active Sandbox Fire Drill
			fmt.Printf("Fire Drill: restoring %s into the sandbox database\n", snapshotID)
			fmt.Printf("   Snapshot ID:    %s\n", snapshotID)
			fmt.Printf("   Sandbox:        %s\n\n", dump.RedactURL(sandboxURL))

			report, err := verifier.RunFireDrill(ctx, snapshotID, resolvedKey, sandboxURL)
			if err != nil {
				return fmt.Errorf("fire drill of %s: %w", snapshotID, err)
			}

			if report.Status == model.VerificationStatusPassed {
				fmt.Printf("Fire Drill Passed\n")
				fmt.Printf("   Verification ID: %s\n", report.VerificationID)
				fmt.Printf("   Duration:        %s\n", time.Duration(report.DurationMs*int64(time.Millisecond)).Round(time.Millisecond))
				fmt.Printf("   Tables restored: %d\n", report.TablesRestored)
				fmt.Printf("   Rows restored:   %d\n", report.RowsRestored)
				fmt.Printf("   Certificate:     %s\n", report.CertificateHash)
				fmt.Println("\nAssertions:")
				for _, a := range report.Assertions {
					fmt.Printf("   [PASS] %s (Expected: %s, Actual: %s)\n", a.Name, a.Expected, a.Actual)
				}
			} else {
				fmt.Printf("Fire Drill Failed\n")
				for _, a := range report.Assertions {
					status := "PASS"
					if !a.Passed {
						status = "FAIL"
					}
					fmt.Printf("   [%s] %s: %s (Expected: %s, Actual: %s)\n", status, a.Name, a.Message, a.Expected, a.Actual)
				}
				return fmt.Errorf("fire drill of %s failed: %s", snapshotID, report.ErrorMessage)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&snapshotID, "snapshot", "", "Snapshot ID to verify (required)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Restore in memory only, even with --sandbox-target (the default without it)")
	cmd.Flags().StringVar(&sandboxURL, "sandbox-target", "", "An empty database to restore the snapshot into for a full Fire Drill: postgres://…, mysql://…, or sqlite:///path/to/absent.db")
	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to the age identity file")
	cmd.Flags().StringVar(&privKey, "private-key", "", "Age identity (AGE-SECRET-KEY-1...), as env:VAR, file:/path or the key")
	cmd.Flags().StringVar(&s3Bucket, "s3-bucket", "", "Read the snapshot from this S3 bucket instead of the configured storage")
	cmd.Flags().StringVar(&s3Prefix, "s3-prefix", "", "Key prefix in the S3 bucket")
	cmd.Flags().StringVar(&s3Region, "s3-region", "", "S3 region of --s3-bucket")
	cmd.Flags().StringVar(&s3Endpoint, "s3-endpoint", "", "S3 endpoint of --s3-bucket, for MinIO, R2 or another S3-compatible store")
	cmd.Flags().StringVar(&s3AccessKey, "s3-access-key", "", "S3 access key ID for --s3-bucket")
	cmd.Flags().StringVar(&s3SecretKey, "s3-secret-key", "", "S3 secret access key, as env:VAR or file:/path")

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
		Short:   "Check a node's attestation chain and Ed25519 signatures",
		Long: `Checks a node's attestation records, fetched from the remote server or read from
a file with --file:

1. The first record has PrevHash 'genesis'.
2. Every later record's PrevHash is the certificate hash of the one before it,
   so no record was changed, removed or inserted.
3. Every signed record's Ed25519 signature is valid against the attestation
   public key (from --key, --key-file or the remote server). Unsigned records
   are counted and reported.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if nodeID == "" {
				nodeID = cfg.NodeID
			}
			if nodeID == "" && localFile == "" {
				return fmt.Errorf("--node is required: this config names no node_id")
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
				pkReq, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, serverURL+"/api/v1/attestations/public-key", nil)
				if err != nil {
					return err
				}
				resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(pkReq)
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
			// A key of the wrong length used to skip every signature check
			// and still report the signatures verified.
			if len(pubKey) != ed25519.PublicKeySize {
				return fmt.Errorf("the attestation public key is %d bytes; an Ed25519 public key is %d", len(pubKey), ed25519.PublicKeySize)
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
				req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, fmt.Sprintf("%s/api/v1/verifications?node_id=%s", serverURL, url.QueryEscape(nodeID)), nil)
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
					fmt.Printf("No attestation records found for node %s.\n", nodeID)
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
			unsigned := 0
			for i, r := range reports {
				// 1. Verify PrevHash chaining
				if r.PrevHash != expectedPrev {
					return fmt.Errorf("CHAIN BREAK DETECTED at index %d (verification %s): expected PrevHash=%q, actual PrevHash=%q",
						i, r.VerificationID, expectedPrev, r.PrevHash)
				}

				// 2. Verify the signature. A record with none is counted and
				// said, never passed as verified.
				if r.Signature == "" {
					unsigned++
				} else {
					sigBytes, err := hex.DecodeString(r.Signature)
					if err != nil || !ed25519.Verify(pubKey, r.CanonicalBytes(), sigBytes) {
						return fmt.Errorf("INVALID SIGNATURE at index %d (verification %s): the Ed25519 signature does not match the record",
							i, r.VerificationID)
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
					"signatures_ok": unsigned == 0,
					"unsigned":      unsigned,
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}

			fmt.Println("Attestation History Verified")
			fmt.Printf("   Node ID:         %s\n", nodeID)
			fmt.Printf("   Records:         %d, each linked to the one before it from genesis\n", len(reports))
			fmt.Printf("   Genesis hash:    %s\n", reports[0].CertificateHash)
			fmt.Printf("   Head hash:       %s\n", reports[len(reports)-1].CertificateHash)
			if unsigned == 0 {
				fmt.Printf("   Signatures:      %d of %d valid (Ed25519)\n", len(reports), len(reports))
			} else {
				fmt.Printf("   Signatures:      %d of %d valid (Ed25519); %d records carry no signature\n",
					len(reports)-unsigned, len(reports), unsigned)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&nodeID, "node", "", "Node ID to verify history for")
	cmd.Flags().StringVar(&keyStr, "key", "", "Hex-encoded Ed25519 attestation public key")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "Path to file containing hex-encoded public key")
	cmd.Flags().StringVar(&localFile, "file", "", "JSON file of verification records to check offline")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Print the result as JSON on stdout")

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

// identityFingerprint names an Age identity by its public half's fingerprint,
// the same one enroll prints and the console shows beside each node. The first
// characters of the identity itself are "AGE-SECRET-KEY-1" for every key, so
// they name nothing.
func identityFingerprint(identity string) string {
	// Restore and verify may hold several identities, one per line: the
	// host's own and the ones SafeGrd holds for the organization.
	var prints []string
	for _, line := range strings.Split(strings.TrimSpace(identity), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		recipient, err := recipientFor(line)
		if err != nil {
			return "unreadable identity"
		}
		prints = append(prints, crypto.Fingerprint(recipient))
	}
	if len(prints) > 1 {
		return fmt.Sprintf("%d keys (%s)", len(prints), strings.Join(prints, ", "))
	}
	return strings.Join(prints, "")
}
