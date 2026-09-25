package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/spf13/cobra"
)

func newBackupCmd() *cobra.Command {
	var (
		dbURL         string
		engineStr     string
		retentionDays int
		tag           string
		jsonOutput    bool

		// File surface flags
		filesPath string
		excludes  []string

		// Email surface flags
		emailMode    bool
		emailHost    string
		emailPort    int
		emailCAFile  string
		emailUser    string
		emailPass    string
		emailFolders []string

		// Storage routing flags
		storageBucket   string
		storagePrefix   string
		storageRegion   string
		storageEndpoint string
	)

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Execute an encrypted, immutable backup (Postgres, Files, or Email)",
		Long: `Performs a zero-knowledge streaming backup, compresses with zstandard,
encrypts client-side using asymmetric Age encryption, and ships ciphertext directly to immutable WORM storage.
Plaintext data NEVER touches disk or third-party networks.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			// Resolve storage according to the routing precedence rule:
			// CLI Flags > Remote Server Project Sink > Local Config Fallback
			storageCfg := resolveStorageRouting(ctx, cfg, storageBucket, storagePrefix, storageRegion, storageEndpoint, !jsonOutput)
			if retentionDays > 0 {
				storageCfg.RetentionDays = retentionDays
			}
			if _, err := resolveHostedStorage(ctx, cfg, &storageCfg, true); err != nil {
				return err
			}

			// Secrets the local config does not carry, fetched just before use
			// and held in memory for this command only. Must run before
			// the provider is constructed: the sink secret is what the provider
			// authenticates with, and before ValidateForBackup, which is what
			// decides the config is incomplete.
			resolveRuntimeCredentials(ctx, cfg, &storageCfg, !jsonOutput)

			// Initialize storage provider
			storageProvider, err := openStorage(ctx, cfg, storageCfg)
			if err != nil {
				return fmt.Errorf("storage initialization failed: %w", err)
			}

			// Preflight check Object Lock on S3 storage to fail early with clear guidance
			if locker, ok := storageProvider.(interface {
				VerifyBucketObjectLock(ctx context.Context) error
			}); ok {
				if err := locker.VerifyBucketObjectLock(ctx); err != nil {
					return fmt.Errorf("immutable storage preflight check failed: %w", err)
				}
			}

			retentionUntil := time.Now().Add(time.Duration(storageCfg.RetentionDays) * 24 * time.Hour)

			snapshotID := fmt.Sprintf("snap-%s-%s", time.Now().UTC().Format("20060102-150405"), uuid.New().String()[:6])
			if tag != "" {
				snapshotID = fmt.Sprintf("snap-%s-%s", tag, uuid.New().String()[:6])
			}

			// ================================================================
			// Surface 1: File Trees & Directories
			// ================================================================
			if filesPath != "" {
				if err := cfg.ValidateForFileBackup(); err != nil {
					return err
				}

				if !jsonOutput {
					fmt.Printf("🛡️  SafeGrd File Backup Started: %s\n", snapshotID)
					fmt.Printf("   Surface:         Files (%s)\n", filesPath)
					fmt.Printf("   Recipient Key:   %s\n", cfg.Encryption.PublicKey[:16]+"...")
					fmt.Printf("   Target Storage:  %s (%s)\n", storageCfg.Type, wormLabel(storageCfg))
				}

				started := time.Now()
				collector := dump.NewFileCollector(dump.FileCollectorConfig{
					RootDir:  filesPath,
					Excludes: excludes,
				})

				rawStream, meta, err := collector.ScanAndStream(ctx)
				// What the walk left out is said out loud, even when the backup succeeds.
				warnSkipped(collector.Skipped())
				if err != nil {
					retErr := fmt.Errorf("file collection failed: %w", err)
					reportBackupFailure(ctx, cfg, snapshotID, model.SurfaceTypeFiles, "", retErr, !jsonOutput)
					return retErr
				}

				cipherReader, cipherWriter := io.Pipe()
				cryptoMetricsChan := make(chan *crypto.StreamMetrics, 1)
				cryptoErrChan := make(chan error, 1)

				go func() {
					metrics, err := crypto.EncryptStream(rawStream, cipherWriter, cfg.Encryption.PublicKey)
					if err != nil {
						_ = cipherWriter.CloseWithError(err)
						cryptoErrChan <- err
						return
					}
					_ = cipherWriter.Close()
					cryptoMetricsChan <- metrics
				}()

				storageURI, err := storageProvider.UploadSnapshot(ctx, snapshotID, cipherReader, -1, retentionUntil)
				if err != nil {
					retErr := fmt.Errorf("upload to immutable storage failed: %w", err)
					reportBackupFailure(ctx, cfg, snapshotID, model.SurfaceTypeFiles, "", retErr, !jsonOutput)
					return retErr
				}

				var cryptoMetrics *crypto.StreamMetrics
				select {
				case err := <-cryptoErrChan:
					retErr := fmt.Errorf("streaming encryption failed: %w", err)
					reportBackupFailure(ctx, cfg, snapshotID, model.SurfaceTypeFiles, "", retErr, !jsonOutput)
					return retErr
				case cryptoMetrics = <-cryptoMetricsChan:
				}

				meta.SnapshotID = snapshotID
				meta.NodeID = cfg.NodeID
				now := time.Now().UTC()
				meta.CompletedAt = &now
				meta.DurationMs = backupMilliseconds(started)
				meta.Status = model.SnapshotStatusCompleted
				meta.StorageURI = storageURI
				recordRetention(meta, storageCfg, retentionUntil)
				meta.RawSizeBytes = cryptoMetrics.RawBytes
				meta.EncryptedSizeBytes = cryptoMetrics.EncryptedBytes
				meta.Sha256Checksum = cryptoMetrics.RawSha256
				meta.EncryptedSha256 = cryptoMetrics.EncryptedSha256
				meta.CalculateTotals()

				warnIfManifestFailed(storageProvider.UploadMetadata(ctx, snapshotID, meta), snapshotID)
				if cfg.ServerURL != "" {
					sendMetadataToServer(ctx, cfg.ServerURL, cfg.ServerToken, meta, !jsonOutput)
				}

				if jsonOutput {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					return enc.Encode(meta)
				}

				fmt.Println("\n✅ File Backup Completed Successfully!")
				fmt.Printf("   Snapshot ID:     %s\n", meta.SnapshotID)
				fmt.Printf("   Files Backed Up: %d\n", meta.TotalItems)
				fmt.Printf("   Directories:     %d\n", meta.TotalContainers)
				fmt.Printf("   Raw Size:        %.2f MB\n", float64(meta.RawSizeBytes)/(1024*1024))
				fmt.Printf("   Encrypted Size:  %.2f MB (%.1fx compression)\n", float64(meta.EncryptedSizeBytes)/(1024*1024), cryptoMetrics.CompressionRatio)
				printRetentionLine(storageCfg, meta.WORMRetentionUntil)
				fmt.Printf("   Storage URI:     %s\n", meta.StorageURI)
				return nil
			}

			// ================================================================
			// Surface 2: Universal IMAP Email Mailboxes
			// ================================================================
			if emailMode || emailHost != "" {
				if err := cfg.ValidateForEmailBackup(); err != nil {
					return err
				}

				host := emailHost
				if host == "" {
					host = "imap.gmail.com"
				}
				port := emailPort
				if port == 0 {
					port = 993
				}
				user := emailUser
				if user == "" {
					user = os.Getenv("SAFEGRD_EMAIL_USER")
				}
				pass := emailPass
				if pass != "" {
					resolvedPass, err := ResolveSecretRef("email-password", pass)
					if err != nil {
						return err
					}
					pass = resolvedPass
				} else {
					pass = os.Getenv("SAFEGRD_EMAIL_PASSWORD")
				}
				if user == "" || pass == "" {
					return fmt.Errorf("email credentials required: specify --email-user and set SAFEGRD_EMAIL_PASSWORD env var")
				}

				if !jsonOutput {
					fmt.Printf("🛡️  SafeGrd Email Backup Started: %s\n", snapshotID)
					fmt.Printf("   Surface:         IMAP Mailbox (%s on %s:%d)\n", user, host, port)
					fmt.Printf("   Recipient Key:   %s\n", cfg.Encryption.PublicKey[:16]+"...")
					fmt.Printf("   Target Storage:  %s (%s)\n", storageCfg.Type, wormLabel(storageCfg))
				}

				caFile := emailCAFile
				if caFile == "" {
					caFile = os.Getenv("SAFEGRD_EMAIL_CA_FILE")
				}
				tlsCfg, err := emailTLSConfig(host, caFile)
				if err != nil {
					return err
				}
				if caFile != "" && !jsonOutput {
					fmt.Printf("   IMAP Trust:      %s (in addition to the system roots)\n", caFile)
				}

				started := time.Now()
				collector := dump.NewEmailCollector(dump.EmailCollectorConfig{
					Host:           host,
					Port:           port,
					Username:       user,
					Password:       pass,
					IncludeFolders: emailFolders,
					ExcludeFolders: []string{"[Gmail]/Spam", "[Gmail]/Trash"},
					TLSConfig:      tlsCfg,
				})

				rawStream, meta, err := collector.ScanAndStream(ctx, nil)
				if err != nil {
					retErr := fmt.Errorf("email collection failed: %w", err)
					reportBackupFailure(ctx, cfg, snapshotID, model.SurfaceTypeEmail, user, retErr, !jsonOutput)
					return retErr
				}

				cipherReader, cipherWriter := io.Pipe()
				cryptoMetricsChan := make(chan *crypto.StreamMetrics, 1)
				cryptoErrChan := make(chan error, 1)

				go func() {
					metrics, err := crypto.EncryptStream(rawStream, cipherWriter, cfg.Encryption.PublicKey)
					if err != nil {
						_ = cipherWriter.CloseWithError(err)
						cryptoErrChan <- err
						return
					}
					_ = cipherWriter.Close()
					cryptoMetricsChan <- metrics
				}()

				storageURI, err := storageProvider.UploadSnapshot(ctx, snapshotID, cipherReader, -1, retentionUntil)
				if err != nil {
					retErr := fmt.Errorf("upload to immutable storage failed: %w", err)
					reportBackupFailure(ctx, cfg, snapshotID, model.SurfaceTypeEmail, user, retErr, !jsonOutput)
					return retErr
				}

				var cryptoMetrics *crypto.StreamMetrics
				select {
				case err := <-cryptoErrChan:
					retErr := fmt.Errorf("streaming encryption failed: %w", err)
					reportBackupFailure(ctx, cfg, snapshotID, model.SurfaceTypeEmail, user, retErr, !jsonOutput)
					return retErr
				case cryptoMetrics = <-cryptoMetricsChan:
				}

				meta.SnapshotID = snapshotID
				meta.NodeID = cfg.NodeID
				now := time.Now().UTC()
				meta.CompletedAt = &now
				meta.DurationMs = backupMilliseconds(started)
				meta.Status = model.SnapshotStatusCompleted
				meta.StorageURI = storageURI
				recordRetention(meta, storageCfg, retentionUntil)
				meta.RawSizeBytes = cryptoMetrics.RawBytes
				meta.EncryptedSizeBytes = cryptoMetrics.EncryptedBytes
				meta.Sha256Checksum = cryptoMetrics.RawSha256
				meta.EncryptedSha256 = cryptoMetrics.EncryptedSha256
				meta.CalculateTotals()

				warnIfManifestFailed(storageProvider.UploadMetadata(ctx, snapshotID, meta), snapshotID)
				if cfg.ServerURL != "" {
					sendMetadataToServer(ctx, cfg.ServerURL, cfg.ServerToken, meta, !jsonOutput)
				}

				if jsonOutput {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					return enc.Encode(meta)
				}

				fmt.Println("\n✅ Email Backup Completed Successfully!")
				fmt.Printf("   Snapshot ID:     %s\n", meta.SnapshotID)
				fmt.Printf("   Emails Saved:    %d\n", meta.TotalItems)
				fmt.Printf("   Mailbox Folders: %d\n", meta.TotalContainers)
				fmt.Printf("   Raw Size:        %.2f MB\n", float64(meta.RawSizeBytes)/(1024*1024))
				fmt.Printf("   Encrypted Size:  %.2f MB (%.1fx compression)\n", float64(meta.EncryptedSizeBytes)/(1024*1024), cryptoMetrics.CompressionRatio)
				printRetentionLine(storageCfg, meta.WORMRetentionUntil)
				fmt.Printf("   Storage URI:     %s\n", meta.StorageURI)
				return nil
			}

			// ================================================================
			// Surface 3: PostgreSQL Databases (Default)
			// ================================================================
			if dbURL != "" {
				resolvedDB, err := ResolveSecretRef("database-url", dbURL)
				if err != nil {
					return err
				}
				cfg.DatabaseURL = resolvedDB
			}

			if err := cfg.ValidateForBackup(); err != nil {
				return err
			}

			engine := dump.EngineType(engineStr)
			dbSurface := dump.SurfaceTypeOfURL(cfg.DatabaseURL)

			if !jsonOutput {
				fmt.Printf("🛡️  SafeGrd Backup Started: %s\n", snapshotID)
				fmt.Printf("   Recipient Key:   %s\n", cfg.Encryption.PublicKey[:16]+"...")
				fmt.Printf("   Target Storage:  %s (%s)\n", storageCfg.Type, wormLabel(storageCfg))
			}

			dumpReader, dumpWriter := io.Pipe()
			cipherReader, cipherWriter := io.Pipe()

			dumper := dump.NewDumper(engine, cfg.DatabaseURL)

			dumpMetaChan := make(chan *model.SnapshotMetadata, 1)
			dumpErrChan := make(chan error, 1)

			go func() {
				meta, err := dumper.Dump(ctx, "", dumpWriter)
				if err != nil {
					_ = dumpWriter.CloseWithError(err)
					dumpErrChan <- err
					return
				}
				_ = dumpWriter.Close()
				dumpMetaChan <- meta
			}()

			cryptoMetricsChan := make(chan *crypto.StreamMetrics, 1)
			cryptoErrChan := make(chan error, 1)

			go func() {
				metrics, err := crypto.EncryptStream(dumpReader, cipherWriter, cfg.Encryption.PublicKey)
				if err != nil {
					_ = cipherWriter.CloseWithError(err)
					cryptoErrChan <- err
					return
				}
				_ = cipherWriter.Close()
				cryptoMetricsChan <- metrics
			}()

			storageURI, err := storageProvider.UploadSnapshot(ctx, snapshotID, cipherReader, -1, retentionUntil)
			if err != nil {
				retErr := fmt.Errorf("upload to immutable storage failed: %w", err)
				reportBackupFailure(ctx, cfg, snapshotID, dbSurface, string(dbSurface), retErr, !jsonOutput)
				return retErr
			}

			var dumpMeta *model.SnapshotMetadata
			select {
			case err := <-dumpErrChan:
				retErr := fmt.Errorf("database dump failed: %w", err)
				reportBackupFailure(ctx, cfg, snapshotID, dbSurface, string(dbSurface), retErr, !jsonOutput)
				return retErr
			case dumpMeta = <-dumpMetaChan:
			}

			var cryptoMetrics *crypto.StreamMetrics
			select {
			case err := <-cryptoErrChan:
				retErr := fmt.Errorf("streaming encryption failed: %w", err)
				reportBackupFailure(ctx, cfg, snapshotID, dbSurface, string(dbSurface), retErr, !jsonOutput)
				return retErr
			case cryptoMetrics = <-cryptoMetricsChan:
			}

			dumpMeta.SnapshotID = snapshotID
			dumpMeta.NodeID = cfg.NodeID
			now := time.Now().UTC()
			if dumpMeta.CreatedAt.IsZero() {
				dumpMeta.CreatedAt = now
			}
			dumpMeta.CompletedAt = &now
			dumpMeta.Status = model.SnapshotStatusCompleted
			dumpMeta.StorageURI = storageURI
			recordRetention(dumpMeta, storageCfg, retentionUntil)
			dumpMeta.RawSizeBytes = cryptoMetrics.RawBytes
			dumpMeta.EncryptedSizeBytes = cryptoMetrics.EncryptedBytes
			dumpMeta.Sha256Checksum = cryptoMetrics.RawSha256
			dumpMeta.EncryptedSha256 = cryptoMetrics.EncryptedSha256
			dumpMeta.CalculateTotals()

			warnIfManifestFailed(storageProvider.UploadMetadata(ctx, snapshotID, dumpMeta), snapshotID)

			if cfg.ServerURL != "" {
				sendMetadataToServer(ctx, cfg.ServerURL, cfg.ServerToken, dumpMeta, !jsonOutput)
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(dumpMeta)
			}

			fmt.Println("\n✅ Backup Completed Successfully!")
			fmt.Printf("   Snapshot ID:     %s\n", dumpMeta.SnapshotID)
			fmt.Printf("   Tables Dumped:   %d\n", dumpMeta.TotalTables)
			fmt.Printf("   Total Rows:      %d\n", dumpMeta.TotalRows)
			fmt.Printf("   Schema:          %s\n", schemaSourceLabel(dumpMeta.SchemaSource))
			fmt.Printf("   Raw Size:        %.2f MB\n", float64(dumpMeta.RawSizeBytes)/(1024*1024))
			fmt.Printf("   Encrypted Size:  %.2f MB (%.1fx compression)\n", float64(dumpMeta.EncryptedSizeBytes)/(1024*1024), cryptoMetrics.CompressionRatio)
			printRetentionLine(storageCfg, dumpMeta.WORMRetentionUntil)
			fmt.Printf("   SHA-256 Digest:  %s\n", dumpMeta.Sha256Checksum)
			fmt.Printf("   Storage URI:     %s\n", dumpMeta.StorageURI)

			if dumpMeta.IsPoisonPillFrozen {
				fmt.Println("\n🚨 WARNING: Threat Shield detected an abnormal schema or volume drop!")
				fmt.Println("   This snapshot is marked anomalous. Restore from the one before it; SafeGrd never prunes a snapshot.")
			}

			return nil
		},
	}

	// Flags for PostgreSQL
	cmd.Flags().StringVar(&dbURL, "database-url", "", "Database connection string: postgres://…, mysql://… (mariadb://…), mongodb://… or sqlite:///path/to/file.db")
	cmd.Flags().StringVar(&engineStr, "engine", "native", "Accepted for old scripts and ignored: there is one Postgres backup path")
	_ = cmd.Flags().MarkDeprecated("engine", "the schema comes from pg_dump and the rows from COPY; the flag is ignored")

	// Flags for Files
	cmd.Flags().StringVar(&filesPath, "files", "", "Path to directory tree for file-based backup")
	cmd.Flags().StringSliceVar(&excludes, "exclude", nil, "Glob patterns to exclude from file backup (e.g. '*.tmp,node_modules/*')")

	// Flags for Email
	cmd.Flags().BoolVar(&emailMode, "email", false, "Execute Universal IMAP email backup")
	cmd.Flags().StringVar(&emailHost, "email-host", "", "IMAP server hostname (e.g. imap.gmail.com)")
	cmd.Flags().IntVar(&emailPort, "email-port", 993, "IMAP server TLS port (default 993)")
	cmd.Flags().StringVar(&emailCAFile, "email-ca-file", "",
		"PEM bundle of extra CAs to trust for the IMAP server, for a self-hosted mailbox "+
			"behind a private CA (or $SAFEGRD_EMAIL_CA_FILE). Added to the system roots, "+
			"never instead of them; there is deliberately no way to skip verification")
	cmd.Flags().StringVar(&emailUser, "email-user", "", "Email account username/address")
	cmd.Flags().StringVar(&emailPass, "email-password", "", "Email account app password (prefer setting SAFEGRD_EMAIL_PASSWORD env var)")
	cmd.Flags().StringSliceVar(&emailFolders, "email-folders", nil, "Specific mailbox folders to back up (default: all except spam/trash)")

	// Global backup flags
	cmd.Flags().IntVar(&retentionDays, "retention-days", 0, "WORM immutability period in days")
	cmd.Flags().StringVar(&tag, "tag", "", "Optional custom snapshot tag prefix")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output result as JSON")

	// Storage routing override flags
	cmd.Flags().StringVar(&storageBucket, "bucket", "", "Storage bucket name (overrides project sink and config)")
	cmd.Flags().StringVar(&storagePrefix, "prefix", "", "Storage key prefix (overrides project sink and config)")
	cmd.Flags().StringVar(&storageRegion, "region", "", "Storage region (overrides project sink and config)")
	cmd.Flags().StringVar(&storageEndpoint, "endpoint", "", "Storage endpoint URL (overrides project sink and config)")

	return cmd
}

// sendMetadataToServer reports a finished backup to the remote server, and says
// so when it cannot.
// The backup itself is already on disk by the time this runs, and a remote
// server that is unreachable must not cause the backup command to report failure.
// Failures to deliver metadata are reported as warnings to stderr so that
// the operator is aware the server has not received the snapshot record.
func sendMetadataToServer(ctx context.Context, serverURL, token string, meta *model.SnapshotMetadata, verbose bool) {
	warn := func(format string, args ...any) {
		// Printed even when quiet. --json suppresses the decorative lines
		// above; it must not suppress "the remote server does not know about
		// this backup", so this goes to stderr and stays out of the JSON on
		// stdout.
		fmt.Fprintf(os.Stderr, "   Remote Server:   "+format+"\n", args...)
	}

	if serverURL == "" {
		if verbose {
			fmt.Printf("   Remote Server:   Not configured (metadata stored locally in WORM manifest)\n")
		}
		return
	}
	// No token: a standalone host, which the CLI supports without an
	// account. That is a choice, not a failure, and not a reason to contact
	// the default remote server. The token is the reliable signal.
	// `init` writes a node_id with no enrolment at all, so having a
	// node_id is not alone proof of enrolment.
	if token == "" {
		warn("not reported: no server_token in this config, so this host is standalone.\n" +
			"                    The backup is in your bucket. Run 'safegrd enroll' to report to the console.")
		return
	}
	if meta.NodeID == "" {
		warn("NOT RECORDED: this config has no node_id, so the report names no node.\n" +
			"                    The backup itself is fine. Add node_id, or re-run 'safegrd enroll'.")
		return
	}

	body, err := json.Marshal(meta)
	if err != nil {
		warn("NOT RECORDED: could not encode the snapshot metadata: %v", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", serverURL+"/api/v1/snapshots", bytes.NewReader(body))
	if err != nil {
		warn("NOT RECORDED: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// The one genuinely benign case: the network is down, the manifest is
		// beside the snapshot, and a later run or the agent reconciles.
		if verbose {
			fmt.Printf("   Remote Server:   Offline (metadata stored locally in WORM manifest)\n")
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		var serverMeta model.SnapshotMetadata
		_ = json.NewDecoder(resp.Body).Decode(&serverMeta)
		meta.IsPoisonPillFrozen = serverMeta.IsPoisonPillFrozen
		if verbose {
			fmt.Printf("   Remote Server:   Synced with %s\n", serverURL)
		}
		return
	}

	// A refusal is not an outage. It means this host is misconfigured or its
	// token is no longer good, and it will keep happening every night until
	// somebody is told.
	var errBody struct {
		Error string `json:"error"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	_ = json.Unmarshal(raw, &errBody)
	detail := errBody.Error
	if detail == "" {
		detail = strings.TrimSpace(string(raw))
	}
	warn("NOT RECORDED: %s rejected the report: HTTP %d %s\n"+
		"                    The backup itself is fine and the manifest is beside it, but the\n"+
		"                    console will show this node as never having backed up.",
		serverURL, resp.StatusCode, detail)
}

func reportBackupFailure(ctx context.Context, cfg *config.CLIConfig, snapshotID string, surfaceType model.SurfaceType, dbName string, backupErr error, verbose bool) {
	if cfg.ServerURL == "" || snapshotID == "" {
		return
	}
	now := time.Now().UTC()
	meta := &model.SnapshotMetadata{
		SnapshotID:   snapshotID,
		NodeID:       cfg.NodeID,
		DatabaseName: dbName,
		SurfaceType:  surfaceType,
		Status:       model.SnapshotStatusFailed,
		ErrorMessage: backupErr.Error(),
		CreatedAt:    now,
		CompletedAt:  &now,
	}
	sendMetadataToServer(ctx, cfg.ServerURL, cfg.ServerToken, meta, verbose)
}

// emailTLSConfig builds the TLS settings for an IMAP connection.
//
// The default is the strict one: system roots, TLS 1.2 floor, server name
// verified. caFile adds trust anchors on top of the system pool for a
// self-hosted mailbox behind a private CA (the standard pattern
// to reach one without weakening anything).
//
// There is no insecure-skip option and there should not be one. The password
// crosses this connection, so a flag that turns verification off would be a flag
// that hands the mailbox to anyone on the path, and it would inevitably be
// pasted into a production config by someone in a hurry. If a certificate cannot
// be verified, the right answer is to trust its CA explicitly, which is what
// this is.
func emailTLSConfig(host, caFile string) (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
	if caFile == "" {
		return cfg, nil
	}

	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("could not read the IMAP CA bundle %s: %w", caFile, err)
	}
	// Start from the system pool rather than an empty one: a private CA for the
	// mail server should not stop every other certificate on the host verifying.
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in the IMAP CA bundle %s: "+
			"it must be PEM-encoded", caFile)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// warnSkipped prints what a file backup left out: FIFOs, sockets and device
// nodes, which are not data and which broke the backup when they were read.
func warnSkipped(skipped []string) {
	if len(skipped) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "[!] %d entries are not files, directories or symlinks and were not backed up:\n", len(skipped))
	for i, s := range skipped {
		if i == 20 {
			fmt.Fprintf(os.Stderr, "    ... and %d more\n", len(skipped)-20)
			break
		}
		fmt.Fprintf(os.Stderr, "    %s\n", s)
	}
}

// backupMilliseconds is how long a backup took since started, rounded up to
// whole milliseconds. A one-file tree finishes in microseconds, and a manifest
// that says it took 0 ms reads as a backup that never ran. time.Since reads the
// monotonic clock, so a host clock stepped mid-backup cannot make it 0 either;
// the completed_at stamp beside it is wall time and would.
// Two readings of the clock can be equal on a coarse one (darwin), so only a
// start in the future, which cannot be a backup that ran, reads as 0.
func backupMilliseconds(started time.Time) int64 {
	d := time.Since(started)
	if d < 0 {
		return 0
	}
	if d == 0 {
		return 1
	}
	return int64((d + time.Millisecond - 1) / time.Millisecond)
}
