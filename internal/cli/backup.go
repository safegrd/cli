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
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/policy"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

func newBackupCmd() *cobra.Command {
	var (
		dbURL         string
		engineStr     string
		retentionDays int
		tag           string
		jsonOutput    bool
		surfaceID     string

		// File surface flags
		filesPath string
		excludes  []string
		fileFmt   string
		newEpoch  bool
		// serverCache: see repoDBParams.ServerCache.
		serverCache bool
		changeLog   bool
		rescan      bool
		oneFS       bool

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
		s3AccessKey     string
		s3SecretKey     string
	)

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Take an encrypted, locked backup of a database, directory or mailbox",
		Long: `Streams a backup, compresses it with zstd, encrypts it on this host with age,
and writes it to locked (WORM) storage. The unencrypted data is never written to disk
and never leaves this host.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if surfaceID != "" {
				for _, f := range []string{"database-url", "files", "email", "json", "tag", "retention-days", "s3-bucket", "s3-prefix", "s3-region", "s3-endpoint", "s3-access-key", "s3-secret-key", "format", "one-filesystem"} {
					if cmd.Flags().Changed(f) {
						return fmt.Errorf("--surface backs up the surface as the config defines it; leave out --%s", f)
					}
				}
				return backupNamedSurface(ctx, cfg, surfaceID, newEpoch, rescan)
			}

			// Resolve storage according to the routing precedence rule:
			// CLI Flags > Remote Server Project Sink > Local Config Fallback
			storageCfg, routeErr := routeStorage(ctx, cfg, storageBucket, storagePrefix, storageRegion, storageEndpoint, !jsonOutput, true)
			if routeErr != nil {
				return routeErr
			}
			// Applied before resolveRuntimeCredentials, which fills only
			// what is still empty, so the flags win over a held secret.
			if s3AccessKey != "" {
				storageCfg.AccessKeyID = s3AccessKey
			}
			if s3SecretKey != "" {
				resolved, err := ResolveSecretRef("s3-secret-key", s3SecretKey)
				if err != nil {
					return err
				}
				storageCfg.SecretAccessKey = resolved
			}
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
					if strings.Contains(err.Error(), "ObjectLockConfigurationNotFound") {
						return fmt.Errorf("bucket %s has no Object Lock, so a backup there could be deleted. "+
							"Use a bucket created with Object Lock, or, for a provider that has none, set "+
							"storage.worm_mode: NONE in the config to back up without a lock. Nothing was written", storageCfg.Bucket)
					}
					return fmt.Errorf("could not check Object Lock on bucket %s: %w. Nothing was written", storageCfg.Bucket, err)
				}
			}

			retentionUntil := time.Now().Add(time.Duration(storageCfg.RetentionDays) * 24 * time.Hour)

			snapshotID := fmt.Sprintf("snap-%s-%s", time.Now().UTC().Format("20060102-150405"), uuid.New().String()[:6])
			if tag != "" {
				snapshotID = fmt.Sprintf("snap-%s-%s", tag, uuid.New().String()[:6])
				if err := storage.ValidateSnapshotID(snapshotID); err != nil {
					return fmt.Errorf("--tag %q: %w", tag, err)
				}
			}

			// ================================================================
			// Surface 1: File Trees & Directories
			// ================================================================
			if filesPath != "" {
				if err := cfg.ValidateForFileBackup(); err != nil {
					return err
				}
				ff, err := fileFormat(fileFmt)
				if err != nil {
					return err
				}
				if ff == formatRepo {
					var oneFSFlag *bool
					if cmd.Flags().Changed("one-filesystem") {
						oneFSFlag = &oneFS
					}
					out := io.Writer(os.Stdout)
					if jsonOutput {
						out = os.Stderr
					}
					node := storageCfg.NodeID
					if node == "" {
						node = cfg.NodeID
						storageCfg.NodeID = node
					}
					meta, _, err := runRepoBackup(ctx, repoParams{
						SurfaceID: repoSurfaceID([]string{filesPath}), Roots: []string{filesPath}, Excludes: excludes, OneFS: oneFSFlag,
						StorageCfg: storageCfg, NodeID: cfg.NodeID, Recipient: cfg.Encryption.PublicKey,
						Retention: policy.Retention{Days: storageCfg.RetentionDays}, Tier: format.TierBase, Planned: retentionUntil,
						NewEpoch: newEpoch, Rescan: rescan, SnapshotID: snapshotID, StateDir: resolveStateDir("", cfg), Out: out,
					})
					if err != nil {
						retErr := fmt.Errorf("file backup failed: %w", err)
						reportBackupFailure(ctx, cfg, snapshotID, model.SurfaceTypeFiles, "", retErr, !jsonOutput)
						return retErr
					}
					if cfg.ServerURL != "" {
						sendMetadataToServer(ctx, cfg.ServerURL, cfg.ServerToken, meta, !jsonOutput)
					}
					if jsonOutput {
						enc := json.NewEncoder(os.Stdout)
						enc.SetIndent("", "  ")
						return enc.Encode(meta)
					}
					// The labelled line scripts and agents read, as every
					// other backup prints it.
					fmt.Printf("   Snapshot ID:     %s\n", meta.SnapshotID)
					return nil
				}
				if newEpoch || rescan || cmd.Flags().Changed("one-filesystem") {
					return fmt.Errorf("--new-epoch, --rescan and --one-filesystem apply to --format repo only")
				}

				if !jsonOutput {
					fmt.Printf("Backing up %s as snapshot %s\n", filesPath, snapshotID)
					fmt.Printf("   Recipient Key:   %s\n", crypto.Fingerprint(cfg.Encryption.PublicKey))
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
					retErr := stageErr(model.BackupReasonSource, fmt.Errorf("file collection failed: %w", err))
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
					retErr := uploadErr(err, cryptoErrChan, "reading the surface failed")
					reportBackupFailure(ctx, cfg, snapshotID, model.SurfaceTypeFiles, "", retErr, !jsonOutput)
					return retErr
				}

				var cryptoMetrics *crypto.StreamMetrics
				select {
				case err := <-cryptoErrChan:
					retErr := stageErr(model.BackupReasonSource, fmt.Errorf("streaming encryption failed: %w", err))
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

				fmt.Printf("\nBacked up %d files\n", meta.TotalItems)
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
					return fmt.Errorf("--email needs a login: pass --email-user (or set SAFEGRD_EMAIL_USER) and set SAFEGRD_EMAIL_PASSWORD")
				}

				if !jsonOutput {
					fmt.Printf("Backing up mailbox %s on %s:%d as snapshot %s\n", user, host, port, snapshotID)
					fmt.Printf("   Recipient Key:   %s\n", crypto.Fingerprint(cfg.Encryption.PublicKey))
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
					retErr := stageErr(model.BackupReasonSource, fmt.Errorf("email collection failed: %w", err))
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
					retErr := uploadErr(err, cryptoErrChan, "reading the surface failed")
					reportBackupFailure(ctx, cfg, snapshotID, model.SurfaceTypeEmail, user, retErr, !jsonOutput)
					return retErr
				}

				var cryptoMetrics *crypto.StreamMetrics
				select {
				case err := <-cryptoErrChan:
					retErr := stageErr(model.BackupReasonSource, fmt.Errorf("streaming encryption failed: %w", err))
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

				fmt.Printf("\nBacked up %d emails\n", meta.TotalItems)
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
			// The flag, or the config's database_url: either may be an env: or
			// file: reference, and `init --database-url env:VAR` writes one to
			// the config. Only the flag used to be resolved, so the reference
			// the docs recommend reached the driver as a literal.
			if dbURL == "" && (strings.HasPrefix(cfg.DatabaseURL, "env:") || strings.HasPrefix(cfg.DatabaseURL, "file:")) {
				dbURL = cfg.DatabaseURL
			}
			if dbURL != "" {
				resolvedDB, err := ResolveSecretRef("database-url", dbURL)
				if err != nil {
					return err
				}
				cfg.DatabaseURL = resolvedDB
			}
			// In memory only, like the resolved secret above.
			var dropped []string
			cfg.DatabaseURL, dropped = cleanPostgresURL(cfg.DatabaseURL)
			sayDroppedURLParams("The database", dropped)
			sayDatabaseTLS("The database", cfg.DatabaseURL)

			if err := cfg.ValidateForBackup(); err != nil {
				return err
			}

			engine := dump.EngineType(engineStr)
			dbSurface := dump.SurfaceTypeOfURL(cfg.DatabaseURL)

			// A PostgreSQL or SQLite database is a run of its repository
			// unless --format tar asks for one archive; MySQL and MongoDB are
			// one archive.
			dbFormat := formatTar
			if repoDatabaseKind(dbSurface) {
				dbFormat = formatRepo
			}
			if cmd.Flags().Changed("format") {
				if dbFormat, err = fileFormat(fileFmt); err != nil {
					return err
				}
			}
			if changeLog && (dbFormat != formatRepo || dbSurface != model.SurfaceTypePostgres) {
				return fmt.Errorf("--change-log applies to a PostgreSQL backup in repo format")
			}
			if dbFormat == formatRepo {
				if rescan {
					return fmt.Errorf("--rescan applies to --files: a database run reads every table")
				}
				out := io.Writer(os.Stdout)
				if jsonOutput {
					out = os.Stderr
				}
				if storageCfg.NodeID == "" {
					storageCfg.NodeID = cfg.NodeID
				}
				meta, _, err := runRepoDatabaseBackup(ctx, repoDBParams{
					SurfaceID: repoDatabaseSurfaceID(cfg.DatabaseURL), DatabaseURL: cfg.DatabaseURL,
					StorageCfg: storageCfg, NodeID: cfg.NodeID, Recipient: cfg.Encryption.PublicKey,
					Retention: policy.Retention{Days: storageCfg.RetentionDays}, Tier: format.TierBase, Planned: retentionUntil,
					NewEpoch: newEpoch, SnapshotID: snapshotID, StateDir: resolveStateDir("", cfg), Out: out,
					ServerCache: serverCache, ChangeLog: changeLog,
				})
				if err != nil {
					retErr := fmt.Errorf("database backup failed: %w", err)
					reportBackupFailure(ctx, cfg, snapshotID, dbSurface, string(dbSurface), retErr, !jsonOutput)
					return retErr
				}
				if cfg.ServerURL != "" {
					sendMetadataToServer(ctx, cfg.ServerURL, cfg.ServerToken, meta, !jsonOutput)
				}
				if jsonOutput {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					return enc.Encode(meta)
				}
				fmt.Printf("   Snapshot ID:     %s\n", meta.SnapshotID)
				fmt.Printf("   Schema:          %s\n", schemaSourceLabel(meta.SchemaSource))
				warnIfThreatShieldFroze(meta)
				return nil
			}
			if rescan || newEpoch {
				return fmt.Errorf("--new-epoch and --rescan apply to --format repo only")
			}

			if !jsonOutput {
				fmt.Printf("Backing up %s as snapshot %s\n", dbSurface, snapshotID)
				fmt.Printf("   Recipient Key:   %s\n", crypto.Fingerprint(cfg.Encryption.PublicKey))
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
				retErr := uploadErr(err, dumpErrChan, "database dump failed")
				reportBackupFailure(ctx, cfg, snapshotID, dbSurface, string(dbSurface), retErr, !jsonOutput)
				return retErr
			}

			var dumpMeta *model.SnapshotMetadata
			select {
			case err := <-dumpErrChan:
				retErr := stageErr(model.BackupReasonSource, fmt.Errorf("database dump failed: %w", err))
				reportBackupFailure(ctx, cfg, snapshotID, dbSurface, string(dbSurface), retErr, !jsonOutput)
				return retErr
			case dumpMeta = <-dumpMetaChan:
			}

			var cryptoMetrics *crypto.StreamMetrics
			select {
			case err := <-cryptoErrChan:
				retErr := stageErr(model.BackupReasonSource, fmt.Errorf("streaming encryption failed: %w", err))
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

			fmt.Printf("\nBacked up %d tables, %d rows\n", dumpMeta.TotalTables, dumpMeta.TotalRows)
			fmt.Printf("   Snapshot ID:     %s\n", dumpMeta.SnapshotID)
			fmt.Printf("   Tables Dumped:   %d\n", dumpMeta.TotalTables)
			fmt.Printf("   Total Rows:      %d\n", dumpMeta.TotalRows)
			fmt.Printf("   Schema:          %s\n", schemaSourceLabel(dumpMeta.SchemaSource))
			fmt.Printf("   Raw Size:        %.2f MB\n", float64(dumpMeta.RawSizeBytes)/(1024*1024))
			fmt.Printf("   Encrypted Size:  %.2f MB (%.1fx compression)\n", float64(dumpMeta.EncryptedSizeBytes)/(1024*1024), cryptoMetrics.CompressionRatio)
			printRetentionLine(storageCfg, dumpMeta.WORMRetentionUntil)
			fmt.Printf("   SHA-256 Digest:  %s\n", dumpMeta.Sha256Checksum)
			fmt.Printf("   Storage URI:     %s\n", dumpMeta.StorageURI)

			warnIfThreatShieldFroze(dumpMeta)
			return nil
		},
	}

	// Flags for PostgreSQL
	cmd.Flags().StringVar(&dbURL, "database-url", "", "Database to back up: postgres://…, mysql://… (mariadb://…), mongodb://… or sqlite:///path/to/file.db, or env:VAR / file:/path")
	cmd.Flags().StringVar(&engineStr, "engine", "native", "Accepted for old scripts and ignored: there is one Postgres backup path")
	_ = cmd.Flags().MarkDeprecated("engine", "the schema comes from pg_dump and the rows from COPY; the flag is ignored")

	// Flags for Files
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Back up this surface from the config's surfaces now, as the daemon would, whatever its schedule")
	cmd.Flags().StringVar(&filesPath, "files", "", "Back up this directory tree")
	cmd.Flags().StringSliceVar(&excludes, "exclude", nil, "Glob patterns to leave out of --files (e.g. '*.tmp,node_modules/*')")
	cmd.Flags().StringVar(&fileFmt, "format", formatRepo, "How the backup is stored: repo (incremental: each run uploads only what changed) or tar (one archive per backup). Repo is the default for --files and a PostgreSQL or SQLite database; MySQL and MongoDB are one archive")
	cmd.Flags().BoolVar(&newEpoch, "new-epoch", false, "With --format repo, or --surface of a repo surface: start a new epoch now, uploading everything once")
	cmd.Flags().BoolVar(&rescan, "rescan", false, "With --format repo, or --surface of a repo surface: read every file, not only those whose size or times changed")
	cmd.Flags().BoolVar(&changeLog, "change-log", false, "With a PostgreSQL repo backup: skip reading tables nothing wrote since the last run. Installs a trigger on each table and a safegrd schema in the database (DROP SCHEMA safegrd CASCADE removes it)")
	cmd.Flags().BoolVar(&serverCache, "server-cache", false, "Keep the repository cache on the remote server between runs, for a run on a machine that does not outlive it")
	_ = cmd.Flags().MarkHidden("server-cache")
	cmd.Flags().BoolVar(&oneFS, "one-filesystem", false, "With --format repo: stay on the root's filesystem (the default when the root is /)")

	// Flags for Email
	cmd.Flags().BoolVar(&emailMode, "email", false, "Back up an IMAP mailbox")
	cmd.Flags().StringVar(&emailHost, "email-host", "", "IMAP server hostname (e.g. imap.gmail.com)")
	cmd.Flags().IntVar(&emailPort, "email-port", 993, "IMAP server TLS port")
	cmd.Flags().StringVar(&emailCAFile, "email-ca-file", "",
		"PEM bundle of extra CAs to trust for the IMAP server, for a self-hosted mailbox "+
			"behind a private CA (or $SAFEGRD_EMAIL_CA_FILE). Added to the system roots, "+
			"never instead of them; there is deliberately no way to skip verification")
	cmd.Flags().StringVar(&emailUser, "email-user", "", "Mailbox username or address (default $SAFEGRD_EMAIL_USER)")
	cmd.Flags().StringVar(&emailPass, "email-password", "", "App password, as env:VAR or file:/path (default $SAFEGRD_EMAIL_PASSWORD)")
	cmd.Flags().StringSliceVar(&emailFolders, "email-folders", nil, "Mailbox folders to back up (default: all except spam and trash)")

	// Global backup flags
	cmd.Flags().IntVar(&retentionDays, "retention-days", 0, "Days this backup is locked (Object Lock retention; default: the config's)")
	cmd.Flags().StringVar(&tag, "tag", "", "Put this tag in the snapshot ID (snap-<tag>-…)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Print the snapshot metadata as JSON on stdout; warnings stay on stderr")

	// Storage routing override flags
	cmd.Flags().StringVar(&storageBucket, "s3-bucket", "", "Write to this S3 bucket instead of the project's or the config's")
	cmd.Flags().StringVar(&storagePrefix, "s3-prefix", "", "Key prefix in the S3 bucket")
	cmd.Flags().StringVar(&storageRegion, "s3-region", "", "S3 region")
	cmd.Flags().StringVar(&storageEndpoint, "s3-endpoint", "", "S3 endpoint, for MinIO, R2 or another S3-compatible store")
	cmd.Flags().StringVar(&s3AccessKey, "s3-access-key", "", "S3 access key ID")
	cmd.Flags().StringVar(&s3SecretKey, "s3-secret-key", "", "S3 secret access key, as env:VAR or file:/path")

	return cmd
}

// warnIfThreatShieldFroze says so when the remote server's Threat Shield
// marked the snapshot just reported anomalous.
func warnIfThreatShieldFroze(meta *model.SnapshotMetadata) {
	if meta.IsPoisonPillFrozen {
		fmt.Fprintln(os.Stderr, "\nWarning: Threat Shield marked this snapshot anomalous: the schema or row counts dropped sharply.")
		fmt.Fprintln(os.Stderr, "   Restore from the snapshot before it. Prune keeps that one as the last known good snapshot.")
	}
}

// sendMetadataToServer reports a finished backup to the remote server, and says
// so when it cannot.
// The backup itself is already on disk by the time this runs, and a remote
// server that is unreachable must not cause the backup command to report failure.
// Failures to deliver metadata are reported as warnings to stderr so that
// the operator is aware the server has not received the snapshot record.
//
// It returns why the remote server does not have the record, or "" when it
// does or was never meant to (no server configured, or a standalone host).
// The daemon carries that reason in its last error, which its heartbeat
// reports, because a warning on the host's stderr is seen by nobody when the
// daemon runs as a service.
func sendMetadataToServer(ctx context.Context, serverURL, token string, meta *model.SnapshotMetadata, verbose bool) string {
	reason, _ := deliverSnapshotRecord(ctx, serverURL, token, meta, verbose)
	return reason
}

// deliverSnapshotRecord is sendMetadataToServer, and also says whether a
// failure is worth sending again: the remote server could not be reached, or
// answered 5xx or 429. A refusal (401, 402, 403, 400) will be refused again,
// so it is not. The daemon keeps retryable records and sends them once the
// remote server answers (unsent.go).
func deliverSnapshotRecord(ctx context.Context, serverURL, token string, meta *model.SnapshotMetadata, verbose bool) (reason string, retry bool) {
	warn := func(format string, args ...any) {
		// Printed even when quiet. --json suppresses the decorative lines
		// above; it must not suppress "the remote server does not know about
		// this backup", so this goes to stderr and stays out of the JSON on
		// stdout.
		fmt.Fprintf(os.Stderr, "   Remote server:   "+format+"\n", args...)
	}

	if serverURL == "" {
		if verbose {
			fmt.Printf("   Remote server:   not configured (the manifest is stored beside the backup)\n")
		}
		return "", false
	}
	// No token: a standalone host, which the CLI supports without an
	// account. That is a choice, not a failure, and not a reason to contact
	// the default remote server. The token is the reliable signal.
	// `init` writes a node_id with no enrolment at all, so having a
	// node_id is not alone proof of enrolment.
	if token == "" {
		warn("not reported: no server_token in this config, so this host is standalone.\n" +
			"                    The backup is stored; run 'safegrd enroll' to report it to the console.")
		return "", false
	}
	if meta.NodeID == "" {
		warn("NOT RECORDED: this config has no node_id, so the report names no node.\n" +
			"                    The backup itself is fine. Add node_id, or re-run 'safegrd enroll'.")
		return "this config has no node_id", false
	}

	body, err := json.Marshal(meta)
	if err != nil {
		warn("NOT RECORDED: could not encode the snapshot metadata: %v", err)
		return "could not encode the snapshot metadata: " + err.Error(), false
	}

	req, err := http.NewRequestWithContext(ctx, "POST", serverURL+"/api/v1/snapshots", bytes.NewReader(body))
	if err != nil {
		warn("NOT RECORDED: %v", err)
		return err.Error(), false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", UserAgent())

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// The network is down or the remote server is. The backup is fine and
		// its manifest is beside it, but the console does not know about it
		// until the record is sent, so it is said even without verbose. The
		// daemon sends it again; a one-shot backup says how to see it.
		warn("NOT RECORDED: %s could not be reached (%v).\n"+
			"                    The backup itself is fine and 'safegrd list' shows it. The daemon sends the\n"+
			"                    records of its own backups again once the remote server answers.",
			serverURL, err)
		return "the remote server could not be reached: " + err.Error(), true
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		var serverMeta model.SnapshotMetadata
		if err := json.NewDecoder(resp.Body).Decode(&serverMeta); err != nil {
			// Recorded, but the answer could not be read, so the two flags
			// below are unknown and their warnings would not print.
			warn("the remote server recorded this backup but its answer could not be read (%v); "+
				"check the console for this snapshot's standing.", err)
		}
		meta.IsPoisonPillFrozen = serverMeta.IsPoisonPillFrozen
		meta.OutsideProjectStorage = serverMeta.OutsideProjectStorage
		if verbose {
			fmt.Printf("   Remote server:   recorded by %s\n", serverURL)
		}
		// Recorded, but not where the project keeps its backups: the console
		// shows the project's storage, and this backup is somewhere else.
		if serverMeta.OutsideProjectStorage {
			warn("OUTSIDE THE PROJECT'S STORAGE: this backup went to %s, which is not the storage\n"+
				"                    its project uses. It is recorded, and a restore has to read it from there.\n"+
				"                    Point this host at the project's storage, or change the project's.", meta.StorageURI)
		}
		return "", false
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
	retry = resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
	return fmt.Sprintf("the remote server rejected the report: HTTP %d %s", resp.StatusCode, detail), retry
}

func reportBackupFailure(ctx context.Context, cfg *config.CLIConfig, snapshotID string, surfaceType model.SurfaceType, dbName string, backupErr error, verbose bool) {
	if cfg.ServerURL == "" || snapshotID == "" {
		return
	}
	now := time.Now().UTC()
	meta := &model.SnapshotMetadata{
		SnapshotID:    snapshotID,
		NodeID:        cfg.NodeID,
		DatabaseName:  dbName,
		SurfaceType:   surfaceType,
		Status:        model.SnapshotStatusFailed,
		ErrorMessage:  backupErr.Error(),
		FailureReason: backupReasonOf(backupErr),
		CreatedAt:     now,
		CompletedAt:   &now,
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
	fmt.Fprintf(os.Stderr, "Warning: %d entries are not files, directories or symlinks and were not backed up:\n", len(skipped))
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
