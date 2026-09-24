package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/runner"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/spf13/cobra"
)

func newRestoreCmd() *cobra.Command {
	var (
		snapshotID string
		targetURL  string
		targetDir  string
		engineStr  string
		keyPath    string
		privKey    string
	)

	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore an encrypted snapshot into a PostgreSQL target or destination directory",
		Long: `Downloads encrypted ciphertext from immutable WORM storage, decrypts client-side
using the private key, decompresses stream, and restores to PostgreSQL or extracts to disk.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if snapshotID == "" {
				return fmt.Errorf("--snapshot flag is required")
			}
			if targetURL == "" && targetDir == "" {
				return fmt.Errorf("either --target (for PostgreSQL database) or --target-dir (for files or email) is required")
			}

			if targetURL != "" {
				resolvedTarget, err := ResolveSecretRef("target", targetURL)
				if err != nil {
					return err
				}
				targetURL = resolvedTarget
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

			// Last resort: SafeGrd may hold this organization's identity.
			// Only reached when the host has no key of its own, and
			// the result is never written to key_path — it opens this archive
			// and then goes away. A customer-held org answers 404 and the
			// error below stands.
			if resolvedKey == "" {
				resolvedKey = resolveManagedIdentity(ctx, cfg, true)
			}

			if resolvedKey == "" {
				return fmt.Errorf("decryption key required: specify --private-key or configure ~/.safegrd/keys/agent.key")
			}

			// Routed and credentialed exactly as backup does, because a node
			// enrolled under Journey A has no bucket or sink secret locally
			// either — restoring from a centrally-configured sink has to work
			// or the journey proves nothing.
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
				return fmt.Errorf("storage initialization failed: %w", err)
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

			// Fetch metadata to detect surface type and checksum
			meta, _ := storageProvider.DownloadMetadata(ctx, snapshotID)
			surface := model.SurfaceTypePostgres
			if meta != nil && meta.SurfaceType != "" {
				surface = meta.SurfaceType
			} else if targetDir != "" && targetURL == "" {
				surface = model.SurfaceTypeFiles
			}

			fmt.Printf("🛡️  SafeGrd Emergency Restore Initiated\n")
			fmt.Printf("   Snapshot ID:    %s\n", snapshotID)
			fmt.Printf("   Surface:        %s\n", surface)

			if (surface == model.SurfaceTypeFiles || surface == model.SurfaceTypeEmail) && targetDir == "" {
				return fmt.Errorf("snapshot %s is a %s snapshot; specify --target-dir to restore", snapshotID, surface)
			}
			if surface.IsDatabase() && targetURL == "" {
				return fmt.Errorf("snapshot %s is a postgres database snapshot; specify --target database connection URL", snapshotID)
			}

			engine := dump.EngineType(engineStr)

			if surface.IsDatabase() && dump.SurfaceTypeOfURL(targetURL) != surface && !(surface == "" && dump.SurfaceTypeOfURL(targetURL) == model.SurfaceTypePostgres) {
				return fmt.Errorf("snapshot %s is a %s snapshot; --target must be a %s database", snapshotID, surface, surface)
			}
			if surface.IsDatabase() {
				fmt.Printf("   Target DB:      %s\n", dump.RedactURL(targetURL))
				if meta != nil {
					fmt.Printf("   Schema:         %s\n", schemaSourceLabel(meta.SchemaSource))
				}
			} else {
				fmt.Printf("   Target Dir:     %s\n", targetDir)
			}

			startTime := time.Now()

			// 1. Fetch encrypted stream from storage
			cipherStream, err := storageProvider.DownloadSnapshot(ctx, snapshotID)
			if err != nil {
				return fmt.Errorf("failed downloading snapshot from storage: %w", err)
			}
			defer cipherStream.Close()

			// 2. Setup streaming decryption pipe
			plainReader, plainWriter := io.Pipe()

			decryptErrChan := make(chan error, 1)
			var decMetrics *crypto.StreamMetrics
			go func() {
				metrics, err := crypto.DecryptStream(cipherStream, plainWriter, resolvedKey)
				decMetrics = metrics
				if err != nil {
					_ = plainWriter.CloseWithError(err)
					decryptErrChan <- err
					return
				}
				_ = plainWriter.Close()
				decryptErrChan <- nil
			}()

			digestChecked := false
			var (
				pgMeta   *model.SnapshotMetadata
				fileRes  *dump.FileExtractionResult
				emailRes *dump.EmailExtractionResult
			)

			switch surface {
			case model.SurfaceTypeFiles:
				fileRestorer := dump.NewFileRestorer()
				fileRes, err = fileRestorer.ExtractArchive(ctx, plainReader, targetDir)
				if err != nil {
					return fmt.Errorf("file extraction failed: %w", err)
				}
			case model.SurfaceTypeEmail:
				emailRestorer := dump.NewEmailRestorer()
				emailRes, err = emailRestorer.ExtractEmailArchive(ctx, plainReader, targetDir)
				if err != nil {
					return fmt.Errorf("email extraction failed: %w", err)
				}
			default:
				restorer := dump.NewRestorer(engine, targetURL)
				// A Postgres restore is one transaction, so it can wait for the
				// digest before committing: a snapshot that fails the check is
				// rolled back and never becomes a database anyone uses.
				if native, ok := restorer.(*dump.NativeRestorer); ok {
					native.BeforeCommit = func() error {
						_, _ = io.Copy(io.Discard, plainReader)
						if err := <-decryptErrChan; err != nil {
							return fmt.Errorf("stream decryption error (tampered snapshot or invalid key): %w", err)
						}
						digestChecked = true
						return checkRestoreDigest(ctx, meta, snapshotID, decMetrics)
					}
				}
				pgMeta, err = restorer.Restore(ctx, plainReader)
				if err != nil {
					return fmt.Errorf("target database restore failed: %w", err)
				}
			}

			if !digestChecked {
				if err := <-decryptErrChan; err != nil {
					return fmt.Errorf("stream decryption error (tampered snapshot or invalid key): %w", err)
				}
				if err := checkRestoreDigest(ctx, meta, snapshotID, decMetrics); err != nil {
					return err
				}
			}

			elapsed := time.Since(startTime)

			fmt.Println("\n✅ Restore Completed Successfully!")
			fmt.Printf("   Duration:       %s\n", elapsed.Round(time.Millisecond))
			switch surface {
			case model.SurfaceTypeFiles:
				if fileRes != nil {
					// "Files" means what backup and the attestation mean by it:
					// regular files and symlinks together. Restore used to count
					// only regular files, so a tree with a link read 6 at backup
					// and 5 here.
					files := fileRes.FilesExtracted + int64(fileRes.SymlinksExtracted)
					if fileRes.SymlinksExtracted > 0 {
						fmt.Printf("   Files:          %d (%d of them symlinks)\n", files, fileRes.SymlinksExtracted)
					} else {
						fmt.Printf("   Files:          %d\n", files)
					}
					fmt.Printf("   Directories:    %d\n", fileRes.DirectoriesExtracted)
					fmt.Printf("   Bytes Written:  %d\n", fileRes.TotalBytesWritten)
				}
				fmt.Printf("   Destination:    %s\n", targetDir)
				if fileRes != nil {
					printFileRestoreLimits(fileRes)
				}
			case model.SurfaceTypeEmail:
				if emailRes != nil {
					fmt.Printf("   Emails:         %d\n", emailRes.EmailsExtracted)
					fmt.Printf("   Folders:        %d\n", emailRes.DirectoriesExtracted)
					fmt.Printf("   Bytes Written:  %d\n", emailRes.TotalBytesWritten)
				}
				fmt.Printf("   Destination:    %s\n", targetDir)
			default:
				if pgMeta != nil {
					fmt.Printf("   Tables:         %d\n", pgMeta.TotalTables)
					fmt.Printf("   Total Rows:     %d\n", pgMeta.TotalRows)
				}
				fmt.Println("   Target state is verified and ready for traffic.")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&snapshotID, "snapshot", "", "Snapshot ID to restore (required)")
	cmd.Flags().StringVar(&targetURL, "target", "", "Target database URL, postgres://… or mysql://… (an empty database)")
	cmd.Flags().StringVar(&targetDir, "target-dir", "", "Target directory path to extract files or emails into")
	cmd.Flags().StringVar(&engineStr, "engine", "native", "Accepted for old scripts and ignored: there is one Postgres restore path")
	_ = cmd.Flags().MarkDeprecated("engine", "there is one Postgres restore path; the flag is ignored")
	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to Age private identity file")
	cmd.Flags().StringVar(&privKey, "private-key", "", "Age private identity key string (AGE-SECRET-KEY-1...)")

	return cmd
}

// printFileRestoreLimits says what a file restore did not bring back. A
// restore that quietly loses metadata is the thing this product exists to be
// the opposite of, so it is printed every time rather than left to the docs.
func printFileRestoreLimits(res *dump.FileExtractionResult) {
	if res.OwnershipRestored {
		fmt.Printf("   Ownership:      restored from the sealed manifest\n")
	} else if res.OwnershipNote != "" {
		fmt.Printf("   Ownership:      not restored — %s\n", res.OwnershipNote)
	}
	fmt.Printf("   Not preserved:  hard links (each comes back as its own copy), extended\n" +
		"                   attributes and ACLs, setuid/setgid bits, and sparse regions\n" +
		"                   (written out in full). See safegrd.dev/docs/surfaces.\n")
	if len(res.Skipped) > 0 {
		fmt.Fprintf(os.Stderr, "\n[!] %d archive entries were not restored, because this restore does not create them:\n", len(res.Skipped))
		for _, s := range res.Skipped {
			fmt.Fprintf(os.Stderr, "    %s\n", s)
		}
	}
}

// schemaSourceLabel says how a Postgres snapshot's schema was captured.
func schemaSourceLabel(source string) string {
	switch {
	case strings.HasPrefix(source, "pg_dump "), strings.HasPrefix(source, "mysqldump"), strings.HasPrefix(source, "mariadb-dump"), strings.HasPrefix(source, "mongodump"):
		return source
	case source == dump.SchemaSourceNative:
		return "re-derived without pg_dump (no foreign keys, views, triggers or enum types)"
	default:
		return "taken before SafeGrd used pg_dump (lossy; take a new backup)"
	}
}

// checkRestoreDigest holds a restored stream to the digest recorded at backup
// time: the remote server's record when it can be asked, the sidecar when not.
func checkRestoreDigest(ctx context.Context, meta *model.SnapshotMetadata, snapshotID string, decMetrics *crypto.StreamMetrics) error {
	// The sidecar is written by whoever can write the bucket; the control
	// plane's record is not, so it wins when it can be asked.
	expected, source := "", "backup manifest (sidecar)"
	if meta != nil {
		expected = meta.Sha256Checksum
	}
	rec, why := runner.RecordedDigests(ctx, cfg.ServerURL, cfg.ServerToken, snapshotID)
	if rec != nil {
		expected, source = rec.Sha256Checksum, "remote server record"
	}
	switch {
	case decMetrics == nil || expected == "":
		fmt.Fprintf(os.Stderr, "\n[!] NOT VERIFIED — no digest is recorded for this snapshot (%s).\n"+
			"    The data decrypted cleanly, but nothing proves it is what was backed up.\n", why)
	case decMetrics.RawSha256 != expected:
		// Exact, against the plaintext. Accepting "either digest
		// matches" is what hid the fact that backup recorded the
		// ciphertext digest and verify compared the plaintext one:
		// restore kept passing, so the broken Fire Drill looked like a
		// Fire Drill problem rather than a manifest problem.
		//
		// A pre-fix snapshot still restores — it is named as such
		// rather than reported as tampering, because it is not.
		if decMetrics.EncryptedSha256 == expected {
			fmt.Printf("   Digest:          manifest predates 2026-09-21 and records the ciphertext digest;\n")
			fmt.Printf("                    the payload decrypted cleanly, so the restore is sound.\n")
		} else {
			return fmt.Errorf("cryptographic tamper detected: the restored stream's SHA-256 (%s) does not match the %s (%s)", decMetrics.RawSha256, source, expected)
		}
	case rec != nil && rec.EncryptedSha256 != "" && decMetrics.EncryptedSha256 != rec.EncryptedSha256:
		return fmt.Errorf("cryptographic tamper detected: the ciphertext read from the sink (%s) is not the one written at backup time (%s)", decMetrics.EncryptedSha256, rec.EncryptedSha256)
	case rec == nil:
		fmt.Fprintf(os.Stderr, "\n[!] Digest checked against the sidecar only: %s.\n"+
			"    Whoever can write the bucket can replace a snapshot and its sidecar together.\n", why)
	default:
		fmt.Printf("   Digest:          matches the remote server's record from backup time\n")
	}
	return nil
}
