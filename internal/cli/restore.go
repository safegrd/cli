package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

func newRestoreCmd() *cobra.Command {
	var (
		snapshotID string
		targetURL  string
		targetDir  string
		toSQL      string
		engineStr  string
		keyPath    string
		privKey    string
		fromPath   string
		paths      []string
		version    int
		surfaceSel string
		tables     []string
		schemas    []string
		dataOnly   []string
		noOwner    bool
	)

	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore a snapshot into a database or a directory",
		Long: `Read a snapshot from this host's storage, decrypt it here with the private key,
and restore it into a database (--target) or a directory (--target-dir).

--to-sql writes a PostgreSQL snapshot as files psql loads without SafeGrd:
the schema as SQL, each table's rows as binary COPY, and load.sql to run them
in order. The files hold the data unencrypted; the directory is 0700.

--from reads a copy made by 'safegrd export --to-dir' instead: the export
directory with --snapshot, or one .safegrd file, whose name gives the snapshot ID.
The copy is checked against the digest recorded at backup time, as a restore
from storage is.

A PostgreSQL restore creates the roles the schema names that the target lacks
(owners, grantees, the roles policies apply to) before the schema runs, and
prints each one. --no-owner restores without ownership and privileges, so
every object belongs to the restoring role; the roles are still created,
because a policy cannot be restored without them.

--schema and --data-only-schema restore part of a PostgreSQL snapshot into a
database that already has other schemas, such as a Supabase project after an
incident: --schema public restores that schema's objects and rows, and
--data-only-schema auth --data-only-schema storage loads only those schemas'
rows into the tables the project already has. The chosen schemas' objects have
to be absent from the target for --schema; everything else in the target is
left alone, and the whole restore is still one transaction.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fromDir := ""
			if fromPath != "" {
				dir, id, err := resolveRestoreFrom(fromPath, snapshotID)
				if err != nil {
					return err
				}
				fromDir, snapshotID = dir, id
			}
			if len(schemas) > 0 || len(dataOnly) > 0 {
				if targetURL == "" || toSQL != "" || len(paths) > 0 || len(tables) > 0 || version > 0 {
					return fmt.Errorf("--schema and --data-only-schema restore part of a PostgreSQL archive into --target; leave out --to-sql, --path, --table and --version")
				}
				if dump.SurfaceTypeOfURL(targetURL) != model.SurfaceTypePostgres {
					return fmt.Errorf("--schema and --data-only-schema restore into a PostgreSQL database")
				}
			}
			if len(tables) > 0 {
				if targetURL == "" || len(paths) > 0 {
					return fmt.Errorf("--table restores tables of a database snapshot into --target; leave out --path, --target-dir and --to-sql")
				}
				if version > 0 {
					if len(tables) != 1 {
						return fmt.Errorf("--version restores one version of one table: give one --table")
					}
					p, err := tablePath(tables[0])
					if err != nil {
						return err
					}
					paths = []string{p}
				}
			}
			// One file or one table with no snapshot named comes back as its
			// newest kept version, the one 'safegrd find' marks (current).
			newest := false
			if version == 0 && snapshotID == "" {
				if len(tables) == 1 && len(paths) == 0 {
					p, err := tablePath(tables[0])
					if err != nil {
						return err
					}
					paths, newest = []string{p}, true
				} else if len(paths) == 1 && len(tables) == 0 && !strings.ContainsAny(paths[0], "*?[") {
					newest = true
				}
			}
			if version > 0 {
				if snapshotID != "" || len(paths) != 1 {
					return fmt.Errorf("--version restores one version of one file: give one --path, and leave out --snapshot")
				}
			} else if snapshotID == "" && !newest {
				return fmt.Errorf("give --snapshot <id> (from 'safegrd list'), or one --path or --table to restore its newest version; --version <n> restores an older one ('safegrd find' numbers them)")
			}
			given := 0
			for _, v := range []string{targetURL, targetDir, toSQL} {
				if v != "" {
					given++
				}
			}
			// A WordPress site takes both a database and a directory; the
			// surface is checked once the snapshot's metadata is read.
			if given != 1 && !(given == 2 && toSQL == "") {
				return fmt.Errorf("give one of --target (a database), --target-dir (files or email) or --to-sql (a PostgreSQL snapshot as files psql loads); a WordPress site takes --target and --target-dir together")
			}
			// Checked before anything is written: a failed export removes the
			// directory, which is only safe when it held nothing of the user's.
			if toSQL != "" {
				if entries, err := os.ReadDir(toSQL); err == nil && len(entries) > 0 {
					return fmt.Errorf("--to-sql %s is not empty; give a new directory", toSQL)
				}
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

			ctx := cmd.Context()

			// SafeGrd may hold this organization's keys, including a lost
			// host's. They are tried beside the host's own key, never written
			// to key_path; they open this archive and then go away. A
			// customer-held org answers 404 and the local key stands alone.
			resolvedKey = withManagedIdentity(ctx, cfg, resolvedKey, heldKeyQuery{snapshotID: snapshotID}, true)

			if resolvedKey == "" {
				return fmt.Errorf("decryption key required: specify --private-key or configure ~/.safegrd/keys/daemon.key")
			}

			var storageProvider storage.StorageProvider
			if fromDir != "" {
				// An export holds incremental repositories in the layout a
				// local directory of storage has.
				rs, err := locateRepoSnapshot(ctx, config.StorageConfig{Type: config.StorageTypeLocal, LocalPath: fromDir}, snapshotID)
				if err != nil {
					return fmt.Errorf("looking for %s in %s: %w", snapshotID, fromDir, err)
				}
				if rs != nil {
					return restoreRepo(ctx, rs, resolvedKey, targetDir, targetURL, toSQL, paths, tables, noOwner)
				}
			}
			if fromDir != "" {
				local, err := storage.NewLocalStorage(fromDir)
				if err != nil {
					return err
				}
				storageProvider = local
			} else {
				// Routed and credentialed exactly as backup does, because a node
				// enrolled with a centrally-managed sink has no bucket or sink secret locally
				// either; restoring from a centrally-configured sink must work.
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
				// A snapshot of an incremental repository has no single
				// object to download; it is restored from its packs.
				if version > 0 || newest {
					id, fetched, err := resolveVersion(ctx, storageCfg, resolvedKey, surfaceSel, paths[0], version)
					if err != nil {
						return err
					}
					snapshotID = id
					if fetched != "" {
						resolvedKey = strings.TrimSpace(resolvedKey + "\n" + fetched)
					}
					// The key was resolved before the snapshot was known: ask
					// for the one this snapshot needs, which may be another
					// host's (a lost host's file, restored on its replacement).
					resolvedKey = withManagedIdentity(ctx, cfg, resolvedKey, heldKeyQuery{snapshotID: snapshotID}, true)
					if len(tables) > 0 {
						paths = nil
					}
				}
				rs, err := locateRepoSnapshot(ctx, storageCfg, snapshotID)
				if err != nil {
					// Said, and not fatal: the snapshot may be an archive, which
					// does not need the repositories to be readable.
					fmt.Fprintf(os.Stderr, "Warning: could not look among the incremental repositories: %v\n", err)
				}
				if rs != nil {
					return restoreRepo(ctx, rs, resolvedKey, targetDir, targetURL, toSQL, paths, tables, noOwner)
				}
				opened, err := openStorage(ctx, cfg, storageCfg)
				if err != nil {
					return fmt.Errorf("storage initialization failed: %w", err)
				}
				storageProvider = opened
			}
			if len(paths) > 0 {
				return fmt.Errorf("--path restores part of an incremental (--format repo) snapshot; %s is one archive, so restore it whole", snapshotID)
			}
			if len(tables) > 0 {
				return fmt.Errorf("--table restores tables from a run of an incremental database backup (--format repo); %s is one archive, so restore it whole", snapshotID)
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

			// Fetch metadata to detect surface type and checksum
			meta, metaErr := storageProvider.DownloadMetadata(ctx, snapshotID)
			surface := model.SurfaceTypePostgres
			if meta != nil && meta.SurfaceType != "" {
				surface = meta.SurfaceType
			} else if targetDir != "" && targetURL == "" {
				surface = model.SurfaceTypeFiles
			}
			if metaErr != nil {
				// Without the sidecar the surface type is a guess from the
				// flags, and the digest cannot be checked against it.
				fmt.Fprintf(os.Stderr, "Warning: could not read the metadata for %s: %v\n   Restoring it as a %s snapshot, going by the flags given.\n", snapshotID, metaErr, surface)
			}

			fmt.Printf("Restoring %s\n", snapshotID)
			fmt.Printf("   Snapshot ID:    %s\n", snapshotID)
			fmt.Printf("   Surface:        %s\n", surface)

			if toSQL != "" && surface != model.SurfaceTypePostgres {
				return fmt.Errorf("snapshot %s is a %s snapshot; --to-sql reads PostgreSQL snapshots only", snapshotID, surface)
			}
			if (surface == model.SurfaceTypeFiles || surface == model.SurfaceTypeEmail) && targetDir == "" {
				return fmt.Errorf("snapshot %s is a %s snapshot; specify --target-dir to restore", snapshotID, surface)
			}
			if surface != model.SurfaceTypeWordPress && targetURL != "" && targetDir != "" {
				return fmt.Errorf("snapshot %s is a %s snapshot; give --target or --target-dir, not both", snapshotID, surface)
			}
			if surface == model.SurfaceTypeWordPress && (targetDir == "" || targetURL == "" || dump.SurfaceTypeOfURL(targetURL) != model.SurfaceTypeMySQL) {
				return fmt.Errorf("snapshot %s is a WordPress site; pass --target with an empty MySQL or MariaDB database (mysql://...) "+
					"for its database and --target-dir with an empty directory for its files", snapshotID)
			}
			if surface.IsDatabase() && targetURL == "" && toSQL == "" {
				return fmt.Errorf("snapshot %s is a %s snapshot; pass --target with a database URL, or --to-sql", snapshotID, surface)
			}

			engine := dump.EngineType(engineStr)

			if surface.IsDatabase() && toSQL == "" && dump.SurfaceTypeOfURL(targetURL) != surface && !(surface == "" && dump.SurfaceTypeOfURL(targetURL) == model.SurfaceTypePostgres) {
				return fmt.Errorf("snapshot %s is a %s snapshot; --target must be a %s database", snapshotID, surface, surface)
			}
			if toSQL != "" {
				fmt.Printf("   Target dir:     %s (SQL and COPY files)\n", toSQL)
			} else if surface == model.SurfaceTypeWordPress {
				fmt.Printf("   Target:         %s\n", dump.RedactURL(targetURL))
				fmt.Printf("   Target dir:     %s\n", targetDir)
			} else if surface.IsDatabase() {
				fmt.Printf("   Target:         %s\n", dump.RedactURL(targetURL))
				if meta != nil {
					fmt.Printf("   Schema:         %s\n", schemaSourceLabel(meta.SchemaSource))
				}
			} else {
				fmt.Printf("   Target dir:     %s\n", targetDir)
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
			// Every return closes the read end, so a decrypt goroutine still
			// writing gets an error and exits instead of blocking on the
			// pipe, with the storage stream, for the life of the process.
			defer plainReader.Close()

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
				native   *dump.NativeRestorer
				sqlRes   *dump.SQLExport
				fileRes  *dump.FileExtractionResult
				wpRes    *dump.WordPressRestoreResult
				emailRes *dump.EmailExtractionResult
			)

			switch {
			case toSQL != "":
				sqlRes, err = dump.ExportSQL(plainReader, toSQL)
				if err != nil {
					_ = os.RemoveAll(toSQL)
					return fmt.Errorf("writing the snapshot as SQL failed, and nothing was kept in %s: %w", toSQL, err)
				}
				// The tar reader stops at the archive's end marker; the rest
				// of the stream has to be read for the digest to be whole.
				_, _ = io.Copy(io.Discard, plainReader)
			case surface == model.SurfaceTypeFiles:
				fileRestorer := dump.NewFileRestorer()
				fileRes, err = fileRestorer.ExtractArchive(ctx, plainReader, targetDir)
				if err != nil {
					return fmt.Errorf("file extraction failed: %w", err)
				}
			case surface == model.SurfaceTypeWordPress:
				wpRes, err = dump.RestoreWordPress(ctx, plainReader, targetURL, targetDir)
				if err != nil {
					return fmt.Errorf("WordPress restore failed: %w", err)
				}
				_, _ = io.Copy(io.Discard, plainReader) // the rest of the stream, for the digest
			case surface == model.SurfaceTypeEmail:
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
				if n, ok := restorer.(*dump.NativeRestorer); ok {
					native = n
					native.NoOwner = noOwner
					if noOwner {
						fmt.Printf("   Ownership:      not restored (--no-owner); every object belongs to the restoring role\n")
					}
					if len(schemas) > 0 || len(dataOnly) > 0 {
						native.Schemas, native.DataOnlySchemas = map[string]bool{}, map[string]bool{}
						for _, sc := range schemas {
							native.Schemas[sc] = true
						}
						for _, sc := range dataOnly {
							native.DataOnlySchemas[sc] = true
						}
						fmt.Printf("   Schemas:        %s\n", describeSchemaChoice(schemas, dataOnly))
					}
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
					if sqlRes != nil {
						_ = os.RemoveAll(toSQL)
						return fmt.Errorf("%w\n   The files written to %s were removed", err, toSQL)
					}
					return err
				}
			}

			elapsed := time.Since(startTime)

			if sqlRes != nil {
				printSQLExport(sqlRes, toSQL, elapsed)
				return nil
			}

			fmt.Println("\nRestore complete")
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
					fmt.Printf("   Bytes written:  %d\n", fileRes.TotalBytesWritten)
				}
				fmt.Printf("   Destination:    %s\n", targetDir)
				if fileRes != nil {
					printFileRestoreLimits(fileRes)
				}
			case model.SurfaceTypeWordPress:
				printWordPressRestore(wpRes, targetDir)
			case model.SurfaceTypeEmail:
				if emailRes != nil {
					fmt.Printf("   Emails:         %d\n", emailRes.EmailsExtracted)
					fmt.Printf("   Folders:        %d\n", emailRes.DirectoriesExtracted)
					fmt.Printf("   Bytes written:  %d\n", emailRes.TotalBytesWritten)
					if emailRes.GmailLabels {
						fmt.Printf("   Gmail labels:   %s (one copy of each message, in All Mail)\n", emailRes.ManifestPath)
					}
				}
				fmt.Printf("   Destination:    %s\n", targetDir)
			default:
				// MongoDB has collections and documents, and the summary
				// said tables and rows for them.
				tables, rows := "Tables:        ", "Rows:          "
				what := "tables and rows"
				if pgMeta != nil && pgMeta.SurfaceType == model.SurfaceTypeMongoDB {
					tables, rows, what = "Collections:   ", "Documents:     ", "collections and documents"
				}
				if pgMeta != nil {
					fmt.Printf("   %s %d\n", tables, pgMeta.TotalTables)
					fmt.Printf("   %s %d\n", rows, pgMeta.TotalRows)
				}
				if native != nil {
					printCreatedRoles(native.CreatedRoles)
				}
				fmt.Printf("   Check the %s above against what you expect before you point an application at it.\n", what)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&snapshotID, "snapshot", "", "Snapshot ID to restore. Leave it out with one --path or --table to restore its newest version")
	cmd.Flags().StringVar(&targetURL, "target", "", "Target database URL: postgres://… or mysql://… (an empty database), or sqlite:///path/to/new.db (a file that does not exist yet)")
	cmd.Flags().StringVar(&targetDir, "target-dir", "", "Directory to restore a files, email or WordPress snapshot into")
	cmd.Flags().StringVar(&toSQL, "to-sql", "", "Write a PostgreSQL snapshot into this new directory as SQL and COPY files that psql loads (load.sql)")
	cmd.Flags().StringVar(&engineStr, "engine", "native", "Accepted for old scripts and ignored: there is one Postgres restore path")
	_ = cmd.Flags().MarkDeprecated("engine", "there is one Postgres restore path; the flag is ignored")
	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to the age identity file")
	cmd.Flags().StringVar(&privKey, "private-key", "", "Age identity (AGE-SECRET-KEY-1...), as env:VAR, file:/path or the key")
	cmd.Flags().IntVar(&version, "version", 0, "With one --path or --table: restore that version, as 'safegrd find' numbers them")
	cmd.Flags().StringArrayVar(&schemas, "schema", nil, "Restore only this schema of a PostgreSQL snapshot, objects and rows, into a database that has other schemas (repeatable)")
	cmd.Flags().StringArrayVar(&dataOnly, "data-only-schema", nil, "Load only this schema's rows into tables the target already has (repeatable)")
	cmd.Flags().BoolVar(&noOwner, "no-owner", false, "PostgreSQL: restore without ownership and privileges, so every object belongs to the restoring role. The roles the schema names are still created")
	cmd.Flags().StringArrayVar(&tables, "table", nil, "Restore only this table (schema.table) of a database run into --target: into an empty table of the same definition, or created as the run defined it when the target has none (repeatable)")
	cmd.Flags().StringVar(&surfaceSel, "surface", "", "With --path or --table and no --snapshot: the surface whose repository holds it")
	cmd.Flags().StringArrayVar(&paths, "path", nil, "Restore only this path of a repository snapshot, relative to / (repeatable; '*', '?' and '**' match)")
	cmd.Flags().StringVar(&fromPath, "from", "", "Restore from an export: the directory 'safegrd export --to-dir' wrote, or one .safegrd file in it")

	return cmd
}

// printCreatedRoles names the roles a restore created on the target because
// the schema named them and the target lacked them, one per line.
func printCreatedRoles(roles []string) {
	for _, r := range roles {
		fmt.Printf("   Created role:   %s\n", r)
	}
}

// printFileRestoreLimits says what a file restore did not bring back. A
// restore that quietly loses metadata is the thing this product exists to be
// the opposite of, so it is printed every time rather than left to the docs.
func printFileRestoreLimits(res *dump.FileExtractionResult) {
	if res.OwnershipRestored {
		fmt.Printf("   Ownership:      restored from the sealed manifest\n")
	} else if res.OwnershipNote != "" {
		fmt.Printf("   Ownership:      not restored (%s)\n", res.OwnershipNote)
	}
	fmt.Printf("   Not preserved:  hard links (each comes back as its own copy), extended\n" +
		"                   attributes and ACLs, setuid/setgid bits, and sparse regions\n" +
		"                   (written out in full). See safegrd.dev/docs/surfaces/files.\n")
	if len(res.Skipped) > 0 {
		fmt.Fprintf(os.Stderr, "\nWarning: %d archive entries were not restored, because this restore does not create them:\n", len(res.Skipped))
		for _, s := range res.Skipped {
			fmt.Fprintf(os.Stderr, "    %s\n", s)
		}
	}
}

// describeSchemaChoice is the --schema and --data-only-schema choice, for the
// restore's summary.
func describeSchemaChoice(schemas, dataOnly []string) string {
	var parts []string
	if len(schemas) > 0 {
		parts = append(parts, strings.Join(schemas, ", ")+" (objects and rows)")
	}
	if len(dataOnly) > 0 {
		parts = append(parts, strings.Join(dataOnly, ", ")+" (rows only)")
	}
	return strings.Join(parts, "; ")
}

// schemaSourceLabel says how a Postgres snapshot's schema was captured.
func schemaSourceLabel(source string) string {
	switch {
	case strings.HasPrefix(source, "pg_dump "), strings.HasPrefix(source, "mysqldump"), strings.HasPrefix(source, "mariadb-dump"), strings.HasPrefix(source, "mongodump"),
		strings.HasPrefix(source, "sqlite "):
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
	// The sidecar is written to the bucket; the remote server's
	// record is kept separately, so it takes precedence when available.
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
		fmt.Fprintf(os.Stderr, "\nWarning: NOT VERIFIED: no digest is recorded for this snapshot (%s).\n"+
			"    The data decrypted cleanly, but nothing proves it is what was backed up.\n", why)
	case decMetrics.RawSha256 != expected:
		// Exact, against the plaintext.
		// A legacy snapshot still restores and is identified as such
		// rather than reported as tampering.
		if decMetrics.EncryptedSha256 == expected {
			fmt.Printf("   Digest:          manifest predates 2026-09-21 and records the ciphertext digest;\n")
			fmt.Printf("                    the payload decrypted cleanly, so the restore is sound.\n")
		} else {
			return fmt.Errorf("cryptographic tamper detected: the restored stream's SHA-256 (%s) does not match the %s (%s)", decMetrics.RawSha256, source, expected)
		}
	case rec != nil && rec.EncryptedSha256 != "" && decMetrics.EncryptedSha256 != rec.EncryptedSha256:
		return fmt.Errorf("cryptographic tamper detected: the ciphertext read from the sink (%s) is not the one written at backup time (%s)", decMetrics.EncryptedSha256, rec.EncryptedSha256)
	case rec == nil:
		fmt.Fprintf(os.Stderr, "\nWarning: digest checked against the sidecar only: %s.\n"+
			"    It was not compared with SafeGrd's record from backup time; run this on an enrolled host to compare.\n", why)
	default:
		fmt.Printf("   Digest:          matches the remote server's record from backup time\n")
	}
	return nil
}

// resolveRestoreFrom turns --from into the directory to read and the snapshot
// ID. A directory needs --snapshot. A .safegrd file names its snapshot, and
// its metadata sidecar sits next to it.
func resolveRestoreFrom(from, snapshotID string) (string, string, error) {
	info, err := os.Stat(from)
	if err != nil {
		return "", "", fmt.Errorf("--from %s: %w", from, err)
	}
	if info.IsDir() {
		if snapshotID == "" {
			return "", "", fmt.Errorf("--from names a directory; add --snapshot with the ID to restore (the file names in it, without .safegrd)")
		}
		return from, snapshotID, nil
	}
	base := filepath.Base(from)
	id, ok := strings.CutSuffix(base, ".safegrd")
	if !ok || id == "" {
		return "", "", fmt.Errorf("--from %s is not a .safegrd snapshot file", from)
	}
	if snapshotID != "" && snapshotID != id {
		return "", "", fmt.Errorf("--snapshot %s does not match --from %s", snapshotID, base)
	}
	return filepath.Dir(from), id, nil
}

// printSQLExport says what restore --to-sql wrote and how to load it.
func printSQLExport(res *dump.SQLExport, dir string, elapsed time.Duration) {
	fmt.Printf("\nWrote %d tables, %d rows to %s (%s)\n", res.Tables, res.Rows, dir, elapsed.Round(time.Millisecond))
	fmt.Println("   The files are unencrypted. Delete them when the database is loaded.")
	fmt.Println("   Load into an empty database:")
	fmt.Printf("   cd %s && psql \"postgres://user@host/empty_db\" -f load.sql\n", dir)
	if w := res.Warning(); w != "" {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
	}
}
