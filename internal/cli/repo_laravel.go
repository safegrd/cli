package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/diskspace"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/dbrun"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/larun"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/unseal"
	"github.com/safegrd/cli/pkg/repo/write"
)

// repoLaravelParams are one backup of a Laravel app into its repository.
type repoLaravelParams struct {
	repoDBParams
	// Root is the app's root, where artisan and .env are.
	Root     string
	Excludes []string
	// DatabaseURL in repoDBParams, when set, overrides the .env's
	// connection: a role made for backups instead of the app's, or the
	// connection Laravel resolved from its config.
	Rescan bool
	// MigrationsTable is the table the app records its migrations in;
	// "" is Laravel's default.
	MigrationsTable string
}

// laravelDumper is the dumper the app's database engine backs up with, as
// that engine's surface stores it.
func laravelDumper(databaseURL string) (dump.Dumper, error) {
	switch dump.SurfaceTypeOfURL(databaseURL) {
	case model.SurfaceTypeSQLite:
		if err := sqliteFileExists(databaseURL); err != nil {
			return nil, classed(exitSource, err)
		}
		d := dump.NewSQLiteDumper(databaseURL)
		d.PageCopy = true
		return d, nil
	case model.SurfaceTypeMySQL:
		return dump.NewMySQLDumper(databaseURL), nil
	case model.SurfaceTypePostgres:
		return dump.NewNativeDumper(databaseURL), nil
	}
	return nil, fmt.Errorf("a Laravel app's database is MySQL, MariaDB, PostgreSQL or SQLite")
}

// runRepoLaravelBackup backs up a Laravel app as one snapshot: its database
// first, as the engine's surface stores it under db/, then its .env, its
// storage/app and its migration files under files/. It returns the metadata
// it recorded in the sidecar; reporting it to the remote server is the
// caller's.
func runRepoLaravelBackup(ctx context.Context, p repoLaravelParams) (*model.SnapshotMetadata, *write.Result, error) {
	out := p.Out
	if out == nil {
		out = io.Discard
	}
	label := "[" + p.SurfaceID + "]"
	app, err := dump.DiscoverLaravel(p.Root)
	if err != nil {
		return nil, nil, stageErr(model.BackupReasonConfig, err)
	}
	var dbURL, connection string
	if p.DatabaseURL != "" {
		dbURL = p.DatabaseURL
		connection = dump.LaravelConnectionOfURL(dbURL)
		if connection == "" {
			return nil, nil, stageErr(model.BackupReasonConfig, fmt.Errorf("surface %s: database_url must be a MySQL, MariaDB, PostgreSQL or SQLite database", p.SurfaceID))
		}
	} else if connection, dbURL, err = app.Database(); err != nil {
		return nil, nil, stageErr(model.BackupReasonConfig, err)
	}
	migrationsTable := dump.LaravelMigrationsTable
	if p.MigrationsTable != "" {
		migrationsTable = p.MigrationsTable
	}
	dumper, err := laravelDumper(dbURL)
	if err != nil {
		return nil, nil, err
	}
	if app.AppKeyProblem != "" {
		fmt.Fprintf(os.Stderr, "Warning: %s %s. A restored app cannot decrypt its encrypted columns, cookies or signed URLs without it, and the drill fails until it is set.\n", label, app.AppKeyProblem)
	}
	if app.FilesystemDisk != "" {
		fmt.Fprintf(os.Stderr, "Warning: %s FILESYSTEM_DISK=%s: the app keeps its uploads there, not in storage/app, and this backup does not hold them.\n"+
			"    Back up the bucket as a files surface with an object_store: block.\n", label, app.FilesystemDisk)
	}

	excludes := append(append([]string{}, dump.LaravelLeftOut...), p.Excludes...)
	if spatie := dump.LaravelSpatieArchives(app.Root, app.AppName); spatie != "" {
		excludes = append(excludes, spatie)
	}
	var mounts []write.Mount
	for _, rel := range []string{dump.LaravelUploadsDir, dump.LaravelMigrationsDir, dump.LaravelSchemaDir} {
		dir := filepath.Join(app.Root, filepath.FromSlash(rel))
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			continue
		}
		mounts = append(mounts, write.Mount{Path: larun.FilesDir + "/" + rel, Dir: dir, ExcludeBase: app.Root})
	}
	migrationFiles, err := dump.LaravelMigrationNames(filepath.Join(app.Root, filepath.FromSlash(dump.LaravelMigrationsDir)))
	if err != nil {
		return nil, nil, stageErr(model.BackupReasonSource, fmt.Errorf("reading %s: %w", dump.LaravelMigrationsDir, err))
	}
	_, schemaErr := os.Stat(filepath.Join(app.Root, filepath.FromSlash(dump.LaravelSchemaDir)))

	b, err := repoBackend(ctx, cfg, p.StorageCfg)
	if err != nil {
		return nil, nil, storageFailure(err)
	}
	if d, ok := b.(*sink.Direct); ok && p.Kept != nil {
		d.Rule = p.Kept
	}
	wb, multi := runCopies(ctx, b, p.Copies)
	started := time.Now()
	var dumpMeta, meta *model.SnapshotMetadata
	stats := &model.LaravelStats{
		Connection: connection, LaravelVersion: app.LaravelVersion, AppName: app.AppName, AppEnv: app.AppEnv,
		MigrationsTable: migrationsTable, MigrationFiles: int64(len(migrationFiles)),
		SchemaDump: schemaErr == nil, FilesystemDisk: app.FilesystemDisk, LeftOut: excludes,
	}
	dbSource := dbrun.Source(dumper, "", &dumpMeta)
	var dbFiles, manifestBytes int64
	dbBytes := &byteCount{}
	source := func(ctx context.Context, emit func(write.Entry) error) error {
		var emitErr error
		err := dbSource(ctx, func(e write.Entry) error {
			e.Path = larun.DBDir + "/" + e.Path
			if e.Reader != nil {
				e.Reader = io.TeeReader(e.Reader, dbBytes)
			}
			dbFiles++
			if err := emit(e); err != nil {
				emitErr = err
				return err
			}
			return nil
		})
		if err != nil {
			// What the database refused is the source's failure; what the
			// upload refused stays the storage's.
			if emitErr == nil && ctx.Err() == nil && !isClassed(err) {
				return stageErr(model.BackupReasonSource, err)
			}
			return err
		}
		env, err := os.ReadFile(filepath.Join(app.Root, dump.LaravelEnvFile))
		if err != nil {
			return stageErr(model.BackupReasonSource, err)
		}
		if err := emit(write.Entry{Path: larun.FilesDir + "/" + dump.LaravelEnvFile, Reader: bytes.NewReader(env)}); err != nil {
			return err
		}
		// PostgreSQL may hold a migrations table in more than one schema;
		// Laravel's is in public unless search_path says otherwise.
		inPublic := false
		for _, t := range dumpMeta.TableStats {
			if t.TableName != stats.MigrationsTable || inPublic {
				continue
			}
			stats.MigrationsRan = t.RowCount
			inPublic = connection == "pgsql" && t.Schema == "public"
		}
		ran, found, err := dump.LaravelMigrationsRan(ctx, dbURL, stats.MigrationsTable)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "Warning: %s could not read the %s table to find migrations not yet run: %v\n", label, stats.MigrationsTable, err)
		case !found && len(migrationFiles) > 0:
			fmt.Fprintf(os.Stderr, "Warning: %s the database has no %s table, so a restored app would run every migration again. "+
				"The drill fails until php artisan migrate has run.\n", label, stats.MigrationsTable)
		default:
			done := map[string]bool{}
			for _, m := range ran {
				done[m] = true
			}
			for _, f := range migrationFiles {
				if !done[f] {
					stats.Pending = append(stats.Pending, f)
				}
			}
		}
		m := *dumpMeta
		m.SurfaceType, m.Laravel = model.SurfaceTypeLaravel, stats
		m.CalculateTotals()
		body, err := json.MarshalIndent(&m, "", "  ")
		if err != nil {
			return err
		}
		manifestBytes = int64(len(body))
		return emit(write.Entry{Path: larun.ManifestFile, Reader: bytes.NewReader(body)})
	}
	host, _ := os.Hostname()
	setRunCopyDocs(multi, p.Copies, p.NodeID, p.SurfaceID, p.RecoverySealTo, func() *model.SnapshotMetadata { return meta })
	res, err := write.Run(ctx, wb, write.Options{
		SurfaceID: p.SurfaceID, StateDir: p.StateDir, Recipient: p.Recipient, Retention: p.Retention,
		Tier: p.Tier, Planned: p.Planned, NewEpoch: p.NewEpoch, Host: host, SnapshotID: p.SnapshotID,
		Rescan:   p.Rescan,
		Chunker:  &format.DatabaseChunker,
		Source:   source,
		Mounts:   mounts,
		Excludes: excludes,
		OnStart: func(r *write.Result) {
			if r.Opened {
				fmt.Fprintf(out, "%s Epoch %s opened (%s). The database and every file are uploaded%s.\n", label, r.Epoch.EpochID, openedWhy(r), onceThisMonth(r.Epoch))
			}
			if r.Resumed {
				fmt.Fprintf(out, "%s Resuming epoch %s: %d %s (%s) already uploaded %s reused.\n", label, r.Epoch.EpochID,
					r.AdoptedPacks, pluralWord(int64(r.AdoptedPacks), "pack", "packs"), formatBytes(r.AdoptedBytes),
					pluralWord(int64(r.AdoptedPacks), "is", "are"))
			}
			if !r.Opened && !r.Resumed {
				fmt.Fprintf(out, "%s Incremental, in epoch %s: only what changed since the last run is uploaded.\n", label, r.Epoch.EpochID)
			}
		},
		RecoveryDoc: repoRecoveryDoc(p.StorageCfg, p.NodeID, p.SurfaceID, p.RecoverySealTo, func() *model.SnapshotMetadata { return meta }),
		Sidecar: func(r *write.Result) ([]byte, error) {
			if dumpMeta == nil {
				return nil, fmt.Errorf("the dump returned no metadata")
			}
			m := *dumpMeta
			now := time.Now().UTC()
			m.SurfaceType = model.SurfaceTypeLaravel
			st := *stats
			// The database's files and the manifest are not the app's.
			st.TotalFiles = r.Snapshot.Stats.Files - dbFiles - 1
			st.FileBytes = r.Snapshot.Stats.LogicalBytes - dbBytes.n - manifestBytes
			m.Laravel = &st
			m.SnapshotID, m.NodeID = p.SnapshotID, p.NodeID
			m.CreatedAt, m.CompletedAt = r.Snapshot.CreatedAt, &now
			m.Status = model.SnapshotStatusCompleted
			m.RawSizeBytes, m.EncryptedSizeBytes = r.Snapshot.Stats.LogicalBytes, r.WrittenBytes
			m.Sha256Checksum, m.EncryptedSha256 = r.Snapshot.ContentRoot, ""
			m.StorageURI = epochURI(b, r.Epoch, p.SurfaceID)
			m.DurationMs = backupMilliseconds(started)
			m.Format, m.EpochID, m.ObjectClass = model.SnapshotFormatRepo, r.Epoch.EpochID, r.Class
			recordRetention(&m, p.StorageCfg, repoKeptUntil(r, repoLocked(p.StorageCfg)))
			m.Unlocked = repoLocked(p.StorageCfg) && !repoRunLocked(r, true)
			m.KeptUntil = keptBeyondLock(r)
			m.CalculateTotals()
			meta = &m
			return json.MarshalIndent(meta, "", "  ")
		},
	})
	if err != nil {
		if !isClassed(err) && !errors.Is(err, context.Canceled) && !errors.Is(err, diskspace.ErrNotEnoughDisk) {
			err = storageFailure(err)
		}
		return nil, nil, err
	}
	if res.CacheWarning != "" {
		fmt.Fprintf(os.Stderr, "Warning: %s %s\n", label, res.CacheWarning)
	}
	if res.RecoveryWarning != "" {
		fmt.Fprintf(os.Stderr, "Warning: %s %s\n", label, res.RecoveryWarning)
	}
	if len(stats.Pending) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %s %d %s not run on this database: %s. The backup holds the database as it is.\n", label,
			len(stats.Pending), pluralWord(int64(len(stats.Pending)), "migration is", "migrations are"), strings.Join(stats.Pending, ", "))
	}
	fmt.Fprintf(out, "%s Laravel %s on %s: %d %s, %s rows, %s %s, %s read, %s stored in %d %s, %s.\n", label,
		orUnknown(stats.LaravelVersion), connection, meta.TotalTables, pluralWord(int64(meta.TotalTables), "table", "tables"),
		formatNumber(meta.TotalRows), formatNumber(meta.Laravel.TotalFiles), pluralWord(meta.Laravel.TotalFiles, "file", "files"),
		formatBytes(res.ReadBytes), formatBytes(res.WrittenBytes), res.Snapshot.Stats.NewPacks,
		pluralWord(res.Snapshot.Stats.NewPacks, "pack", "packs"), shortDuration(time.Since(started)))
	printRepoKept(out, label, res, repoLocked(p.StorageCfg))
	noteRunCopies(multi, p.Copies, meta)
	return meta, res, nil
}

// byteCount counts what is written to it.
type byteCount struct{ n int64 }

func (c *byteCount) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

func orUnknown(v string) string {
	if v == "" {
		return "(version not in composer.lock)"
	}
	return v
}

// laravelTargetEmpty refuses a directory that holds anything.
func laravelTargetEmpty(dir string) error {
	des, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(des) > 0 {
		return fmt.Errorf("%s is not empty; restore into a new, empty directory", dir)
	}
	return nil
}

// restoreRepoLaravel restores a Laravel app's snapshot: the database into an
// empty database of its engine, then the .env, storage/app and the migration
// files into an empty directory. Every file is checked against its SHA-256,
// and the content root against the one recorded at backup time, before
// anything is written.
func restoreRepoLaravel(ctx context.Context, rs *repoSnapshot, privateKey, targetURL, targetDir string) error {
	id := rs.Meta.SnapshotID
	ids, err := unseal.Identities(privateKey)
	if err != nil {
		return err
	}
	r := read.Open(rs.Backend, rs.Epoch, ids)
	snap, err := r.Snapshot(ctx, id)
	if err != nil {
		return fmt.Errorf("reading snapshot %s: %w", id, err)
	}
	idx, err := r.LoadIndex(ctx, snap)
	if err != nil {
		return fmt.Errorf("reading snapshot %s: %w", id, err)
	}
	root, _, err := r.ContentRoot(ctx, idx, snap)
	if err != nil {
		return fmt.Errorf("reading snapshot %s: %w", id, err)
	}
	if err := checkRepoContentRoot(ctx, rs.Meta, id, root); err != nil {
		return err
	}
	run, err := larun.Files(ctx, r, idx, snap)
	if err != nil {
		return err
	}
	manifest, err := larun.ReadManifest(ctx, r, idx, run)
	if err != nil {
		return err
	}
	if manifest.Laravel == nil {
		return fmt.Errorf("snapshot %s: its manifest does not describe a Laravel app", id)
	}
	conn := manifest.Laravel.Connection
	if got := dump.LaravelConnectionOfURL(targetURL); got == "" || (got != conn && !(isMySQLFamily(got) && isMySQLFamily(conn))) {
		return fmt.Errorf("snapshot %s holds a %s database; --target must be an empty database of that engine", id, conn)
	}
	if err := laravelTargetEmpty(targetDir); err != nil {
		return err
	}
	if conn == "sqlite" {
		p, err := dump.SQLitePath(targetURL)
		if err != nil {
			return err
		}
		if err := dump.SQLiteCheckEmpty(p); err != nil {
			return err
		}
	}
	if isMySQLFamily(conn) {
		db, err := dump.OpenMySQL(targetURL)
		if err != nil {
			return err
		}
		err = dump.MySQLCheckEmpty(ctx, db)
		_ = db.Close()
		if err != nil {
			return err
		}
	}

	started := time.Now()
	pr, pw := io.Pipe()
	archived := make(chan error, 1)
	go func() {
		err := larun.DatabaseArchive(ctx, r, idx, run, pw)
		_ = pw.CloseWithError(err)
		archived <- err
	}()
	var got *model.SnapshotMetadata
	waited := false
	switch {
	case conn == "sqlite":
		got, err = dump.NewSQLiteRestorer(targetURL).Restore(ctx, pr)
	case isMySQLFamily(conn):
		got, err = dump.NewMySQLRestorer(targetURL).Restore(ctx, pr)
	default:
		restorer := dump.NewNativeRestorer(targetURL)
		restorer.BeforeCommit = func() error {
			_, _ = io.Copy(io.Discard, pr)
			waited = true
			return <-archived
		}
		got, err = restorer.Restore(ctx, pr)
		if err == nil && restorer.ChangeLogRemoved {
			got = dump.WithoutChangeLog(got)
		}
	}
	_ = pr.CloseWithError(fmt.Errorf("the restore stopped"))
	var aerr error
	if !waited {
		aerr = <-archived
	}
	if err == nil && aerr != nil {
		err = fmt.Errorf("reading the snapshot back: %w", aerr)
	}
	if err != nil {
		return fmt.Errorf("the database restore failed, and no file was written: %w", err)
	}
	var rows int64
	for _, t := range got.TableStats {
		rows += t.RowCount
	}
	fmt.Printf("Restored the database: %d %s, %s rows, every table matched its row count.\n",
		len(got.TableStats), pluralWord(int64(len(got.TableStats)), "table", "tables"), formatNumber(rows))

	fres, err := r.Restore(ctx, snap, idx, read.RestoreOptions{Target: targetDir, Paths: []string{larun.FilesDir}, Base: larun.FilesDir})
	if err != nil {
		return fmt.Errorf("the database is restored, and the files are not: %w", err)
	}
	fmt.Printf("Restored the files: %s %s, %s, into %s.\n", formatNumber(fres.Files), pluralWord(fres.Files, "file", "files"),
		formatBytes(fres.Bytes), targetDir)
	fmt.Printf("Restore complete in %s.\n", shortDuration(time.Since(started)))
	printLaravelNextSteps(manifest.Laravel, targetDir)
	return nil
}

func isMySQLFamily(conn string) bool { return conn == "mysql" || conn == "mariadb" }

// printLaravelNextSteps says what is left to run the app on what was
// restored.
func printLaravelNextSteps(st *model.LaravelStats, targetDir string) {
	if st.LaravelVersion != "" {
		fmt.Printf("   Laravel:        %s (the code is not in the snapshot: check out the app at this version)\n", st.LaravelVersion)
	}
	fmt.Printf("   .env:           %s (it still names the old database)\n", filepath.Join(targetDir, dump.LaravelEnvFile))
	if st.FilesystemDisk != "" {
		fmt.Printf("   Uploads:        on %s, not in this snapshot\n", st.FilesystemDisk)
	}
	fmt.Printf("Next, in the app's checkout:\n")
	fmt.Printf("   1. Copy .env and storage/app from %s into it.\n", targetDir)
	if st.Connection == "sqlite" {
		fmt.Printf("   2. Point DB_DATABASE in .env at the restored database file.\n")
	} else {
		fmt.Printf("   2. Point DB_HOST, DB_DATABASE, DB_USERNAME and DB_PASSWORD in .env at the restored database.\n")
	}
	fmt.Printf("   3. Run: php artisan config:clear && php artisan storage:link && php artisan migrate:status\n")
}

// laravelSurfaceRoot is the one root a laravel surface names.
func laravelSurfaceRoot(s *config.SurfaceConfig) (string, error) {
	if len(s.Roots) != 1 {
		return "", fmt.Errorf("surface %s: a laravel surface takes one root, the app's root (where artisan and .env are)", s.ID)
	}
	return s.Roots[0], nil
}
