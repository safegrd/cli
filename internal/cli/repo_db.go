package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/diskspace"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/repo/dbrun"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/policy"
	"github.com/safegrd/cli/pkg/repo/read"
	"github.com/safegrd/cli/pkg/repo/sink"
	"github.com/safegrd/cli/pkg/repo/unseal"
	"github.com/safegrd/cli/pkg/repo/write"
	"github.com/safegrd/cli/pkg/runner"
)

// repoDatabaseSurfaceID names the repository of an ad-hoc
// `backup --database-url … --format repo`: the same database always lands in
// the same repository, whatever password or options the URL carries, or
// whichever path names a SQLite file.
func repoDatabaseSurfaceID(databaseURL string) string {
	if dump.IsMySQLURL(databaseURL) || dump.IsMongoURL(databaseURL) {
		prefix := "mysql-"
		if dump.IsMongoURL(databaseURL) {
			prefix = "mongodb-"
		}
		key := databaseURL
		if u, err := url.Parse(databaseURL); err == nil {
			// The same database whether or not the URL spells the default
			// port, as SameMySQLDatabase and SameMongoDatabase take it.
			host := strings.ToLower(u.Host)
			defaultPort := ":3306"
			if dump.IsMongoURL(databaseURL) {
				defaultPort = ":27017"
			}
			var hosts []string
			for _, h := range strings.Split(host, ",") {
				if !strings.Contains(h, ":") {
					h += defaultPort
				}
				hosts = append(hosts, h)
			}
			key = prefix + strings.Join(hosts, ",") + u.Path
		}
		sum := sha256.Sum256([]byte(key))
		return prefix + hex.EncodeToString(sum[:])[:12]
	}
	if dump.IsSQLiteURL(databaseURL) {
		key := databaseURL
		if p, err := dump.SQLitePath(databaseURL); err == nil {
			if real, err := filepath.EvalSymlinks(p); err == nil {
				p = real
			}
			key = "sqlite://" + p
		}
		sum := sha256.Sum256([]byte(key))
		return "sqlite-" + hex.EncodeToString(sum[:])[:12]
	}
	key := databaseURL
	if c, err := pgx.ParseConfig(databaseURL); err == nil {
		key = fmt.Sprintf("postgres://%s:%d/%s", c.Host, c.Port, c.Database)
	}
	sum := sha256.Sum256([]byte(key))
	return "postgres-" + hex.EncodeToString(sum[:])[:12]
}

// repoDatabaseKind reports whether a database backs up as a run of its
// repository: every engine does, PostgreSQL as one file per table, SQLite
// as its file, MySQL as the dump cut per table, MongoDB as one file per
// collection.
func repoDatabaseKind(t model.SurfaceType) bool {
	return t == model.SurfaceTypePostgres || t == model.SurfaceTypeSQLite || t == model.SurfaceTypeMySQL || t == model.SurfaceTypeMongoDB
}

// runUnit names what a run of kind is made of, for its output lines.
func runUnit(kind model.SurfaceType) (everything, table, tables, rows string) {
	switch kind {
	case model.SurfaceTypeSQLite:
		return "the whole database", "table", "tables", "rows"
	case model.SurfaceTypeMongoDB:
		return "every collection", "collection", "collections", "documents"
	}
	return "every table", "table", "tables", "rows"
}

// repoDBParams are one database backup into a repository.
type repoDBParams struct {
	SurfaceID   string
	DatabaseURL string
	StorageCfg  config.StorageConfig
	NodeID      string
	Recipient   string
	Retention   policy.Retention
	Tier        string
	Planned     time.Time
	NewEpoch    bool
	SnapshotID  string
	StateDir    string
	Out         io.Writer
	// Kept is the rule this run writes under in the host's own bucket when
	// its project locks only the kept copies; nil locks every object.
	Kept *sink.KeptRule
	// ServerCache keeps the writer's cache on the remote server between
	// runs, for a run on a machine that does not outlive it.
	ServerCache bool
	// ChangeLog installs the change log in the database, with the
	// customer's consent, and carries forward unread the tables it shows
	// nothing wrote since the last run.
	ChangeLog bool
	// RolesWithoutPasswords leaves role passwords out of roles.sql.
	RolesWithoutPasswords bool
	// RecoverySealTo seals the recovery document to this recipient; ""
	// writes it as text.
	RecoverySealTo string
	// SkipIfUnchanged writes nothing when no table changed (write.Options).
	SkipIfUnchanged bool
}

// runRepoDatabaseBackup dumps a database into its repository as one
// snapshot, and returns the metadata it recorded in the sidecar: PostgreSQL
// as one file per section and per table, SQLite as its database file copied
// page for page, MySQL as the dump tool's stream cut per table, MongoDB as
// mongodump's archive taken apart per collection. Reporting it to the
// remote server is the caller's.
func runRepoDatabaseBackup(ctx context.Context, p repoDBParams) (*model.SnapshotMetadata, *write.Result, error) {
	out := p.Out
	if out == nil {
		out = io.Discard
	}
	kind := dump.SurfaceTypeOfURL(p.DatabaseURL)
	if !repoDatabaseKind(kind) {
		return nil, nil, fmt.Errorf("--format repo backs up a PostgreSQL, MySQL, MongoDB or SQLite database, or files")
	}
	if p.ChangeLog && kind != model.SurfaceTypePostgres {
		return nil, nil, fmt.Errorf("the change log applies to a PostgreSQL database")
	}
	// What a run that cannot reuse the epoch uploads again.
	everything, tableWord, tablesWord, rowsWord := runUnit(kind)
	if kind == model.SurfaceTypeSQLite {
		// Before anything is opened in storage: a mistyped path opened an
		// epoch on the remote server, and printed "Epoch opened", before
		// the dump found no file.
		if err := sqliteFileExists(p.DatabaseURL); err != nil {
			return nil, nil, classed(exitSource, err)
		}
	}
	// The same for a dump tool the host lacks: the epoch it opened made the
	// next run read as an increment over its first complete one.
	if err := dump.CheckDumpTool(ctx, kind); err != nil {
		return nil, nil, classed(exitSource, err)
	}
	b, err := repoBackend(ctx, cfg, p.StorageCfg)
	if err != nil {
		return nil, nil, storageFailure(err)
	}
	if d, ok := b.(*sink.Direct); ok && p.Kept != nil {
		d.Rule = p.Kept
	}
	label := "[" + p.SurfaceID + "]"
	started := time.Now()
	var sc *serverCache
	if p.ServerCache {
		var note string
		if sc, note, err = fetchServerCache(ctx, cfg, p.SurfaceID, p.StateDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s the cache kept on the remote server could not be fetched (%v). This run uploads %s again.\n", label, err, everything)
		} else if note != "" && strings.HasPrefix(note, "no cache") {
			fmt.Fprintf(out, "%s %s.\n", label, strings.ToUpper(note[:1])+note[1:])
		} else if note != "" {
			fmt.Fprintf(os.Stderr, "Warning: %s %s. This run uploads %s again.\n", label, note, everything)
		}
	}
	var dumpMeta, meta *model.SnapshotMetadata
	var source write.Source
	var dumper *dump.NativeDumper
	switch kind {
	case model.SurfaceTypeSQLite:
		sd := dump.NewSQLiteDumper(p.DatabaseURL)
		sd.PageCopy = true
		source = dbrun.Source(sd, "", &dumpMeta)
	case model.SurfaceTypeMySQL:
		md := dump.NewMySQLDumper(p.DatabaseURL)
		md.PerTable = true
		source = dbrun.Source(md, "", &dumpMeta)
	case model.SurfaceTypeMongoDB:
		md := dump.NewMongoDumper(p.DatabaseURL)
		md.PerCollection = true
		source = dbrun.Source(md, "", &dumpMeta)
	default:
		dumper = dump.NewNativeDumper(p.DatabaseURL)
		dumper.RolesWithoutPasswords = p.RolesWithoutPasswords
		source = dbrun.Source(dumper, "", &dumpMeta)
	}
	var (
		prior    *dump.ChangeLogState
		plan     *dump.ChangeLogPlan
		consumer string
		canCarry func(string) bool
		priorRaw []byte
	)
	if p.ChangeLog {
		inner := source
		source = func(ctx context.Context, emit func(write.Entry) error) error {
			if len(priorRaw) > 0 {
				var st dump.ChangeLogState
				if json.Unmarshal(priorRaw, &st) == nil {
					prior = &st
				}
			}
			consumer = dump.NewChangeLogConsumer()
			if prior != nil && prior.Consumer != "" {
				consumer = prior.Consumer
			}
			setup, err := dump.SetupChangeLog(ctx, p.DatabaseURL, consumer)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %s the change log is not used this run (%v). Every table is read.\n", label, err)
				return inner(ctx, emit)
			}
			if n := len(setup.Installed); n > 0 {
				fmt.Fprintf(out, "%s Change log trigger put in place on %d %s, read in full this run.\n", label, n, pluralWord(int64(n), "table", "tables"))
			}
			if len(setup.Untracked) > 0 {
				names := make([]string, 0, len(setup.Untracked))
				for name := range setup.Untracked {
					names = append(names, name)
				}
				sort.Strings(names)
				shown := names
				if len(shown) > 5 {
					shown = shown[:5]
				}
				var parts []string
				for _, name := range shown {
					parts = append(parts, name+" ("+setup.Untracked[name]+")")
				}
				more := ""
				if len(names) > len(shown) {
					more = fmt.Sprintf(" and %d more", len(names)-len(shown))
				}
				fmt.Fprintf(out, "%s %d %s have no change log trigger and are read every run: %s%s.\n", label, len(names),
					pluralWord(int64(len(names)), "table", "tables"), strings.Join(parts, ", "), more)
			}
			dumper.Carry = func(ctx context.Context, tx pgx.Tx, m *model.SnapshotMetadata, filtered map[string]int64, version int) (map[string]int64, error) {
				pl, err := dump.PlanChangeLog(ctx, tx, dump.PlanChangeLogInput{Meta: m, Filtered: filtered, Prior: prior,
					Consumer: consumer, CanCarry: canCarry, ServerVersionNum: version})
				if err != nil {
					return nil, err
				}
				plan = pl
				return pl.Carry, nil
			}
			return inner(ctx, emit)
		}
	}
	// What the database refused is the source's failure; what the upload
	// refused reaches the source as emit's error, and stays the storage's.
	dumpSource := source
	source = func(ctx context.Context, emit func(write.Entry) error) error {
		var emitErr error
		err := dumpSource(ctx, func(e write.Entry) error {
			if err := emit(e); err != nil {
				emitErr = err
				return err
			}
			return nil
		})
		if err != nil && emitErr == nil && ctx.Err() == nil && !isClassed(err) {
			return stageErr(model.BackupReasonSource, err)
		}
		return err
	}
	host, _ := os.Hostname()
	res, err := write.Run(ctx, b, write.Options{
		SurfaceID: p.SurfaceID, StateDir: p.StateDir, Recipient: p.Recipient, Retention: p.Retention,
		Tier: p.Tier, Planned: p.Planned, NewEpoch: p.NewEpoch, Host: host, SnapshotID: p.SnapshotID, SkipIfUnchanged: p.SkipIfUnchanged,
		// Every run reads every table: a dump has no file times to skip by.
		Rescan:  true,
		Chunker: &format.DatabaseChunker,
		Source:  source,
		OnStart: func(r *write.Result) {
			priorRaw, canCarry = r.PriorState, r.CanCarry
			if r.Opened {
				fmt.Fprintf(out, "%s Epoch %s opened (%s). %s is uploaded%s.\n", label, r.Epoch.EpochID, openedWhy(r),
					strings.ToUpper(everything[:1])+everything[1:], onceThisMonth(r.Epoch))
			}
			if r.Resumed {
				fmt.Fprintf(out, "%s Resuming epoch %s: %d %s (%s) already uploaded %s reused.\n", label, r.Epoch.EpochID,
					r.AdoptedPacks, pluralWord(int64(r.AdoptedPacks), "pack", "packs"), formatBytes(r.AdoptedBytes),
					pluralWord(int64(r.AdoptedPacks), "is", "are"))
			}
			if !r.Opened && !r.Resumed {
				// Said so: only a first run said anything about the epoch.
				fmt.Fprintf(out, "%s Incremental, in epoch %s: only what changed since the last run is uploaded.\n", label, r.Epoch.EpochID)
			}
		},
		State: func(r *write.Result) ([]byte, error) {
			if !p.ChangeLog || plan == nil || dumpMeta == nil {
				return r.PriorState, nil
			}
			return json.Marshal(plan.State(dumpMeta, prior, started))
		},
		RecoveryDoc: repoRecoveryDoc(p.StorageCfg, p.NodeID, p.SurfaceID, p.RecoverySealTo, func() *model.SnapshotMetadata { return meta }),
		Sidecar: func(r *write.Result) ([]byte, error) {
			if dumpMeta == nil {
				return nil, fmt.Errorf("the dump returned no metadata")
			}
			m := *dumpMeta
			now := time.Now().UTC()
			m.SnapshotID, m.NodeID = p.SnapshotID, p.NodeID
			m.CreatedAt, m.CompletedAt = r.Snapshot.CreatedAt, &now
			m.Status = model.SnapshotStatusCompleted
			m.RawSizeBytes, m.EncryptedSizeBytes = r.Snapshot.Stats.LogicalBytes, r.WrittenBytes
			// A run has no single plaintext stream: its digest is the content
			// root, over every file's SHA-256, which a drill recomputes.
			m.Sha256Checksum, m.EncryptedSha256 = r.Snapshot.ContentRoot, ""
			m.StorageURI = epochURI(b, r.Epoch, p.SurfaceID)
			m.DurationMs = backupMilliseconds(started)
			m.Format, m.EpochID, m.ObjectClass = model.SnapshotFormatRepo, r.Epoch.EpochID, r.Class
			recordRetention(&m, p.StorageCfg, repoKeptUntil(r, repoLocked(p.StorageCfg)))
			m.Unlocked = repoLocked(p.StorageCfg) && !repoRunLocked(r, true)
			m.KeptUntil = keptBeyondLock(r)
			m.TableStats = append([]model.TableStat(nil), dumpMeta.TableStats...)
			for i := range m.TableStats {
				t := &m.TableStats[i]
				if n, ok := r.NewBytes[dbrun.TablePath(kind, t.Schema, t.TableName)]; ok {
					t.NewBytes = &n
				}
			}
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
	if res.Skipped {
		fmt.Fprintf(out, "%s Nothing changed since the last run: %s read, no backup written.\n", label, formatBytes(res.ReadBytes))
		return nil, res, nil
	}
	if res.CacheWarning != "" {
		fmt.Fprintf(os.Stderr, "Warning: %s %s\n", label, res.CacheWarning)
	}
	if res.RecoveryWarning != "" {
		fmt.Fprintf(os.Stderr, "Warning: %s %s\n", label, res.RecoveryWarning)
	}
	fmt.Fprintf(out, "%s %d %s, %s %s, %s read, %s stored in %d %s, %s.\n", label, meta.TotalTables,
		pluralWord(int64(meta.TotalTables), tableWord, tablesWord), formatNumber(meta.TotalRows), rowsWord, formatBytes(res.ReadBytes),
		formatBytes(res.WrittenBytes), res.Snapshot.Stats.NewPacks, pluralWord(res.Snapshot.Stats.NewPacks, "pack", "packs"),
		shortDuration(time.Since(started)))
	if p.ChangeLog && plan != nil {
		carried := 0
		for _, t := range meta.TableStats {
			if t.Carried {
				carried++
			}
		}
		if carried > 0 {
			fmt.Fprintf(out, "%s %d of %d %s not read: the change log shows no write since the last run.\n", label, carried,
				meta.TotalTables, pluralWord(int64(meta.TotalTables), "table", "tables"))
		} else if plan.NoCarry != "" {
			fmt.Fprintf(out, "%s Every table read: %s.\n", label, plan.NoCarry)
		}
	}
	printRepoKept(out, label, res, repoLocked(p.StorageCfg))
	cacheKept := true
	if sc != nil {
		if n, err := sc.save(ctx); err != nil {
			cacheKept = false
			fmt.Fprintf(os.Stderr, "Warning: %s the cache could not be kept on the remote server (%v). The next run uploads %s again.\n", label, err, everything)
		} else {
			fmt.Fprintf(out, "%s Cache kept on the remote server (%s, encrypted).\n", label, formatBytes(n))
		}
	}
	// The change log's rows this run saw go only once the run and the state
	// that names its snapshot are kept: until then the next run needs them.
	if p.ChangeLog && plan != nil && res.StateSaved && cacheKept && dumpMeta.SourceSnapshot != "" {
		if _, err := dump.AdvanceChangeLog(ctx, p.DatabaseURL, consumer, dumpMeta.SourceSnapshot); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s the change log was not advanced (%v). The next run reads every table.\n", label, err)
		}
	}
	return meta, res, nil
}

// restoreRepo restores a repository snapshot: a files snapshot into a
// directory, a database run into an empty database.
func restoreRepo(ctx context.Context, rs *repoSnapshot, privateKey, targetDir, targetURL, toSQL string, paths, tables []string, noOwner, salvage bool) error {
	id := rs.Meta.SnapshotID
	if salvage && (runner.IsRepoDatabase(rs.Meta) || runner.IsRepoLaravel(rs.Meta) || runner.IsRepoWordPress(rs.Meta) || toSQL != "") {
		return fmt.Errorf("--salvage restores what verifies of a files snapshot; %s restores whole, in one transaction", id)
	}
	if len(tables) > 0 && !runner.IsRepoDatabase(rs.Meta) {
		return fmt.Errorf("--table restores tables of a database snapshot; %s is a files snapshot", id)
	}
	if toSQL != "" {
		if !runner.IsRepoDatabase(rs.Meta) {
			return fmt.Errorf("snapshot %s is a files snapshot; --to-sql reads PostgreSQL snapshots only", id)
		}
		if rs.Meta.SurfaceType == model.SurfaceTypeSQLite {
			return fmt.Errorf("snapshot %s is a SQLite snapshot; --to-sql reads PostgreSQL snapshots only. Restore it with --target sqlite:///path/new.db and open that file", id)
		}
		if kind := rs.Meta.SurfaceType; kind != "" && kind != model.SurfaceTypePostgres {
			return fmt.Errorf("snapshot %s is a %s snapshot; --to-sql reads PostgreSQL snapshots only", id, kind)
		}
		if len(tables) > 0 || len(paths) > 0 {
			return fmt.Errorf("--to-sql writes the whole snapshot; leave out --table and --path")
		}
		fmt.Printf("Writing %s (epoch %s, %s) to %s as SQL and COPY files\n", id, rs.Epoch.Epoch.EpochID, rs.SurfaceID, toSQL)
		return restoreRepoSQL(ctx, rs, privateKey, toSQL)
	}
	if runner.IsRepoLaravel(rs.Meta) {
		if targetDir == "" || targetURL == "" {
			return fmt.Errorf("snapshot %s is a Laravel app; pass --target with an empty database of its engine "+
				"and --target-dir with an empty directory for its .env and files", id)
		}
		if len(paths) > 0 || len(tables) > 0 {
			return fmt.Errorf("snapshot %s is a Laravel app and restores whole; leave out --path and --table", id)
		}
		fmt.Printf("Restoring %s (epoch %s, %s) into %s and %s\n", id, rs.Epoch.Epoch.EpochID, rs.SurfaceID, dump.RedactURL(targetURL), targetDir)
		return restoreRepoLaravel(ctx, rs, privateKey, targetURL, targetDir)
	}
	if !runner.IsRepoWordPress(rs.Meta) && targetDir != "" && targetURL != "" {
		return fmt.Errorf("snapshot %s is a %s snapshot; give --target or --target-dir, not both", id, rs.Meta.SurfaceType)
	}
	if runner.IsRepoWordPress(rs.Meta) {
		if targetDir == "" || targetURL == "" || dump.SurfaceTypeOfURL(targetURL) != model.SurfaceTypeMySQL {
			return fmt.Errorf("snapshot %s is a WordPress site; pass --target with an empty MySQL or MariaDB database (mysql://...) "+
				"for its database and --target-dir with an empty directory for its files", id)
		}
		if len(paths) > 0 || len(tables) > 0 {
			return fmt.Errorf("snapshot %s is a WordPress site and restores whole; leave out --path and --table", id)
		}
		fmt.Printf("Restoring %s (epoch %s, %s) into %s and %s\n", id, rs.Epoch.Epoch.EpochID, rs.SurfaceID, dump.RedactURL(targetURL), targetDir)
		return restoreRepoWordPress(ctx, rs, privateKey, targetURL, targetDir)
	}
	if !runner.IsRepoDatabase(rs.Meta) {
		if targetDir == "" {
			return fmt.Errorf("snapshot %s is a files snapshot; specify --target-dir to restore", id)
		}
		fmt.Printf("Restoring %s (epoch %s, %s) into %s\n", id, rs.Epoch.Epoch.EpochID, rs.SurfaceID, targetDir)
		return restoreRepoSnapshot(ctx, rs, privateKey, targetDir, paths, salvage)
	}
	if targetURL == "" {
		return fmt.Errorf("snapshot %s is a %s snapshot; pass --target with the URL of an empty database", id, rs.Meta.SurfaceType)
	}
	if len(paths) > 0 {
		return fmt.Errorf("--path restores files; %s is a database snapshot and restores whole", id)
	}
	if rs.Meta.SurfaceType == model.SurfaceTypeSQLite {
		if len(tables) > 0 {
			return fmt.Errorf("--table restores tables of a PostgreSQL snapshot; %s is a SQLite snapshot and restores whole", id)
		}
		if !dump.IsSQLiteURL(targetURL) {
			return fmt.Errorf("snapshot %s is a SQLite snapshot; --target must be a sqlite: URL naming a new file", id)
		}
		fmt.Printf("Restoring %s (epoch %s, %s) into %s\n", id, rs.Epoch.Epoch.EpochID, rs.SurfaceID, dump.RedactURL(targetURL))
		return restoreRepoSQLite(ctx, rs, privateKey, targetURL)
	}
	if kind := rs.Meta.SurfaceType; kind == model.SurfaceTypeMySQL || kind == model.SurfaceTypeMongoDB {
		if len(tables) > 0 {
			return fmt.Errorf("--table restores tables of a PostgreSQL snapshot; %s is a %s snapshot and restores whole", id, kind)
		}
		if dump.SurfaceTypeOfURL(targetURL) != kind {
			return fmt.Errorf("snapshot %s is a %s snapshot; --target must be an empty %s database", id, kind, kind)
		}
		fmt.Printf("Restoring %s (epoch %s, %s) into %s\n", id, rs.Epoch.Epoch.EpochID, rs.SurfaceID, dump.RedactURL(targetURL))
		return restoreRepoEngine(ctx, rs, privateKey, targetURL)
	}
	if dump.SurfaceTypeOfURL(targetURL) != model.SurfaceTypePostgres {
		return fmt.Errorf("snapshot %s is a PostgreSQL snapshot; --target must be a PostgreSQL database", id)
	}
	if len(tables) > 0 {
		fmt.Printf("Restoring %s from %s (epoch %s, %s) into %s\n", strings.Join(tables, ", "), id, rs.Epoch.Epoch.EpochID, rs.SurfaceID, dump.RedactURL(targetURL))
		return restoreRepoTables(ctx, rs, privateKey, targetURL, tables)
	}
	fmt.Printf("Restoring %s (epoch %s, %s) into %s\n", id, rs.Epoch.Epoch.EpochID, rs.SurfaceID, dump.RedactURL(targetURL))
	return restoreRepoDatabase(ctx, rs, privateKey, targetURL, noOwner)
}

// tablePath is the file a database run keeps a table's rows in. A name with
// no schema is in public.
func tablePath(name string) (string, error) {
	schema, table, ok := strings.Cut(name, ".")
	if !ok {
		schema, table = "public", name
	}
	if schema == "" || table == "" || strings.ContainsAny(name, "/\x00") {
		return "", fmt.Errorf("--table %q is not schema.table", name)
	}
	return "data/" + schema + "/" + table + ".copy", nil
}

// openRun reads a run's snapshot, index and files, after checking its
// content root against the one recorded at backup time.
func openRun(ctx context.Context, rs *repoSnapshot, privateKey string) (*read.Repo, read.Index, []read.Item, error) {
	ids, err := unseal.Identities(privateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	id := rs.Meta.SnapshotID
	r := read.Open(rs.Backend, rs.Epoch, ids)
	snap, err := r.Snapshot(ctx, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading snapshot %s: %w", id, err)
	}
	idx, err := r.LoadIndex(ctx, snap)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading snapshot %s: %w", id, err)
	}
	root, _, err := r.ContentRoot(ctx, idx, snap)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading snapshot %s: %w", id, err)
	}
	if err := checkRepoContentRoot(ctx, rs.Meta, id, root); err != nil {
		return nil, nil, nil, err
	}
	files, err := dbrun.Files(ctx, r, idx, snap)
	if err != nil {
		return nil, nil, nil, err
	}
	return r, idx, files, nil
}

// restoreRepoTables loads chosen tables of one run into tables of the same
// definition that are empty in the target, in one transaction
// (tableRestore).
func restoreRepoTables(ctx context.Context, rs *repoSnapshot, privateKey, targetURL string, tables []string) error {
	id := rs.Meta.SnapshotID
	r, idx, files, err := openRun(ctx, rs, privateKey)
	if err != nil {
		return err
	}
	manifest, err := dbrun.ReadManifest(ctx, r, idx, files)
	if err != nil {
		return err
	}
	byPath := map[string]read.Item{}
	for _, f := range files {
		byPath[f.Path] = f
	}
	tr := &tableRestore{id: id, asOf: rs.Meta.CreatedAt, sections: func() (map[string]string, error) {
		return readRunSections(ctx, r, idx, byPath)
	}}
	if err := tr.pick(manifest.TableStats, tables, func(path string) bool { _, ok := byPath[path]; return ok }); err != nil {
		return err
	}
	tx, done, err := tr.begin(ctx, targetURL)
	if err != nil {
		return err
	}
	defer done()
	if err := tr.prepare(ctx, tx); err != nil {
		return err
	}
	for _, p := range tr.picks {
		f := byPath[p.path]
		pr, pw := io.Pipe()
		cat := make(chan error, 1)
		go func() {
			err := r.Cat(ctx, idx, f.Node, pw)
			_ = pw.CloseWithError(err)
			cat <- err
		}()
		copyErr := tr.load(ctx, tx, p, pr)
		_ = pr.CloseWithError(fmt.Errorf("the load stopped"))
		if catErr := <-cat; catErr != nil {
			return fmt.Errorf("reading %s from %s: %w; nothing was restored", p.name, id, catErr)
		}
		if copyErr != nil {
			return copyErr
		}
	}
	return tr.commit(ctx, tx)
}

// readRunSections reads a run's schema and sequence sections, the ones it has.
func readRunSections(ctx context.Context, r *read.Repo, idx read.Index, byPath map[string]read.Item) (map[string]string, error) {
	out := map[string]string{}
	for _, name := range []string{dbrun.PreData, dbrun.PostData, dbrun.Sequences} {
		f, ok := byPath[name]
		if !ok {
			continue
		}
		var b strings.Builder
		if err := r.Cat(ctx, idx, f.Node, &b); err != nil {
			return nil, fmt.Errorf("reading %s from the snapshot: %w", name, err)
		}
		out[name] = b.String()
	}
	return out, nil
}

// restoreRepoSQL writes a database run as the files psql loads without
// SafeGrd, each file checked against its SHA-256 as it is read and the
// content root before any is. A failure removes what was written.
func restoreRepoSQL(ctx context.Context, rs *repoSnapshot, privateKey, dir string) error {
	r, idx, files, err := openRun(ctx, rs, privateKey)
	if err != nil {
		return err
	}
	started := time.Now()
	pr, pw := io.Pipe()
	archived := make(chan error, 1)
	go func() {
		err := dbrun.Archive(ctx, r, idx, files, pw)
		_ = pw.CloseWithError(err)
		archived <- err
	}()
	res, err := dump.ExportSQL(pr, dir)
	_, _ = io.Copy(io.Discard, pr)
	if aerr := <-archived; err == nil {
		err = aerr
	}
	if err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("writing the snapshot as SQL failed, and nothing was kept in %s: %w", dir, err)
	}
	printSQLExport(res, dir, time.Since(started))
	return nil
}

// restoreRepoDatabase loads a database run into an empty database in one
// transaction, which commits only once every file has matched its SHA-256
// and the content root matched the one recorded at backup time.
func restoreRepoDatabase(ctx context.Context, rs *repoSnapshot, privateKey, targetURL string, noOwner bool) error {
	id := rs.Meta.SnapshotID
	r, idx, files, err := openRun(ctx, rs, privateKey)
	if err != nil {
		return err
	}
	started := time.Now()
	pr, pw := io.Pipe()
	archived := make(chan error, 1)
	go func() {
		err := dbrun.Archive(ctx, r, idx, files, pw)
		_ = pw.CloseWithError(err)
		archived <- err
	}()
	restorer := dump.NewNativeRestorer(targetURL)
	restorer.NoOwner = noOwner
	if noOwner {
		fmt.Printf("   Ownership:      not restored (--no-owner); every object belongs to the restoring role\n")
	}
	waited := false
	restorer.BeforeCommit = func() error {
		_, _ = io.Copy(io.Discard, pr)
		waited = true
		return <-archived
	}
	got, err := restorer.Restore(ctx, pr)
	_ = pr.CloseWithError(fmt.Errorf("the restore stopped"))
	if !waited {
		<-archived
	}
	if err != nil {
		return fmt.Errorf("restore failed, and the target was rolled back: %w", err)
	}
	if restorer.ChangeLogRemoved {
		got = dump.WithoutChangeLog(got)
	}
	var rows int64
	for _, t := range got.TableStats {
		rows += t.RowCount
	}
	fmt.Printf("Restored %d %s, %s rows, from %s in %s. Every table matched its SHA-256 and its row count.\n",
		len(got.TableStats), pluralWord(int64(len(got.TableStats)), "table", "tables"), formatNumber(rows), id,
		shortDuration(time.Since(started)))
	printCreatedRoles(restorer.CreatedRoles)
	if restorer.ChangeLogRemoved {
		fmt.Printf("   Change log:     not restored. A backup with change_log: true puts it back.\n")
	}
	return nil
}

// restoreRepoSQLite writes a SQLite run's database to a new file. The file
// appears only once every chunk matched its hash, the content root matched
// the one recorded at backup time, and the copy passed PRAGMA
// integrity_check.
func restoreRepoSQLite(ctx context.Context, rs *repoSnapshot, privateKey, targetURL string) error {
	id := rs.Meta.SnapshotID
	target, err := dump.SQLitePath(targetURL)
	if err != nil {
		return err
	}
	if err := dump.SQLiteCheckEmpty(target); err != nil {
		return err
	}
	r, idx, files, err := openRun(ctx, rs, privateKey)
	if err != nil {
		return err
	}
	started := time.Now()
	pr, pw := io.Pipe()
	archived := make(chan error, 1)
	go func() {
		err := dbrun.Archive(ctx, r, idx, files, pw)
		_ = pw.CloseWithError(err)
		archived <- err
	}()
	got, err := dump.NewSQLiteRestorer(targetURL).Restore(ctx, pr)
	_ = pr.CloseWithError(fmt.Errorf("the restore stopped"))
	if aerr := <-archived; aerr != nil && err == nil {
		// The restorer reads the archive to its end before it renames the
		// file into place, so only closing the archive can fail after that.
		if rerr := dump.SQLiteResetDatabase(target); rerr != nil {
			return fmt.Errorf("restore failed (%w), and %s could not be removed (%v). Delete it by hand: it may not match the backup", aerr, target, rerr)
		}
		err = aerr
	}
	if err != nil {
		return fmt.Errorf("restore failed, and nothing was written to %s: %w", target, err)
	}
	var rows int64
	for _, t := range got.TableStats {
		rows += t.RowCount
	}
	fmt.Printf("Restored %d %s, %s rows, from %s into %s in %s. The database matched its SHA-256 and passed PRAGMA integrity_check.\n",
		len(got.TableStats), pluralWord(int64(len(got.TableStats)), "table", "tables"), formatNumber(rows), id, target,
		shortDuration(time.Since(started)))
	return nil
}

// restoreRepoEngine loads a MySQL or MongoDB run into an empty database
// through its engine's restorer, which reads the run as the archive it was
// taken from: every file checked against its SHA-256 as it is read, and the
// content root against the one recorded at backup time before any is.
// MySQL commits each statement as it goes and mongorestore each document,
// so a failure part way leaves what loaded in the target, which the
// restorer's own error says.
func restoreRepoEngine(ctx context.Context, rs *repoSnapshot, privateKey, targetURL string) error {
	id := rs.Meta.SnapshotID
	r, idx, files, err := openRun(ctx, rs, privateKey)
	if err != nil {
		return err
	}
	started := time.Now()
	pr, pw := io.Pipe()
	archived := make(chan error, 1)
	go func() {
		err := dbrun.Archive(ctx, r, idx, files, pw)
		_ = pw.CloseWithError(err)
		archived <- err
	}()
	got, err := dump.NewRestorer(dump.EngineTypeNative, targetURL).Restore(ctx, pr)
	_, _ = io.Copy(io.Discard, pr) // the rest of the run, checked to its end
	if aerr := <-archived; aerr != nil && err == nil {
		err = fmt.Errorf("reading the snapshot back: %w", aerr)
	}
	if err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}
	_, tableWord, tablesWord, rowsWord := runUnit(rs.Meta.SurfaceType)
	var rows int64
	for _, t := range got.TableStats {
		rows += t.RowCount
	}
	fmt.Printf("Restored %d %s, %s %s, from %s in %s. Every file matched its SHA-256, and every %s its count.\n",
		len(got.TableStats), pluralWord(int64(len(got.TableStats)), tableWord, tablesWord), formatNumber(rows), rowsWord, id,
		shortDuration(time.Since(started)), tableWord)
	return nil
}

// verifyRepoDatabase drills one database run, in memory or into a sandbox,
// and prints it the way verify prints every drill.
func verifyRepoDatabase(ctx context.Context, rs *repoSnapshot, privateKey, sandboxURL string, checks []model.DrillCheck) error {
	verifier := runner.NewVerifier(nil, cfg.ServerURL)
	verifier.Checks = checks
	if cfg.ServerToken != "" {
		verifier.SetServerToken(cfg.ServerToken)
	}
	id := rs.Meta.SnapshotID
	if sandboxURL == "" {
		everything, _, _, _ := runUnit(rs.Meta.SurfaceType)
		fmt.Printf("Verifying %s (epoch %s, %s): checking the packs, reading %s back, restoring it in memory.\n",
			id, rs.Epoch.Epoch.EpochID, rs.SurfaceID, everything)
	} else {
		fmt.Printf("Verifying %s (epoch %s, %s): checking the packs, restoring it into %s.\n",
			id, rs.Epoch.Epoch.EpochID, rs.SurfaceID, dump.RedactURL(sandboxURL))
	}
	report, err := verifier.RunRepoDatabaseDrill(ctx, runner.RepoDrill{Backend: rs.Backend, Epoch: rs.Epoch, Meta: rs.Meta}, privateKey, sandboxURL)
	if err != nil {
		return err
	}
	noteDrillDamage(resolveStateDir("", cfg), rs.SurfaceID, rs, report)
	for _, a := range report.Assertions {
		status := "PASS"
		if !a.Passed {
			status = "FAIL"
		}
		fmt.Printf("   [%s] %s (Expected: %s, Actual: %s)\n", status, a.Name, a.Expected, a.Actual)
		if !a.Passed && a.Message != "" {
			fmt.Printf("          %s\n", a.Message)
		}
	}
	if report.Status != model.VerificationStatusPassed {
		return fmt.Errorf("verification of %s failed: %s", id, report.ErrorMessage)
	}
	// The same closing lines as an archive's drill.
	if sandboxURL == "" {
		fmt.Printf("\nDry restore verified\n")
	} else {
		fmt.Printf("\nFire Drill Passed\n")
	}
	fmt.Printf("   Verification ID: %s\n", report.VerificationID)
	fmt.Printf("   Duration:        %s\n", time.Duration(report.DurationMs*int64(time.Millisecond)).Round(time.Millisecond))
	fmt.Printf("   Tables:          %d\n", report.TablesRestored)
	fmt.Printf("   Rows:            %s\n", formatNumber(report.RowsRestored))
	fmt.Printf("   Certificate:     %s\n", report.CertificateHash)
	return nil
}

// sqliteFileExists says why the SQLite file a URL names cannot be backed up,
// or nil when it is there and is a file.
func sqliteFileExists(databaseURL string) error {
	path, err := dump.SQLitePath(databaseURL)
	if err != nil {
		return err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("SQLite database %s: %w", path, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("SQLite database %s is a directory, not a database file", path)
	}
	return nil
}
