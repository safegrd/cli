package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/storage"
	"github.com/safegrd/cli/pkg/wal"
)

func newWALCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wal",
		Short: "Archive a PostgreSQL surface's WAL and restore it to a point in time",
		Long: `Archives the write-ahead log of a PostgreSQL surface that has a wal: block, so
it restores to any moment inside its window and not only to its last backup.

In postgresql.conf:
  wal_level = replica
  archive_mode = on
  archive_command = 'safegrd wal push --surface <id> %p'

Each WAL file is compressed and encrypted on this host and written to the
surface's storage, unlocked. 'safegrd wal bundle' (the daemon runs it daily)
joins them into one locked object and deletes the unlocked ones.
'safegrd wal base' takes the base backup a restore starts from (the daemon
takes one a week).`,
	}
	cmd.AddCommand(newWALPushCmd(), newWALDrainCmd(), newWALFetchCmd(), newWALBaseCmd(), newWALBundleCmd(), newWALStatusCmd(), newWALRestoreCmd(), newWALPointCmd(), newWALDrillCmd())
	return cmd
}

// walSurface finds a surface that archives its WAL.
func walSurface(c *config.CLIConfig, id string) (*config.SurfaceConfig, error) {
	if id == "" {
		return nil, errors.New("--surface is required: the id of a PostgreSQL or SQLite surface in the config")
	}
	var ids []string
	for i := range c.Surfaces {
		s := c.Surfaces[i]
		ids = append(ids, s.ID)
		if s.ID != id {
			continue
		}
		if s.Type != "" && !strings.EqualFold(s.Type, "postgres") && !strings.EqualFold(s.Type, "sqlite") {
			return nil, fmt.Errorf("surface %s is %s; WAL archiving is for a PostgreSQL or SQLite surface", id, s.Type)
		}
		if s.WAL == nil {
			return nil, fmt.Errorf("surface %s has no wal: block. Add one (wal: {} keeps the defaults) to archive its WAL", id)
		}
		return &s, nil
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("--surface %s: this config defines no surfaces", id)
	}
	return nil, fmt.Errorf("--surface %s: no surface with that id in this config. It has: %s", id, strings.Join(ids, ", "))
}

// walStorageConfig is where the surface's WAL goes. A host whose config
// names its bucket and key never asks the remote server: archive_command
// runs once per WAL file. One that relies on the bucket or key the remote
// server holds asks for them, and fails when it gets no answer instead of
// writing to the config's own storage, which would split the archive.
// PostgreSQL then keeps the file and tries again.
func walStorageConfig(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig) (config.StorageConfig, error) {
	sc := c.Storage
	if s.Storage != nil {
		sc = *s.Storage
	}
	enrolled := c.ServerURL != "" && c.NodeID != "" && c.ServerToken != ""
	if !enrolled || sc.Type == config.StorageTypeHosted {
		return sc, nil
	}
	if s.Storage == nil && !(sc.Type == config.StorageTypeS3 && sc.Bucket != "" && sc.SecretAccessKey != "") {
		resp, err := fetchNodeSink(ctx, c.ServerURL, c.NodeID, c.ServerToken)
		if err != nil {
			return sc, serverFailure(fmt.Errorf("could not ask the remote server where this project's backups go: %w", err))
		}
		if resp.Configured && resp.Sink != nil && resp.Sink.Bucket != "" {
			if err := secondOrigin(resp, &sc); err != nil {
				return sc, err
			}
			applyProjectSink(resp, &sc)
		}
	}
	if sc.Type == config.StorageTypeS3 && sc.SecretAccessKey == "" {
		creds, err := fetchNodeCredentials(ctx, c.ServerURL, c.NodeID, c.ServerToken)
		if err != nil {
			return sc, serverFailure(fmt.Errorf("could not fetch the bucket key the remote server holds: %w", err))
		}
		if creds.Sink != nil && creds.Sink.SecretAccessKey != "" {
			sc.AccessKeyID, sc.SecretAccessKey = creds.Sink.AccessKeyID, creds.Sink.SecretAccessKey
		}
	}
	return sc, nil
}

// walStore opens the surface's WAL storage.
func walStore(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig) (wal.Store, error) {
	sc, err := walStorageConfig(ctx, c, s)
	if err != nil {
		return nil, err
	}
	switch sc.Type {
	case config.StorageTypeLocal, "":
		p := sc.LocalPath
		if p == "" {
			p = "./safegrd-storage"
		}
		return wal.NewDirStore(p, strings.TrimSpace(sc.NodeID))
	case config.StorageTypeS3:
		if hostedLayout(sc) {
			return nil, errors.New("storage.layout: hosted only reads; WAL is archived to a bucket this host writes to")
		}
		prov, err := storage.NewS3Storage(ctx, sc)
		if err != nil {
			return nil, storageFailure(err)
		}
		client, bucket, prefix, mode := prov.ObjectStore()
		return wal.NewS3Store(client, bucket, prefix, mode), nil
	case config.StorageTypeHosted:
		return newWALHostedStore(c, s)
	case config.StorageTypeSFTP:
		return nil, errors.New("WAL archiving is not available on SFTP storage: give the surface a storage block with a bucket, hosted storage or a local directory for its WAL")
	}
	return nil, fmt.Errorf("storage type %q holds no WAL archive", sc.Type)
}

// walArchive is the archive of one surface's cluster. systemID may be ""
// for a command that fills it in.
func walArchive(ctx context.Context, c *config.CLIConfig, surfaceID, systemID string) (*wal.Archive, *config.SurfaceConfig, error) {
	s, err := walSurface(c, surfaceID)
	if err != nil {
		return nil, nil, err
	}
	st, err := walStore(ctx, c, s)
	if err != nil {
		return nil, nil, err
	}
	a := &wal.Archive{Store: st, SurfaceID: s.ID, SystemID: systemID,
		Window: walDays(s.WAL.WindowDays), BaseEvery: walDays(s.WAL.BaseEveryDays),
		IndexCache: filepath.Join(resolveStateDir("", c), "cache", "wal")}
	a.Recipient = c.Encryption.PublicKey
	if s.Encryption != nil && s.Encryption.PublicKey != "" {
		a.Recipient = s.Encryption.PublicKey
	}
	return a, s, nil
}

// walReadFrom points a read at another host's archive on hosted storage,
// where each host's WAL is filed under its own node: a host that replaces
// a lost one restores from the old one's archive.
func walReadFrom(a *wal.Archive, node string) error {
	if node == "" {
		return nil
	}
	h, ok := a.Store.(*walHostedStore)
	if !ok {
		return errors.New("--node reads another host's archive on hosted storage. In your own bucket, give this host the same storage settings as the one that archived")
	}
	h.readNode = node
	return nil
}

func walDays(n int) time.Duration {
	if n <= 0 {
		n = 7
	}
	return time.Duration(n) * 24 * time.Hour
}

// walSystems lists the clusters a surface's archive holds, or the one named.
func walSystems(ctx context.Context, a *wal.Archive, named string) ([]string, error) {
	if named != "" {
		if err := wal.ValidSystemID(named); err != nil {
			return nil, err
		}
		return []string{named}, nil
	}
	ids, err := wal.Systems(ctx, a.Store, a.SurfaceID)
	if err != nil {
		return nil, storageFailure(err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("surface %s has no WAL archive in %s yet. Set archive_command, and take a base backup with 'safegrd wal base --surface %s'", a.SurfaceID, a.Store.Describe(), a.SurfaceID)
	}
	return ids, nil
}

// oneSystem is the one cluster a fetch or a restore reads.
func oneSystem(ctx context.Context, a *wal.Archive, named string) (string, error) {
	ids, err := walSystems(ctx, a, named)
	if err != nil {
		return "", err
	}
	if len(ids) > 1 {
		return "", fmt.Errorf("surface %s archives more than one cluster (%s); name one with --system", a.SurfaceID, strings.Join(ids, ", "))
	}
	return ids[0], nil
}

func walLockLine(a *wal.Archive, until time.Time) string {
	switch {
	case !until.IsZero():
		return "locked until " + until.UTC().Format("2006-01-02 15:04 UTC")
	case a.Store.Locks():
		return "not locked"
	}
	if _, ok := a.Store.(*wal.DirStore); ok {
		return "not locked: a local directory"
	}
	return "not locked: the storage has worm_mode NONE"
}

func newWALPushCmd() *cobra.Command {
	var surfaceID, pgdata string
	cmd := &cobra.Command{
		Use:   "push <path>",
		Short: "Archive one WAL file (PostgreSQL's archive_command)",
		Long: `Archives one WAL file and exits 0 only once it is stored, so PostgreSQL never
recycles a file the archive does not hold. It prints nothing on success, since
PostgreSQL logs whatever an archive_command writes.

  archive_command = 'safegrd wal push --surface <id> %p'

The cluster's system identifier is read from global/pg_control under the
current directory, which is the data directory when PostgreSQL runs it.

With wal.spool on, it returns once the file is copied into the spool and
synced to disk, and the daemon uploads the spool (safegrd wal drain). With
wal.queue_max set, the oldest WAL waiting to leave the host past that size
is let go without being archived, and said, so a full pg_wal does not stop
the database.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, s, err := walArchive(cmd.Context(), cfg, surfaceID, "")
			if err != nil {
				return err
			}
			if err := refuseSQLite(s, "there is no archive_command to set"); err != nil {
				return err
			}
			if a.Recipient == "" {
				return fmt.Errorf("encryption.public_key is not set, and WAL is encrypted to it")
			}
			if a.SystemID, err = wal.ReadSystemID(pgdata); err != nil {
				return err
			}
			p := args[0]
			if !filepath.IsAbs(p) {
				p = filepath.Join(pgdata, p)
			}
			if err := walPushFile(cmd.Context(), a, s, pgdata, p); err != nil {
				return storageFailure(err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Surface id from the config (required)")
	cmd.Flags().StringVar(&pgdata, "pgdata", ".", "The cluster's data directory")
	return cmd
}

func newWALFetchCmd() *cobra.Command {
	var surfaceID, systemID, keyPath, privKey, node string
	cmd := &cobra.Command{
		Use:   "fetch <name> <path>",
		Short: "Write one archived WAL file to a path (PostgreSQL's restore_command)",
		Long: `Writes one WAL file from the archive to path. It exits 1, printing nothing,
when the archive does not hold the file, which is how a restore learns it has
replayed all there is. Any other failure (the storage does not answer, the key
is missing, a file does not decrypt to what was pushed) exits 140 after a few
tries, which makes PostgreSQL stop recovery instead of ending it there and
promoting with WAL missing; fix the cause and start it again.
'safegrd wal restore' writes the restore_command.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := walFetch(cmd.Context(), args[0], args[1], surfaceID, systemID, keyPath, privKey, node)
			if errors.Is(err, wal.ErrNotFound) {
				return &exitError{code: 1}
			}
			if err != nil {
				return &exitError{code: exitRecoveryStop, err: fmt.Errorf("%w. Recovery stops here rather than promote with WAL missing; fix this and start PostgreSQL again", err)}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Surface id from the config (required)")
	cmd.Flags().StringVar(&systemID, "system", "", "The cluster's system identifier, when the archive holds more than one")
	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to the age identity (default encryption.key_path)")
	cmd.Flags().StringVar(&privKey, "private-key", "", "The age identity, as env:VAR or file:/path")
	cmd.Flags().StringVar(&node, "node", "", "On hosted storage, read the archive another host of the organization wrote")
	return cmd
}

const (
	// walFetchAttempts is how many times a fetch asks the storage for a file
	// before it gives up: restore_command runs once per WAL file, and a
	// storage that does not answer for a moment should not end a replay.
	walFetchAttempts = 4
	walFetchBackoff  = 2 * time.Second
)

// walFetch writes one archived WAL file to dst, trying again after a
// failure that is not the archive lacking the file.
func walFetch(ctx context.Context, name, dst, surfaceID, systemID, keyPath, privKey, node string) error {
	a, s, err := walArchive(ctx, cfg, surfaceID, "")
	if err != nil {
		return err
	}
	// A file fetched ahead by the call before is already here.
	ahead := filepath.Join(filepath.Dir(dst), ".safegrd-prefetch")
	if wal.IsSegment(name) {
		if err := os.Rename(filepath.Join(ahead, name), dst); err == nil {
			return nil
		}
	}
	if err := walReadFrom(a, node); err != nil {
		return err
	}
	if a.SystemID, err = oneSystem(ctx, a, systemID); err != nil {
		return err
	}
	if a.Identity, err = resolveIdentity(ctx, keyPath, privKey); err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		err = walFetchOnce(ctx, a, name, dst)
		if err == nil {
			walFetchAhead(ctx, a, name, dst, ahead, walParallel(s))
			return nil
		}
		if errors.Is(err, wal.ErrNotFound) || attempt+1 >= walFetchAttempts {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(walFetchBackoff << attempt):
		}
	}
}

// walFetchAhead fetches the n WAL files after name into dir, at once, so
// PostgreSQL's next restore_command calls find them there. Files before
// name are removed; a file the archive does not hold yet ends nothing,
// since the next call fetches it itself.
func walFetchAhead(ctx context.Context, a *wal.Archive, name, dst, dir string, n int) {
	if !wal.IsSegment(name) || n < 1 {
		return
	}
	info, err := os.Stat(dst)
	if err != nil || info.Size() <= 0 {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	if old, err := os.ReadDir(dir); err == nil {
		for _, e := range old {
			if e.Name() <= name {
				os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	var wg sync.WaitGroup
	for _, next := range wal.NextSegments(name, uint64(info.Size()), n) {
		if _, err := os.Stat(filepath.Join(dir, next)); err == nil {
			continue
		}
		wg.Add(1)
		go func(next string) {
			defer wg.Done()
			_ = walFetchOnce(ctx, a, next, filepath.Join(dir, next)) // a miss is fetched by its own call
		}(next)
	}
	wg.Wait()
}

// walFetchOnce writes the file beside dst and renames it into place, so a
// fetch that fails part way leaves no half file for PostgreSQL to read.
func walFetchOnce(ctx context.Context, a *wal.Archive, name, dst string) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".safegrd-fetch-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	ferr := a.Fetch(ctx, name, tmp)
	if cerr := tmp.Close(); ferr == nil {
		ferr = cerr
	}
	if ferr != nil {
		return ferr
	}
	return os.Rename(tmp.Name(), dst)
}

func newWALBaseCmd() *cobra.Command {
	var surfaceID string
	cmd := &cobra.Command{
		Use:   "base",
		Short: "Take a base backup of a PostgreSQL surface into its WAL archive",
		Long: `Runs pg_basebackup against the surface's database and streams it, compressed
and encrypted, into the archive as one locked object. The base is complete
once every WAL file it needs is archived; the command waits for that.

The surface's role needs the REPLICATION attribute, and pg_hba.conf a
'replication' line for this host.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			a, s, err := walArchive(ctx, cfg, surfaceID, "")
			if err != nil {
				return err
			}
			if err := refuseSQLite(s, "it takes a new base itself every wal.base_every_days"); err != nil {
				return err
			}
			if a.Recipient == "" {
				return fmt.Errorf("encryption.public_key is not set, and the base backup is encrypted to it")
			}
			info, err := walBase(ctx, cfg, a, s)
			if err != nil {
				return err
			}
			fmt.Printf("Base backup %s (%s, %s), %s\n", info.BaseID, formatBytes(info.StoredBytes),
				info.EndedAt.Sub(info.StartedAt).Round(time.Second), walLockLine(a, info.LockedUntil))
			fmt.Printf("   WAL from %s to %s, PostgreSQL %d, system %s\n", info.StartWAL, info.EndWAL, info.Major(), info.SystemID)
			if from := info.SourceWords(); from != "" {
				fmt.Printf("   Taken from %s; its WAL comes from the primary's archive\n", from)
			}
			warnChecksumFailures(info)
			return nil
		},
	}
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Surface id from the config (required)")
	return cmd
}

// walBase takes one base backup of the surface.
func walBase(ctx context.Context, c *config.CLIConfig, a *wal.Archive, s *config.SurfaceConfig) (wal.BaseInfo, error) {
	connURL, srv, err := walServer(ctx, c, s)
	if err != nil {
		return wal.BaseInfo{}, err
	}
	return a.Base(ctx, walBaseOptions(a, s, connURL, srv))
}

// walBaseOptions are a base backup's options. With a spool, the base is
// complete once its WAL is in the archive, and that WAL waits on this host
// until it is uploaded, so the wait uploads the spool.
func walBaseOptions(a *wal.Archive, s *config.SurfaceConfig, connURL string, srv wal.Server) wal.BaseOptions {
	o := wal.BaseOptions{ConnURL: connURL, Server: srv}
	if s.WAL != nil && s.WAL.Spool {
		o.BeforeWALCheck = func(ctx context.Context) {
			b := *a
			if _, _, err := walDrain(ctx, &b, s); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Surface %s: uploading the spool: %v\n", s.ID, err)
			}
		}
	}
	return o
}

// walServer connects to the surface's database for replication and says
// which cluster it is.
func walServer(ctx context.Context, c *config.CLIConfig, s *config.SurfaceConfig) (string, wal.Server, error) {
	if s.FromSafeGrd() {
		st := loadDaemonState(filepath.Join(resolveStateDir("", c), "daemon_state.json"))
		node := s.ID
		if ss, ok := st.Surfaces[s.ID]; ok && ss.ServerNodeID != "" {
			node = ss.ServerNodeID
		}
		fetchHeldSurfaceSecret(ctx, c, node, s)
	}
	connURL, err := resolveSurfaceDatabaseURL(ctx, c, s)
	if err != nil {
		return "", wal.Server{}, err
	}
	if connURL == "" {
		return "", wal.Server{}, fmt.Errorf("surface %s names no database_url", s.ID)
	}
	srv, err := wal.Identify(ctx, connURL)
	if err != nil {
		return "", wal.Server{}, classed(exitSource, err)
	}
	return connURL, srv, nil
}

func newWALBundleCmd() *cobra.Command {
	var surfaceID string
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Lock a surface's unlocked WAL in one bundle and delete the pieces",
		Long: `Joins the encrypted bytes of every unlocked WAL file into one locked object,
reads it back, and deletes the unlocked files it holds. It needs no private
key. The daemon runs it once a day, and sooner when the unlocked WAL passes
wal.bundle_mb.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			a, _, err := walArchive(ctx, cfg, surfaceID, "")
			if err != nil {
				return err
			}
			systems, err := walSystems(ctx, a, "")
			if err != nil {
				return err
			}
			conflicts, err := walBundleAll(ctx, a, systems)
			if err != nil {
				return err
			}
			if len(conflicts) > 0 {
				return errors.New(walConflictWords(conflicts))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Surface id from the config (required)")
	return cmd
}

// walConflictWords says which WAL file names were archived twice with
// different contents. Those files stay unlocked and out of every bundle
// until a person looks at them.
func walConflictWords(conflicts []string) string {
	return fmt.Sprintf("%d WAL file name(s) were archived twice with different contents and are left out of the bundle: %s. Check that only one cluster archives to this surface",
		len(conflicts), strings.Join(conflicts, ", "))
}

// walBundleAll bundles each cluster's unlocked WAL and says what it did. The
// names archived twice with different contents come back on their own: the
// bundle is done, and they are the caller's to report.
func walBundleAll(ctx context.Context, a *wal.Archive, systems []string) ([]string, error) {
	var conflicts []string
	for _, sys := range systems {
		a.SystemID = sys
		res, err := a.Bundle(ctx)
		if err != nil {
			return nil, storageFailure(err)
		}
		switch {
		case res.Files > 0:
			fmt.Printf("Bundled %d WAL files (%s), %s\n", res.Files, formatBytes(res.Bytes), walLockLine(a, res.LockedUntil))
		case res.Deleted == 0 && res.Kept == 0:
			fmt.Printf("No unlocked WAL to bundle for system %s.\n", sys)
		}
		if res.Deleted > 0 {
			fmt.Printf("   Deleted %d unlocked WAL files.\n", res.Deleted)
		}
		if res.Kept > 0 {
			fmt.Fprintf(os.Stderr, "Warning: %d bundled WAL files stay unlocked in %s: %v. They are in a locked bundle too; delete them, or allow s3:DeleteObjectVersion under wal/ and run this again.\n",
				res.Kept, a.Store.Describe(), res.KeptWhy)
		}
		conflicts = append(conflicts, res.Conflicts...)
	}
	return conflicts, nil
}

func newWALStatusCmd() *cobra.Command {
	var surfaceID, systemID, node string
	var jsonOut, check bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show a surface's WAL archive: its base backups, its window and any gap",
		Long: `Lists the base backups and WAL a surface's archive holds and the window a
restore can reach. It exits 1 when there is no complete base backup, or when a
WAL file is missing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			a, s, err := walArchive(ctx, cfg, surfaceID, "")
			if err != nil {
				return err
			}
			if err := walReadFrom(a, node); err != nil {
				return err
			}
			systems, err := walSystems(ctx, a, systemID)
			if err != nil {
				return err
			}
			var all []wal.Status
			var problems []string
			sqlite := walIsSQLite(s)
			for _, sys := range systems {
				a.SystemID = sys
				status := a.Status
				if sqlite {
					status = a.SQLiteStatus
				}
				st, err := status(ctx)
				if err != nil {
					return storageFailure(err)
				}
				all = append(all, st)
				if !jsonOut {
					printWALStatus(a, st)
					printWALQueue(s, sys)
				}
				if !st.HasWindow {
					problems = append(problems, fmt.Sprintf("system %s has no base backup with unbroken WAL after it", sys))
				}
				if len(st.Gaps) > 0 {
					problems = append(problems, fmt.Sprintf("system %s is missing WAL from %s", sys, st.Gaps[0].First))
				}
				if check {
					probs, err := a.CheckRecords(ctx)
					if err != nil {
						return storageFailure(err)
					}
					for _, p := range probs {
						if !jsonOut {
							fmt.Printf("   Record:        %s: %s\n", p.Key, p.Problem)
						}
						problems = append(problems, fmt.Sprintf("%s: %s", p.Key, p.Problem))
					}
					if len(probs) == 0 && !jsonOut {
						fmt.Printf("   Records:       every base record and bundle index has two whole, matching copies\n")
					}
				}
			}
			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(all); err != nil {
					return err
				}
			}
			if len(problems) > 0 {
				return errors.New(strings.Join(problems, "; "))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Surface id from the config (required)")
	cmd.Flags().StringVar(&systemID, "system", "", "Show only this cluster's archive")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Print the status as JSON")
	cmd.Flags().BoolVar(&check, "check", false, "Also read both copies of every base record and bundle index, and name any pair that is not whole and alike")
	cmd.Flags().StringVar(&node, "node", "", "On hosted storage, show the archive another host of the organization wrote")
	return cmd
}

// printWALQueue says what waits in the surface's spool and what WAL of
// system sys was let go past wal.queue_max, from this host's record.
func printWALQueue(s *config.SurfaceConfig, sys string) {
	if s.WAL == nil || (!s.WAL.Spool && s.WAL.QueueMax == "") {
		return
	}
	sp := walSpool(cfg, s)
	if files, err := sp.List(); err == nil && len(files) > 0 {
		var n int64
		for _, f := range files {
			n += f.Size
		}
		fmt.Printf("   Spooled:       %d WAL %s (%s) wait to be uploaded\n", len(files), pluralWord(int64(len(files)), "file", "files"), formatBytes(n))
	}
	dropped, err := sp.Dropped()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		return
	}
	var mine []wal.Dropped
	for _, d := range dropped {
		if d.System == sys {
			mine = append(mine, d)
		}
	}
	if len(mine) > 0 {
		last := mine[len(mine)-1]
		fmt.Printf("   Let go:        %d WAL %s past wal.queue_max, newest %s at %s. No restore replays past one; the window starts at the next base backup after it\n",
			len(mine), pluralWord(int64(len(mine)), "file", "files"), last.Name, last.At.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
}

func printWALStatus(a *wal.Archive, st wal.Status) {
	ts := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }
	fmt.Printf("Surface %s, system %s, in %s\n", a.SurfaceID, a.SystemID, a.Describe())
	if st.HasWindow {
		fmt.Printf("   Recoverable:   %s to %s\n", ts(st.WindowFrom), ts(st.WindowTo))
	} else {
		fmt.Printf("   Recoverable:   nothing yet\n")
	}
	switch {
	case !a.Store.Locks():
		fmt.Printf("   Locked:        no, %s\n", strings.TrimPrefix(walLockLine(a, time.Time{}), "not locked: "))
	case st.LockedTo.IsZero() && !st.NewestPush.IsZero():
		fmt.Printf("   Locked to:     nothing bundled yet; WAL to %s is kept, not locked\n", ts(st.NewestPush))
	case st.NewestPush.After(st.LockedTo):
		fmt.Printf("   Locked to:     %s; WAL to %s is kept, not locked\n", ts(st.LockedTo), ts(st.NewestPush))
	case !st.LockedTo.IsZero():
		fmt.Printf("   Locked to:     %s\n", ts(st.LockedTo))
	}
	fmt.Printf("   Base backups:  %d", len(st.Bases))
	if n := len(st.Bases); n > 0 {
		b := st.Bases[n-1]
		if b.Kind == "sqlite" {
			fmt.Printf(", newest %s ended %s (generation %s)", b.BaseID, ts(b.EndedAt), b.Generation)
		} else {
			fmt.Printf(", newest %s ended %s (PostgreSQL %d)", b.BaseID, ts(b.EndedAt), b.Major())
		}
	}
	fmt.Println()
	for _, b := range st.Bases {
		if b.ChecksumFailures > 0 {
			fmt.Printf("   Damaged pages: base %s, %s (failed their checksum)\n", b.BaseID, b.ChecksumWords())
		}
	}
	for _, id := range st.Incomplete {
		fmt.Printf("   Incomplete:    %s (its WAL never all arrived, or the run stopped)\n", id)
	}
	fmt.Printf("   WAL files:     %d (%d unlocked, %s; %d bundles, %s)\n", st.Files, st.Unlocked, formatBytes(st.UnlockedBytes), st.Bundles, formatBytes(st.BundledBytes))
	for _, g := range st.Gaps {
		line := fmt.Sprintf("   Missing:       %s", g.First)
		if g.Last != g.First {
			line += " to " + g.Last
		}
		if len(g.Breaks) > 0 {
			line += "; replay from " + strings.Join(g.Breaks, ", ") + " stops here"
		}
		fmt.Println(line)
	}
	for _, n := range st.Conflicts {
		fmt.Printf("   Conflict:      %s, archived twice with different contents\n", n)
	}
}

func newWALRestoreCmd() *cobra.Command {
	var surfaceID, systemID, to, toPoint, toLSN, toXID, timeline, pgdata, out, keyPath, privKey, node string
	var exclusive bool
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore a PostgreSQL surface to a point in time into an empty data directory",
		Long: `Unpacks the newest base backup that ends before --to into an empty directory
and sets PostgreSQL up to replay the archived WAL to that time and promote:
recovery.signal, and restore_command and recovery_target_time in
postgresql.auto.conf. Start PostgreSQL on the directory to run the replay.

Run it as the user PostgreSQL will run as: restore_command calls this CLI
with the same config and key. Archiving is turned off on the restored cluster.

A SQLite surface is restored to a new database file instead: --out names it.
The daemon's segments are about a second apart, so the file holds every
transaction committed up to the last segment pushed at or before --to.

--to takes RFC 3339 (2026-10-17T14:52:00Z) or "2026-10-17 14:52:00", read as UTC,
or "latest": every archived WAL file is replayed, which is the restore after a
lost host. A time at or after the last commit in the archive is refused by
PostgreSQL ("recovery ended before configured recovery target was reached"),
so use latest for the newest state.

--to-lsn 16/B374D848 replays to a position in the WAL, and --to-xid 1234567 to
just after a transaction commits; --exclusive stops just before either, or
before --to's moment. --timeline follows a timeline other than the newest
(latest, current or its number); the archive's history of it is checked
before anything is written.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			var target time.Time
			var err error
			latest := strings.EqualFold(strings.TrimSpace(to), "latest")
			targets := 0
			for _, t := range []string{to, toPoint, toLSN, toXID} {
				if t != "" {
					targets++
				}
			}
			switch {
			case targets > 1:
				return errors.New("--to, --to-point, --to-lsn and --to-xid are each a target; give one")
			case exclusive && (latest || toPoint != ""):
				return errors.New("--exclusive stops before a time, a position or a transaction, not before a restore point or the end of the archive")
			case toLSN != "":
				if _, err := wal.ParseLSN(toLSN); err != nil {
					return fmt.Errorf("--to-lsn: %w; give it as PostgreSQL prints it, such as 16/B374D848", err)
				}
			case toXID != "":
			case toPoint == "" && !latest:
				if target, err = parseWALTarget(to); err != nil {
					return err
				}
			}
			a, s, err := walArchive(ctx, cfg, surfaceID, "")
			if err != nil {
				return err
			}
			if err := walReadFrom(a, node); err != nil {
				return err
			}
			if a.SystemID, err = oneSystem(ctx, a, systemID); err != nil {
				return err
			}
			if a.Identity, err = resolveIdentity(ctx, keyPath, privKey); err != nil {
				return err
			}
			if walIsSQLite(s) {
				if toLSN != "" || toXID != "" || timeline != "" || exclusive {
					return errors.New("--to-lsn, --to-xid, --exclusive and --timeline are PostgreSQL's; a SQLite surface restores to a time or a restore point")
				}
				return walRestoreSQLite(ctx, a, target, toPoint, out)
			}
			if pgdata == "" {
				return errors.New("--pgdata is required: an empty directory to restore into")
			}
			dir, err := filepath.Abs(pgdata)
			if err != nil {
				return err
			}
			fetch, err := walFetchCommand(a, keyPath, privKey, node)
			if err != nil {
				return err
			}
			o := wal.RestoreOptions{Target: target, PGData: dir, FetchCommand: fetch, TargetLSN: strings.TrimSpace(toLSN),
				TargetXID: strings.TrimSpace(toXID), Exclusive: exclusive, Timeline: strings.TrimSpace(timeline)}
			if toPoint != "" {
				points, err := a.RestorePoints(ctx)
				if err != nil {
					return storageFailure(err)
				}
				for _, p := range points {
					if p.Name == toPoint {
						o.Target, o.TargetName = p.At, p.Name
					}
				}
				if o.TargetName == "" {
					return fmt.Errorf("the archive records no restore point %s. 'safegrd wal point' makes one", toPoint)
				}
				target = o.Target
			}
			res, err := a.Restore(ctx, o)
			if err != nil {
				return err
			}
			fmt.Printf("Restored base %s (PostgreSQL %d) into %s\n", res.Base.BaseID, res.Base.Major(), dir)
			goal := target.UTC().Format("2006-01-02 15:04:05 UTC")
			switch {
			case toPoint != "":
				goal = "restore point " + toPoint
			case toLSN != "":
				goal = "WAL position " + toLSN
			case toXID != "":
				goal = "transaction " + toXID
			case latest:
				goal = fmt.Sprintf("the end of the archive (pushed %s)", res.ArchiveEnd.UTC().Format("2006-01-02 15:04:05 UTC"))
			}
			if exclusive {
				goal = "just before " + goal
			}
			if timeline != "" {
				goal += " on timeline " + timeline
			}
			fmt.Printf("   Replays WAL to %s and promotes, when PostgreSQL %d starts on it:\n", goal, res.Base.Major())
			if res.NoConf {
				// Debian and Ubuntu keep the configuration in /etc, and
				// their postgresql.conf names the original data_directory:
				// started with it as is, PostgreSQL would open the live
				// cluster, not this one.
				fmt.Printf("   The base holds no postgresql.conf: the cluster kept its configuration outside its data directory.\n")
				fmt.Printf("   Copy postgresql.conf, pg_hba.conf and pg_ident.conf into %s, take data_directory, hba_file and ident_file out of the copy, set a free port, then:\n", dir)
			}
			fmt.Printf("   pg_ctl -D %s start\n", dir)
			if res.CheckpointKept != "" {
				fmt.Fprintf(os.Stderr, "Warning: %s. Its checkpoint was left as the base had it: keep backup_label in %s, or the cluster starts from the wrong place.\n", res.CheckpointKept, dir)
			} else {
				fmt.Printf("   It starts only with backup_label in place: keep that file.\n")
			}
			fmt.Printf("   Archiving is off on it (postgresql.auto.conf). Turn it on once this is the database you keep.\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Surface id from the config (required)")
	cmd.Flags().StringVar(&systemID, "system", "", "The cluster's system identifier, when the archive holds more than one")
	cmd.Flags().StringVar(&to, "to", "", "The moment to restore to, or latest for the end of the archive")
	cmd.Flags().StringVar(&toPoint, "to-point", "", "A restore point to restore to, as 'safegrd wal point' named it")
	cmd.Flags().StringVar(&toLSN, "to-lsn", "", "A WAL position to restore to, such as 16/B374D848")
	cmd.Flags().StringVar(&toXID, "to-xid", "", "A transaction id to restore to, just after it commits")
	cmd.Flags().BoolVar(&exclusive, "exclusive", false, "Stop just before the target instead of just after it")
	cmd.Flags().StringVar(&timeline, "timeline", "", "The timeline to follow: latest (the default), current, or its number")
	cmd.Flags().StringVar(&pgdata, "pgdata", "", "PostgreSQL: an empty directory to restore into")
	cmd.Flags().StringVar(&out, "out", "", "SQLite: the database file to write; it must not exist")
	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to the age identity (default encryption.key_path)")
	cmd.Flags().StringVar(&privKey, "private-key", "", "The age identity, as env:VAR or file:/path")
	cmd.Flags().StringVar(&node, "node", "", "On hosted storage, restore from the archive another host of the organization wrote (a host that replaces a lost one)")
	return cmd
}

func parseWALTarget(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("--to or --to-point is required: the moment or the restore point to restore to, or --to latest")
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02 15:04"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("--to %q is not a time; use 2026-10-17T14:52:00Z or \"2026-10-17 14:52:00\" (UTC)", s)
}

// walFetchCommand is the restore_command a restored cluster calls: this
// binary, this config and this key.
func walFetchCommand(a *wal.Archive, keyPath, privKey, node string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	q := shellQuote
	parts := []string{q(exe)}
	if cfgFile != "" {
		abs, err := filepath.Abs(cfgFile)
		if err != nil {
			return "", err
		}
		parts = append(parts, "--config", q(abs))
	}
	parts = append(parts, "wal", "fetch", "--surface", q(a.SurfaceID), "--system", a.SystemID)
	if node != "" {
		parts = append(parts, "--node", q(node))
	}
	if keyPath != "" {
		abs, err := filepath.Abs(keyPath)
		if err != nil {
			return "", err
		}
		parts = append(parts, "--key-path", q(abs))
	}
	// A key given by reference is passed on as the reference, never as the
	// key: postgresql.auto.conf is not a place for it.
	if strings.HasPrefix(privKey, "env:") || strings.HasPrefix(privKey, "file:") {
		parts = append(parts, "--private-key", q(privKey))
	}
	return strings.Join(append(parts, "%f", "%p"), " "), nil
}

// shellQuote quotes s for /bin/sh, which runs restore_command.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=@") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// walIsSQLite says whether a surface's WAL is SQLite's, which the daemon
// follows, rather than PostgreSQL's, which archive_command pushes.
func walIsSQLite(s *config.SurfaceConfig) bool { return strings.EqualFold(s.Type, "sqlite") }

// refuseSQLite is the answer of a command that is PostgreSQL's only.
func refuseSQLite(s *config.SurfaceConfig, what string) error {
	if !walIsSQLite(s) {
		return nil
	}
	return fmt.Errorf("surface %s is SQLite, whose WAL the resident daemon follows ('safegrd daemon run'); %s", s.ID, what)
}

// walRestoreSQLite writes a SQLite surface's database as it was at the
// target, or at a restore point, to a new file.
func walRestoreSQLite(ctx context.Context, a *wal.Archive, target time.Time, toPoint, out string) error {
	if out == "" {
		return errors.New("--out is required for a SQLite surface: the database file to write")
	}
	o := wal.SQLiteRestoreOptions{Target: target, Out: out}
	if toPoint != "" {
		points, err := a.RestorePoints(ctx)
		if err != nil {
			return storageFailure(err)
		}
		for i := range points {
			if points[i].Name == toPoint {
				o.Point = &points[i]
			}
		}
		if o.Point == nil {
			return fmt.Errorf("the archive records no restore point %s", toPoint)
		}
	}
	res, err := a.RestoreSQLite(ctx, o)
	if err != nil {
		return err
	}
	ts := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }
	fmt.Printf("Restored %s from generation %s (%d segments), integrity_check ok\n", out, res.Base.Generation, res.Segments)
	switch {
	case o.Point != nil:
		fmt.Printf("   At restore point %s (%s)\n", o.Point.Name, ts(o.Point.At))
	case target.IsZero():
		fmt.Printf("   Holds every transaction committed by %s, the last segment in the archive\n", ts(res.ReachedAt))
	default:
		fmt.Printf("   Holds every transaction committed by %s, the last segment at or before %s\n", ts(res.ReachedAt), ts(target))
	}
	return nil
}

// walSpool is a surface's spool, and the record of WAL let go past
// wal.queue_max beside it.
func walSpool(c *config.CLIConfig, s *config.SurfaceConfig) wal.Spool {
	root := s.WAL.SpoolDir
	if root == "" {
		root = filepath.Join(resolveStateDir("", c), "wal-spool")
	}
	return wal.Spool{Dir: filepath.Join(root, s.ID)}
}

// walParallel is wal.parallel, or 4.
func walParallel(s *config.SurfaceConfig) int {
	if s.WAL.Parallel > 0 {
		return s.WAL.Parallel
	}
	return 4
}

// walQueueMax is wal.queue_max in bytes, 0 when it is not set.
func walQueueMax(s *config.SurfaceConfig) (int64, error) {
	given := strings.TrimSpace(s.WAL.QueueMax)
	if given == "" {
		return 0, nil
	}
	num, mult := given, int64(1)
	for _, u := range []struct {
		suffix string
		m      int64
	}{{"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"kB", 1 << 10}} {
		if strings.HasSuffix(given, u.suffix) {
			num, mult = strings.TrimSpace(strings.TrimSuffix(given, u.suffix)), u.m
			break
		}
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n <= 0 || mult == 1 {
		return 0, fmt.Errorf("wal.queue_max %q is not a size such as 8GB or 512MB", given)
	}
	return n * mult, nil
}

// walPushFile archives one WAL file as wal push does: into the spool when
// wal.spool is on, else straight to the archive. Past wal.queue_max the
// oldest WAL waiting is let go, said on stderr and recorded.
func walPushFile(ctx context.Context, a *wal.Archive, s *config.SurfaceConfig, pgdata, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	name := filepath.Base(path)
	max, err := walQueueMax(s)
	if err != nil {
		return err
	}
	sp := walSpool(cfg, s)
	if s.WAL.Spool {
		if max > 0 && wal.IsSegment(name) {
			dropped, derr := sp.DropOldest(max, int64(len(body)))
			sayDropped(sp, s, max, dropped, "the spool is full and the daemon has not uploaded it")
			if derr != nil {
				return derr
			}
		}
		return sp.Add(a.SystemID, name, body)
	}
	err = a.Push(ctx, name, bytes.NewReader(body))
	if err == nil || max == 0 || !wal.IsSegment(name) {
		return err
	}
	// PostgreSQL archives in order, so the file it asks for while others
	// wait is the oldest.
	queued, qerr := wal.ReadyBytes(pgdata, int64(len(body)))
	if qerr != nil || queued <= max {
		return err
	}
	sayDropped(sp, s, max, []wal.Dropped{{System: a.SystemID, Name: name, At: time.Now().UTC()}}, "the archive cannot be reached: "+err.Error())
	return nil
}

// sayDropped records WAL let go past wal.queue_max and says it on stderr,
// which PostgreSQL writes to its log for archive_command.
func sayDropped(sp wal.Spool, s *config.SurfaceConfig, max int64, dropped []wal.Dropped, why string) {
	if len(dropped) == 0 {
		return
	}
	if err := sp.RecordDropped(dropped...); err != nil {
		fmt.Fprintf(os.Stderr, "Error: surface %s: the record of WAL let go could not be written: %v\n", s.ID, err)
	}
	names := make([]string, 0, len(dropped))
	for _, d := range dropped {
		names = append(names, d.Name)
	}
	fmt.Fprintf(os.Stderr, "Warning: surface %s: %d WAL %s let go without being archived (%s), because the WAL waiting to leave this host passed wal.queue_max (%s) and %s. "+
		"A restore cannot replay past them: the point-in-time window starts again at the next base backup (safegrd wal base --surface %s).\n",
		s.ID, len(dropped), pluralWord(int64(len(dropped)), "file was", "files were"), strings.Join(names, ", "), formatBytes(max), why, s.ID)
}

func newWALDrainCmd() *cobra.Command {
	var surfaceID string
	cmd := &cobra.Command{
		Use:   "drain",
		Short: "Upload the WAL waiting in a surface's spool (wal.spool)",
		Long: `Uploads the WAL files wal push left in the surface's spool, wal.parallel at a
time, and removes each once the archive holds it. The daemon does this on every
pass; this runs it now.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, s, err := walArchive(cmd.Context(), cfg, surfaceID, "")
			if err != nil {
				return err
			}
			n, left, err := walDrain(cmd.Context(), a, s)
			fmt.Printf("Uploaded %d WAL %s from the spool; %d %s.\n", n, pluralWord(int64(n), "file", "files"), left, pluralWord(int64(left), "waits", "wait"))
			if err != nil {
				return storageFailure(err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Surface id from the config (required)")
	return cmd
}

// walDrain uploads a surface's spool and says how many files are left.
func walDrain(ctx context.Context, a *wal.Archive, s *config.SurfaceConfig) (pushed, left int, err error) {
	sp := walSpool(cfg, s)
	pushed, err = wal.Drain(ctx, a, sp, walParallel(s))
	l, lerr := sp.List()
	if err == nil {
		err = lerr
	}
	return pushed, len(l), err
}
