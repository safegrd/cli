package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	cmd.AddCommand(newWALPushCmd(), newWALFetchCmd(), newWALBaseCmd(), newWALBundleCmd(), newWALStatusCmd(), newWALRestoreCmd(), newWALPointCmd(), newWALDrillCmd())
	return cmd
}

// walSurface finds a surface that archives its WAL.
func walSurface(c *config.CLIConfig, id string) (*config.SurfaceConfig, error) {
	if id == "" {
		return nil, errors.New("--surface is required: the id of a PostgreSQL surface in the config")
	}
	var ids []string
	for i := range c.Surfaces {
		s := c.Surfaces[i]
		ids = append(ids, s.ID)
		if s.ID != id {
			continue
		}
		if s.Type != "" && !strings.EqualFold(s.Type, "postgres") {
			return nil, fmt.Errorf("surface %s is %s; WAL archiving is for a PostgreSQL surface", id, s.Type)
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
current directory, which is the data directory when PostgreSQL runs it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, _, err := walArchive(cmd.Context(), cfg, surfaceID, "")
			if err != nil {
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
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			if err := a.Push(cmd.Context(), filepath.Base(p), f); err != nil {
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
replayed all there is. 'safegrd wal restore' writes the restore_command.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, _, err := walArchive(ctx, cfg, surfaceID, "")
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
			dst := args[1]
			tmp, err := os.CreateTemp(filepath.Dir(dst), ".safegrd-fetch-*")
			if err != nil {
				return err
			}
			defer os.Remove(tmp.Name())
			ferr := a.Fetch(ctx, args[0], tmp)
			if cerr := tmp.Close(); ferr == nil {
				ferr = cerr
			}
			if errors.Is(ferr, wal.ErrNotFound) {
				return &exitError{code: 1}
			}
			if ferr != nil {
				return storageFailure(ferr)
			}
			return os.Rename(tmp.Name(), dst)
		},
	}
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Surface id from the config (required)")
	cmd.Flags().StringVar(&systemID, "system", "", "The cluster's system identifier, when the archive holds more than one")
	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to the age identity (default encryption.key_path)")
	cmd.Flags().StringVar(&privKey, "private-key", "", "The age identity, as env:VAR or file:/path")
	cmd.Flags().StringVar(&node, "node", "", "On hosted storage, read the archive another host of the organization wrote")
	return cmd
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
	return a.Base(ctx, wal.BaseOptions{ConnURL: connURL, Server: srv})
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
			return walBundleAll(ctx, a, systems)
		},
	}
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Surface id from the config (required)")
	return cmd
}

// walBundleAll bundles each cluster's unlocked WAL and says what it did.
func walBundleAll(ctx context.Context, a *wal.Archive, systems []string) error {
	var conflicts []string
	for _, sys := range systems {
		a.SystemID = sys
		res, err := a.Bundle(ctx)
		if err != nil {
			return storageFailure(err)
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
	if len(conflicts) > 0 {
		return fmt.Errorf("%d WAL file name(s) were archived twice with different contents and are left out of the bundle: %s. Check that only one cluster archives to this surface",
			len(conflicts), strings.Join(conflicts, ", "))
	}
	return nil
}

func newWALStatusCmd() *cobra.Command {
	var surfaceID, systemID, node string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show a surface's WAL archive: its base backups, its window and any gap",
		Long: `Lists the base backups and WAL a surface's archive holds and the window a
restore can reach. It exits 1 when there is no complete base backup, or when a
WAL file is missing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			a, _, err := walArchive(ctx, cfg, surfaceID, "")
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
			for _, sys := range systems {
				a.SystemID = sys
				st, err := a.Status(ctx)
				if err != nil {
					return storageFailure(err)
				}
				all = append(all, st)
				if !jsonOut {
					printWALStatus(a, st)
				}
				if !st.HasWindow {
					problems = append(problems, fmt.Sprintf("system %s has no base backup with unbroken WAL after it", sys))
				}
				if len(st.Gaps) > 0 {
					problems = append(problems, fmt.Sprintf("system %s is missing WAL from %s", sys, st.Gaps[0].First))
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
	cmd.Flags().StringVar(&node, "node", "", "On hosted storage, show the archive another host of the organization wrote")
	return cmd
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
		fmt.Printf(", newest %s ended %s (PostgreSQL %d)", b.BaseID, ts(b.EndedAt), b.Major())
	}
	fmt.Println()
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
	var surfaceID, systemID, to, toPoint, pgdata, keyPath, privKey, node string
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore a PostgreSQL surface to a point in time into an empty data directory",
		Long: `Unpacks the newest base backup that ends before --to into an empty directory
and sets PostgreSQL up to replay the archived WAL to that time and promote:
recovery.signal, and restore_command and recovery_target_time in
postgresql.auto.conf. Start PostgreSQL on the directory to run the replay.

Run it as the user PostgreSQL will run as: restore_command calls this CLI
with the same config and key. Archiving is turned off on the restored cluster.

--to takes RFC 3339 (2026-10-17T14:52:00Z) or "2026-10-17 14:52:00", read as UTC.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if pgdata == "" {
				return errors.New("--pgdata is required: an empty directory to restore into")
			}
			var target time.Time
			var err error
			switch {
			case to != "" && toPoint != "":
				return errors.New("--to and --to-point are two targets; give one")
			case toPoint == "":
				if target, err = parseWALTarget(to); err != nil {
					return err
				}
			}
			a, _, err := walArchive(ctx, cfg, surfaceID, "")
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
			dir, err := filepath.Abs(pgdata)
			if err != nil {
				return err
			}
			fetch, err := walFetchCommand(a, keyPath, privKey, node)
			if err != nil {
				return err
			}
			o := wal.RestoreOptions{Target: target, PGData: dir, FetchCommand: fetch}
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
			if toPoint != "" {
				goal = "restore point " + toPoint
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
			fmt.Printf("   Archiving is off on it (postgresql.auto.conf). Turn it on once this is the database you keep.\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&surfaceID, "surface", "", "Surface id from the config (required)")
	cmd.Flags().StringVar(&systemID, "system", "", "The cluster's system identifier, when the archive holds more than one")
	cmd.Flags().StringVar(&to, "to", "", "The moment to restore to")
	cmd.Flags().StringVar(&toPoint, "to-point", "", "A restore point to restore to, as 'safegrd wal point' named it")
	cmd.Flags().StringVar(&pgdata, "pgdata", "", "An empty directory to restore into (required)")
	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to the age identity (default encryption.key_path)")
	cmd.Flags().StringVar(&privKey, "private-key", "", "The age identity, as env:VAR or file:/path")
	cmd.Flags().StringVar(&node, "node", "", "On hosted storage, restore from the archive another host of the organization wrote (a host that replaces a lost one)")
	return cmd
}

func parseWALTarget(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("--to or --to-point is required: the moment or the restore point to restore to")
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
