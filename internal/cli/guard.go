package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/spf13/cobra"
)

// guardRefused is the exit code guard uses when it did not run the command
// because no locked snapshot was taken. Hooks and CI read it to tell "the
// backup failed" apart from "the command failed".
const guardRefused = 3

// exitError carries an exit code to Execute. A nil err exits quietly: the
// wrapped command already said what it had to.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

// guardOptions is what guard was told about the snapshot it needs.
type guardOptions struct {
	surfaceID     string
	allowUnlocked bool
	// maxAge, when set, lets a locked snapshot of the surface younger than
	// this stand in for a new backup. Zero takes a backup every time.
	maxAge time.Duration
	// checkOnly, with maxAge, takes no backup at all: without a recent
	// locked snapshot the command is refused.
	checkOnly bool
}

func newGuardCmd() *cobra.Command {
	var (
		opts    guardOptions
		matches string
		list    bool
		hook    string
	)
	cmd := &cobra.Command{
		Use:   "guard [--surface ID] [-- command [args...]]",
		Short: "Take a locked snapshot, then run a command that could destroy data",
		Long: `Backs up one surface, waits until the snapshot is uploaded and locked, and
then runs the command. If the backup fails or the snapshot is not locked, the
command is not run and guard exits 3.

  safegrd guard --surface prod-db -- psql "$DATABASE_URL" -c 'DROP TABLE sessions'
  safegrd guard -- terraform destroy

With no command, guard takes the snapshot and exits: 0 when it is locked, 3
when it is not. A hook that runs before an agent's shell command uses this.

The surface is --surface, the only surface in the config, or the config's
database_url when it lists none.

Exit codes: the command's own exit code when it ran; 3 when guard refused to
run it; 1 for a usage or configuration error.

  safegrd guard --list                 the commands hooks treat as destructive
  safegrd guard --matches "<command>"  exit 0 if it is one of them, 1 if not

As an AI coding tool's pre-command hook, guard reads the tool's JSON on stdin,
backs up first when the command matches the list, and blocks the command when
no locked snapshot could be taken:

  safegrd guard --hook claude-code --surface prod-db   (also: cursor, codex)

A locked snapshot taken in the last while can stand in for a new one, so an
agent running several destructive commands in a row does not take a backup
for each:

  safegrd guard --max-age 30m -- psql -c 'TRUNCATE sessions'
  safegrd guard --max-age 30m --check-only -- terraform destroy

--check-only takes no backup at all: without a locked snapshot younger than
--max-age the command is refused (exit 3). Use it where the surface is backed
up by its daemon or by the remote server, and this host should only check.`,
		// A hook answers even when the config cannot be read: an exit 1 lets
		// the agent's command through, so the refusal has to be the answer
		// (runGuardHook blocks a destructive command with the reason).
		// --list and --matches read no config at all.
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			runningCommand = cmd.Name()
			if hook != "" || list || cmd.Flags().Changed("matches") {
				cmd.SilenceUsage = true
				return nil
			}
			return requireUsableConfig(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if list {
				return printGuardRules(os.Stdout)
			}
			if cmd.Flags().Changed("matches") {
				if r := matchDestructive(matches); r != nil {
					fmt.Println(r.Name)
					return nil
				}
				return &exitError{code: 1}
			}
			if opts.checkOnly && opts.maxAge <= 0 {
				return errors.New("--check-only needs --max-age: how young a locked snapshot has to be")
			}
			if hook != "" {
				ctx := cmd.Context()
				if ctx == nil {
					ctx = context.Background()
				}
				return runGuardHook(ctx, hook, opts, os.Stdin, os.Stdout)
			}

			var command []string
			if dash := cmd.ArgsLenAtDash(); dash >= 0 {
				command = args[dash:]
				args = args[:dash]
			}
			if len(args) > 0 {
				return fmt.Errorf("put the command after --, as in: safegrd guard -- %s", strings.Join(args, " "))
			}

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			snap, err := guardSnapshot(ctx, opts, describeCommand(command))
			if err != nil {
				if len(command) > 0 {
					fmt.Fprintf(os.Stderr, "Error: not running %s: %v\n", describeCommand(command), err)
				} else {
					fmt.Fprintf(os.Stderr, "Error: no locked snapshot: %v\n", err)
				}
				return &exitError{code: guardRefused}
			}
			if len(command) == 0 {
				return nil
			}
			fmt.Fprintf(os.Stderr, "Running %s (snapshot %s)\n", describeCommand(command), snap.SnapshotID)
			return runGuarded(command)
		},
	}
	cmd.Flags().StringVar(&opts.surfaceID, "surface", "", "The surface to back up, by its id in the config")
	cmd.Flags().BoolVar(&opts.allowUnlocked, "allow-unlocked", false,
		"Run the command after a backup that is not locked: local storage, or worm_mode NONE. "+
			"Without it guard refuses, because anyone who can run the command can delete that backup")
	cmd.Flags().DurationVar(&opts.maxAge, "max-age", 0,
		"A locked snapshot of the surface younger than this stands in for a new backup (30m, 2h). 0 backs up every time")
	cmd.Flags().BoolVar(&opts.checkOnly, "check-only", false,
		"Take no backup: refuse the command unless a locked snapshot younger than --max-age exists")
	cmd.Flags().StringVar(&matches, "matches", "", "Check a command against the destructive list and take no backup")
	cmd.Flags().BoolVar(&list, "list", false, "Print the destructive command list and exit")
	cmd.Flags().StringVar(&hook, "hook", "", "Answer an AI coding tool's pre-command hook on stdin: claude-code, cursor or codex")
	return cmd
}

// guardSnapshot backs up the chosen surface and returns its metadata once the
// snapshot is uploaded and locked. With opts.maxAge, a locked snapshot of the
// surface that young is returned instead and no backup is taken. Everything
// it prints goes to stderr, so the wrapped command's stdout is its own.
func guardSnapshot(ctx context.Context, opts guardOptions, what string) (*model.SnapshotMetadata, error) {
	stdout := os.Stdout
	os.Stdout = os.Stderr
	defer func() { os.Stdout = stdout }()

	surface, standalone, err := guardSurface(opts.surfaceID)
	if err != nil {
		return nil, err
	}
	if opts.maxAge > 0 {
		recent, err := recentLockedSnapshot(ctx, surface, standalone, opts.maxAge, time.Now())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not read the snapshots in storage: %v\n", err)
		}
		if recent != nil {
			fmt.Printf("Snapshot %s of %s, taken %s ago, is locked until %s; not backing up again\n",
				recent.SnapshotID, surface.ID, time.Since(recent.CreatedAt).Round(time.Minute), recent.WORMRetentionUntil.UTC().Format("2006-01-02 15:04 MST"))
			return recent, nil
		}
		if opts.checkOnly {
			return nil, fmt.Errorf("no locked snapshot of %s younger than %s, and --check-only takes none. "+
				"Run 'safegrd backup' or wait for the next scheduled one", surface.ID, opts.maxAge)
		}
	}
	if what != "" {
		fmt.Printf("Backing up %s before running %s\n", surface.ID, what)
	} else {
		fmt.Printf("Backing up %s\n", surface.ID)
	}

	stateDir := resolveStateDir("", cfg)
	lockDir := filepath.Join(stateDir, "locks")
	if err := os.MkdirAll(lockDir, 0700); err != nil {
		return nil, fmt.Errorf("could not create the state directory %s: %w", stateDir, err)
	}
	statePath := filepath.Join(stateDir, "daemon_state.json")
	state := loadDaemonState(statePath)
	if standalone {
		// The config's own database_url is what `backup` takes. It is
		// reported as this host and keeps no daemon state of its own.
		state = &DaemonState{Surfaces: map[string]*SurfaceState{}}
		statePath = filepath.Join(os.TempDir(), fmt.Sprintf("safegrd-guard-%d.json", os.Getpid()))
		defer os.Remove(statePath)
	}
	st, ok := state.Surfaces[surface.ID]
	if !ok {
		st = &SurfaceState{SurfaceID: surface.ID, SurfaceType: surface.Type}
		state.Surfaces[surface.ID] = st
	}

	nodeID := cfg.NodeID
	if !standalone {
		nodeID = surfaceNodeID(ctx, cfg, surface, st, map[string]bool{})
		if nodeID == "" {
			return nil, fmt.Errorf("surface %s: %s", surface.ID, st.Retired)
		}
		fetchHeldSurfaceSecret(ctx, cfg, nodeID, surface)
	}

	meta, err := backupSurfaceNow(ctx, cfg, surface, st, nodeID, lockDir, statePath, state)
	if err != nil {
		return nil, fmt.Errorf("the backup of %s failed: %w", surface.ID, err)
	}
	if meta == nil {
		return nil, fmt.Errorf("the backup of %s did not run: another backup of it holds the lock", surface.ID)
	}
	if st.notRecorded != "" {
		// The snapshot is in storage and locked, which is what guard
		// promises. The console not knowing about it is said, not hidden.
		fmt.Fprintf(os.Stderr, "Warning: snapshot %s is not recorded by the remote server: %s\n", meta.SnapshotID, st.notRecorded)
	}

	locked, why := snapshotLocked(meta, time.Now())
	if !locked && !opts.allowUnlocked {
		return nil, fmt.Errorf("snapshot %s was written but is not locked: %s. "+
			"Point this host at a bucket with Object Lock, or pass --allow-unlocked", meta.SnapshotID, why)
	}
	if locked {
		fmt.Printf("Snapshot %s is locked: %s\n", meta.SnapshotID, why)
	} else {
		fmt.Printf("Warning: snapshot %s is not locked (%s). Running anyway because of --allow-unlocked\n", meta.SnapshotID, why)
	}
	return meta, nil
}

// recentLockedSnapshot is the newest locked snapshot of the surface taken
// within maxAge, read from storage the way `list --json` reads it, or nil.
// The surface's snapshots are the ones filed under its node (a surface a
// daemon registered has its own) or, for an incremental repository, under
// its surface id; a standalone database_url is filed under this host.
func recentLockedSnapshot(ctx context.Context, surface *config.SurfaceConfig, standalone bool, maxAge time.Duration, now time.Time) (*model.SnapshotMetadata, error) {
	entries, err := listedSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	nodeID := cfg.NodeID
	if !standalone {
		state := loadDaemonState(filepath.Join(resolveStateDir("", cfg), "daemon_state.json"))
		if st, ok := state.Surfaces[surface.ID]; ok && st.ServerNodeID != "" {
			nodeID = st.ServerNodeID
		}
	}
	return pickRecentLockedSnapshot(entries, nodeID, surface.ID, standalone, maxAge, now), nil
}

// pickRecentLockedSnapshot chooses among listed snapshots: completed, locked,
// of this surface, created within maxAge of now; the newest wins.
func pickRecentLockedSnapshot(entries []listedSnapshot, nodeID, surfaceID string, standalone bool, maxAge time.Duration, now time.Time) *model.SnapshotMetadata {
	var best *model.SnapshotMetadata
	for _, e := range entries {
		if !e.Locked || e.MetadataError != "" || e.Status != string(model.SnapshotStatusCompleted) || e.CreatedAt == "" {
			continue
		}
		mine := e.RepoSurface == surfaceID || (e.NodeID != "" && e.NodeID == nodeID && (standalone || e.RepoSurface == ""))
		if !mine {
			continue
		}
		created, err := time.Parse(time.RFC3339, e.CreatedAt)
		if err != nil || created.After(now) || now.Sub(created) > maxAge {
			continue
		}
		until, _ := time.Parse(time.RFC3339, e.LockedUntil)
		if best == nil || created.After(best.CreatedAt) {
			best = &model.SnapshotMetadata{SnapshotID: e.SnapshotID, NodeID: e.NodeID, SurfaceType: model.SurfaceType(e.Surface),
				Status: model.SnapshotStatusCompleted, CreatedAt: created, WORMMode: e.WORMMode, WORMRetentionUntil: until, StorageURI: "s3://"}
		}
	}
	return best
}

// guardSurface picks the surface guard backs up. standalone is true for the
// config's own database_url, which has no surface entry.
func guardSurface(id string) (*config.SurfaceConfig, bool, error) {
	if id != "" {
		for i := range cfg.Surfaces {
			if cfg.Surfaces[i].ID == id {
				s := cfg.Surfaces[i]
				s.Schedule = effectiveSchedule(cfg, s)
				return &s, false, nil
			}
		}
		return nil, false, fmt.Errorf("no surface %q in the config; it has: %s", id, surfaceIDs())
	}
	switch len(cfg.Surfaces) {
	case 0:
		if cfg.DatabaseURL == "" {
			return nil, false, errors.New("the config lists no surfaces and has no database_url, so there is nothing to back up. " +
				"Add a surface, or set database_url")
		}
		return &config.SurfaceConfig{ID: "database_url", Type: string(dump.SurfaceTypeOfURL(cfg.DatabaseURL))}, true, nil
	case 1:
		s := cfg.Surfaces[0]
		s.Schedule = effectiveSchedule(cfg, s)
		return &s, false, nil
	default:
		return nil, false, fmt.Errorf("the config lists %d surfaces; name one with --surface (%s)", len(cfg.Surfaces), surfaceIDs())
	}
}

func surfaceIDs() string {
	ids := make([]string, 0, len(cfg.Surfaces))
	for _, s := range cfg.Surfaces {
		ids = append(ids, s.ID)
	}
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}

// snapshotLocked says whether storage will refuse to delete a snapshot, from
// what the backup recorded as it uploaded it. An S3 upload under Object Lock
// sends the mode and date with the object, and a bucket without Object Lock
// refuses that upload, so a completed upload with a mode and a future date is
// a locked object.
func snapshotLocked(meta *model.SnapshotMetadata, now time.Time) (bool, string) {
	switch {
	case strings.HasPrefix(meta.StorageURI, "file://"):
		return false, "it is in a directory on this host, which has no Object Lock"
	case meta.WORMMode == string(config.WORMModeNone):
		return false, "worm_mode is NONE, so the bucket applies no Object Lock"
	case meta.WORMRetentionUntil.IsZero() || !meta.WORMRetentionUntil.After(now):
		return false, "it has no retention date in the future"
	}
	mode := meta.WORMMode
	if mode == "" {
		mode = string(config.WORMModeCompliance)
	}
	return true, fmt.Sprintf("%s until %s", mode, meta.WORMRetentionUntil.UTC().Format("2006-01-02 15:04 MST"))
}

// describeCommand is the command as one line, for messages.
func describeCommand(command []string) string {
	if len(command) == 0 {
		return ""
	}
	s := redactURLPasswords(strings.Join(command, " "))
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return "'" + s + "'"
}

// urlPassword matches the password in a URL's userinfo: scheme://user:PASS@.
var urlPassword = regexp.MustCompile(`(://[^:/@\s]+:)[^@\s]+@`)

// redactURLPasswords hides a password written into a connection URL. guard
// echoed `psql postgres://user:pass@host/db ...` as it ran it, putting the
// password into the terminal and into an agent's transcript.
func redactURLPasswords(s string) string {
	return urlPassword.ReplaceAllString(s, "${1}xxxxx@")
}

func printGuardRules(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "RULE\tPATTERN")
	for _, r := range destructiveRules {
		fmt.Fprintf(tw, "%s\t%s\n", r.Name, r.Pattern)
	}
	return tw.Flush()
}
