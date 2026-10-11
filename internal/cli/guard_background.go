package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// A pre-command hook has to answer before the agent's tool gives up on it,
// and Claude Code runs the command anyway when a hook times out. A backup of
// a large database outlasts any timeout an agent session can live with, so
// under --hook the backup runs in a process of its own, detached from the
// hook. Guard waits up to --wait for it: when it finishes, the command goes
// through; when it does not, the command is denied, the backup keeps going,
// and the agent's retry finds the snapshot through --max-age. Every database
// size takes the same hook line.

const (
	hookDefaultMaxAge = 30 * time.Minute
	hookDefaultWait   = 20 * time.Second
	// A run older than this is not joined, whatever its pid says: the pid
	// has been reused.
	guardRunStale = 24 * time.Hour
)

// guardRun is the backup a hook started, recorded so the next hook call
// waits for it instead of starting another.
type guardRun struct {
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
	Result  string    `json:"result"`
	Log     string    `json:"log"`
}

// guardResult is what `guard --result-file` writes when its backup ends.
type guardResult struct {
	SnapshotID  string    `json:"snapshot_id,omitempty"`
	SurfaceType string    `json:"surface_type,omitempty"`
	WORMMode    string    `json:"worm_mode,omitempty"`
	LockedUntil time.Time `json:"locked_until,omitempty"`
	StorageURI  string    `json:"storage_uri,omitempty"`
	Finished    time.Time `json:"finished"`
	Error       string    `json:"error,omitempty"`
}

func (r *guardResult) snapshot() *model.SnapshotMetadata {
	return &model.SnapshotMetadata{SnapshotID: r.SnapshotID, SurfaceType: model.SurfaceType(r.SurfaceType),
		Status: model.SnapshotStatusCompleted, CreatedAt: r.Finished, WORMMode: r.WORMMode,
		WORMRetentionUntil: r.LockedUntil, StorageURI: r.StorageURI}
}

// backupRunningError is the hook's answer while the backup is still going.
type backupRunningError struct {
	surface string
	started time.Time
	log     string
}

func (e *backupRunningError) Error() string {
	return fmt.Sprintf("a backup of %s started %s ago and is still running, so there is no locked snapshot yet (log: %s)",
		e.surface, time.Since(e.started).Round(time.Second), e.log)
}

// spawnGuardBackup starts `safegrd guard --result-file` for the surface in a
// process the hook does not wait for. done is closed when it exits, if this
// process is still there to see it. Tests replace it.
var spawnGuardBackup = func(opts guardOptions, resultPath, logPath string) (pid int, done <-chan struct{}, err error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, nil, err
	}
	args := []string{"guard", "--result-file", resultPath}
	if cfgFile != "" {
		args = append(args, "--config", cfgFile)
	}
	if opts.surfaceID != "" {
		args = append(args, "--surface", opts.surfaceID)
	}
	if opts.allowUnlocked {
		args = append(args, "--allow-unlocked")
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, nil, err
	}
	defer logf.Close()
	cmd := exec.Command(exe, args...)
	// No pipe of the hook's: the agent's tool waits for the hook's stdout
	// and stderr to close, and would wait for the backup too.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, logf, logf
	detachProcess(cmd)
	if err := cmd.Start(); err != nil {
		return 0, nil, err
	}
	ch := make(chan struct{})
	go func() {
		_ = cmd.Wait() // the exit code is in the result file
		close(ch)
	}()
	return cmd.Process.Pid, ch, nil
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// guardHookSnapshot is guardSnapshot for a hook: a recent locked snapshot
// stands in, otherwise a detached backup is started (or joined) and waited
// for up to opts.wait. reused says the snapshot was not taken for this
// command.
func guardHookSnapshot(ctx context.Context, opts guardOptions, what string) (snap *model.SnapshotMetadata, reused bool, err error) {
	stdout := os.Stdout
	os.Stdout = os.Stderr
	defer func() { os.Stdout = stdout }()

	surface, standalone, err := guardSurface(opts.surfaceID)
	if err != nil {
		return nil, false, err
	}
	recent, err := recentLockedSnapshot(ctx, surface, standalone, opts.maxAge, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read the snapshots in storage: %v\n", err)
	}
	if recent != nil {
		fmt.Printf("Snapshot %s of %s, taken %s ago, is locked until %s; not backing up again\n",
			recent.SnapshotID, surface.ID, time.Since(recent.CreatedAt).Round(time.Minute), recent.WORMRetentionUntil.UTC().Format("2006-01-02 15:04 MST"))
		return recent, true, nil
	}

	dir := filepath.Join(resolveStateDir("", cfg), "guard")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, fmt.Errorf("could not create %s: %w", dir, err)
	}
	name := unsafeFileChars.ReplaceAllString(surface.ID, "_")
	runPath := filepath.Join(dir, name+".run.json")
	last := readGuardRun(runPath)

	// The last run's own result counts too: storage is not listed for an
	// unlocked snapshot taken under --allow-unlocked, and the retry after a
	// long backup must not start another one.
	if last != nil {
		if res := readGuardResult(last.Result); res != nil && res.Error == "" && res.SnapshotID != "" &&
			time.Since(res.Finished) <= opts.maxAge {
			if locked, _ := snapshotLocked(res.snapshot(), time.Now()); locked || opts.allowUnlocked {
				fmt.Printf("Snapshot %s of %s, taken %s ago, stands in; not backing up again\n",
					res.SnapshotID, surface.ID, time.Since(res.Finished).Round(time.Minute))
				return res.snapshot(), true, nil
			}
		}
	}
	if opts.checkOnly {
		return nil, false, fmt.Errorf("no locked snapshot of %s younger than %s, and --check-only takes none. "+
			"Run 'safegrd backup' or wait for the next scheduled one", surface.ID, opts.maxAge)
	}

	var done <-chan struct{}
	run := last
	if run == nil || readGuardResult(run.Result) != nil || !processAlive(run.PID) || time.Since(run.Started) > guardRunStale {
		started := time.Now()
		run = &guardRun{Started: started,
			Result: filepath.Join(dir, fmt.Sprintf("%s-%d.result.json", name, started.UnixNano())),
			Log:    filepath.Join(dir, name+".log")}
		if what != "" {
			fmt.Printf("Backing up %s before running %s\n", surface.ID, what)
		} else {
			fmt.Printf("Backing up %s\n", surface.ID)
		}
		pid, ch, err := spawnGuardBackup(opts, run.Result, run.Log)
		if err != nil {
			return nil, false, fmt.Errorf("could not start the backup of %s: %w", surface.ID, err)
		}
		run.PID, done = pid, ch
		if last != nil {
			_ = os.Remove(last.Result) // an old run's result; the new run is the record
		}
		if err := writeJSONFile(runPath, run); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not record the backup in %s, so the next command starts another: %v\n", runPath, err)
		}
	} else {
		fmt.Printf("Waiting for the backup of %s started %s ago\n", surface.ID, time.Since(run.Started).Round(time.Second))
	}

	deadline := time.NewTimer(opts.wait)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if res := readGuardResult(run.Result); res != nil {
			if res.Error != "" {
				return nil, false, errors.New(res.Error)
			}
			return res.snapshot(), false, nil
		}
		exited := false
		if done != nil {
			select {
			case <-done:
				exited = true
			default:
			}
		} else {
			exited = !processAlive(run.PID)
		}
		if exited {
			if res := readGuardResult(run.Result); res != nil {
				continue
			}
			return nil, false, fmt.Errorf("the backup of %s stopped without a result. Its log is %s", surface.ID, run.Log)
		}
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-deadline.C:
			return nil, false, &backupRunningError{surface: surface.ID, started: run.Started, log: run.Log}
		case <-tick.C:
		}
	}
}

// writeGuardResult records how `guard --result-file` ended, for the hook
// waiting on it.
func writeGuardResult(path string, meta *model.SnapshotMetadata, err error) error {
	res := guardResult{Finished: time.Now().UTC()}
	if err != nil {
		res.Error = err.Error()
	} else {
		res.SnapshotID, res.SurfaceType, res.WORMMode = meta.SnapshotID, string(meta.SurfaceType), meta.WORMMode
		res.LockedUntil, res.StorageURI = meta.WORMRetentionUntil, meta.StorageURI
	}
	return writeJSONFile(path, res)
}

func readGuardRun(path string) *guardRun {
	var run guardRun
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &run) != nil || run.Result == "" {
		return nil
	}
	return &run
}

func readGuardResult(path string) *guardResult {
	var res guardResult
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &res) != nil {
		return nil
	}
	return &res
}

// writeJSONFile writes v whole or not at all, so a reader never sees half.
func writeJSONFile(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
