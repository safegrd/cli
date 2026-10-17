package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/config"
	"github.com/safegrd/cli/pkg/model"
)

// hookTimeout bounds a surface hook. A pre_backup hook that quiesces
// an application and then hangs would otherwise hold the application quiet,
// and every surface behind it waiting, indefinitely.
const hookTimeout = 10 * time.Minute

// runHook runs one of a surface's hooks under the shell, as the daemon's user,
// with the surface described in its environment. Its output is echoed to the
// daemon's log with the surface and hook named, so a hook that fails at 3am
// leaves its own explanation behind.
func runHook(ctx context.Context, s *config.SurfaceConfig, which, command string, env ...string) error {
	ctx, cancel := context.WithTimeout(ctx, hookTimeout)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command)
	}
	cmd.Env = append(os.Environ(),
		"SAFEGRD_SURFACE_ID="+s.ID,
		"SAFEGRD_SURFACE_TYPE="+strings.ToLower(s.Type),
		"SAFEGRD_HOOK="+which,
	)
	cmd.Env = append(cmd.Env, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	start := time.Now()
	err := cmd.Run()
	if text := strings.TrimSpace(out.String()); text != "" {
		if len(text) > 4000 {
			text = "…" + text[len(text)-4000:]
		}
		for _, line := range strings.Split(text, "\n") {
			fmt.Printf("   [%s %s] %s\n", s.ID, which, line)
		}
	}
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return fmt.Errorf("%s hook did not finish within %s", which, hookTimeout)
	case err != nil:
		return fmt.Errorf("%s hook failed after %s: %v", which, time.Since(start).Round(time.Second), err)
	}
	return nil
}

// What a failed pre_backup means (pre_backup_on_error).
const (
	preBackupSkip     = "skip"
	preBackupContinue = "continue"
	preBackupRetry    = "retry"
)

// preBackupRetries is how many more times "retry" runs a failed pre_backup.
const preBackupRetries = 2

// preBackupRetryWait is the wait before retry n (0, 1): 10 seconds, then 20.
// Long enough for a lock or a migration step to clear, short enough that
// the surface's next backup is not held up.
func preBackupRetryWait(n int) time.Duration { return 10 * time.Second << n }

// preBackupOnError is the surface's pre_backup_on_error, or an error naming
// the values it takes.
func preBackupOnError(s *config.SurfaceConfig) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(s.PreBackupOnError)); v {
	case "", preBackupSkip:
		return preBackupSkip, nil
	case preBackupContinue, preBackupRetry:
		return v, nil
	default:
		return "", fmt.Errorf("surface %s: pre_backup_on_error is %q; use skip, continue or retry", s.ID, s.PreBackupOnError)
	}
}

// runPreBackup runs the surface's pre_backup and returns the error that stops
// the backup, or nil when the backup goes ahead.
func runPreBackup(ctx context.Context, s *config.SurfaceConfig) error {
	mode, err := preBackupOnError(s)
	if err != nil {
		return stageErr(model.BackupReasonConfig, err)
	}
	err = runHook(ctx, s, "pre_backup", s.PreBackup)
	for n := 0; err != nil && mode == preBackupRetry && n < preBackupRetries; n++ {
		wait := preBackupRetryWait(n)
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: %v. Running it again in %s.\n", s.ID, err, wait)
		select {
		case <-ctx.Done():
			return stageErr(model.BackupReasonPreBackupHook, fmt.Errorf("not backed up: %w", err))
		case <-time.After(wait):
		}
		err = runHook(ctx, s, "pre_backup", s.PreBackup, fmt.Sprintf("SAFEGRD_HOOK_ATTEMPT=%d", n+2))
	}
	switch {
	case err == nil:
		return nil
	case mode == preBackupContinue:
		fmt.Fprintf(os.Stderr, "Warning: Surface %s: %v. Backing up anyway, as pre_backup_on_error: continue says.\n", s.ID, err)
		return nil
	}
	return stageErr(model.BackupReasonPreBackupHook, fmt.Errorf("not backed up: %w", err))
}
