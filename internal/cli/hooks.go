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
)

// hookTimeout bounds a pre_backup or post_backup hook. A hook that quiesces
// an application and then hangs would otherwise hold the application quiet,
// and every surface behind it waiting, indefinitely.
const hookTimeout = 10 * time.Minute

// runHook runs one of a surface's hooks under the shell, as the agent's user,
// with the surface described in its environment. Its output is echoed to the
// agent's log with the surface and hook named, so a hook that fails at 3am
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
