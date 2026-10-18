//go:build unix

package cli

import (
	"os"
	"syscall"
)

// execSelf replaces this process with bin, keeping its process id, so the
// service manager running the daemon sees no restart.
func execSelf(bin string, args []string) error {
	return syscall.Exec(bin, append([]string{bin}, args...), os.Environ())
}
