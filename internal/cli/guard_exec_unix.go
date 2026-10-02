//go:build unix

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// runGuarded replaces this process with the command, so its exit code,
// signals and terminal are exactly what they would be without guard.
func runGuarded(command []string) error {
	path, err := exec.LookPath(command[0])
	if err != nil {
		return &exitError{code: 127, err: fmt.Errorf("the snapshot is taken, but %s was not found: %w", command[0], err)}
	}
	if err := syscall.Exec(path, command, os.Environ()); err != nil {
		return &exitError{code: 126, err: fmt.Errorf("the snapshot is taken, but %s could not be started: %w", command[0], err)}
	}
	return nil
}
