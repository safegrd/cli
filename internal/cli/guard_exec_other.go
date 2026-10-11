//go:build !unix

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// runGuarded runs the command with this process's terminal and returns its
// exit code. Where exec cannot replace the process, guard waits for it.
func runGuarded(command []string) error {
	c := exec.Command(command[0], command[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := c.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ee):
		return &exitError{code: ee.ExitCode()}
	default:
		return &exitError{code: 127, err: fmt.Errorf("the snapshot is taken, but %s could not be started: %w", command[0], err)}
	}
}

// detachProcess leaves the command as it is: a backup a hook started there
// runs as the hook's child.
func detachProcess(*exec.Cmd) {}

// processAlive says whether a process with this pid exists. FindProcess
// opens the process on Windows, and fails for one that is gone.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p.Release() // only the handle; the answer is already decided
	return true
}
