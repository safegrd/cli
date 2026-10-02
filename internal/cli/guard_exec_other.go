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
