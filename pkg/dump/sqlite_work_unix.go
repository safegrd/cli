//go:build unix

package dump

import (
	"errors"
	"syscall"
)

// processGone reports whether no process with this id is running. A process
// owned by another user answers EPERM: it exists.
func processGone(pid int) bool {
	err := syscall.Kill(pid, 0)
	return errors.Is(err, syscall.ESRCH)
}

// processCheckable says whether processGone can tell a live process from a
// dead one on this platform.
const processCheckable = true
