//go:build unix

package read

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// canChown reports whether this process may give files to other owners,
// which on Unix means running as root.
func canChown() bool { return os.Geteuid() == 0 }

// lchtimes sets a symlink's own time, not its target's.
func lchtimes(p string, t time.Time) error {
	ts := unix.NsecToTimespec(t.UnixNano())
	return unix.UtimesNanoAt(unix.AT_FDCWD, p, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW)
}
