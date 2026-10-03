//go:build unix

package write

import (
	"os"
	"syscall"
)

// openNoFollow opens a regular file without following a symlink that
// replaced it after the walk looked.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
