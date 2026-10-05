//go:build linux || darwin

package runner

import (
	"os"
	"syscall"
)

// fileOwner is the uid that owns fi.
func fileOwner(fi os.FileInfo) uint32 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid
	}
	return 0
}
