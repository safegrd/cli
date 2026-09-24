//go:build unix

package dump

import (
	"os"
	"syscall"
)

// ownerOf returns the numeric owner of a file, or nils where the platform
// does not report one.
func ownerOf(info os.FileInfo) (uid, gid *int) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil
	}
	u, g := int(st.Uid), int(st.Gid)
	return &u, &g
}

// canChown reports whether this process may give files away to other
// owners, which on Unix means running as root.
func canChown() bool {
	return os.Geteuid() == 0
}
