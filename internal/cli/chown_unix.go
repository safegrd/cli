//go:build unix

package cli

import (
	"os"
	"syscall"
)

// chownLike gives path the owner and group of like.
func chownLike(path, like string) error {
	fi, err := os.Stat(like)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) == os.Geteuid() {
		return nil
	}
	return os.Chown(path, int(st.Uid), int(st.Gid))
}
