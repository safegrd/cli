//go:build linux || darwin

package diskspace

import "syscall"

// DiskSpace is what an ordinary user may still write under dir, and the
// filesystem's size.
func DiskSpace(dir string) (avail, total int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), int64(st.Blocks) * int64(st.Bsize), nil
}
