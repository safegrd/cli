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

// filesystemID is the device dir is on, or 0 when dir cannot be read: its
// free space cannot be read either, and the check lets the write go ahead.
func filesystemID(dir string) uint64 {
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		return 0
	}
	return uint64(st.Dev)
}
