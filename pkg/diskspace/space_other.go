//go:build !linux && !darwin

package diskspace

import "errors"

// DiskSpace cannot be read on this system; CheckFreeSpace lets the write go
// ahead and say for itself if the disk fills.
func DiskSpace(string) (int64, int64, error) {
	return 0, 0, errors.New("free space is not read on this system")
}
