//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package write

import "os"

// Elsewhere there is no device, inode or change time to compare, so the
// files cache matches on size and modification time alone.
func sysStat(os.FileInfo) statInfo { return statInfo{} }
