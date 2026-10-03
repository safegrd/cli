//go:build unix

package read

import "os"

// canChown reports whether this process may give files to other owners,
// which on Unix means running as root.
func canChown() bool { return os.Geteuid() == 0 }
