//go:build !unix

package read

import "time"

func canChown() bool { return false }

// lchtimes leaves a symlink's time as it is where there is no call for it.
func lchtimes(string, time.Time) error { return nil }
