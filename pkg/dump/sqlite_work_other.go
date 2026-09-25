//go:build !unix

package dump

// processGone cannot ask the platform, so it never claims a process is gone;
// leftovers there are swept by age instead (sqliteWorkMaxAge).
func processGone(int) bool { return false }
