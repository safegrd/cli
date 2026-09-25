package dump

import "time"

// elapsedMilliseconds is how long something took since start, rounded up to
// whole milliseconds. Duration.Milliseconds truncates, so a small SQLite file
// or a one-message mailbox finished in microseconds records 0 ms, which reads
// as a step that never ran. time.Since uses the monotonic clock, so a host
// clock stepped mid-run cannot shorten it.
func elapsedMilliseconds(start time.Time) int64 {
	d := time.Since(start)
	if d <= 0 {
		return 0
	}
	return int64((d + time.Millisecond - 1) / time.Millisecond)
}
