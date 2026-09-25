package dump

import (
	"testing"
	"time"
)

func TestElapsedMillisecondsNeverRecordsAFinishedStepAsZero(t *testing.T) {
	if got := elapsedMilliseconds(time.Now()); got < 1 {
		t.Fatalf("a step that just finished took %d ms, want at least 1", got)
	}
	if got := elapsedMilliseconds(time.Now().Add(-1500 * time.Millisecond)); got < 1500 || got > 1600 {
		t.Fatalf("1.5 s took %d ms", got)
	}
	if got := elapsedMilliseconds(time.Now().Add(time.Hour)); got != 0 {
		t.Fatalf("a start in the future took %d ms, want 0", got)
	}
}
