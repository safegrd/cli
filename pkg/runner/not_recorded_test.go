package runner

import (
	"strings"
	"testing"
)

// A drill the remote server declined under the plan used to print the
// server's sentence after a dash, with a pitch on the end. It says what
// happened and when the next one counts.
func TestADeclinedDrillSaysWhatHappenedAndWhatNext(t *testing.T) {
	msg := notRecordedByPlan("The Free plan records a Fire Drill monthly. A larger plan drills more often.",
		"2026-11-01T09:30:00Z")
	for _, want := range []string{"Not recorded", "HTTP 402", "2026-11-01 09:30 UTC"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	for _, banned := range []string{"—", "upgrade", "larger plan"} {
		if strings.Contains(msg, banned) {
			t.Errorf("message carries %q:\n%s", banned, msg)
		}
	}

	// Without a due time the server's reason is all there is to say.
	msg = notRecordedByPlan("Sandbox Fire Drills start on the Growth plan.", "")
	if !strings.Contains(msg, "Reason: Sandbox Fire Drills start on the Growth plan.") {
		t.Errorf("the server's reason is missing:\n%s", msg)
	}
}
