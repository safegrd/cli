package cli

import (
	"reflect"
	"testing"
)

// A bare name matches at any depth; a path stays a path from /. "find
// contract.txt" found nothing, because patterns were only ever paths.
func TestABareNameMatchesAtAnyDepth(t *testing.T) {
	got := cleanPatterns([]string{"contract.txt", " /srv/studio ", "srv/*.txt", "**/logo.png", ""})
	want := []string{"**/contract.txt", "srv/studio", "srv/*.txt", "**/logo.png", ""}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cleanPatterns = %q, want %q", got, want)
	}
}
