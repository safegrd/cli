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

// A table's file is named as the table in what restore says.
func TestATablePathIsShownAsTheTable(t *testing.T) {
	for in, want := range map[string]string{
		"data/public/customers.copy": "public.customers",
		"srv/app/data/x.copy":        "srv/app/data/x.copy",
		"notes.md":                   "notes.md",
	} {
		if got := shownPath(in); got != want {
			t.Errorf("shownPath(%q) = %q, want %q", in, got, want)
		}
	}
	if got := findArgs("data/public/customers.copy"); got != "--table public.customers" {
		t.Errorf("findArgs of a table: %q", got)
	}
}
