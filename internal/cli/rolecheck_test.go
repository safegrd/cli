package cli

import (
	"strings"
	"testing"
)

// A sign-in role that row-level security filters is refused as the source's
// failure: the database's grants decide it, and the fix is in the database
// or the credential.
func TestHiddenRowsExitAsTheSource(t *testing.T) {
	err := hiddenRowsRefusal("cli_login_read_only", []string{"auth.users", "public.orders"}, "supabase")
	if err == nil || !strings.Contains(err.Error(), "row-level security hides rows of 2 table(s)") {
		t.Fatalf("refusal: %v", err)
	}
	if got := exitCodeOf(err); got != exitSource {
		t.Fatalf("exit %d, want %d (the source)", got, exitSource)
	}
}
