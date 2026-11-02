package config

import (
	"os"
	"testing"
)

// mustRead is the contents of path; a file that cannot be read fails the
// test rather than reading as empty, which a "does not contain" check would
// pass.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
