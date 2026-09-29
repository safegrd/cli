// Package testhome gives a test process an empty home directory, so no test
// reads or writes the ~/.safegrd of the machine running it. A developer's own
// config once failed a unit test, and one test's config could as easily have
// changed another's result.
package testhome

import (
	"fmt"
	"os"
	"testing"
)

// Main runs a package's tests with HOME (and its Windows and XDG
// counterparts) pointed at a new empty directory, removed afterwards. Child
// processes inherit it, so a compiled CLI a test runs sees it too.
func Main(m *testing.M) int {
	return Run(m.Run)
}

// Run is Main for a TestMain that already wraps m.Run.
func Run(run func() int) int {
	dir, err := os.MkdirTemp("", "safegrd-test-home-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "testhome: %v\n", err)
		return 1
	}
	defer os.RemoveAll(dir)
	for _, k := range []string{"HOME", "USERPROFILE"} {
		if err := os.Setenv(k, dir); err != nil {
			fmt.Fprintf(os.Stderr, "testhome: %v\n", err)
			return 1
		}
	}
	os.Unsetenv("XDG_CONFIG_HOME")
	return run()
}
