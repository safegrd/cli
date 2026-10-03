// Package testhome gives a test process an empty home directory, so no test
// reads or writes the ~/.safegrd of the machine running it. A developer's own
// config once failed a unit test, and one test's config could as easily have
// changed another's result.
package testhome

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
	pinGoCaches()
	dir, err := os.MkdirTemp("", "safegrd-test-home-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "testhome: %v\n", err)
		return 1
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "testhome: removing %s: %v\n", dir, err)
		}
	}()
	for _, k := range []string{"HOME", "USERPROFILE"} {
		if err := os.Setenv(k, dir); err != nil {
			fmt.Fprintf(os.Stderr, "testhome: %v\n", err)
			return 1
		}
	}
	os.Unsetenv("XDG_CONFIG_HOME")
	return run()
}

// pinGoCaches fixes the go command's module cache, build cache and env file
// at the paths they have under the real HOME. They default to locations under
// HOME, so a test that runs `go build` would otherwise download every module
// again into the temporary home (about 1.3 GB). Go writes the module cache
// read-only, so os.RemoveAll then fails and the directory stays in TMPDIR.
func pinGoCaches() {
	out, err := exec.Command("go", "env", "-json", "GOMODCACHE", "GOCACHE", "GOPATH", "GOENV").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "testhome: go env: %v; go commands run by tests will use the temporary home\n", err)
		return
	}
	var env map[string]string
	if err := json.Unmarshal(out, &env); err != nil {
		fmt.Fprintf(os.Stderr, "testhome: go env: %v\n", err)
		return
	}
	for k, v := range env {
		if v != "" && os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
}
