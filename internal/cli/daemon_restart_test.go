package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// On a host where no daemon service was installed, restart says so and what
// to run instead. It used to run the service manager and print launchctl's
// "Could not find service", which is what the console's setup step and
// claim sent every host without a daemon to.
func TestRestartWithNoDaemonInstalledSaysWhatToRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// The system-wide service paths under a root of the test's own: a
	// service installed on the machine running the test does not decide it.
	old := serviceRoot
	serviceRoot = t.TempDir()
	t.Cleanup(func() { serviceRoot = old })
	if daemonServiceInstalled() {
		t.Fatal("a fresh HOME and service root with no service file reads as installed")
	}
	cmd := newDaemonRestartCmd()
	cmd.SetArgs(nil)
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "safegrd daemon install") || !strings.Contains(err.Error(), "daemon run --once") {
		t.Fatalf("restart with no service: %v", err)
	}
	if !strings.Contains(daemonNextStep(), "safegrd daemon install") {
		t.Fatalf("claim's next step on a host with no daemon: %q", daemonNextStep())
	}
	// The same root with a service file in it reads as installed, so the
	// check above read the test's root and not the machine's.
	p := launchdPath(false)
	if runtime.GOOS != "darwin" {
		p = systemdPath(false)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !daemonServiceInstalled() {
		t.Fatalf("a service file at %s does not read as installed", p)
	}
}
