package cli

import (
	"os"
	"strings"
	"testing"
)

// On a host where no daemon service was installed, restart says so and what
// to run instead. It used to run the service manager and print launchctl's
// "Could not find service", which is what the console's setup step and
// claim sent every host without a daemon to.
func TestRestartWithNoDaemonInstalledSaysWhatToRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, p := range []string{systemdPath(false), launchdPath(false)} {
		if _, err := os.Stat(p); err == nil {
			t.Skipf("this machine has a system daemon service at %s", p)
		}
	}
	if daemonServiceInstalled() {
		t.Fatal("a fresh HOME with no service file reads as installed")
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
}
