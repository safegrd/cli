package dump

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// wantErr fails the test unless err is an error whose text holds every one
// of words: a refusal is proven by what it says, not only by failing.
func wantErr(t *testing.T, err error, words ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error; want one saying %q", words)
	}
	for _, w := range words {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("error %q does not say %q", err, w)
		}
	}
}

// mustRead is the contents of path; a file that cannot be read fails the
// test rather than reading as empty.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// deadPID is the PID of a process that has exited and been reaped: this test
// binary, run once with no test selected. A fixed number such as 999999 is a
// live process on a host whose pid_max is larger.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatalf("running a process to get a dead PID: %v", err)
	}
	return cmd.ProcessState.Pid()
}
