//go:build linux || darwin

// Package sqlitelocktest asks, from another process, whether a SQLite
// database file is under a reader's shared lock. A process cannot see its own
// POSIX locks with F_GETLK, so the question is asked by the test binary run
// again: a package's TestMain calls Main, and a test calls SharedHeld.
package sqlitelocktest

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const probeEnv = "SAFEGRD_SQLITE_LOCK_PROBE"

// SQLite's shared lock is a read lock on 510 bytes from 2 past the pending
// byte at 1 GiB (os_unix.c: SHARED_FIRST, SHARED_SIZE).
const (
	sharedFirst = 0x40000000 + 2
	sharedSize  = 510
)

// Main runs the probe when the test binary was started by SharedHeld, and
// the tests otherwise.
func Main(m *testing.M) {
	if path := os.Getenv(probeEnv); path != "" {
		held, err := probe(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Print(held)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func probe(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: io.SeekStart, Start: sharedFirst, Len: sharedSize}
	if err := unix.FcntlFlock(f.Fd(), unix.F_GETLK, &lk); err != nil {
		return false, err
	}
	return lk.Type != unix.F_UNLCK, nil
}

// SharedHeld reports whether a process other than the one it starts holds a
// lock on path's SHARED range: whether this test process, as SQLite, still
// holds the shared lock a reader takes.
func SharedHeld(t *testing.T, path string) bool {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), probeEnv+"="+path)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("probing the locks on %s: %v", path, err)
	}
	return strings.TrimSpace(string(out)) == "true"
}
