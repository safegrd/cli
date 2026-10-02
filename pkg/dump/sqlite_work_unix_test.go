//go:build unix

package dump

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A work directory whose process is alive stays, however old: a long drill
// on a slow host used to lose its copy at 24 hours. One whose process is
// gone is removed at once.
func TestSweepKeepsALiveProcesssWorkHoweverOld(t *testing.T) {
	parent := t.TempDir()
	live := filepath.Join(parent, fmt.Sprintf("%s%d-old", sqliteWorkPrefix, os.Getppid()))
	dead := filepath.Join(parent, sqliteWorkPrefix+"999999-gone")
	for _, d := range []string{live, dead} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-3 * sqliteWorkMaxAge)
		if err := os.Chtimes(d, old, old); err != nil {
			t.Fatal(err)
		}
	}
	sweepSQLiteWork(parent)
	if _, err := os.Stat(live); err != nil {
		t.Errorf("a live process's work directory was removed for its age: %v", err)
	}
	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Errorf("a dead process's work directory was kept")
	}
}

// A MySQL or Mongo credential file left by a process killed outright is
// removed by the next run, not left on disk with the password in it.
func TestSweepRemovesCredentialDirsOfDeadProcesses(t *testing.T) {
	parent := t.TempDir()
	dead := filepath.Join(parent, ".safegrd-mysql-999999-x")
	mine := filepath.Join(parent, fmt.Sprintf(".safegrd-mysql-%d-x", os.Getpid()))
	for _, d := range []string{dead, mine} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sweepWorkDirs(parent, ".safegrd-mysql-")
	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Error("a dead process's credential directory was kept")
	}
	if _, err := os.Stat(mine); err != nil {
		t.Errorf("this process's own credential directory was removed: %v", err)
	}
}
