package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/config"
)

// A schedule below the floor runs at the floor, never at its own cadence: a
// "30m" surface backed up 40 minutes ago is not due. This test used to assert
// that "30m" meant thirty minutes, which under Object Lock is 48 undeletable
// objects a day.
func TestIsSurfaceDueNeverRunsBelowTheFloor(t *testing.T) {
	now := time.Now().UTC()
	surf := &config.SurfaceConfig{ID: "pg-floor", Type: "postgres", Schedule: "30m"}
	st := &SurfaceState{SurfaceID: surf.ID, LastSuccess: now.Add(-40 * time.Minute)}
	if due, next := isSurfaceDue(surf, st, now); due || !next.Equal(st.LastSuccess.Add(time.Hour)) {
		t.Errorf("a 30m schedule 40 minutes after a success: due=%t next=%v, want not due until the 1h floor", due, next)
	}
}

func TestEffectiveScheduleInheritsTheDefaults(t *testing.T) {
	c := &config.CLIConfig{Defaults: config.DefaultsConfig{Schedule: "@hourly"}}
	if got := effectiveSchedule(c, config.SurfaceConfig{ID: "a"}); got != "@hourly" {
		t.Errorf("a surface with no schedule got %q, want the defaults' @hourly", got)
	}
	if got := effectiveSchedule(c, config.SurfaceConfig{ID: "b", Schedule: "6h"}); got != "6h" {
		t.Errorf("a surface's own schedule was overridden: got %q", got)
	}
}

func TestIsSurfaceDue(t *testing.T) {
	now := time.Now().UTC()
	surf := &config.SurfaceConfig{
		ID:       "pg-due-test",
		Type:     "postgres",
		Schedule: "@hourly",
	}

	// 1. Never backed up -> Due immediately
	st1 := &SurfaceState{
		SurfaceID: surf.ID,
	}
	due, _ := isSurfaceDue(surf, st1, now)
	if !due {
		t.Errorf("expected surface never backed up to be due immediately")
	}

	// 2. Backed up 10 minutes ago -> Not due
	st2 := &SurfaceState{
		SurfaceID:   surf.ID,
		LastSuccess: now.Add(-10 * time.Minute),
	}
	due, nextDue := isSurfaceDue(surf, st2, now)
	if due {
		t.Errorf("expected surface backed up 10m ago to NOT be due for @hourly")
	}
	if nextDue.Before(now) {
		t.Errorf("expected nextDue in future, got %v", nextDue)
	}

	// 3. Backed up 2 hours ago -> Due now
	st3 := &SurfaceState{
		SurfaceID:   surf.ID,
		LastSuccess: now.Add(-2 * time.Hour),
	}
	due, _ = isSurfaceDue(surf, st3, now)
	if !due {
		t.Errorf("expected surface backed up 2h ago to be due for @hourly")
	}

	// 4. A failure is retried 5 minutes after the attempt, whatever the
	// schedule, up to three tries in all
	st4 := &SurfaceState{
		SurfaceID:           surf.ID,
		LastSuccess:         now.Add(-10 * time.Minute),
		LastAttempt:         now.Add(-2 * time.Minute),
		ConsecutiveFailures: 1,
	}
	if due, next := isSurfaceDue(surf, st4, now); due || !next.Equal(st4.LastAttempt.Add(5*time.Minute)) {
		t.Errorf("a failure 2 minutes ago: due %v, next %s; want not due, retry 5 minutes after the attempt", due, next)
	}
	st4.LastAttempt = now.Add(-6 * time.Minute)
	if due, _ := isSurfaceDue(surf, st4, now); !due {
		t.Errorf("a surface that failed 6 minutes ago is not retried; its schedule is %s and it backed up 10 minutes before", surf.Schedule)
	}
	// 5. After the third failed try it waits for the next scheduled run.
	st4.ConsecutiveFailures = 3
	if due, next := isSurfaceDue(surf, st4, now); due || !next.Equal(st4.LastAttempt.Add(time.Hour)) {
		t.Errorf("after three tries: due %v, next %s; want the next hourly run after the last attempt", due, next)
	}
}

func TestDaemonLockingAndStaleRecovery(t *testing.T) {
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "test.lock")

	// 1. Normal lock acquisition
	release, err := acquireLock(lockPath, "test-surf", "snap-001")
	if err != nil {
		t.Fatalf("failed to acquire lock: %v", err)
	}

	// Second acquisition by live PID must fail
	_, err = acquireLock(lockPath, "test-surf", "snap-002")
	if err == nil {
		t.Fatalf("expected error acquiring already held lock")
	}

	// Release lock
	release()

	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Errorf("expected lockfile to be removed upon release")
	}

	// 2. Stale lock recovery: a lock left by a process that has exited.
	staleLock := LockInfo{
		PID:        deadPID(t),
		StartTime:  time.Now().UTC().Add(-3 * time.Hour),
		SnapshotID: "snap-stale",
		SurfaceID:  "test-surf",
	}
	data, err := json.Marshal(staleLock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Attempting acquisition should reclaim the stale lock
	release2, err := acquireLock(lockPath, "test-surf", "snap-new")
	if err != nil {
		t.Fatalf("expected stale lock to be reclaimed, got: %v", err)
	}
	var now LockInfo
	if b, err := os.ReadFile(lockPath); err != nil || json.Unmarshal(b, &now) != nil || now.SnapshotID != "snap-new" || now.PID != os.Getpid() {
		t.Fatalf("the reclaimed lock reads %+v (%v), want this process's, for snap-new", now, err)
	}
	release2()
}

// deadPID is the PID of a process that has exited and been reaped. A fixed
// number such as 999999 can be a live process on Linux, where PIDs go up to
// 4194304.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatalf("starting a process to outlive: %v", err)
	}
	return cmd.Process.Pid
}

// A lock that names this process's PID and that this process did not take
// was left by an earlier process with the same PID: in a container the
// daemon is PID 1, and after a crash the restarted daemon found its own PID
// in the lock and refused to start for two hours. A zombie's PID answers
// signal 0, so it counted as running too.
func TestALockLeftUnderThisProcesssPIDIsStale(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "daemon.lock")
	left, _ := json.Marshal(LockInfo{PID: os.Getpid(), StartTime: time.Now().UTC(), SurfaceID: daemonLockID})
	if err := os.WriteFile(lockPath, left, 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := acquireLock(lockPath, daemonLockID, "")
	if err != nil {
		t.Fatalf("a lock left under this PID by an earlier process was refused: %v", err)
	}
	// Held by this process now: a second take in the same process is refused.
	if _, err := acquireLock(lockPath, daemonLockID, ""); err == nil {
		t.Fatal("a lock this process holds was taken twice")
	}
	release()
}

// The daemon's lock has no age limit: a daemon runs for as long as the host
// is up, and after two hours a second daemon took its lock over.
func TestALiveDaemonsLockIsHeldPastTwoHours(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "daemon.lock")
	parent := os.Getppid()
	old, _ := json.Marshal(LockInfo{PID: parent, StartTime: time.Now().UTC().Add(-5 * time.Hour), SurfaceID: daemonLockID})
	if err := os.WriteFile(lockPath, old, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := acquireLock(lockPath, daemonLockID, "")
	if err == nil || !strings.Contains(err.Error(), "another daemon is running") {
		t.Fatalf("a live daemon's lock from 5 hours ago: %v", err)
	}
}

func TestDaemonStatePersistence(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "daemon_state.json")

	state := loadDaemonState(statePath)
	if state.DaemonID == "" {
		t.Errorf("expected non-empty daemon ID generated")
	}

	now := time.Now().UTC()
	state.Surfaces["surf-01"] = &SurfaceState{
		SurfaceID:      "surf-01",
		SurfaceType:    "files",
		LastSuccess:    now,
		LastSnapshotID: "snap-abc",
	}

	if err := saveDaemonState(statePath, state); err != nil {
		t.Fatalf("failed to save daemon state: %v", err)
	}

	// Reload state
	loaded := loadDaemonState(statePath)
	if loaded.DaemonID != state.DaemonID {
		t.Errorf("expected daemon ID %s, got %s", state.DaemonID, loaded.DaemonID)
	}
	surf := loaded.Surfaces["surf-01"]
	if surf == nil || surf.LastSnapshotID != "snap-abc" {
		t.Errorf("surface state did not persist properly: %+v", surf)
	}
}

// A host clock that jumps backwards must not stop backups until it catches
// up: the surface is due now.
func TestABackwardsClockDoesNotStallTheSchedule(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	s := &config.SurfaceConfig{ID: "db", Schedule: "1h"}
	st := &SurfaceState{LastSuccess: now.Add(72 * time.Hour), LastAttempt: now.Add(72 * time.Hour)}
	if due, _ := isSurfaceDue(s, st, now); !due {
		t.Error("a surface whose last success is three days in the future is not due")
	}
	st = &SurfaceState{LastSuccess: now.Add(-2 * time.Hour), LastAttempt: now.Add(48 * time.Hour), ConsecutiveFailures: 3}
	if due, _ := isSurfaceDue(s, st, now); !due {
		t.Error("a failure recorded in the future holds the backoff open")
	}
	st = &SurfaceState{LastSuccess: now.Add(-30 * time.Minute), LastAttempt: now.Add(-30 * time.Minute)}
	if due, _ := isSurfaceDue(s, st, now); due {
		t.Error("an hourly surface backed up 30 minutes ago is due")
	}
}

// A backup that finished inside a millisecond still took time. Truncating it to
// 0 wrote manifests that read as a backup that never ran, and the daemon-loop
// end-to-end test caught one.
func TestBackupMillisecondsRoundsUpNeverDown(t *testing.T) {
	if got := backupMilliseconds(time.Now()); got < 1 {
		t.Errorf("a backup started just now took %d ms, want at least 1", got)
	}
	if got := backupMilliseconds(time.Now().Add(-1500 * time.Millisecond)); got < 1500 || got > 1600 {
		t.Errorf("a backup of 1.5 s took %d ms, want 1500 or a little over", got)
	}
	if got := backupMilliseconds(time.Now().Add(time.Hour)); got != 0 {
		t.Errorf("a start in the future gave %d ms, want 0", got)
	}
}

// Two daemons starting together both used to proceed: the lock was read,
// checked and then written. Exactly one of many processes taking it at once
// wins. They are processes, not goroutines: within one process acquireLock
// holds a mutex, so goroutines would never race on the file.
func TestDaemonLockHasOneWinnerUnderContention(t *testing.T) {
	if dir := os.Getenv("SAFEGRD_TEST_LOCK_RACE"); dir != "" {
		lockRaceChild(dir)
		return
	}
	dir := t.TempDir()
	const takers = 8
	type child struct {
		cmd *exec.Cmd
		out *bufio.Reader
	}
	var children []child
	for i := 0; i < takers; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDaemonLockHasOneWinnerUnderContention$", "-test.count=1")
		cmd.Env = append(os.Environ(), "SAFEGRD_TEST_LOCK_RACE="+dir)
		cmd.Stderr = os.Stderr
		pipe, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		children = append(children, child{cmd, bufio.NewReader(pipe)})
	}
	t.Cleanup(func() {
		for _, c := range children {
			_ = c.cmd.Process.Kill() // ends a child left waiting by a failed run; its exit is not the subject
			_ = c.cmd.Wait()         // reaps it; the result was read from its output
		}
	})
	// Each child says it is ready, then all start at once.
	for i, c := range children {
		if line, err := c.out.ReadString('\n'); err != nil || line != "ready\n" {
			t.Fatalf("child %d: %q, %v", i, line, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "go"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	wins := 0
	for i, c := range children {
		line, err := c.out.ReadString('\n')
		if err != nil {
			t.Fatalf("child %d said nothing: %v", i, err)
		}
		switch strings.TrimSpace(line) {
		case "won":
			wins++
		case "lost":
		default:
			t.Fatalf("child %d: %q", i, line)
		}
	}
	// The winner holds the lock until every child has tried.
	if err := os.WriteFile(filepath.Join(dir, "done"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if wins != 1 {
		t.Fatalf("%d of %d processes held the lock at once, want 1", wins, takers)
	}
}

// lockRaceChild is one taker: it waits for the start, takes the lock, says
// whether it won, and holds it until told the race is over.
func lockRaceChild(dir string) {
	fmt.Println("ready")
	wait := func(name string) {
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return
			}
		}
		os.Exit(3)
	}
	wait("go")
	if _, err := acquireLock(filepath.Join(dir, "race.lock"), "race", ""); err == nil {
		fmt.Println("won")
	} else {
		fmt.Println("lost")
	}
	wait("done")
}

// A surface's backups are locked for its own retention_days, else its own
// storage block's, else the config's storage: a surface with a storage block
// and no retention was locked for zero days while registering thirty.
func TestASurfaceRetentionFallsBackThroughItsStorage(t *testing.T) {
	c := config.NewDefaultCLIConfig()
	c.Storage.RetentionDays = 30
	for _, tc := range []struct {
		s    config.SurfaceConfig
		want int
	}{
		{config.SurfaceConfig{ID: "a", RetentionDays: 7}, 7},
		{config.SurfaceConfig{ID: "b", Storage: &config.StorageConfig{Type: config.StorageTypeLocal, RetentionDays: 45}}, 45},
		{config.SurfaceConfig{ID: "c", Storage: &config.StorageConfig{Type: config.StorageTypeLocal}}, 30},
		{config.SurfaceConfig{ID: "d"}, 30},
	} {
		if got := surfaceRetentionDays(c, &tc.s); got != tc.want {
			t.Errorf("surface %s: %d days, want %d", tc.s.ID, got, tc.want)
		}
	}
}

// A process this user may not signal is alive: signal 0 answers EPERM for
// another user's process, and reading that as dead let a host's own CLI
// take over the lock of a daemon running as root.
func TestAProcessOfAnotherUserIsAlive(t *testing.T) {
	if !isPIDAlive(1) {
		t.Error("PID 1 reads as dead")
	}
	if !isPIDAlive(os.Getpid()) {
		t.Error("this process reads as dead")
	}
	if pid := deadPID(t); isPIDAlive(pid) {
		t.Errorf("PID %d, which exited, reads as alive", pid)
	}
}
