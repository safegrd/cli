package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/safegrd/cli/pkg/model"
)

// layoutWith makes install.sh's versions directory with the releases named,
// current pointing at the first, and an updater for it as a daemon running
// that release with the state in its own directory.
func layoutWith(t *testing.T, versions ...string) *updater {
	t.Helper()
	root := t.TempDir()
	for _, v := range versions {
		dir := filepath.Join(root, "versions", v)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "safegrd"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	l := &hostLayout{root: root}
	if err := l.setLink("current", versions[0]); err != nil {
		t.Fatal(err)
	}
	old := Version
	Version = versions[0]
	t.Cleanup(func() { Version = old })
	u, err := newUpdater("", "", t.TempDir(), []string{"daemon", "run"})
	if err != nil {
		t.Fatal(err)
	}
	u.layout, u.installedBy = l, model.InstalledByInstaller
	return u
}

// noExec records what the updater would have exec'd, and fails the exec.
func noExec(t *testing.T) *[]string {
	t.Helper()
	var ran []string
	old := execImage
	execImage = func(bin string, _ []string) error {
		ran = append(ran, bin)
		return errors.New("not in a test")
	}
	t.Cleanup(func() { execImage = old })
	return &ran
}

func TestAnUpdateNeverGoesToTheReleaseRunningOrAnOlderOne(t *testing.T) {
	for _, v := range []string{"0.0.5", "0.0.4", "v0.0.1"} {
		u := layoutWith(t, "0.0.5", "0.0.4")
		ran := noExec(t)
		err := u.install(context.Background(), &model.UpdateRequest{ID: "r1", Action: model.UpdateActionInstall, Version: v})
		if err == nil || !strings.Contains(err.Error(), "only to a newer release") {
			t.Fatalf("installing %s on 0.0.5: %v, want a refusal", v, err)
		}
		if got := u.layout.link("current"); got != "0.0.5" || len(*ran) != 0 {
			t.Fatalf("installing %s moved current to %q and ran %v", v, got, *ran)
		}
	}
}

func TestAReleaseThatDoesNotVerifyIsNeverSwitchedTo(t *testing.T) {
	// Served, but signed by nothing this test build trusts.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("data for " + r.URL.Path))
	}))
	defer ts.Close()
	u := layoutWith(t, "0.0.1")
	u.baseURL = ts.URL
	ran := noExec(t)
	err := u.install(context.Background(), &model.UpdateRequest{ID: "r1", Action: model.UpdateActionInstall, Version: "0.0.2"})
	if err == nil || !strings.Contains(err.Error(), "downloading 0.0.2") {
		t.Fatalf("an unverifiable release: %v", err)
	}
	if got := u.layout.link("current"); got != "0.0.1" || len(*ran) != 0 || u.rec.Pending != nil {
		t.Fatalf("after refusing: current %q, ran %v, pending %+v", got, *ran, u.rec.Pending)
	}
}

func TestGoingBackNeedsAReleaseOnTheHostWhoseStateItCanRead(t *testing.T) {
	u := layoutWith(t, "0.0.2", "0.0.1")
	noExec(t)
	if err := u.revert(&model.UpdateRequest{ID: "r1", Action: model.UpdateActionRevert}); err == nil || !strings.Contains(err.Error(), "no earlier release") {
		t.Fatalf("with no previous link: %v", err)
	}
	if err := u.layout.setLink("previous", "0.0.1"); err != nil {
		t.Fatal(err)
	}
	u.rec.PreviousFormat = stateFormat - 1
	if err := u.revert(&model.UpdateRequest{ID: "r2", Action: model.UpdateActionRevert}); err == nil || !strings.Contains(err.Error(), "cannot read") {
		t.Fatalf("with a previous release older than the state: %v", err)
	}
	u.rec.PreviousFormat = stateFormat
	err := u.revert(&model.UpdateRequest{ID: "r3", Action: model.UpdateActionRevert})
	if err == nil || !strings.Contains(err.Error(), "could not start 0.0.1") {
		t.Fatalf("going back with the exec failing: %v", err)
	}
	// The exec failed, so everything is put back as it was.
	if c, p := u.layout.link("current"), u.layout.link("previous"); c != "0.0.2" || p != "0.0.1" {
		t.Fatalf("after a failed exec: current %q previous %q", c, p)
	}
}

func TestAReleaseThatDoesNotCheckInGoesBackToTheOneBefore(t *testing.T) {
	u := layoutWith(t, "0.0.2", "0.0.1")
	if err := u.layout.setLink("previous", "0.0.1"); err != nil {
		t.Fatal(err)
	}
	ran := noExec(t)
	u.rec.Pending = &pendingSwitch{From: "0.0.1", To: "0.0.2"}
	lockDir := t.TempDir()

	u.afterPass(context.Background(), lockDir)
	if len(*ran) != 0 {
		t.Fatalf("rolled back after one pass")
	}
	u.afterPass(context.Background(), lockDir)
	if len(*ran) != 1 || !strings.HasSuffix((*ran)[0], filepath.Join("current", "safegrd")) {
		t.Fatalf("after two passes without a check-in it ran %v", *ran)
	}
	if c, p := u.layout.link("current"), u.layout.link("previous"); c != "0.0.1" || p != "" {
		t.Fatalf("after rolling back: current %q previous %q", c, p)
	}
	if u.rec.Failed != "0.0.2" || u.rec.Change != model.UpdateChangeRolledBack || !strings.Contains(u.rec.FailedReason, "did not check in") {
		t.Fatalf("recorded %+v", u.rec)
	}
	st := u.report(60)
	if st.Failed != "0.0.2" || st.Previous != "" || st.Running != "0.0.2" {
		t.Fatalf("reported %+v", st)
	}
}

func TestACheckInConfirmsTheSwitch(t *testing.T) {
	u := layoutWith(t, "0.0.2", "0.0.1")
	ran := noExec(t)
	u.rec.Pending = &pendingSwitch{From: "0.0.1", To: "0.0.2"}
	u.heard(&model.HeartbeatResponse{LatestCLIVersion: "0.0.2"})
	for range 3 {
		u.afterPass(context.Background(), t.TempDir())
	}
	if u.rec.Pending != nil || len(*ran) != 0 {
		t.Fatalf("a release that checked in: pending %+v, ran %v", u.rec.Pending, *ran)
	}
	// Read back by the next start: nothing pending.
	again, _ := newUpdater("", "", u.stateDir, nil)
	if again.rec.Pending != nil {
		t.Fatalf("update.json still holds %+v", again.rec.Pending)
	}
}

func TestAReleaseThatKeepsFailingToStartGoesBack(t *testing.T) {
	u := layoutWith(t, "0.0.2", "0.0.1")
	if err := u.layout.setLink("previous", "0.0.1"); err != nil {
		t.Fatal(err)
	}
	ran := noExec(t)
	u.rec.Pending = &pendingSwitch{From: "0.0.1", To: "0.0.2"}
	for i := 1; i <= updateMaxStarts; i++ {
		u.start()
		if len(*ran) != 0 {
			t.Fatalf("went back at start %d", i)
		}
	}
	u.start()
	if len(*ran) != 1 || u.layout.link("current") != "0.0.1" || !strings.Contains(u.rec.FailedReason, "started 3 times") {
		t.Fatalf("after %d starts: ran %v, current %q, %q", updateMaxStarts+1, *ran, u.layout.link("current"), u.rec.FailedReason)
	}
}

func TestARequestWaitsForAnotherSafegrdHoldingALock(t *testing.T) {
	lockDir := t.TempDir()
	if busy := otherSafegrdRunning(lockDir); busy != "" {
		t.Fatalf("an empty lock directory: %q", busy)
	}
	release, err := acquireLock(filepath.Join(lockDir, "data.lock"), "data", "")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// The lock is this process's own, as the daemon's are: not another's.
	if busy := otherSafegrdRunning(lockDir); busy != "" {
		t.Fatalf("this process's own lock: %q", busy)
	}
	// The test's parent process is alive and is not this one.
	other := fmt.Sprintf(`{"pid":%d,"surface_id":"other"}`, os.Getppid())
	os.WriteFile(filepath.Join(lockDir, "other.lock"), []byte(other), 0o600)
	if busy := otherSafegrdRunning(lockDir); !strings.Contains(busy, fmt.Sprintf("PID %d", os.Getppid())) {
		t.Fatalf("a lock held by another live process: %q", busy)
	}
}

func TestADevelopmentBuildSaysItDoesNotUpdate(t *testing.T) {
	u := layoutWith(t, "0.0.1")
	Version = "dev"
	if why := u.blocked(); !strings.Contains(why, "development build") {
		t.Fatalf("a dev build: %q", why)
	}
}

// A release downloaded earlier that no longer passes its checks (changed on
// disk, cut short) is downloaded again, not refused on every request.
func TestADamagedDownloadIsFetchedAgain(t *testing.T) {
	var fetched atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetched.Add(1)
		w.Write([]byte("data"))
	}))
	defer ts.Close()
	u := layoutWith(t, "0.0.1")
	u.baseURL = ts.URL
	noExec(t)
	dir := u.layout.versionDir("0.0.2")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte("damaged"), 0o644)
	u.rec.Staged = "0.0.2"

	err := u.install(context.Background(), &model.UpdateRequest{ID: "r1", Action: model.UpdateActionInstall, Version: "0.0.2"})
	if err == nil || !strings.Contains(err.Error(), "downloading 0.0.2") {
		t.Fatalf("installing a damaged download: %v", err)
	}
	if fetched.Load() == 0 {
		t.Fatal("the damaged download was not fetched again")
	}
	again, _ := newUpdater("", "", u.stateDir, nil)
	if again.rec.Staged != "" || u.layout.link("current") != "0.0.1" {
		t.Fatalf("after a damaged download: staged %q saved, current %q", again.rec.Staged, u.layout.link("current"))
	}
}
