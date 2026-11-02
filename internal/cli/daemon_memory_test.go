package cli

import (
	"sync"
	"testing"
	"time"
)

// forgetWhatTheDaemonSaid clears what a resident daemon remembers for the
// life of its process (what it has said once, what it last checked), now and
// when the test ends. Without it a test that says something about surface
// "db" silences the same line in the next test that uses that id.
//
// Every test that runs reconcileSurfaces calls it.
func forgetWhatTheDaemonSaid(t *testing.T) {
	t.Helper()
	forget := func() {
		consoleSettingsSaid = map[string]bool{}
		repeatedIDSaid = map[string]bool{}
		probeSaid = map[string]string{}
		walArchiverSaid = map[string]string{}
		walSizeChecked = map[string]time.Time{}
		walHeldChecked = map[string]time.Time{}
		blackoutSaid = sync.Map{}
		projectCopiesSaid = sync.Map{}
		exportConfigSaid = ""
		recordedMemo.mu.Lock()
		recordedMemo.m = nil
		recordedMemo.mu.Unlock()
	}
	forget()
	t.Cleanup(forget)
}

// The reset clears every one of them.
func TestForgettingWhatTheDaemonSaidClearsIt(t *testing.T) {
	consoleSettingsSaid["db"] = true
	repeatedIDSaid["db"] = true
	probeSaid["db"] = "x"
	walArchiverSaid["db"] = "x"
	blackoutSaid.Store("db", true)
	projectCopiesSaid.Store("db", true)
	exportConfigSaid = "x"
	forgetWhatTheDaemonSaid(t)
	_, b := blackoutSaid.Load("db")
	_, p := projectCopiesSaid.Load("db")
	if consoleSettingsSaid["db"] || repeatedIDSaid["db"] || probeSaid["db"] != "" || walArchiverSaid["db"] != "" || b || p || exportConfigSaid != "" {
		t.Fatal("something the daemon said is still remembered")
	}
}
