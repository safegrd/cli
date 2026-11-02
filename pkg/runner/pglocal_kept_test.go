package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A local sandbox kept after a failed drill survives the sweep until its day
// is up, and goes with the next sweep after; one without a marker is a
// leftover and goes at once.
func TestTheSweepKeepsAKeptSandboxForItsDay(t *testing.T) {
	state := t.TempDir()
	socks := t.TempDir()
	mk := func(name string, until time.Time) string {
		sock := filepath.Join(socks, "safegrd-pg-"+name)
		if err := os.MkdirAll(sock, 0o700); err != nil {
			t.Fatal(err)
		}
		d := filepath.Join(state, "drill", localSandboxPrefix+name)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if !until.IsZero() {
			b, err := json.Marshal(keptSandbox{Until: until, SockDir: sock})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, keptMarker), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	kept := mk("kept", time.Now().Add(time.Hour))
	expired := mk("expired", time.Now().Add(-time.Minute))
	leftover := mk("leftover", time.Time{})

	SweepLocalSandboxes(state)

	if _, err := os.Stat(kept); err != nil {
		t.Errorf("a sandbox kept for another hour was swept: %v", err)
	}
	for _, d := range []string{expired, leftover} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Errorf("%s was not swept", d)
		}
	}
	if _, err := os.Stat(filepath.Join(socks, "safegrd-pg-expired")); !os.IsNotExist(err) {
		t.Error("the expired sandbox's socket directory was left behind")
	}
	if _, err := os.Stat(filepath.Join(socks, "safegrd-pg-kept")); err != nil {
		t.Errorf("the kept sandbox's socket directory was swept: %v", err)
	}
}
