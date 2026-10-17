package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/wal"
)

func TestRestoreCommandQuotesForTheShellAndNeverCarriesTheKey(t *testing.T) {
	old := cfgFile
	cfgFile = "/etc/safe grd/config.yaml"
	defer func() { cfgFile = old }()
	a := &wal.Archive{SurfaceID: "appdb", SystemID: "7697520923061272610"}
	cmd, err := walFetchCommand(a, "", "AGE-SECRET-KEY-1EXAMPLE")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "--config '/etc/safe grd/config.yaml' wal fetch --surface appdb --system 7697520923061272610") || !strings.HasSuffix(cmd, " %f %p") {
		t.Fatalf("restore_command %q", cmd)
	}
	if strings.Contains(cmd, "AGE-SECRET-KEY") {
		t.Fatalf("restore_command carries the key itself: %q", cmd)
	}
	cmd, err = walFetchCommand(a, "", "env:PGKEY")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "--private-key env:PGKEY") {
		t.Fatalf("a key given by reference is not passed on: %q", cmd)
	}
	if got := shellQuote("it's"); got != `'it'\''s'` {
		t.Fatalf("shellQuote: %s", got)
	}
}

func TestARestoreTargetIsReadAsUTC(t *testing.T) {
	want := time.Date(2026, 10, 17, 14, 52, 0, 0, time.UTC)
	for _, in := range []string{"2026-10-17T14:52:00Z", "2026-10-17 14:52:00", "2026-10-17T16:52:00+02:00", "2026-10-17 14:52"} {
		got, err := parseWALTarget(in)
		if err != nil || !got.Equal(want) {
			t.Fatalf("%q read as %s %v", in, got, err)
		}
	}
	if _, err := parseWALTarget("yesterday"); err == nil {
		t.Fatal("a target that is not a time was accepted")
	}
}
