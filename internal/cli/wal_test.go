package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/safegrd/cli/pkg/wal"
)

func TestRestoreCommandQuotesForTheShellAndNeverCarriesTheKey(t *testing.T) {
	old := cfgFile
	cfgFile = "/etc/safe grd/config.yaml"
	defer func() { cfgFile = old }()
	a := &wal.Archive{SurfaceID: "appdb", SystemID: "7697520923061272610"}
	cmd, err := walFetchCommand(a, "", "AGE-SECRET-KEY-1EXAMPLE", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, "--config '/etc/safe grd/config.yaml' wal fetch --surface appdb --system 7697520923061272610") || !strings.HasSuffix(cmd, " %f %p") {
		t.Fatalf("restore_command %q", cmd)
	}
	if strings.Contains(cmd, "AGE-SECRET-KEY") {
		t.Fatalf("restore_command carries the key itself: %q", cmd)
	}
	cmd, err = walFetchCommand(a, "", "env:PGKEY", "")
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

// restore_command's exit code is what PostgreSQL reads: 1 says the archive
// does not hold the file and the replay ends there; anything else the
// command cannot do (no key, no storage) exits above 125, which stops
// recovery instead of promoting with WAL missing.
func TestAFetchExitsOneOnlyWhenTheArchiveLacksTheFile(t *testing.T) {
	ctx := context.Background()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Execute loads the config from cfgFile, so the test's is a file.
	store := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf(`daemon:
  state_dir: %q
storage:
  type: "local"
  local_path: %q
  node_id: "node-1"
encryption:
  public_key: %q
surfaces:
  - id: "db"
    type: "postgres"
    database_url: "postgres://walrep@127.0.0.1:1/app"
    wal: {}
`, filepath.Join(dir, "state"), store, id.Recipient().String())), 0o600); err != nil {
		t.Fatal(err)
	}
	oldFile, oldCfg := cfgFile, cfg
	cfgFile = cfgPath
	defer func() { cfgFile, cfg = oldFile, oldCfg }()
	st, err := wal.NewDirStore(store, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	a := &wal.Archive{Store: st, SurfaceID: "db", SystemID: "7697520923061272610", Recipient: id.Recipient().String()}
	if err := a.Push(ctx, "000000010000000000000001", bytes.NewReader(bytes.Repeat([]byte{7}, 4096))); err != nil {
		t.Fatal(err)
	}
	code := func(args ...string) int {
		t.Helper()
		c := newWALFetchCmd()
		c.SetArgs(append([]string{"--surface", "db"}, args...))
		err := c.ExecuteContext(ctx)
		var ee *exitError
		switch {
		case err == nil:
			return 0
		case errors.As(err, &ee):
			return ee.code
		}
		return exitCodeOf(err)
	}
	dst := filepath.Join(dir, "out")
	if got := code("--key-path", keyPath, "000000010000000000000001", dst); got != 0 {
		t.Fatalf("fetching a file the archive holds exited %d", got)
	}
	if b, err := os.ReadFile(dst); err != nil || len(b) != 4096 || b[0] != 7 {
		t.Fatalf("the fetched file: %d bytes, %v", len(b), err)
	}
	if got := code("--key-path", keyPath, "000000010000000000000002", filepath.Join(dir, "absent")); got != 1 {
		t.Fatalf("fetching a file the archive does not hold exited %d, want 1", got)
	}
	if got := code("--key-path", filepath.Join(dir, "no-such-key"), "000000010000000000000001", filepath.Join(dir, "out2")); got != exitRecoveryStop {
		t.Fatalf("fetching with no key exited %d, want %d so that recovery stops", got, exitRecoveryStop)
	}
}
