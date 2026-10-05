package cli

import (
	"slices"
	"strings"
	"testing"
)

// The local MCP's restore ran `safegrd restore --target postgres://user:pass@…`,
// so the password sat in ps for the restore and the agent read the warning
// about it. The URL goes through the environment instead.
func TestTheLocalMCPRestoreKeepsTheURLOutOfTheCommandLine(t *testing.T) {
	url := "postgres://app:secret@db:5432/app_restored"
	argv, env := targetToEnv([]string{"restore", "--snapshot", "snap-1", "--target", url})
	if slices.ContainsFunc(argv, func(a string) bool { return strings.Contains(a, "secret") }) {
		t.Errorf("the password is on the command line: %v", argv)
	}
	if !slices.Equal(argv, []string{"restore", "--snapshot", "snap-1", "--target", "env:SAFEGRD_MCP_TARGET"}) ||
		!slices.Equal(env, []string{"SAFEGRD_MCP_TARGET=" + url}) {
		t.Errorf("argv %v, env %v", argv, env)
	}
	if argv, env := targetToEnv([]string{"restore", "--snapshot", "snap-1", "--target-dir", "/restore"}); env != nil || argv[4] != "/restore" {
		t.Errorf("a directory restore changed: %v %v", argv, env)
	}
}
