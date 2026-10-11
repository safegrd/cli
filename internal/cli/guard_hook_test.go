package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// The stdin each tool documents for its pre-command hook, with the fields a
// real call carries.
const (
	claudeCodeInput = `{"session_id":"abc123","transcript_path":"/home/u/.claude/projects/x/t.jsonl","cwd":"/home/u/app",` +
		`"permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash",` +
		`"tool_input":{"command":%q,"description":"Run it","timeout":120000,"run_in_background":false},"tool_use_id":"toolu_01ABC"}`
	codexInput = `{"session_id":"thr_123","turn_id":"turn_456","cwd":"/home/u/app","hook_event_name":"PreToolUse",` +
		`"permission_mode":"default","tool_name":"Bash","tool_input":{"command":%q}}`
	cursorInput = `{"conversation_id":"c1","generation_id":"g1","model":"m","hook_event_name":"beforeShellExecution",` +
		`"cursor_version":"1.7","workspace_roots":["/home/u/app"],"user_email":"u@example.com","transcript_path":null,` +
		`"command":%q,"cwd":"/home/u/app","sandbox":false}`
)

// inlineGuardBackup stands in for the detached `guard --result-file`
// process: the backup runs before it returns, as a fast one would.
func inlineGuardBackup(t *testing.T) {
	t.Helper()
	old := spawnGuardBackup
	t.Cleanup(func() { spawnGuardBackup = old })
	spawnGuardBackup = func(opts guardOptions, resultPath, _ string) (int, <-chan struct{}, error) {
		opts.maxAge, opts.checkOnly = 0, false
		meta, err := guardSnapshot(context.Background(), opts, "")
		done := make(chan struct{})
		close(done)
		return os.Getpid(), done, writeGuardResult(resultPath, meta, err)
	}
}

func runGuardHookFor(t *testing.T, tool, input string, allowUnlocked bool) (string, error) {
	t.Helper()
	inlineGuardBackup(t)
	var out bytes.Buffer
	var err error
	captureStdoutErr(t, func() error {
		err = runGuardHook(context.Background(), tool, guardOptions{allowUnlocked: allowUnlocked}, strings.NewReader(input), &out)
		return nil
	})
	return out.String(), err
}

func TestClaudeCodeAndCodexHooksBlockOnlyWithoutASnapshot(t *testing.T) {
	for tool, format := range map[string]string{hookClaudeCode: claudeCodeInput, hookCodex: codexInput} {
		t.Run(tool, func(t *testing.T) {
			guardConfig(t)

			// Not on the list: let through, no backup, nothing on stdout.
			out, err := runGuardHookFor(t, tool, sprintfJSON(format, "ls -la"), false)
			if err != nil || out != "" {
				t.Errorf("a harmless command: %q %v", out, err)
			}

			// On the list, and the snapshot cannot be locked: denied with the reason.
			out, err = runGuardHookFor(t, tool, sprintfJSON(format, `psql -c 'DROP TABLE users'`), false)
			if err != nil {
				t.Fatal(err)
			}
			var ans preToolUseOutput
			if jsonErr := json.Unmarshal([]byte(out), &ans); jsonErr != nil {
				t.Fatalf("not the documented JSON: %v\n%s", jsonErr, out)
			}
			h := ans.HookSpecificOutput
			if h.HookEventName != "PreToolUse" || h.PermissionDecision != "deny" || !strings.Contains(h.PermissionDecisionReason, "not locked") {
				t.Errorf("answer %+v", h)
			}

			// On the list, snapshot taken: the normal permission flow decides.
			// Claude Code is told which snapshot covers the command; guard
			// never approves it.
			out, err = runGuardHookFor(t, tool, sprintfJSON(format, `psql -c 'DROP TABLE users'`), true)
			if err != nil {
				t.Fatal(err)
			}
			if tool == hookCodex {
				if out != "" {
					t.Errorf("after a snapshot: %q", out)
				}
				return
			}
			ans = preToolUseOutput{}
			if jsonErr := json.Unmarshal([]byte(out), &ans); jsonErr != nil {
				t.Fatalf("not the documented JSON: %v\n%s", jsonErr, out)
			}
			h = ans.HookSpecificOutput
			if h.PermissionDecision != "" || !strings.Contains(h.AdditionalContext, "To undo it: safegrd restore --snapshot snap-") {
				t.Errorf("after a snapshot: %+v", h)
			}
		})
	}
}

func TestAHookIgnoresToolsThatAreNotTheShell(t *testing.T) {
	guardConfig(t)
	in := `{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"x.sql","content":"DROP TABLE users"}}`
	out, err := runGuardHookFor(t, hookClaudeCode, in, false)
	if err != nil || out != "" {
		t.Errorf("a file write: %q %v", out, err)
	}
}

func TestTheCursorHookAlwaysAnswers(t *testing.T) {
	guardConfig(t)
	var ans cursorOutput

	out, err := runGuardHookFor(t, hookCursor, sprintfJSON(cursorInput, "npm test"), false)
	if err != nil || json.Unmarshal([]byte(out), &ans) != nil || ans.Permission != "allow" {
		t.Errorf("a harmless command: %q %v", out, err)
	}

	out, err = runGuardHookFor(t, hookCursor, sprintfJSON(cursorInput, "npx prisma migrate reset --force"), false)
	ans = cursorOutput{}
	if err != nil || json.Unmarshal([]byte(out), &ans) != nil {
		t.Fatalf("%q %v", out, err)
	}
	if ans.Permission != "deny" || !strings.Contains(ans.AgentMessage, "prisma migrate reset") || ans.UserMessage == "" {
		t.Errorf("a destructive command with no locked snapshot: %+v", ans)
	}

	out, _ = runGuardHookFor(t, hookCursor, sprintfJSON(cursorInput, "npx prisma migrate reset --force"), true)
	ans = cursorOutput{}
	if json.Unmarshal([]byte(out), &ans) != nil || ans.Permission != "allow" {
		t.Errorf("after a snapshot: %q", out)
	}
}

// Input a hook cannot read is refused, rather than letting through a command
// nothing has checked.
func TestUnreadableHookInputIsRefused(t *testing.T) {
	guardConfig(t)
	out, _ := runGuardHookFor(t, hookClaudeCode, "not json", false)
	if !strings.Contains(out, `"permissionDecision":"deny"`) {
		t.Errorf("unreadable input: %q", out)
	}
	if _, err := runGuardHookFor(t, "vim", "{}", false); err == nil {
		t.Error("an unknown --hook value was accepted")
	}
}

func sprintfJSON(format, command string) string {
	b, _ := json.Marshal(command)
	return strings.Replace(format, "%q", string(b), 1)
}

// A backup that outlasts --wait does not hold the agent: the command is
// denied with "run it again", the backup goes on, a second call waits for
// the same backup instead of starting another, and once it has finished the
// retry goes through. A backup that dies without a result is a refusal.
func TestAHookDeniesWhileItsBackupRunsAndLetsTheRetryThrough(t *testing.T) {
	guardConfig(t)
	var spawned []string
	old := spawnGuardBackup
	t.Cleanup(func() { spawnGuardBackup = old })
	spawnGuardBackup = func(_ guardOptions, resultPath, _ string) (int, <-chan struct{}, error) {
		spawned = append(spawned, resultPath)
		return os.Getpid(), make(chan struct{}), nil // still running
	}
	opts := guardOptions{allowUnlocked: true, wait: 50 * time.Millisecond}
	hook := func() preToolUseOutput {
		t.Helper()
		var out bytes.Buffer
		captureStdoutErr(t, func() error {
			return runGuardHook(context.Background(), hookClaudeCode, opts, strings.NewReader(sprintfJSON(claudeCodeInput, "psql -c 'TRUNCATE orders'")), &out)
		})
		var ans preToolUseOutput
		if out.Len() > 0 {
			if err := json.Unmarshal(out.Bytes(), &ans); err != nil {
				t.Fatalf("not the documented JSON: %v\n%s", err, out.String())
			}
		}
		return ans
	}

	h := hook().HookSpecificOutput
	if h.PermissionDecision != "deny" || !strings.Contains(h.PermissionDecisionReason, "still running") ||
		!strings.Contains(h.PermissionDecisionReason, "run the same command again") {
		t.Fatalf("while the backup runs: %+v", h)
	}
	h = hook().HookSpecificOutput
	if h.PermissionDecision != "deny" || len(spawned) != 1 {
		t.Fatalf("a second call started another backup (%d) or let the command through: %+v", len(spawned), h)
	}

	// The backup finishes.
	if err := writeGuardResult(spawned[0], &model.SnapshotMetadata{SnapshotID: "snap-20261011-120000-abcdef",
		StorageURI: "file:///store/x"}, nil); err != nil {
		t.Fatal(err)
	}
	h = hook().HookSpecificOutput
	if h.PermissionDecision != "" || !strings.Contains(h.AdditionalContext, "snap-20261011-120000-abcdef") || len(spawned) != 1 {
		t.Fatalf("the retry after the backup finished: %+v (%d backups)", h, len(spawned))
	}

	// A backup process that ends with no result refuses the command.
	if err := os.Remove(filepath.Join(cfg.Daemon.StateDir, "guard", "docs.run.json")); err != nil {
		t.Fatal(err)
	}
	spawnGuardBackup = func(_ guardOptions, _, _ string) (int, <-chan struct{}, error) {
		done := make(chan struct{})
		close(done)
		return os.Getpid(), done, nil
	}
	h = hook().HookSpecificOutput
	if h.PermissionDecision != "deny" || !strings.Contains(h.PermissionDecisionReason, "stopped without a result") {
		t.Fatalf("a backup that died: %+v", h)
	}
}

func TestAnyHookInvocationExitsTwoOnError(t *testing.T) {
	for args, want := range map[string]bool{
		"guard --hook claude-code --max-age 30":  true,
		"guard --hook=cursor":                    true,
		"guard --surface db -- grep --hook x.sh": false,
		"guard --surface db":                     false,
	} {
		if got := hookInvocation(strings.Fields(args)); got != want {
			t.Errorf("%q: %v, want %v", args, got, want)
		}
	}
}
