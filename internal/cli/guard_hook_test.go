package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
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

func runGuardHookFor(t *testing.T, tool, input string, allowUnlocked bool) (string, error) {
	t.Helper()
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
			out, err = runGuardHookFor(t, tool, sprintfJSON(format, `psql -c 'DROP TABLE users'`), true)
			if err != nil || out != "" {
				t.Errorf("after a snapshot: %q %v", out, err)
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
