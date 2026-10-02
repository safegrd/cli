package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// The hook formats guard answers, as each tool documents its pre-command hook.
//
// Claude Code and Codex (PreToolUse): the tool call arrives on stdin as
// {"tool_name": "Bash", "tool_input": {"command": "..."}}. Printing nothing
// and exiting 0 lets the call through the normal permission flow; printing
// {"hookSpecificOutput": {"hookEventName": "PreToolUse",
// "permissionDecision": "deny", "permissionDecisionReason": "..."}} blocks it
// and tells the agent why.
//
// Cursor (beforeShellExecution): {"command": "...", "cwd": "..."} on stdin,
// and it reads {"permission": "allow"|"deny", "user_message": "...",
// "agent_message": "..."} on stdout. Invalid JSON blocks the command, so
// guard always answers.
const (
	hookClaudeCode = "claude-code"
	hookCodex      = "codex"
	hookCursor     = "cursor"
)

type hookInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
	Command string `json:"command"`
}

type preToolUseOutput struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

type cursorOutput struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

// runGuardHook answers one pre-command hook: a command that matches the
// destructive list is backed up first, and blocked when no locked snapshot
// could be taken. Anything else passes with no backup.
func runGuardHook(ctx context.Context, tool, surfaceID string, allowUnlocked bool, in io.Reader, out io.Writer) error {
	switch tool {
	case hookClaudeCode, hookCodex, hookCursor:
	default:
		return fmt.Errorf("--hook %q: want claude-code, cursor or codex", tool)
	}
	var h hookInput
	if err := json.NewDecoder(io.LimitReader(in, 1<<20)).Decode(&h); err != nil {
		return hookAnswer(tool, out, "", fmt.Sprintf("safegrd guard could not read the hook input: %v", err))
	}
	command := h.Command
	if tool != hookCursor {
		// Only shell commands carry something to match.
		if h.ToolName != "" && h.ToolName != "Bash" && h.ToolName != "shell" {
			return hookAnswer(tool, out, "", "")
		}
		command = h.ToolInput.Command
	}
	rule := matchDestructive(command)
	if rule == nil {
		return hookAnswer(tool, out, "", "")
	}
	if cfgLoadErr != nil {
		return hookAnswer(tool, out, "", fmt.Sprintf(
			"Blocked by safegrd guard: this command matches %q, and the SafeGrd config could not be read, "+
				"so no snapshot could be taken first: %v", rule.Name, cfgLoadErr))
	}
	snap, err := guardSnapshot(ctx, surfaceID, allowUnlocked, describeCommand([]string{command}))
	if err != nil {
		return hookAnswer(tool, out, "", fmt.Sprintf(
			"Blocked by safegrd guard: this command matches %q, and no locked snapshot could be taken first: %v. "+
				"Fix the backup, then run the command again.", rule.Name, err))
	}
	return hookAnswer(tool, out, snap.SnapshotID, "")
}

// hookAnswer writes the tool's answer. An empty reason lets the command run.
func hookAnswer(tool string, out io.Writer, snapshotID, reason string) error {
	if tool == hookCursor {
		ans := cursorOutput{Permission: "allow"}
		if reason != "" {
			ans = cursorOutput{Permission: "deny", UserMessage: reason, AgentMessage: reason}
		}
		return json.NewEncoder(out).Encode(ans)
	}
	if reason == "" {
		if snapshotID != "" {
			fmt.Fprintf(os.Stderr, "safegrd guard: locked snapshot %s taken first\n", snapshotID)
		}
		return nil
	}
	var ans preToolUseOutput
	ans.HookSpecificOutput.HookEventName = "PreToolUse"
	ans.HookSpecificOutput.PermissionDecision = "deny"
	ans.HookSpecificOutput.PermissionDecisionReason = strings.TrimSpace(reason)
	return json.NewEncoder(out).Encode(ans)
}
