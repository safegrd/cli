package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/model"
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
		PermissionDecision       string `json:"permissionDecision,omitempty"`
		PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
		AdditionalContext        string `json:"additionalContext,omitempty"`
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
func runGuardHook(ctx context.Context, tool string, opts guardOptions, in io.Reader, out io.Writer) error {
	switch tool {
	case hookClaudeCode, hookCodex, hookCursor:
	default:
		return fmt.Errorf("--hook %q: want claude-code, cursor or codex", tool)
	}
	if opts.maxAge <= 0 {
		opts.maxAge = hookDefaultMaxAge
	}
	if opts.wait <= 0 {
		opts.wait = hookDefaultWait
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
	snap, reused, err := guardHookSnapshot(ctx, opts, describeCommand([]string{command}))
	var running *backupRunningError
	switch {
	case errors.As(err, &running):
		return hookAnswer(tool, out, "", fmt.Sprintf(
			"Blocked by safegrd guard: this command matches %q, and %s. "+
				"Wait a minute, then run the same command again: it goes through once the snapshot is locked.",
			rule.Name, running.Error()))
	case err != nil:
		what := "no locked snapshot could be taken first"
		if opts.checkOnly {
			what = "no locked snapshot is recent enough"
		}
		return hookAnswer(tool, out, "", fmt.Sprintf(
			"Blocked by safegrd guard: this command matches %q, and %s: %v. "+
				"Fix the backup, then run the command again.", rule.Name, what, firstLine(err)))
	}
	return hookAnswer(tool, out, snapshotNote(snap, reused), "")
}

// snapshotNote tells the agent which snapshot covers the command and how to
// undo it, so it can tell the person it works for.
func snapshotNote(snap *model.SnapshotMetadata, reused bool) string {
	note := fmt.Sprintf("safegrd guard: locked snapshot %s was taken before this command.", snap.SnapshotID)
	if locked, _ := snapshotLocked(snap, time.Now()); !locked {
		note = fmt.Sprintf("safegrd guard: snapshot %s (not locked) was taken before this command.", snap.SnapshotID)
	}
	if reused {
		note = fmt.Sprintf("safegrd guard: snapshot %s, taken %s ago, covers this command; no new backup was taken. "+
			"Changes made since then are not in it.", snap.SnapshotID, time.Since(snap.CreatedAt).Round(time.Minute))
	}
	if snap.SurfaceType == model.SurfaceTypePostgres || snap.SurfaceType == "" {
		note += fmt.Sprintf(" To undo it for one table: safegrd restore --snapshot %s --table <schema.table> --target <database URL>", snap.SnapshotID)
	} else {
		note += fmt.Sprintf(" To undo it: safegrd restore --snapshot %s", snap.SnapshotID)
	}
	return note
}

// hookAnswer answers in the tool's format. With no reason the command goes
// on to the tool's normal permission flow: guard never approves a command,
// it only blocks one. note, when set, is what the agent is told on the way.
func hookAnswer(tool string, out io.Writer, note, reason string) error {
	if tool == hookCursor {
		ans := cursorOutput{Permission: "allow"}
		if reason != "" {
			ans = cursorOutput{Permission: "deny", UserMessage: reason, AgentMessage: reason}
		}
		return json.NewEncoder(out).Encode(ans)
	}
	if reason == "" {
		if note == "" {
			return nil
		}
		fmt.Fprintln(os.Stderr, note)
		if tool != hookClaudeCode {
			return nil
		}
		// additionalContext with no permissionDecision: Claude Code shows it
		// to the model and leaves the decision to its permission settings.
		var ans preToolUseOutput
		ans.HookSpecificOutput.HookEventName = "PreToolUse"
		ans.HookSpecificOutput.AdditionalContext = note
		return json.NewEncoder(out).Encode(ans)
	}
	var ans preToolUseOutput
	ans.HookSpecificOutput.HookEventName = "PreToolUse"
	ans.HookSpecificOutput.PermissionDecision = "deny"
	ans.HookSpecificOutput.PermissionDecisionReason = strings.TrimSpace(reason)
	return json.NewEncoder(out).Encode(ans)
}

// hookInvocation says whether the command line asks for a hook answer, so
// an error before guard runs (a flag it cannot parse) still exits 2 and
// blocks: every other exit code lets the agent's command through.
func hookInvocation(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--hook" || strings.HasPrefix(a, "--hook=") {
			return true
		}
	}
	return false
}

func firstLine(err error) string {
	msg := err.Error()
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = strings.TrimRight(msg[:i], ": ")
	}
	return msg
}
