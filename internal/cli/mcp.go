package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

// newMCPCmd serves this host's safegrd as an MCP server over stdio, for a
// coding agent running on the same machine (Claude Code, Cursor and the like).
//
// It is the half of agent access that needs the key: backing up, proving a
// snapshot restores and restoring happen here, because the remote server can
// decrypt nothing. Each tool runs this same binary with this host's config, so
// it does exactly what the command would, with the same refusals, and no more.
//
// Two limits are the design, not omissions. No tool takes a private key as an
// argument: the host's key_path is used, so a key never passes through an
// agent's context. And restore writes only into a new or empty directory, or a
// database the restore itself confirms is empty, so an agent cannot restore
// over data.
func newMCPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Serve this host's safegrd to a local AI agent over MCP (stdio)",
		Long: `Serve this host's safegrd as an MCP server on stdin and stdout, for a coding
agent on the same machine. For example, in Claude Code:

  claude mcp add safegrd -- safegrd mcp

Tools: status, list, doctor, backup, verify, restore and export. Each runs the
command of the same name with this host's config. Nothing can delete a backup,
no tool accepts a private key, and restore only writes into a new or empty
directory or an empty database.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			self, err := os.Executable()
			if err != nil {
				return err
			}
			server := mcp.NewServer(&mcp.Implementation{Name: "safegrd-local", Title: "SafeGrd (this host)", Version: Version}, &mcp.ServerOptions{
				Instructions: "SafeGrd on this host: encrypted, locked backups, and Fire Drills that prove they restore. " +
					"Take a backup before a risky migration and verify it; restore only ever writes into a new or empty target.",
			})
			addLocalTools(server, self)
			return server.Run(cmd.Context(), &mcp.StdioTransport{})
		},
	}
}

type localArgs struct {
	SnapshotID string `json:"snapshot_id,omitempty"`
	Surface    string `json:"surface,omitempty"`
	Files      string `json:"files,omitempty"`
	SandboxURL string `json:"sandbox_url,omitempty"`
	TargetDir  string `json:"target_dir,omitempty"`
	TargetURL  string `json:"target_url,omitempty"`
	ToDir      string `json:"to_dir,omitempty"`
	ToBucket   string `json:"to_bucket,omitempty"`
	ToEndpoint string `json:"to_endpoint,omitempty"`
}

// localArgDescriptions describes each argument once. A tool's schema offers
// only the arguments that tool reads, so an agent is never shown target_url
// on backup, and a missing snapshot_id is refused before anything runs.
var localArgDescriptions = map[string]string{
	"snapshot_id": "Snapshot id, from the list tool.",
	"surface":     "The id of one surface in this host's config to back up now.",
	"files":       "A directory tree to back up instead of the configured database.",
	"sandbox_url": "An empty database to restore into for a full Fire Drill. Without it the snapshot is replayed in memory.",
	"target_dir":  "A new or empty directory to restore files or mail into.",
	"target_url":  "An empty database URL to restore into.",
	"to_dir":      "A directory to copy every snapshot into, still encrypted.",
	"to_bucket":   "Your own S3 bucket to copy every snapshot into, still encrypted.",
	"to_endpoint": "The S3 endpoint of to_bucket.",
}

func localSchema(required, optional []string) *jsonschema.Schema {
	s := &jsonschema.Schema{Type: "object", Properties: map[string]*jsonschema.Schema{},
		Required: required, AdditionalProperties: &jsonschema.Schema{Not: &jsonschema.Schema{}}}
	for _, k := range append(append([]string{}, required...), optional...) {
		s.Properties[k] = &jsonschema.Schema{Type: "string", Description: localArgDescriptions[k]}
	}
	return s
}

// localTool is one tool's shape. readOnly tools only report; the others write
// a new snapshot or a copy, or restore into an empty target. None deletes or
// overwrites anything, and none reaches past this host's own storage and
// remote server.
type localTool struct {
	name, title, desc  string
	required, optional []string
	readOnly           bool
}

func addLocalTools(server *mcp.Server, self string) {
	tool := func(t localTool, build func(a localArgs) ([]string, error)) {
		no := false
		mcp.AddTool(server, &mcp.Tool{Name: t.name, Title: t.title, Description: t.desc,
			InputSchema: localSchema(t.required, t.optional),
			Annotations: &mcp.ToolAnnotations{Title: t.title, ReadOnlyHint: t.readOnly, IdempotentHint: t.readOnly,
				DestructiveHint: &no, OpenWorldHint: &no}},
			func(ctx context.Context, _ *mcp.CallToolRequest, a localArgs) (*mcp.CallToolResult, any, error) {
				argv, err := build(a)
				if err != nil {
					return toolResult(err.Error(), true), nil, nil
				}
				out, err := runSelf(ctx, self, argv)
				return toolResult(out, err != nil), nil, nil
			})
	}
	need := func(v, name string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s is required", name)
		}
		return nil
	}

	tool(localTool{name: "status", title: "Status", readOnly: true,
		desc: "This host's storage and remote server connection, and its latest snapshot."},
		func(localArgs) ([]string, error) { return []string{"status"}, nil })
	tool(localTool{name: "list", title: "List snapshots", readOnly: true,
		desc: "Every snapshot in this host's storage: when, what it holds, and until when it is locked."},
		func(localArgs) ([]string, error) { return []string{"list"}, nil })
	tool(localTool{name: "doctor", title: "Doctor", readOnly: true,
		desc: "Check this host's configuration, key, storage and database access, and say what is wrong."},
		func(localArgs) ([]string, error) { return []string{"doctor"}, nil })
	tool(localTool{name: "backup", title: "Back up now", optional: []string{"surface", "files"},
		desc: "Back up now: one surface of this host's config by id (surface), the configured database, or a directory tree given as files. Take one before changing a database. The snapshot is encrypted and locked, and cannot be deleted early."},
		func(a localArgs) ([]string, error) {
			if a.Surface != "" && a.Files != "" {
				return nil, fmt.Errorf("give surface or files, not both")
			}
			if a.Surface != "" {
				return []string{"backup", "--surface", a.Surface}, nil
			}
			if a.Files != "" {
				return []string{"backup", "--files", a.Files}, nil
			}
			return []string{"backup"}, nil
		})
	tool(localTool{name: "verify", title: "Run a Fire Drill", required: []string{"snapshot_id"}, optional: []string{"sandbox_url"},
		desc: "Prove a snapshot restores (a Fire Drill): replayed in memory, or restored into sandbox_url, an empty database, for a full drill."},
		func(a localArgs) ([]string, error) {
			if err := need(a.SnapshotID, "snapshot_id"); err != nil {
				return nil, err
			}
			if a.SandboxURL != "" {
				return []string{"verify", "--snapshot", a.SnapshotID, "--sandbox-target", a.SandboxURL}, nil
			}
			return []string{"verify", "--snapshot", a.SnapshotID, "--dry-run"}, nil
		})
	tool(localTool{name: "restore", title: "Restore into an empty target", required: []string{"snapshot_id"}, optional: []string{"target_dir", "target_url"},
		desc: "Restore a snapshot into a new or empty directory (target_dir) or an empty database (target_url). Never over existing data."},
		func(a localArgs) ([]string, error) {
			if err := need(a.SnapshotID, "snapshot_id"); err != nil {
				return nil, err
			}
			switch {
			case a.TargetDir != "" && a.TargetURL == "":
				if entries, err := os.ReadDir(a.TargetDir); err == nil && len(entries) > 0 {
					return nil, fmt.Errorf("%s is not empty: restore only writes into a new or empty directory", a.TargetDir)
				}
				return []string{"restore", "--snapshot", a.SnapshotID, "--target-dir", a.TargetDir}, nil
			case a.TargetURL != "" && a.TargetDir == "":
				// The restore itself refuses a database that holds data.
				return []string{"restore", "--snapshot", a.SnapshotID, "--target", a.TargetURL}, nil
			default:
				return nil, fmt.Errorf("give exactly one of target_dir or target_url")
			}
		})
	tool(localTool{name: "export", title: "Export snapshots", optional: []string{"to_dir", "to_bucket", "to_endpoint"},
		desc: "Copy every snapshot, still encrypted, to a directory (to_dir) or your own bucket (to_bucket). Nothing is decrypted or deleted."},
		func(a localArgs) ([]string, error) {
			switch {
			case a.ToDir != "" && a.ToBucket == "":
				return []string{"export", "--to-dir", a.ToDir}, nil
			case a.ToBucket != "" && a.ToDir == "":
				argv := []string{"export", "--to-bucket", a.ToBucket}
				if a.ToEndpoint != "" {
					argv = append(argv, "--to-endpoint", a.ToEndpoint)
				}
				return argv, nil
			default:
				return nil, fmt.Errorf("give exactly one of to_dir or to_bucket")
			}
		})
}

// runSelf runs this binary with the config this server was started with.
func runSelf(ctx context.Context, self string, argv []string) (string, error) {
	if cfgFile != "" {
		argv = append([]string{"--config", cfgFile}, argv...)
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Hour)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, argv...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func toolResult(text string, isErr bool) *mcp.CallToolResult {
	if text == "" {
		text = "(no output)"
	}
	return &mcp.CallToolResult{IsError: isErr, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}
