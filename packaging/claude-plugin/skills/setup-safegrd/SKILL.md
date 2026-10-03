---
name: setup-safegrd
description: Connect Claude Code to SafeGrd. Covers the token, installing the SafeGrd CLI on a host, the local SafeGrd MCP server, and the guard hook that takes a locked backup before a destructive command runs. Use when the user wants to start protecting a database with SafeGrd, or wants backups taken automatically before an agent runs a destructive command.
---

# Set up SafeGrd in Claude Code

## The remote server

This plugin connects to `https://safegrd.dev/mcp` with the personal access token entered
when the plugin was installed. If a SafeGrd tool answers `401`, the token is missing,
expired or revoked. Ask the user to create one in the console under Tokens and set it with
`claude plugin configure safegrd`. Never ask them to paste it into the chat.

## Install the CLI on a host

Backups run on the user's host, or on SafeGrd for a database SafeGrd can reach. For a
database without a host of its own (Supabase, Neon, Railway, Render), point the user to
**Back up on SafeGrd** under Surfaces in the console.

For a host, ask the user to run the installer in their own terminal. Do not run it through
a tool. In a terminal it signs in through a browser and asks who holds the encryption key:

```sh
curl -fsSL https://safegrd.dev/install.sh | sh
```

The key question is the user's to answer. Do not choose for them. Describe both options:

- **SafeGrd holds it:** SafeGrd keeps the key sealed and releases it only to the
  organization's enrolled hosts, so they can restore even after losing a host.
- **Customer-held:** only they can decrypt these backups. They keep a copy of the key file
  somewhere safe.

Then check the host with `safegrd status` and `safegrd doctor`. The full guide is at
https://safegrd.dev/docs/install.

## The local MCP server

On a host with the CLI, the local server backs up, verifies and restores with that host's
config and key. A restore writes only into a new or empty target. Add it with:

```sh
claude mcp add safegrd-local -- safegrd mcp
```

## The guard hook

With the hook, Claude Code takes a locked snapshot before any command that can destroy
data (`DROP`, `TRUNCATE`, `DELETE` without `WHERE`, `dropdb`, `terraform destroy`,
`prisma migrate reset` and others: `safegrd guard --list`). If the snapshot fails or is not
locked, the command is blocked. A command that matches nothing runs with no backup.

It goes in the project, not here, because it names the surface that project works on. Get
the surface id from `safegrd daemon status`, then add this to the project's
`.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "safegrd guard --hook claude-code --surface <surface id>",
            "timeout": 600
          }
        ]
      }
    ]
  }
}
```

Set the timeout above the time one backup of that surface takes. Check it with
`safegrd guard --matches "DROP TABLE users"`, which takes no backup, and with
`safegrd doctor --agent-proof`, which checks that an agent on this host cannot delete the
backups. Details: https://safegrd.dev/docs/agents.
