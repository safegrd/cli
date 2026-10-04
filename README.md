# SafeGrd CLI (`safegrd`)

[![CI](https://github.com/safegrd/cli/actions/workflows/ci.yml/badge.svg)](https://github.com/safegrd/cli/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)

`safegrd` backs up PostgreSQL, MySQL, MariaDB, MongoDB and SQLite databases, directory trees
and IMAP mailboxes. Each backup is compressed with zstd and encrypted with age on the host that
takes it, written to S3-compatible storage under Object Lock, and restored on a schedule to
check that every table, row and file came back.

It is the CLI and daemon of [SafeGrd](https://safegrd.dev). Documentation is at
[safegrd.dev/docs](https://safegrd.dev/docs), and every command and flag is in the
[command reference](https://safegrd.dev/docs/cli).

- **Backups go from your host straight to storage.** The remote server receives a record of each
  backup (when it ran, its size, its digest and the date its lock ends) and the signed result
  of each restore test. The data never passes through it.
- **You choose who holds the key.** By default the remote server keeps your key sealed and
  releases it only to your enrolled hosts, so you can restore even after losing a host. With
  `enroll --key-custody local`, only you can decrypt these backups.
- **Restores are tested.** A Fire Drill restores the newest backup into a throwaway database or
  directory, compares its tables, rows and digests with what was backed up, and signs the
  result.
- **An agent cannot remove a backup.** `safegrd guard` takes a locked snapshot before a
  destructive command runs, and a personal access token cannot delete a backup or shorten its
  lock.

---

## Installation

### Install script (Linux and macOS)

```sh
curl -fsSL https://safegrd.dev/install.sh | sh
```

It detects your OS and architecture, downloads the matching release archive, checks
it against the release's `checksums.txt`, and installs `safegrd` to `/usr/local/bin`
(or `~/.local/bin` when it cannot use sudo). The script is [`install.sh`](install.sh)
in this repository; `https://raw.githubusercontent.com/safegrd/cli/main/install.sh`
serves the same file.

When it runs in a terminal, it then offers to connect the machine to a remote server:
a browser login, a question about who holds the encryption key, then `safegrd enroll`.
The login prints a URL and a code that you can open in a browser on **any** device, so
it works the same on a server you reached over SSH or PuTTY. Without a terminal (CI,
cloud-init, cron) it installs and stops.

Options are environment variables, and they go on the `sh` after the pipe. Written
before `curl` they apply to `curl`, and the script never sees them:

```sh
curl -fsSL https://safegrd.dev/install.sh | VERSION=v0.0.3 sh                  # pin a release
curl -fsSL https://safegrd.dev/install.sh | SAFEGRD_INSTALL_DIR=~/.local/bin sh  # no sudo
curl -fsSL https://safegrd.dev/install.sh | SAFEGRD_NO_SETUP=1 sh               # install only
```

| Variable | Effect |
| :--- | :--- |
| `VERSION` | Release tag to install. Default: the latest release. |
| `SAFEGRD_INSTALL_DIR` | Where the binary goes. |
| `SAFEGRD_NO_SETUP=1` | Install only; do not offer to log in and enroll. |
| `SAFEGRD_FORCE_INSTALL=1` | Download and install even when the release asked for is already installed. |
| `SAFEGRD_PROJECT` | Project ID or slug to enroll this machine into. |
| `SAFEGRD_STORAGE` | `hosted` or `local`: where backups go when the project has no bucket. |
| `SAFEGRD_CLAIM` | The claim code the console shows for this machine. It carries the project, where backups go and the surfaces to protect, so enrollment writes them into the config and asks nothing. Needs a release whose `enroll` has `--claim`; an older one stops and says so. |
| `SAFEGRD_NODE_NAME` | Name the machine is shown under. |
| `SAFEGRD_KEY_CUSTODY` | `local` keeps this host's key on the host. Without it the remote server keeps the key sealed and releases it only to your enrolled hosts. |
| `SAFEGRD_SERVER_URL` | Remote server to log in and enroll with. Default: `https://safegrd.dev`. |

### Homebrew (macOS and Linux)

```sh
brew install safegrd/tap/safegrd
```

The formula installs the same release archives as the script.

### Go

```sh
go install github.com/safegrd/cli/cmd/safegrd@latest
```

### Container image

`ghcr.io/safegrd/cli` runs on linux/amd64 and linux/arm64 and carries `pg_dump`, `mysqldump`
and `mongodump`, and a PostgreSQL 18 server so a drill can restore a database into a
throwaway cluster on the volume. The tag names the Postgres client: `<version>-pg18` reads
Postgres 18 and every older server. Releases are signed with cosign (keyless, from this repository's release
workflow):

```bash
cosign verify ghcr.io/safegrd/cli:<version>-pg18 \
  --certificate-identity-regexp 'https://github.com/safegrd/cli/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

[`packaging/compose`](packaging/compose/compose.yaml) runs the daemon beside a database,
[`packaging/kubernetes`](packaging/kubernetes/cronjob.yaml) runs `daemon run --once` as a
CronJob, and [`packaging/helm/safegrd`](packaging/helm/safegrd) runs the daemon as a
Deployment.
Each names the release it was cut with, such as `ghcr.io/safegrd/cli:0.0.10`; change
the tag to upgrade.

### Release archives, or from source

Static binaries for Linux and macOS (`amd64`, `arm64`) and their SHA-256 checksums are
on the [releases page](https://github.com/safegrd/cli/releases). To build:

```sh
git clone https://github.com/safegrd/cli.git && cd cli
make build
```

---

## Quickstart

### 1. Create a config and a key

Skip this if you let the install script connect the machine: it already wrote the
keypair and `~/.safegrd/config.yaml`, and `init` refuses to overwrite them.

```bash
# writes an age X25519 keypair and ~/.safegrd/config.yaml
safegrd init \
  --database-url "postgres://postgres:password@localhost:5432/myapp_prod" \
  --storage local \
  --local-path ./backups \
  --retention-days 14
```

### 2. Connect to a remote server (optional)

```bash
# Prints a URL and a code: open it in a browser on any device, including over SSH
safegrd login

# Register this machine, generating its encryption key if it has none.
# --key-custody decides whether the server keeps a copy (safegrd) or not (local)
safegrd enroll --key-custody local

# Headless / CI: a Personal Access Token instead of the browser
safegrd enroll --token "sg_pat_..."

# Or with the claim code the console's setup shows: the project, where backups go and
# the surfaces are written into ~/.safegrd/config.yaml, and the key stays on this machine
safegrd enroll --claim <code>
safegrd daemon run --once

# Later, on an enrolled host: add the surfaces named for it in the console
# (Add surface on its row). Only adds; the old config is kept as config.yaml.bak
safegrd claim
safegrd daemon restart

# Verify the active session
safegrd whoami
```

### 3. Back up

```bash
# dumps, compresses, encrypts with age on this host, and writes to locked storage
safegrd backup
```

### 4. Run a Fire Drill

```bash
# restores into an empty database and checks every table's row count
safegrd verify \
  --snapshot snap-20260919-01 \
  --sandbox-target "postgres://postgres:password@localhost:5432/ephemeral_test_db"
```

### 5. Restore

```bash
safegrd restore \
  --snapshot snap-20260919-01 \
  --target "postgres://postgres:password@localhost:5432/myapp_recovered"
```

### 6. Protect several things on one host, unattended

Each entry under `surfaces:` in `~/.safegrd/config.yaml` is one protected thing, and
`safegrd daemon install` runs them on their schedules. A surface's `credential` block says
where its secret comes from; the config never holds it:

```yaml
surfaces:
  - id: app-primary
    type: postgres
    schedule: "@daily"
    credential:
      from: env                 # or: command (with run), file (with path),
      name: APP_DATABASE_URL    # or safegrd: the remote server holds it for this host
  - id: user-uploads
    type: files
    schedule: "6h"
    roots: ["/var/www/uploads"]
```

[`safegrd.example.yaml`](safegrd.example.yaml) is the annotated version. The daemon reads its
config when it starts, so run `safegrd daemon restart` after changing it.

### 7. Take a locked snapshot before a destructive command

`safegrd guard` backs up one surface, waits until the snapshot is uploaded and locked, and
then runs the command. If the backup fails or the snapshot is not locked, the command does
not run and guard exits 3.

```bash
safegrd guard --surface app-primary -- psql "$APP_DATABASE_URL" -c 'DROP TABLE sessions'
safegrd guard -- terraform destroy

# The commands a hook treats as destructive, and a check that takes no backup
safegrd guard --list
safegrd guard --matches "npx prisma migrate reset"   # exit 0: it matches
```

Storage on the host's own disk, or a bucket with `worm_mode: NONE`, cannot lock a snapshot,
so guard refuses there unless you pass `--allow-unlocked`.

A locked snapshot of the surface younger than `--max-age` stands in for a new backup, so an
agent running several destructive commands in a row backs up once. `--check-only` takes no
backup at all and refuses the command unless such a snapshot exists:

```bash
safegrd guard --max-age 30m -- psql "$APP_DATABASE_URL" -c 'TRUNCATE sessions'
safegrd guard --max-age 1h --check-only -- terraform destroy
```

`safegrd list --json` prints every snapshot with its lock date, for scripts.

### Claude Code plugin

The plugin in [safegrd/agent-plugins](https://github.com/safegrd/agent-plugins) connects
Claude Code to the remote server's MCP tools, with skills that take a backup and prove it
restores before a risky change:

```text
/plugin marketplace add safegrd/agent-plugins
/plugin install safegrd@safegrd
```

On a host with the CLI, `claude mcp add safegrd-local -- safegrd mcp` adds the local server,
which backs up, verifies and restores with this host's config and key.

### 8. Back up a directory tree, and get one file back

File backups are incremental: the first run of each month uploads every file, and every
run after it uploads only the chunks that changed. Every kept version of every file is
searchable, and one file restores on its own.

```bash
safegrd backup --files /srv/app --exclude '*.tmp,node_modules/*'

# every kept version of a file, numbered from the oldest
safegrd find etc/nginx/nginx.conf

# one version of one file, or a directory as it was in one snapshot
safegrd restore --path etc/nginx/nginx.conf --version 2 --target-dir ./out
safegrd restore --snapshot snap-20260919-01 --path 'var/www/**' --target-dir ./out

# every pack present and every listing consistent, without restoring anything
safegrd check --all
```

`--format tar` keeps one archive per backup instead. What is locked, for how long, and
what a restore brings back: [safegrd.dev/docs/surfaces/files](https://safegrd.dev/docs/surfaces/files).

---

## What it backs up

- **PostgreSQL, incrementally:** the schema comes from `pg_dump` and the rows stream over binary `COPY` from the same snapshot, so arrays, enums, foreign keys, views, triggers and sequence positions all come back. Each run uploads only the chunks of each table that changed, `restore --table` loads chosen tables into a running database, and `--change-log` skips reading tables nothing wrote since the last run. `--format tar` keeps one archive per backup. Needs a `pg_dump` at least as new as the server on the host.
- **SQLite, incrementally:** copied through SQLite's online backup in one read transaction, so transactions still in the WAL are in it and writers carry on. The copy keeps the database's pages in place, so each run uploads only the chunks whose pages changed. `--format tar` keeps one archive per backup. Needs nothing installed on the host.
- **MySQL and MariaDB** through `mysqldump --single-transaction`, and **MongoDB** through `mongodump --archive`, one archive per backup.
- **Directory trees, incrementally:** each run uploads only the chunks that changed, every object is locked once when it is written, and `safegrd find` lists every kept version of a file for `restore --path --version`.
- **IMAP mailboxes,** every message as RFC 5322 mail, checked by SHA-256 on every drill.
- **Locked storage:** S3 Object Lock in compliance mode, or governance mode where a lock may need lifting. Storage on the host's own disk, and a bucket with `worm_mode: NONE`, keep backups without a lock.
- **Fire Drills:** restore backups on a schedule, count what came back, and sign a record of each test.

---

## Development

Go 1.25 or newer. `make` with no target lists everything.

```bash
make build      # compile bin/safegrd
make test       # unit and integration tests, race detector
make ci         # the exact gate CI runs: gofmt check, tidy check, vet, race tests
make dist       # cross-compile release archives + checksums into dist/
make fmt tidy   # the developer-facing fixers (these rewrite files; `ci` never does)
```

CI runs `make ci` on every push and pull request, so a green local run means a
green pipeline. Tagging `v*` runs `make dist VERSION=<tag without v>` and
publishes the archives and `checksums.txt` as a GitHub Release.

---

## License
 
Business Source License 1.1, with an Additional Use Grant. See [LICENSE](LICENSE).

In short: read, modify and build it freely, and use it for evaluation anywhere.
Production use is included with a SafeGrd account on any plan, the free one too.
Listing, verifying, restoring and exporting your backups is always permitted, with
or without an account. Each version becomes GPL-3.0-or-later four years after it
is published. For a commercial licence, contact support@safegrd.dev.
