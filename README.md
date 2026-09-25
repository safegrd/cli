# SafeGrd CLI (`safegrd`)

[![CI](https://github.com/safegrd/cli/actions/workflows/ci.yml/badge.svg)](https://github.com/safegrd/cli/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)

> **Agent-Safe, Cryptographically Air-Gapped Backup and Verification CLI**

`safegrd` protects modern engineering teams and autonomous AI agents from data corruption and accidental drops. It delivers **PostgreSQL backups that restore as the database** (schema from `pg_dump`, rows over binary `COPY`, one snapshot), **streaming POSIX file tree archives**, **universal IMAP email extraction**, **client-side Age (X25519) encryption**, **Zstandard compression**, **immutable WORM storage**, and **automated Fire Drill restore verifications**.

The private key stays on your machine. Fire Drills run here, in your environment, and the remote server receives a signed attestation report; never your data and never your key.

**Surfaces.** Supports PostgreSQL, MySQL, MariaDB and MongoDB databases, POSIX file trees, and IMAP email mailboxes under one customer-held Age keypair, Object Lock WORM policy, and attestation chain.

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
| `SAFEGRD_PROJECT` | Project ID or slug to enroll this machine into. |
| `SAFEGRD_NODE_NAME` | Name the machine is shown under. |
| `SAFEGRD_KEY_CUSTODY` | `safegrd` or `local`: answers the key question in advance. |
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

### Release archives, or from source

Static binaries for Linux and macOS (`amd64`, `arm64`) and their SHA-256 checksums are
on the [releases page](https://github.com/safegrd/cli/releases). To build:

```sh
git clone https://github.com/safegrd/cli.git && cd cli
make build
```

---

## Quickstart

### 1. Initialize Configuration & Encryption Keys

Skip this if you let the install script connect the machine: it already wrote the
keypair and `~/.safegrd/config.yaml`, and `init` refuses to overwrite them.

```bash
# Generates an Age X25519 keypair and creates ~/.safegrd/config.yaml
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

# Verify the active session
safegrd whoami
```

### 3. Create an Encrypted Immutable Backup

```bash
# Zero-knowledge streaming: dumps, compresses, encrypts with Age, and locks in WORM storage
safegrd backup
```

### 4. Run an Automated "Fire Drill" Verification

```bash
# Proves backups work by restoring into an ephemeral sandbox and verifying row counts
safegrd verify \
  --snapshot snap-20260919-01 \
  --sandbox-target "postgres://postgres:password@localhost:5432/ephemeral_test_db"
```

### 5. Emergency Restore

```bash
safegrd restore \
  --snapshot snap-20260919-01 \
  --target "postgres://postgres:password@localhost:5432/myapp_recovered"
```

---

## Core Features

- **Postgres, restored whole:** the schema comes from `pg_dump` and the rows stream over binary `COPY` from the same snapshot, so arrays, enums, foreign keys, views, triggers and sequence positions all come back. Needs a `pg_dump` at least as new as the server on the host.
- **Client-Side Zero-Knowledge:** Plaintext data is encrypted using Age (X25519) before leaving your machine. Private keys never leave your infrastructure.
- **Immutable WORM Storage:** Supports AWS S3 Object Lock (Governance and Compliance modes) and local filesystem WORM locking.
- **Fire Drill Sandbox Restores:** Tests backups automatically to guarantee recoverability and generate cryptographic audit certificates.

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
