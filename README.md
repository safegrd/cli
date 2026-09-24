# SafeGrd CLI (`safegrd`)

[![CI](https://github.com/safegrd/cli/actions/workflows/ci.yml/badge.svg)](https://github.com/safegrd/cli/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)

> **Agent-Safe, Cryptographically Air-Gapped Backup and Verification CLI**

`safegrd` protects modern engineering teams and autonomous AI agents from data corruption and accidental drops. It delivers **PostgreSQL backups that restore as the database** (schema from `pg_dump`, rows over binary `COPY`, one snapshot), **streaming POSIX file tree archives**, **universal IMAP email extraction**, **client-side Age (X25519) encryption**, **Zstandard compression**, **immutable WORM storage**, and **automated Fire Drill restore verifications**.

The private key stays on your machine. Fire Drills run here, in your environment, and the remote server receives a signed attestation report — never your data and never your key.

**Surfaces.** Supports PostgreSQL, MySQL, MariaDB and MongoDB databases, POSIX file trees, and IMAP email mailboxes under one customer-held Age keypair, Object Lock WORM policy, and attestation chain.

---

## Installation

### Method 1: Universal Shell Script (Linux & macOS — Recommended for Servers)

```bash
# Installs the pre-compiled binary for your OS and architecture to /usr/local/bin
curl -fsSL https://safegrd.dev/install.sh | bash

# Or directly from the GitHub repository:
curl -fsSL https://raw.githubusercontent.com/safegrd/cli/main/install.sh | bash
```

Custom installation options:
```bash
# Pin a specific release version:
VERSION=v0.0.1 curl -fsSL https://safegrd.dev/install.sh | bash

# Install to a custom directory without root/sudo:
SAFEGRD_INSTALL_DIR=~/.local/bin curl -fsSL https://safegrd.dev/install.sh | bash
```

### Method 2: Direct Release Binaries

Download pre-built static binaries and SHA256 checksums directly from the [GitHub Releases](https://github.com/safegrd/cli/releases) page for Linux (`amd64`, `arm64`) and macOS (`amd64`, `arm64`).

### Method 3: Install via Go or Build from Source

```bash
# Install directly via Go
go install github.com/safegrd/cli/cmd/safegrd@latest

# Or compile from source
git clone https://github.com/safegrd/cli.git && cd cli
make build
```

---

## Quickstart

### 1. Initialize Configuration & Encryption Keys

```bash
# Generates an Age X25519 keypair and creates ~/.safegrd/config.yaml
safegrd init \
  --database-url "postgres://postgres:password@localhost:5432/myapp_prod" \
  --storage local \
  --local-path ./backups \
  --retention-days 14
```

### 2. Authenticate with a remote server (Optional)

```bash
# Interactive browser flow
safegrd login

# Or headless / CI using Personal Access Token (PAT)
safegrd login --token "sg_pat_..."

# Verify active session
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
