#!/bin/sh
# SafeGrd CLI Universal Installer
# https://safegrd.dev
#
# Usage:
#   curl -fsSL https://safegrd.dev/install.sh | sh
#   or, the same file from the source repository:
#   curl -fsSL https://raw.githubusercontent.com/safegrd/cli/main/install.sh | sh
#
# After installing, and only when there is a terminal to ask on, it offers to
# connect this host: a browser login (the URL can be opened on any device, so
# it works over SSH), a question about who holds the encryption key, then
# `safegrd enroll`. Without a terminal (CI, cloud-init) it installs and stops.
#
# Options are environment variables, and they go on the shell that runs the
# script, after the pipe. `VERSION=v1 curl ... | sh` sets it for curl instead,
# and the script never sees it.
#
#   curl -fsSL https://safegrd.dev/install.sh | VERSION=v0.0.3 sh
#   curl -fsSL https://safegrd.dev/install.sh | SAFEGRD_INSTALL_DIR=~/.local/bin sh
#
#   VERSION              release tag to install (default: latest)
#   SAFEGRD_INSTALL_DIR  where to put the binary (default: /usr/local/bin, or ~/.local/bin without sudo)
#   SAFEGRD_NO_SETUP=1   install only; do not offer to log in and enroll
#   SAFEGRD_PROJECT      project ID or slug to enroll this host into
#   SAFEGRD_NODE_NAME    name this host is shown under
#   SAFEGRD_KEY_CUSTODY  'safegrd' or 'local'; answers the key question in advance
#   SAFEGRD_SERVER_URL   remote server to log in and enroll with (default: https://safegrd.dev)
#   SAFEGRD_DOWNLOAD_BASE  where release archives are fetched from, for testing a
#                        build before it is published (curl only; file:// works)

set -e

# ANSI styling
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD="\033[1m"
  GREEN="\033[32m"
  CYAN="\033[36m"
  YELLOW="\033[33m"
  RED="\033[31m"
  RESET="\033[0m"
else
  BOLD=""
  GREEN=""
  CYAN=""
  YELLOW=""
  RED=""
  RESET=""
fi

log_info() {
  printf "${CYAN}==>${RESET} ${BOLD}%s${RESET}\n" "$1"
}

log_success() {
  printf "${GREEN}✓${RESET} %s\n" "$1"
}

log_warn() {
  printf "${YELLOW}⚠️  %s${RESET}\n" "$1"
}

log_error() {
  printf "${RED}❌ Error: %s${RESET}\n" "$1" >&2
}

# 1. Detect Operating System
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  linux*)  OS="linux" ;;
  darwin*) OS="darwin" ;;
  *)
    log_error "Unsupported operating system '$OS'. SafeGrd CLI currently supports Linux and macOS."
    exit 1
    ;;
esac

# 2. Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)
    log_error "Unsupported architecture '$ARCH'. SafeGrd CLI supports amd64 and arm64."
    exit 1
    ;;
esac

# 3. Detect Downloader
if command -v curl >/dev/null 2>&1; then
  DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER="wget"
else
  log_error "Neither 'curl' nor 'wget' was found on your system. Please install either curl or wget to continue."
  exit 1
fi

download_file() {
  url="$1"
  dest="$2"
  if [ "$DOWNLOADER" = "curl" ]; then
    curl -fsSL "$url" -o "$dest"
  else
    wget -qO "$dest" "$url"
  fi
}

download_stdout() {
  url="$1"
  if [ "$DOWNLOADER" = "curl" ]; then
    curl -fsSL "$url"
  else
    wget -qO- "$url"
  fi
}

# 4. Resolve Target Version
TARGET_VERSION="${VERSION:-${SAFEGRD_VERSION:-}}"

if [ -z "$TARGET_VERSION" ]; then
  log_info "Detecting latest SafeGrd CLI release from GitHub..."
  # Try GitHub API first
  LATEST_JSON="$(download_stdout "https://api.github.com/repos/safegrd/cli/releases/latest" 2>/dev/null || true)"
  TARGET_VERSION="$(echo "$LATEST_JSON" | grep '"tag_name":' | head -n 1 | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/' || true)"

  # Fallback to redirect resolution if API was rate-limited or failed
  if [ -z "$TARGET_VERSION" ] && [ "$DOWNLOADER" = "curl" ]; then
    LOC="$(curl -sI "https://github.com/safegrd/cli/releases/latest" 2>/dev/null | grep -i '^location:' | tr -d '\r\n' || true)"
    case "$LOC" in
      */tag/*) TARGET_VERSION="$(echo "$LOC" | sed -E 's/.*tag\///')" ;;
    esac
  fi

  # No guessed default: a version baked into this file goes stale with the
  # next release and would install an old binary without saying so.
  if [ -z "$TARGET_VERSION" ]; then
    log_error "Could not find the latest release on GitHub (network blocked or rate-limited)."
    log_error "Name one explicitly, e.g.:  curl -fsSL https://safegrd.dev/install.sh | VERSION=v0.0.3 sh"
    log_error "Releases: https://github.com/safegrd/cli/releases"
    exit 1
  fi
fi

# Ensure TAG starts with 'v' and VERSION_NUM does not
case "$TARGET_VERSION" in
  v*) TAG="$TARGET_VERSION"; VERSION_NUM="${TARGET_VERSION#v}" ;;
  *)  TAG="v$TARGET_VERSION"; VERSION_NUM="$TARGET_VERSION" ;;
esac

log_info "Target release: ${BOLD}${TAG}${RESET} (${OS}/${ARCH})"

# 5. Determine Destination Directory
if [ -n "${SAFEGRD_INSTALL_DIR:-}" ]; then
  INSTALL_DIR="$SAFEGRD_INSTALL_DIR"
  USE_SUDO=0
elif [ "$(id -u)" -eq 0 ]; then
  INSTALL_DIR="/usr/local/bin"
  USE_SUDO=0
elif [ -w "/usr/local/bin" ]; then
  INSTALL_DIR="/usr/local/bin"
  USE_SUDO=0
elif command -v sudo >/dev/null 2>&1; then
  INSTALL_DIR="/usr/local/bin"
  USE_SUDO=1
else
  INSTALL_DIR="${HOME}/.local/bin"
  USE_SUDO=0
fi

# 6. Download Artifacts to Temporary Directory
TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'safegrd-install')"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

ARCHIVE_NAME="safegrd_${VERSION_NUM}_${OS}_${ARCH}.tar.gz"
DOWNLOAD_BASE="${SAFEGRD_DOWNLOAD_BASE:-https://github.com/safegrd/cli/releases/download/${TAG}}"
DOWNLOAD_URL="${DOWNLOAD_BASE}/${ARCHIVE_NAME}"
CHECKSUMS_URL="${DOWNLOAD_BASE}/checksums.txt"

log_info "Downloading ${ARCHIVE_NAME}..."
if ! download_file "$DOWNLOAD_URL" "$TMP_DIR/$ARCHIVE_NAME"; then
  log_error "Failed to download release archive from:"
  log_error "  $DOWNLOAD_URL"
  log_error "Please verify the tag exists at https://github.com/safegrd/cli/releases"
  exit 1
fi

# 7. Checksum Verification
if ! download_file "$CHECKSUMS_URL" "$TMP_DIR/checksums.txt" 2>/dev/null; then
  log_warn "No checksums.txt next to the archive; the download was NOT verified."
else
  log_info "Verifying SHA256 checksum..."
  EXPECTED_HASH="$(grep "${ARCHIVE_NAME}" "$TMP_DIR/checksums.txt" | awk '{print $1}' | head -n 1 || true)"
  if [ -n "$EXPECTED_HASH" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      ACTUAL_HASH="$(sha256sum "$TMP_DIR/$ARCHIVE_NAME" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
      ACTUAL_HASH="$(shasum -a 256 "$TMP_DIR/$ARCHIVE_NAME" | awk '{print $1}')"
    else
      ACTUAL_HASH=""
      log_warn "Neither 'sha256sum' nor 'shasum' found; skipping checksum verification."
    fi

    if [ -n "$ACTUAL_HASH" ]; then
      if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
        log_error "Checksum verification failed!"
        log_error "  Expected: $EXPECTED_HASH"
        log_error "  Actual:   $ACTUAL_HASH"
        exit 1
      fi
      log_success "Checksum verified: ${ACTUAL_HASH}"
    fi
  else
    log_warn "${ARCHIVE_NAME} is not listed in checksums.txt; the download was NOT verified."
  fi
fi

# 8. Unpack Archive
log_info "Extracting binary..."
tar -xzf "$TMP_DIR/$ARCHIVE_NAME" -C "$TMP_DIR"

if [ ! -f "$TMP_DIR/safegrd" ]; then
  # Check if nested in folder
  FOUND_BIN="$(find "$TMP_DIR" -type f -name safegrd | head -n 1 || true)"
  if [ -n "$FOUND_BIN" ]; then
    cp "$FOUND_BIN" "$TMP_DIR/safegrd"
  else
    log_error "Binary 'safegrd' not found inside archive."
    exit 1
  fi
fi

chmod +x "$TMP_DIR/safegrd"

# 9. Install Binary
if [ "$USE_SUDO" -eq 1 ]; then
  log_info "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo mkdir -p "$INSTALL_DIR"
  sudo cp "$TMP_DIR/safegrd" "$INSTALL_DIR/safegrd"
  sudo chmod 755 "$INSTALL_DIR/safegrd"
else
  log_info "Installing to ${INSTALL_DIR}..."
  mkdir -p "$INSTALL_DIR"
  cp "$TMP_DIR/safegrd" "$INSTALL_DIR/safegrd"
  chmod 755 "$INSTALL_DIR/safegrd"
fi

# 10. Smoke Test
if [ -x "$INSTALL_DIR/safegrd" ]; then
  VERSION_OUTPUT="$("$INSTALL_DIR/safegrd" version 2>/dev/null || "$INSTALL_DIR/safegrd" --version 2>/dev/null || true)"
  log_success "Installed successfully: ${VERSION_OUTPUT:-safegrd}"
else
  log_error "Installation failed: $INSTALL_DIR/safegrd is not executable."
  exit 1
fi

# 11. Check PATH
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    log_warn "$INSTALL_DIR is not in your PATH environment variable."
    printf "   Add it by running:\n"
    printf "   ${BOLD}export PATH=\"%s:\$PATH\"${RESET}\n" "$INSTALL_DIR"
    printf "   or append it to your ${BOLD}~/.bashrc${RESET} or ${BOLD}~/.zshrc${RESET}.\n\n"
    ;;
esac

# 12. Connect this host, or say how to
SAFEGRD_BIN="$INSTALL_DIR/safegrd"

# A binary older than this script (a pinned VERSION, or a release published
# before it) has an enroll that ignores the saved login, so `login` then
# `enroll` would fail. Ask the binary rather than compare versions.
ENROLL_USES_LOGIN=""
if "$SAFEGRD_BIN" enroll --help 2>/dev/null | grep -q "safegrd login"; then
  ENROLL_USES_LOGIN=1
fi

print_next_steps() {
  printf "\n"
  printf "${BOLD} Next steps${RESET}\n"
  if [ -n "$ENROLL_USES_LOGIN" ]; then
    printf "   1. Log in. Prints a URL and a code; open it in a browser on any device:\n"
    printf "      ${CYAN}safegrd login${RESET}\n\n"
    printf "   2. Register this host. Generates its encryption key if it has none:\n"
    printf "      ${CYAN}safegrd enroll${RESET}\n\n"
  else
    printf "   1. Create a token under Tokens in the console, then register this host.\n"
    printf "      It generates the encryption key if the host has none:\n"
    printf "      ${CYAN}safegrd enroll --token sg_pat_YOUR_TOKEN${RESET}\n"
    printf "      (%s predates enrolling through a browser login; the latest release has it.)\n\n" "$TAG"
  fi
  if [ -n "$ENROLL_USES_LOGIN" ]; then step=3; else step=2; fi
  printf "   %s. Take the first encrypted, immutable backup:\n" "$step"
  printf "      ${CYAN}safegrd backup --database-url \"\$DATABASE_URL\"${RESET}\n\n"
  printf "   No account? ${CYAN}safegrd init${RESET} sets up a standalone host that contacts no server.\n"
  printf " Docs: ${CYAN}https://safegrd.dev/docs/install${RESET} | Source: ${CYAN}https://github.com/safegrd/cli${RESET}\n\n"
}

# `curl | sh` gives the script the pipe as stdin, so questions are asked on the
# terminal directly. Opening /dev/tty fails when there is no controlling
# terminal (CI, cloud-init, cron), and then nothing is asked.
have_tty() {
  (exec </dev/tty) 2>/dev/null
}

ask() {
  # $1 prompt; the answer is left in REPLY
  printf "%s" "$1" >/dev/tty
  REPLY=""
  read -r REPLY </dev/tty || REPLY=""
}

setup_failed() {
  printf "\n"
  log_error "$1"
  printf "   safegrd itself is installed at %s. Finish setting up with:\n" "$SAFEGRD_BIN" >&2
  printf "      safegrd login && safegrd enroll\n\n" >&2
  exit 1
}

printf "\n"
log_success "SafeGrd CLI ${TAG} is installed."

if [ -n "${SAFEGRD_NO_SETUP:-}" ] || [ -z "$ENROLL_USES_LOGIN" ] || ! have_tty; then
  print_next_steps
  exit 0
fi

# A host that is already enrolled keeps its key and its node: re-running the
# installer is how people upgrade, and it must not re-register anything.
if [ -f "${HOME}/.safegrd/config.yaml" ] && grep -q '^server_token: *sg_tok_' "${HOME}/.safegrd/config.yaml" 2>/dev/null; then
  printf "   This host is already enrolled (%s). Nothing else to do.\n" "${HOME}/.safegrd/config.yaml"
  printf "   Check it with: ${CYAN}safegrd status${RESET}\n\n"
  exit 0
fi

printf "\n"
ask "Connect this host to SafeGrd now? It opens a browser login. [Y/n] "
case "$REPLY" in
  n|N|no|NO|No)
    print_next_steps
    exit 0
    ;;
esac

printf "\n"
if ! "$SAFEGRD_BIN" login </dev/tty; then
  setup_failed "Login did not complete, so this host is not enrolled."
fi

# A key already on this host (from `safegrd init`, or a key you put there) is
# yours and is never sent, so there is nothing to ask; enroll says so.
KEY_ON_HOST=""
if [ -f "${HOME}/.safegrd/keys/agent.key" ] || grep -q '^ *public_key: *age1' "${HOME}/.safegrd/config.yaml" 2>/dev/null; then
  KEY_ON_HOST=1
fi

CUSTODY="${SAFEGRD_KEY_CUSTODY:-}"
if [ -z "$CUSTODY" ] && [ -z "$KEY_ON_HOST" ]; then
  printf "\n${BOLD}Who holds the key that decrypts this host's backups?${RESET}\n" >/dev/tty
  printf "  This is decided once, when the key is made, and cannot be changed later.\n\n" >/dev/tty
  printf "  1) SafeGrd keeps a copy. Losing this host does not lose the backups,\n" >/dev/tty
  printf "     and SafeGrd CAN decrypt them.\n" >/dev/tty
  printf "  2) Only you. SafeGrd gets the public half and can NEVER decrypt them;\n" >/dev/tty
  printf "     lose the key file and nobody can recover the backups.\n\n" >/dev/tty
  while [ -z "$CUSTODY" ]; do
    ask "Choose 1 or 2: "
    case "$REPLY" in
      1) CUSTODY="safegrd" ;;
      2) CUSTODY="local" ;;
    esac
  done
fi

set -- enroll
if [ -n "$CUSTODY" ] && [ -z "$KEY_ON_HOST" ]; then
  set -- "$@" --key-custody "$CUSTODY"
fi
if [ -n "${SAFEGRD_PROJECT:-}" ]; then
  set -- "$@" --project "$SAFEGRD_PROJECT"
fi
if [ -n "${SAFEGRD_NODE_NAME:-}" ]; then
  set -- "$@" --node-name "$SAFEGRD_NODE_NAME"
fi

printf "\n"
if ! "$SAFEGRD_BIN" "$@" </dev/tty; then
  setup_failed "Enrollment failed, so this host is not registered."
fi

printf "\n"
log_success "This host is enrolled. Take the first backup with:"
printf "      ${CYAN}safegrd backup --database-url \"\$DATABASE_URL\"${RESET}\n"
printf "   or run it unattended: ${CYAN}https://safegrd.dev/docs/agent${RESET}\n\n"
