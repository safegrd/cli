#!/bin/sh
# SafeGrd CLI Universal Installer
# https://safegrd.dev
#
# Usage:
#   curl -fsSL https://safegrd.dev/install.sh | sh
#   or, the same file from the source repository:
#   curl -fsSL https://raw.githubusercontent.com/safegrd/cli/main/install.sh | sh
#
# When the release asked for is already installed, it is not downloaded again;
# the script goes straight on to connecting the host.
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
#   SAFEGRD_FORCE_INSTALL=1  download and install even when this release is already installed
#   SAFEGRD_PROJECT      project ID or slug to enroll this host into
#   SAFEGRD_STORAGE      where backups go when the project has no bucket: 'hosted' or 'local'
#   SAFEGRD_CLAIM        the code the console shows for this host: the project, where backups
#                        go and the surfaces to protect, as chosen in the browser
#   SAFEGRD_NODE_NAME    name this host is shown under (default: its hostname)
#   SAFEGRD_KEY_CUSTODY  'local' keeps this host's key on the host. Without it SafeGrd keeps
#                        the key sealed and releases it only to your enrolled hosts
#   SAFEGRD_TOKEN        a token from Tokens in the console (sg_pat_...). With it the host
#                        enrolls with no terminal and no browser login: CI, cloud-init,
#                        ssh host 'curl ... | sh'
#   SAFEGRD_SERVER_URL   remote server to log in and enroll with (default: https://safegrd.dev)
#   SAFEGRD_DOWNLOAD_BASE  where release archives are fetched from, for testing a
#                        build before it is published (curl only; file:// works)

set -e

# ANSI styling. The variables hold the escape characters themselves, not
# "\033" text: printf expands that only in its format, so a colour passed in
# as an argument (log_info "... ${BOLD}${TAG}${RESET}") printed as \033[1m.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  ESC="$(printf '\033')"
  BOLD="${ESC}[1m"
  GREEN="${ESC}[32m"
  CYAN="${ESC}[36m"
  YELLOW="${ESC}[33m"
  RED="${ESC}[31m"
  RESET="${ESC}[0m"
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
  printf "${GREEN}%s${RESET}\n" "$1"
}

log_warn() {
  printf "${YELLOW}Warning: %s${RESET}\n" "$1" >&2
}

log_error() {
  printf "${RED}Error: %s${RESET}\n" "$1" >&2
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

# 6. Is this release already installed?
# Re-running the one-liner is how a claim code or a second setup attempt is
# used, so a host that already has the release is not made to download it
# again. The binary in INSTALL_DIR decides when there is one: it is the one
# this script would replace. Otherwise one on PATH counts, unless an install
# directory was named, which asks for a copy there.
installed_version() {
  "$1" --version 2>/dev/null | sed -n 's/^safegrd version \([^ ]*\).*/\1/p' | head -n 1
}

SAFEGRD_BIN="$INSTALL_DIR/safegrd"
if [ -x "$INSTALL_DIR/safegrd" ]; then
  EXISTING_BIN="$INSTALL_DIR/safegrd"
elif [ -z "${SAFEGRD_INSTALL_DIR:-}" ] && command -v safegrd >/dev/null 2>&1; then
  EXISTING_BIN="$(command -v safegrd)"
else
  EXISTING_BIN=""
fi

ALREADY_INSTALLED=""
if [ -n "$EXISTING_BIN" ] && [ -z "${SAFEGRD_FORCE_INSTALL:-}" ]; then
  EXISTING_VERSION="$(installed_version "$EXISTING_BIN" || true)"
  if [ -n "$EXISTING_VERSION" ] && [ "$EXISTING_VERSION" = "$VERSION_NUM" ]; then
    ALREADY_INSTALLED=1
    SAFEGRD_BIN="$EXISTING_BIN"
    INSTALL_DIR="$(dirname "$EXISTING_BIN")"
    log_success "SafeGrd CLI ${TAG} is already installed and up to date (${EXISTING_BIN})."
    printf "   Set SAFEGRD_FORCE_INSTALL=1 to download and install it again.\n"
  fi
fi

TMP_DIR=""
cleanup() {
  if [ -n "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}

if [ -z "$ALREADY_INSTALLED" ]; then
  # 7. Download Artifacts to Temporary Directory
  TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'safegrd-install')"
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

  # 8. Checksum verification. Nothing is installed that was not checked:
  # a missing checksums.txt, an archive it does not list or a machine with
  # no SHA-256 tool stops here. SAFEGRD_SKIP_VERIFY=1 is the explicit
  # override, for a mirror that publishes no checksums.
  if [ -n "${SAFEGRD_SKIP_VERIFY:-}" ]; then
    log_warn "SAFEGRD_SKIP_VERIFY is set; the download was NOT verified."
  else
    if ! download_file "$CHECKSUMS_URL" "$TMP_DIR/checksums.txt" 2>/dev/null; then
      log_error "No checksums.txt next to the archive, so the download cannot be verified:"
      log_error "  $CHECKSUMS_URL"
      log_error "Not installing. Set SAFEGRD_SKIP_VERIFY=1 to install an unverified download."
      exit 1
    fi
    log_info "Verifying SHA256 checksum..."
    EXPECTED_HASH="$(grep "${ARCHIVE_NAME}" "$TMP_DIR/checksums.txt" | awk '{print $1}' | head -n 1 || true)"
    if [ -z "$EXPECTED_HASH" ]; then
      log_error "${ARCHIVE_NAME} is not listed in checksums.txt, so the download cannot be verified."
      log_error "Not installing. Set SAFEGRD_SKIP_VERIFY=1 to install an unverified download."
      exit 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
      ACTUAL_HASH="$(sha256sum "$TMP_DIR/$ARCHIVE_NAME" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
      ACTUAL_HASH="$(shasum -a 256 "$TMP_DIR/$ARCHIVE_NAME" | awk '{print $1}')"
    else
      log_error "Neither 'sha256sum' nor 'shasum' is installed, so the download cannot be verified."
      log_error "Not installing. Install one of them, or set SAFEGRD_SKIP_VERIFY=1 to install an unverified download."
      exit 1
    fi
    if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
      log_error "Checksum verification failed!"
      log_error "  Expected: $EXPECTED_HASH"
      log_error "  Actual:   $ACTUAL_HASH"
      exit 1
    fi
    log_success "Checksum verified: ${ACTUAL_HASH}"
  fi

  # 9. Unpack Archive
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

  # 10. Install Binary
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

  # 11. Smoke Test
  if [ -x "$INSTALL_DIR/safegrd" ]; then
    VERSION_OUTPUT="$("$INSTALL_DIR/safegrd" version 2>/dev/null || "$INSTALL_DIR/safegrd" --version 2>/dev/null || true)"
    log_success "Installed: ${VERSION_OUTPUT:-safegrd}"
  else
    log_error "Installation failed: $INSTALL_DIR/safegrd is not executable."
    exit 1
  fi
fi

# 12. Check PATH
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    log_warn "$INSTALL_DIR is not in your PATH environment variable."
    printf "   Add it by running:\n"
    printf "   ${BOLD}export PATH=\"%s:\$PATH\"${RESET}\n" "$INSTALL_DIR"
    printf "   or append it to your ${BOLD}~/.bashrc${RESET} or ${BOLD}~/.zshrc${RESET}.\n\n"
    ;;
esac

# Another safegrd earlier on PATH (a package manager's, an older copy) is the
# one every command typed after this script runs, so the next steps would run
# a different release from the one just set up, and a config it does not
# understand. Said as the last thing printed, whichever way the script ends.
# same_file says whether two paths are one file, following symlinks (a
# Homebrew binary is a symlink into its Cellar). `test -ef` does this but is
# not POSIX, and dash is what runs `curl | sh` on Debian and Ubuntu.
same_file() {
  [ "$1" = "$2" ] && return 0
  # An inode is unique only within its filesystem, so both are compared.
  # Only ls -Li's first field, the inode, is read, so SC2012's concern about
  # unusual file names does not apply; POSIX has no stat to ask instead.
  # shellcheck disable=SC2012
  a="$(ls -Li "$1" 2>/dev/null | awk '{print $1}'):$(df -P "$1" 2>/dev/null | awk 'NR==2 {print $1}')"
  # shellcheck disable=SC2012
  b="$(ls -Li "$2" 2>/dev/null | awk '{print $1}'):$(df -P "$2" 2>/dev/null | awk 'NR==2 {print $1}')"
  [ "${a%%:*}" != "" ] && [ "$a" = "$b" ]
}

warn_if_shadowed() {
  ON_PATH="$(command -v safegrd 2>/dev/null || true)"
  if [ -z "$ON_PATH" ] || same_file "$ON_PATH" "$SAFEGRD_BIN"; then
    return 0
  fi
  ON_PATH_VERSION="$("$ON_PATH" --version 2>/dev/null | head -n 1 || true)"
  printf "\n" >&2
  log_warn "Typing 'safegrd' runs ${ON_PATH} (${ON_PATH_VERSION:-unknown version}), not ${SAFEGRD_BIN} (${TAG})."
  printf "   Every safegrd command you type uses that one. Remove it (for Homebrew: brew uninstall safegrd),\n" >&2
  printf "   or put %s before it in PATH, then open a new shell.\n\n" "$(dirname "$SAFEGRD_BIN")" >&2
}
# This replaces the EXIT trap set at step 7, so it removes the download too.
trap 'warn_if_shadowed; cleanup' EXIT

# 13. Connect this host, or say how to
# A binary older than this script (a pinned VERSION, or a release published
# before it) has an enroll that ignores the saved login, so `login` then
# `enroll` would fail. Ask the binary rather than compare versions.
ENROLL_USES_LOGIN=""
if "$SAFEGRD_BIN" enroll --help 2>/dev/null | grep -q "safegrd login"; then
  ENROLL_USES_LOGIN=1
fi

# The enroll command the console's choices make, for printing. The claim
# carries the project, the storage and the key answer, so it needs no more.
claim_enroll_line() {
  line="safegrd enroll --claim ${SAFEGRD_CLAIM}"
  if [ -n "${SAFEGRD_NODE_NAME:-}" ]; then line="${line} --node-name ${SAFEGRD_NODE_NAME}"; fi
  printf "%s" "$line"
}

print_next_steps() {
  printf "\n"
  printf "${BOLD} Next steps${RESET}\n"
  # A claim made in the console names this host's surfaces; generic steps
  # would drop every one of them.
  if [ -n "${SAFEGRD_CLAIM:-}" ] && [ -n "$ENROLL_USES_LOGIN" ]; then
    printf "   1. Log in. Prints a URL and a code; open it in a browser on any device:\n"
    printf "      ${CYAN}safegrd login${RESET}\n\n"
    printf "   2. Enroll this host with the surfaces named in the console:\n"
    printf "      ${CYAN}%s${RESET}\n\n" "$(claim_enroll_line)"
    printf "   3. Check every surface opens from this host. The console shows the result:\n"
    printf "      ${CYAN}safegrd doctor${RESET}\n\n"
    printf "   4. Take the first backups, then keep the daemon running:\n"
    printf "      ${CYAN}safegrd daemon run --once${RESET}\n"
    printf "      ${CYAN}safegrd daemon install${RESET}\n\n"
    printf "   With no terminal, set SAFEGRD_TOKEN to a token from Tokens in the console and run the\n"
    printf "   one-liner again: it enrolls with the claim and nothing to answer.\n"
    printf " Docs: ${CYAN}https://safegrd.dev/docs/install${RESET}\n\n"
    return
  fi
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
  printf "   %s. Check the host. The console shows the result:\n" "$step"
  printf "      ${CYAN}safegrd doctor${RESET}\n\n"
  step=$((step + 1))
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
  # The project and name asked for go into the command, or the retry
  # enrols into the default project.
  hint="safegrd login && safegrd enroll"
  if [ -n "${SAFEGRD_PROJECT:-}" ]; then hint="${hint} --project ${SAFEGRD_PROJECT}"; fi
  if [ -n "${SAFEGRD_NODE_NAME:-}" ]; then hint="${hint} --node-name ${SAFEGRD_NODE_NAME}"; fi
  if [ "${SAFEGRD_KEY_CUSTODY:-}" = "local" ]; then hint="${hint} --key-custody local"; fi
  printf "      %s\n\n" "$hint" >&2
  exit 1
}

# A key already on this host (from `safegrd init`, or a key you put there) is
# yours and is never sent, so there is nothing to ask; enroll says so.
KEY_ON_HOST=""
if [ -f "${HOME}/.safegrd/keys/daemon.key" ] || grep -q '^ *public_key: *age1' "${HOME}/.safegrd/config.yaml" 2>/dev/null; then
  KEY_ON_HOST=1
fi
CUSTODY="${SAFEGRD_KEY_CUSTODY:-}"
CLAIM=""

# Only a release whose enroll takes --claim can use one. An older release is
# told so, rather than enrolled without the setup the console prepared.
use_claim() {
  if [ -n "${SAFEGRD_CLAIM:-}" ]; then
    if "$SAFEGRD_BIN" enroll --help 2>/dev/null | grep -q -- "--claim"; then
      CLAIM="$SAFEGRD_CLAIM"
    else
      setup_failed "This release of safegrd cannot use the console's claim code yet. Install the latest release, or enroll with: safegrd enroll"
    fi
  fi
}

enroll_with() {
  # $@: enroll followed by the credential flags, if any
  if [ -n "$CUSTODY" ] && [ -z "$KEY_ON_HOST" ]; then
    set -- "$@" --key-custody "$CUSTODY"
  fi
  if [ -n "${SAFEGRD_PROJECT:-}" ]; then
    set -- "$@" --project "$SAFEGRD_PROJECT"
  fi
  if [ -n "${SAFEGRD_NODE_NAME:-}" ]; then
    set -- "$@" --node-name "$SAFEGRD_NODE_NAME"
  fi
  if [ -n "$CLAIM" ]; then
    set -- "$@" --claim "$CLAIM"
  fi
  # Only a release whose enroll has --storage is given it. An older one would
  # stop at "unknown flag"; it also never reports its storage, so the remote
  # server does not refuse it for lacking one.
  if [ -n "${SAFEGRD_STORAGE:-}" ] && "$SAFEGRD_BIN" enroll --help 2>/dev/null | grep -q -- "--storage"; then
    set -- "$@" --storage "$SAFEGRD_STORAGE"
  fi
  "$SAFEGRD_BIN" "$@"
}

print_enrolled() {
  printf "\n"
  # A claimed host already has its surfaces in its config, so the daemon is what
  # runs them; a one-off backup command would ignore every choice made in the
  # console.
  if [ -n "$CLAIM" ]; then
    # enroll --claim has just printed the two next steps; saying them again
    # here printed them twice, one under the other.
    log_success "This host is enrolled with the surfaces named in the console."
    printf "\n"
  else
    log_success "This host is enrolled. Take the first backup with:"
    printf "      ${CYAN}safegrd backup --database-url \"\$DATABASE_URL\"${RESET}\n"
    printf "   or run it unattended: ${CYAN}https://safegrd.dev/docs/daemon${RESET}\n\n"
  fi
}

already_enrolled() {
  [ -f "${HOME}/.safegrd/config.yaml" ] && grep -q '^  token: *sg_tok_' "${HOME}/.safegrd/config.yaml" 2>/dev/null
}

printf "\n"
log_success "SafeGrd CLI ${TAG} is installed."

# A host that is already enrolled keeps its key and its node: re-running the
# installer is how people upgrade, and it must not re-register anything.
if [ -z "${SAFEGRD_NO_SETUP:-}" ] && already_enrolled; then
  printf "   This host is already enrolled (%s).\n" "${HOME}/.safegrd/config.yaml"
  printf "   To add the surfaces named for it in the console: ${CYAN}safegrd claim${RESET}\n"
  printf "   Check it with: ${CYAN}safegrd doctor${RESET}\n\n"
  exit 0
fi

# With a token there is nothing to ask and no browser login, so this runs
# where there is no terminal: CI, cloud-init, ssh host 'curl ... | sh'.
if [ -z "${SAFEGRD_NO_SETUP:-}" ] && [ -n "${SAFEGRD_TOKEN:-}" ]; then
  case "$SAFEGRD_TOKEN" in
    sg_pat_*) ;;
    *) setup_failed "SAFEGRD_TOKEN must be a token from Tokens in the console (sg_pat_...)." ;;
  esac
  use_claim
  printf "\n"
  # By reference, so the token is not in the process table while enroll runs.
  export SAFEGRD_TOKEN
  if ! enroll_with enroll --token env:SAFEGRD_TOKEN </dev/null; then
    setup_failed "Enrollment failed, so this host is not registered."
  fi
  print_enrolled
  exit 0
fi

if [ -n "${SAFEGRD_NO_SETUP:-}" ] || [ -z "$ENROLL_USES_LOGIN" ] || ! have_tty; then
  print_next_steps
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

use_claim

printf "\n"
if ! enroll_with enroll </dev/tty; then
  setup_failed "Enrollment failed, so this host is not registered."
fi
print_enrolled
