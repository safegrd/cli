#!/bin/sh
# SafeGrd CLI Universal Installer
# https://safegrd.dev
#
# Usage:
#   curl -fsSL https://safegrd.dev/install.sh | bash
#   or:
#   curl -fsSL https://raw.githubusercontent.com/safegrd/cli/main/install.sh | bash
#
# Custom options:
#   VERSION=v0.0.1 curl -fsSL https://safegrd.dev/install.sh | bash
#   SAFEGRD_INSTALL_DIR=~/.local/bin curl -fsSL https://safegrd.dev/install.sh | bash

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
DEFAULT_FALLBACK_VERSION="v0.0.1"
TARGET_VERSION="${VERSION:-${SAFEGRD_VERSION:-}}"

if [ -z "$TARGET_VERSION" ]; then
  log_info "Detecting latest SafeGrd CLI release from GitHub..."
  # Try GitHub API first
  LATEST_JSON="$(download_stdout "https://api.github.com/repos/safegrd/cli/releases/latest" 2>/dev/null || true)"
  TARGET_VERSION="$(echo "$LATEST_JSON" | grep '"tag_name":' | head -n 1 | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/' || true)"

  # Fallback to redirect resolution if API was rate-limited or failed
  if [ -z "$TARGET_VERSION" ]; then
    if [ "$DOWNLOADER" = "curl" ]; then
      LOC="$(curl -sI "https://github.com/safegrd/cli/releases/latest" 2>/dev/null | grep -i '^location:' | tr -d '\r\n' || true)"
      TARGET_VERSION="$(echo "$LOC" | sed -E 's/.*tag\///' || true)"
    fi
  fi

  # Final fallback if repository has no public releases yet or network is blocked
  if [ -z "$TARGET_VERSION" ]; then
    TARGET_VERSION="$DEFAULT_FALLBACK_VERSION"
    log_warn "Could not query GitHub releases API; defaulting to ${TARGET_VERSION}"
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
DOWNLOAD_URL="https://github.com/safegrd/cli/releases/download/${TAG}/${ARCHIVE_NAME}"
CHECKSUMS_URL="https://github.com/safegrd/cli/releases/download/${TAG}/checksums.txt"

log_info "Downloading ${ARCHIVE_NAME}..."
if ! download_file "$DOWNLOAD_URL" "$TMP_DIR/$ARCHIVE_NAME"; then
  log_error "Failed to download release archive from:"
  log_error "  $DOWNLOAD_URL"
  log_error "Please verify the tag exists at https://github.com/safegrd/cli/releases"
  exit 1
fi

# 7. Checksum Verification
if download_file "$CHECKSUMS_URL" "$TMP_DIR/checksums.txt" 2>/dev/null; then
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

# 12. Quickstart Guidance
printf "\n"
printf "${BOLD}================================================================${RESET}\n"
printf "${BOLD} SafeGrd CLI (${TAG}) Ready!${RESET}\n"
printf "${BOLD}================================================================${RESET}\n"
printf " Next steps:\n"
printf "   1. Initialize your local asymmetric Age encryption keys:\n"
printf "      ${CYAN}safegrd init --database-url \"\$DATABASE_URL\"${RESET}\n\n"
printf "   2. Enroll this host with the SafeGrd remote server:\n"
printf "      ${CYAN}safegrd enroll --token <PAT_TOKEN>${RESET}\n\n"
printf "   3. Create your first immutable, zero-knowledge backup:\n"
printf "      ${CYAN}safegrd backup${RESET}\n\n"
printf " Documentation: ${CYAN}https://safegrd.dev${RESET} | CLI source: ${CYAN}https://github.com/safegrd/cli${RESET}\n"
printf "${BOLD}================================================================${RESET}\n\n"
