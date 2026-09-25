#!/bin/sh
# Install a release from its archives, through the real installer, and take one
# encrypted backup through to a byte-identical restore.
#
#   scripts/release-smoke.sh <dist-dir> <version>      e.g. scripts/release-smoke.sh dist 0.0.4
#
# The release workflow runs this on every platform it can before publishing, on
# the same archives it then uploads, so a tag whose binary does not start, does
# not install, or cannot restore what it backed up never reaches
# `releases/latest` and therefore never reaches `curl ... | sh`.
set -eu

dist="$(cd "$1" && pwd)"
version="$2"
here="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

fail() { printf 'release smoke FAILED: %s\n' "$1" >&2; exit 1; }

export HOME="$work/home"
mkdir -p "$HOME"

echo "==> Installing v${version} through install.sh, from ${dist}"
SAFEGRD_DOWNLOAD_BASE="file://${dist}" VERSION="v${version}" \
  SAFEGRD_INSTALL_DIR="$work/bin" SAFEGRD_NO_SETUP=1 \
  sh "$here/install.sh" </dev/null > "$work/install.log" 2>&1 || { cat "$work/install.log"; fail "install.sh exited non-zero"; }
cat "$work/install.log"
grep -q "Checksum verified" "$work/install.log" || fail "the archive was not checked against checksums.txt"

bin="$work/bin/safegrd"
"$bin" version | grep -F "version ${version} " || fail "the installed binary does not report version ${version}"

echo "==> Standalone round trip: init, backup, verify, restore"
mkdir -p "$work/data/nested"
printf 'first file\n' > "$work/data/a.txt"
printf 'second file, one level down\n' > "$work/data/nested/b.txt"

"$bin" init --storage local --local-path "$work/store" || fail "init"
"$bin" backup --files "$work/data" || fail "backup"
snap="$("$bin" list | awk '/^snap-/{print $1; exit}')"
[ -n "$snap" ] || fail "list shows no snapshot after a backup"
"$bin" verify --snapshot "$snap" || fail "verify"
"$bin" restore --snapshot "$snap" --target-dir "$work/restored" || fail "restore"
diff -r "$work/data" "$work/restored" || fail "the restored tree differs from what was backed up"

echo "==> release smoke passed for v${version} on $(uname -s)/$(uname -m)"
