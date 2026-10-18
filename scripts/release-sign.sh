#!/bin/sh
# Signs a release's checksums.txt.
#
#   SAFEGRD_RELEASE_SIGNING_KEY="$(cat key.pem)" sh scripts/release-sign.sh dist
#
# Writes dist/checksums.txt.sig: the Ed25519 signature over checksums.txt,
# base64. Then checks it against every key in pkg/release/trusted_keys.txt and
# fails unless one verifies it, so a release is never published with a
# signature its own binary would refuse. Needs OpenSSL 3.
set -eu

dist="${1:?usage: release-sign.sh <dist directory>}"
keys_file="$(dirname "$0")/../pkg/release/trusted_keys.txt"

if [ -z "${SAFEGRD_RELEASE_SIGNING_KEY:-}" ]; then
  echo "Error: SAFEGRD_RELEASE_SIGNING_KEY is empty. Set the release environment's secret before tagging." >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
umask 077
printf '%s\n' "$SAFEGRD_RELEASE_SIGNING_KEY" > "$work/key.pem"

openssl pkeyutl -sign -inkey "$work/key.pem" -rawin -in "$dist/checksums.txt" -out "$work/sig.bin"
openssl base64 -A -in "$work/sig.bin" > "$dist/checksums.txt.sig"
printf '\n' >> "$dist/checksums.txt.sig"

# A key is one base64 word, so splitting the lines into words is reading them.
# shellcheck disable=SC2013
for key in $(grep -v '^[[:space:]]*#' "$keys_file" | grep -v '^[[:space:]]*$'); do
  printf '%s\n' '-----BEGIN PUBLIC KEY-----' "MCowBQYDK2VwAyEA${key}" '-----END PUBLIC KEY-----' > "$work/pub.pem"
  if openssl pkeyutl -verify -pubin -inkey "$work/pub.pem" -rawin -in "$dist/checksums.txt" -sigfile "$work/sig.bin" >/dev/null 2>&1; then
    echo "Signed checksums.txt; it verifies with ${key}."
    exit 0
  fi
done
echo "Error: the signing key is not one pkg/release/trusted_keys.txt lists, so safegrd would refuse this release." >&2
exit 1
