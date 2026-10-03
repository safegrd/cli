#!/bin/sh
# The CLI release the packaging files run: the Compose file, the Kubernetes
# CronJob and the Helm chart. They name a released version, never `latest`, so
# a node pulls the image when the version changes and not on every run.
#
#   sh scripts/packaging-version.sh check          all of them name one version
#   sh scripts/packaging-version.sh check 0.0.11   and it is 0.0.11
#   sh scripts/packaging-version.sh set 0.0.11     make them name 0.0.11
#
# `make release-tag` runs `set` before it tags; the release refuses a tag that
# `check` does not match.
set -eu
cd "$(dirname "$0")/.."

compose=packaging/compose/compose.yaml
cronjob=packaging/kubernetes/cronjob.yaml
chart=packaging/helm/safegrd/Chart.yaml
image='ghcr.io/safegrd/cli'

fail() {
	echo "packaging-version: $*" >&2
	exit 1
}

# One line per place a version is named: the Compose file's image, the
# CronJob's two images, the chart's version and appVersion.
named() {
	sed -n "s|^ *image: $image:\\([^[:space:]\"]*\\).*|$compose \\1|p" "$compose"
	sed -n "s|^ *image: $image:\\([^[:space:]\"]*\\).*|$cronjob \\1|p" "$cronjob"
	sed -n "s|^version: *\"\\{0,1\\}\\([^\"]*\\)\"\\{0,1\\}\$|$chart \\1|p; s|^appVersion: *\"\\{0,1\\}\\([^\"]*\\)\"\\{0,1\\}\$|$chart \\1|p" "$chart"
}

valid() {
	printf '%s' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'
}

check() {
	lines="$(named)"
	n="$(printf '%s\n' "$lines" | grep -c .)"
	[ "$n" = 5 ] || fail "found $n of the 5 places a version is named:
$lines"
	versions="$(printf '%s\n' "$lines" | awk '{ print $2 }' | sort -u)"
	[ "$(printf '%s\n' "$versions" | grep -c .)" = 1 ] || fail "the packaging files name different versions:
$lines"
	valid "$versions" || fail "the packaging files name '$versions', not a released version such as 0.0.11"
	if [ -n "${1:-}" ] && [ "$versions" != "$1" ]; then
		fail "the packaging files name $versions and this is $1. Run: sh scripts/packaging-version.sh set $1"
	fi
	echo "The packaging files name $versions."
}

case "${1:-}" in
check)
	check "${2:-}"
	;;
set)
	v="${2:-}"
	valid "$v" || fail "set takes a version such as 0.0.11, not '$v'"
	for f in "$compose" "$cronjob"; do
		sed "s|^\\( *image: $image:\\)[^[:space:]\"]*|\\1$v|" "$f" >"$f.tmp" && mv "$f.tmp" "$f"
	done
	sed "s|^version: .*|version: $v|; s|^appVersion: .*|appVersion: \"$v\"|" "$chart" >"$chart.tmp" && mv "$chart.tmp" "$chart"
	check "$v"
	;;
*)
	fail "usage: $0 check [version] | set version"
	;;
esac
