#!/usr/bin/env bash
# Downloads the pinned execution-specs fixture release and verifies its checksum.
# Usage: fetch_eth_fixtures.sh [DEST]   (default: tests/ethereum/fixtures)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lock="$root/tests/ethereum/fixtures.lock"
dest="${1:-$root/tests/ethereum/fixtures}"

lockval() { sed -n "s/^$1=//p" "$lock"; }
url="$(lockval url)"
want="$(lockval sha256)"

if [[ -f "$dest/.sha256" && "$(cat "$dest/.sha256")" == "$want" ]]; then
	echo "fixtures up to date: $dest"
	exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "downloading $url"
curl -fsSL -o "$tmp/fixtures.tar.gz" "$url"
got="$(shasum -a 256 "$tmp/fixtures.tar.gz" | cut -d' ' -f1)"
if [[ "$got" != "$want" ]]; then
	echo "sha256 mismatch: got $got want $want" >&2
	exit 1
fi

rm -rf "$dest"
mkdir -p "$dest"
tar -xzf "$tmp/fixtures.tar.gz" -C "$dest" --strip-components=1
echo "$want" > "$dest/.sha256"
echo "fixtures ready: $dest"
