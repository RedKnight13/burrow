#!/usr/bin/env bash
# Downloads the pinned execution-specs fixture release, verifies its checksum and
# unpacks the parts cmd/ethtest uses (state_tests and blockchain_tests).
# Usage: fetch_eth_fixtures.sh [DEST]   (default: tests/ethereum/fixtures)
# The archive is kept in $ETH_FIXTURES_CACHE (default: tests/ethereum/.cache).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lock="$root/tests/ethereum/fixtures.lock"
dest="${1:-$root/tests/ethereum/fixtures}"
cache="${ETH_FIXTURES_CACHE:-$root/tests/ethereum/.cache}"

lockval() { sed -n "s/^$1=//p" "$lock"; }
url="$(lockval url)"
want="$(lockval sha256)"

if [[ -f "$dest/.sha256" && "$(cat "$dest/.sha256")" == "$want" ]]; then
	echo "fixtures up to date: $dest"
	exit 0
fi

archive="$cache/fixtures-$want.tar.gz"
sha() {
	if command -v sha256sum >/dev/null; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

if [[ ! -f "$archive" || "$(sha "$archive")" != "$want" ]]; then
	mkdir -p "$cache"
	echo "downloading $url"
	curl -fsSL -o "$archive.part" "$url"
	got="$(sha "$archive.part")"
	if [[ "$got" != "$want" ]]; then
		rm -f "$archive.part"
		echo "sha256 mismatch: got $got want $want" >&2
		exit 1
	fi
	mv "$archive.part" "$archive"
fi

rm -rf "$dest"
mkdir -p "$dest"
tar -xzf "$archive" -C "$dest" --strip-components=1 fixtures/state_tests fixtures/blockchain_tests
echo "$want" > "$dest/.sha256"
echo "fixtures ready: $dest"
