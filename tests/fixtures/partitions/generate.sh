#!/usr/bin/env bash
set -euo pipefail

# Regenerate the partition table fixtures in this directory with macOS
# hdiutil: 1 MiB raw disk images with an Apple Partition Map (SPUD), a GPT
# (GPTSPUD) and an MBR (MBRSPUD), each with one empty partition and no
# filesystem, stored gzip-compressed.
# Usage: tests/fixtures/partitions/generate.sh
# Environment: HDIUTIL (default: hdiutil) names the tool.
# hdiutil writes random disk and partition GUIDs, so the GPT image and its
# CRCs differ on every run; see README.md for the committed hashes.

cd "$(dirname "$0")"

HDIUTIL="${HDIUTIL:-hdiutil}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for pair in "apm:SPUD" "gpt:GPTSPUD" "mbr:MBRSPUD"; do
    name="${pair%%:*}"
    layout="${pair#*:}"
    "$HDIUTIL" create -quiet -size 1m -layout "$layout" -type UDIF \
        -o "$work/$name" 2> /dev/null
    image="$work/$name.dmg"
    if [ "$(wc -c < "$image" | tr -d ' ')" != 1048576 ]; then
        echo "$name: hdiutil did not write a 1 MiB raw image" >&2
        exit 1
    fi
    gzip -9 -n -c "$image" > "hdiutil-$name.img.gz"
done

shasum -a 256 hdiutil-*.img.gz
