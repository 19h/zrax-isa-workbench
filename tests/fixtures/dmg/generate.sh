#!/usr/bin/env bash
set -euo pipefail

# Regenerate the Apple disk image fixtures in this directory with hdiutil:
# 1 MiB images whose one volume holds the synthetic ELF header
# tests/fixtures/compressed/payload.elf. HFS+ images in every compressed
# and raw UDIF format hdiutil writes (UDZO zlib, UDBZ bzip2, ULFO LZFSE,
# ULMO LZMA, UDCO ADC, UDRO raw), the UDRO image split into two segments
# of at most 32 KiB, a FAT volume (MS-DOS) image, and an AES-128 encrypted
# UDZO image with the passphrase "zrax". Every file is stored
# gzip-compressed.
# Usage: tests/fixtures/dmg/generate.sh
# Environment: HDIUTIL (default: hdiutil) names the tool. hdiutil writes
# random identifiers, the current time and (for the encrypted image) a
# random salt and keys into the images, so they differ on every run;
# README.md records the committed hashes.

cd "$(dirname "$0")"

HDIUTIL="${HDIUTIL:-hdiutil}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir "$work/src"
cp ../compressed/payload.elf "$work/src/payload.elf"

# create <file system> <format> <image> [options...]: a 1 MiB image of the
# source folder, volume name ZRAX.
create() {
    local fs="$1"
    local format="$2"
    local image="$3"
    shift 3
    "$HDIUTIL" create -quiet -size 1m -fs "$fs" -volname ZRAX -srcfolder "$work/src" \
        -format "$format" "$@" "$work/$image"
}

create HFS+ UDZO hfs-udzo.dmg
create HFS+ UDBZ hfs-udbz.dmg
create HFS+ ULFO hfs-ulfo.dmg
create HFS+ ULMO hfs-ulmo.dmg
create HFS+ UDCO hfs-udco.dmg
create HFS+ UDRO hfs-udro.dmg
create MS-DOS UDZO fat-udzo.dmg
printf 'zrax' | create HFS+ UDZO encrypted.dmg -encryption AES-128 -stdinpass
# segmented.dmg holds the tables and the first 32 KiB of the data fork,
# segmented.002.dmgpart the rest.
"$HDIUTIL" segment -quiet -segmentSize 32k -o "$work/segmented" "$work/hfs-udro.dmg"

# hdiutil must read back every unencrypted image.
for image in "$work"/hfs-*.dmg "$work"/fat-*.dmg "$work"/segmented.dmg; do
    "$HDIUTIL" verify -quiet "$image"
done

rm -f ./*.gz
for file in "$work"/*.dmg "$work"/*.dmgpart; do
    gzip -9 -n -c "$file" > "$(basename "$file").gz"
done

shasum -a 256 ./*.gz
