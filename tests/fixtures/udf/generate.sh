#!/usr/bin/env bash
set -euo pipefail

# Regenerate the UDF fixtures in this directory: one synthetic tree written
# by macOS hdiutil makehybrid (UDF 1.02, UDF 1.50 and a UDF bridge disc with
# ISO 9660) and by macOS newfs_udf on raw images filled through the macOS
# UDF file system (UDF 1.02, 2.01 with a fragmented file, 2.50 with a
# metadata partition, 2.01 with 512-byte blocks, and an empty 2.01 volume
# with 4096-byte blocks, which macOS does not mount from a disk image).
# Every image is gzip-compressed (`gzip -9 -n`); the tests decompress them.
# Usage: tests/fixtures/udf/generate.sh
# Requires macOS: hdiutil, /sbin/newfs_udf and the UDF file system. See
# README.md for the versions used. The images are not reproducible byte for
# byte: volume identifiers and set identifiers carry the time of writing,
# and so do the descriptors' timestamps.

cd "$(dirname "$0")"
fixtures="$(pwd)"

work="$(mktemp -d)"
mnt="$work/mnt"
mkdir "$mnt"
cleanup() {
    hdiutil detach -quiet -force "$mnt" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

# The tree: the 256 B x86-64 ELF header from the compressed fixtures, the
# 8 KiB synthetic arm64 Mach-O from the Apple fixtures four directories
# down, a text file that no format recognizes, and the ELF again under a
# name outside Latin-1, which UDF records with 16-bit CS0 characters.
tree="$work/tree"
mkdir -p "$tree/bin" "$tree/deep/a/b/c" "$tree/docs"
cp ../compressed/payload.elf "$tree/bin/payload.elf"
cp ../apple/kernel.macho "$tree/deep/a/b/c/kernel.macho"
printf 'zrax UDF fixture: not a recognized format\n' > "$tree/docs/readme.txt"
cp ../compressed/payload.elf "$tree/docs/café-€.elf"
find "$tree" -exec touch -h -t 202610130000 {} +

hdiutil makehybrid -quiet -o "$work/hdiutil-102.iso" -udf -udf-version 1.02 \
    -udf-volume-name ZRAX_UDF102 "$tree"
hdiutil makehybrid -quiet -o "$work/hdiutil-150.iso" -udf -udf-version 1.50 \
    -udf-volume-name ZRAX_UDF150 "$tree"
hdiutil makehybrid -quiet -o "$work/hdiutil-bridge.iso" -iso -udf \
    -iso-volume-name ZRAX_BRIDGE -udf-volume-name ZRAX_BRIDGE "$tree"

# A zero-filled image of $2 KiB formatted by newfs_udf with the options
# after it.
format() {
    local image="$work/$1" size_kib="$2"
    shift 2
    dd if=/dev/zero of="$image" bs=1k count="$size_kib" 2>/dev/null
    /sbin/newfs_udf "$@" "$image" > /dev/null
}

attach() {
    hdiutil attach -quiet -nobrowse -noverify -noautoopen -mountpoint "$mnt" \
        -imagekey diskimage-class=CRawDiskImage "$work/$1"
}

detach() {
    sync
    hdiutil detach -quiet "$mnt"
}

# Copy the tree onto the image $1.
fill() {
    attach "$1"
    cp -RX "$tree/" "$mnt/"
    detach
}

# Copy the tree onto the image $1, then fill the volume with 4 KiB text
# files, delete every other one and write fragmented.elf (payload.elf
# padded with text to 40 KiB) into the holes, so that it needs several
# extents.
fill_fragmented() {
    attach "$1"
    cp -RX "$tree/" "$mnt/"
    local i
    # The volume fills up after a few dozen files; the shell's message for
    # the file it cannot create is not shown.
    for i in $(seq 1 400); do
        (head -c 4096 /dev/zero | tr '\0' x > "$mnt/spacer$i.txt") 2>/dev/null || break
    done
    sync
    for i in $(seq 1 2 400); do
        rm -f "$mnt/spacer$i.txt"
    done
    sync
    python3 -I - ../compressed/payload.elf "$mnt/fragmented.elf" <<'PY'
import sys
body = bytearray(open(sys.argv[1], "rb").read())
while len(body) < 40 << 10:
    body += b"zrax synthetic fragmented member "
open(sys.argv[2], "wb").write(bytes(body[:40 << 10]))
PY
    detach
}

format newfs-102.img 1024 -r 1.02 -v ZRAX_UDF102
fill newfs-102.img
format newfs-201.img 1024 -r 2.01 -v ZRAX_UDF201
fill_fragmented newfs-201.img
format newfs-250.img 1024 -r 2.50 -v ZRAX_UDF250
fill newfs-250.img
format newfs-512.img 1024 -r 2.01 -b 512 -v ZRAX_UDF512
fill newfs-512.img
format newfs-4k.img 2048 -r 2.01 -b 4096 -v ZRAX_UDF4K

for image in hdiutil-102.iso hdiutil-150.iso hdiutil-bridge.iso newfs-102.img newfs-201.img \
    newfs-250.img newfs-512.img newfs-4k.img; do
    gzip -9 -n -c "$work/$image" > "$fixtures/$image.gz"
done
