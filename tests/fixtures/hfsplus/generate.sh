#!/usr/bin/env bash
set -euo pipefail

# Regenerate the HFS+ and HFSX volume fixtures in this directory.
# Usage: tests/fixtures/hfsplus/generate.sh
# Requires macOS: hdiutil creates and attaches the raw (UDRW) images,
# newfs_hfs formats them, and ditto --hfsCompression writes decmpfs
# (AppleFSCompression) files. See README.md for the versions used. The
# images are not reproducible byte for byte: volume dates, the volume UUID
# in the Finder info and the journal contents differ on each run.

cd "$(dirname "$0")"

work="$(mktemp -d)"
mnt="$work/mnt"
mkdir "$mnt"
cleanup() {
    hdiutil detach -quiet "$mnt" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

# Members, built from the committed synthetic inputs:
# - payload.elf: the 256 B x86-64 ELF header from the compressed fixtures;
# - zrax.macho: the 8 KiB synthetic arm64 Mach-O from the Apple fixtures,
#   padded with ASCII text to 24 KiB, so that ditto compresses it into the
#   com.apple.decmpfs attribute (files of 16 KiB or less stay uncompressed);
# - large.macho: the same Mach-O padded to 200 KiB, so that ditto stores it
#   as 64 KiB chunks in the resource fork;
# - fragmented.elf: payload.elf padded with ASCII text to 40 KiB, written
#   into single free blocks so that it needs more than eight extents.
python3 - "$work" <<'PY'
import sys
work = sys.argv[1]
elf = open("../compressed/payload.elf", "rb").read()
macho = open("../apple/kernel.macho", "rb").read()

def padded(head, size, text):
    body = bytearray(head)
    while len(body) < size:
        body += text
    return bytes(body[:size])

files = {
    "payload.elf": elf,
    "zrax.macho": padded(macho, 24 << 10, b"zrax synthetic inline member "),
    "large.macho": padded(macho, 200 << 10, b"zrax synthetic resource fork member "),
    "fragmented.elf": padded(elf, 40 << 10, b"zrax synthetic fragmented member "),
    "notes.txt": b"zrax HFS+ fixture: not a recognized format\n",
}
for name, data in files.items():
    open(f"{work}/{name}", "wb").write(data)
PY

attach() {
    hdiutil attach -quiet -nobrowse -noverify -noautoopen -mountpoint "$mnt" "$1"
}

# hfsplus.img: journaled HFS+, 1 MiB, 4 KiB allocation blocks.
hdiutil create -quiet -size 1m -layout NONE -fs "Journaled HFS+" -volname ZRAX "$work/hfsplus"
attach "$work/hfsplus.dmg"
mkdir -p "$mnt/Applications/Zrax.app/Contents/MacOS" "$mnt/Library" "$mnt/bin" "$mnt/links"
cp "$work/payload.elf" "$mnt/payload.elf"
cp "$work/notes.txt" "$mnt/notes.txt"
ditto --hfsCompression "$work/zrax.macho" "$mnt/Applications/Zrax.app/Contents/MacOS/Zrax"
ditto --hfsCompression "$work/large.macho" "$mnt/Library/large.macho"
ln "$mnt/payload.elf" "$mnt/links/hardlink.elf"
ln -s ../payload.elf "$mnt/links/symlink.elf"
# Fragment the free space: 40 single-block files, a filler that takes the
# rest of the volume, then every other single-block file deleted, so the
# 40 KiB file can only be allocated one block at a time.
mkdir "$mnt/frag"
for i in $(seq -w 0 39); do
    dd if=/dev/zero of="$mnt/frag/$i" bs=4096 count=1 status=none
done
dd if=/dev/zero of="$mnt/frag/filler" bs=4096 status=none 2>/dev/null || true
for i in $(seq -w 1 2 39); do
    rm "$mnt/frag/$i"
done
cp "$work/fragmented.elf" "$mnt/bin/fragmented.elf"
rm -rf "$mnt/frag"
sync
hdiutil detach -quiet "$mnt"
cp "$work/hfsplus.dmg" hfsplus.img

# hfsx.img: case-sensitive HFSX, 512 KiB, 512 B allocation blocks, so the
# 4 KiB catalog nodes span eight blocks. /CASE and /case differ only in
# case.
hdiutil create -quiet -size 512k -layout NONE -fs "Case-sensitive HFS+" -fsargs "-b 512" \
    -volname ZRAXX "$work/hfsx"
attach "$work/hfsx.dmg"
mkdir -p "$mnt/CASE" "$mnt/case"
cp "$work/payload.elf" "$mnt/CASE/payload.elf"
cp "$work/zrax.macho" "$mnt/case/payload.elf"
ditto --hfsCompression "$work/large.macho" "$mnt/case/large.macho"
sync
hdiutil detach -quiet "$mnt"
cp "$work/hfsx.dmg" hfsx.img

# The volumes are mostly free space; they are committed compressed.
gzip -9 -n -f hfsplus.img hfsx.img
shasum -a 256 hfsplus.img.gz hfsx.img.gz
