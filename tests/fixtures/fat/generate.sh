#!/usr/bin/env bash
set -euo pipefail

# Regenerate the FAT12, FAT16 and FAT32 fixtures in this directory with
# dosfstools and mtools.
# Usage: tests/fixtures/fat/generate.sh
# Environment: MKFS_FAT (default: mkfs.fat) and FSCK_FAT (default:
# fsck.fat) name the dosfstools tools; MTOOLS_BIN (default: empty, the
# PATH) is the directory of mcopy, mmd and mdel. The script also needs GNU
# coreutils (touch -d, truncate) and gzip. See README.md for the versions
# used and for running it in a container on macOS.

cd "$(dirname "$0")"

MKFS_FAT="${MKFS_FAT:-mkfs.fat}"
FSCK_FAT="${FSCK_FAT:-fsck.fat}"
MTOOLS_BIN="${MTOOLS_BIN:-}"
MCOPY="${MTOOLS_BIN:+$MTOOLS_BIN/}mcopy"
MMD="${MTOOLS_BIN:+$MTOOLS_BIN/}mmd"
MDEL="${MTOOLS_BIN:+$MTOOLS_BIN/}mdel"

# mkfs.fat --invariant fixes the volume ID, the boot sector serial and the
# label timestamp; mtools stamps new directories with SOURCE_DATE_EPOCH and
# copied files (mcopy -m) with their modification time.
FIXED_TIME=1760227200
export SOURCE_DATE_EPOCH="$FIXED_TIME"
export MTOOLS_SKIP_CHECK=1

tree="$(mktemp -d)"
trap 'rm -rf "$tree"' EXIT

# Source files:
# - payload.elf: the synthetic ELF of the compressed-stream fixtures;
# - payload.elf.gz: its gzip stream;
# - notes.txt: text that is not a recognized format;
# - hole.txt: 512 B of text (one cluster), deleted again to leave a hole;
# - keep.txt: text after the hole;
# - split.elf: payload.elf and 60 lines of text, 1396 B (three clusters).
#   It is copied after hole.txt is deleted, so its chain starts in the hole
#   and continues after keep.txt.
cp ../compressed/payload.elf "$tree/payload.elf"
cp ../compressed/payload.elf.gz "$tree/payload.elf.gz"
printf 'zrax FAT fixture: not a recognized format\n' > "$tree/notes.txt"
for i in $(seq -w 0 15); do
    printf 'zrax FAT hole line %s ......\n' "$i"
done > "$tree/hole.txt"
printf 'zrax FAT fixture: the cluster after the hole\n' > "$tree/keep.txt"
cp ../compressed/payload.elf "$tree/split.elf"
for i in $(seq -w 0 59); do
    printf 'zrax split line %s\n' "$i"
done >> "$tree/split.elf"
touch -d "@$FIXED_TIME" "$tree"/*

# build <image> <FAT bits> <size in KiB> <label>
build() {
    local image="$1"
    rm -f "$image"
    "$MKFS_FAT" --invariant -i 5a524146 -n "$4" -F "$2" -s 1 -C "$image" "$3" > /dev/null
    "$MCOPY" -i "$image" -m "$tree/payload.elf" ::/payload.elf
    "$MCOPY" -i "$image" -m "$tree/notes.txt" ::/notes.txt
    "$MCOPY" -i "$image" -m "$tree/payload.elf" "::/Long File Name Payload.elf"
    "$MMD" -i "$image" ::/boot
    "$MCOPY" -i "$image" -m "$tree/payload.elf.gz" ::/boot/payload.elf.gz
    "$MMD" -i "$image" ::/frag
    "$MCOPY" -i "$image" -m "$tree/hole.txt" ::/frag/hole.txt
    "$MCOPY" -i "$image" -m "$tree/keep.txt" ::/frag/keep.txt
    "$MDEL" -i "$image" ::/frag/hole.txt
    "$MCOPY" -i "$image" -m "$tree/split.elf" ::/frag/split.elf
    # A deleted entry that no later file reuses.
    "$MCOPY" -i "$image" -m "$tree/payload.elf" ::/boot/deleted.elf
    "$MDEL" -i "$image" ::/boot/deleted.elf
    "$FSCK_FAT" -n "$image" > /dev/null
}

# FAT12: 128 KiB, 512 B clusters (220 clusters).
build fat12.img 12 128 ZRAXFAT12
# FAT16: 2304 KiB, 512 B clusters, the fewest clusters FAT16 allows plus a
# margin (4,500 clusters); committed gzip-compressed.
build fat16.img 16 2304 ZRAXFAT16
# FAT32: 34 MiB, 512 B clusters, the fewest clusters FAT32 allows plus a
# margin (68,000 clusters); committed gzip-compressed.
build fat32.img 32 34816 ZRAXFAT32
rm -f fat16.img.gz fat32.img.gz
gzip -9 -n fat16.img fat32.img
