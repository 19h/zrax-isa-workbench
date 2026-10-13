#!/usr/bin/env bash
set -euo pipefail

# Regenerate the exFAT fixture in this directory with exfatprogs and the
# Linux exfat driver. The script formats an image, mounts it through a loop
# device and copies the tree, so it needs root and a kernel with exfat
# support (see README.md for running it in a privileged container).
# Usage: tests/fixtures/fat/generate-exfat.sh
# Environment: MKFS_EXFAT (default: mkfs.exfat) and FSCK_EXFAT (default:
# fsck.exfat) name the exfatprogs tools. The script also needs GNU
# coreutils and gzip. The volume serial number and the creation and access
# timestamps come from the clock, so the image is not byte-reproducible.

cd "$(dirname "$0")"

MKFS_EXFAT="${MKFS_EXFAT:-mkfs.exfat}"
FSCK_EXFAT="${FSCK_EXFAT:-fsck.exfat}"
FIXED_TIME=1760227200

tree="$(mktemp -d)"
mnt="$(mktemp -d)"
cleanup() {
    if mountpoint -q "$mnt"; then
        umount "$mnt"
    fi
    rm -rf "$tree" "$mnt"
}
trap cleanup EXIT

# Source files: as in generate.sh, with split.elf 6000 B (two 4 KiB
# clusters). Its first cluster is written before keep.txt and the rest
# appended after it, so the driver chains its clusters in the FAT instead of
# marking them contiguous (NoFatChain).
cp ../compressed/payload.elf "$tree/payload.elf"
cp ../compressed/payload.elf.gz "$tree/payload.elf.gz"
printf 'zrax exFAT fixture: not a recognized format\n' > "$tree/notes.txt"
printf 'zrax exFAT fixture: the cluster after split.elf\n' > "$tree/keep.txt"
cp ../compressed/payload.elf "$tree/split.elf"
for i in $(seq -w 0 299); do
    printf 'zrax split line %s\n' "$i"
done >> "$tree/split.elf"
truncate -s 6000 "$tree/split.elf"
head -c 4096 "$tree/split.elf" > "$tree/split.head"
tail -c +4097 "$tree/split.elf" > "$tree/split.tail"
touch -d "@$FIXED_TIME" "$tree"/*

rm -f exfat.img exfat.img.gz
truncate -s 2M exfat.img
"$MKFS_EXFAT" -q -L ZRAXEXFAT -c 4096 -b 4096 exfat.img
mount -o loop exfat.img "$mnt"
cp --preserve=timestamps "$tree/payload.elf" "$mnt/payload.elf"
cp --preserve=timestamps "$tree/notes.txt" "$mnt/notes.txt"
cp --preserve=timestamps "$tree/payload.elf" "$mnt/Long File Name Payload.elf"
mkdir "$mnt/boot"
cp --preserve=timestamps "$tree/payload.elf.gz" "$mnt/boot/payload.elf.gz"
mkdir "$mnt/frag"
cp "$tree/split.head" "$mnt/frag/split.elf"
sync
cp --preserve=timestamps "$tree/keep.txt" "$mnt/frag/keep.txt"
sync
cat "$tree/split.tail" >> "$mnt/frag/split.elf"
touch -d "@$FIXED_TIME" "$mnt/frag/split.elf"
# A deleted entry set that no later file reuses.
cp --preserve=timestamps "$tree/payload.elf" "$mnt/boot/deleted.elf"
sync
rm "$mnt/boot/deleted.elf"
umount "$mnt"
"$FSCK_EXFAT" -n exfat.img > /dev/null
gzip -9 -n exfat.img
