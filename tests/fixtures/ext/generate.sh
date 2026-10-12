#!/usr/bin/env bash
set -euo pipefail

# Regenerate the ext2 and ext4 filesystem fixtures in this directory.
# Usage: tests/fixtures/ext/generate.sh
# Environment: MKE2FS (default: mke2fs), E2FSCK (default: e2fsck) and
# DEBUGFS (default: debugfs) name the e2fsprogs tools. The script needs GNU
# coreutils (touch -d, truncate, find -printf). See README.md for the
# versions used and for running it in a container on macOS.

cd "$(dirname "$0")"

MKE2FS="${MKE2FS:-mke2fs}"
E2FSCK="${E2FSCK:-e2fsck}"
DEBUGFS="${DEBUGFS:-debugfs}"

# Fixed volume and hash-seed UUIDs and timestamps. mke2fs and debugfs read
# E2FSPROGS_FAKE_TIME, e2fsck reads E2FSCK_TIME; inode change times are
# copied from the source tree and pinned with debugfs below.
EXT2_UUID="5a524158-6578-7432-8000-000000000002"
EXT4_UUID="5a524158-6578-7434-8000-000000000004"
HASH_SEED="5a524158-6861-7368-8000-000000000000"
FIXED_TIME=1760227200
export E2FSPROGS_FAKE_TIME="$FIXED_TIME"
export E2FSCK_TIME="$FIXED_TIME"

tree="$(mktemp -d)"
commands="$(mktemp)"
trap 'rm -rf "$tree" "$commands"' EXIT

# Directory tree:
# - payload.elf: the synthetic ELF from the compressed fixtures;
# - boot/payload.elf.gz: its gzip stream;
# - notes.txt: text that is not a recognized format;
# - bin/link: a symlink;
# - bin/sparse.elf: the ELF with data regions at 64, 128, 192, 256 and
#   300 KiB and holes between them. With 1 KiB blocks the regions use the
#   single- and double-indirect blocks; with 4 KiB blocks the six extents
#   need an extent tree of depth 1;
# - many/: 160 hard links to one empty file, enough entries for e2fsck -D
#   to build an htree index, a hard link to payload.elf and a separate copy
#   of it.
mkdir -p "$tree/boot" "$tree/bin" "$tree/many"
cp ../compressed/payload.elf "$tree/payload.elf"
cp ../compressed/payload.elf.gz "$tree/boot/payload.elf.gz"
printf 'zrax ext fixture: not a recognized format\n' > "$tree/notes.txt"
ln -s ../payload.elf "$tree/bin/link"
cp ../compressed/payload.elf "$tree/bin/sparse.elf"
for kib in 64 128 192 256 300; do
    printf 'zrax sparse region at %s KiB\n' "$kib" |
        dd of="$tree/bin/sparse.elf" bs=1024 seek="$kib" conv=notrunc status=none
done
truncate -s 310K "$tree/bin/sparse.elf"
: > "$tree/many/empty"
for i in $(seq -w 0 159); do
    ln "$tree/many/empty" "$tree/many/member-entry-$i.bin"
done
ln "$tree/payload.elf" "$tree/many/hardlink.elf"
cp ../compressed/payload.elf "$tree/many/member-entry-160.elf"
find "$tree" -exec touch -h -d "@$FIXED_TIME" {} +

# mke2fs -d gives the source inodes numbers 12 and up, in creation order.
inode_count="$(find "$tree" -mindepth 1 -printf '%i\n' | sort -u | wc -l)"
for ((inode = 12; inode < 12 + inode_count; inode++)); do
    for field in atime ctime mtime; do
        echo "set_inode_field <$inode> $field @$FIXED_TIME"
    done
done > "$commands"

# Build htree indexes for directories that span several blocks, then pin the
# inode times the source tree could not fix. e2fsck exits with 1 when it
# changed the filesystem.
finish() {
    local status=0
    "$E2FSCK" -fyD "$1" > /dev/null || status=$?
    if [ "$status" -gt 1 ]; then
        echo "e2fsck -fyD $1 failed with status $status" >&2
        exit 1
    fi
    "$DEBUGFS" -w -f "$commands" "$1" > /dev/null
    "$E2FSCK" -fn "$1"
}

rm -f ext2.img ext4.img

# ext2: 1 KiB blocks, 128-byte inodes, block maps, no resize inode.
"$MKE2FS" -q -F -t ext2 -b 1024 -I 128 -N 32 -m 0 -O ^resize_inode \
    -L zrax-ext2 -U "$EXT2_UUID" -E root_owner=0:0,hash_seed="$HASH_SEED" \
    -d "$tree" ext2.img 256
finish ext2.img

# ext4: 4 KiB blocks, 256-byte inodes and the mke2fs.conf ext4 features
# (extents, flex_bg, 64bit, metadata_csum, ...), without a journal, which
# would need at least 1024 blocks.
"$MKE2FS" -q -F -t ext4 -b 4096 -I 256 -N 32 -m 0 -O ^has_journal,^resize_inode \
    -L zrax-ext4 -U "$EXT4_UUID" -E root_owner=0:0,hash_seed="$HASH_SEED" \
    -d "$tree" ext4.img 64
finish ext4.img
