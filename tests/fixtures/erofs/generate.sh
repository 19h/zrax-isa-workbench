#!/usr/bin/env bash
set -euo pipefail

# Regenerate the EROFS fixtures in this directory with mkfs.erofs.
# Usage: tests/fixtures/erofs/generate.sh
# Environment: MKFS_EROFS (default: mkfs.erofs) names the erofs-utils tool.
# The script also needs perl for the deterministic noise. See README.md for
# the version used and the tree the images hold.

cd "$(dirname "$0")"

MKFS_EROFS="${MKFS_EROFS:-mkfs.erofs}"

tree="$(mktemp -d)"
trap 'rm -rf "$tree"' EXIT

# Directory tree:
# - payload.elf: the synthetic ELF of the compressed-stream fixtures;
# - boot/payload.elf.gz: its gzip stream;
# - notes.txt: text that is not a recognized format;
# - bin/link: a symlink;
# - lib/big.elf: payload.elf, then 1000 lines of text (27256 B);
# - lib/mixed.elf: payload.elf, 8192 B of LCG noise (seed 1), 600 lines of
#   text and 4096 B of LCG noise (seed 7), 24544 B in all. The noise does
#   not compress, so compressed images store it in plain pclusters.
mkdir -p "$tree/boot" "$tree/bin" "$tree/lib"
cp ../compressed/payload.elf "$tree/payload.elf"
cp ../compressed/payload.elf.gz "$tree/boot/payload.elf.gz"
printf 'zrax erofs fixture: not a recognized format\n' > "$tree/notes.txt"
ln -s ../payload.elf "$tree/bin/link"
cp ../compressed/payload.elf "$tree/lib/big.elf"
for i in $(seq -w 0 999); do
    printf 'zrax erofs filler line %s\n' "$i"
done >> "$tree/lib/big.elf"
# x(n+1) = (x(n) * 1103515245 + 12345) mod 2^31; each byte is bits 16-23.
noise() {
    perl -e '$x = $ARGV[0]; for (1 .. $ARGV[1]) { $x = ($x * 1103515245 + 12345) % 2147483648; print chr(($x >> 16) & 255) }' "$1" "$2"
}
cp ../compressed/payload.elf "$tree/lib/mixed.elf"
noise 1 8192 >> "$tree/lib/mixed.elf"
for i in $(seq -w 0 599); do
    printf 'mixed text line %s\n' "$i"
done >> "$tree/lib/mixed.elf"
noise 7 4096 >> "$tree/lib/mixed.elf"

# 4 KiB blocks, build time and every file time 0, a fixed UUID, root
# ownership: the images are reproducible byte for byte.
build() {
    local name="$1"
    shift
    rm -f "$name"
    "$MKFS_EROFS" --quiet -b4096 -T0 -U 5a524158-6572-6f66-8000-000000000000 \
        --all-root "$@" "$name" "$tree"
}

# Uncompressed: flat-plain and flat-inline (tail-packed) files, compact
# inodes.
build plain.img
# Chunk-based files with 8-byte chunk indexes, extended inodes.
build chunk.img --chunksize=4096 -Eforce-chunk-indexes -Eforce-inode-extended
# LZ4HC with 16 KiB big pclusters, compact indexes and tail packing.
build lz4.img -zlz4hc,level=12 -C16384 -Eztailpacking
# LZ4 with full (legacy) indexes.
build lz4-full.img -zlz4 -Elegacy-compress
# DEFLATE (raw DEFLATE pclusters).
build deflate.img -zdeflate,level=9
# MicroLZMA with every file in the packed inode (fragments).
build lzma-fragments.img -zlzma -Eall-fragments
