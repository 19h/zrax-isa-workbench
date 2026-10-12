#!/usr/bin/env bash
set -euo pipefail

# Regenerate the flash filesystem fixtures with mtd-utils 2.2.1
# (mkfs.jffs2, mkfs.ubifs, ubinize) from Alpine Linux 3.22, run in a
# container because mtd-utils does not build on macOS.
#
# Usage: tests/fixtures/mtd/generate.sh [output-dir]
#
# The output directory defaults to this directory. Requires docker and
# network access for `apk add`. mkfs.ubifs writes a random UUID, so the
# UBIFS and UBI images differ from the committed ones on every run; the
# JFFS2 images are reproducible. See README.md.

here="$(cd "$(dirname "$0")" && pwd)"
fixtures="$(cd "$here/.." && pwd)"
out="$(cd "${1:-$here}" && pwd)"

docker run --rm --platform linux/amd64 \
  -v "$fixtures/compressed/payload.elf:/in/payload.elf:ro" \
  -v "$fixtures/transforms/aarch64.text.bin:/in/code.bin:ro" \
  -v "$here/ubinize.cfg:/in/ubinize.cfg:ro" \
  -v "$out:/out" \
  alpine:3.22 sh -euc '
    apk add --no-cache mtd-utils-jffs=2.2.1-r0 mtd-utils-ubi=2.2.1-r0 >/dev/null

    # The synthetic tree. tool.elf is an ELF header followed by raw code, so
    # it spans two 4 KiB blocks; sparse.elf has a hole between two ELF
    # headers; tool-link.elf is a hard link; motd is not a recognized
    # format; sbin is a symlink.
    mkdir -p /work/root/bin /work/root/boot /work/root/etc /work/root/lib /work/root/var
    cat /in/payload.elf /in/code.bin > /work/root/bin/tool.elf
    ln /work/root/bin/tool.elf /work/root/bin/tool-link.elf
    cp /in/payload.elf /work/root/lib/payload.elf
    cp /in/payload.elf /work/root/boot/sparse.elf
    dd if=/in/payload.elf of=/work/root/boot/sparse.elf bs=4096 seek=3 conv=notrunc 2>/dev/null
    printf "zrax mtd fixture\n" > /work/root/etc/motd
    : > /work/root/var/empty
    ln -s bin /work/root/sbin
    find /work/root -exec touch -h -d "2026-10-12 00:00:00" {} +

    # The static UBI volume: an ELF header and six copies of the code, so it
    # spans three 15 KiB LEBs.
    cat /in/payload.elf /in/code.bin /in/code.bin /in/code.bin /in/code.bin /in/code.bin \
      /in/code.bin > /work/kernel.bin

    cd /work
    mkfs.jffs2 -l -U -e 64KiB -r root -o /out/rootfs-le-zlib.jffs2
    mkfs.jffs2 -l -U -e 64KiB -x zlib -r root -o /out/rootfs-le-rtime.jffs2
    mkfs.jffs2 -b -U -e 16KiB -X lzo -x zlib -x rtime -p -r root -o /out/rootfs-be-lzo.jffs2
    mkfs.ubifs -U -m 512 -e 15360 -c 64 -x lzo -r root -o /out/rootfs-lzo.ubifs
    mkfs.ubifs -U -m 512 -e 15360 -c 64 -x zstd -r root -o /work/rootfs-zstd.ubifs
    ubinize -o /out/image.ubi -p 16KiB -m 512 -s 512 -Q 1515340872 /in/ubinize.cfg
  '
