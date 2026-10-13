#!/usr/bin/env bash
set -euo pipefail

# Regenerate the virtual disk fixtures in this directory with qemu-img and
# qemu-io: a 170 KiB raw disk whose MBR has one FAT12 partition holding the
# FAT12 fixture (tests/fixtures/fat/fat12.img, which contains the synthetic
# payload.elf), converted to QCOW2, VMDK, VHD, VHDX and VDI images. Every
# file is stored gzip-compressed.
# Usage: tests/fixtures/vdisk/generate.sh
# Environment: QEMU_IMG (default: qemu-img) and QEMU_IO (default: qemu-io)
# name the tools. QEMU writes random identifiers and the current time into
# most of these formats, so the images differ on every run; README.md
# records the committed hashes.

cd "$(dirname "$0")"

QEMU_IMG="${QEMU_IMG:-qemu-img}"
QEMU_IO="${QEMU_IO:-qemu-io}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# 340 sectors are 5 cylinders of 4 heads and 17 sectors, the geometry the
# VHD specification's CHS algorithm gives for this size, so qemu-img keeps
# the VHD images at exactly the size of the raw disk.
disk_sectors=340
partition_start=64
fat="../fat/fat12.img"
raw="$work/disk.img"

# put <file> <offset> <hex byte>...: overwrite bytes in place.
put() {
    local file="$1"
    local offset="$2"
    shift 2
    # shellcheck disable=SC2059 # the format is the escaped byte string
    printf "$(printf '\\x%s' "$@")" | dd of="$file" bs=1 seek="$offset" conv=notrunc 2> /dev/null
}

dd if=/dev/zero of="$raw" bs=512 count="$disk_sectors" 2> /dev/null
dd if="$fat" of="$raw" bs=512 seek="$partition_start" conv=notrunc 2> /dev/null
# MBR (UEFI 2.10 Table 5.1): disk signature 0x5A524158 at 440; record 1 at
# 446: inactive, CHS placeholders, OS type 0x01 (FAT12), starting LBA 64,
# 256 sectors (little-endian); boot signature 55 AA at 510.
put "$raw" 440 58 41 52 5a
put "$raw" 446 00 fe ff ff 01 fe ff ff 40 00 00 00 00 01 00 00
put "$raw" 510 55 aa

convert() {
    "$QEMU_IMG" convert -q -f raw "$@"
}

convert -O qcow2 -o compat=1.1,cluster_size=4096 "$raw" "$work/qcow2-v3.qcow2"
convert -O qcow2 -o compat=0.10,cluster_size=512 "$raw" "$work/qcow2-v2.qcow2"
convert -c -O qcow2 -o cluster_size=4096 "$raw" "$work/qcow2-deflate.qcow2"
convert -c -O qcow2 -o cluster_size=4096,compression_type=zstd "$raw" "$work/qcow2-zstd.qcow2"
convert -O qcow2 -o cluster_size=16384,extended_l2=on "$raw" "$work/qcow2-extl2.qcow2"
convert -O vmdk -o subformat=monolithicSparse "$raw" "$work/vmdk-sparse.vmdk"
convert -O vmdk -o subformat=streamOptimized "$raw" "$work/vmdk-stream.vmdk"
convert -O vpc -o subformat=dynamic "$raw" "$work/vhd-dynamic.vhd"
convert -O vpc -o subformat=fixed "$raw" "$work/vhd-fixed.vhd"
convert -O vhdx -o subformat=dynamic,block_size=1M,log_size=1M "$raw" "$work/vhdx-dynamic.vhdx"
convert -O vhdx -o subformat=fixed,block_size=1M,log_size=1M "$raw" "$work/vhdx-fixed.vhdx"
convert -O vdi "$raw" "$work/vdi-dynamic.vdi"
convert -O vdi -o static=on "$raw" "$work/vdi-static.vdi"

# An overlay on qcow2-v3.qcow2 that holds one written sector (sector 8,
# between the MBR and the partition); every other cluster is left to the
# backing file.
(
    cd "$work"
    "$QEMU_IMG" create -q -f qcow2 -o cluster_size=4096 -b qcow2-v3.qcow2 -F qcow2 \
        qcow2-overlay.qcow2
    "$QEMU_IO" -f qcow2 -c 'write -q -P 0x5a 4096 512' qcow2-overlay.qcow2 > /dev/null
)

# Every image must read back as the raw disk. The format is named because
# qemu-img probes a fixed VHD, whose first sector is the guest's, as raw.
for image in "$work"/*.qcow2 "$work"/*.vmdk "$work"/*.vhd "$work"/*.vhdx "$work"/*.vdi; do
    case "$image" in
        *-overlay.qcow2) continue ;;
        *.qcow2) format=qcow2 ;;
        *.vmdk) format=vmdk ;;
        *.vhd) format=vpc ;;
        *.vhdx) format=vhdx ;;
        *.vdi) format=vdi ;;
    esac
    "$QEMU_IMG" compare -q -f raw -F "$format" "$raw" "$image"
done
for image in "$work"/*.qcow2; do
    "$QEMU_IMG" check -q -f qcow2 "$image"
done

rm -f ./*.gz
for file in "$work"/*; do
    gzip -9 -n -c "$file" > "$(basename "$file").gz"
done

shasum -a 256 ./*.gz
