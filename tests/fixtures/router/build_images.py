#!/usr/bin/env python3
"""Build the synthetic router firmware fixtures for tests/router.rs.

Purpose: write synthetic payloads and wrap them in Broadcom TRX, Netgear
CHK, D-Link SEAMA, TP-Link (mktplinkfw v1, mktplinkfw2 v2) and TP-Link
SafeLoader containers. Each wrapper follows the OpenWrt firmware-utils
writer at a1d9589f1ea1b96529ac10fef5d164ff3aa03dc7 field by field (trx.c,
mkchkimg.c, seama.c, mktplinkfw.c, mktplinkfw2.c, mktplinkfw-lib.c and
tplink-safeloader.c). This is an independent re-implementation for test
fixtures; it does not run the upstream tools.

Output layout (all in DIR):
  payloads step: kernel.elf, loader.elf, rootfs.bin
  wrappers step: loader.gz, image.trx, image-v2.trx, image.chk,
                 image.seama, tplink-v1.bin, tplink-v2.bin, safeloader.bin
The wrappers step reads kernel.elf.lzma, which generate.sh makes with xz.

Usage:
  build_images.py payloads DIR
  build_images.py wrappers DIR
"""

import argparse
import gzip
import hashlib
import struct
import zlib
from pathlib import Path

ELFCLASS32 = 1
ELFDATA2MSB = 2
ET_EXEC = 2
EM_MIPS = 8

TRX_MAGIC = 0x30524448
TRX_ROUND = 0x1000

CHK_MAGIC = 0x2A23245E
CHK_BOARD_ID = b"U12H072T00_NETGEAR"

SEAMA_MAGIC = 0x5EA3A417

TPLINK_HEADER_SIZE = 0x200
TPLINK_V1_SALT_NORMAL = bytes.fromhex("dcd73aa5c39598fbddf9e7f40eae4738")
TPLINK_V2_SALT_NORMAL = bytes.fromhex("dcd73aa5c39598fbdcf9e7f40eae4737")
# Synthetic board values; they name no real device.
TPLINK_HW_ID = 0x5A520001
TPLINK_KERNEL_LA = 0x80060000
TPLINK_FW_MAX_LEN = 0x3C0000
TPLINK_ROOTFS_OFS = 0x1000

SAFELOADER_SALT = bytes.fromhex("7a2b15ed9b98596de504ab44ac2a9f4e")
SAFELOADER_PAYLOAD_OFFSET = 0x1014
SAFELOADER_TABLE_SIZE = 0x800


def elf_header(body_text: bytes, size: int) -> bytes:
    """A 52-byte ELF32 big-endian MIPS executable header, then body text."""
    header = bytearray(52)
    header[0:4] = b"\x7fELF"
    header[4] = ELFCLASS32
    header[5] = ELFDATA2MSB
    header[6] = 1  # EV_CURRENT
    struct.pack_into(">HHI", header, 16, ET_EXEC, EM_MIPS, 1)
    # e_ehsize, e_phentsize, e_shentsize
    struct.pack_into(">HHH", header, 40, 52, 32, 40)
    body = (body_text * size)[: size - len(header)]
    return bytes(header) + body


def jamcrc(data: bytes) -> int:
    """CRC-32 with initial value 0xFFFFFFFF and no final XOR (trx.c)."""
    return zlib.crc32(data) ^ 0xFFFFFFFF


def pad_to(data: bytearray, align: int) -> None:
    """Zero-fill to a multiple of align, as trx.c does."""
    remainder = len(data) % align
    if remainder:
        data.extend(b"\0" * (align - remainder))


def cybertan_header() -> bytes:
    """32-byte Cybertan code header (addpattern.c): magic W54G, date
    2026-10-12, version 1.0.0, id U2ND, stable/try fields zero."""
    header = bytearray(32)
    header[0:4] = b"W54G"
    header[8:11] = bytes([26, 10, 12])
    header[11:14] = bytes([1, 0, 0])
    header[14:18] = b"U2ND"
    return bytes(header)


def trx(parts: list, version: int) -> bytes:
    """trx.c: header, each part zero-padded to 4 B with its offset
    recorded, the image zero-padded to 4 KiB, CRC from offset 12."""
    header_size = 28 if version == 1 else 32
    image = bytearray(header_size)
    offsets = []
    for part in parts:
        offsets.append(len(image))
        image.extend(part)
        pad_to(image, 4)
    pad_to(image, TRX_ROUND)
    struct.pack_into("<III", image, 0, TRX_MAGIC, len(image), 0)
    struct.pack_into("<I", image, 12, version << 16)
    for i, offset in enumerate(offsets):
        struct.pack_into("<I", image, 16 + 4 * i, offset)
    crc_input = bytearray(image)
    if version == 2:
        # "set stable and try1-3 to 0xFF for CRC calculation like CFE does"
        at = offsets[3] + 22
        crc_input[at:at + 8] = b"\xff" * 8
    struct.pack_into("<I", image, 8, jamcrc(bytes(crc_input[12:])))
    return bytes(image)


def netgear_checksum(data: bytes) -> int:
    """netgear_checksum_add and _fini from mkchkimg.c."""
    c0 = c1 = 0
    for byte in data:
        c0 = (c0 + byte) & 0xFFFFFFFF
        c1 = (c1 + c0) & 0xFFFFFFFF

    def fold(value: int) -> int:
        folded = (value & 0xFFFF) + (value >> 16)
        return ((folded >> 16) + folded) & 0xFFFF

    return (fold(c1) << 16) | fold(c0)


def chk(kernel: bytes) -> bytes:
    """mkchkimg.c without a root filesystem: region 1 (WW), version
    digits 99 (the tool default), default board ID."""
    header = bytearray(40)
    header_len = 40 + len(CHK_BOARD_ID)
    struct.pack_into(">II", header, 0, CHK_MAGIC, header_len)
    header[8] = 1
    header[9:16] = bytes([99] * 7)
    struct.pack_into(">I", header, 16, netgear_checksum(kernel))
    struct.pack_into(">I", header, 24, len(kernel))
    struct.pack_into(">I", header, 32, netgear_checksum(kernel))
    header_checksum = netgear_checksum(bytes(header) + CHK_BOARD_ID)
    struct.pack_into(">I", header, 36, header_checksum)
    return bytes(header) + CHK_BOARD_ID + kernel


def seama_meta(strings: list) -> bytes:
    """NUL-terminated strings padded with NULs to 4 B (seama.c)."""
    meta = b"".join(s + b"\0" for s in strings)
    return meta + b"\0" * (-len(meta) % 4)


def seama_seal(image: bytes) -> bytes:
    """seama.c -s: a seal header (size 0) and metadata, then one entity:
    header, MD5 of the image, metadata, image."""
    entity_meta = seama_meta([b"dev=/dev/mtdblock/1", b"type=firmware"])
    entity = struct.pack(">IHHI", SEAMA_MAGIC, 0, len(entity_meta), len(image))
    entity += hashlib.md5(image).digest() + entity_meta + image
    seal_meta = seama_meta([b"signature=zrax_router_fixture"])
    seal = struct.pack(">IHHI", SEAMA_MAGIC, 0, len(seal_meta), 0)
    return seal + seal_meta + entity


def tplink_v1(kernel: bytes, rootfs: bytes, combined: bool) -> bytes:
    """mktplinkfw.c fill_header and build_fw with -s (no padding). A
    combined image (-c -O) has no MD5, firmware length or root
    filesystem, and its root filesystem offset points after the kernel."""
    if combined:
        image = bytearray(TPLINK_HEADER_SIZE) + kernel
    else:
        image = bytearray(b"\xff" * (TPLINK_ROOTFS_OFS + len(rootfs)))
        image[0:TPLINK_HEADER_SIZE] = bytes(TPLINK_HEADER_SIZE)
        image[TPLINK_HEADER_SIZE:TPLINK_HEADER_SIZE + len(kernel)] = kernel
        image[TPLINK_ROOTFS_OFS:] = rootfs
    struct.pack_into(">I", image, 0x00, 0x01000000)
    image[0x04:0x04 + 20] = b"TP-LINK Technologies"
    image[0x1C:0x1C + 8] = b"ver. 1.0"
    struct.pack_into(">II", image, 0x40, TPLINK_HW_ID, 1)
    struct.pack_into(">II", image, 0x74, TPLINK_KERNEL_LA, TPLINK_KERNEL_LA)
    struct.pack_into(">II", image, 0x80, TPLINK_HEADER_SIZE, len(kernel))
    if combined:
        struct.pack_into(">I", image, 0x88, TPLINK_HEADER_SIZE + len(kernel))
    else:
        struct.pack_into(">I", image, 0x7C, TPLINK_FW_MAX_LEN)
        struct.pack_into(">II", image, 0x88, TPLINK_ROOTFS_OFS, len(rootfs))
    struct.pack_into(">HHH", image, 0x98, 1, 0, 0)
    if not combined:
        image[0x4C:0x5C] = TPLINK_V1_SALT_NORMAL
        image[0x4C:0x5C] = hashlib.md5(bytes(image)).digest()
    return bytes(image)


def tplink_v2(kernel: bytes, rootfs: bytes) -> bytes:
    """mktplinkfw2.c fill_header_bootloader without a bootloader and
    build_fw with -s: a 0xFF-filled header, version word 2."""
    image = bytearray(b"\xff" * (TPLINK_ROOTFS_OFS + len(rootfs)))
    image[TPLINK_HEADER_SIZE:TPLINK_HEADER_SIZE + len(kernel)] = kernel
    image[TPLINK_ROOTFS_OFS:] = rootfs
    struct.pack_into(">I", image, 0x00, 0x02000000)
    image[0x04:0x04 + 9] = b"ver. 1.0\0"
    struct.pack_into(">III", image, 0x34, TPLINK_HW_ID, 1, 0)
    image[0x40:0x50] = TPLINK_V2_SALT_NORMAL
    struct.pack_into(">I", image, 0x50, 0)
    struct.pack_into(">I", image, 0x64, 0xFFFFFFFF)
    struct.pack_into(">III", image, 0x68,
                     TPLINK_KERNEL_LA, TPLINK_KERNEL_LA, TPLINK_FW_MAX_LEN)
    struct.pack_into(">II", image, 0x74, TPLINK_HEADER_SIZE, len(kernel))
    struct.pack_into(">II", image, 0x7C, TPLINK_ROOTFS_OFS, len(rootfs))
    struct.pack_into(">II", image, 0x84, 0, 0)
    struct.pack_into(">HBBB", image, 0x8C, 0x55AA, 1, 0, 0xA5)
    image[0x91:0x94] = bytes([1, 0, 0])
    image[0x40:0x50] = hashlib.md5(bytes(image)).digest()
    return bytes(image)


def meta_partition(data: bytes) -> bytes:
    """init_meta_partition_entry without a trailing pad byte."""
    return struct.pack(">II", len(data), 0) + data


def flash_table() -> bytes:
    """make_partition_table: 00 04 00 00, lines, NUL, 0xFF fill."""
    lines = b"".join(
        b"partition %s base 0x%05x size 0x%05x\n" % (name, base, size)
        for name, base, size in [
            (b"fs-uboot", 0x00000, 0x20000),
            (b"os-image", 0x20000, 0x180000),
            (b"file-system", 0x1A0000, 0x620000),
        ]
    )
    table = b"\x00\x04\x00\x00" + lines + b"\0"
    return table + b"\xff" * (SAFELOADER_TABLE_SIZE - len(table))


def safeloader(os_image: bytes, rootfs: bytes) -> bytes:
    """generate_factory_image: preamble, vendor information, fwup-ptn
    table and partitions; MD5 of the salt and the bytes from 0x14."""
    # pad1, version 1.0.0, BCD date 2026-10-12, revision 1
    soft_version = bytes([0xFF, 1, 0, 0, 0x20, 0x26, 0x10, 0x12])
    soft_version += struct.pack(">I", 1)
    support_list = b"SupportList:\r\nZRAX-FIXTURE(ZRAX|UN|TEST):1.0\r\n"
    parts = [
        (b"partition-table", flash_table()),
        (b"soft-version", meta_partition(soft_version)),
        (b"support-list", meta_partition(support_list)),
        (b"os-image", os_image),
        (b"file-system", rootfs),
    ]
    size = SAFELOADER_PAYLOAD_OFFSET + SAFELOADER_TABLE_SIZE
    size += sum(len(data) for _, data in parts)
    image = bytearray(b"\xff" * size)
    struct.pack_into(">I", image, 0, size)
    vendor = b"vendor:ZRAX\r\n"
    struct.pack_into(">I", image, 0x14, len(vendor))
    image[0x18:0x18 + len(vendor)] = vendor
    table = b""
    base = SAFELOADER_TABLE_SIZE
    for name, data in parts:
        start = SAFELOADER_PAYLOAD_OFFSET + base
        image[start:start + len(data)] = data
        table += b"fwup-ptn %s base 0x%05x size 0x%05x\t\r\n" % (
            name, base, len(data))
        base += len(data)
    table += b"\0"
    table_end = SAFELOADER_PAYLOAD_OFFSET + len(table)
    image[SAFELOADER_PAYLOAD_OFFSET:table_end] = table
    digest = hashlib.md5(SAFELOADER_SALT + bytes(image[0x14:])).digest()
    image[0x04:0x14] = digest
    return bytes(image)


def write_payloads(out: Path) -> None:
    kernel = elf_header(b"zrax router kernel fixture ", 256)
    loader = elf_header(b"zrax router loader fixture ", 128)
    rootfs = (b"zrax router rootfs fixture\n" * 20)[:512]
    (out / "kernel.elf").write_bytes(kernel)
    (out / "loader.elf").write_bytes(loader)
    (out / "rootfs.bin").write_bytes(rootfs)


def write_wrappers(out: Path) -> None:
    kernel = (out / "kernel.elf.lzma").read_bytes()
    rootfs = (out / "rootfs.bin").read_bytes()
    # The bcm47xx recipe appends one NUL to loader.gz.
    loader_elf = (out / "loader.elf").read_bytes()
    loader = gzip.compress(loader_elf, compresslevel=9, mtime=0) + b"\0"
    (out / "loader.gz").write_bytes(loader)
    image_trx = trx([loader, kernel, rootfs], 1)
    (out / "image.trx").write_bytes(image_trx)
    image_v2 = trx([loader, kernel, rootfs, cybertan_header()], 2)
    (out / "image-v2.trx").write_bytes(image_v2)
    (out / "image.chk").write_bytes(chk(image_trx))
    (out / "image.seama").write_bytes(seama_seal(kernel))
    tplink_v1_image = tplink_v1(kernel, rootfs, combined=False)
    (out / "tplink-v1.bin").write_bytes(tplink_v1_image)
    (out / "tplink-v2.bin").write_bytes(tplink_v2(kernel, rootfs))
    os_image = tplink_v1(kernel, rootfs, combined=True)
    (out / "safeloader.bin").write_bytes(safeloader(os_image, rootfs))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("step", choices=["payloads", "wrappers"])
    parser.add_argument("dir", type=Path)
    args = parser.parse_args()
    if args.step == "payloads":
        write_payloads(args.dir)
    else:
        write_wrappers(args.dir)


if __name__ == "__main__":
    main()
