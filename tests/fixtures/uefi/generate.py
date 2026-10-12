#!/usr/bin/env python3
"""Regenerate the synthetic UEFI fixtures in this directory.

The fixtures are built from the documented wire layouts (UEFI PI 1.8
Vol. 1 chapter 15 and Vol. 3 chapters 2-3, EDK2 edk2-stable202408 headers,
coreboot/flashrom flash descriptor definitions), not by the parser under
test. LZMA, LZMA with the x86 BCJ filter and Brotli encodings come from the
XZ Utils `xz` and the `brotli` command-line tools.

Output (in --out, default: this directory):
  pe32-sections.bin          FFS section stream: PE32 section (x86-64 PE32+
                             header and code) and a USER_INTERFACE section
  pe32-sections.bin.lzma     LZMA-alone stream of it, size field set
  pe32-sections.bin.x86.lzma raw LZMA1 with the x86 BCJ filter, with an
                             LZMA-alone header prepended
  pe32-sections.bin.br       Brotli stream of it
  sample.fd                  4 KiB FFSv2 firmware volume (see README.md)
  flash.bin                  20 KiB flash image with an Intel flash
                             descriptor, GbE, ME and BIOS regions

Usage: tests/fixtures/uefi/generate.py [--out DIR]
"""

import argparse
import lzma
import pathlib
import struct
import subprocess

# PE/COFF machine values (Microsoft PE format, "Machine Types").
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

# FFS section types (PI 1.8 Vol. 3, 3.2.4) and file types (3.2.3).
EFI_SECTION_GUID_DEFINED = 0x02
EFI_SECTION_PE32 = 0x10
EFI_SECTION_TE = 0x12
EFI_SECTION_USER_INTERFACE = 0x15
EFI_FV_FILETYPE_PEIM = 0x06
EFI_FV_FILETYPE_DRIVER = 0x07
EFI_FV_FILETYPE_FFS_PAD = 0xF0
FFS_ATTRIB_CHECKSUM = 0x40
EFI_FILE_DATA_VALID = 0x04
EFI_GUIDED_SECTION_PROCESSING_REQUIRED = 0x01

# Volume header fields (PI 1.8 Vol. 3, 3.2.1.1).
EFI_FVB2_ERASE_POLARITY = 0x0000_0800
FV_ATTRIBUTES = 0x0004_FEFF
FV_LENGTH = 0x1000
EXT_HEADER_OFFSET = 0x48
EFI_FV_EXT_TYPE_USED_SIZE_TYPE = 0x0003

# Intel flash descriptor (coreboot ifdtool.h, flashrom ich_descriptors.h).
FLVALSIG = 0x0FF0A55A


def guid(text):
    """On-disk bytes of a GUID written in registry form."""
    data1, data2, data3, data4a, data4b = text.split("-")
    return (struct.pack("<IHH", int(data1, 16), int(data2, 16), int(data3, 16))
            + bytes.fromhex(data4a + data4b))


FFS2_GUID = guid("8C8CE578-8A3D-4F1C-9935-896185C32DD3")
LZMA_GUID = guid("EE4E5898-3914-4259-9D6E-DC7BD79403CF")
VOLUME_NAME = guid("5A1E7E57-0000-4000-8000-0000000000A0")
X64_FILE = guid("5A1E7E57-0000-4000-8000-000000000001")
AA64_FILE = guid("5A1E7E57-0000-4000-8000-000000000002")
TE_FILE = guid("5A1E7E57-0000-4000-8000-000000000003")
LZMA_FILE = guid("5A1E7E57-0000-4000-8000-000000000004")
PAD_FILE = b"\xff" * 16

# x86-64 code with E8 calls so the BCJ filter has work: push rbp; mov rbp,
# rsp; call +0x10; pop rbp; ret.
X64_CODE = bytes.fromhex("554889e5e8100000005dc3") * 4
# AArch64: nop; nop; ret.
AA64_CODE = bytes.fromhex("1f2003d51f2003d5c0035fd6")


def pe_image(machine, code):
    """A PE32+ image: DOS header with e_lfanew 0x40, the PE signature, a COFF
    header (one section, 0xF0-byte optional header), a PE32+ optional header
    with entry point and base of code 0x180, one .text section header, and
    the code at file offset 0x180 (file alignment = section alignment 0x20).
    """
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, 0xF0, 0x0022)
    optional = bytearray(0xF0)
    struct.pack_into("<HBBIIIII", optional, 0, 0x20B, 0, 0, len(code), 0, 0, 0x180, 0x180)
    struct.pack_into("<QII", optional, 24, 0, 0x20, 0x20)  # image base, alignments
    struct.pack_into("<I", optional, 56, 0x180 + len(code))  # SizeOfImage
    struct.pack_into("<I", optional, 60, 0x180)  # SizeOfHeaders
    struct.pack_into("<H", optional, 68, 11)  # EFI boot service driver
    struct.pack_into("<I", optional, 108, 16)  # NumberOfRvaAndSizes
    text = struct.pack("<8sIIIIIIHHI", b".text", len(code), 0x180, len(code), 0x180,
                       0, 0, 0, 0, 0x6000_0020)
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(optional) + text
    assert len(headers) <= 0x180
    return headers.ljust(0x180, b"\0") + code


def te_image(machine, code):
    """A TE image as EDK2 GenFw writes it from pe_image(): the PE headers up
    to the end of the optional header (0x148 B) are replaced by the 40-byte
    TE header; the section header is kept, so the code at RVA 0x180 sits at
    TE offset 0x180 - 0x148 + 40 = 0x60.
    """
    header = struct.pack("<2sHBBHIIQIIII", b"VZ", machine, 1, 11, 0x148, 0x180, 0x180,
                         0, 0, 0, 0, 0)
    text = struct.pack("<8sIIIIIIHHI", b".text", len(code), 0x180, len(code), 0x180,
                       0, 0, 0, 0, 0x6000_0020)
    return (header + text).ljust(0x60, b"\0") + code


def section(section_type, body):
    """A section: 24-bit size including the 4-byte header, the type, the body."""
    return struct.pack("<I", len(body) + 4)[:3] + bytes([section_type]) + body


def ui_section(name):
    """A USER_INTERFACE section: NUL-terminated UCS-2 name."""
    return section(EFI_SECTION_USER_INTERFACE, (name + "\0").encode("utf-16-le"))


def section_stream(*sections):
    """Sections, each padded with zeros to a 4-byte boundary."""
    out = b""
    for item in sections:
        out += item + b"\0" * (-len(item) % 4)
    return out


def guid_defined_section(definition, payload):
    """A GUID-defined section with DataOffset 0x18 and PROCESSING_REQUIRED."""
    fields = definition + struct.pack("<HH", 0x18, EFI_GUIDED_SECTION_PROCESSING_REQUIRED)
    return section(EFI_SECTION_GUID_DEFINED, fields + payload)


def sum8(data):
    return sum(data) & 0xFF


def ffs_file(name, file_type, data, attributes=0):
    """An FFS file with a 24-byte header, valid header checksum, a data
    checksum (FFS_ATTRIB_CHECKSUM) or the fixed 0xAA, and state DATA_VALID
    stored inverted for erase polarity 1."""
    size = 24 + len(data)
    file_checksum = (-sum8(data)) & 0xFF if attributes & FFS_ATTRIB_CHECKSUM else 0xAA
    header = bytearray(name + bytes([0, 0, file_type, attributes]) + struct.pack("<I", size)[:3]
                       + b"\0")
    header[0x10] = (-sum8(header)) & 0xFF
    header[0x11] = file_checksum
    header[0x17] = ~EFI_FILE_DATA_VALID & 0xFF
    return bytes(header) + data


def volume(files):
    """An FFSv2 volume of FV_LENGTH bytes: header with one block-map entry,
    the extended header (name GUID, used-size entry) at 0x48, files from
    0x68 on 8-byte boundaries, free space 0xFF."""
    body = b""
    position = 0x68
    for item in files:
        pad = -position % 8
        body += b"\xff" * pad + item
        position += pad + len(item)
    used = position
    ext = VOLUME_NAME + struct.pack("<IHHI", 0x1C, 8, EFI_FV_EXT_TYPE_USED_SIZE_TYPE, used)
    header = bytearray(0x48)
    header[0x10:0x20] = FFS2_GUID
    struct.pack_into("<Q4sIHHHBB", header, 0x20, FV_LENGTH, b"_FVH", FV_ATTRIBUTES, 0x48, 0,
                     EXT_HEADER_OFFSET, 0, 2)
    struct.pack_into("<II", header, 0x38, FV_LENGTH // 0x1000, 0x1000)
    checksum = (-sum(struct.unpack("<36H", header))) & 0xFFFF
    struct.pack_into("<H", header, 0x32, checksum)
    image = bytes(header) + ext + b"\xff" * (0x68 - 0x48 - len(ext)) + body
    assert len(image) <= FV_LENGTH, len(image)
    return image.ljust(FV_LENGTH, b"\xff")


def flash_image(bios_volume):
    """A 20 KiB flash image: descriptor (16 B of 0xFF, FLVALSIG at 0x10,
    FLMAP0 FCBA 0x30 / FRBA 0x40, FLMAP1 FMBA 0x80 / FPSBA 0x100, FLREG at
    0x40), GbE 0x1000-0x1FFF, ME 0x2000-0x2FFF, BIOS 0x3000-0x4FFF with the
    volume at its top; unused regions are 0x00007FFF."""
    descriptor = bytearray(b"\xff" * 0x1000)
    struct.pack_into("<IIII", descriptor, 0x10, FLVALSIG, 0x0404_0003, 0x1010_0208, 0)
    regions = [0x0000_0000, 0x0004_0003, 0x0002_0002, 0x0001_0001] + [0x0000_7FFF] * 12
    struct.pack_into("<16I", descriptor, 0x40, *regions)
    gbe = (b"\x00\x11\x22\x33\x44\x55" + b"GbE synthetic ").ljust(0x1000, b"\x5a")
    me = (b"ME region: synthetic bytes, not firmware " * 100)[:0x1000]
    bios = b"\xff" * (0x2000 - len(bios_volume)) + bios_volume
    return bytes(descriptor) + gbe + me + bios


def test_ms_byte(b):
    """Bra86.c Test86MSByte: the byte is 0x00 or 0xFF."""
    return ((b + 1) & 0xFE) == 0


def x86_convert(data, encoding):
    """LZMA SDK Bra86.c x86_Convert (as copied into EDK2), state 0, ip 0."""
    data = bytearray(data)
    size = len(data)
    if size < 5:
        return bytes(data)
    limit = size - 4
    ip = 5
    pos = 0
    mask = 0
    while True:
        p = pos
        while p < limit and (data[p] & 0xFE) != 0xE8:
            p += 1
        d = p - pos
        pos = p
        if p >= limit:
            return bytes(data)
        if d > 2:
            mask = 0
        else:
            mask >>= d
            if mask != 0 and (mask > 4 or mask == 3 or test_ms_byte(data[p + (mask >> 1) + 1])):
                mask = (mask >> 1) | 4
                pos += 1
                continue
        if test_ms_byte(data[p + 4]):
            v = data[p + 4] << 24 | data[p + 3] << 16 | data[p + 2] << 8 | data[p + 1]
            cur = (ip + pos) & 0xFFFFFFFF
            pos += 5
            v = (v + cur if encoding else v - cur) & 0xFFFFFFFF
            if mask != 0:
                sh = (mask & 6) << 2
                if test_ms_byte((v >> sh) & 0xFF):
                    v ^= ((0x100 << sh) - 1) & 0xFFFFFFFF
                    v = (v + cur if encoding else v - cur) & 0xFFFFFFFF
                mask = 0
            data[p + 1] = v & 0xFF
            data[p + 2] = (v >> 8) & 0xFF
            data[p + 3] = (v >> 16) & 0xFF
            data[p + 4] = (0 - ((v >> 24) & 1)) & 0xFF
        else:
            mask = (mask >> 1) | 4
            pos += 1


def run(*command, data):
    return subprocess.run(command, input=data, stdout=subprocess.PIPE, check=True).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path(__file__).parent)
    out = parser.parse_args().out

    sections = section_stream(section(EFI_SECTION_PE32, pe_image(IMAGE_FILE_MACHINE_AMD64,
                                                                   X64_CODE)),
                              ui_section("LzmaDxe"))
    (out / "pe32-sections.bin").write_bytes(sections)

    # EDK2 LzmaCompress stores the decoded size; xz writes "unknown".
    alone = bytearray(run("xz", "--format=lzma", "--lzma1=preset=6,dict=64KiB", "-c",
                          data=sections))
    struct.pack_into("<Q", alone, 5, len(sections))
    (out / "pe32-sections.bin.lzma").write_bytes(bytes(alone))

    raw = run("xz", "--format=raw", "--x86", "--lzma1=preset=6,lc=3,lp=0,pb=2,dict=64KiB",
              "-c", data=sections)
    filtered = lzma.decompress(raw, format=lzma.FORMAT_RAW,
                               filters=[{"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2,
                                         "dict_size": 64 << 10}])
    assert filtered != sections, "the x86 filter changed nothing"
    # xz's BCJ encoder must agree with the EDK2 (LZMA SDK) decoder.
    assert x86_convert(filtered, encoding=False) == sections
    assert x86_convert(sections, encoding=True) == filtered
    x86_alone = struct.pack("<BIQ", 0x5D, 64 << 10, len(sections)) + raw
    (out / "pe32-sections.bin.x86.lzma").write_bytes(x86_alone)

    (out / "pe32-sections.bin.br").write_bytes(run("brotli", "-c", "-q", "9", data=sections))

    files = [
        ffs_file(X64_FILE, EFI_FV_FILETYPE_DRIVER,
                 section_stream(section(EFI_SECTION_PE32,
                                        pe_image(IMAGE_FILE_MACHINE_AMD64, X64_CODE)),
                                ui_section("X64Driver")),
                 FFS_ATTRIB_CHECKSUM),
        ffs_file(AA64_FILE, EFI_FV_FILETYPE_DRIVER,
                 section_stream(section(EFI_SECTION_PE32,
                                        pe_image(IMAGE_FILE_MACHINE_ARM64, AA64_CODE)),
                                ui_section("Aa64Driver"))),
        ffs_file(TE_FILE, EFI_FV_FILETYPE_PEIM,
                 section_stream(section(EFI_SECTION_TE,
                                        te_image(IMAGE_FILE_MACHINE_AMD64, X64_CODE)),
                                ui_section("TePeim"))),
        ffs_file(PAD_FILE, EFI_FV_FILETYPE_FFS_PAD, b"\xff" * 16),
        ffs_file(LZMA_FILE, EFI_FV_FILETYPE_DRIVER,
                 section_stream(guid_defined_section(LZMA_GUID, bytes(alone)))),
    ]
    fd = volume(files)
    (out / "sample.fd").write_bytes(fd)
    (out / "flash.bin").write_bytes(flash_image(fd))


if __name__ == "__main__":
    main()
