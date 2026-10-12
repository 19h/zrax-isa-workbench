#!/usr/bin/env python3
"""Write the synthetic inputs that generate.sh hands to img4tool.

Outputs:
  kernel  An 8 KiB stand-in for a kernelcache: a 64-bit little-endian
          Mach-O header (CPU_TYPE_ARM64, MH_FILESET, one LC_UUID command)
          followed by repeating ASCII filler. It is not a runnable program.
  im4m    An IM4M manifest in the layout img4lib, PyIMG4 and img4tool share:
          version 0, a MANB body with MANP (CHIP 0x8030, BORD 0x0C) and a
          krnl group (an all-zero 48 B DGST), a 256 B all-zero "signature"
          and a certificate chain holding one placeholder element. Nothing
          in it is signed.

Usage:
  synthetic.py kernel OUT
  synthetic.py im4m OUT
"""

import argparse
import struct

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
MH_FILESET = 0xC
LC_UUID = 0x1B
KERNEL_SIZE = 8192
FILLER = b"zrax synthetic kernelcache "


def kernel():
    """Mach-O header, LC_UUID (UUID bytes 00..0F), then filler."""
    uuid_command = struct.pack("<II", LC_UUID, 24) + bytes(range(16))
    header = struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64,
        CPU_TYPE_ARM64,
        0,  # cpusubtype: CPU_SUBTYPE_ARM64_ALL
        MH_FILESET,
        1,  # ncmds
        len(uuid_command),  # sizeofcmds
        0,  # flags
        0,  # reserved
    )
    image = header + uuid_command
    repeats = KERNEL_SIZE // len(FILLER) + 1
    return image + (FILLER * repeats)[: KERNEL_SIZE - len(image)]


def der_length(size):
    """Definite length: short form below 128, else the fewest octets."""
    if size < 0x80:
        return bytes([size])
    octets = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(octets)]) + octets


def der(identifier, contents):
    return identifier + der_length(len(contents)) + contents


def sequence(*items):
    return der(b"\x30", b"".join(items))


def der_set(*items):
    return der(b"\x31", b"".join(items))


def ia5(text):
    return der(b"\x16", text.encode("ascii"))


def octet_string(data):
    return der(b"\x04", data)


def integer(value):
    """Unsigned big-endian contents with a sign octet when needed."""
    contents = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return der(b"\x02", contents)


def private_tag(fourcc):
    """PRIVATE, constructed, high tag number: the 4CC as a big-endian u32
    in base-128 octets, continuation bit on all but the last."""
    number = int.from_bytes(fourcc.encode("ascii"), "big")
    groups = []
    while True:
        groups.append(number & 0x7F)
        number >>= 7
        if number == 0:
            break
    groups.reverse()
    octets = [g | 0x80 for g in groups[:-1]] + [groups[-1]]
    return b"\xff" + bytes(octets)


def prop(fourcc, value):
    return der(private_tag(fourcc), sequence(ia5(fourcc), value))


def im4m():
    """IM4M: magic, version, SET { MANB }, signature, certificate chain."""
    chip = prop("CHIP", integer(0x8030))
    board = prop("BORD", integer(0x0C))
    manp = prop("MANP", der_set(chip, board))
    krnl = prop("krnl", der_set(prop("DGST", octet_string(bytes(48)))))
    manb = prop("MANB", der_set(manp, krnl))
    signature = octet_string(bytes(256))
    chain = sequence(sequence(octet_string(b"cert")))
    return sequence(ia5("IM4M"), integer(0), der_set(manb), signature, chain)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("kind", choices=["kernel", "im4m"])
    parser.add_argument("out")
    args = parser.parse_args()
    data = kernel() if args.kind == "kernel" else im4m()
    with open(args.out, "wb") as out:
        out.write(data)


if __name__ == "__main__":
    main()
