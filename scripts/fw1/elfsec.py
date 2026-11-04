#!/usr/bin/env python3
"""List the section headers of one ELF32/ELF64 file: index, name, type,
flags, address, file offset and size.

Usage: elfsec.py FILE
"""
import argparse
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file")
    args = parser.parse_args()
    with open(args.file, "rb") as f:
        data = f.read()
    is_64 = data[4] == 2
    order = "<" if data[5] == 1 else ">"
    if is_64:
        shoff = struct.unpack(order + "Q", data[0x28:0x30])[0]
        shentsize, shnum, shstrndx = struct.unpack(order + "HHH", data[0x3A:0x40])
        layout = order + "IIQQQQ"
    else:
        shoff = struct.unpack(order + "I", data[0x20:0x24])[0]
        shentsize, shnum, shstrndx = struct.unpack(order + "HHH", data[0x2E:0x34])
        layout = order + "IIIIII"

    def section(index):
        """(name offset, type, flags, address, offset, size) of one header."""
        start = shoff + index * shentsize
        return struct.unpack(layout, data[start:start + struct.calcsize(layout)])

    names = section(shstrndx)[4]
    for index in range(shnum):
        name_at, kind, flags, address, offset, size = section(index)
        start = names + name_at
        name = data[start:data.index(b"\0", start)].decode(errors="replace")
        print(f"{index:2} {name:24} type={kind:#x} flags={flags:#x} addr={address:#x} off={offset:#x} size={size:#x}")


if __name__ == "__main__":
    main()
