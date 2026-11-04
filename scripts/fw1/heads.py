#!/usr/bin/env python3
"""Header fields of every fw1 binary: ELF, PE or Mach-O identity plus the
first 64 bytes in hex.

Columns: sha, kind (elf, pe, mz, macho, fat or empty), cls (ELF class), le
(ELF little-endian), machine (ELF e_machine, PE Machine or Mach-O cputype),
etype (ELF e_type), eflags (ELF e_flags), head (hex).

Usage: heads.py FW1_DIR ALL.tsv OUT.tsv
"""
import argparse
import csv
import os
import struct

ELF_MAGIC = b"\x7fELF"
PE_SIGNATURE = b"PE\0\0"
MACHO_MAGICS_LE = (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
MACHO_MAGICS_BE = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf")
FAT_MAGIC = b"\xca\xfe\xba\xbe"
HEAD_SIZE = 4096


def header_fields(head):
    """(kind, class, little-endian, machine, e_type, e_flags) of a file start."""
    if head[:4] == ELF_MAGIC and len(head) >= 0x34:
        elf_class = head[4]
        little = head[5] == 1
        order = "<" if little else ">"
        e_type, machine = struct.unpack(order + "HH", head[16:20])
        flags_at = 0x30 if elf_class == 2 else 0x24
        flags = struct.unpack(order + "I", head[flags_at:flags_at + 4])[0]
        return "elf", elf_class, little, machine, e_type, flags
    if head[:2] == b"MZ" and len(head) >= 0x40:
        pe_at = struct.unpack("<I", head[0x3C:0x40])[0]
        if pe_at + 6 <= len(head) and head[pe_at:pe_at + 4] == PE_SIGNATURE:
            return "pe", "", "", struct.unpack("<H", head[pe_at + 4:pe_at + 6])[0], "", ""
        return "mz", "", "", "", "", ""
    if head[:4] in MACHO_MAGICS_LE + MACHO_MAGICS_BE:
        order = "<" if head[:4] in MACHO_MAGICS_LE else ">"
        return "macho", "", "", struct.unpack(order + "I", head[4:8])[0], "", ""
    if head[:4] == FAT_MAGIC:
        return "fat", "", "", "", "", ""
    return "", "", "", "", "", ""


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("fw1_dir")
    parser.add_argument("all_tsv", help="dump.py output")
    parser.add_argument("out")
    args = parser.parse_args()
    with open(args.all_tsv) as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    with open(args.out, "w", newline="") as out:
        writer = csv.writer(out, delimiter="\t")
        writer.writerow(["sha", "kind", "cls", "le", "machine", "etype", "eflags", "head"])
        for row in rows:
            with open(os.path.join(args.fw1_dir, row["sha"]), "rb") as f:
                head = f.read(HEAD_SIZE)
            writer.writerow([row["sha"], *header_fields(head), head[:64].hex()])


if __name__ == "__main__":
    main()
