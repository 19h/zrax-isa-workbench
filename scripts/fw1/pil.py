#!/usr/bin/env python3
"""Match Qualcomm PIL split segments (`.bNN`) to the program headers of
their `.mdt`/`.b00` ELF headers.

A segment matches the header entry with the same base name, segment index
and `p_filesz`. Bits 24-26 of `p_flags` are the Qualcomm segment type (2 is
the hash segment). Writes `pil_match.tsv` in the current directory, one row
per matched raw segment.

Usage (from the directory holding all.tsv): pil.py FW1_DIR
"""
import argparse
import collections
import csv
import os
import re
import struct

EM_NAMES = {164: "hexagon", 40: "arm", 183: "a_arch64", 94: "xtensa", 243: "riscv", 195: "arc_compact2",
            8: "mips"}
SEGMENT_NAME = re.compile(r"^(?P<base>.+?)\.(?P<ext>mdt|b(?P<idx>\d\d))(_\d+)?$", re.I)
HEADER_READ = 1 << 16


def program_headers(data):
    """(e_machine, [(p_type, p_flags, p_filesz)]) of an ELF header, or None."""
    if data[:4] != b"\x7fELF":
        return None
    is_64 = data[4] == 2
    order = "<" if data[5] == 1 else ">"
    machine = struct.unpack(order + "H", data[0x12:0x14])[0]
    if is_64:
        phoff = struct.unpack(order + "Q", data[0x20:0x28])[0]
        phentsize, phnum = struct.unpack(order + "HH", data[0x36:0x3A])
    else:
        phoff = struct.unpack(order + "I", data[0x1C:0x20])[0]
        phentsize, phnum = struct.unpack(order + "HH", data[0x2A:0x2E])
    entries = []
    for i in range(phnum):
        entry = data[phoff + i * phentsize:phoff + (i + 1) * phentsize]
        if len(entry) < phentsize:
            break
        if is_64:
            p_type, p_flags, _, _, _, p_filesz = struct.unpack(order + "IIQQQQ", entry[:40])
        else:
            p_type, _, _, _, p_filesz, _, p_flags = struct.unpack(order + "7I", entry[:28])
        entries.append((p_type, p_flags, p_filesz))
    return machine, entries


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("fw1_dir")
    args = parser.parse_args()
    with open("all.tsv") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    index = collections.defaultdict(set)
    for row in rows:
        match = SEGMENT_NAME.match(row["name"])
        if not match or match.group("ext").lower() not in ("mdt", "b00"):
            continue
        with open(os.path.join(args.fw1_dir, row["sha"]), "rb") as f:
            parsed = program_headers(f.read(HEADER_READ))
        if parsed is None:
            continue
        machine, entries = parsed
        for i, (p_type, p_flags, p_filesz) in enumerate(entries):
            if p_filesz:
                key = (match.group("base").lower(), i, p_filesz)
                index[key].add((p_type, p_flags, EM_NAMES.get(machine, str(machine))))
    matched = 0
    with open("pil_match.tsv", "w", newline="") as out:
        writer = csv.writer(out, delimiter="\t")
        writer.writerow(["name", "idx", "size", "ptype", "pflags", "exec", "qc_type", "elf_isa", "zrax_fmt",
                         "zrax_isa", "conf"])
        for row in rows:
            match = SEGMENT_NAME.match(row["name"])
            if not match or not match.group("idx") or match.group("idx") == "00":
                continue
            hits = index.get((match.group("base").lower(), int(match.group("idx")), int(row["size"])))
            if not hits or len(hits) != 1:
                continue
            p_type, p_flags, isa = next(iter(hits))
            writer.writerow([row["name"], match.group("idx"), row["size"], p_type, hex(p_flags), bool(p_flags & 1),
                             (p_flags >> 24) & 7, isa, row["format"], row["isa"], row["conf"]])
            matched += 1
    print("matched", matched, "index keys", len(index))


if __name__ == "__main__":
    main()
