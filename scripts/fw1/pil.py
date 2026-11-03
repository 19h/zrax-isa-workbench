#!/usr/bin/env python3
"""Match Qualcomm PIL split segments (.bNN) to program headers from .mdt/.b00 files.

Key: (base name, segment index, p_filesz). Output: one TSV row per matched raw segment.
"""
import csv, os, re, struct, sys, collections
root = sys.argv[1]
rows = list(csv.DictReader(open("all.tsv"), delimiter="\t"))
EM = {164: "hexagon", 40: "arm", 183: "a_arch64", 94: "xtensa", 243: "riscv", 195: "arc_compact2", 8: "mips"}
PT_LOAD = 1
NAME = re.compile(r"^(?P<base>.+?)\.(?P<ext>mdt|b(?P<idx>\d\d))(_\d+)?$", re.I)
index = collections.defaultdict(set)
for r in rows:
    m = NAME.match(r["name"])
    if not m or m.group("ext").lower() not in ("mdt", "b00"):
        continue
    d = open(os.path.join(root, r["sha"]), "rb").read(1 << 16)
    if d[:4] != b"\x7fELF":
        continue
    c64 = d[4] == 2; e = "<" if d[5] == 1 else ">"
    mach = struct.unpack(e + "H", d[0x12:0x14])[0]
    if c64:
        phoff = struct.unpack(e + "Q", d[0x20:0x28])[0]; phentsize, phnum = struct.unpack(e + "HH", d[0x36:0x3A])
    else:
        phoff = struct.unpack(e + "I", d[0x1C:0x20])[0]; phentsize, phnum = struct.unpack(e + "HH", d[0x2A:0x2E])
    for i in range(phnum):
        ph = d[phoff + i * phentsize: phoff + (i + 1) * phentsize]
        if len(ph) < phentsize:
            break
        if c64:
            ptype, pflags, off, va, pa, filesz, memsz, al = struct.unpack(e + "IIQQQQQQ", ph[:56])
        else:
            ptype, off, va, pa, filesz, memsz, pflags, al = struct.unpack(e + "8I", ph[:32])
        if filesz:
            # bits 24-26 of p_flags are the Qualcomm segment type; 2 = hash segment
            index[(m.group("base").lower(), i, filesz)].add((ptype, pflags, EM.get(mach, str(mach))))
w = csv.writer(open("pil_match.tsv", "w", newline=""), delimiter="\t")
w.writerow(["name", "idx", "size", "ptype", "pflags", "exec", "qc_type", "elf_isa", "zrax_fmt", "zrax_isa", "conf"])
n = 0
for r in rows:
    m = NAME.match(r["name"])
    if not m or not m.group("idx") or m.group("idx") == "00":
        continue
    hits = index.get((m.group("base").lower(), int(m.group("idx")), int(r["size"])))
    if not hits or len(hits) != 1:
        continue
    ptype, pflags, isa = next(iter(hits))
    w.writerow([r["name"], m.group("idx"), r["size"], ptype, hex(pflags), bool(pflags & 1), (pflags >> 24) & 7, isa,
                r["format"], r["isa"], r["conf"]])
    n += 1
print("matched", n, "index keys", len(index))
