#!/usr/bin/env python3
"""Read header fields of every fw1 binary: ELF/PE/Mach-O identity plus first 64 bytes hex.

Usage: heads.py FW_DIR ALL_TSV OUT_TSV
"""
import csv, os, struct, sys
root, tsv, outp = sys.argv[1:4]
rows = list(csv.DictReader(open(tsv), delimiter="\t"))
w = csv.writer(open(outp, "w", newline=""), delimiter="\t")
w.writerow(["sha", "kind", "cls", "le", "machine", "etype", "eflags", "head"])
for r in rows:
    p = os.path.join(root, r["sha"])
    with open(p, "rb") as f:
        h = f.read(4096)
    kind = cls = le = mach = et = fl = ""
    if h[:4] == b"\x7fELF" and len(h) >= 0x34:
        cls = h[4]; le = h[5] == 1
        e = "<" if le else ">"
        et, mach = struct.unpack(e + "HH", h[16:20])
        fl = struct.unpack(e + "I", h[0x30:0x34] if cls == 2 and len(h) >= 0x34 else h[0x24:0x28])[0]
        kind = "elf"
    elif h[:2] == b"MZ" and len(h) >= 0x40:
        lf = struct.unpack("<I", h[0x3C:0x40])[0]
        if lf + 6 <= len(h) and h[lf:lf+4] == b"PE\0\0":
            kind = "pe"; mach = struct.unpack("<H", h[lf+4:lf+6])[0]
        else:
            kind = "mz"
    elif h[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        kind = "macho"
        e = "<" if h[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"
        mach = struct.unpack(e + "I", h[4:8])[0]
    elif h[:4] == b"\xca\xfe\xba\xbe":
        kind = "fat"
    w.writerow([r["sha"], kind, cls, le, mach, et, fl, h[:64].hex()])
