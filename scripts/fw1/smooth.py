#!/usr/bin/env python3
"""Score each raw-classified file for 8-bit PCM-like smoothness.

smooth = fraction of non-constant adjacent signed-byte pairs with |delta| <= 6,
measured over up to 256 KiB sampled from the file (padding runs excluded).
"""
import csv, os, sys
root = sys.argv[1]
rows = list(csv.DictReader(open("all.tsv"), delimiter="\t"))
w = csv.writer(open("smooth.tsv", "w", newline=""), delimiter="\t")
w.writerow(["sha", "name", "isa", "conf", "size", "smooth", "pairs"])
for r in rows:
    if r["format"] != "raw":
        continue
    p = os.path.join(root, r["sha"])
    size = int(r["size"])
    with open(p, "rb") as f:
        chunks = []
        step = max(size // 16, 16384)
        for off in range(0, size, step):
            f.seek(off); chunks.append(f.read(16384))
    small = total = 0
    for d in chunks:
        s = [(b ^ 0x80) - 128 for b in d]
        for a, b in zip(s, s[1:]):
            if a == b:
                continue
            total += 1
            if abs(a - b) <= 6:
                small += 1
    w.writerow([r["sha"], r["name"], r["isa"], r["conf"], size, f"{small/total:.3f}" if total else "", total])
