#!/usr/bin/env python3
"""Per-file entropy profile for raw-classified files.

For 4 KiB windows sampled across each file (up to 256 windows, padding windows skipped),
record the fraction of windows with Shannon entropy >= 7.9 bits/byte (compressed/encrypted).
"""
import csv, math, os, sys, collections
root = sys.argv[1]
rows = [r for r in csv.DictReader(open("all.tsv"), delimiter="\t") if r["format"] == "raw"]
w = csv.writer(open("entropy.tsv", "w", newline=""), delimiter="\t")
w.writerow(["sha", "name", "isa", "conf", "size", "hi_frac", "windows"])
for r in rows:
    size = int(r["size"])
    n = max(1, size // 4096)
    idx = range(n) if n <= 256 else [i * n // 256 for i in range(256)]
    hi = tot = 0
    with open(os.path.join(root, r["sha"]), "rb") as f:
        for i in idx:
            f.seek(i * 4096); b = f.read(4096)
            if len(b) < 1024:
                continue
            c = collections.Counter(b)
            if c.most_common(1)[0][1] > 0.9 * len(b):
                continue
            e = -sum(v / len(b) * math.log2(v / len(b)) for v in c.values())
            tot += 1; hi += e >= 7.9
    w.writerow([r["sha"], r["name"], r["isa"], r["conf"], size, f"{hi/tot:.3f}" if tot else "", tot])
