#!/usr/bin/env python3
"""Cross-tabulate libmagic descriptions against zrax results for raw-format files."""
import csv, collections, re
rows = {r["sha"]: r for r in csv.DictReader(open("all.tsv"), delimiter="\t")}
mg = {}
for line in open("magic.txt", encoding="utf-8", errors="replace"):
    s, _, m = line.partition("|")
    mg[s.strip()] = m.strip()
c = collections.Counter(); ex = collections.defaultdict(list)
for s, r in rows.items():
    if r["format"] != "raw":
        continue
    m = mg.get(s, "")
    k = re.sub(r"[,(].*", "", m)[:60]
    c[k] += 1
    ex[k].append((r["isa"], r["conf"][:4], r["name"][:45]))
for k, n in c.most_common(150):
    print(n, "|", k, "|", ex[k][:3])
