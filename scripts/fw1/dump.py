#!/usr/bin/env python3
"""Flatten fw1 sidecar JSON into a TSV: one row per binary."""
import json, glob, os, sys, csv
root = sys.argv[1]
out = csv.writer(open(sys.argv[2], "w", newline=""), delimiter="\t")
out.writerow(["sha","size","name","format","fvariant","isa","variant","bits","endian","conf","source","nslices","slice_isas"])
for p in sorted(glob.glob(os.path.join(root, "*.json"))):
    d = json.load(open(p))
    z = d.get("zrax") or {}
    sl = z.get("slices") or []
    out.writerow([d["sha256"], d.get("size"), (d.get("original_name") or "").replace("\t"," "), z.get("format"), z.get("format_variant"),
                  z.get("isa"), z.get("variant"), z.get("bitwidth"), z.get("endianness"), z.get("confidence"), z.get("source"),
                  len(sl), ",".join(sorted(set(str(s.get("isa")) for s in sl)))])
