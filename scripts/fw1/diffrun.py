#!/usr/bin/env python3
"""Diff two runall.sh outputs; tally ISA transitions and score them against findings.tsv.

Usage: diffrun.py OLD.jsonl NEW.jsonl
"""
import csv, json, sys, collections
def load(p):
    out = {}
    for line in open(p):
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        out[d["file"]] = d
    return out
old, new = load(sys.argv[1]), load(sys.argv[2])
names = {r["sha"]: r["name"] for r in csv.DictReader(open("all.tsv"), delimiter="\t")}
flags = collections.defaultdict(set)
for r in csv.DictReader(open("findings.tsv"), delimiter="\t"):
    flags[r["sha"]].add(r["category"])
def key(d):
    return (d.get("format"), d.get("isa"), d.get("variant") or "", d.get("bitwidth"))
changed = [s for s in old if s in new and key(old[s]) != key(new[s])]
print("files", len(old), len(new), "changed", len(changed), "errors old/new", sum("error" in d for d in old.values()), sum("error" in d for d in new.values()))
trans = collections.Counter()
ex = collections.defaultdict(list)
for s in changed:
    o, n = old[s], new[s]
    t = (f"{o.get('isa')}/{o.get('variant') or ''}", f"{n.get('isa')}/{n.get('variant') or ''}", ",".join(sorted(flags[s])) or "-")
    trans[t] += 1
    ex[t].append(names.get(s, s)[:38])
for t, c in trans.most_common(70):
    print(f"{c:5}  {t[0]:22} -> {t[1]:22} [{t[2]}]  e.g. {ex[t][:3]}")
cat_total = collections.Counter(c for s in flags for c in flags[s])
cat_changed = collections.Counter(c for s in changed for c in flags[s])
print("\nflagged categories: changed/total")
for c, n in cat_total.most_common():
    print(f"  {c:26} {cat_changed[c]:5}/{n}")
