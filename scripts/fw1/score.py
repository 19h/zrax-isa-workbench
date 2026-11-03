#!/usr/bin/env python3
"""Score CLI runs (runall.sh JSONL) against golden.tsv, per label and split.

Usage: score.py SPLIT RUN.jsonl...
"""
import csv, json, sys, collections
split = sys.argv[1]
gold = [r for r in csv.DictReader(open("golden.tsv"), delimiter="\t") if r["split"] == split]
def outcome(g, d):
    isa = d.get("isa") if d else None
    no_isa = isa in (None, "<rejected>") or str(isa).startswith("unknown")
    if g["expect"] == "none":
        return "ok" if no_isa else "wrong"
    if no_isa:
        return "rejected"
    if str(isa).replace("_", "") != g["expect"].replace("_", ""):
        return "wrong"
    if g["expect"] == "z80" and d.get("variant") == "ez80":
        return "variant"
    return "ok"
for run in sys.argv[2:]:
    res = {}
    for line in open(run):
        d = json.loads(line)
        res[d.get("file")] = d
    t = collections.defaultdict(collections.Counter)
    for g in gold:
        if g["sha"] in res:
            t[g["label"]][outcome(g, res[g["sha"]])] += 1
    tot = sum(t.values(), collections.Counter())
    print(f"== {run}: {split} files={sum(tot.values())} ok={tot['ok']/max(1,sum(tot.values())):.1%} {dict(tot)}")
    for label in sorted(t):
        n = sum(t[label].values())
        print(f"   {label:16} n={n:4} ok={t[label]['ok']/n:6.1%} {dict(t[label])}")
