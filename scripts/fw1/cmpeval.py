#!/usr/bin/env python3
"""Compare two eval.rs outputs per class at one input size. Usage: cmpeval.py A B [size] [min_delta]"""
import sys, re
def load(p, size):
    out = {}
    for line in open(p):
        f = line.split()
        if len(f) >= 7 and f[1] == size and f[3].endswith("%"):
            out[f[0]] = (int(f[2]), float(f[3][:-1]), float(f[4][:-1]), float(f[5][:-1]), " ".join(f[7:])[:90])
    return out
a, b = load(sys.argv[1], sys.argv[3] if len(sys.argv) > 3 else "file"), load(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "file")
md = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
for k in sorted(set(a) | set(b)):
    x, y = a.get(k), b.get(k)
    if not x or not y: continue
    neg = k.startswith("neg_")
    dx = (y[3] - x[3]) if neg else (y[2] - x[2])
    if abs(dx) > md or (not neg and y[2] < 90) or (neg and y[3] > 2):
        metric = "wrong" if neg else "exact"
        print(f"{k:12} n={y[0]:5} {metric} {x[3] if neg else x[2]:6.1f} -> {y[3] if neg else y[2]:6.1f}   now: {y[4]}")
