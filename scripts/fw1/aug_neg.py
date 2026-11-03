#!/usr/bin/env python3
"""Augment train-split negatives with the byte orders the classifier's transform search tries.

zrax re-reads an inconclusive raw input byte-swapped and lane-interleaved
(src/transform.rs CANDIDATES) and accepts a decisive code verdict on any of
those readings, so non-code must be learned in those readings too.

Output: build_corpus.py layout, one sample per (input sample, transform),
source "aug-<transform>", same class/group, split "train".

Usage: aug_neg.py OUT CORPUS...
"""
import hashlib, json, os, sys

def swap(data, n):
    end = len(data) - len(data) % n
    return b"".join(data[i:i + n][::-1] for i in range(0, end, n))

def interleave(data, lanes, reversed_lanes):
    size = len(data) // lanes
    parts = [data[i * size:(i + 1) * size] for i in range(lanes)]
    if reversed_lanes:
        parts.reverse()
    return bytes(b for i in range(size) for b in (p[i] for p in parts))

TRANSFORMS = {
    "swap16": lambda d: swap(d, 2),
    "swap32": lambda d: swap(d, 4),
    "il2": lambda d: interleave(d, 2, False),
    "il2r": lambda d: interleave(d, 2, True),
    "il4": lambda d: interleave(d, 4, False),
    "il4r": lambda d: interleave(d, 4, True),
}

out, corpora = sys.argv[1], sys.argv[2:]
os.makedirs(os.path.join(out, "samples"), exist_ok=True)
n = 0
with open(os.path.join(out, "manifest.jsonl"), "w") as manifest:
    for corpus in corpora:
        for line in open(os.path.join(corpus, "manifest.jsonl")):
            r = json.loads(line)
            if not r["class"].startswith("neg_") or r["split"] != "train":
                continue
            data = open(os.path.join(corpus, "samples", r["class"], r["id"] + ".bin"), "rb").read()
            if len(data) < 1024:
                continue
            for name, fn in TRANSFORMS.items():
                t = fn(data)
                sid = hashlib.sha1(t).hexdigest()[:16]
                d = os.path.join(out, "samples", r["class"])
                os.makedirs(d, exist_ok=True)
                with open(os.path.join(d, sid + ".bin"), "wb") as f:
                    f.write(t)
                row = dict(r, id=sid, source="aug-" + name, size=len(t))
                manifest.write(json.dumps(row) + "\n")
                n += 1
print(n, "augmented samples")
