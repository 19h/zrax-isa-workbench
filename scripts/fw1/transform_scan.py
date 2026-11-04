#!/usr/bin/env python3
"""Window statistics of a file under one of zrax's transform readings.

Applies the transform (same definitions as src/transform.rs CANDIDATES),
writes the transformed bytes next to the report, runs `scan_debug` on them,
and prints how many windows are code, per class, against all windows.

Usage: transform_scan.py SCAN_DEBUG FILE {none,swap16,swap32,il2,il2r,il4,il4r} OUT_DIR
"""
import argparse
import collections
import os
import subprocess


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
    "none": lambda d: d,
    "swap16": lambda d: swap(d, 2),
    "swap32": lambda d: swap(d, 4),
    "il2": lambda d: interleave(d, 2, False),
    "il2r": lambda d: interleave(d, 2, True),
    "il4": lambda d: interleave(d, 4, False),
    "il4r": lambda d: interleave(d, 4, True),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scan_debug")
    ap.add_argument("file")
    ap.add_argument("transform", choices=TRANSFORMS)
    ap.add_argument("out_dir")
    a = ap.parse_args()
    data = TRANSFORMS[a.transform](open(a.file, "rb").read())
    out = os.path.join(a.out_dir, os.path.basename(a.file) + "." + a.transform)
    with open(out, "wb") as f:
        f.write(data)
    lines = subprocess.run([a.scan_debug, out], capture_output=True, text=True).stdout.splitlines()
    kinds = collections.Counter()
    for line in lines:
        fields = line.split()
        if len(fields) < 3 or not all(c in "0123456789abcdef" for c in fields[0]):
            continue
        kinds[fields[3] if fields[2] == "CODE" else fields[2].split("(")[0]] += 1
    total = sum(kinds.values())
    code = {k: v for k, v in kinds.items() if k not in ("data", "padding", "ambiguous")}
    print(f"{a.transform:7} windows={total} code={sum(code.values())} "
          f"({100 * sum(code.values()) / max(total, 1):.1f}%) by class={dict(sorted(code.items(), key=lambda kv: -kv[1])[:4])}")


if __name__ == "__main__":
    main()
