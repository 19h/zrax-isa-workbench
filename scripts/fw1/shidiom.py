#!/usr/bin/env python3
"""Per-MiB density of SuperH idioms at halfword alignment, in both byte
orders: `rts` (`000B`), `nop` (`0009`) and `sts.l pr,@-r15` (`4F22`).

Usage: shidiom.py LABEL FILE...
"""
import argparse
import importlib.util
import os

# Loaded by path: `python3 -I` keeps the script directory off sys.path.
_spec = importlib.util.spec_from_file_location("idioms", os.path.join(os.path.dirname(os.path.abspath(__file__)), "idioms.py"))
_idioms = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_idioms)
aligned_count = _idioms.aligned_count

IDIOMS = (0x000B, 0x0009, 0x4F22)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("label")
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()
    for path in args.files:
        with open(path, "rb") as f:
            data = f.read()
        mib = len(data) / 2**20
        little = [aligned_count(data, v.to_bytes(2, "little")) / mib for v in IDIOMS]
        big = [aligned_count(data, v.to_bytes(2, "big")) / mib for v in IDIOMS]
        print(f"{args.label:9} LE rts/nop/stspr={little[0]:6.0f}/{little[1]:6.0f}/{little[2]:6.0f}  "
              f"BE={big[0]:6.0f}/{big[1]:6.0f}/{big[2]:6.0f}")


if __name__ == "__main__":
    main()
