#!/usr/bin/env python3
"""Per-MiB density of TriCore and ARCompact return idioms, at halfword
alignment: TriCore `ret16` (bytes `00 90`), ARCompact `j_s [blink]`
(`0x7EE0`, bytes `e0 7e`) and `nop_s` (`0x78E0`, bytes `e0 78`).

Usage: idioms.py LABEL FILE...
"""
import argparse

TRICORE_RET16 = bytes([0x00, 0x90])
ARC_J_S_BLINK = bytes([0xE0, 0x7E])
ARC_NOP_S = bytes([0xE0, 0x78])


def aligned_count(data, pattern):
    """Occurrences of pattern at even offsets."""
    count = 0
    at = data.find(pattern)
    while at >= 0:
        count += at % 2 == 0
        at = data.find(pattern, at + 1)
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("label")
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()
    for path in args.files:
        with open(path, "rb") as f:
            data = f.read()
        mib = max(len(data) / 2**20, 1 / 16)
        print(f"{args.label:10} ret16={aligned_count(data, TRICORE_RET16) / mib:8.0f} "
              f"arc_j_s_blink={aligned_count(data, ARC_J_S_BLINK) / mib:8.0f} "
              f"arc_nop_s={aligned_count(data, ARC_NOP_S) / mib:8.0f} size={len(data)}")


if __name__ == "__main__":
    main()
