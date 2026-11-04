#!/usr/bin/env python3
"""Compare two `examples/eval.rs` reports per class at one input size.

For code classes the exact share is compared, for `neg_*` classes the
wrong (false accept) share. A class is printed when it changed by more than
MIN_DELTA points, when code is below 90% exact, or when a negative class
is above 2% wrong.

Usage: cmpeval.py A.txt B.txt [--size file|128B|512B|2048B] [--min-delta N]
"""
import argparse


def load(path, size):
    """class -> (n, correct %, exact %, wrong %, confusions) at one input size."""
    out = {}
    with open(path) as f:
        for line in f:
            fields = line.split()
            if len(fields) >= 7 and fields[1] == size and fields[3].endswith("%"):
                n = int(fields[2])
                correct, exact, wrong = (float(fields[i][:-1]) for i in (3, 4, 5))
                out[fields[0]] = (n, correct, exact, wrong, " ".join(fields[7:])[:90])
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("a")
    parser.add_argument("b")
    parser.add_argument("size", nargs="?", default="file")
    parser.add_argument("min_delta", nargs="?", type=float, default=0.0)
    args = parser.parse_args()
    before, after = load(args.a, args.size), load(args.b, args.size)
    for cls in sorted(set(before) | set(after)):
        old, new = before.get(cls), after.get(cls)
        if not old or not new:
            continue
        negative = cls.startswith("neg_")
        metric = 3 if negative else 2
        delta = new[metric] - old[metric]
        if abs(delta) > args.min_delta or (not negative and new[2] < 90) or (negative and new[3] > 2):
            label = "wrong" if negative else "exact"
            print(f"{cls:12} n={new[0]:5} {label} {old[metric]:6.1f} -> {new[metric]:6.1f}   now: {new[4]}")


if __name__ == "__main__":
    main()
