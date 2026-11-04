#!/usr/bin/env python3
"""Per-file entropy profile of raw-classified fw1 files.

For 4 KiB windows sampled across each file (at most 256, padding windows
skipped), records the share of windows with Shannon entropy of at least 7.9
bits per byte (compressed or encrypted). Writes `entropy.tsv` in the
current directory.

Usage (from the directory holding all.tsv): entropy.py FW1_DIR
"""
import argparse
import collections
import csv
import math
import os

WINDOW = 4096
MAX_WINDOWS = 256
HIGH_ENTROPY = 7.9
PADDING_SHARE = 0.9


def entropy(block):
    counts = collections.Counter(block)
    return -sum(n / len(block) * math.log2(n / len(block)) for n in counts.values())


def high_entropy_share(path, size):
    """(share of high-entropy windows or None, windows measured)."""
    count = max(1, size // WINDOW)
    indices = range(count) if count <= MAX_WINDOWS else [i * count // MAX_WINDOWS for i in range(MAX_WINDOWS)]
    high = measured = 0
    with open(path, "rb") as f:
        for index in indices:
            f.seek(index * WINDOW)
            block = f.read(WINDOW)
            if len(block) < 1024:
                continue
            if collections.Counter(block).most_common(1)[0][1] > PADDING_SHARE * len(block):
                continue
            measured += 1
            high += entropy(block) >= HIGH_ENTROPY
    return (high / measured if measured else None), measured


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("fw1_dir")
    args = parser.parse_args()
    with open("all.tsv") as f:
        rows = [r for r in csv.DictReader(f, delimiter="\t") if r["format"] == "raw"]
    with open("entropy.tsv", "w", newline="") as out:
        writer = csv.writer(out, delimiter="\t")
        writer.writerow(["sha", "name", "isa", "conf", "size", "hi_frac", "windows"])
        for row in rows:
            size = int(row["size"])
            share, measured = high_entropy_share(os.path.join(args.fw1_dir, row["sha"]), size)
            writer.writerow([row["sha"], row["name"], row["isa"], row["conf"], size,
                             f"{share:.3f}" if share is not None else "", measured])


if __name__ == "__main__":
    main()
