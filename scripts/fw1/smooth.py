#!/usr/bin/env python3
"""Score each raw-classified fw1 file for 8-bit PCM-like smoothness.

smooth is the share of adjacent signed-byte pairs (constant pairs skipped)
whose difference is at most 6, over 16 KiB chunks sampled across the file.
Known code never scores above 0.39; 8-bit PCM scores 0.6 or more. Writes
`smooth.tsv` in the current directory.

Usage (from the directory holding all.tsv): smooth.py FW1_DIR
"""
import argparse
import csv
import os

CHUNK = 16384
CHUNKS = 16
SMALL_STEP = 6


def smoothness(path, size):
    """(smooth share or None, number of non-constant pairs)."""
    small = total = 0
    with open(path, "rb") as f:
        step = max(size // CHUNKS, CHUNK)
        for offset in range(0, size, step):
            f.seek(offset)
            samples = [(b ^ 0x80) - 128 for b in f.read(CHUNK)]
            for a, b in zip(samples, samples[1:]):
                if a == b:
                    continue
                total += 1
                small += abs(a - b) <= SMALL_STEP
    return (small / total if total else None), total


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("fw1_dir")
    args = parser.parse_args()
    with open("all.tsv") as f:
        rows = [r for r in csv.DictReader(f, delimiter="\t") if r["format"] == "raw"]
    with open("smooth.tsv", "w", newline="") as out:
        writer = csv.writer(out, delimiter="\t")
        writer.writerow(["sha", "name", "isa", "conf", "size", "smooth", "pairs"])
        for row in rows:
            size = int(row["size"])
            share, pairs = smoothness(os.path.join(args.fw1_dir, row["sha"]), size)
            writer.writerow([row["sha"], row["name"], row["isa"], row["conf"], size,
                             f"{share:.3f}" if share is not None else "", pairs])


if __name__ == "__main__":
    main()
