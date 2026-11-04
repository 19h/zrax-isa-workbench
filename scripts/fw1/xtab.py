#!/usr/bin/env python3
"""Cross-tabulate libmagic descriptions against zrax results for
raw-classified files: one line per description (count, description, three
examples of ISA, confidence and name).

`magic.txt` holds `file -N --separator '|'` output for the fw1 files.

Usage (from the directory holding all.tsv and magic.txt): xtab.py [--top N]
"""
import argparse
import collections
import csv
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--top", type=int, default=150, help="descriptions to print")
    args = parser.parse_args()
    with open("all.tsv") as f:
        rows = {r["sha"]: r for r in csv.DictReader(f, delimiter="\t")}
    descriptions = {}
    with open("magic.txt", encoding="utf-8", errors="replace") as f:
        for line in f:
            sha, _, description = line.partition("|")
            descriptions[sha.strip()] = description.strip()
    counts = collections.Counter()
    examples = collections.defaultdict(list)
    for sha, row in rows.items():
        if row["format"] != "raw":
            continue
        kind = re.sub(r"[,(].*", "", descriptions.get(sha, ""))[:60]
        counts[kind] += 1
        examples[kind].append((row["isa"], row["conf"][:4], row["name"][:45]))
    for kind, count in counts.most_common(args.top):
        print(count, "|", kind, "|", examples[kind][:3])


if __name__ == "__main__":
    main()
