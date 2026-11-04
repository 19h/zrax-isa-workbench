#!/usr/bin/env python3
"""Match fw1 files to MAME ROM definitions by SHA-1.

Reads the region index written by mame_regions.py and all.tsv (from the
current directory), hashes every fw1 file with SHA-1, and writes
mame_match.tsv (no header), one row per fw1 file that MAME lists:

    sha256, sha1, kind, region tag, set, ROM name, load macro, isa, confidence, name

`kind` is the region kind of the first listing, or `mixed` when MAME loads
the same dump into regions of different kinds. `isa` and `confidence` are the
original zrax result from all.tsv. fw1_corpus.py labels `graphics` and
`sound` matches as non-code; findings.py flags those that got an ISA.

Usage (from the directory holding all.tsv): mame_match.py FW1_DIR MAME_REGIONS.tsv
"""
import argparse
import collections
import csv
import hashlib
import os


def sha1_of(path):
    digest = hashlib.sha1()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("fw1_dir")
    parser.add_argument("regions", help="mame_regions.py output")
    args = parser.parse_args()
    listings = collections.defaultdict(list)
    with open(args.regions) as f:
        for line in f:
            fields = line.rstrip("\n").split("\t")
            listings[fields[0]].append(fields)
    with open("all.tsv") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    matched = 0
    with open("mame_match.tsv", "w") as out:
        for row in rows:
            sha1 = sha1_of(os.path.join(args.fw1_dir, row["sha"]))
            entries = listings.get(sha1)
            if not entries:
                continue
            kinds = {e[1] for e in entries}
            kind = kinds.pop() if len(kinds) == 1 else "mixed"
            first = entries[0]
            out.write("\t".join((row["sha"], sha1, kind, first[2], first[3], first[4], first[5],
                                 row["isa"], row["conf"], row["name"])) + "\n")
            matched += 1
    print(matched)


if __name__ == "__main__":
    main()
