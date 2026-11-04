#!/usr/bin/env python3
"""Turn a corpus into a held-out test set: keep only the rows of one source
whose sample IDs are not in the training corpus, all marked split "test".

Built for the ISAdetect held-out set: `build_corpus.py --isadetect-skip 400
--isadetect-per-arch 150` selects ISAdetect files 400-549 of each
architecture, and this script drops everything else from that corpus
(armgen objects, raw dumps, and any sample whose bytes are already in the
base corpus, since sample IDs are content hashes).

The corpus manifest (CORPUS/manifest.jsonl) is rewritten in place; the
sample files of dropped rows stay on disk, unreferenced.

Usage: holdout.py CORPUS BASE [--source isadetect]
"""
import argparse
import collections
import json
import os


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("corpus", help="corpus to rewrite (build_corpus.py layout)")
    parser.add_argument("base", help="training corpus whose sample IDs must not reappear")
    parser.add_argument("--source", default="isadetect", help="manifest source to keep (default: isadetect)")
    args = parser.parse_args()

    with open(os.path.join(args.base, "manifest.jsonl")) as f:
        base_ids = {json.loads(line)["id"] for line in f}
    manifest = os.path.join(args.corpus, "manifest.jsonl")
    with open(manifest) as f:
        rows = [json.loads(line) for line in f]
    kept = [dict(r, split="test") for r in rows if r["source"] == args.source and r["id"] not in base_ids]
    with open(manifest, "w") as f:
        for row in kept:
            f.write(json.dumps(row) + "\n")
    per_class = collections.Counter(r["class"] for r in kept)
    print(f"{len(rows)} -> {len(kept)} rows; {len(per_class)} classes")


if __name__ == "__main__":
    main()
