#!/usr/bin/env python3
"""Augment the train-split negatives of corpora with the byte orders that
the classifier's transform search tries (src/transform.rs CANDIDATES):
16/32-bit swaps and 2/4-lane interleaves, each lane order.

Output: build_corpus.py layout, one sample per (input sample, transform),
source `aug-<transform>`, same class and group, split `train`.

Usage: aug_neg.py [--sources A,B] OUT CORPUS...   (--sources: only these corpus sources)
"""
import argparse
import hashlib
import json
import os

MIN_SAMPLE = 1024


def swap(data, width):
    end = len(data) - len(data) % width
    return b"".join(data[i:i + width][::-1] for i in range(0, end, width))


def interleave(data, lanes, reversed_lanes):
    size = len(data) // lanes
    parts = [data[i * size:(i + 1) * size] for i in range(lanes)]
    if reversed_lanes:
        parts.reverse()
    return bytes(b for i in range(size) for b in (part[i] for part in parts))


TRANSFORMS = {
    "swap16": lambda data: swap(data, 2),
    "swap32": lambda data: swap(data, 4),
    "il2": lambda data: interleave(data, 2, False),
    "il2r": lambda data: interleave(data, 2, True),
    "il4": lambda data: interleave(data, 4, False),
    "il4r": lambda data: interleave(data, 4, True),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out")
    parser.add_argument("corpora", nargs="+")
    parser.add_argument("--sources", default=None, help="comma-separated corpus sources to augment (default: all)")
    args = parser.parse_args()
    sources = set(args.sources.split(",")) if args.sources else None
    os.makedirs(os.path.join(args.out, "samples"), exist_ok=True)
    written = 0
    with open(os.path.join(args.out, "manifest.jsonl"), "w") as manifest:
        for corpus in args.corpora:
            with open(os.path.join(corpus, "manifest.jsonl")) as f:
                rows = [json.loads(line) for line in f]
            for row in rows:
                if not row["class"].startswith("neg_") or row["split"] != "train":
                    continue
                if sources is not None and row["source"] not in sources:
                    continue
                with open(os.path.join(corpus, "samples", row["class"], row["id"] + ".bin"), "rb") as f:
                    data = f.read()
                if len(data) < MIN_SAMPLE:
                    continue
                for name, transform in TRANSFORMS.items():
                    transformed = transform(data)
                    sample_id = hashlib.sha1(transformed).hexdigest()[:16]
                    directory = os.path.join(args.out, "samples", row["class"])
                    os.makedirs(directory, exist_ok=True)
                    with open(os.path.join(directory, sample_id + ".bin"), "wb") as f:
                        f.write(transformed)
                    manifest.write(json.dumps(dict(row, id=sample_id, source="aug-" + name, size=len(transformed))) + "\n")
                    written += 1
    print(written, "augmented samples")


if __name__ == "__main__":
    main()
