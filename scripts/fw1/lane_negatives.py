#!/usr/bin/env python3
"""Byte lanes of code samples, as a non-code corpus class (`neg_lanes`).

A ROM on a 16- or 32-bit bus is often dumped as one file per byte lane
(MAME's ROM_LOAD16_BYTE, ROM_LOAD32_BYTE): each file holds every second or
fourth byte of the program and no whole instruction. A lane of 68000 code
still carries the opcode bytes' statistics, and the code model read a
single lane as 68000 (fw1, 2026-11-04: `cpu30uu-ubr-v2.1.rom` at 0.86, one
of four lanes of a 68030 board ROM whose four lanes interleaved read as
68000 at 0.99). This
script splits the code samples of the given classes into their 2 and 4 byte
lanes and writes them as `neg_lanes` samples, one group per source sample,
so the lanes of a test sample stay out of training.

Output layout: build_corpus.py's (OUT/samples/neg_lanes/<id>.bin and
OUT/manifest.jsonl); the split follows the source sample's.

Sources are taken in sample-id order (a deterministic shuffle) until the
lanes reach --max-bytes, so the class stays the size of a data class rather
than of the code classes it is cut from.

Usage: lane_negatives.py [--max-bytes N] CORPUS OUT CLASS...
"""
import argparse
import hashlib
import json
import os

LANE_COUNTS = (2, 4)
MIN_LANE_BYTES = 2048
DEFAULT_MAX_BYTES = 2 * 1024 * 1024


def lanes(data, count):
    """The `count` byte lanes of data: lane i holds bytes i, i + count, ..."""
    return [data[i::count] for i in range(count)]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("corpus")
    parser.add_argument("out")
    parser.add_argument("classes", nargs="+")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    args = parser.parse_args()
    samples = os.path.join(args.out, "samples", "neg_lanes")
    os.makedirs(samples, exist_ok=True)
    seen = set()
    rows = []
    with open(os.path.join(args.corpus, "manifest.jsonl")) as f:
        sources = sorted((json.loads(line) for line in f), key=lambda r: r["id"])
    total = 0
    for source in sources:
        if source["class"] not in args.classes:
            continue
        if total >= args.max_bytes:
            break
        path = os.path.join(args.corpus, "samples", source["class"], source["id"] + ".bin")
        with open(path, "rb") as f:
            data = f.read()
        for count in LANE_COUNTS:
            for lane in lanes(data, count):
                digest = hashlib.sha1(lane).hexdigest()
                if len(lane) < MIN_LANE_BYTES or digest in seen:
                    continue
                seen.add(digest)
                sample_id = digest[:16]
                with open(os.path.join(samples, sample_id + ".bin"), "wb") as out:
                    out.write(lane)
                rows.append({"id": sample_id, "class": "neg_lanes", "group": "lanes:" + source["group"],
                             "source": "lanes-" + source["class"], "size": len(lane), "split": source["split"]})
                total += len(lane)
    with open(os.path.join(args.out, "manifest.jsonl"), "w") as manifest:
        for row in rows:
            manifest.write(json.dumps(row) + "\n")
    print(len(rows), sum(r["size"] for r in rows))


if __name__ == "__main__":
    main()
