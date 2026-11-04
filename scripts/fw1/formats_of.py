#!/usr/bin/env python3
"""Print `file<TAB>format<TAB>isa<TAB>notes` for every file, using `zrax -f json`.

Reads file paths (one per line) and runs the given zrax binary in batches.
Files zrax cannot classify are printed with format "<error>". With
`--notes TEXT`, the last column holds the notes that contain TEXT.

Usage: formats_of.py [--notes TEXT] ZRAX LIST > out.tsv
"""
import argparse
import json
import subprocess

BATCH = 64


def decode_stream(text):
    """Yield the JSON objects of a concatenated JSON stream."""
    decoder = json.JSONDecoder()
    pos = 0
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            return
        obj, pos = decoder.raw_decode(text, pos)
        yield obj


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("zrax")
    ap.add_argument("list")
    ap.add_argument("--notes", default=None, help="report notes containing this text")
    a = ap.parse_args()
    paths = [line.rstrip("\n") for line in open(a.list) if line.strip()]
    for i in range(0, len(paths), BATCH):
        batch = paths[i:i + BATCH]
        out = subprocess.run([a.zrax, "-f", "json", *batch], capture_output=True, text=True).stdout
        seen = set()
        for d in decode_stream(out):
            seen.add(d["file"])
            notes = [n["message"] for n in d.get("notes", []) if a.notes and a.notes in n["message"]]
            print(f"{d['file']}\t{d.get('format')}\t{d.get('isa')}\t{' | '.join(notes)}")
        for p in batch:
            if p not in seen:
                print(f"{p}\t<error>\t")


if __name__ == "__main__":
    main()
