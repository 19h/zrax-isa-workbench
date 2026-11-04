#!/usr/bin/env python3
"""Tabulate the structure zrax reports for files detected as weak TI layouts.

For each listed file, runs `zrax -f json` and prints the layout variant, ISA,
section count, file size, the largest load section as a share of the file,
and the structural note.

Usage: tisurvey.py ZRAX FW1_DIR LIST.tsv   (LIST: sha<TAB>name per line)
"""
import argparse
import json
import subprocess


def survey(zrax, path):
    out = subprocess.run([zrax, "-f", "json", path], capture_output=True, text=True).stdout
    if not out.strip():
        return None
    d = json.loads(out)
    meta = {m["label"]: m["value"] for m in d["metadata"]}
    sections = [m["value"] for m in d["metadata"] if m["label"].startswith("Load section")]
    size = int(meta.get("Container size (B)", "0"))
    largest = max((int(s.split(";")[2].split()[0]) for s in sections), default=0)
    note = next((n["message"] for n in d["notes"] if "boot;" in n["message"] or "Structural" in n["message"]), "")
    return d["format_variant"], d["isa"], len(sections), size, 100 * largest / max(size, 1), note


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("zrax")
    ap.add_argument("fw1_dir")
    ap.add_argument("list")
    a = ap.parse_args()
    for line in open(a.list):
        sha, name = line.rstrip("\n").split("\t")
        row = survey(a.zrax, f"{a.fw1_dir}/{sha}")
        if row is None:
            print(f"{'-':24} {'-':14} {name}")
            continue
        variant, isa, nsec, size, largest, note = row
        print(f"{(variant or '')[:24]:24} {str(isa)[:14]:14} nsec={nsec:3} size={size:8} "
              f"largest={largest:5.1f}% {note[:30]:30} {name[:44]}")


if __name__ == "__main__":
    main()
