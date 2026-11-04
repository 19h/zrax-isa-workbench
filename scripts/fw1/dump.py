#!/usr/bin/env python3
"""Flatten fw1 sidecar JSON into a TSV, one row per binary.

Each `<sha256>.json` sidecar holds the original file name and the zrax
result recorded when the file was received. Columns: sha, size, name,
format, fvariant, isa, variant, bits, endian, conf, source, nslices,
slice_isas.

Usage: dump.py FW1_DIR OUT.tsv
"""
import argparse
import csv
import glob
import json
import os

COLUMNS = ["sha", "size", "name", "format", "fvariant", "isa", "variant", "bits", "endian", "conf",
           "source", "nslices", "slice_isas"]


def sidecar_row(sidecar):
    """The TSV row of one parsed sidecar."""
    result = sidecar.get("zrax") or {}
    slices = result.get("slices") or []
    name = (sidecar.get("original_name") or "").replace("\t", " ")
    slice_isas = ",".join(sorted({str(s.get("isa")) for s in slices}))
    return [sidecar["sha256"], sidecar.get("size"), name, result.get("format"), result.get("format_variant"),
            result.get("isa"), result.get("variant"), result.get("bitwidth"), result.get("endianness"),
            result.get("confidence"), result.get("source"), len(slices), slice_isas]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("fw1_dir", help="directory of fw1 binaries and sidecars")
    parser.add_argument("out", help="TSV to write")
    args = parser.parse_args()
    with open(args.out, "w", newline="") as out:
        writer = csv.writer(out, delimiter="\t")
        writer.writerow(COLUMNS)
        for path in sorted(glob.glob(os.path.join(args.fw1_dir, "*.json"))):
            with open(path) as f:
                writer.writerow(sidecar_row(json.load(f)))


if __name__ == "__main__":
    main()
