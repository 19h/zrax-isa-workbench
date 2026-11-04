#!/usr/bin/env python3
"""Score CLI runs (runlist.sh JSONL) against golden.tsv, per label, for one
split.

Outcomes: ok; wrong (another ISA, or an ISA for non-code); variant (right
ISA, wrong variant: eZ80 for Z80, a width other than 16 bits for real-mode
x86); rejected (no ISA for code).

Usage (from the directory holding golden.tsv): score.py [--golden TSV] SPLIT RUN.jsonl...
"""
import argparse
import collections
import csv
import json


def outcome(expected, result):
    isa = result.get("isa") if result else None
    no_isa = isa in (None, "<rejected>") or str(isa).startswith("unknown")
    if expected == "none":
        return "ok" if no_isa else "wrong"
    if no_isa:
        return "rejected"
    if expected == "x86_16":
        if isa != "x86":
            return "wrong"
        return "ok" if result.get("bitwidth") == 16 else "variant"
    # The CLI writes `aarch64` where the payload JSON writes `a_arch64`;
    # `a|b` accepts either (`sh4|sh`: SH-4 code without SH-4-only
    # instructions is reported as SuperH).
    if str(isa).replace("_", "") not in [e.replace("_", "") for e in expected.split("|")]:
        return "wrong"
    if expected == "z80" and result.get("variant") == "ez80":
        return "variant"
    return "ok"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("split")
    parser.add_argument("runs", nargs="+")
    parser.add_argument("--golden", default="golden.tsv", help="golden_files.py output (default golden.tsv)")
    args = parser.parse_args()
    with open(args.golden) as f:
        gold = [r for r in csv.DictReader(f, delimiter="\t") if r["split"] == args.split]
    for run in args.runs:
        results = {}
        with open(run) as f:
            for line in f:
                result = json.loads(line)
                results[result.get("file")] = result
        tally = collections.defaultdict(collections.Counter)
        for row in gold:
            if row["sha"] in results:
                tally[row["label"]][outcome(row["expect"], results[row["sha"]])] += 1
        total = sum(tally.values(), collections.Counter())
        files = sum(total.values())
        print(f"== {run}: {args.split} files={files} ok={total['ok'] / max(1, files):.1%} {dict(total)}")
        for label in sorted(tally):
            n = sum(tally[label].values())
            print(f"   {label:16} n={n:4} ok={tally[label]['ok'] / n:6.1%} {dict(tally[label])}")


if __name__ == "__main__":
    main()
