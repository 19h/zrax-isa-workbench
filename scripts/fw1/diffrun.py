#!/usr/bin/env python3
"""Diff two full CLI runs (runall.sh/runlist.sh JSONL): tally ISA
transitions and how many files of each findings.tsv category changed.

Usage (from the directory holding all.tsv and findings.tsv):
    diffrun.py OLD.jsonl NEW.jsonl [--top N]
"""
import argparse
import collections
import csv
import json


def load(path):
    """file -> result of one run; unparsable lines are skipped."""
    out = {}
    with open(path) as f:
        for line in f:
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue
            out[result["file"]] = result
    return out


def key(result):
    return (result.get("format"), result.get("isa"), result.get("variant") or "", result.get("bitwidth"))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("old")
    parser.add_argument("new")
    parser.add_argument("--top", type=int, default=70)
    args = parser.parse_args()
    old, new = load(args.old), load(args.new)
    with open("all.tsv") as f:
        names = {r["sha"]: r["name"] for r in csv.DictReader(f, delimiter="\t")}
    categories = collections.defaultdict(set)
    with open("findings.tsv") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            categories[row["sha"]].add(row["category"])
    changed = [sha for sha in old if sha in new and key(old[sha]) != key(new[sha])]
    print("files", len(old), len(new), "changed", len(changed))
    transitions = collections.Counter()
    examples = collections.defaultdict(list)
    for sha in changed:
        before, after = old[sha], new[sha]
        transition = (f"{before.get('isa')}/{before.get('variant') or ''}",
                      f"{after.get('isa')}/{after.get('variant') or ''}",
                      ",".join(sorted(categories[sha])) or "-")
        transitions[transition] += 1
        examples[transition].append(names.get(sha, sha)[:38])
    for transition, count in transitions.most_common(args.top):
        before, after, category = transition
        print(f"{count:5}  {before:22} -> {after:22} [{category}]  e.g. {examples[transition][:3]}")
    total = collections.Counter(c for sha in categories for c in categories[sha])
    moved = collections.Counter(c for sha in changed for c in categories[sha])
    print("\nflagged categories: changed/total")
    for category, count in total.most_common():
        print(f"  {category:26} {moved[category]:5}/{count}")


if __name__ == "__main__":
    main()
