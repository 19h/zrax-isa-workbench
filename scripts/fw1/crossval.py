#!/usr/bin/env python3
"""Leave-one-group-out folds of a corpus, for groups that start with PREFIX.

For each group (e.g. every `mame:<set>`), writes OUT/<group name>/ with a
manifest of the corpus without that group's rows (labelled samples and the
hard negatives mined from them carry the group of their source file) and a
`samples` symlink to the corpus's sample directory, so `train_model` can
train the fold without copying samples. Prints `group<TAB>fold directory`
per fold.

Usage: crossval.py CORPUS PREFIX OUT
"""
import argparse
import json
import os


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("corpus")
    parser.add_argument("prefix", help="group prefix of the folds, e.g. mame:")
    parser.add_argument("out")
    args = parser.parse_args()
    with open(os.path.join(args.corpus, "manifest.jsonl")) as f:
        rows = [json.loads(line) for line in f]
    groups = sorted({r["group"] for r in rows if r["group"].startswith(args.prefix)})
    samples = os.path.abspath(os.path.join(args.corpus, "samples"))
    for group in groups:
        fold = os.path.join(args.out, group.replace(":", "_").replace("/", "_"))
        os.makedirs(fold, exist_ok=True)
        link = os.path.join(fold, "samples")
        if not os.path.lexists(link):
            os.symlink(samples, link)
        with open(os.path.join(fold, "manifest.jsonl"), "w") as manifest:
            for row in rows:
                if row["group"] != group:
                    manifest.write(json.dumps(row) + "\n")
        print(f"{group}\t{fold}")


if __name__ == "__main__":
    main()
