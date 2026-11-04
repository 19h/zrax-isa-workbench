#!/usr/bin/env python3
"""List the fw1 non-code files of the train split as
`path<TAB>class<TAB>group` for `examples/mine_hard.rs`.

Labels come from `fw1_corpus.file_label`.

Usage (from the directory holding all.tsv and smooth.tsv):
    hardlist.py REPO FW1_DIR CORPUS_FW1 > list.tsv
"""
import argparse
import importlib.util
import json
import os


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repo")
    parser.add_argument("fw1_dir")
    parser.add_argument("corpus")
    args = parser.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("fw1_corpus", os.path.join(here, "fw1_corpus.py"))
    fc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fc)
    bc = fc.load_build_corpus(args.repo)
    split = {}
    with open(os.path.join(args.corpus, "manifest.jsonl")) as f:
        for line in f:
            row = json.loads(line)
            split[(row["class"], row["group"])] = row["split"]
    rows = fc.read_rows("all.tsv")
    smooth = {r["sha"]: r for r in fc.read_rows("smooth.tsv")}
    pil = fc.pil_headers(rows, args.fw1_dir)
    for row in rows:
        label = fc.file_label(row, args.fw1_dir, pil, smooth, bc)
        if label and label.cls.startswith("neg_") and split.get((label.cls, label.group)) == "train":
            print(f"{os.path.join(args.fw1_dir, row['sha'])}\t{label.cls}\t{label.group}")


if __name__ == "__main__":
    main()
