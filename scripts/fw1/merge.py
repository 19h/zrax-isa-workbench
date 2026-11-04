#!/usr/bin/env python3
"""Merge corpora in build_corpus.py layout into OUT: the manifests are
concatenated and the samples symlinked (OUT is recreated).

Usage: merge.py OUT CORPUS...
"""
import argparse
import os
import shutil


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out")
    parser.add_argument("corpora", nargs="+")
    args = parser.parse_args()
    shutil.rmtree(args.out, ignore_errors=True)
    os.makedirs(os.path.join(args.out, "samples"))
    rows = 0
    with open(os.path.join(args.out, "manifest.jsonl"), "w") as manifest:
        for corpus in map(os.path.abspath, args.corpora):
            with open(os.path.join(corpus, "manifest.jsonl")) as f:
                for line in f:
                    manifest.write(line)
                    rows += 1
            samples = os.path.join(corpus, "samples")
            for cls in os.listdir(samples):
                target = os.path.join(args.out, "samples", cls)
                os.makedirs(target, exist_ok=True)
                for name in os.listdir(os.path.join(samples, cls)):
                    link = os.path.join(target, name)
                    if not os.path.lexists(link):
                        os.symlink(os.path.join(samples, cls, name), link)
    print(rows)


if __name__ == "__main__":
    main()
