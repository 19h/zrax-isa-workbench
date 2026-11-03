#!/usr/bin/env python3
"""Merge corpora in build_corpus.py layout into OUT, symlinking samples.

Usage: merge.py OUT CORPUS...
"""
import os
import shutil
import sys

out, corpora = sys.argv[1], sys.argv[2:]
shutil.rmtree(out, ignore_errors=True)
os.makedirs(os.path.join(out, "samples"))
rows = 0
with open(os.path.join(out, "manifest.jsonl"), "w") as manifest:
    for corpus in corpora:
        corpus = os.path.abspath(corpus)
        with open(os.path.join(corpus, "manifest.jsonl")) as f:
            for line in f:
                manifest.write(line)
                rows += 1
        samples = os.path.join(corpus, "samples")
        for cls in os.listdir(samples):
            target = os.path.join(out, "samples", cls)
            os.makedirs(target, exist_ok=True)
            for name in os.listdir(os.path.join(samples, cls)):
                link = os.path.join(target, name)
                if not os.path.lexists(link):
                    os.symlink(os.path.join(samples, cls, name), link)
print(rows)
