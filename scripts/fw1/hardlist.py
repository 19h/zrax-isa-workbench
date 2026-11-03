#!/usr/bin/env python3
"""List fw1 file-level negatives in the train split as path<TAB>class<TAB>group for mine_hard.

Usage: hardlist.py FW_DIR CORPUS_FW1 > list.tsv
"""
import csv, importlib.util, json, os, re, sys
fw, corpus = sys.argv[1:3]
spec = importlib.util.spec_from_file_location("fw1_corpus", os.path.join(os.path.dirname(os.path.abspath(__file__)), "fw1_corpus.py"))
fc = importlib.util.module_from_spec(spec); spec.loader.exec_module(fc)
split = {}
for line in open(os.path.join(corpus, "manifest.jsonl")):
    r = json.loads(line)
    split[(r["class"], r["group"])] = r["split"]
rows = fc.read_rows("all.tsv")
smooth = {r["sha"]: r for r in fc.read_rows("smooth.tsv")}
pil = {r["name"]: r for r in fc.read_rows("pil_match.tsv")}
for r in rows:
    name, path = r["name"], os.path.join(fw, r["sha"])
    p = pil.get(name)
    if p and p["exec"] == "False" and p["qc_type"] != "2":
        cls, group = "neg_rodata", "fw1:" + fc.family(name)
    elif r["format"] != "raw":
        continue
    elif (s := smooth.get(r["sha"])) and s["smooth"] and float(s["smooth"]) >= 0.6 and int(s["pairs"]) > 500:
        cls, group = "neg_media", "fw1:pcm-" + re.split(r"[_\-. ]", fc.family(name))[0]
    elif re.match(r"swfl_.*\.159_010_001$", name) or re.match(r"board(-2)?\.bin", name):
        cls, group = "neg_table", "fw1:" + fc.family(name)
    else:
        continue
    if split.get((cls, group)) == "train":
        print(f"{path}\t{cls}\t{group}")
