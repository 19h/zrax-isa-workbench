#!/usr/bin/env python3
"""File-level golden labels for fw1 raw files, with the corpus split of their group.

Output TSV: sha, split, expect (isa id or "none"), family label, name.
Expected ISA ids are zrax JSON ids; "none" means the file is not code.

Usage: golden_files.py FW_DIR CORPUS_FW1 > golden.tsv
"""
import csv, importlib.util, json, os, re, sys
fw, corpus = sys.argv[1:3]
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("fw1_corpus", os.path.join(here, "fw1_corpus.py"))
fc = importlib.util.module_from_spec(spec); spec.loader.exec_module(fc)
CLASS_ISA = {"hexagon": "hexagon", "aarch64": "a_arch64", "arm": "arm", "thumb": "arm", "xtensa": "xtensa",
             "z80": "z80", "sh": "sh", "i8051": "i8051"}
split = {}
for line in open(os.path.join(corpus, "manifest.jsonl")):
    r = json.loads(line)
    split[(r["class"], r["group"])] = r["split"]
rows = fc.read_rows("all.tsv")
smooth = {r["sha"]: r for r in fc.read_rows("smooth.tsv")}
pil = {r["name"]: r for r in fc.read_rows("pil_match.tsv")}
print("sha\tsplit\texpect\tlabel\tname")
for r in rows:
    name, path = r["name"], os.path.join(fw, r["sha"])
    p = pil.get(name)
    cls = group = label = None
    if p and p["qc_type"] != "2" and int(p["size"]) == int(r["size"]):
        if p["exec"] == "True":
            cls = {"hexagon": "hexagon", "a_arch64": "aarch64", "xtensa": "xtensa", "arm": "thumb"}.get(p["elf_isa"])
            label = "pil-code"
        else:
            cls, label = "neg_rodata", "pil-data"
        group = "fw1:" + fc.family(name)
    elif r["format"] == "raw":
        s = smooth.get(r["sha"])
        if s and s["smooth"] and float(s["smooth"]) >= 0.6 and int(s["pairs"]) > 500:
            cls, group, label = "neg_media", "fw1:pcm-" + re.split(r"[_\-. ]", fc.family(name))[0], "pcm"
        elif re.match(r"swfl_.*\.159_010_001$", name) or re.match(r"board(-2)?\.bin", name):
            cls, group, label = "neg_table", "fw1:" + fc.family(name), "calibration"
        else:
            rom = next(((c, f) for pat, c, f in fc.ROM_FAMILIES if re.search(pat, name, re.I)), None)
            with open(path, "rb") as f:
                first = f.read(64)
            if rom:
                cls, group, label = rom[0], "fw1:" + rom[1], "rom-" + rom[1]
            elif fc.has_8051_vectors(first, int(r["size"])):
                cls, group, label = "i8051", "fw1:" + fc.family(name), "8051-vectors"
            elif fc.has_cortexm_vectors(first):
                cls, group, label = "thumb", "fw1:" + fc.family(name), "cortexm"
    if not cls:
        continue
    sp = split.get((cls, group), "absent")
    # arm_mode decides A32 vs T32 for PIL ARM; both are zrax isa "arm"
    if cls == "thumb" and label == "pil-code":
        sp = split.get(("thumb", group), split.get(("arm", group), "absent"))
    expect = "none" if cls.startswith("neg_") else CLASS_ISA[cls]
    print(f"{r['sha']}\t{sp}\t{expect}\t{label}\t{name}")
