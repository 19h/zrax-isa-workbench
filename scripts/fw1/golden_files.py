#!/usr/bin/env python3
"""File-level golden labels for fw1 files, with the corpus split of their
group, for scoring whole files through the CLI (score.py).

Labels come from `fw1_corpus.file_label`, the same rules that build the
corpus. Output TSV: sha, split, expect (zrax ISA id, `x86_16` for real-mode
x86, or `none` for non-code), label, name. Held-out labels (XTIDE ROMs) are
always in the test split.

Usage (from the directory holding all.tsv and smooth.tsv):
    golden_files.py REPO FW1_DIR CORPUS_FW1 > golden.tsv
"""
import argparse
import importlib.util
import json
import os

# Corpus class -> zrax JSON ISA id the CLI should report.
CLASS_ISA = {
    "hexagon": "hexagon", "aarch64": "a_arch64", "arm": "arm", "thumb": "arm", "armeb": "arm",
    "thumbeb": "arm", "xtensa": "xtensa", "z80": "z80", "sh": "sh", "i8051": "i8051", "x86_16": "x86_16",
    "z8": "z8", "msp430": "msp430", "mipsel": "mips", "i8085": "i8085", "unsp": "unsp", "mcs96": "mcs96",
    "fr30": "fr30",
}


# Golden labels whose expected answer is not their class's: the NAOMI BIOS
# runs on an SH-4 (training class `sh`), reported as SH-4 or as SuperH.
LABEL_ISA = {"rom-naomi-bios": "sh4|sh"}


def load_fw1_corpus():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("fw1_corpus", os.path.join(here, "fw1_corpus.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repo")
    parser.add_argument("fw1_dir")
    parser.add_argument("corpus", help="fw1 corpus whose manifest gives the split of each group")
    args = parser.parse_args()
    fc = load_fw1_corpus()
    bc = fc.load_build_corpus(args.repo)
    split = {}
    with open(os.path.join(args.corpus, "manifest.jsonl")) as f:
        for line in f:
            row = json.loads(line)
            split[(row["class"], row["group"])] = row["split"]
    rows = fc.read_rows("all.tsv")
    smooth = {r["sha"]: r for r in fc.read_rows("smooth.tsv")}
    pil = fc.pil_headers(rows, args.fw1_dir)
    mame = fc.read_mame("mame_match.tsv")
    print("sha\tsplit\texpect\tlabel\tname")
    for row in rows:
        label = fc.file_label(row, args.fw1_dir, pil, smooth, bc, mame)
        if label is None:
            continue
        group_split = "test" if label.held_out else split.get((label.cls, label.group), "absent")
        expect = "none" if label.cls.startswith("neg_") else LABEL_ISA.get(label.label, CLASS_ISA.get(label.cls))
        if expect is None:
            continue
        print(f"{row['sha']}\t{group_split}\t{expect}\t{label.label}\t{row['name']}")


if __name__ == "__main__":
    main()
