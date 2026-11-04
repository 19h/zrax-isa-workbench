#!/usr/bin/env python3
"""Check a full CLI run against findings.tsv: for every flagged file, does
the new result meet what its category needs (no ISA for data, Z80 not eZ80,
16-bit x86, ...)? Prints counts per category and the files that still fail.

An ISA on a Qualcomm data segment counts as resolved when the segment holds
another core's code of that ISA: with --fw, `embedded_code_class` from
fw1_corpus.py (return idioms over the non-fill blocks) names the family.

Where MAME lists the file's CPU (mame_cpus.tsv from mame_cpus.py, read from
the same directory when present), the answer must be that CPU's ISA.

Usage (from the directory holding findings.tsv):
    verify_findings.py RUN.jsonl [--show N] [--fw FW1_DIR]
"""
import argparse
import collections
import csv
import importlib.util
import json
import os

# Name-labelled files: the ISA their bytes or provenance establish.
NAMED_ISA = {"mn10200_code1.bin": "mips", "mn10200_swapped.bin": "mips", "hop_leds_pic12c671.bin": "pic"}
NAMED_PREFIX_ISA = {"MN10300_GH2": "mn10300"}
# fw1_corpus idiom class -> zrax JSON ISA id.
IDIOM_ISA = {"thumb": "arm", "arm": "arm", "aarch64": "a_arch64", "hexagon": "hexagon", "xtensa": "xtensa",
             "mipsel": "mips", "micromipsel": "mips", "tricore": "tricore", "sh": "sh", "msp430": "msp430",
             "shframe": "sh", "riscv": ("risc_v32", "risc_v64", "riscv32", "riscv64")}

NO_ISA_CATEGORIES = {"calibration-as-arc", "weak-format-on-pil-data",
                     "bdf-as-code", "data-as-code", "elf-unknown-machine", "mame-data-as-code"}


def read_mame_cpus(path):
    """sha256 -> the ISA of the CPU MAME runs a whole program-ROM dump on
    (mame_cpus.py output), or {} without the file. Byte-lane dumps hold no
    whole instruction and are left out."""
    if not os.path.exists(path):
        return {}
    cpus = {}
    with open(path) as f:
        for line in f:
            sha, _set, _rom, _tag, _types, isa, layout = line.rstrip("\n").split("\t")
            if isa and layout != "byte-lanes":
                cpus[sha] = isa
    return cpus


def no_isa(result):
    isa = result.get("isa")
    return isa in (None, "<rejected>") or str(isa).startswith("unknown")


def load_fw1_corpus():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("fw1_corpus", os.path.join(here, "fw1_corpus.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def meets(category, name, result, embedded=None, mame_isa=None):
    """Whether `result` resolves a finding of `category` for file `name`.

    `embedded` is the idiom class of the code a data segment holds, if any;
    `mame_isa` the ISA of the CPU MAME runs the file on, if MAME lists it.
    """
    isa = result.get("isa")
    if category in NO_ISA_CATEGORIES:
        return no_isa(result)
    if category in ("isa-on-pil-data", "pcm-as-code"):
        if no_isa(result):
            return True
        if mame_isa:
            return isa == mame_isa
        expected = IDIOM_ISA.get(embedded, ())
        return isa in (expected if isinstance(expected, tuple) else (expected,))
    if category == "z80-as-ez80":
        # The defect is a 24-bit eZ80 claim. Z80, 8080/8085 (code that uses no
        # Z80-only instruction runs on both) and no claim are all supported;
        # MAME's CPU decides where MAME names it.
        if mame_isa:
            return isa == mame_isa
        return result.get("variant") != "ez80" and (isa in ("z80", "i8085") or no_isa(result))
    if category == "8051-as-wasm":
        return isa == "i8051"
    if category == "clemency":
        return isa != "clemency" and (not name.startswith("epr-") or isa == "sh")
    if category == "x86-16bit":
        return isa == "x86" and result.get("bitwidth") == 16
    if category == "elf-bitwidth":
        return result.get("bitwidth") == 64
    if category == "cortexm-missed":
        return isa == "arm"
    if category == "name-contradicts":
        expected = NAMED_ISA.get(name) or next(
            (v for prefix, v in NAMED_PREFIX_ISA.items() if name.startswith(prefix)), None)
        return isa == expected
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run")
    parser.add_argument("--show", type=int, default=40)
    parser.add_argument("--fw", help="fw1 directory: check data segments for embedded code")
    args = parser.parse_args()
    fc = load_fw1_corpus() if args.fw else None
    with open(args.run) as f:
        results = {json.loads(line)["file"]: json.loads(line) for line in f}
    mame_cpus = read_mame_cpus("mame_cpus.tsv")
    tally = collections.defaultdict(collections.Counter)
    failures = []
    with open("findings.tsv") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            result = results.get(row["sha"], {})
            embedded = None
            if fc and row["category"] in ("isa-on-pil-data", "pcm-as-code") and not no_isa(result):
                with open(os.path.join(args.fw, row["sha"]), "rb") as data:
                    embedded = fc.embedded_code_class(data.read())
            ok = meets(row["category"], row["name"], result, embedded, mame_cpus.get(row["sha"]))
            status = "fixed" if ok else "open"
            tally[row["category"]][status] += 1
            if status != "fixed":
                failures.append((status, row["category"], row["name"][:44], result.get("format"), result.get("isa"),
                                 result.get("variant"), result.get("bitwidth")))
    for category, counts in sorted(tally.items(), key=lambda kv: -sum(kv[1].values())):
        extra = f", open {counts['open']}" if counts["open"] else ""
        print(f"{category:26} fixed {counts['fixed']:4} / {sum(counts.values()):4}{extra}")
    for failure in failures[:args.show]:
        print(f"  {failure[0]}:", *failure[1:])


if __name__ == "__main__":
    main()
