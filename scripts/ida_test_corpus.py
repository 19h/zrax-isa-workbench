#!/usr/bin/env python3
"""
Raw ground-truth code for ISAs that have no compiler on this machine, taken
from IDA's kernel test inputs (ida/tests/input) with IDA's reference listings
(ida/tests/logs/<test>.lst) as the code map (see ida_listing_code.py).

Only instruction bytes are kept, so the samples carry no vectors, tables,
strings or erased flash. Instruction-set coverage tests ("allins",
"opcodes", ...) are left out: their uniform opcode mix is not what real code
looks like.

Samples are written as <out>/<class>/<test>.bin. Images with more than
CHUNK bytes of code are cut into CHUNK-sized pieces named <test>#<k>.bin, so
the corpus builder's group split can hold some of each image out. Those
pieces come from one program: they measure how well the rest of that image
is recognised, not how well other programs are.

Usage:
    scripts/ida_test_corpus.py --out corpus_extra/raw-ida [--ida-tests ~/hexrays/ida/tests]
Then pass one `--raw CLASS=<out>/CLASS/*.bin` per class to build_corpus.py.
"""

import argparse
import fnmatch
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ida_listing_code  # noqa: E402

# A multiple of 2, 3 and 4, so pieces of word-oriented code start on a word.
CHUNK = 16380

# (class, test-file glob). Classes must exist in src/heuristics/model.rs.
SOURCES = [
    ("mcs96", "8065.hex"),
    ("mcs96", "8061.hex"),
    ("mcs96", "8096.hex"),
    ("mcs96", "80196.bin"),
    ("tlcs900", "tlcs900--b800.bin"),
    ("mn10200", "mn102l00--b8000_rv31.bin"),
    ("st20", "st20_bin.bin"),
    ("unsp", "unsp_flower.bin"),
    ("oakdsp", "oakdsp_p1.bin"),
    ("cr16", "cr16_dect11.bin"),
    ("r32c", "r32c_honda--bFFF8000.bin"),
    ("r32c", "r32c_primes.hex"),
    ("adsp21xx", "ad218x_voc_code.bin"),
    ("dsp56100", "dsp561xx*.bin"),
    ("dsp56k", "dsp563xx_bin.bin"),
    ("dsp56k", "dsp56k_bin.bin"),
    # Two firmware versions of one program: merged into one sample so they
    # cannot land on both sides of the split.
    ("tic3x", "tms320c3--b10000*.bin", "tms320c3--b10000"),
    ("pic24", "pic33_reljmp16.bin"),
    ("pic24", "pic33_33ep256gm304.hex"),
    ("pic24", "pic24_c_binary.hex"),
    ("pic24", "pic24_ep512gp202.hex"),
    ("pic24", "pic24_p24F32KA302_bootloader.hex"),
    ("pic24", "pic24_stkpnt.hex"),
    ("pic24", "pic30_*.hex"),
    ("pic14", "pic16cxx_161fxxx.bin"),
    ("pic14", "pic12Cxx.hex"),
    ("pic18", "pic18cxx_*.hex"),
    ("hc08", "hcs08_*.s19"),
    ("i8051", "8051.hex"),
    ("i8051", "8051_aaagsm.hex"),
    ("xa", "51xa-g3*.hex"),
    ("m7700", "m7700_*.hex"),
    ("m7700", "m7900_*.hex"),
    ("hc16", "6816_*.s19"),
    ("ez80", "ez80_*.bin"),
    ("z80", "z180.hex"),
    ("z80", "z380.hex"),
    ("z80", "z80_*.bin"),
    ("sm83", "gb_*.bin"),
    ("pdp11", "pdp11*.sav"),
    ("mos6502", "m6502_*"),
    ("mos6502", "m65c02_*"),
    ("m6800", "6803*.s19"),
    ("hc05", "6805_*.s19"),
    ("st7", "st7_alpha.s19"),
    ("z8", "z8_bin.bin"),
    ("z8", "sam8_*.hex"),
    ("f2mc16", "f2mc16lx_*"),
    ("kr1878", "kr1878*.bin"),
    ("h8500", "h8500*.bin"),
    ("dsp96k", "dsp96k_*.s19"),
]

# cLEMENCy packs 9-bit bytes, which the listing shows as 9-bit values; the
# whole programs are used instead (each is a separate program, so they are
# not cut into pieces).
WHOLE = [("clemency", "clemency_*.bin")]

# Word-addressed DSPs are stored little-endian (build_corpus.py derives the
# big-endian classes): class -> {listing packing: word size to reverse}.
SWAP_TO_LE = {
    "tic3x": {"packing=be32": 4},
    "dsp56k": {"packing=be24": 3},
    "dsp56100": {"packing=be16": 2},
}

SKIP_WORDS = ("allins", "all_instructions", "opcodes", "newinsns")
SIDECARS = (".hints", ".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til", ".mas", ".lst", ".txt")


def write(out, cls, name, code, chunk=True):
    d = os.path.join(out, cls)
    os.makedirs(d, exist_ok=True)
    if not chunk or len(code) <= CHUNK * 3 // 2:
        pieces = [code]
    else:
        pieces = [code[i : i + CHUNK] for i in range(0, len(code), CHUNK)]
    for k, piece in enumerate(pieces):
        fn = name if len(pieces) == 1 else f"{name}#{k}"
        with open(os.path.join(d, fn + ".bin"), "wb") as f:
            f.write(piece)
    return len(pieces)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--ida-tests", default=os.path.expanduser("~/hexrays/ida/tests"))
    a = ap.parse_args()
    inputs = os.path.join(a.ida_tests, "input")
    logs = os.path.join(a.ida_tests, "logs")
    names = sorted(n for n in os.listdir(inputs) if not n.endswith(SIDECARS))
    totals = {}
    merged = {}
    for cls, pattern, *program in SOURCES + WHOLE:
        for name in fnmatch.filter(names, pattern):
            if any(w in name.lower() for w in SKIP_WORDS):
                continue
            src = os.path.join(inputs, name)
            if not os.path.isfile(src):
                continue
            if (cls, pattern) in WHOLE:
                code, info = open(src, "rb").read(), "whole file"
            else:
                lst = os.path.join(logs, name + ".lst")
                if not os.path.isfile(lst):
                    print(f"{name}: no listing", file=sys.stderr)
                    continue
                code, info = ida_listing_code.extract(lst, src)
                if code is None:
                    print(f"{name}: {info}", file=sys.stderr)
                    continue
            if len(code) < 64:
                continue
            if cls in SWAP_TO_LE and info.split()[0] in SWAP_TO_LE[cls]:
                n = SWAP_TO_LE[cls][info.split()[0]]
                code = b"".join(code[i : i + n][::-1] for i in range(0, len(code) - len(code) % n, n))
                info += " (swapped to little-endian)"
            if program:
                merged.setdefault((cls, program[0]), bytearray()).extend(code)
                print(f"{cls:10s} {name:40s} {len(code):8d} bytes -> {program[0]}  {info}", file=sys.stderr)
                continue
            n = write(a.out, cls, name, code, chunk=(cls, pattern) not in WHOLE)
            totals[cls] = totals.get(cls, 0) + len(code)
            print(f"{cls:10s} {name:40s} {len(code):8d} bytes in {n} piece(s)  {info}", file=sys.stderr)
    for (cls, program), code in merged.items():
        write(a.out, cls, program, bytes(code), chunk=False)
        totals[cls] = totals.get(cls, 0) + len(code)
    for cls, n in sorted(totals.items()):
        print(f"{cls:10s} {n:8d}", file=sys.stderr)


if __name__ == "__main__":
    main()
