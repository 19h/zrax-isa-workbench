#!/usr/bin/env python3
"""Collect every flagged fw1 file into findings.tsv: category, sha, name, zrax result, evidence.

Run from the directory holding all.tsv, heads.tsv, pil_match.tsv and smooth.tsv.

Usage: findings.py FW1_DIR
"""
import argparse
import collections
import csv
import re
import struct

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("fw1_dir", help="directory of fw1 binaries named by SHA-256")
FW1_DIR = parser.parse_args().fw1_dir
rows = {r["sha"]: r for r in csv.DictReader(open("all.tsv"), delimiter="\t")}
byname = {}
for r in rows.values():
    byname.setdefault(r["name"], []).append(r)
heads = {r["sha"]: r for r in csv.DictReader(open("heads.tsv"), delimiter="\t")}
pil = {r["name"]: r for r in csv.DictReader(open("pil_match.tsv"), delimiter="\t")}
smooth = {r["sha"]: r for r in csv.DictReader(open("smooth.tsv"), delimiter="\t")}
# mame_match.tsv (mame_regions.py, matched by SHA-1): MAME's ROM region per dump.
mame = {}
try:
    with open("mame_match.tsv") as f:
        for line in f:
            fields = line.rstrip("\n").split("\t")
            mame[fields[0]] = fields
except FileNotFoundError:
    pass
out = []
def add(cat, r, ev):
    out.append([cat, r["sha"], r["name"], r["format"], r["fvariant"], r["isa"], r["variant"], r["bits"], r["endian"], r["conf"][:5], ev])
for s, r in rows.items():
    p = pil.get(r["name"])
    if p and p["exec"] == "False" and p["qc_type"] != "2" and int(p["size"]) == int(r["size"]):
        if r["format"] in ("tiboot", "tiimage", "coff"):
            add("weak-format-on-pil-data", r, f"Qualcomm {p['elf_isa']} ELF data segment p_flags={p['pflags']}")
        elif r["isa"]:
            add("isa-on-pil-data", r, f"Qualcomm {p['elf_isa']} ELF data segment p_flags={p['pflags']}")
    sm = smooth.get(s)
    if sm and sm["smooth"] and float(sm["smooth"]) >= 0.6 and int(sm["pairs"]) > 500 and r["isa"]:
        add("pcm-as-code", r, f"8-bit PCM smoothness {sm['smooth']} (code max 0.389)")
    if r["isa"] == "z80" and r["variant"] == "ez80" and not re.search(r"(?i)ez80|ti-?84", r["name"]):
        add("z80-as-ez80", r, "plain Z80 platform ROM reported as eZ80 24-bit")
    if r["isa"] == "clemency":
        add("clemency", r, "cLEMENCy is a CTF-only ISA; NAOMI ROMs show SH-4 LE idiom density")
    if re.match(r"swfl_.*\.159_010_001$", r["name"]) and r["isa"] == "arc_compact":
        add("calibration-as-arc", r, "524032 B calibration maps; no ARC/TriCore idioms")
    if re.match(r"board(-2)?\.bin", r["name"]) and r["isa"]:
        add("bdf-as-code", r, "QCA-ATH1xK-BOARD board-data container")
    h = heads[s]
    if h["kind"] == "elf" and h["machine"] == "4160":
        add("elf-unknown-machine", r, "EI_DATA=MSB, e_machine 0x1040; zrax endianness/ISA from heuristic")
    if h["kind"] == "elf" and h["machine"] == "15" and h["cls"] == "2":
        add("elf-bitwidth", r, "ELFCLASS64 PA-RISC reported 32-bit")
    if r["name"].startswith("ide_") and r["format"] == "raw" and r["isa"].startswith("x86"):
        add("x86-16bit", r, "XT-IDE legacy option ROM (8088 real mode)")
    if r["name"].startswith("faceauth") and r["isa"] != "arm" and r["format"] == "raw":
        add("cortexm-missed", r, "Cortex-M vector table + Thumb code at offset 0")
    if r["name"] in ("mn10200_code1.bin", "mn10200_swapped.bin"):
        # The name says MN10200; the bytes are little-endian MIPS R3000 code
        # (stored and 16-bit swapped), so the expected answer is MIPS.
        add("name-contradicts", r, "MIPS R3000 reset code writing 0x1F801010 (name says MN10200)")
    if r["name"] == "hop_leds_pic12c671.bin":
        add("name-contradicts", r, "PIC14 GOTO/CALL/MOVLW/RETURN words; PIC12C671 is a 14-bit mid-range part")
    if r["name"].startswith("MN10300_GH2"):
        add("name-contradicts", r, "file name names MN10300 (decrypted Panasonic GH2 firmware); not otherwise verified")
    m = mame.get(s)
    if m and m[2] in ("graphics", "sound") and r["isa"]:
        add("mame-data-as-code", r, f"MAME set {m[4]} loads this dump into region {m[3]} ({m[2]})")
    if r["name"] == "A3440_42_9B5042a_TMAP_16" or r["name"] == "SCH-V745_ZE29_0x2890000.FNT":
        add("data-as-code", r, "bplist00 header / valid zlib stream")
for s, r in rows.items():
    d = None
    if r["isa"] == "wasm" and r["format"] == "raw":
        d = open(FW1_DIR + "/" + s, "rb").read(0x30)
        if d[0] == 2 and sum(d[a] in (2, 0x32) for a in (3, 0xB, 0x13, 0x1B, 0x23)) >= 2:
            add("8051-as-wasm", r, "8051 LJMP reset + RETI/LJMP interrupt vectors")
w = csv.writer(open("findings.tsv", "w", newline=""), delimiter="\t")
w.writerow(["category", "sha", "name", "format", "format_variant", "isa", "variant", "bits", "endian", "conf", "evidence"])
w.writerows(sorted(out))
for k, v in collections.Counter(o[0] for o in out).most_common(): print(v, k)
print("total rows", len(out), "unique files", len({o[1] for o in out}))
