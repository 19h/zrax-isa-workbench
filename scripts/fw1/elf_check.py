#!/usr/bin/env python3
"""File-level check of a zrax CLI on labelled ELF corpora. Each file is
classified twice: whole, where the ELF header decides and the header-against-
code check can withdraw the answer, and as the raw bytes of its largest
executable section, where the code model decides.

Inputs:
  --ds2 DIR    ISAdetect ds2: files FIRST .. FIRST+COUNT-1 (sorted by name)
               of each architecture directory, labelled by the directory.
               build_corpus.py trains on files 0-399, the ds2h held-out set
               is 400-549 and negatives come from the last 40, so the
               default 550-599 was never used.
  --elf DIR    every ELF file under DIR, labelled by its e_machine (only
               machines listed in E_MACHINE_LABELS).

Output, in OUT:
  results.tsv  one row per file: corpus, label, path, expected ISA, the
               whole-file ISA and variant, the raw ISA, byte order and
               confidence, and the two verdicts
  text/        the extracted sections, named by the SHA-256 of the file
  stdout       per label: files, whole-file right, raw right / wrong /
               no answer, and the most frequent wrong raw answers

A raw verdict is "right" for the expected ISA in the expected byte order,
"none" for a rejection or an unknown ISA, else "wrong".

Usage: elf_check.py ZRAX OUT [--ds2 DIR [--first N] [--count N]] [--elf DIR]
"""
import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
import struct
import subprocess

# ISAdetect architecture directory -> (zrax ISA ID, byte order); `a|b`
# accepts either (Debian's sh4 port targets the SH-4, whose code without
# SH-4-only instructions is reported as SuperH).
DS2_LABELS = {
    "alpha": ("alpha", "little"),
    "amd64": ("x86_64", "little"),
    "arm64": ("aarch64", "little"),
    "armel": ("arm", "little"),
    "armhf": ("arm", "little"),
    "hppa": ("parisc", "big"),
    "i386": ("x86", "little"),
    "ia64": ("ia64", "little"),
    "m68k": ("m68k", "big"),
    "mips": ("mips", "big"),
    "mips64el": ("mips64", "little"),
    "mipsel": ("mips", "little"),
    "powerpc": ("ppc", "big"),
    "powerpcspe": ("ppc", "big"),
    "ppc64": ("ppc64", "big"),
    "ppc64el": ("ppc64", "little"),
    "riscv64": ("riscv64", "little"),
    "s390": ("s390", "big"),
    "s390x": ("s390x", "big"),
    "sh4": ("sh4|sh", "little"),
    "sparc": ("sparc", "big"),
    "sparc64": ("sparc64", "big"),
    "x32": ("x86_64", "little"),
}

# e_machine -> (label, zrax ISA ID) for --elf corpora.
E_MACHINE_LABELS = {164: ("hexagon", "hexagon")}

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
SHT_PROGBITS = 1
SHF_EXECINSTR = 0x4
PT_LOAD = 1
PF_X = 0x1
WORKERS = 8


def elf_header(data):
    """(is_64, byte order prefix, e_machine) of an ELF file, or None."""
    if len(data) < 0x40 or data[:4] != ELF_MAGIC:
        return None
    order = "<" if data[5] == ELFDATA2LSB else ">"
    (machine,) = struct.unpack_from(order + "H", data, 0x12)
    return data[4] == ELFCLASS64, order, machine


def executable_ranges(data):
    """(offset, size) of each executable PROGBITS section, else of each
    executable PT_LOAD segment; empty for a malformed table."""
    is_64, order, _ = elf_header(data)
    if is_64:
        phoff, shoff = struct.unpack_from(order + "QQ", data, 0x20)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(order + "HHHH", data, 0x36)
        section_layout, segment_layout = order + "IIQQQQ", order + "IIQQQQ"
    else:
        phoff, shoff = struct.unpack_from(order + "II", data, 0x1C)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(order + "HHHH", data, 0x2A)
        section_layout, segment_layout = order + "IIIIII", order + "IIIIII"
    sections = []
    for index in range(shnum):
        start = shoff + index * shentsize
        if start + struct.calcsize(section_layout) > len(data):
            return []
        _, kind, flags, _, offset, size = struct.unpack_from(section_layout, data, start)
        if kind == SHT_PROGBITS and flags & SHF_EXECINSTR and size:
            sections.append((offset, size))
    if sections:
        return sections
    segments = []
    for index in range(phnum):
        start = phoff + index * phentsize
        if start + struct.calcsize(segment_layout) > len(data):
            return []
        fields = struct.unpack_from(segment_layout, data, start)
        if is_64:
            kind, flags, offset, _, _, size = fields
        else:
            kind, offset, _, _, size, _ = fields
            (flags,) = struct.unpack_from(order + "I", data, start + 0x18)
        if kind == PT_LOAD and flags & PF_X and size:
            segments.append((offset, size))
    return segments


def largest_code(data):
    """Bytes of the largest executable range inside the file, or None."""
    if elf_header(data) is None:
        return None
    ranges = [(o, s) for o, s in executable_ranges(data) if o + s <= len(data)]
    if not ranges:
        return None
    offset, size = max(ranges, key=lambda r: r[1])
    return data[offset:offset + size]


def classify(zrax, path):
    """The CLI's JSON answer for one file; {} for a rejection."""
    run = subprocess.run([zrax, "-f", "json", path], capture_output=True, check=False)
    text = run.stdout.decode(errors="replace").strip()
    return json.loads(text) if text else {}


def ds2_inputs(root, first, count):
    """(corpus, label, path, expected ISA, byte order) per selected ds2 file."""
    for arch in sorted(DS2_LABELS):
        names = sorted(os.listdir(os.path.join(root, arch)))[first:first + count]
        isa, order = DS2_LABELS[arch]
        for name in names:
            yield "ds2", arch, os.path.join(root, arch, name), isa, order


def elf_inputs(root):
    """(corpus, label, path, expected ISA, byte order) per labelled ELF."""
    for directory, _, names in sorted(os.walk(root)):
        for name in sorted(names):
            path = os.path.join(directory, name)
            with open(path, "rb") as f:
                header = elf_header(f.read(0x40))
            if header is None or header[2] not in E_MACHINE_LABELS:
                continue
            label, isa = E_MACHINE_LABELS[header[2]]
            order = "little" if header[1] == "<" else "big"
            yield os.path.basename(root), label, path, isa, order


def check(zrax, text_dir, item):
    """One results row for one input."""
    corpus, label, path, isa, order = item
    with open(path, "rb") as f:
        data = f.read()
    whole = classify(zrax, path)
    whole_isa = whole.get("isa", "<rejected>")
    accepted = isa.split("|")
    code = largest_code(data)
    raw = {}
    if code is not None:
        text_path = os.path.join(text_dir, hashlib.sha256(data).hexdigest()[:24] + ".bin")
        with open(text_path, "wb") as f:
            f.write(code)
        raw = classify(zrax, text_path)
    raw_isa = raw.get("isa", "<rejected>" if code is not None else "<no code>")
    raw_order = raw.get("endianness")
    if raw_isa in accepted and raw_order == order:
        raw_verdict = "right"
    elif raw_isa in ("<rejected>", "<no code>") or raw_isa.startswith("unknown"):
        raw_verdict = "none"
    else:
        raw_verdict = "wrong"
    return {
        "corpus": corpus,
        "label": label,
        "path": path,
        "expected": isa,
        "whole_isa": whole_isa,
        "whole_variant": whole.get("variant") or "",
        "whole_verdict": "right" if whole_isa in accepted else "wrong",
        "raw_isa": raw_isa,
        "raw_order": raw_order or "",
        "raw_confidence": f"{raw.get('confidence') or 0:.2f}",
        "raw_size": len(code) if code is not None else 0,
        "raw_verdict": raw_verdict,
    }


def summarize(rows):
    """Print per-label counts and the most frequent wrong raw answers."""
    by_label = collections.defaultdict(list)
    for row in rows:
        by_label[(row["corpus"], row["label"])].append(row)
    print("corpus\tlabel\tfiles\twhole_right\traw_right\traw_wrong\traw_none\twrong raw answers")
    totals = collections.Counter()
    for (corpus, label), group in sorted(by_label.items()):
        verdicts = collections.Counter(r["raw_verdict"] for r in group)
        whole_right = sum(r["whole_verdict"] == "right" for r in group)
        wrong = collections.Counter(
            f"{r['raw_isa']}/{r['raw_order']}" for r in group if r["raw_verdict"] == "wrong"
        )
        totals.update(files=len(group), whole_right=whole_right, **verdicts)
        listed = ", ".join(f"{answer} {n}" for answer, n in wrong.most_common(3))
        print(
            f"{corpus}\t{label}\t{len(group)}\t{whole_right}\t{verdicts['right']}\t"
            f"{verdicts['wrong']}\t{verdicts['none']}\t{listed}"
        )
    print(
        f"total\t\t{totals['files']}\t{totals['whole_right']}\t{totals['right']}\t"
        f"{totals['wrong']}\t{totals['none']}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("zrax", help="zrax CLI binary")
    parser.add_argument("out", help="output directory")
    parser.add_argument("--ds2", help="ISAdetect ds2 directory (one subdirectory per architecture)")
    parser.add_argument("--first", type=int, default=550, help="first ds2 file per architecture (default 550)")
    parser.add_argument("--count", type=int, default=50, help="ds2 files per architecture (default 50)")
    parser.add_argument("--elf", action="append", default=[], help="directory of ELF files labelled by e_machine")
    args = parser.parse_args()

    text_dir = os.path.join(args.out, "text")
    os.makedirs(text_dir, exist_ok=True)
    items = []
    if args.ds2:
        items += ds2_inputs(args.ds2, args.first, args.count)
    for root in args.elf:
        items += elf_inputs(root)
    zrax = os.path.abspath(args.zrax)
    with concurrent.futures.ThreadPoolExecutor(WORKERS) as pool:
        rows = list(pool.map(lambda item: check(zrax, text_dir, item), items))
    with open(os.path.join(args.out, "results.tsv"), "w") as f:
        f.write("\t".join(rows[0]) + "\n")
        for row in rows:
            f.write("\t".join(str(v) for v in row.values()) + "\n")
    summarize(rows)


if __name__ == "__main__":
    main()
