#!/usr/bin/env python3
"""Build a golden corpus from the fw1 firmware set, in build_corpus.py's layout.

Labels never come from zrax output. Sources and their evidence:

  fw1-elf        code sections / executable PT_LOADs of fw1 ELF files (e_machine)
  fw1-elf-data   .rodata/.data of fw1 ELF files                    -> neg_rodata
  fw1-pil        Qualcomm split segments (.bNN) whose .mdt/.b00 program header
                 marks them executable (class from the header's e_machine)
  fw1-pil-data   split segments marked non-executable, not hash     -> neg_rodata
  fw1-pcm        8-bit PCM by adjacent-sample smoothness >= 0.6     -> neg_media
  fw1-cal        swfl_*.159_010_001 calibration maps, QCA board data -> neg_table
  fw1-8051       raw images with an 8051 reset + interrupt vector table -> i8051
  fw1-cortexm    raw images with a Cortex-M vector table           -> thumb
  fw1-rom        ROM families whose platform fixes the CPU (Z80, SH-4 LE)

Groups are firmware families, so near-duplicate builds stay on one side of
the train/test split.

Output layout: <out>/samples/<class>/<id>.bin and <out>/manifest.jsonl.

Usage: fw1_corpus.py --repo REPO --fw FW1_DIR --work SCRATCH_DIR --out OUT
       [--exclude-ids BASE_MANIFEST]   (drop samples already in another corpus)
"""
import argparse
import csv
import importlib.util
import json
import os
import re
import struct

ROM_FAMILIES = [
    # (regex on original name, class, family)
    (r"^trd\d", "z80", "trdos"),
    (r"^mf(1|3|128)_", "z80", "multiface"),
    (r"^opus-", "z80", "opus"),
    (r"^(disciple|plusd)_", "z80", "disciple"),
    (r"^if1-\d\.rom$", "z80", "interface1"),
    (r"^rcz80_std_|^rc_std_", "z80", "rc2014"),
    (r"^vzdos", "z80", "vzdos"),
    (r"^cpcados\.rom$", "z80", "amsdos"),
    (r"^tuberom_z80\.rom$", "z80", "acorn-tube"),
    (r"^z80_(120|200)\.rom$", "z80", "z80-rom"),
    (r"^epr-2(13[23]\d|157\d|158\d|180[12]|360\d|3610)[a-z]?(_multi)?\.ic27$", "sh", "naomi-bios"),
]
EM_CLASS = {164: "hexagon", 183: "aarch64", 94: "xtensa"}
PIL_NAME = re.compile(r"^(?P<base>.+?)\.(?P<ext>mdt|b(?P<idx>\d\d))(_\d+)?$", re.I)


def load_build_corpus(repo):
    spec = importlib.util.spec_from_file_location("build_corpus", os.path.join(repo, "scripts", "build_corpus.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def family(name):
    """Firmware family of a file name: timestamps, versions and segment suffixes removed."""
    stem = re.sub(r"_\d{10}$", "", name)
    stem = re.sub(r"\.(b\d\d|mdt|mbn|elf|bin|img|fw)$", "", stem, flags=re.I)
    stem = re.sub(r"[_\-. ]?v?\d[\d._]*$", "", stem)
    return stem.lower() or name.lower()


def read_rows(path):
    return list(csv.DictReader(open(path), delimiter="\t"))


def pil_headers(rows, fw):
    """(base, segment index, filesz) -> (p_flags, e_machine) from every .mdt/.b00 ELF header."""
    index = {}
    for r in rows:
        m = PIL_NAME.match(r["name"])
        if not m or m.group("ext").lower() not in ("mdt", "b00"):
            continue
        with open(os.path.join(fw, r["sha"]), "rb") as f:
            d = f.read(1 << 16)
        if d[:4] != b"\x7fELF":
            continue
        is_64 = d[4] == 2
        e = "<" if d[5] == 1 else ">"
        machine = struct.unpack_from(e + "H", d, 0x12)[0]
        if is_64:
            phoff = struct.unpack_from(e + "Q", d, 0x20)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", d, 0x36)
        else:
            phoff = struct.unpack_from(e + "I", d, 0x1C)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", d, 0x2A)
        for i in range(phnum):
            ph = d[phoff + i * phentsize: phoff + (i + 1) * phentsize]
            if len(ph) < (56 if is_64 else 32):
                break
            if is_64:
                _, flags, _, _, _, filesz = struct.unpack_from(e + "IIQQQQ", ph)
            else:
                _, _, _, _, filesz, _, flags = struct.unpack_from(e + "7I", ph)
            if filesz:
                key = (m.group("base").lower(), i, filesz)
                index.setdefault(key, set()).add((flags, machine))
    return index


def sh_le_density(data):
    """Halfword-aligned little-endian SuperH `rts` (000B) per MiB; ARM code measures < 25."""
    count = pos = 0
    while (pos := data.find(b"\x0b\x00", pos)) >= 0:
        count += pos % 2 == 0
        pos += 1
    return count / max(len(data) / 2**20, 1 / 16)


RETURN_BLOCK = 4096
# MIPS ELF e_flags ASE bit (binutils include/elf/mips.h); build_corpus.py's
# elf_class ignores it and would label microMIPS code as MIPS32.
EF_MIPS_MICROMIPS = 0x0200_0000


def has_return(cls, block):
    """True if block holds a return instruction of cls at instruction alignment.

    Executable segments of firmware ELFs (no section headers) also carry
    tables; a 4 KiB block of real code nearly always returns somewhere.
    Classes without an entry here are not filtered.
    """
    if cls == "aarch64":
        words = struct.unpack_from(f"<{len(block) // 4}I", block)
        return any(w in (0xD65F03C0, 0xD65F0BFF, 0xD65F0FFF) for w in words)
    if cls == "hexagon":
        words = struct.unpack_from(f"<{len(block) // 4}I", block)
        # jumpr r31 / dealloc_return with any packet parse bits (14-15)
        return any(w & ~0xC000 in (0x529F0000, 0x961E001E) for w in words)
    if cls == "arm":
        words = struct.unpack_from(f"<{len(block) // 4}I", block)
        return any(w & 0x0FFFFFFF == 0x012FFF1E or w & 0x0FFF8000 == 0x08BD8000 for w in words)
    if cls == "thumb":
        halves = struct.unpack_from(f"<{len(block) // 2}H", block)
        return any(h == 0x4770 or h & 0xFF00 == 0xBD00 for h in halves)
    if cls == "xtensa":
        return any(block.find(p) >= 0 for p in (b"\x0d\xf0", b"\x1d\xf0", b"\x80\x00\x00", b"\x90\x00\x00"))
    if cls in ("micromipsel", "micromips"):
        halves = struct.unpack_from(("<" if cls == "micromipsel" else ">") + f"{len(block) // 2}H", block)
        # jr16 ra, jrc ra, jraddiusp
        return any(h in (0x459F, 0x45BF) or h & 0xFFE0 == 0x4700 for h in halves)
    if cls == "mipsel":
        words = struct.unpack_from(f"<{len(block) // 4}I", block)
        return 0x03E00008 in words
    return True


def code_blocks(cls, data):
    """The 4 KiB blocks of data that contain a return instruction of cls, concatenated."""
    kept = [data[i:i + RETURN_BLOCK] for i in range(0, len(data), RETURN_BLOCK)]
    return b"".join(b for b in kept if len(b) >= 64 and has_return(cls, b[:len(b) - len(b) % 4]))


def has_8051_vectors(head, size):
    if len(head) < 0x30 or head[0] != 0x02:
        return False
    target = (head[1] << 8) | head[2]
    vectors = sum(head[a] in (0x02, 0x32) for a in (0x03, 0x0B, 0x13, 0x1B, 0x23))
    return 0x30 <= target < size and vectors >= 2


def has_cortexm_vectors(head):
    if len(head) < 32:
        return False
    words = struct.unpack_from("<8I", head)
    sp, reset = words[0], words[1]
    handlers = [w for w in words[1:8] if w]
    return (0x1FF00000 <= sp <= 0x20400000 and sp % 4 == 0 and handlers
            and all(w % 2 for w in handlers) and all(abs(w - reset) <= 0x100000 for w in handlers))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--fw", required=True)
    ap.add_argument("--work", required=True, help="dir with all.tsv, heads.tsv, smooth.tsv")
    ap.add_argument("--out", required=True)
    ap.add_argument("--exclude-ids", help="manifest.jsonl whose sample ids are dropped from this corpus")
    ap.add_argument("--test-mod", type=int, default=5)
    a = ap.parse_args()

    bc = load_build_corpus(a.repo)
    corpus = bc.Corpus(a.out)
    if a.exclude_ids:
        # Corpus._write skips ids it has seen: pre-seed with the base corpus's samples.
        for line in open(a.exclude_ids):
            row = json.loads(line)
            path = os.path.join(os.path.dirname(a.exclude_ids), "samples", row["class"], row["id"] + ".bin")
            with open(path, "rb") as f:
                corpus.seen.add(bc.hashlib.sha1(f.read()).hexdigest())

    rows = read_rows(os.path.join(a.work, "all.tsv"))
    heads = {r["sha"]: r for r in read_rows(os.path.join(a.work, "heads.tsv"))}
    smooth = {r["sha"]: r for r in read_rows(os.path.join(a.work, "smooth.tsv"))}
    pil = pil_headers(rows, a.fw)
    tally = {}

    def add(cls, group, source, data):
        if cls is None:
            return
        before = len(corpus.rows)
        corpus.add(cls, group, source, data)
        tally[(source, cls)] = tally.get((source, cls), 0) + (len(corpus.rows) - before)

    for r in rows:
        path = os.path.join(a.fw, r["sha"])
        name = r["name"]
        size = int(r["size"])
        group = "fw1:" + family(name)
        head = heads[r["sha"]]

        if head["kind"] == "elf":
            with open(path, "rb") as f:
                d = f.read()
            parsed = bc.elf_code(d)
            if parsed and parsed[4]:
                machine, le, is_64, flags, chunks = parsed
                if machine == 40:
                    cls = bc.arm_mode(chunks)
                    cls = cls + "eb" if cls and not le else cls
                elif machine == 8 and flags & EF_MIPS_MICROMIPS:
                    cls = "micromipsel" if le else "micromips"
                else:
                    cls = bc.elf_class(machine, le, is_64, flags)
                for chunk in chunks:
                    add(cls, group, "fw1-elf", code_blocks(cls, chunk) if cls else chunk)
            for chunk in bc.elf_data(d):
                add("neg_rodata", group, "fw1-elf-data", chunk)
            continue

        m = PIL_NAME.match(name)
        if m and m.group("idx") and m.group("idx") != "00":
            hits = pil.get((m.group("base").lower(), int(m.group("idx")), size))
            if hits and len(hits) == 1:
                flags, machine = next(iter(hits))
                with open(path, "rb") as f:
                    d = f.read()
                if (flags >> 24) & 7 == 2:
                    continue  # hash segment: signatures and certificates, opaque
                if flags & 1:
                    cls = bc.arm_mode([d]) if machine == 40 else EM_CLASS.get(machine)
                    add(cls, group, "fw1-pil", code_blocks(cls, d) if cls else d)
                else:
                    add("neg_rodata", group, "fw1-pil-data", d)
                continue

        if r["format"] != "raw":
            continue
        s = smooth.get(r["sha"])
        if s and s["smooth"] and float(s["smooth"]) >= 0.6 and int(s["pairs"]) > 500:
            with open(path, "rb") as f:
                add("neg_media", "fw1:pcm-" + re.split(r"[_\-. ]", family(name))[0], "fw1-pcm", f.read())
            continue
        if re.match(r"swfl_.*\.159_010_001$", name) or re.match(r"board(-2)?\.bin", name):
            with open(path, "rb") as f:
                add("neg_table", group, "fw1-cal", f.read())
            continue
        rom = next(((cls, fam) for pat, cls, fam in ROM_FAMILIES if re.search(pat, name, re.I)), None)
        if rom:
            with open(path, "rb") as f:
                d = f.read()
            if rom[0] != "sh" or sh_le_density(d) >= 300:
                add(rom[0], "fw1:" + rom[1], "fw1-rom", d)
            continue
        with open(path, "rb") as f:
            first = f.read(64)
        if has_8051_vectors(first, size):
            with open(path, "rb") as f:
                add("i8051", group, "fw1-8051", f.read())
        elif has_cortexm_vectors(first):
            with open(path, "rb") as f:
                add("thumb", group, "fw1-cortexm", f.read())

    corpus.finish(a.test_mod)
    for (source, cls), n in sorted(tally.items()):
        print(f"{source:14} {cls or '-':12} {n:6}")
    splits = {}
    for row in corpus.rows:
        splits[(row["class"], row["split"])] = splits.get((row["class"], row["split"]), 0) + 1
    print("samples", len(corpus.rows), "by class/split:", dict(sorted(splits.items())))


if __name__ == "__main__":
    main()
