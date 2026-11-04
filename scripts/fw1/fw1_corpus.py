#!/usr/bin/env python3
"""Build a golden corpus from the fw1 firmware set, in build_corpus.py's layout.

Labels never come from zrax output. Sources and their evidence:

  fw1-elf        code sections / executable PT_LOADs of fw1 ELF files (e_machine)
  fw1-elf-data   .rodata/.data of fw1 ELF files                    -> neg_rodata
  fw1-pil        Qualcomm split segments (.bNN) whose .mdt/.b00 program header
                 marks them executable (class from the header's e_machine)
  fw1-pil-data   split segments marked non-executable, not hash, without code
                 idioms                                              -> neg_rodata
  fw1-pil-embedded  non-executable segments holding another core's code, by
                 strong return idioms (embedded_code_class)          -> that class
  fw1-pcm        8-bit PCM by adjacent-sample smoothness >= 0.6     -> neg_media
  fw1-ecu96      engine ECU dumps (tuning-tool names) dense with MCS-96
                 register-file immediate loads -> mcs96, grouped by family
  fw1-cal        swfl_*.159_010_001 calibration maps, QCA board data -> neg_table
  fw1-table16    VW swfl blocks of smooth 16-bit values without code idioms -> neg_table
  fw1-amdgpu-ucode  AMD GPU command-processor microcode (F32, no model class) -> neg_table
  fw1-8051       raw images with an 8051 reset + interrupt vector table -> i8051
  fw1-cortexm    raw images with a Cortex-M vector table           -> thumb
  fw1-rom        ROM families whose platform fixes the CPU (Z80, SH-4 LE)
  fw1-mame-code  program ROMs of MAME sets in MAME_CODE_SETS -> that class
                 (held out: file-level test only)
  fw1-mame-unsp  program and system ROMs that MAME maps into a µ'nSP SoC's
                 address space (UNSP_SETS): the instruction words reached
                 from the vectors (unsp_trace.py) -> unsp, grouped by ROM family;
                 64 KiB blocks of them with no traced instruction -> neg_media
                 (fw1-mame-unsp-data, same group); a ROM without a vector table
                 gives only such blocks and is expected to give no ISA
  fw1-mame       ROMs whose SHA-1 MAME lists in a graphics or sound region
                 (mame_match.tsv from mame_regions.py) -> neg_pixels (graphics)
                 or neg_media (sound), grouped by MAME set
  fw1-optionrom  PCI option ROM images whose PCI data structure says x86 -> x86_16
                 (held out: a test of the real-mode class, not training data)
  fw1-realos     raw images that link Fujitsu's REALOS/FR (its banner) -> fr30,
                 the 4 KiB blocks holding an FR RET, grouped by image family
  fw1-hex        Intel HEX files whose names name a Z8 program -> z8

XTIDE Universal BIOS ROMs and PCI option ROMs are left out: they are the
held-out test of the real-mode class (golden_files.py).

Groups are firmware families, so near-duplicate builds stay on one side of
the train/test split.

Output layout: <out>/samples/<class>/<id>.bin and <out>/manifest.jsonl.

Usage: fw1_corpus.py --repo REPO --fw FW1_DIR --work SCRATCH_DIR --out OUT
       [--exclude-ids BASE_MANIFEST]   (drop samples already in another corpus)
"""
import argparse
import collections
import csv
import dataclasses
import functools
import importlib.util
import json
import os
import re
import struct
import typing

ROM_FAMILIES = [
    # (regex on original name, class, family)
    (r"^trd\d", "z80", "trdos"),
    (r"^mf(1|3|128)_", "z80", "multiface"),
    # Opus Discovery (ZX Spectrum) ROMs are numbered; `opus-ddos*` is Slogger's
    # DDOS for the BBC Micro ("DDOS Copyright (c) 1984 Slogger"), 6502 code.
    (r"^opus-\d", "z80", "opus"),
    (r"^(disciple|plusd)_", "z80", "disciple"),
    (r"^if1-\d\.rom$", "z80", "interface1"),
    (r"^rcz80_std_|^rc_std_", "z80", "rc2014"),
    (r"^vzdos", "z80", "vzdos"),
    (r"^cpcados\.rom$", "z80", "amsdos"),
    (r"^tuberom_z80\.rom$", "z80", "acorn-tube"),
    (r"^z80_(120|200)\.rom$", "z80", "z80-rom"),
    (r"^epr-2(13[23]\d|157\d|158\d|180[12]|360\d|3610)[a-z]?(_multi)?\.ic27$", "sh", "naomi-bios"),
]
# `mn10200_code1.bin` is not labelled by its name: its bytes are
# little-endian MIPS R3000 code (`lui at,0x1f80; sw t0,0x1010(at)` writes the
# PlayStation BIOS-ROM delay register), so the name is wrong (2026-11-04).
# Intel HEX files whose names name a Zilog Z8 program (monitors, BASIC, Forth).
Z8_HEX = re.compile(r"(?i)(z8[-_]forth|z8_mon|unimon_z8|basic_compiler_for_z8|rz8-40)")
# Linux ihex2fw binary records (include/linux/ihex.h): big-endian address
# (4) and length (2), the data, the next record at ALIGN(6 + length, 4), and
# a zero-length record in the last 6 bytes. Records in the FF: segment load
# into MCS-251 code memory (Intel 8XC251 user's guide, memory space FF:0000h-
# FF:FFFFh), which the 8051 does not have; fw1 holds one such file, the
# Edgeport `down2.fw` that Linux io_edgeport.c loads only on 80251 boards.
IHEX2FW_HEADER = 6
IHEX2FW_ALIGN = 4
MCS251_CODE_SEGMENT = 0xFF
MCS251_MIN_CODE_BYTES = 1024
# Largest file read for the check (our choice: Linux USB firmware is small).
IHEX2FW_MAX_BYTES = 1 << 20
# PCI option ROM: `55 AA`, PCI data structure pointer at 0x18; the
# structure (`PCIR`) holds the image length in 512 B units at 0x10 and the
# code type at 0x14, 0 meaning PC-AT x86 (PCI Firmware Specification 3.0,
# section 5.1.2).
PCIR_CODE_X86 = 0
# Bytes of an option ROM image taken as real-mode code (our choice).
OPTION_ROM_CODE_SIZE = 32 * 1024
EM_CLASS = {164: "hexagon", 183: "aarch64", 94: "xtensa"}
PIL_NAME = re.compile(r"^(?P<base>.+?)\.(?P<ext>mdt|b(?P<idx>\d\d))(_\d+)?$", re.I)


def load_build_corpus(repo):
    spec = importlib.util.spec_from_file_location("build_corpus", os.path.join(repo, "scripts", "build_corpus.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_unsp_trace():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("unsp_trace", os.path.join(here, "unsp_trace.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@functools.lru_cache(maxsize=1)
def unsp_samples(path):
    """(code, data blocks) of the µ'nSP ROM at path, in the byte order
    (little- or big-endian words) that traces more code.

    `code` is the traced instruction words as little-endian bytes. `data
    blocks` are up to UNSP_DATA_BLOCKS evenly spaced UNSP_DATA_BLOCK_WORDS
    blocks, after the first, in which the trace (with its scan of every
    `push` word) finds no instruction and that are not fill: game graphics,
    audio and tables (our reading: no function starts in them).
    """
    trace = load_unsp_trace()
    with open(path, "rb") as f:
        data = f.read()
    count = len(data) // 2
    best = None
    for order in ("<", ">"):
        words = struct.unpack(f"{order}{count}H", data[:2 * count])
        code, _kept, _dropped = trace.trace(words)
        if best is None or sum(code.values()) > sum(best[1].values()):
            best = (words, code)
    words, code = best
    with_code = {pc // UNSP_DATA_BLOCK_WORDS for pc in code}
    block_bytes = 2 * UNSP_DATA_BLOCK_WORDS
    candidates = []
    for block in range(1, count // UNSP_DATA_BLOCK_WORDS):
        contents = data[block * block_bytes:(block + 1) * block_bytes]
        if block not in with_code and len(set(contents)) > UNSP_FILL_DISTINCT_BYTES:
            candidates.append(contents)
    step = max(1, len(candidates) // UNSP_DATA_BLOCKS)
    return trace.traced_bytes(words, code), candidates[::step][:UNSP_DATA_BLOCKS]


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


# An executable PIL segment is labelled code only if its bytes show code:
# one that is at least PIL_FILL_SHARE fill (its two most common 32-bit words)
# with under PIL_MIN_CONTENT_BYTES of other bytes is not. In the fw1 set
# these are four `cdsp.b03` segments (zeros and 0x7F7F7F7F around a table and
# the string "face_process", 196-236 B) and `wpss.b03` (104 B of Hexagon code
# before 998 Hexagon NOP packets, less than a window reads once the fill is
# skipped as padding); 2026-11-04. Segments with less fill keep their label:
# 220-byte segments holding 192 B of code read as Hexagon, and `adsp.b02`
# (97% fill) holds 90 KB of code. Our rule.
PIL_FILL_SHARE = 0.9
PIL_MIN_CONTENT_BYTES = 1024


def is_fill_segment(data):
    """Whether a segment is fill with too little other content to show code
    (PIL_FILL_SHARE, PIL_MIN_CONTENT_BYTES)."""
    count = len(data) // 4
    if count == 0:
        return True
    words = struct.unpack_from(f"<{count}I", data)
    fill = sum(n for _, n in collections.Counter(words).most_common(2))
    content_bytes = 4 * (count - fill)
    return fill >= PIL_FILL_SHARE * count and content_bytes < PIL_MIN_CONTENT_BYTES


# Fujitsu's real-time OS for its FR CPU family: an image that links it runs
# on an FR core. In the fw1 set, raw images with this banner are Nikon
# camera firmware (D300S, D3S, D90, D3100) and `B3000111.bin` and
# `IMG_LOKI-212/213.bin`, 7 to 16 MiB each (2026-11-04). FR30's only other
# samples are GCC output, and Softune-built firmware read as big-endian
# SuperH in a quarter of its windows.
REALOS_FR_BANNER = b"REALOS/FR is Realtime OS for FR Family"
REALOS_MIN_BYTES = 1 << 20


# NAOMI BIOS images below this `rts` density are not taken as SH-4 code;
# ARM code measures under 25 per MiB, the BIOS images 700 and more.
SH_MIN_RTS_PER_MIB = 300


def sh_le_density(data):
    """Halfword-aligned little-endian SuperH `rts` (000B) per MiB; ARM code measures < 25."""
    count = pos = 0
    while (pos := data.find(b"\x0b\x00", pos)) >= 0:
        count += pos % 2 == 0
        pos += 1
    return count / max(len(data) / 2**20, 1 / 16)


RETURN_BLOCK = 4096


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
    if cls == "fr30":
        halves = struct.unpack_from(f">{len(block) // 2}H", block)
        # RET and RET:D (FR30 instruction set: 1001 0111 0010 0000, 1001 1111 0010 0000)
        return any(h in (0x9720, 0x9F20) for h in halves)
    if cls in ("micromipsel", "micromips"):
        halves = struct.unpack_from(("<" if cls == "micromipsel" else ">") + f"{len(block) // 2}H", block)
        # jr16 ra, jrc ra, jraddiusp
        return any(h in (0x459F, 0x45BF) or h & 0xFFE0 == 0x4700 for h in halves)
    if cls == "sh":
        halves = struct.unpack_from(f"<{len(block) // 2}H", block)
        return 0x000B in halves  # rts
    if cls == "tricore":
        halves = struct.unpack_from(f"<{len(block) // 2}H", block)
        return 0x9000 in halves  # ret16
    if cls == "mipsel":
        words = struct.unpack_from(f"<{len(block) // 4}I", block)
        return 0x03E00008 in words
    if cls == "msp430":
        halves = struct.unpack_from(f"<{len(block) // 2}H", block)
        return 0x4130 in halves or 0x1300 in halves  # ret (mov @sp+,pc), reti
    return True


def code_blocks(cls, data):
    """The 4 KiB blocks of data that contain a return instruction of cls, concatenated."""
    kept = [data[i:i + RETURN_BLOCK] for i in range(0, len(data), RETURN_BLOCK)]
    return b"".join(b for b in kept if len(b) >= 64 and has_return(cls, b[:len(b) - len(b) % 4]))


def ihex2fw_records(data):
    """(address, data) of each Linux ihex2fw record, or None when `data` is
    not a complete record list."""
    records = []
    pos = 0
    last = len(data) - IHEX2FW_HEADER
    while 0 <= pos <= last:
        address = int.from_bytes(data[pos:pos + 4], "big")
        length = int.from_bytes(data[pos + 4:pos + IHEX2FW_HEADER], "big")
        if length == 0:
            return records if pos == last and records else None
        end = pos + IHEX2FW_HEADER + length
        if end > len(data):
            return None
        records.append((address, data[pos + IHEX2FW_HEADER:end]))
        pos = (end + IHEX2FW_ALIGN - 1) // IHEX2FW_ALIGN * IHEX2FW_ALIGN
    return None


def mcs251_code(data):
    """The records of a Linux ihex2fw file that load in the MCS-251 code
    segment, in address order; empty for any other file."""
    records = ihex2fw_records(data) or []
    code = [body for address, body in sorted(records) if address >> 16 == MCS251_CODE_SEGMENT]
    joined = b"".join(code)
    return joined if len(joined) >= MCS251_MIN_CODE_BYTES else b""


def intel_hex_bytes(text):
    """Data records of an Intel HEX file in address order (gaps not filled);
    empty for a malformed file."""
    records = {}
    base = 0
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith(b":"):
            continue
        try:
            raw = bytes.fromhex(line[1:].decode("ascii"))
        except ValueError:
            return b""
        if len(raw) < 5 or len(raw) != raw[0] + 5 or sum(raw) & 0xFF:
            return b""
        count, address, kind = raw[0], (raw[1] << 8) | raw[2], raw[3]
        if kind == 0:
            records[base + address] = raw[4:4 + count]
        elif kind == 2:
            base = int.from_bytes(raw[4:6], "big") << 4
        elif kind == 4:
            base = int.from_bytes(raw[4:6], "big") << 16
    return b"".join(records[a] for a in sorted(records))


def pci_x86_image(data):
    """The first image of a PCI option ROM whose PCI data structure says x86
    code, or None."""
    if len(data) < 0x1C or data[:2] != b"\x55\xaa":
        return None
    pcir = int.from_bytes(data[0x18:0x1A], "little")
    if data[pcir:pcir + 4] != b"PCIR" or len(data) < pcir + 0x18:
        return None
    length = int.from_bytes(data[pcir + 0x10:pcir + 0x12], "little") * 512
    if data[pcir + 0x14] != PCIR_CODE_X86 or not 0 < length <= len(data):
        return None
    # Initialization code follows the entry jump; fonts and tables sit
    # further into the image.
    return data[:min(length, OPTION_ROM_CODE_SIZE)]


# Return-instruction idioms per KiB above which a segment the host marks
# non-executable is taken to hold another core's firmware (sensor-hub and
# fingerprint-MCU images inside Qualcomm images): not data, and not labelled.
# Data segments measure a median of 0.02 (fw1 audit, 2026-11-04).
EMBEDDED_CODE_RETURNS_PER_KIB = 1.0
IDIOM_CLASSES = ("thumb", "arm", "aarch64", "hexagon", "xtensa", "mipsel", "micromipsel", "tricore", "sh", "msp430")
# A 4 KiB block whose most common byte covers this share is fill; segments
# are measured without it, since zero-filled data dilutes the idioms of the
# code beside it (Goodix segments are 88% zeros).
FILL_SHARE = 0.9


def is_fill(block):
    return max(block.count(b) for b in set(block)) >= FILL_SHARE * len(block)


def content_blocks(data):
    """The 4 KiB blocks of data that are not fill, in order."""
    blocks = (data[i:i + RETURN_BLOCK] for i in range(0, len(data), RETURN_BLOCK))
    return [b[:len(b) - len(b) % 4] for b in blocks if len(b) >= 64 and not is_fill(b)]


def embeds_code(data):
    """True if any ISA's return idioms are dense enough to be code, measured
    over the blocks that are not fill: at least half of them return, and
    the idioms reach EMBEDDED_CODE_RETURNS_PER_KIB."""
    return embedded_code_class(data) is not None


def embedded_code_class(data):
    """The idiom class whose return idioms mark data as code, or None: dense
    enough over the whole non-fill content, or in one region of it (another
    core's firmware is one contiguous image inside a larger data segment)."""
    blocks = content_blocks(data)
    content = b"".join(blocks)
    if len(content) < 1024:
        return None
    for cls in IDIOM_CLASSES:
        returning = sum(has_return(cls, b) for b in blocks)
        if 2 * returning >= len(blocks) and idiom_density(cls, content) >= EMBEDDED_CODE_RETURNS_PER_KIB:
            if cls == "thumb" and thumb_call_density(content) < EMBEDDED_CODE_RETURNS_PER_KIB:
                continue
            return cls
    if idiom_density("riscv", content) >= EMBEDDED_CODE_RETURNS_PER_KIB:
        return "riscv"
    return embedded_code_region_class(blocks)


# Region test: idioms per KiB in REGION_BLOCKS consecutive non-fill blocks.
# Only idioms that data rarely forms count: Thumb returns paired with their
# pushes, RISC-V, MSP430, AArch64, ARM, Hexagon and MIPS returns, and Xtensa
# `entry` together with `ret.n`/`retw.n`, SH `sts.l pr,@-r15` paired with
# (Thumb also needs BL calls at the same density: Hexagon segments of
# float16 tables reach 6-7 paired 0xB5xx/0xBDxx per KiB, real Thumb regions
# 9-31 BL per KiB and the tables none),
# `lds.l @r15+,pr` (`shframe`). SH `rts` (0x000B) and TriCore
# `ret16` (0x9000) are also small integers and reach 3-4 per KiB in data
# segments. Real embedded firmware measures 2.8 (RISC-V, Goodix) to 10
# (Thumb, fingerprint TAs); data segments without code stay below 1
# (fw1 audit, 2026-11-04).
# Idiom class -> corpus class for labelling embedded code. RISC-V returns
# do not tell RV32 from RV64, and `sh`/`tricore` idioms are too weak.
EMBEDDED_CODE_CLASS = {"thumb": "thumb", "arm": "arm", "aarch64": "aarch64", "hexagon": "hexagon",
                       "xtensa": "xtensa", "mipsel": "mipsel", "msp430": "msp430", "shframe": "sh"}
# Files whose smoothness passes the PCM test but whose bytes decode as code
# (manual disassembly; not labelled either way).
CODE_NOT_PCM = {
    # 0x1000: SHLD E089h; LHLD E074h; INX H; SHLD E074h; ... RET. MAME's
    # pce/tourvis.cpp runs it on an I8085A (TourVision BIOS).
    "v4-40.ic29": "i8085",
}
REGION_BLOCKS = 4
REGION_RETURNS_PER_KIB = 2.0
REGION_CLASSES = ("thumb", "riscv", "msp430", "aarch64", "arm", "hexagon", "mipsel", "shframe")


def thumb_call_density(data):
    """Thumb BL instruction pairs per KiB (first halfword 0xF000-0xF7FF, second
    with bits 15, 14 and 12 set). Code calls; float16 tables, whose negative
    values also look like push/pop pairs, never form them."""
    halves = struct.unpack_from(f"<{len(data) // 2}H", data)
    calls = sum(1 for a, b in zip(halves, halves[1:]) if 0xF000 <= a <= 0xF7FF and b & 0xD000 == 0xD000)
    return calls / (len(data) / 1024)


def xtensa_entry_density(data):
    """Windowed-ABI `entry a1, n` instructions per KiB (byte 0x36, then a
    byte whose low nibble names a1)."""
    entries = sum(1 for i in range(len(data) - 2) if data[i] == 0x36 and data[i + 1] & 0x0F == 0x01)
    return entries / (len(data) / 1024)


def embedded_code_region_class(blocks):
    """The class of the densest qualifying code region of the blocks, or None."""
    for start in range(max(1, len(blocks) - REGION_BLOCKS + 1)):
        region = b"".join(blocks[start:start + REGION_BLOCKS])
        if len(region) < REGION_BLOCKS * RETURN_BLOCK // 2:
            continue
        for cls in REGION_CLASSES:
            if idiom_density(cls, region) < REGION_RETURNS_PER_KIB:
                continue
            if cls == "thumb" and thumb_call_density(region) < REGION_RETURNS_PER_KIB:
                continue
            return cls
        if (idiom_density("xtensa", region) >= REGION_RETURNS_PER_KIB
                and xtensa_entry_density(region) >= REGION_RETURNS_PER_KIB):
            return "xtensa"
    return None


def idiom_density(cls, data):
    """Return idioms of cls per KiB of data."""
    halves = struct.unpack_from(f"<{len(data) // 2}H", data)
    words = struct.unpack_from(f"<{len(data) // 4}I", data)
    if cls == "thumb":
        # bx lr, and pop {..., pc} paired with push {..., lr} of the same
        # register list: a lone 0xBDxx is also the high half of a small
        # negative float32 (weight tables in fingerprint trusted apps).
        pushes = collections.Counter(h & 0xFF for h in halves if h & 0xFF00 == 0xB500)
        pops = collections.Counter(h & 0xFF for h in halves if h & 0xFF00 == 0xBD00)
        n = halves.count(0x4770) + sum(min(count, pushes[regs]) for regs, count in pops.items())
    elif cls == "arm":
        n = sum(1 for w in words if w & 0x0FFFFFFF == 0x012FFF1E)
    elif cls == "aarch64":
        n = words.count(0xD65F03C0)
    elif cls == "hexagon":
        n = sum(1 for w in words if w & ~0xC000 in (0x529F0000, 0x961E001E))
    elif cls == "xtensa":
        n = halves.count(0xF00D) + halves.count(0xF01D)
    elif cls in ("mipsel", "micromipsel"):
        n = words.count(0x03E00008) + halves.count(0x45BF)
    elif cls == "tricore":
        n = halves.count(0x9000)  # ret16
    elif cls == "sh":
        n = halves.count(0x000B)  # rts
    elif cls == "msp430":
        n = halves.count(0x4130) + halves.count(0x1300)  # ret, reti
    elif cls == "shframe":
        # sts.l pr,@-r15 paired with lds.l @r15+,pr: a function frame that
        # saves the return address; `rts` alone is also a small integer.
        n = min(halves.count(0x4F22), halves.count(0x4F26))
    elif cls == "riscv":
        # c.jr ra / c.ret (0x8082) and ret (jalr x0, 0(ra))
        n = halves.count(0x8082) + words.count(0x00008067)
    else:
        n = 0
    return n / (len(data) / 1024)


# Engine ECU dumps by their tuning-tool names: `.ORI`/`.BSH`/`.std` dumps and
# Bosch hardware numbers (0261 2xx xxx).
ECU_DUMP_NAME = re.compile(r"(\.ori$|\.bsh$|\.std$|0261\d{6}|motronic)", re.I)
ECU_MAX_BYTES = 1 << 20
# MCS-96 code loads its register file with immediates all the time:
# LD reg,#imm16 (A1 lo hi reg, reg even) and LDB reg,#imm8 (B1 imm reg), reg
# 0x18-0xFF ("8XC196Kx User's Manual", Intel 272258). Among the 930 ECU dumps
# of fw1, the 153 with at least 15 such loads per KiB include 152 that the
# code model reads as MCS-96; 8051 and C166 code holds at most 2.8 and 1.1
# (corpus samples, 2026-11-04). Bosch Motronic M3.x and M5.x, the source of
# most of them, run on i196 parts.
MCS96_MIN_LOADS_PER_KIB = 15.0


def mcs96_register_loads_per_kib(data):
    """MCS-96 immediate loads into the register file per KiB of data."""
    loads = sum(1 for i in range(len(data) - 3) if data[i] == 0xA1 and data[i + 3] >= 0x18 and data[i + 3] % 2 == 0)
    loads += sum(1 for i in range(len(data) - 2) if data[i] == 0xB1 and data[i + 2] >= 0x18)
    return 1024 * loads / max(len(data), 1)


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


@dataclasses.dataclass
class FileLabel:
    """The golden label of one fw1 file that is not an ELF image."""

    cls: str
    """Corpus class (`neg_*` for non-code)."""
    group: str
    """Firmware family; whole groups fall on one side of the split."""
    source: str
    """Corpus source tag."""
    label: str
    """Golden label name, as file-level scoring reports it."""
    load: typing.Callable[[], bytes]
    """The labelled bytes (filtered code blocks, decoded HEX, ...)."""
    held_out: bool = False
    """Only for testing: never added to the corpus."""
    part_size: int = 0
    """When set, the bytes are added as consecutive samples of at most this
    many bytes (traced code of one ROM can exceed the per-sample cap)."""
    data_blocks: typing.Optional[typing.Callable[[], list]] = None
    """Non-code blocks of the same file, added as UNSP_DATA_CLASS in the same group."""


# Held out of training entirely: XTIDE Universal BIOS option ROMs (real mode).
XTIDE = re.compile(r"^ide_(xt|xtp|at)\.bin,v")
PCM_SMOOTHNESS = 0.6
PCM_MIN_PAIRS = 500
# Tables of 16-bit values (calibration maps, waveforms): the share of
# adjacent little-endian 16-bit values (0x0000/0xFFFF and repeats skipped)
# that differ by less than 2048. Known code measures at most 0.35 (median
# 0.12); VW calibration blocks 0.69-0.74 (fw1 audit, 2026-11-04).
TABLE16_SMOOTHNESS = 0.6
TABLE16_STEP = 2048
TABLE16_MIN_PAIRS = 200
TABLE16_READ = 1 << 20
# AMD GPU command-processor microcode (gfx6 to gfx10.3) runs on AMD's F32
# micro engine, which no model class covers; reading it as PIC24 or x86 is
# a false claim. gfx11 MES/RS64 firmware is left out (linux-firmware
# amdgpu/radeon naming).
AMDGPU_CP_UCODE = re.compile(
    r"^(bonaire|hawaii|kabini|kaveri|mullins|topaz|tonga|carrizo|stoney|fiji|polaris1[012]|vegam|vega1[02]|vega20"
    r"|raven2?|picasso|renoir|arcturus|navi1[024]|sienna_cichlid|navy_flounder|dimgrey_cavefish|beige_goby|vangogh"
    r"|yellow_carp|green_sardine|aldebaran|cyan_skillfish)_(mec2?|me|pfp|ce)(_2)?\.bin(_\d+)?$")


def table16_smoothness(data):
    """The 16-bit table smoothness of data, or None with too few pairs."""
    words = struct.unpack_from(f"<{len(data) // 2}H", data)
    pairs = [(a, b) for a, b in zip(words, words[1:]) if a != b and a not in (0, 0xFFFF) and b not in (0, 0xFFFF)]
    if len(pairs) < TABLE16_MIN_PAIRS:
        return None
    return sum(1 for a, b in pairs if abs(a - b) < TABLE16_STEP) / len(pairs)


def file_label(row, fw_dir, pil, smooth, bc, mame=None):
    """The label of a fw1 file that is not an ELF image, or None.

    `pil` is `pil_headers` output, `smooth` maps sha to a smooth.tsv row,
    `bc` is the loaded build_corpus module (for `arm_mode`), `mame` maps sha
    to a mame_match.tsv row (`read_mame`).
    """
    path = os.path.join(fw_dir, row["sha"])
    name = row["name"]
    size = int(row["size"])
    group = "fw1:" + family(name)

    def read():
        with open(path, "rb") as f:
            return f.read()

    segment = PIL_NAME.match(name)
    if segment and segment.group("idx") and segment.group("idx") != "00":
        hits = pil.get((segment.group("base").lower(), int(segment.group("idx")), size))
        if hits and len(hits) == 1:
            flags, machine = next(iter(hits))
            if (flags >> 24) & 7 == 2:
                return None  # hash segment: signatures and certificates, opaque
            data = read()
            if flags & 1 and is_fill_segment(data):
                return None  # executable, but fill: no code to label
            if flags & 1:
                # Little-endian: so are all 300 PIL headers in fw1 (2026-11-04).
                cls = bc.arm_mode([data], True) if machine == 40 else EM_CLASS.get(machine)
                if cls is None:
                    return None
                return FileLabel(cls, group, "fw1-pil", "pil-code", lambda: code_blocks(cls, data))
            embedded = embedded_code_class(data)
            if embedded in EMBEDDED_CODE_CLASS:
                # Another core's firmware with idioms that fix its class:
                # its returning blocks are code of that class.
                cls = EMBEDDED_CODE_CLASS[embedded]
                return FileLabel(cls, group, "fw1-pil-embedded", "pil-embedded", lambda: code_blocks(cls, data))
            if embedded:
                return None  # code whose class the idioms do not fix (RISC-V: 32 or 64 bit)
            return FileLabel("neg_rodata", group, "fw1-pil-data", "pil-data", lambda: data)

    region = mame.get(row["sha"]) if mame else None
    if region and region["set"] in UNSP_SETS and region["region"] in UNSP_REGIONS:
        unsp_group = "mame-unsp:" + UNSP_SETS[region["set"]]
        if not unsp_samples(path)[0]:
            # No vector table, so no code is established (MAME's `pokermor`
            # ROM holds pixel data at the vectors): its blocks are data, and
            # the file is expected to give no ISA.
            return FileLabel(UNSP_DATA_CLASS, unsp_group, "fw1-mame-unsp", "mame-unsp-data", lambda: b"",
                             data_blocks=lambda: unsp_samples(path)[1])
        return FileLabel("unsp", unsp_group, "fw1-mame-unsp", "mame-unsp", lambda: unsp_samples(path)[0],
                         part_size=UNSP_PART_BYTES, data_blocks=lambda: unsp_samples(path)[1])
    if region and region["kind"] == "code" and region["set"] in MAME_CODE_SETS:
        cls = MAME_CODE_SETS[region["set"]]
        return FileLabel(cls, "mame:" + region["set"], "fw1-mame-code", "mame-code", read, held_out=True)
    if region and region["kind"] in ("graphics", "sound"):
        # MAME loads a dump with this SHA-1 into a graphics or sound region.
        cls = "neg_pixels" if region["kind"] == "graphics" else "neg_media"
        return FileLabel(cls, "mame:" + region["set"], "fw1-mame", "mame-" + region["kind"], read)
    if Z8_HEX.search(name):
        return FileLabel("z8", group, "fw1-hex", "z8-hex", lambda: intel_hex_bytes(read()))
    if name.endswith(".fw") and size <= IHEX2FW_MAX_BYTES and mcs251_code(read()):
        # MCS-251 Source-mode code from a vendor compiler, unlike the SDCC
        # output of the class (the only such code in fw1, so its own answer
        # is fit, not held out).
        return FileLabel("mcs251", group, "fw1-ihex2fw", "ihex2fw-mcs251", lambda: mcs251_code(read()))
    if XTIDE.match(name):
        return FileLabel("x86_16", "fw1:xtide", "fw1-xtide", "xtide", read, held_out=True)
    if row["format"] != "raw":
        if row["format"] == "pcioptionrom":
            image = pci_x86_image(read())
            if image:
                # Held out: as training data, the fonts and tables in option
                # ROMs taught the real-mode class to accept data (fw1 false
                # accepts 2.3% with them, 0.8% without; 2026-11-04).
                return FileLabel("x86_16", group, "fw1-optionrom", "optionrom", lambda: image, held_out=True)
        return None

    pcm = smooth.get(row["sha"])
    if pcm and pcm["smooth"] and float(pcm["smooth"]) >= PCM_SMOOTHNESS and int(pcm["pairs"]) > PCM_MIN_PAIRS:
        # Program ROMs that carry samples after the code are smooth overall
        # but hold a code region (SH-4 sound ROMs in the fw1 set).
        if name in CODE_NOT_PCM or embedded_code_region_class(content_blocks(read())):
            return None
        pcm_group = "fw1:pcm-" + re.split(r"[_\-. ]", family(name))[0]
        return FileLabel("neg_media", pcm_group, "fw1-pcm", "pcm", read)
    if ECU_DUMP_NAME.search(name) and size <= ECU_MAX_BYTES:
        data = read()
        if mcs96_register_loads_per_kib(data) >= MCS96_MIN_LOADS_PER_KIB:
            ecu_group = "fw1:ecu96-" + re.split(r"[_\-. ]", family(name))[0]
            return FileLabel("mcs96", ecu_group, "fw1-ecu96", "ecu96", lambda: data)
    if size >= REALOS_MIN_BYTES:
        data = read()
        if REALOS_FR_BANNER in data:
            # The name's first token: the camera model or image family.
            realos_group = "fw1:realos-" + re.split(r"[_\-. ]", name)[0].lower()
            return FileLabel("fr30", realos_group, "fw1-realos", "realos-fr", lambda: code_blocks("fr30", data))
    if re.match(r"swfl_.*\.159_010_001$", name) or re.match(r"board(-2)?\.bin", name):
        data = read()
        # Two VW blocks of this type are TriCore program flash (3.4 MB, 3.3
        # 16-bit RET per KiB; the 138 calibration maps hold at most 0.02).
        if embedded_code_class(data) == "tricore":
            return None
        return FileLabel("neg_table", group, "fw1-cal", "calibration", lambda: data)
    if name.startswith("swfl_"):
        # VW ECU flash blocks (TriCore/C166 controllers): smooth 16-bit
        # blocks without code idioms are calibration data. The smoothness
        # test alone is not code-safe: AVR and PIC14 opcodes, stored as
        # 16-bit words, reach it too.
        data = read()
        smooth16 = table16_smoothness(data[:TABLE16_READ])
        if smooth16 is not None and smooth16 >= TABLE16_SMOOTHNESS and not embeds_code(data):
            return FileLabel("neg_table", group, "fw1-table16", "table16", lambda: data)
    if AMDGPU_CP_UCODE.match(name):
        return FileLabel("neg_table", group, "fw1-amdgpu-ucode", "amdgpu-ucode", read)
    rom = next(((cls, fam) for pat, cls, fam in ROM_FAMILIES if re.search(pat, name, re.I)), None)
    if rom:
        cls, rom_family = rom
        rom_group = "fw1:" + rom_family
        if cls == "sh":
            data = read()
            if sh_le_density(data) < SH_MIN_RTS_PER_MIB:
                return None
            return FileLabel("sh", rom_group, "fw1-rom", "rom-" + rom_family, lambda: code_blocks("sh", data))
        return FileLabel(cls, rom_group, "fw1-rom", "rom-" + rom_family, read)
    with open(path, "rb") as f:
        first = f.read(64)
    if has_8051_vectors(first, size):
        return FileLabel("i8051", group, "fw1-8051", "8051-vectors", read)
    if has_cortexm_vectors(first):
        return FileLabel("thumb", group, "fw1-cortexm", "cortexm", lambda: code_blocks("thumb", read()))
    return None


# MAME sets whose program ROMs run on a CPU with a model class, read from the
# driver's machine configuration (no decryption in these drivers). Held out:
# file-level tests of the class, not training data.
MAME_CODE_SETS = {
    "ppatrol": "i8085",  # misc/statriv2.cpp: I8085A(config, m_maincpu, 12.44_MHz_XTAL)
}
# MAME sets whose program or system ROM is mapped flat into the address space
# of a µ'nSP SoC, by ROM family (versions of one system ROM are one group):
# vtech/vsmile.cpp (SPG24X; "sysrom" mapped from 0), vtech/vsmileb.cpp
# (SPG28X; "sysrom" from 0), tvgames/spg2xx_jakks_gkr.cpp and
# tvgames/spg2xx_lexibook.cpp (SPG24X "maincpu"),
# tvgames/generalplus_gpl16250_rom.cpp and generalplus_gpl16250_mobigo.cpp
# (GPL162xx "maincpu").
UNSP_SETS = {
    "vsmile": "vsmile", "vsmilem": "vsmile", "vsmilebsw": "vsmileb", "jak_dbza": "jakks",
    "pokermor": "lexibook", "bornk220": "bornkid", "mobigof": "mobigo",
}
UNSP_REGIONS = ("maincpu", "sysrom")
UNSP_PART_BYTES = 128 * 1024
# Data blocks of µ'nSP ROMs (unsp_samples): 64 KiB each, at most 8 per ROM;
# blocks of at most 16 distinct byte values are fill or near-fill.
UNSP_DATA_BLOCK_WORDS = 32 * 1024
UNSP_DATA_BLOCKS = 8
UNSP_FILL_DISTINCT_BYTES = 16
# The blocks are game graphics and audio. As `neg_rodata` they shifted that
# class away from ELF data: an ARM relocation table in a Qualcomm data
# segment (`fpc1145_fpctzappfingerprint.b07`) read as PIC24 (2026-11-04).
UNSP_DATA_CLASS = "neg_media"
MAME_MATCH_FIELDS = ("sha", "sha1", "kind", "region", "set", "rom", "macro", "isa", "confidence", "name")


def read_mame(path):
    """sha -> mame_match.tsv row (no header), or {} without the file."""
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        rows = (dict(zip(MAME_MATCH_FIELDS, line.rstrip("\n").split("\t"))) for line in f)
        return {r["sha"]: r for r in rows}


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
    mame = read_mame(os.path.join(a.work, "mame_match.tsv"))
    tally = {}

    def add(cls, group, source, data):
        if cls is None:
            return
        before = len(corpus.rows)
        corpus.add(cls, group, source, data)
        tally[(source, cls)] = tally.get((source, cls), 0) + (len(corpus.rows) - before)

    for r in rows:
        path = os.path.join(a.fw, r["sha"])
        group = "fw1:" + family(r["name"])
        if heads[r["sha"]]["kind"] == "elf":
            with open(path, "rb") as f:
                d = f.read()
            parsed = bc.elf_code(d)
            if parsed and parsed[4]:
                machine, le, is_64, flags, chunks = parsed
                if machine == 40:
                    cls = bc.arm_class(chunks, le, flags)
                else:
                    cls = bc.elf_class(machine, le, is_64, flags)
                for chunk in chunks:
                    add(cls, group, "fw1-elf", code_blocks(cls, chunk) if cls else chunk)
            for chunk in bc.elf_data(d):
                add("neg_rodata", group, "fw1-elf-data", chunk)
            continue
        label = file_label(r, a.fw, pil, smooth, bc, mame)
        if label and not label.held_out:
            data = label.load()
            part_size = label.part_size or max(len(data), 1)
            for at in range(0, len(data), part_size):
                add(label.cls, label.group, label.source, data[at:at + part_size])
            for block in label.data_blocks() if label.data_blocks else ():
                add(UNSP_DATA_CLASS, label.group, label.source + "-data", block)

    corpus.finish(a.test_mod)
    for (source, cls), n in sorted(tally.items()):
        print(f"{source:14} {cls or '-':12} {n:6}")
    splits = {}
    for row in corpus.rows:
        splits[(row["class"], row["split"])] = splits.get((row["class"], row["split"]), 0) + 1
    print("samples", len(corpus.rows), "by class/split:", dict(sorted(splits.items())))


if __name__ == "__main__":
    main()
