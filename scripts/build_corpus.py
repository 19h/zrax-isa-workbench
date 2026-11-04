#!/usr/bin/env python3
"""
Build the ground-truth code corpus used to train and evaluate the raw-code
ISA models (`src/heuristics/model.bin`).

Every sample is *executable code with a known ISA*: code sections pulled out
of ELF/PE objects (truth from e_machine / Machine, never from a filename),
compiler output from the armgen matrix, and a small set of raw firmware dumps
whose ISA is known from their provenance.

Samples are grouped by *program* (or by source file where there is no program
identity) and the train/test split is made per group, so the same program
compiled with different flags never lands on both sides of the split.

Output layout:
    <out>/samples/<class>/<id>.bin
    <out>/manifest.jsonl     one JSON object per sample:
                             {id, class, group, split, source, size}

Usage:
    scripts/build_corpus.py --out /path/to/corpus [--data /path/to/data] [--armgen /path/to/armgen]
                            [--gen DIR ...] [--raw CLASS=GLOB ...] [--raw-group CLASS=REGEX ...]
                            [--elf GLOB ...]
                            [--isadetect-per-arch N] [--isadetect-skip N]
"""

import argparse
import glob
import hashlib
import json
import os
import re
import struct
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# Per-sample cap: large .text sections are sampled, not taken whole, so one
# 20MB binary cannot dominate a class.
MAX_SAMPLE_BYTES = 256 * 1024
MIN_SAMPLE_BYTES = 256

# ---------------------------------------------------------------------------
# Truth mappings
# ---------------------------------------------------------------------------


# MIPS ELF e_flags ASE bit (binutils include/elf/mips.h): the code is microMIPS.
EF_MIPS_MICROMIPS = 0x0200_0000

# ARM ELF e_flags bit (binutils include/elf/arm.h; "ELF for the Arm
# Architecture", e_flags): a BE-8 executable, whose data are big-endian but
# whose instructions are little-endian. Big-endian ARM objects without it
# (relocatable objects, BE-32 executables) store big-endian instructions.
EF_ARM_BE8 = 0x0080_0000


def elf_class(machine, is_le, is_64, flags):
    """Map ELF e_machine (+ endianness/class) to a corpus class, or None."""
    m = machine
    if m == 3:
        return "x86"
    if m == 62:
        return "x86_64"
    if m == 40:
        return None  # A32 vs T32 is not knowable from the header; see arm_mode()
    if m == 183:
        return "aarch64"
    if m in (8, 10):
        if flags & EF_MIPS_MICROMIPS:
            return "micromipsel" if is_le else "micromips"
        if is_64:
            return "mips64el" if is_le else "mips64"
        return "mipsel" if is_le else "mips"
    if m == 20:
        return "ppc" if not is_le else None
    if m == 21:
        return "ppc64le" if is_le else "ppc64"
    if m in (2, 18):
        return "sparc"
    if m == 43:
        return "sparc64"
    if m == 22:
        return "s390x" if is_64 else "s390"
    if m == 243:
        return "riscv64" if is_64 else "riscv32"
    if m == 258:
        return "loongarch64" if is_64 else "loongarch32"
    if m == 164:
        return "hexagon"
    if m == 83:
        return "avr"
    if m == 105:
        return "msp430"
    if m == 44:
        return "tricore"
    if m == 244:
        return "lanai"
    if m == 247:
        return "bpf"
    if m == 4:
        return "m68k"
    if m == 42:
        return "sh" if is_le else "sheb"
    if m == 15:
        return "hppa"
    if m == 50:
        return "ia64"
    if m in (41, 0x9026):
        return "alpha"
    if m == 94:
        return "xtensa" if is_le else "xtensaeb"
    if m in (93, 195):
        return "arc"
    if m in (36, 87, 0x9080):
        return "v850"
    if m == 252:
        return "csky"
    if m == 39:
        # EM_MCORE: C-SKY V1 toolchains use the M·CORE machine number.
        return "cskyv1" if is_le else "cskyv1eb"
    if m in (46, 47, 48, 49):
        return "h8300"
    if m in (88, 0x9041):
        return "m32r"
    if m in (117, 120):
        return "m16c"
    if m == 167:
        return "nds32"
    if m == 144:
        return "pru"
    if m == 0x5441:
        return "frv"
    if m == 106:
        return "blackfin"
    if m == 197:
        return "rl78"
    if m == 173:
        return "rx"
    if m == 140:
        return "tic6000" if is_le else None
    if m == 141:
        return "tic28x"
    if m == 53:
        return "hcs12"
    if m == 70:
        return "hc11"
    if m == 84:
        return "fr30"
    if m == 89:
        return "mn10300"
    if m == 75:
        return "vax"
    if m == 19:
        return "i960"
    if m == 23:
        return "cellspu"
    if m == 256:
        return "kvx"
    if m == 165:
        return "i8051"
    if m == 71:
        return "hc08"
    if m == 72:
        return "hc05"
    if m == 69:
        return "hc16"
    if m == 68:
        return "st7"
    if m == 186:
        return "stm8"
    if m == 220:
        return "z80"
    if m == 65:
        return "pdp11"
    if m in (103, 177):
        return "cr16"
    if m == 104:
        return "f2mc16"
    if m == 162:
        return "r32c"
    return None


PE_MACHINES = {
    0x014C: "x86",
    0x8664: "x86_64",
    0xAA64: "aarch64",
    0x0200: "ia64",
    0x0166: "mipsel",
    0x0169: "mipsel",
    0x0184: "alpha",
    0x0284: "alpha",
    0x01A2: "sh",
    0x01A3: "sh",
    0x01A6: "sh",
    0x01C0: "arm",
    0x01C2: "thumb",
    0x01C4: "thumb",
}

# armgen oracle family directory -> class
ARMGEN_FAMILIES = {
    "aarch64": "aarch64",
    "arm32": "arm",
    "thumb": "thumb",
    "avr": "avr",
    "hexagon": "hexagon",
    "loongarch64": "loongarch64",
    "mips32_be": "mips",
    "mips32_le": "mipsel",
    "mips64_be": "mips64",
    "mips64_le": "mips64el",
    "msp430": "msp430",
    "ppc32": "ppc",
    "ppc64_be": "ppc64",
    "ppc64_le": "ppc64le",
    "riscv32": "riscv32",
    "riscv64": "riscv64",
    "s390x": "s390x",
    "sparc32": "sparc",
    "sparc64": "sparc64",
    "x86": "x86",
    "x86_64": "x86_64",
}

# armgen objects-fresh target triple -> class (ELF objects; e_machine is used
# as the truth, this only covers the formats that are not ELF)
FRESH_NON_ELF = {"wasm32-unknown-unknown": "wasm", "wasm32-wasi": "wasm"}

# (--gen class dir, ELF is little-endian) -> class, where the directory name
# alone does not determine the byte order.
GEN_BYTE_ORDER = {
    ("xtensa", False): "xtensaeb",
}

# Classes whose code, as it appears in a linked image or flash dump, is a
# fixed byte permutation of another class's code: source class -> (derived
# class, word size). Every sample of the source class is also added, with
# each word byte-reversed, to the derived class (same group, so the same
# split).
#
# RX in big-endian mode fetches code as big-endian 32-bit words but decodes
# instructions in little-endian byte order, so big-endian executables and
# ROM images store code with every 32-bit word reversed (binutils
# bfd/elf32-rx.c, rx_get_section_contents). Relocatable objects are not
# swapped, which is why the compiler output itself is labelled "rx".
WORD_SWAPPED = {
    "rx": ("rxeb", 4),
    # Word-addressed DSPs: ROM images and object-to-binary converters store
    # the words in either byte order (DSP563xx byte-wide boot ROMs low byte
    # first, LOD/.p56 conversions high byte first; TI C3x COFF little-endian,
    # some ROM dumps big-endian). Samples are stored little-endian.
    "dsp56k": ("dsp56keb", 3),
    "dsp56100": ("dsp56100eb", 2),
    "tic3x": ("tic3xeb", 4),
    # µ'nSP program ROMs: MAME lists SPG2xx dumps of both word orders (the
    # pokermor dump traces as big-endian words, the others little-endian).
    "unsp": ("unspeb", 2),
}

# ISAdetect (Debian) architecture -> class
ISADETECT = {
    "alpha": "alpha",
    "amd64": "x86_64",
    "arm64": "aarch64",
    "armel": "arm",
    "armhf": "thumb",
    "hppa": "hppa",
    "i386": "x86",
    "ia64": "ia64",
    "m68k": "m68k",
    "mips": "mips",
    "mips64el": "mips64el",
    "mipsel": "mipsel",
    "powerpc": "ppc",
    "powerpcspe": "ppc",
    "ppc64": "ppc64",
    "ppc64el": "ppc64le",
    "riscv64": "riscv64",
    "s390": "s390",
    "s390x": "s390x",
    "sh4": "sh",
    "sparc": "sparc",
    "sparc64": "sparc64",
    "x32": "x86_64",
}

# Raw dumps whose ISA is known from provenance (filename prefix within a
# curated directory).  Only ISAs with no better source are listed.
IDAREF_RAW = [
    ("sh4_", "sh"),
    ("sh3_", "sh"),
    ("sh4b_", "sheb"),
    ("sh3b_", "sheb"),
    ("sh2a_", "sheb"),
    ("v850e1_", "v850"),
    ("v850e2m_", "v850"),
    ("rh850_", "v850"),
    ("tricore--", "tricore"),
    ("c166_", "c166"),
    ("68K_", "m68k"),
    ("68000_", "m68k"),
    ("tms320c6_", "tic6000"),
    ("tms32028_", "tic28x"),
    ("arcmpct_", "arc"),
    ("arcv2_", "arc"),
    ("xtensa_", "xtensa"),
    ("6811_", "hc11"),
]

TESTBINS_RAW = [
    ("superh_", "sheb"),
    ("rh850_", "v850"),
    ("arc_", "arc"),
    ("tricore-", "tricore"),
]

# ---------------------------------------------------------------------------
# Container parsing
# ---------------------------------------------------------------------------


STUB_SECTIONS = (b".plt", b".iplt", b".got", b".glink", b".MIPS.stubs", b".init", b".fini", b".stub")


def elf_code(d):
    """Return (machine, is_le, is_64, flags, [code chunks]) or None."""
    if len(d) < 52 or d[:4] != b"\x7fELF" or d[4] not in (1, 2) or d[5] not in (1, 2):
        return None
    is_64 = d[4] == 2
    le = d[5] == 1
    E = "<" if le else ">"
    try:
        machine = struct.unpack_from(E + "H", d, 18)[0]
        if is_64:
            phoff, shoff = struct.unpack_from(E + "QQ", d, 32)
            flags, _, phentsize, phnum, shentsize, shnum = struct.unpack_from(E + "IHHHHH", d, 48)
        else:
            phoff, shoff, flags = struct.unpack_from(E + "III", d, 28)
            _, phentsize, phnum, shentsize, shnum = struct.unpack_from(E + "HHHHH", d, 40)
    except struct.error:
        return None

    chunks = []
    if shoff and shentsize >= (64 if is_64 else 40) and shnum < 4096:
        headers = []
        for i in range(shnum):
            b = shoff + i * shentsize
            try:
                if is_64:
                    headers.append(struct.unpack_from(E + "IIQQQQ", d, b))
                else:
                    headers.append(struct.unpack_from(E + "IIIIII", d, b))
            except struct.error:
                break
        try:
            shstrndx = struct.unpack_from(E + "H", d, 62 if is_64 else 50)[0]
            strtab = headers[shstrndx][4] if shstrndx < len(headers) else None
        except struct.error:
            strtab = None
        for name_off, ty, fl, _, off, size in headers:
            if not (ty == 1 and fl & 0x4 and 0 < size and off + size <= len(d)):
                continue
            name = b""
            if strtab is not None and strtab + name_off < len(d):
                end = d.find(b"\0", strtab + name_off)
                name = d[strtab + name_off : end if end >= 0 else None]
            # Linker stubs and descriptor tables are not representative code
            # (on PA-RISC/PPC64 some of them are plain data flagged executable).
            if name.startswith(STUB_SECTIONS):
                continue
            chunks.append(d[off : off + size])
    if not chunks and phoff and phnum < 4096:
        for i in range(phnum):
            b = phoff + i * phentsize
            try:
                if is_64:
                    ty, pf, off, _, _, filesz = struct.unpack_from(E + "IIQQQQ", d, b)
                else:
                    ty, off, _, _, filesz, _, pf = struct.unpack_from(E + "IIIIIII", d, b)
            except struct.error:
                break
            if ty == 1 and pf & 0x1 and 0 < filesz and off + filesz <= len(d):
                chunks.append(d[off : off + filesz])
    return machine, le, is_64, flags, chunks


def pe_code(d):
    if len(d) < 0x40 or d[:2] != b"MZ":
        return None
    try:
        o = struct.unpack_from("<I", d, 0x3C)[0]
        if d[o : o + 4] != b"PE\0\0":
            return None
        machine, nsec = struct.unpack_from("<HH", d, o + 4)
        optsz = struct.unpack_from("<H", d, o + 20)[0]
        s = o + 24 + optsz
        chunks = []
        for i in range(min(nsec, 96)):
            b = s + 40 * i
            rawsize, rawptr = struct.unpack_from("<II", d, b + 16)
            ch = struct.unpack_from("<I", d, b + 36)[0]
            if ch & 0x20000020 and rawsize and rawptr + rawsize <= len(d):
                chunks.append(d[rawptr : rawptr + rawsize])
        return machine, chunks
    except struct.error:
        return None


# DOS MZ header fields (word offsets in the 28-byte header): bytes in the
# last page (0x02), pages (0x04), header paragraphs (0x08), new-header offset
# (0x3C, only meaningful for NE/LE/LX/PE executables).
MZ_NEW_SIGNATURES = (b"PE\0\0", b"NE", b"LE", b"LX")


def dos_code(d):
    """The load module of a plain DOS MZ executable (16-bit real-mode code
    and data), or None for NE/LE/LX/PE executables and broken headers."""
    if len(d) < 0x40 or d[:2] != b"MZ":
        return None
    last, pages, _, paragraphs = struct.unpack_from("<HHHH", d, 2)
    lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    if 0 < lfanew < len(d) - 2 and d[lfanew:lfanew + 4].startswith(MZ_NEW_SIGNATURES):
        return None
    start = paragraphs * 16
    end = (pages - 1) * 512 + (last or 512) if pages else 0
    if not 0x1C <= start < end <= len(d):
        return None
    return d[start:end]


def leb128(d, i):
    r = s = 0
    while True:
        b = d[i]
        i += 1
        r |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            return r, i


def wasm_code(d):
    """Return the code section payload of a wasm module/object."""
    if d[:4] != b"\0asm":
        return None
    i = 8
    try:
        while i < len(d):
            sid = d[i]
            size, i = leb128(d, i + 1)
            if sid == 10:
                return d[i : i + size]
            i += size
    except IndexError:
        return None
    return None


# ---------------------------------------------------------------------------
# Corpus assembly
# ---------------------------------------------------------------------------


PADDING_RUN = re.compile(rb"(.)\1{63,}", re.S)


PRINTABLE = bytes(b for b in range(256) if 0x20 <= b < 0x7F or b in (9, 10, 13))


def strip_text_blocks(data, block=256, limit=0.85):
    """Drop embedded string tables (256-byte blocks that are mostly printable).

    Code sections of real binaries (and whole firmware images) interleave
    strings with code; left in, they teach an ISA model to like text.
    """
    out = bytearray()
    for i in range(0, len(data), block):
        b = data[i : i + block]
        if len(b.translate(None, PRINTABLE)) >= (1 - limit) * len(b):
            out += b
    return bytes(out)


# Sources that are whole memory dumps rather than extracted code sections.
RAW_SOURCES = {"idaref-raw", "testbins-raw", "raw"}


def word_swap(data, n):
    """Byte-reverse every n-byte word of data (a trailing partial word is dropped)."""
    end = len(data) - len(data) % n
    return b"".join(data[i : i + n][::-1] for i in range(0, end, n))


def looks_like_code(data, raw_dump):
    """Reject text listings and, for raw dumps, fill-dominated images.

    Printable ASCII above 0.85 is a listing, never code (real code measures
    <= 0.57). The zero/0xFF limits only apply to raw dumps: unrelocated
    compiler output (BPF, PPC, SPARC objects) is legitimately zero-heavy.
    """
    n = len(data)
    printable = sum(1 for b in data if 0x20 <= b < 0x7F or b in (9, 10, 13))
    if printable / n > 0.85:
        return False
    return not raw_dump or (data.count(0) / n <= 0.5 and data.count(0xFF) / n <= 0.5)


class Corpus:
    def __init__(self, out):
        self.out = out
        self.rows = []
        self.seen = set()
        self.per_class_bytes = defaultdict(int)
        self.rejected = defaultdict(int)
        os.makedirs(os.path.join(out, "samples"), exist_ok=True)

    def add(self, cls, group, source, data):
        if cls is None:
            return
        derived = WORD_SWAPPED.get(cls)
        # Swap before cleaning: dropping a padding run or a text block shifts
        # the word phase of everything after it.
        swapped = word_swap(data, derived[1]) if derived else None
        data = self._clean(cls, source, data)
        if data is not None and self._write(cls, group, source, data) and derived:
            swapped = self._clean(derived[0], source, swapped)
            if swapped is not None:
                self._write(derived[0], group, source, swapped)

    def _clean(self, cls, source, data):
        """The sample as it is stored, or None if it is not usable."""
        if not cls.startswith("neg_"):
            # Padding is skipped by the classifier, so it must not be learned
            # as code; and a "code" sample that is mostly text or fill is a
            # listing or an erased-flash dump, not code.
            data = strip_text_blocks(PADDING_RUN.sub(b"", data))
            raw_dump = source in RAW_SOURCES
            if len(data) >= MIN_SAMPLE_BYTES and not looks_like_code(data, raw_dump):
                self.rejected[cls] += 1
                return None
        if len(data) < MIN_SAMPLE_BYTES:
            return None
        if len(data) > MAX_SAMPLE_BYTES:
            # Deterministic window from the middle of the section: the start
            # of .text is dominated by crt/PLT boilerplate.
            start = ((len(data) - MAX_SAMPLE_BYTES) // 2) & ~0xF
            data = data[start : start + MAX_SAMPLE_BYTES]
        return data

    def _write(self, cls, group, source, data):
        h = hashlib.sha1(data).hexdigest()
        if h in self.seen:  # exact duplicates add nothing but leakage
            return False
        self.seen.add(h)
        sid = h[:16]
        d = os.path.join(self.out, "samples", cls)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, sid + ".bin"), "wb") as f:
            f.write(data)
        self.rows.append(
            {"id": sid, "class": cls, "group": group, "source": source, "size": len(data)}
        )
        self.per_class_bytes[cls] += len(data)
        return True

    def finish(self, test_mod):
        by_class = defaultdict(set)
        for r in self.rows:
            by_class[r["class"]].add(r["group"])

        def ghash(g):
            return int(hashlib.md5(g.encode()).hexdigest()[:8], 16)

        test_groups = {}
        for cls, groups in by_class.items():
            groups = sorted(groups, key=ghash)
            test = {g for g in groups if ghash(g) % test_mod == 0}
            if len(groups) >= 2 and not test:
                test = {groups[0]}
            if len(test) == len(groups) and len(groups) >= 2:
                test.discard(groups[-1])
            test_groups[cls] = test
        for r in self.rows:
            r["split"] = "test" if r["group"] in test_groups[r["class"]] else "train"
        with open(os.path.join(self.out, "manifest.jsonl"), "w") as f:
            for r in self.rows:
                f.write(json.dumps(r) + "\n")


def arm_mode(chunks, instructions_le):
    """Decide A32 vs T32 for an ARM ELF code blob by counting cond==AL words.
    The condition is the top nibble of each word: in its last byte when the
    instructions are little-endian, in its first when they are big-endian."""
    blob = b"".join(chunks)[:65536]
    n = len(blob) // 4
    if n < 16:
        return None
    cond_byte = 3 if instructions_le else 0
    al = sum(1 for i in range(0, n * 4, 4) if blob[i + cond_byte] & 0xF0 == 0xE0)
    return "arm" if al / n > 0.55 else "thumb"


def arm_class(chunks, le, flags):
    """Model class of the code of an ARM ELF (`arm`, `thumb`, `armeb`,
    `thumbeb`), or None: big-endian only when the instructions are, which a
    BE-8 image's are not."""
    instructions_le = le or bool(flags & EF_ARM_BE8)
    cls = arm_mode(chunks, instructions_le)
    if cls and not instructions_le:
        cls += "eb"
    return cls


def add_elf_file(corpus, path, group, source_tag):
    if not os.path.isfile(path):
        return
    try:
        with open(path, "rb") as f:
            d = f.read()
    except OSError:
        return
    r = elf_code(d)
    if r is None:
        w = wasm_code(d)
        if w is not None:
            corpus.add("wasm", group, source_tag, w)
        return
    machine, le, is_64, flags, chunks = r
    if not chunks:
        return
    if machine == 40:
        cls = arm_class(chunks, le, flags)
    else:
        cls = elf_class(machine, le, is_64, flags)
    for c in chunks:
        corpus.add(cls, group, source_tag, c)


def elf_data(d):
    """Non-executable PROGBITS sections (.rodata/.data/...) of an ELF image."""
    if len(d) < 52 or d[:4] != b"\x7fELF" or d[4] not in (1, 2) or d[5] not in (1, 2):
        return []
    is_64 = d[4] == 2
    E = "<" if d[5] == 1 else ">"
    try:
        if is_64:
            shoff = struct.unpack_from(E + "Q", d, 40)[0]
            shentsize, shnum = struct.unpack_from(E + "HH", d, 58)
        else:
            shoff = struct.unpack_from(E + "I", d, 32)[0]
            shentsize, shnum = struct.unpack_from(E + "HH", d, 46)
    except struct.error:
        return []
    out = []
    for i in range(min(shnum, 4096)):
        b = shoff + i * shentsize
        try:
            if is_64:
                _, ty, fl, _, off, size = struct.unpack_from(E + "IIQQQQ", d, b)
            else:
                _, ty, fl, _, off, size = struct.unpack_from(E + "IIIIII", d, b)
        except struct.error:
            break
        # PROGBITS, allocated, not executable
        if ty == 1 and fl & 0x2 and not fl & 0x4 and 1024 <= size and off + size <= len(d):
            out.append(d[off : off + size])
    return out


def pcm8(n, k, rng):
    """Signed 8-bit PCM as haptic and ringtone files store it: decaying tone
    bursts at amplitudes from near-silent (+-1, mostly 0x00/0xFF) to full
    scale, separated by silence. Code models once read such files as
    Dalvik, C166 or BPF (fw1 audit, 2026-11-03)."""
    import math

    amplitude = (1, 2, 4, 16, 60, 127)[k % 6]
    out = bytearray()
    while len(out) < n:
        burst = rng.randrange(64, 2048)
        freq = rng.uniform(0.01, 0.4)
        decay = rng.uniform(0.0, 4.0) / burst
        for i in range(burst):
            v = round(amplitude * math.exp(-decay * i) * math.sin(i * freq))
            out.append(v & 0xFF)
        out.extend(bytes(rng.randrange(0, 256)))  # silence between bursts
    return bytes(out[:n])


TILE = 8
TILE_CANVAS = 128


def tile_canvas(rng, colors):
    """A 128x128 canvas of palette indices, 0 transparent, drawn the way game
    graphics are: sprites (filled and outlined shapes), font-like glyph
    cells, or dithered background patterns."""
    size = TILE_CANVAS
    pixels = [[0] * size for _ in range(size)]
    style = rng.randrange(3)
    if style == 0:  # sprites on a transparent background
        for _ in range(rng.randrange(4, 24)):
            x0, y0 = rng.randrange(size), rng.randrange(size)
            w, h = rng.randrange(2, 32), rng.randrange(2, 32)
            color = rng.randrange(1, colors)
            outline = rng.random() < 0.4
            ellipse = rng.random() < 0.5
            for y in range(y0, min(size, y0 + h)):
                for x in range(x0, min(size, x0 + w)):
                    dx, dy = (2 * (x - x0) + 1) / w - 1, (2 * (y - y0) + 1) / h - 1
                    inside = dx * dx + dy * dy <= 1 if ellipse else True
                    edge = x in (x0, x0 + w - 1) or y in (y0, y0 + h - 1)
                    if inside and (edge or not outline):
                        pixels[y][x] = color
    elif style == 1:  # glyph cells: a 5x7 dot pattern in each 8x8 cell
        color = rng.randrange(1, colors)
        glyphs = [[[rng.random() < 0.35 for _ in range(5)] for _ in range(7)] for _ in range(48)]
        for cy in range(0, size, TILE):
            for cx in range(0, size, TILE):
                if rng.random() < 0.2:
                    continue
                glyph = rng.choice(glyphs)
                for gy in range(7):
                    for gx in range(5):
                        if glyph[gy][gx]:
                            pixels[cy + gy][cx + 1 + gx] = color
    else:  # background: bands, checks and ordered dither of a few colors
        period = rng.choice((2, 4, 8, 16))
        a, b = rng.randrange(colors), rng.randrange(colors)
        for y in range(size):
            for x in range(size):
                band = (x // period + y // (period * 2)) % 2
                dither = (x ^ y) & 1 if rng.random() < 0.1 else 0
                pixels[y][x] = a if band ^ dither else b
    return pixels


def tile_rows(pixels):
    """Rows of every 8x8 tile in tile order (left to right, top to bottom)."""
    for ty in range(0, TILE_CANVAS, TILE):
        for tx in range(0, TILE_CANVAS, TILE):
            yield [pixels[ty + y][tx:tx + TILE] for y in range(TILE)]


def plane_byte(row, plane):
    """One tile row of one bit plane, leftmost pixel in the high bit."""
    value = 0
    for pixel in row:
        value = (value << 1) | ((pixel >> plane) & 1)
    return value


def encode_tile(rows, layout, plane):
    """One 8x8 tile in a common tile-ROM layout (MAME gfx layouts and
    console formats: one bit plane per ROM, 2bpp NES, 4bpp SNES planar,
    4bpp packed nibbles, 8bpp linear)."""
    if layout == 0:  # one bit plane of a multi-ROM planar set
        return bytes(plane_byte(r, plane) for r in rows)
    if layout == 1:  # 2bpp, plane 0 rows then plane 1 rows
        return bytes(plane_byte(r, 0) for r in rows) + bytes(plane_byte(r, 1) for r in rows)
    if layout == 2:  # 4bpp, planes 0/1 interleaved per row, then planes 2/3
        low = bytes(b for r in rows for b in (plane_byte(r, 0), plane_byte(r, 1)))
        return low + bytes(b for r in rows for b in (plane_byte(r, 2), plane_byte(r, 3)))
    if layout == 3:  # 4bpp packed, left pixel in the high nibble
        return bytes((r[x] << 4) | r[x + 1] for r in rows for x in range(0, TILE, 2))
    return bytes(p for r in rows for p in r)  # 8bpp linear


TILE_LAYOUT_COLORS = (8, 4, 16, 16, 64)
TILE_SEED = 5678


def tiles(n, k, rng):
    """Game tile graphics: canvases of sprites, glyphs or backgrounds cut
    into 8x8 tiles and stored in one tile-ROM layout. Code models read
    arcade graphics ROMs as R32C, 68HC08, SuperH or WebAssembly (fw1 audit
    against MAME's ROM regions, 2026-11-04)."""
    layout = k % len(TILE_LAYOUT_COLORS)
    colors = TILE_LAYOUT_COLORS[layout]
    plane = k % 3
    out = bytearray()
    while len(out) < n:
        for rows in tile_rows(tile_canvas(rng, colors)):
            out.extend(encode_tile(rows, layout, plane))
    return bytes(out[:n])


PIXEL_SEED = 3456
PIXEL_FORMATS = ("<H", ">H", "<I")  # RGB565 little- and big-endian, ARGB8888


def rgb565(red, green, blue):
    return ((red >> 3) << 11) | ((green >> 2) << 5) | (blue >> 3)


def pixels(n, k, rng):
    """Uncompressed images as UI frame buffers and phone resource partitions
    store them: RGB565 in either byte order or ARGB8888, rows of a canvas
    of flat shapes, glyphs or patterns, or a vertical gradient. Code models
    read a phone's 34 MiB image region as 6800 code (fw1 audit,
    2026-11-04)."""
    fmt = PIXEL_FORMATS[k % len(PIXEL_FORMATS)]
    out = bytearray()
    while len(out) < n:
        palette = [(rng.randrange(256), rng.randrange(256), rng.randrange(256)) for _ in range(16)]
        if rng.random() < 0.25:
            top, bottom = palette[0], palette[1]
            rows = [[tuple(t + (b - t) * y // TILE_CANVAS for t, b in zip(top, bottom))] * TILE_CANVAS
                    for y in range(TILE_CANVAS)]
        else:
            rows = [[palette[i] for i in row] for row in tile_canvas(rng, len(palette))]
        for row in rows:
            for red, green, blue in row:
                value = rgb565(red, green, blue) if fmt[1] == "H" else 0xFF000000 | red << 16 | green << 8 | blue
                out.extend(struct.pack(fmt, value))
    return bytes(out[:n])


WEIGHT_SCALES = (0.01, 0.05, 0.2, 1.0)
WEIGHT_SEED = 9012


def weights(n, k, rng):
    """Neural-network weight tables: normally distributed float32 or float16
    values in either byte order. Fingerprint-matching trusted apps carry
    megabytes of them, which code models read as RISC-V (fw1 audit,
    2026-11-04)."""
    scale = WEIGHT_SCALES[k % len(WEIGHT_SCALES)]
    order = "<" if k % 2 == 0 else ">"
    kind = "f" if (k // 2) % 2 == 0 else "e"
    count = n // struct.calcsize(kind)
    return struct.pack(f"{order}{count}{kind}", *(rng.gauss(0.0, scale) for _ in range(count)))


def add_negatives(corpus, data_dir, per_arch):
    """Non-code material: real .rodata/.data, text, media, compressed, synthetic tables."""
    import random

    rng = random.Random(1234)
    ds2 = os.path.join(data_dir, "new_new_dataset", "ds2")
    for arch in sorted(ISADETECT):
        files = sorted(glob.glob(os.path.join(ds2, arch, "*")))[-per_arch:]
        for p in files:
            with open(p, "rb") as f:
                for c in elf_data(f.read()):
                    corpus.add("neg_rodata", "deb:" + os.path.basename(p), "isadetect-data", c)
    text_files = sorted(glob.glob(os.path.join(REPO, "src", "**", "*.rs"), recursive=True))[:120]
    text_files += sorted(glob.glob(os.path.join(REPO, "*.md")))
    for p in text_files:
        with open(p, "rb") as f:
            t = f.read()
        corpus.add("neg_text", "file:" + os.path.basename(p), "text", t)
        corpus.add("neg_text", "file:" + os.path.basename(p), "text-utf16", bytes(x for b in t for x in (b, 0)))
    for pattern, cls in [
        ("/System/Library/Fonts/*.tt?", "neg_media"),
        ("/System/Library/Sounds/*.aiff", "neg_media"),
        ("/Library/Desktop Pictures/*", "neg_media"),
        ("/usr/share/man/man1/*.gz", "neg_compressed"),
        ("/System/Library/Desktop Pictures/*.heic", "neg_media"),
    ]:
        for p in sorted(glob.glob(pattern))[:40]:
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    corpus.add(cls, "file:" + os.path.basename(p), "system", f.read(MAX_SAMPLE_BYTES))
    for k in range(64):
        n = 4096 << (k % 5)
        corpus.add("neg_random", f"rand:{k}", "synthetic", bytes(rng.getrandbits(8) for _ in range(n)))
        import math
        f32 = b"".join(struct.pack("<f", math.sin(i * 0.01 * (k + 1)) * (k + 1)) for i in range(n // 4))
        corpus.add("neg_table", f"f32:{k}", "synthetic", f32)
        f64 = b"".join(struct.pack(">d", math.cos(i * 0.003 * (k + 1)) * 1e3) for i in range(n // 8))
        corpus.add("neg_table", f"f64:{k}", "synthetic", f64)
        pcm = b"".join(struct.pack("<h", int(math.sin(i * 0.05 * (1 + k % 7)) * 8000)) for i in range(n // 2))
        corpus.add("neg_table", f"pcm:{k}", "synthetic", pcm)
        corpus.add("neg_media", f"pcm8:{k}", "synthetic-pcm8", pcm8(n, k, rng))
        # Own generator, so the samples after it stay as they were.
        corpus.add("neg_pixels", f"tiles:{k}", "synthetic-tiles", tiles(n, k, random.Random(TILE_SEED + k)))
        corpus.add("neg_table", f"weights:{k}", "synthetic-weights", weights(n, k, random.Random(WEIGHT_SEED + k)))
        corpus.add("neg_pixels", f"pixels:{k}", "synthetic-pixels", pixels(n, k, random.Random(PIXEL_SEED + k)))
        ints = b"".join(struct.pack("<I" if k % 2 else ">I", rng.randrange(1000)) for _ in range(n // 4))
        corpus.add("neg_table", f"u32:{k}", "synthetic", ints)
        base = rng.randrange(1 << 28) & ~0xFFFF
        ptrs = b"".join(struct.pack("<I" if k % 2 else ">I", base + rng.randrange(1 << 16) * 4) for _ in range(n // 4))
        corpus.add("neg_table", f"ptr:{k}", "synthetic", ptrs)


def program_of(path):
    base = os.path.basename(path)
    stem = base.rsplit(".", 1)[0]
    return stem.split("__", 1)[-1]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--data", default=os.path.join(REPO, "..", "isa-harvester", "data"))
    ap.add_argument("--armgen", default=os.path.join(REPO, "..", "isa-harvester", "armgen"))
    ap.add_argument("--gen", action="append", default=[], help="extra dir of <class>/**/*.o compiler output")
    ap.add_argument("--raw", action="append", default=[], help="CLASS=GLOB of raw code dumps")
    ap.add_argument(
        "--raw-group",
        action="append",
        default=[],
        help="CLASS=REGEX: group raw samples of CLASS by the regex's first capture in the file name "
        "(versions of one program on one side of the split); default one group per file",
    )
    ap.add_argument("--isadetect-per-arch", type=int, default=400)
    ap.add_argument("--isadetect-skip", type=int, default=0, help="ISAdetect binaries per arch to skip first (for a held-out set)")
    ap.add_argument("--elf", action="append", default=[], help="GLOB of ELF files labelled by e_machine (e.g. hexagon-dsp-binaries)")
    ap.add_argument("--test-mod", type=int, default=5, help="1/N of groups go to the test split")
    ap.add_argument("--negatives", type=int, default=40, help="ISAdetect binaries per arch to mine .rodata/.data from (0 = no negatives)")
    a = ap.parse_args()

    corpus = Corpus(a.out)

    # 1. armgen oracle objects: raw .text blobs, truth from the family dir.
    objects = os.path.join(a.armgen, "objects")
    for fam, cls in ARMGEN_FAMILIES.items():
        for p in glob.glob(os.path.join(objects, fam, "**", "*.bin"), recursive=True):
            if not os.path.isfile(p):
                continue
            with open(p, "rb") as f:
                corpus.add(cls, "prog:" + program_of(p), "armgen", f.read())

    # 2. armgen objects-fresh: ELF/wasm objects, truth from e_machine.
    fresh = os.path.join(a.armgen, "objects-fresh")
    for p in glob.glob(os.path.join(fresh, "*", "**", "*.o"), recursive=True):
        add_elf_file(corpus, p, "prog:" + program_of(p), "armgen-fresh")

    # 3. Extra compiler output (e.g. the LLVM cross-compile matrix).  The
    #    directory name is the class because e_machine cannot tell A32/T32 or
    #    microMIPS apart; wasm objects are parsed for their code section.
    #    Toolchains without ELF output (SDCC, cc65, pdp11-aout, gputils)
    #    leave extracted code as raw *.bin files instead of *.o.
    for gen in a.gen:
        # One source per matrix directory, so the trainer's per-source cap
        # balances toolchains (LLVM vs GCC) instead of lumping them together.
        gen_path = os.path.normpath(gen)
        gen_tag = "gen:" + "/".join(gen_path.split(os.sep)[-2:])
        for cls in sorted(os.listdir(gen)):
            paths = glob.glob(os.path.join(gen, cls, "**", "*.o"), recursive=True)
            paths += glob.glob(os.path.join(gen, cls, "**", "*.bin"), recursive=True)
            for p in sorted(paths):
                if not os.path.isfile(p):
                    continue
                with open(p, "rb") as f:
                    d = f.read()
                group = "prog:" + program_of(p)
                if p.endswith(".bin"):
                    corpus.add(cls, group, gen_tag, d)
                    continue
                if cls == "wasm":
                    w = wasm_code(d)
                    if w is not None:
                        corpus.add("wasm", group, gen_tag, w)
                    continue
                r = elf_code(d)
                if r:
                    # The directory names the ISA, but the object's own byte
                    # order is authoritative (GCC's default xtensa core is
                    # big-endian, while ESP32-class Xtensa is little-endian).
                    target_cls = GEN_BYTE_ORDER.get((cls, r[1]), cls)
                    for c in r[4]:
                        corpus.add(target_cls, group, gen_tag, c)

    # 4. ISAdetect: real Debian binaries, a deterministic subset per arch.
    ds2 = os.path.join(a.data, "new_new_dataset", "ds2")
    for arch, cls in ISADETECT.items():
        files = sorted(glob.glob(os.path.join(ds2, arch, "*")))[a.isadetect_skip : a.isadetect_skip + a.isadetect_per_arch]
        for p in files:
            add_elf_file(corpus, p, "deb:" + os.path.basename(p), "isadetect")

    # 5. idaref and radare2 testbins: ELF/PE with header truth, plus curated raw dumps.
    for root in (os.path.join(REPO, "idaref"), os.path.join(a.data, "radare2-testbins")):
        for dirpath, _, files in os.walk(root):
            if "fuzzed" in dirpath:
                continue
            for fn in files:
                if fn.endswith((".id0", ".id1", ".id2", ".nam", ".til", ".hints")):
                    continue
                p = os.path.join(dirpath, fn)
                group = "file:" + fn
                try:
                    with open(p, "rb") as f:
                        head = f.read(4)
                except OSError:
                    continue
                if head == b"\x7fELF":
                    add_elf_file(corpus, p, group, os.path.basename(root))
                elif head[:2] == b"MZ":
                    with open(p, "rb") as f:
                        d = f.read()
                    r = pe_code(d)
                    if r and r[0] in PE_MACHINES:
                        for c in r[1]:
                            corpus.add(PE_MACHINES[r[0]], group, os.path.basename(root), c)
                    elif (dos := dos_code(d)) is not None:
                        corpus.add("x86_16", group, os.path.basename(root) + "-dos", dos)
                elif root.endswith("idaref"):
                    for pre, cls in IDAREF_RAW:
                        if fn.startswith(pre) and fn.endswith((".bin", ".dmp", ".esp")):
                            with open(p, "rb") as f:
                                corpus.add(cls, group, "idaref-raw", f.read())
                            break

    for fn in sorted(os.listdir(os.path.join(REPO, "testbins"))):
        for pre, cls in TESTBINS_RAW:
            if fn.startswith(pre) and fn.endswith(".bin"):
                with open(os.path.join(REPO, "testbins", fn), "rb") as f:
                    corpus.add(cls, "file:" + fn, "testbins-raw", f.read())
                break

    # 6. Header-labelled ELF collections: code and data sections.
    for pattern in a.elf:
        for p in sorted(glob.glob(pattern, recursive=True)):
            if not os.path.isfile(p):
                continue
            group = "elf:" + os.path.basename(p)
            add_elf_file(corpus, p, group, "elf-glob")
            with open(p, "rb") as f:
                for chunk in elf_data(f.read()):
                    corpus.add("neg_rodata", group, "elf-glob-data", chunk)

    # 7. Explicit raw dumps.
    raw_groups = {cls: re.compile(rx) for cls, rx in (spec.split("=", 1) for spec in a.raw_group)}
    for spec in a.raw:
        cls, pattern = spec.split("=", 1)
        for p in sorted(glob.glob(pattern)):
            if not os.path.isfile(p):
                continue
            name = os.path.basename(p)
            match = raw_groups[cls].search(name) if cls in raw_groups else None
            group = f"{cls}:{match.group(1).lower()}" if match else "file:" + name
            with open(p, "rb") as f:
                corpus.add(cls, group, "raw", f.read())

    if a.negatives:
        add_negatives(corpus, a.data, a.negatives)

    corpus.finish(a.test_mod)
    total = 0
    for cls in sorted(corpus.per_class_bytes):
        n = sum(1 for r in corpus.rows if r["class"] == cls)
        g = len({r["group"] for r in corpus.rows if r["class"] == cls})
        b = corpus.per_class_bytes[cls]
        total += b
        print(f"{cls:14s} samples={n:6d} groups={g:5d} bytes={b/1024/1024:8.2f}MB", file=sys.stderr)
    print(f"total {len(corpus.rows)} samples, {total/1024/1024:.1f}MB", file=sys.stderr)
    for cls, n in sorted(corpus.rejected.items()):
        print(f"rejected {n} {cls} samples as text/fill", file=sys.stderr)


if __name__ == "__main__":
    main()
