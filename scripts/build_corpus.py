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
    scripts/build_corpus.py --out /path/to/corpus [--data ../data] [--armgen ../armgen]
                            [--gen DIR ...] [--raw CLASS=GLOB ...]
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


def arm_mode(chunks):
    """Decide A32 vs T32 for an ARM ELF code blob by counting cond==AL words."""
    blob = b"".join(chunks)[:65536]
    n = len(blob) // 4
    if n < 16:
        return None
    al = sum(1 for i in range(0, n * 4, 4) if blob[i + 3] & 0xF0 == 0xE0)
    return "arm" if al / n > 0.55 else "thumb"


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
        cls = arm_mode(chunks)
        if cls and not le:
            cls += "eb"
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
    ap.add_argument("--data", default=os.path.join(REPO, "..", "data"))
    ap.add_argument("--armgen", default=os.path.join(REPO, "..", "armgen"))
    ap.add_argument("--gen", action="append", default=[], help="extra dir of <class>/**/*.o compiler output")
    ap.add_argument("--raw", action="append", default=[], help="CLASS=GLOB of raw code dumps")
    ap.add_argument("--isadetect-per-arch", type=int, default=400)
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
        files = sorted(glob.glob(os.path.join(ds2, arch, "*")))[: a.isadetect_per_arch]
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
                        r = pe_code(f.read())
                    if r and r[0] in PE_MACHINES:
                        for c in r[1]:
                            corpus.add(PE_MACHINES[r[0]], group, os.path.basename(root), c)
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

    # 6. Explicit raw dumps.
    for spec in a.raw:
        cls, pattern = spec.split("=", 1)
        for p in sorted(glob.glob(pattern)):
            if not os.path.isfile(p):
                continue
            with open(p, "rb") as f:
                corpus.add(cls, "file:" + os.path.basename(p), "raw", f.read())

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
