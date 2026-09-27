#!/usr/bin/env python3
"""Helper for scripts/sdcc_matrix/build.sh: compile the armgen programs with SDCC
and cc65, link them, and write only the executable code bytes of each program
(and of each prebuilt library module) as one raw binary.

Subcommands (build.sh drives them; see its header for the big picture):

  prep ARMGEN WORK             prepped copies of armgen/programs{,2}/*.c -> WORK/src
  sdcc-lib PORT LIBDIR ...     one .bin per module of the prebuilt SDCC libraries
  sdcc-prog ...                compile + link one program with SDCC, write its code
  cc65-lib LIB ...             one .bin per module of a cc65 library
  cc65-prog ...                compile + link one program with cc65, write its code
  summary OUT                  per class/config counts and byte totals
  check OUT                    sanity checks over all outputs

"Code only" is enforced in three layers:
  1. only code areas/segments are taken (SDCC: CSEG/CODE/HOME/GSINIT*/GSFINAL;
     cc65: STARTUP/LOWCODE/ONCE/CODE); ABS areas (vectors, crt0 headers) never;
  2. inside those, bytes emitted by assembler data directives (.db/.dw/.ascii/
     .byte/...) are removed, using the assembler listing (.lst) of the program
     module placed at its link addresses (SDCC); cc65's code generator emits no
     data into code segments (checked per program);
  3. prebuilt library modules that carry data inside a code area (z80-family
     SDCC libraries keep C string literals/const tables in _CODE) are found by
     rebuilding the module from SDCC's lib/src with a listing; see sdcc_lib().
"""
import argparse
import collections
import glob
import hashlib
import json
import multiprocessing
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
STUBINC = os.path.normpath(os.path.join(HERE, "..", "stubinc"))
SDCC_SHARE = os.environ.get("SDCC_SHARE", "/opt/homebrew/share/sdcc")
CC65_SHARE = os.environ.get("CC65_SHARE", "/opt/homebrew/share/cc65")
MIN_BYTES = 64
# Programs whose code exceeds a 16-bit address space are pathological for these
# targets (SDCC expands some large local initialisers into ~100k stores: 07_regex
# is 600 KB of `ld` on stm8) and are not written.
MAX_PROG_BYTES = 0x10000

# --------------------------------------------------------------------------
# Ports
# --------------------------------------------------------------------------
# sdcc -m<port>; lib source dirs searched (in order) before lib/src/*.c;
# assembler for .s/.asm sources.
PORTS = {
    "mcs51":    dict(src=["mcs51"], asm="sdas8051"),
    "ds390":    dict(src=["ds390"], asm="sdas390"),
    "hc08":     dict(src=["hc08"], asm="sdas6808"),
    "s08":      dict(src=["s08", "hc08"], asm="sdas6808"),
    "z80":      dict(src=["z80"], asm="sdasz80"),
    "z180":     dict(src=["z180", "z80"], asm="sdasz80"),
    "ez80":     dict(src=["ez80", "z80"], asm="sdasz80"),
    "r800":     dict(src=["r800", "z80"], asm="sdasz80"),
    "sm83":     dict(src=["sm83"], asm="sdasgb"),
    "stm8":     dict(src=["stm8"], asm="sdasstm8"),
    "mos6502":  dict(src=["mos6502"], asm="sdas6500"),
    "mos65c02": dict(src=["mos65c02", "mos6502"], asm="sdas6500"),
}

# Area names (leading '_' stripped) that hold instructions. Everything else is
# data: CONST/RODATA (const data, string literals), XINIT/INITIALIZER (images
# of initialised variables), CABS (absolute code-space data), CODEIVT (vector
# table), HEADERn (z80/sm83 crt0 RST/interrupt vectors, ABS), DATA/BSS/...
CODE_AREA = re.compile(r"^(CODE|CSEG|HOME|GSINIT\d*|GSFINAL|CODE_\w+)$")
KNOWN_DATA_AREA = re.compile(
    r"^(\.ABS\.|\. +\.ABS\.|CONST|RODATA|XINIT|INITIALIZER|INITIALIZED|CABS|DABS|CODEIVT\d*|HEADER\w*|DATA|BSS|HEAP|HEAP_END|"
    r"DSEG|OSEG|SSEG|ISEG|IABS|BSEG|PSEG|XSEG|XABS|XISEG|XSTK|RSEG\d*|REG_BANK_\d|BIT_BANK|ZP|BSEG_BYTES|"
    r"XSEG_\w+|STACK)$")


def is_code_area(name):
    return bool(CODE_AREA.match(name.lstrip("_")))


def run(cmd, cwd=None, timeout=600, env=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, env=env)
        return p.returncode, p.stdout.decode("latin-1")
    except subprocess.TimeoutExpired:
        return -9, "TIMEOUT"


# --------------------------------------------------------------------------
# Source preparation
# --------------------------------------------------------------------------
PRELUDE_COMMON = r"""/* sdcc_matrix prelude: neutralise GNU builtins the 8-bit compilers lack */
#define __builtin_expect(x, y) (x)
#define __builtin_assume_aligned(p, a) (p)
#define __builtin_prefetch(p) ((void)0)
#define __sync_synchronize() ((void)0)
#define __atomic_thread_fence(m) ((void)0)
#define __atomic_signal_fence(m) ((void)0)
#define __atomic_load_n(p, m) (*(p))
#define __atomic_store_n(p, v, m) ((void)(*(p) = (v)))
#define __sync_lock_release(p) ((void)(*(p) = 0))
#define __sync_add_and_fetch(p, v) (*(p) += (v))
#define __sync_sub_and_fetch(p, v) (*(p) -= (v))
#define __sync_fetch_and_add(p, v) ((*(p) += (v)) - (v))
#define __sync_fetch_and_sub(p, v) ((*(p) -= (v)) + (v))
#define __sync_bool_compare_and_swap(p, o, n) ((*(p) == (o)) ? (*(p) = (n), 1) : 0)
#define __sync_lock_test_and_set(p, v) armgen_xchg((void *)(p), (v))
#define __sync_val_compare_and_swap(p, o, n) armgen_cas((void *)(p), (o), (n))
#define __builtin_clz(x) armgen_clz(x)
#define __builtin_ctz(x) armgen_ctz(x)
#define __builtin_popcount(x) armgen_popcount(x)
#define __builtin_parity(x) armgen_parity(x)
#define __builtin_ffs(x) armgen_ffs(x)
#define __builtin_calloc(n, s) armgen_calloc(n, s)
#define __extension__
#define __inline__ inline
#define __inline inline
#define __restrict__
#define __restrict
#define __volatile__ volatile
int armgen_xchg(void *, int);
int armgen_cas(void *, int, int);
int armgen_clz(unsigned int);
int armgen_ctz(unsigned int);
int armgen_popcount(unsigned int);
int armgen_parity(unsigned int);
int armgen_ffs(int);
void *armgen_calloc(unsigned int, unsigned int);
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
"""
PRELUDE_SDCC = r"""#define __builtin_clzll(x) armgen_clzll(x)
#define __builtin_popcountll(x) armgen_popcountll(x)
#define __builtin_exp(x) armgen_expf(x)
#define __builtin_log2f(x) armgen_log2f(x)
int armgen_clzll(unsigned long long);
int armgen_popcountll(unsigned long long);
float armgen_expf(float);
float armgen_log2f(float);
"""
PRELUDE_CC65 = r"""#define inline
typedef long int64_t;
typedef unsigned long uint64_t;
#define restrict
#define __builtin_clzll(x) armgen_clz(x)
#define __builtin_popcountll(x) armgen_popcount(x)
"""


def _skip_balanced(s, i):
    """s[i] == '('; index after the matching ')', skipping string/char literals."""
    depth, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in "\"'":
            i += 1
            while i < n and s[i] != c:
                i += 2 if s[i] == "\\" else 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


_ATTR = re.compile(r"\b__attribute__\s*\(")
_ASM = re.compile(r"\b(?:__asm__|__asm|asm)\b(?:\s*(?:__volatile__|volatile|__inline__|inline|goto))*\s*\(")
_ALIGNAS = re.compile(r"\b(?:alignas|_Alignas)\s*\(")
# `uint32_t reserved : 27;` -> SDCC and cc65 only take bit-fields up to 16 bits.
_BITFIELD = re.compile(
    r"^(\s*)((?:(?:const|volatile|signed|unsigned)\s+)*"
    r"(?:u?int(?:8|16|32|64)_t|int|long|short|char|unsigned|signed|_Bool|bool)(?:\s+(?:long|int))*)"
    r"(\s+\w+\s*|\s*):\s*(\d+)(\s*[;,])", re.M)


def strip_gnu(src):
    out, i = [], 0
    while True:
        m = None
        for rx in (_ATTR, _ASM, _ALIGNAS):
            mm = rx.search(src, i)
            if mm and (m is None or mm.start() < m.start()):
                m = mm
        if not m:
            out.append(src[i:])
            break
        line_start = src.rfind("\n", 0, m.start()) + 1
        if src[line_start:m.start()].lstrip().startswith("#"):
            # inside a preprocessor directive (e.g. `#define __attribute__(x)`)
            out.append(src[i:m.end()])
            i = m.end()
            continue
        out.append(src[i:m.start()])
        end = _skip_balanced(src, m.end() - 1)
        if m.re is _ASM:
            prev = src[:m.start()].rstrip()
            # `register long x __asm__("r0")` -> drop; asm statement -> no-op
            if not (prev and (prev[-1].isalnum() or prev[-1] == "_")):
                out.append("((void)0)")
        # keep line numbering
        out.append("\n" * src.count("\n", m.start(), end))
        i = end
    return "".join(out)


def clamp_bitfields(src, int_only=False):
    """Bit-fields wider than 16 bits -> 16 (SDCC, cc65 limit); with int_only
    (cc65) the declared type becomes (un)signed int, the only types cc65 takes."""
    def sub(m):
        typ = m.group(2)
        if int_only:
            typ = "signed int" if re.match(r"(signed\b|int\b|int\d+_t|short|long|char)", typ) else "unsigned int"
        return m.group(1) + typ + m.group(3) + ":" + str(min(int(m.group(4)), 16)) + m.group(5)
    return _BITFIELD.sub(sub, src)


def prep(armgen, work):
    dst = os.path.join(work, "src")
    os.makedirs(dst, exist_ok=True)
    n = 0
    for set_name in ("programs", "programs2"):
        for p in sorted(glob.glob(os.path.join(armgen, set_name, "*.c"))):
            body = strip_gnu(open(p, encoding="latin-1").read())
            name = "%s__%s" % (set_name, os.path.basename(p))
            for flavour, pre in (("sdcc", PRELUDE_SDCC), ("cc65", PRELUDE_CC65)):
                text = PRELUDE_COMMON + pre + '#line 1 "%s"\n' % os.path.basename(p) + \
                    clamp_bitfields(body, int_only=flavour == "cc65")
                path = os.path.join(dst, flavour, name)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                if not os.path.exists(path) or open(path, encoding="latin-1").read() != text:
                    with open(path, "w", encoding="latin-1") as f:
                        f.write(text)
            n += 1
    print("prepped %d programs -> %s" % (n, dst))


# --------------------------------------------------------------------------
# ASxxxx file formats
# --------------------------------------------------------------------------
def read_ihx(path):
    """Intel hex or Motorola S-records (sdld writes S19 for hc08/s08) ->
    ({addr: byte}, set of addresses written more than once)."""
    mem, dup, base = {}, set(), 0

    def put(a, data):
        for k, x in enumerate(data):
            if a + k in mem:
                dup.add(a + k)
            mem[a + k] = x

    for line in open(path, errors="replace"):
        line = line.strip()
        if line.startswith(":"):
            b = bytes.fromhex(line[1:])
            addr, typ, data = (b[1] << 8) | b[2], b[3], b[4:4 + b[0]]
            if typ == 0:
                put(base + addr, data)
            elif typ == 2:
                base = ((data[0] << 8) | data[1]) << 4
            elif typ == 4:
                base = ((data[0] << 8) | data[1]) << 16
            elif typ == 1:
                break
        elif line[:2] in ("S1", "S2", "S3"):
            b = bytes.fromhex(line[2:])
            alen = {"S1": 2, "S2": 3, "S3": 4}[line[:2]]
            addr = int.from_bytes(b[1:1 + alen], "big")
            put(addr, b[1 + alen:b[0]])
    return mem, dup


_MAP_AREA = re.compile(r"^(\S.*?)\s+([0-9A-Fa-f]{4,8})\s+([0-9A-Fa-f]{4,8})\s+=\s+(\d+)\.\s+bytes\s+\(([^)]*)\)")
_MAP_SYM = re.compile(r"^(?:[A-Z]:)?\s+([0-9A-Fa-f]{4,8})\s+(\S+)\s+(\S+)\s*$")


def read_map(path):
    """sdld map -> dict(areas=[(name, addr, size, attrs)], syms=[(addr, name, module, area)],
    libmods=[(libpath, module)])."""
    areas, syms, libmods = [], [], []
    cur = None
    lines = open(path, errors="replace").read().splitlines()
    mode = None
    pending_lib = None
    for line in lines:
        m = _MAP_AREA.match(line)
        if m:
            cur = m.group(1).strip()
            areas.append((cur, int(m.group(2), 16), int(m.group(3), 16), m.group(5)))
            mode = "area"
            continue
        if line.startswith("Files Linked"):
            mode = "files"
            continue
        if line.startswith("Libraries Linked"):
            mode = "libs"
            continue
        if line.startswith("User Base Address") or line.startswith("User Global"):
            mode = None
            continue
        if mode == "area":
            s = _MAP_SYM.match(line)
            if s:
                syms.append((int(s.group(1), 16), s.group(2), s.group(3), cur))
        elif mode == "libs":
            t = line.strip()
            if t.startswith("[") and pending_lib:
                libmods.append((pending_lib, t.strip("[] ").strip()))
                pending_lib = None
            elif t:
                pending_lib = t
    return dict(areas=areas, syms=syms, libmods=libmods)


_REL_AREA = re.compile(r"^A\s+(\S+)\s+size\s+([0-9A-Fa-f]+)\s+flags\s+([0-9A-Fa-f]+)")
_REL_SYM = re.compile(r"^S\s+(\S+)\s+Def([0-9A-Fa-f]+)")


def read_rel(text):
    """.rel -> dict(areas={name: size}, flags={name: flags}, syms={name: (area, offset)})
    (hex radix assumed; flag 0x08 = ABS)."""
    areas, flags, syms, cur = collections.OrderedDict(), {}, {}, None
    for line in text.splitlines():
        m = _REL_AREA.match(line)
        if m:
            cur = m.group(1)
            areas[cur] = int(m.group(2), 16)
            flags[cur] = int(m.group(3), 16)
            continue
        s = _REL_SYM.match(line)
        if s and cur is not None:
            syms[s.group(1)] = (cur, int(s.group(2), 16))
    return dict(areas=areas, flags=flags, syms=syms)


def ar_members(path):
    """GNU-style ar archive (as written by sdar) -> [(member name, bytes)]."""
    d = open(path, "rb").read()
    if d[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive: " + path)
    p, longnames, out = 8, b"", []
    while p + 60 <= len(d):
        h = d[p:p + 60]
        name = h[:16].decode("latin-1").rstrip()
        size = int(h[48:58])
        p += 60
        body = d[p:p + size]
        p += size + (size & 1)
        if name == "/":
            continue
        if name == "//":
            longnames = body
            continue
        if name.startswith("/") and name[1:].isdigit():
            o = int(name[1:])
            e = longnames.find(b"\n", o)
            name = longnames[o:e].decode("latin-1")
        out.append((name.rstrip("/"), body))
    return out


_CYCLES = re.compile(r"\[[\s\d/]*\]")
_LABEL = re.compile(r"^\s*[A-Za-z_.$][\w.$]*::?")
_LEAD_NUM = re.compile(r"^( {16,})(\d+) ")
_NOT_HEX = re.compile(r"[^0-9A-F\s]")


def read_listing(path):
    """ASxxxx assembler listing (.lst) -> [(area, offset, [bytes], is_data)] per
    statement that emits bytes; offset is relative to the module's part of the
    area. is_data: the statement is an assembler directive (.db/.dw/.ascii/...)
    rather than an instruction. Relocation flags next to bytes (r, s, *, ...)
    are ignored; continuation lines extend the previous statement.
    (The linker-updated .rst is not used: sdld6808 garbles it.)"""
    lines = open(path, errors="replace").read().splitlines()
    # Column where the source line number ends, from lines that carry only a
    # line number (comments, .area, ...).
    ends = collections.Counter()
    for ln in lines:
        m = _LEAD_NUM.match(ln)
        if m:
            ends[len(m.group(1)) + len(m.group(2))] += 1
    if not ends:
        return []
    col = ends.most_common(1)[0][0]
    out, last, area = [], None, None
    for ln in lines:
        if len(ln) > col:
            has_num = ln[col - 1].isdigit() and ln[col] in " \t"
        else:
            has_num = len(ln) == col and ln[col - 1].isdigit()
        if has_num:
            pre, src = ln[:col], ln[col + 1:]
            k = col - 1
            while k >= 0 and pre[k].isdigit():
                k -= 1
            pre = pre[:k + 1]
            text = src.split(";", 1)[0]
            while True:
                m = _LABEL.match(text)
                if not m:
                    break
                text = text[m.end():]
            words = text.split()
            if words and words[0].lower() == ".area" and len(words) > 1:
                area = words[1]
        else:
            pre, words = ln, []
        toks = _NOT_HEX.sub(" ", _CYCLES.sub(" ", pre)).split()
        addr = None
        if toks and has_num and re.fullmatch(r"[0-9A-F]{4,8}", toks[0]):
            addr = int(toks[0], 16)
            toks = toks[1:]
        if not all(re.fullmatch(r"[0-9A-F]{2}", t) for t in toks):
            last = None
            continue
        bs = [int(t, 16) for t in toks]
        if has_num:
            if not bs or addr is None:
                last = None
                continue
            is_data = bool(words) and words[0].startswith(".")
            last = [area, addr, bs, is_data]
            out.append(last)
        elif bs and last is not None:
            last[2].extend(bs)
    return [tuple(x) for x in out]


def data_offsets(listing):
    """{area: set of offsets} of bytes emitted by data directives. A lone 1-2 byte
    directive between instructions (e.g. `.db 0x2c` BIT-skip tricks) counts as code."""
    by_area = collections.defaultdict(list)
    for area, off, bs, isd in read_listing(listing):
        by_area[area].append((off, bs, isd))
    data = collections.defaultdict(set)
    for area, st in by_area.items():
        st.sort(key=lambda t: t[0])
        for k, (a, bs, d) in enumerate(st):
            if not d:
                continue
            if len(bs) <= 2:
                prev_code = k > 0 and not st[k - 1][2] and st[k - 1][0] + len(st[k - 1][1]) == a
                nxt_code = k + 1 < len(st) and not st[k + 1][2] and a + len(bs) == st[k + 1][0]
                if prev_code and nxt_code:
                    continue
            data[area].update(range(a, a + len(bs)))
    return data


def module_bases(rel, mapinfo, module_syms=None):
    """Link address of each area of one module: map address of one of its
    global symbols minus the symbol's offset in the module's .rel."""
    addr = {name: a for a, name, mod, area in mapinfo["syms"]}
    bases = {}
    for name, (area, off) in rel["syms"].items():
        if area not in bases and name in addr:
            bases[area] = addr[name] - off
    return bases


def code_image(mapinfo, mem, dup, data=frozenset(), exclude=()):
    """Concatenate the bytes of the code areas in address order, dropping data
    bytes, bytes inside ABS areas and excluded ranges. Returns (bytes, stats)."""
    code_areas = sorted((a for a in mapinfo["areas"]
                         if is_code_area(a[0]) and "ABS" not in a[3].split(",") and a[2] > 0),
                        key=lambda a: a[1])
    abs_ranges = [(a[1], a[1] + a[2]) for a in mapinfo["areas"] if "ABS" in a[3].split(",") and a[2] > 0]
    excl = list(exclude) + abs_ranges
    out = bytearray()
    st = collections.Counter()
    for name, addr, size, _ in code_areas:
        for x in range(addr, addr + size):
            if x not in mem:
                st["missing"] += 1
            elif x in data:
                st["data"] += 1
            elif x in dup or any(lo <= x < hi for lo, hi in excl):
                st["excluded"] += 1
            else:
                out.append(mem[x])
    other = sorted({a[0] for a in mapinfo["areas"]
                    if not is_code_area(a[0]) and not KNOWN_DATA_AREA.match(a[0].lstrip("_")) and a[2] > 0})
    if other:
        st["unknown_areas:" + ",".join(other)] += 1
    return bytes(out), st


# --------------------------------------------------------------------------
# SDCC programs
# --------------------------------------------------------------------------
# Compile attempts, in order: SDCC's own headers first, stubinc (declares the
# hosted stdio/stdlib bits SDCC lacks, e.g. fprintf/stderr) as fallback.
ATTEMPTS = [
    ("native-c11", ["--std-sdcc11"], False),
    ("stubinc-c11", ["--std-sdcc11", "-I" + STUBINC], False),
    ("native-c2y", ["--std-sdcc2y"], False),
    ("stubinc-c2y", ["--std-sdcc2y", "-I" + STUBINC], False),
]
LINK_FAIL = re.compile(r"ASlink-Error|Could not get|Insufficient|overlap", re.I)


def shrink_data_areas(rel_path):
    """Set uninitialised-data area sizes to 0 in a .rel so that a program whose
    variables do not fit the memory model still links (the code bytes are the
    same; data addresses wrap)."""
    t = open(rel_path, encoding="latin-1").read()
    def sub(m):
        name = m.group(1)
        if is_code_area(name) or re.match(r"^_?(CONST|RODATA|XINIT|INITIALIZER|CABS|HEADER\w*|CODEIVT\d*)$", name):
            return m.group(0)
        return "A %s size 0 flags" % name
    t2 = re.sub(r"^A\s+(\S+)\s+size\s+[0-9A-Fa-f]+\s+flags", sub, t, flags=re.M)
    with open(rel_path, "w", encoding="latin-1") as f:
        f.write(t2)


def lib_dirty_ranges(mapinfo, libinfo_dir, log):
    """Address ranges of linked library modules known to hold data in a code
    area (from sdcc-lib's libinfo); the whole module contribution is dropped."""
    excl = []
    by_mod = collections.defaultdict(list)
    for addr, name, mod, area in mapinfo["syms"]:
        by_mod[mod].append((name, addr, area))
    for libpath, member in mapinfo["libmods"]:
        libdir = os.path.basename(os.path.dirname(libpath))
        info = _libinfo(libinfo_dir, libdir)
        mod = member[:-4] if member.endswith(".rel") else member
        key = "%s/%s" % (os.path.basename(libpath), mod)
        ent = info.get(key)
        if ent is None:
            log.append("no libinfo for %s/%s" % (libdir, key))
            continue
        if not ent.get("dirty"):
            continue
        rel = read_rel(open(ent["rel"], encoding="latin-1").read())
        done = set()
        for name, addr, area in by_mod.get(mod, []):
            if name in rel["syms"]:
                a, off = rel["syms"][name]
                if a in done or not is_code_area(a):
                    continue
                base = addr - off
                excl.append((base, base + rel["areas"][a]))
                done.add(a)
        for a, size in rel["areas"].items():
            if is_code_area(a) and size and a not in done:
                log.append("dirty module %s: no symbol to place area %s" % (key, a))
    return excl


_LIBINFO_CACHE = {}


def _libinfo(d, libdir):
    if libdir not in _LIBINFO_CACHE:
        p = os.path.join(d, libdir + ".json")
        _LIBINFO_CACHE[libdir] = json.load(open(p)) if os.path.exists(p) else {}
    return _LIBINFO_CACHE[libdir]


def sdcc_prog(a):
    """Compile + link one program; write the code-only binary (or a .fail note)."""
    name = os.path.basename(a.src)[:-2]
    out_bin = os.path.join(a.out, name + ".bin")
    wd = os.path.join(a.work, name)
    note = os.path.join(wd, "result.json")
    if os.path.exists(note) and not a.force:
        return
    shutil.rmtree(wd, ignore_errors=True)
    os.makedirs(wd)
    port_flags = a.flags.split()
    log = []
    res = dict(program=name, status="fail")
    for tag, extra, _ in ATTEMPTS:
        for f in glob.glob(os.path.join(wd, "p.*")):
            os.remove(f)
        cmd = ["sdcc"] + port_flags + extra + ["-I" + a.inc, "-c", a.src, "-o", os.path.join(wd, "p.rel")]
        rc, out = run(cmd, cwd=wd, timeout=a.timeout)
        if rc == 0 and os.path.exists(os.path.join(wd, "p.rel")):
            res["attempt"] = tag
            break
        log.append("[%s] compile rc=%d\n%s" % (tag, rc, out[-3000:]))
        if rc == -9:  # timed out: it compiles, just too slowly; other attempts would too
            res["error"] = "compile timeout"
            _finish(wd, note, res, log)
            return
    else:
        res["error"] = "compile"
        _finish(wd, note, res, log)
        return
    # link (sdcc drives sdld with the right crt0/libs for the port and model)
    lcmd = ["sdcc"] + port_flags + ["p.rel", "-o", "p.ihx"]
    rc, out = run(lcmd, cwd=wd, timeout=a.timeout)
    if not os.path.exists(os.path.join(wd, "p.ihx")):
        log.append("link rc=%d\n%s" % (rc, out[-3000:]))
        shutil.copy(os.path.join(wd, "p.rel"), os.path.join(wd, "p.rel.orig"))
        shrink_data_areas(os.path.join(wd, "p.rel"))
        rc, out = run(lcmd, cwd=wd, timeout=a.timeout)
        res["link"] = "shrunk-data"
        if not os.path.exists(os.path.join(wd, "p.ihx")):
            log.append("relink rc=%d\n%s" % (rc, out[-3000:]))
            res["error"] = "link"
            _finish(wd, note, res, log)
            return
    else:
        res["link"] = "ok"
    undefined = sorted(set(re.findall(r"Undefined Global (\S+)", out)))
    if undefined:
        res["undefined"] = undefined
    mapinfo = read_map(os.path.join(wd, "p.map"))
    mem, dup = read_ihx(os.path.join(wd, "p.ihx"))
    # data directives of the program module: listing offsets + the module's
    # area bases (from its global symbols) -> absolute addresses
    rel = read_rel(open(os.path.join(wd, "p.rel"), encoding="latin-1").read())
    bases = module_bases(rel, mapinfo)
    data = set()
    for area, offs in data_offsets(os.path.join(wd, "p.lst")).items():
        if area is None or not is_code_area(area) or not offs:
            continue
        if area not in bases:
            res["error"] = "data in area %s without a global symbol to place it" % area
            _finish(wd, note, res, log)
            return
        data.update(bases[area] + o for o in offs)
    excl = lib_dirty_ranges(mapinfo, a.libinfo, log)
    code, st = code_image(mapinfo, mem, dup, data, excl)
    res.update(stats=dict(st), code_bytes=len(code),
               libmods=[m for _, m in mapinfo["libmods"]], dirty_excluded=len(excl))
    if len(code) < MIN_BYTES:
        res["status"] = "small"
    elif len(code) > MAX_PROG_BYTES:
        res["status"] = "fail"
        res["error"] = "code larger than 64 KB"
    else:
        os.makedirs(a.out, exist_ok=True)
        with open(out_bin, "wb") as f:
            f.write(code)
        res["status"] = "ok"
    _finish(wd, note, res, log)
    if not a.keep:
        for f in glob.glob(os.path.join(wd, "p.*")):
            if not f.endswith((".map", ".lst", ".rel")):
                os.remove(f)


def _finish(wd, note, res, log):
    with open(os.path.join(wd, "log.txt"), "w") as f:
        f.write("\n".join(log))
    with open(note, "w") as f:
        json.dump(res, f, indent=1)


# --------------------------------------------------------------------------
# SDCC prebuilt libraries
# --------------------------------------------------------------------------
def _find_source(port, mod):
    base = os.path.join(SDCC_SHARE, "lib", "src")
    for d in PORTS[port]["src"]:
        for ext in (".s", ".asm", ".c"):
            p = os.path.join(base, d, mod + ext)
            if os.path.exists(p):
                return p
    p = os.path.join(base, mod + ".c")
    return p if os.path.exists(p) else None


def _place_module(port, model_flags, rel_path, wd):
    """Link one .rel module and locate its code areas in the image.

    First with the port's libraries and crt0, so that calls into the runtime
    get real addresses; the module's areas are found through its global
    symbols. If that fails (link error, an area without a global symbol), the
    module is linked on its own (--nostdlib; undefined globals -> 0).
    Returns (mem, dup, {area: (start, size)}, how) or None."""
    rel = read_rel(open(rel_path, encoding="latin-1").read())
    want = {a: n for a, n in rel["areas"].items() if is_code_area(a) and n and not rel["flags"][a] & 0x08}
    base = os.path.basename(rel_path)
    for how in ("libs", "alone"):
        for f in glob.glob(os.path.join(wd, "m.*")):
            if not f.endswith((".rel", ".lst", ".asm")):
                os.remove(f)
        cmd = ["sdcc", "-m" + port] + model_flags
        if how == "alone":
            cmd.append("--nostdlib")
            if port not in ("mcs51", "ds390", "hc08", "s08", "stm8"):
                cmd.append("--no-std-crt0")
        cmd += [base, "-o", "m.ihx"]
        rc, out = run(cmd, cwd=wd, timeout=300)
        if not os.path.exists(os.path.join(wd, "m.ihx")) and how == "alone":
            # e.g. a small-model module whose data exceeds the 8051 internal RAM
            shrink_data_areas(rel_path)
            rc, out = run(cmd, cwd=wd, timeout=300)
        if not os.path.exists(os.path.join(wd, "m.ihx")) or "multiple definition" in out.lower():
            continue
        mapinfo = read_map(os.path.join(wd, "m.map"))
        mem, dup = read_ihx(os.path.join(wd, "m.ihx"))
        if how == "libs":
            bases = module_bases(rel, mapinfo)
            if not all(a in bases for a in want):
                continue
            ranges = {a: (bases[a], n) for a, n in want.items()}
        else:
            ranges = {a[0]: (a[1], a[2]) for a in mapinfo["areas"]
                      if a[0] in want and "ABS" not in a[3] and a[2] > 0}
        return mem, dup, ranges, how
    return None


def _module_bytes(mem, dup, ranges, data_offs=None):
    out = bytearray()
    for area, (lo, n) in sorted(ranges.items(), key=lambda t: t[1][0]):
        skip = (data_offs or {}).get(area, ())
        for o in range(n):
            x = lo + o
            if o in skip or x in dup or x not in mem:
                continue
            out.append(mem[x])
    return bytes(out)


def _lib_module(job):
    port, model_flags, libname, mod, rel_bytes, wd, out_path = job
    shutil.rmtree(wd, ignore_errors=True)
    os.makedirs(wd)
    rel_path = os.path.join(wd, "m.rel")
    with open(rel_path, "wb") as f:
        f.write(rel_bytes)
    info = dict(rel=rel_path, module=mod)
    rel = read_rel(rel_bytes.decode("latin-1"))
    sizes = {a: n for a, n in rel["areas"].items() if is_code_area(a) and n and not rel["flags"][a] & 0x08}
    if not sizes:
        info.update(status="empty", dirty=False)
        return libname, mod, info
    placed = _place_module(port, model_flags, rel_path, wd)
    if placed is None:
        info.update(status="link-failed", dirty=True)
        return libname, mod, info
    mem, dup, ranges, info["link"] = placed
    code = _module_bytes(mem, dup, ranges)
    info["prebuilt_bytes"] = len(code)
    # Rebuild from lib/src with a listing to find data directives in code areas.
    src = _find_source(port, mod)
    info["source"] = src
    rb = os.path.join(wd, "rebuild")
    os.makedirs(rb, exist_ok=True)
    doffs = None
    if src:
        if src.endswith(".c"):
            cmd = ["sdcc", "-m" + port] + model_flags + ["--std-c23", "-c", src, "-o", os.path.join(rb, "m.rel")]
        else:
            cmd = [PORTS[port]["asm"], "-plosgff", "-I" + os.path.dirname(src), os.path.join(rb, "m.rel"), src]
        rc, bout = run(cmd, cwd=rb, timeout=600)
        if os.path.exists(os.path.join(rb, "m.rel")) and os.path.exists(os.path.join(rb, "m.lst")):
            doffs = data_offsets(os.path.join(rb, "m.lst"))
    if doffs is None:
        # No source or it does not build here: keep the prebuilt code, flagged.
        info.update(status="unverified", dirty=False)
        result = code
    else:
        rrel = read_rel(open(os.path.join(rb, "m.rel"), encoding="latin-1").read())
        rsizes = {a: n for a, n in rrel["areas"].items() if is_code_area(a) and n and not rrel["flags"][a] & 0x08}
        doffs = {a: o for a, o in doffs.items() if a in rsizes and o}
        info["data_bytes"] = sum(len(o) for o in doffs.values())
        if not doffs:
            info.update(status="clean", dirty=False)
            result = code
        elif rsizes == sizes:
            # Same layout as the prebuilt module: drop the same offsets.
            info.update(status="masked", dirty=True)
            result = _module_bytes(mem, dup, ranges, doffs)
        else:
            # Layout differs (library built with other flags): use the rebuilt module.
            info.update(status="rebuilt", dirty=True)
            rplaced = _place_module(port, model_flags, os.path.join(rb, "m.rel"), rb)
            if rplaced is None:
                info["status"] = "rebuilt-link-failed"
                result = b""
            else:
                rmem, rdup, rranges, _ = rplaced
                result = _module_bytes(rmem, rdup, rranges, doffs)
    info["code_bytes"] = len(result)
    if len(result) >= MIN_BYTES:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(result)
        info["written"] = out_path
    return libname, mod, info


def sdcc_lib(a):
    libdir = os.path.join(SDCC_SHARE, "lib", a.libdir)
    model_flags = a.flags.split()
    jobs = []
    for lib in sorted(glob.glob(os.path.join(libdir, "*.lib"))):
        libname = os.path.basename(lib)[:-4]
        if not libname.startswith("lib"):
            libname = "lib" + libname
        seen = set()
        for member, body in ar_members(lib):
            # some archives carry the same member twice (identical copies)
            if not member.endswith(".rel") or member in seen:
                continue
            seen.add(member)
            mod = member[:-4]
            wd = os.path.join(a.work, a.libdir, libname, mod)
            out = os.path.join(a.out, "%s__%s.bin" % (libname, mod))
            jobs.append((a.port, model_flags, os.path.basename(lib), mod, body, wd, out))
    crt0 = os.path.join(libdir, "crt0.rel")
    if os.path.exists(crt0):
        jobs.append((a.port, model_flags, "crt0.rel", "crt0", open(crt0, "rb").read(),
                     os.path.join(a.work, a.libdir, "crt0", "crt0"), os.path.join(a.out, "libcrt0__crt0.bin")))
    with multiprocessing.Pool(a.jobs) as pool:
        results = pool.map(_lib_module, jobs, chunksize=1)
    info = {"%s/%s" % (lib, mod): ent for lib, mod, ent in results}
    os.makedirs(a.libinfo, exist_ok=True)
    with open(os.path.join(a.libinfo, a.libdir + ".json"), "w") as f:
        json.dump(info, f, indent=1, sort_keys=True)
    c = collections.Counter(e["status"] for e in info.values())
    w = sum(1 for e in info.values() if "written" in e)
    b = sum(e.get("code_bytes", 0) for e in info.values() if "written" in e)
    print("%-20s modules=%d written=%d bytes=%d %s" % (a.libdir, len(info), w, b, dict(c)))


# --------------------------------------------------------------------------
# 6502 linear-sweep check (cc65 library modules have no listing)
# --------------------------------------------------------------------------
def _opcodes_6502():
    t = {}
    for op in (0x00, 0x08, 0x0A, 0x18, 0x28, 0x2A, 0x38, 0x40, 0x48, 0x4A, 0x58, 0x60, 0x68, 0x6A, 0x78,
               0x88, 0x8A, 0x98, 0x9A, 0xA8, 0xAA, 0xB8, 0xBA, 0xC8, 0xCA, 0xD8, 0xE8, 0xEA, 0xF8):
        t[op] = 1
    for base in (0x00, 0x20, 0x40, 0x60, 0xC0, 0xE0, 0xA0):  # ORA AND EOR ADC CMP SBC LDA
        for off, n in ((0x09, 2), (0x05, 2), (0x15, 2), (0x01, 2), (0x11, 2), (0x0D, 3), (0x1D, 3), (0x19, 3)):
            t[base + off] = n
    for op, n in ((0x85, 2), (0x95, 2), (0x81, 2), (0x91, 2), (0x8D, 3), (0x9D, 3), (0x99, 3)):  # STA
        t[op] = n
    for base in (0x00, 0x20, 0x40, 0x60, 0xC0, 0xE0):  # ASL ROL LSR ROR DEC INC
        t[base + 0x06], t[base + 0x16], t[base + 0x0E], t[base + 0x1E] = 2, 2, 3, 3
    for op, n in ((0x86, 2), (0x96, 2), (0x8E, 3), (0xA2, 2), (0xA6, 2), (0xB6, 2), (0xAE, 3), (0xBE, 3),
                  (0x24, 2), (0x2C, 3), (0x84, 2), (0x94, 2), (0x8C, 3), (0xA0, 2), (0xA4, 2), (0xB4, 2),
                  (0xAC, 3), (0xBC, 3), (0xC0, 2), (0xC4, 2), (0xCC, 3), (0xE0, 2), (0xE4, 2), (0xEC, 3),
                  (0x4C, 3), (0x6C, 3), (0x20, 3)):
        t[op] = n
    for op in (0x10, 0x30, 0x50, 0x70, 0x90, 0xB0, 0xD0, 0xF0):
        t[op] = 2
    c = dict(t)
    for op in (0x1A, 0x3A, 0x5A, 0x7A, 0xDA, 0xFA, 0xCB, 0xDB):
        c[op] = 1
    for op in (0x80, 0x89, 0x34, 0x04, 0x14, 0x64, 0x74, 0x12, 0x32, 0x52, 0x72, 0x92, 0xB2, 0xD2, 0xF2):
        c[op] = 2
    for op in (0x0C, 0x1C, 0x3C, 0x7C, 0x9C, 0x9E):
        c[op] = 3
    for k in range(8):
        c[0x07 + 16 * k] = c[0x87 + 16 * k] = 2  # RMB/SMB
        c[0x0F + 16 * k] = c[0x8F + 16 * k] = 3  # BBR/BBS
    return t, c


OPC_6502, OPC_65C02 = _opcodes_6502()


def sweep_6502(data, cpu="6502"):
    """Linear sweep from offset 0; returns the number of undefined opcodes hit."""
    t = OPC_65C02 if cpu.upper() == "65C02" else OPC_6502
    i = bad = 0
    while i < len(data):
        n = t.get(data[i])
        if n is None:
            bad += 1
            n = 1
        i += n
    return bad


# --------------------------------------------------------------------------
# cc65
# --------------------------------------------------------------------------
CC65_CODE_SEGS = ("STARTUP", "LOWCODE", "ONCE", "CODE")


def cc65_config(full):
    """ld65 config: code segments -> %O, everything else -> %O.data / nowhere.
    full: program link (linker-defined symbols + CONDES tables, in RODATA)."""
    sym = """SYMBOLS {
    __STACKSIZE__:  type = weak, value = $0800;
    __STACKSTART__: type = weak, value = $8000;
    __ZPSTART__:    type = weak, value = $0080;
}
""" if full else ""
    feat = """FEATURES {
    CONDES: type = constructor, label = __CONSTRUCTOR_TABLE__, count = __CONSTRUCTOR_COUNT__, segment = RODATA;
    CONDES: type = destructor,  label = __DESTRUCTOR_TABLE__,  count = __DESTRUCTOR_COUNT__,  segment = RODATA;
    CONDES: type = interruptor, label = __INTERRUPTOR_TABLE__, count = __INTERRUPTOR_COUNT__, segment = RODATA, import = __CALLIRQ__;
}
""" if full else ""
    d = ", define = yes" if full else ""
    return sym + """MEMORY {
    ZP:   file = "",         start = $0080, size = $0080%s;
    MAIN: file = %%O,         start = $1000, size = $E000;
    RO:   file = "%%O.data",  start = $0000, size = $10000;
    RAM:  file = "",         start = $0000, size = $10000%s;
}
SEGMENTS {
    ZEROPAGE: load = ZP,   type = zp,  optional = yes;
    EXTZP:    load = ZP,   type = zp,  optional = yes;
    STARTUP:  load = MAIN, type = ro,  optional = yes;
    LOWCODE:  load = MAIN, type = ro,  optional = yes;
    ONCE:     load = MAIN, type = ro,  optional = yes;
    CODE:     load = MAIN, type = ro,  optional = yes;
    RODATA:   load = RO,   type = ro,  optional = yes;
    DATA:     load = RO,   type = rw,  optional = yes;
    INIT:     load = RO,   type = rw,  optional = yes;
    NULL:     load = RO,   type = rw,  optional = yes;
    BSS:      load = RAM,  type = bss, optional = yes%s;
}
""" % (d, d, d) + feat


def read_ld65_map(path):
    """-> (segments {name: start}, modules [(module, seg, offs, size)])."""
    segs, mods, mode, cur = {}, [], None, None
    for line in open(path, errors="replace"):
        line = line.rstrip("\n")
        if line.startswith("Modules list"):
            mode = "mods"
            continue
        if line.startswith("Segment list"):
            mode = "segs"
            continue
        if line.startswith("Exports list"):
            mode = None
            continue
        if mode == "mods":
            if line and not line.startswith(" ") and line.endswith(":"):
                cur = line[:-1]
            m = re.match(r"^\s+(\w+)\s+Offs=([0-9A-F]+)\s+Size=([0-9A-F]+)", line)
            if m and cur:
                mods.append((cur, m.group(1), int(m.group(2), 16), int(m.group(3), 16)))
        elif mode == "segs":
            m = re.match(r"^(\w+)\s+([0-9A-F]{6})\s+([0-9A-F]{6})\s+([0-9A-F]{6})", line)
            if m:
                segs[m.group(1)] = int(m.group(2), 16)
    return segs, mods


def _cc65_stubs(wd, names_abs, names_zp, v_abs=0, v_zp=0):
    """Define unresolved imports (0 by default, like SDCC's undefined globals)."""
    lines = [".export %s: absolute = %d" % (n, v_abs) for n in sorted(names_abs)]
    lines += [".exportzp %s: zeropage = %d" % (n, v_zp) for n in sorted(names_zp)]
    with open(os.path.join(wd, "stubs.s"), "w") as f:
        f.write("\n".join(lines) + "\n")
    return run(["ca65", "stubs.s", "-o", "stubs.o"], cwd=wd)[0] == 0


def _cc65_code(segs, mods, image, module=None, exclude=()):
    """Bytes of the code segments of `module` (or of all modules but `exclude`)
    from the MAIN image, whose file offset 0 is $1000."""
    out = bytearray()
    for mod, seg, offs, size in sorted(mods, key=lambda t: (segs.get(t[1], 0) + t[2])):
        if seg not in CC65_CODE_SEGS or size == 0:
            continue
        if module is not None and mod != module:
            continue
        if any(mod.endswith("(%s)" % e) for e in exclude):
            continue
        lo = segs[seg] + offs - 0x1000
        out += image[lo:lo + size]
    return bytes(out)


C89_KEYWORDS = re.compile(r"\b(__fastcall__|__cdecl__|__near__|__far__|__fastcall|__cdecl)\b")


def c99_to_c89(text):
    """cc65 2.19 is C89 + a little: no declarations after statements, none in
    for-init. Parse the preprocessed program with pycparser and open a nested
    block at every late declaration (same scoping), hoist for-init declarations
    into a block around the loop, then print it back as C."""
    from pycparser import c_parser, c_ast, c_generator
    DECL = (c_ast.Decl, c_ast.Typedef)

    def wrap(items):
        out, seen = [], False
        for k, it in enumerate(items):
            if isinstance(it, DECL):
                if seen:
                    out.append(c_ast.Compound(wrap(items[k:])))
                    return out
            else:
                if not isinstance(it, c_ast.Pragma):
                    seen = True
                it = fix(it)
            out.append(it)
        return out

    def fix(n):
        if n is None:
            return None
        if isinstance(n, c_ast.Compound):
            n.block_items = wrap(n.block_items or [])
        elif isinstance(n, c_ast.For):
            n.stmt = fix(n.stmt)
            if isinstance(n.init, c_ast.DeclList):
                decls, n.init = n.init.decls, None
                return c_ast.Compound(list(decls) + [n])
        elif isinstance(n, (c_ast.While, c_ast.DoWhile, c_ast.Switch, c_ast.Label)):
            n.stmt = fix(n.stmt)
        elif isinstance(n, c_ast.If):
            n.iftrue, n.iffalse = fix(n.iftrue), fix(n.iffalse)
        elif isinstance(n, (c_ast.Case, c_ast.Default)):
            n.stmts = wrap(n.stmts or [])
        return n

    text = strip_gnu(text)
    text = C89_KEYWORDS.sub("", text)
    text = re.sub(r"typedef\s+unsigned\s+char\s+_Bool\s*;", "", text)
    text = re.sub(r"\b_Bool\b", "unsigned char", text)
    ast = c_parser.CParser().parse(text, filename="<pp>")
    for ext in ast.ext:
        if isinstance(ext, c_ast.FuncDef):
            fix(ext.body)
    return c_generator.CGenerator().visit(ast)


_DATA_DIR = re.compile(r"^\s*(?:[\w@]+:)?\s*\.(byte|word|addr|dbyt|dword|faraddr|res|asciiz|lobytes|hibytes|bankbytes|literal)\b", re.I)


def data_in_code_segments(asm_text):
    seg, n = "CODE", 0
    for line in asm_text.splitlines():
        m = re.match(r'^\s*\.segment\s+"(\w+)"', line)
        if m:
            seg = m.group(1)
            continue
        t = line.strip().lower()
        if t in (".code", ".rodata", ".data", ".bss", ".zeropage"):
            seg = t[1:].upper()
            continue
        if seg in CC65_CODE_SEGS and _DATA_DIR.match(line):
            n += 1
    return n


def cc65_prog(a):
    name = os.path.basename(a.src)[:-2]
    out_bin = os.path.join(a.out, name + ".bin")
    wd = os.path.join(a.work, name)
    note = os.path.join(wd, "result.json")
    if os.path.exists(note) and not a.force:
        return
    shutil.rmtree(wd, ignore_errors=True)
    os.makedirs(wd)
    log, res = [], dict(program=name, status="fail")
    for tag, inc in (("native", []), ("stubinc", ["-I", STUBINC])):
        rc, out = run(["cc65", "-E", "-t", "none", "--cpu", a.cpu] + inc + ["-I", a.inc, a.src, "-o", "p.i"], cwd=wd)
        if rc == 0:
            res["attempt"] = tag
            break
        log.append("[%s] preprocess rc=%d\n%s" % (tag, rc, out[-2000:]))
    else:
        res["error"] = "preprocess"
        return _finish(wd, note, res, log)
    try:
        c89 = c99_to_c89(open(os.path.join(wd, "p.i"), encoding="latin-1").read())
    except Exception as e:  # pycparser cannot parse it (VLA, GNU syntax, ...)
        res["error"] = "c89: %s" % str(e)[:200]
        return _finish(wd, note, res, log)
    with open(os.path.join(wd, "p.c"), "w", encoding="latin-1") as f:
        f.write(c89)
    rc, out = run(["cc65", "-t", "none", "--cpu", a.cpu] + a.opt.split() + ["p.c", "-o", "p.s"], cwd=wd,
                  timeout=a.timeout)
    if rc != 0:
        log.append("compile rc=%d\n%s" % (rc, out[-3000:]))
        res["error"] = "compile"
        return _finish(wd, note, res, log)
    n = data_in_code_segments(open(os.path.join(wd, "p.s"), encoding="latin-1").read())
    if n:
        res["error"] = "%d data directives in code segments" % n
        return _finish(wd, note, res, log)
    rc, out = run(["ca65", "--cpu", a.cpu, "p.s", "-o", "p.o"], cwd=wd)
    if rc != 0:
        log.append("assemble rc=%d\n%s" % (rc, out[-3000:]))
        res["error"] = "assemble"
        return _finish(wd, note, res, log)
    with open(os.path.join(wd, "p.cfg"), "w") as f:
        f.write(cc65_config(full=True))
    lib = os.path.join(CC65_SHARE, "lib", a.lib + ".lib")
    objs, undefined = ["p.o"], set()
    for _ in range(3):
        rc, out = run(["ld65", "-C", "p.cfg", "-m", "p.map", "-o", "p.bin"] + objs + [lib], cwd=wd)
        if rc == 0:
            break
        unres = set(re.findall(r"Unresolved external '([^']+)'", out))
        if not unres or unres <= undefined:
            log.append("link rc=%d\n%s" % (rc, out[-3000:]))
            res["error"] = "link"
            return _finish(wd, note, res, log)
        undefined |= unres
        if not _cc65_stubs(wd, undefined, ()):
            res["error"] = "stubs"
            return _finish(wd, note, res, log)
        objs = ["p.o", "stubs.o"]
    else:
        res["error"] = "link"
        return _finish(wd, note, res, log)
    if undefined:
        res["undefined"] = sorted(undefined)
    segs, mods = read_ld65_map(os.path.join(wd, "p.map"))
    image = open(os.path.join(wd, "p.bin"), "rb").read()
    info = json.load(open(os.path.join(a.libinfo, "cc65-%s.json" % a.lib)))
    dirty = [k for k, v in info.items() if v.get("dirty")]
    linked = sorted({m.split("(")[1].rstrip(")") for m, *_ in mods if "(" in m})
    code = _cc65_code(segs, mods, image, exclude=dirty)
    res.update(code_bytes=len(code), libmods=linked, dirty_excluded=sorted(set(dirty) & set(linked)),
               undefined_opcodes=sweep_6502(_cc65_code(segs, mods, image, module="p.o"), a.cpu))
    if len(code) < MIN_BYTES:
        res["status"] = "small"
    elif len(code) > MAX_PROG_BYTES:
        res["status"] = "fail"
        res["error"] = "code larger than 64 KB"
    else:
        os.makedirs(a.out, exist_ok=True)
        with open(out_bin, "wb") as f:
            f.write(code)
        res["status"] = "ok"
    _finish(wd, note, res, log)


def _cc65_link(wd, mod, abs_, zp, lib):
    """Link one module: with `lib` (unresolved -> 0) or alone (all imports -> 0,
    a mid-range value if an expression on an import overflows). -> bool."""
    with open(os.path.join(wd, "m.cfg"), "w") as f:
        f.write(cc65_config(full=bool(lib)))
    if lib:
        objs, undefined = [mod], set()
        for _ in range(3):
            rc, out = run(["ld65", "-C", "m.cfg", "-m", "m.map", "-o", "m.bin"] + objs + [lib], cwd=wd)
            if rc == 0:
                return True
            unres = set(re.findall(r"Unresolved external '([^']+)'", out))
            if not unres or unres <= undefined:
                return False
            undefined |= unres
            if not _cc65_stubs(wd, undefined - zp, undefined & zp):
                return False
            objs = [mod, "stubs.o"]
        return False
    for v_abs, v_zp in ((0, 0), (0x2000, 0x80)):
        objs = [mod]
        if abs_ or zp:
            if not _cc65_stubs(wd, abs_, zp, v_abs, v_zp):
                return False
            objs.append("stubs.o")
        rc, out = run(["ld65", "-C", "m.cfg", "-m", "m.map", "-o", "m.bin"] + objs, cwd=wd)
        if rc == 0:
            return True
    return False


def _cc65_module(job):
    """Link one cc65 library module and take its code segments from the ld65 map.
    Linked alone first (relocation-independent image: undefined-opcode check and
    duplicate detection across libraries), then with its library so that
    runtime calls get real addresses (that image is written)."""
    obj, lib, cpu, wd, out_path = job
    shutil.rmtree(wd, ignore_errors=True)
    os.makedirs(wd)
    mod = os.path.basename(obj)
    shutil.copy(obj, os.path.join(wd, mod))
    rc, out = run(["od65", "--dump-imports", mod], cwd=wd)
    abs_, zp = set(), set()
    for size, nm in re.findall(r"Address size:\s+0x[0-9A-Fa-f]+\s+\((\w+)\)\s+Name:\s+\"([^\"]+)\"", out):
        (zp if size == "zeropage" else abs_).add(nm)

    def code():
        segs, mods = read_ld65_map(os.path.join(wd, "m.map"))
        return _cc65_code(segs, mods, open(os.path.join(wd, "m.bin"), "rb").read(), module=mod)

    if not _cc65_link(wd, mod, abs_, zp, None):
        return mod, dict(status="link-failed", dirty=True)
    alone = code()
    bad = sweep_6502(alone, cpu)
    info = dict(code_bytes=len(alone), undefined_opcodes=bad, image_sha1=hashlib.sha1(alone).hexdigest())
    if bad:
        # data (tables, strings) inside CODE: cannot be separated without source
        info.update(status="data-in-code", dirty=True)
        return mod, info
    info.update(status="clean", dirty=False)
    result, info["link"] = alone, "alone"
    if _cc65_link(wd, mod, abs_, zp, lib):
        linked = code()
        if len(linked) == len(alone):
            result, info["link"] = linked, "libs"
    if len(result) >= MIN_BYTES:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(result)
        info["written"] = out_path
    return mod, info


def cc65_lib(a):
    lib = os.path.join(CC65_SHARE, "lib", a.lib + ".lib")
    xd = os.path.join(a.work, "cc65-" + a.lib, "_objs")
    os.makedirs(xd, exist_ok=True)
    rc, out = run(["ar65", "t", lib])
    names = [n for n in out.split() if n.endswith(".o")]
    run(["ar65", "x", lib] + names, cwd=xd)
    seen = {}
    for other in a.dedupe or []:
        p = os.path.join(a.libinfo, "cc65-%s.json" % other)
        if os.path.exists(p):
            for m, e in json.load(open(p)).items():
                if e.get("image_sha1"):
                    seen[e["image_sha1"]] = other
    jobs = [(os.path.join(xd, n), lib, a.cpu, os.path.join(a.work, "cc65-" + a.lib, n[:-2]),
             os.path.join(a.out, "lib%s__%s.bin" % (a.lib, n[:-2]))) for n in names]
    with multiprocessing.Pool(a.jobs) as pool:
        results = pool.map(_cc65_module, jobs, chunksize=4)
    info = {}
    for mod, e in results:
        if "written" in e and e.get("image_sha1") in seen:
            # same code as a module of an already processed library
            os.remove(e["written"])
            del e["written"]
            e["duplicate_of"] = seen[e["image_sha1"]]
        info[mod[:-2]] = e
    if os.path.isdir(a.out) and not os.listdir(a.out):
        os.rmdir(a.out)
    os.makedirs(a.libinfo, exist_ok=True)
    with open(os.path.join(a.libinfo, "cc65-%s.json" % a.lib), "w") as f:
        json.dump(info, f, indent=1, sort_keys=True)
    c = collections.Counter(e["status"] for e in info.values())
    w = sum(1 for e in info.values() if "written" in e)
    b = sum(e.get("code_bytes", 0) for e in info.values() if "written" in e)
    print("%-20s modules=%d written=%d bytes=%d %s" % ("cc65-" + a.lib, len(info), w, b, dict(c)))


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
def _our_classes():
    """Classes built by this matrix (OUT may be shared with other generators)."""
    cls = set()
    for line in open(os.path.join(HERE, "variants.txt")):
        w = line.split()
        if not w or w[0].startswith("#"):
            continue
        cls.add(w[1] if w[0] == "lib" else w[0])
    return cls


def summary(a):
    rows = []
    for cls in sorted(set(os.listdir(a.out)) & _our_classes()):
        cdir = os.path.join(a.out, cls)
        if not os.path.isdir(cdir):
            continue
        for cfg in sorted(os.listdir(cdir)):
            bins = glob.glob(os.path.join(cdir, cfg, "*.bin"))
            nbytes = sum(os.path.getsize(b) for b in bins)
            extra = ""
            if a.work and not cfg.startswith("lib_"):
                notes = glob.glob(os.path.join(a.work, "build", cls, cfg, "*", "result.json"))
                st = collections.Counter(json.load(open(n)).get("status") for n in notes)
                extra = "jobs=%d ok=%d small=%d fail=%d" % (len(notes), st["ok"], st["small"], st["fail"])
            rows.append((cls, cfg, len(bins), nbytes, extra))
    tot = collections.defaultdict(lambda: [0, 0, 0, 0])
    for cls, cfg, n, b, extra in rows:
        print("%-8s %-34s %5d files %9d bytes  %s" % (cls, cfg, n, b, extra))
        k = 2 if cfg.startswith("lib_") else 0
        tot[cls][k] += n
        tot[cls][k + 1] += b
    print()
    for cls, (pn, pb, ln, lb) in sorted(tot.items()):
        print("%-8s programs: %5d files %9d bytes   libraries: %5d modules %8d bytes" % (cls, pn, pb, ln, lb))


def dedupe(a):
    """Remove byte-identical outputs within a class (e.g. --opt-code-size/speed
    change nothing for mcs51/ds390 on most programs; many library modules are
    the same for z80/z180/r800). The first path in sorted order is kept, so
    <config>_default wins over _size/_speed and lib dirs sort by name."""
    ours = _our_classes()
    removed = collections.Counter()
    for cls in sorted(set(os.listdir(a.out)) & ours):
        seen = {}
        for p in sorted(glob.glob(os.path.join(a.out, cls, "*", "*.bin"))):
            h = hashlib.sha1(open(p, "rb").read()).hexdigest()
            if h in seen:
                os.remove(p)
                removed[cls] += 1
            else:
                seen[h] = p
        for d in glob.glob(os.path.join(a.out, cls, "*")):
            if os.path.isdir(d) and not os.listdir(d):
                os.rmdir(d)
    print("removed duplicates:", dict(removed))


def check(a):
    """Flag outputs that do not look like code: fill, ASCII, long identical runs;
    for the 6502 class also undefined opcodes on a linear sweep."""
    flagged, n, per_cls = [], 0, collections.defaultdict(list)
    ours = _our_classes()
    for p in sorted(glob.glob(os.path.join(a.out, "*", "*", "*.bin"))):
        cls = p.split(os.sep)[-3]
        if cls not in ours:
            continue
        d = open(p, "rb").read()
        n += 1
        cfg = p.split(os.sep)[-2]
        z, ff = d.count(0) / len(d), d.count(0xFF) / len(d)
        pr = max((sum(32 <= c < 127 or c in (9, 10, 13) for c in d[i:i + 256]) / len(d[i:i + 256])
                  for i in range(0, len(d), 256) if len(d[i:i + 256]) >= 64), default=0)
        run_, best = 1, 1
        for i in range(1, len(d)):
            run_ = run_ + 1 if d[i] == d[i - 1] else 1
            best = max(best, run_)
        why = []
        if z > 0.4:
            why.append("zeros %.2f" % z)
        if ff > 0.3:
            why.append("0xFF %.2f" % ff)
        if pr > 0.85 and len(d) >= 128:
            why.append("printable block %.2f" % pr)
        if best >= 64:
            why.append("run of %d identical bytes" % best)
        if cls == "mos6502":
            cpu = "65C02" if "65c02" in cfg.lower() else "6502"
            bad = sweep_6502(d, cpu)
            if bad:
                why.append("%d undefined %s opcodes" % (bad, cpu))
        per_cls[cls].append((z, ff))
        if why:
            flagged.append((p, why))
    for cls, v in sorted(per_cls.items()):
        v.sort()
        print("%-8s files=%5d  zero-fraction median %.3f max %.3f   0xFF max %.3f" %
              (cls, len(v), v[len(v) // 2][0], max(x[0] for x in v), max(x[1] for x in v)))
    print("%d files checked, %d flagged" % (n, len(flagged)))
    for p, why in flagged[:200]:
        print("  %s: %s" % (os.path.relpath(p, a.out), ", ".join(why)))


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("prep")
    p.add_argument("armgen")
    p.add_argument("work")
    p = sp.add_parser("sdcc-prog")
    p.add_argument("--flags", required=True)
    p.add_argument("--src", required=True)
    p.add_argument("--inc", required=True)
    p.add_argument("--work", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--libinfo", required=True)
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--force", action="store_true")
    p.add_argument("--keep", action="store_true")
    p = sp.add_parser("sdcc-lib")
    p.add_argument("--port", required=True)
    p.add_argument("--libdir", required=True)
    p.add_argument("--flags", default="")
    p.add_argument("--work", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--libinfo", required=True)
    p.add_argument("--jobs", type=int, default=8)
    p = sp.add_parser("cc65-prog")
    p.add_argument("--cpu", required=True)
    p.add_argument("--opt", default="")
    p.add_argument("--lib", default="none")
    p.add_argument("--src", required=True)
    p.add_argument("--inc", required=True)
    p.add_argument("--work", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--libinfo", required=True)
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--force", action="store_true")
    p = sp.add_parser("cc65-lib")
    p.add_argument("--lib", required=True)
    p.add_argument("--cpu", required=True)
    p.add_argument("--work", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--libinfo", required=True)
    p.add_argument("--dedupe", action="append", help="skip modules identical to one of this cc65 lib")
    p.add_argument("--jobs", type=int, default=8)
    p = sp.add_parser("summary")
    p.add_argument("out")
    p.add_argument("--work")
    p = sp.add_parser("check")
    p.add_argument("out")
    p = sp.add_parser("dedupe")
    p.add_argument("out")
    a = ap.parse_args()
    if a.cmd == "prep":
        prep(a.armgen, a.work)
    elif a.cmd == "sdcc-prog":
        sdcc_prog(a)
    elif a.cmd == "sdcc-lib":
        sdcc_lib(a)
    elif a.cmd == "cc65-prog":
        cc65_prog(a)
    elif a.cmd == "cc65-lib":
        cc65_lib(a)
    elif a.cmd == "summary":
        summary(a)
    elif a.cmd == "check":
        check(a)
    elif a.cmd == "dedupe":
        dedupe(a)


if __name__ == "__main__":
    main()
