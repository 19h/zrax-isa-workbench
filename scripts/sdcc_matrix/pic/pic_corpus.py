#!/usr/bin/env python3
"""Helper for scripts/sdcc_matrix/pic/build.sh: compile the armgen C programs
and the SDCC PIC libraries, link them with gplink and cut the executable code
out of the linked (relocated) Microchip COFF.

Subcommands (build.sh calls them; see its header for the big picture):

  programs --work W --out O --cls pic14 --config NAME --port pic14 --device 16f877a
           [--flags="..."] [--jobs N] SRC.c ...   (use --flags=, values start with --)
      For every source: prep -> sdcc -c -> gplink -> extract, writing
      O/<cls>/<config>/<set>__<stem>.bin and W/build/<cls>/<config>/manifest.tsv.

  libs --work W --out O --cls pic14 --port pic14 --device 16f877a --devlib LIB
       [--jobs N] LIB.lib ...
      Every member of every library is linked on its own (plus the device
      library for the SFR addresses and generated stubs for its other
      externals, so its own sections are all that is in the image); its code
      goes to O/<cls>/lib_<port>/lib<name>__<module>.bin.

  dump FILE.o|FILE.cof
      List the sections of a Microchip COFF file.

What counts as code
  * COFF sections with STYP_TEXT set.  romdata (.cinit tables of initialised
    data), idata, udata, config (CONFIG/__CONFIG), IDLOCS and EEDATA sections
    are never STYP_TEXT and are dropped.
  * pic14: SDCC puts `const` data in code sections named IDC_<module>_N as
    RETLW tables -- dropped.
  * pic16: SDCC puts `const` data and string literals in the object's single
    unnamed `code` section (COFF name ".code"); functions always get
    S_<module>__<function>.  So for objects that have S_* sections the ".code"
    section is dropped (hand-written asm library modules keep it).  When a
    module has no other initialised constants, the string literals are instead
    appended to the last function's section; they are cut at the first
    ___str_N label (from the object's symbol table).
  * Only the program's own sections are taken from the linked image (matched by
    name against the program's object); library code linked into the program is
    not repeated in every program sample -- it is emitted once per module by
    the `libs` subcommand.
  Sections are concatenated in link-address order; gaps/fill are not included.
"""
import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
STUBINC = os.path.normpath(os.path.join(HERE, '..', '..', 'stubinc'))
MIN_BYTES = 64
STATUSES = ('linked', 'linked-mergedram', 'linked-fakemem', 'unlinked')

# ---------------------------------------------------------------- COFF ----
STYP_TEXT = 0x20
# gputils RELOC_* numbers that imply the target is code: CALL, GOTO, PAGESEL,
# GOTO2/CALL2, BRA/RCALL, CONDBRA, PAGESEL_WREG, PAGESEL_BITS, PAGESEL_MOVLP
CODE_RELOCS = {1, 2, 7, 14, 19, 20, 23, 24, 34}


def parse_coff(path):
    b = open(path, 'rb').read()
    magic, nscns, _ts, symptr, nsyms, opthdr, _fl = struct.unpack_from('<HHIIIHH', b, 0)
    if magic not in (0x1234, 0x1240):
        raise ValueError(f'{path}: not a Microchip COFF file (magic {magic:#x})')
    v2 = magic == 0x1240
    symsz = 20 if v2 else 18
    strtab = symptr + nsyms * symsz

    def name_at(off):
        raw = b[off:off + 8]
        if raw[:4] == b'\0\0\0\0':
            s = strtab + struct.unpack_from('<I', raw, 4)[0]
            return b[s:b.index(b'\0', s)].decode('latin-1')
        return raw.split(b'\0')[0].decode('latin-1')

    syms = []
    i = 0
    while i < nsyms:
        off = symptr + i * symsz
        name = name_at(off)
        if v2:
            value, secnum, _typ, cls, naux = struct.unpack_from('<IhIbb', b, off + 8)
        else:
            value, secnum, _typ, cls, naux = struct.unpack_from('<IhHbb', b, off + 8)
        syms.append({'name': name, 'value': value, 'sec': secnum, 'cls': cls, 'index': i})
        # aux entries occupy symbol-table slots of their own
        syms.extend([None] * naux)
        i += 1 + naux

    secs = []
    off = 20 + opthdr
    for _ in range(nscns):
        name = name_at(off)
        paddr, vaddr, size, scnptr, relptr, _ln, nreloc, _nln, flags = struct.unpack_from('<IIIIIIHHI', b, off + 8)
        data = b[scnptr:scnptr + size] if scnptr and size else b''
        relocs = []
        for r in range(nreloc):
            rv, rsym, roff, rtype = struct.unpack_from('<IIhH', b, relptr + 12 * r)
            relocs.append((rv, rsym, roff, rtype))
        secs.append({'name': name, 'addr': paddr, 'size': size, 'flags': flags, 'data': data, 'relocs': relocs})
        off += 40
    return {'sections': secs, 'symbols': syms}


def undefined_externals(coff):
    """{name: 'code'|'data'} for the undefined externals of an object."""
    kinds = {}
    by_index = {s['index']: s for s in coff['symbols'] if s}
    for s in coff['symbols']:
        if s and s['sec'] == 0 and s['cls'] == 2:
            kinds[s['name']] = 'data'
    for sec in coff['sections']:
        for _rv, rsym, _ro, rtype in sec['relocs']:
            s = by_index.get(rsym)
            if s and s['name'] in kinds and rtype in CODE_RELOCS:
                kinds[s['name']] = 'code'
    return kinds


STR_LABEL = re.compile(r'^___str_\d+$')


def code_sections(coff, port):
    """{name: length} of the sections of an unlinked object that hold
    executable code; length cuts off string literals that pic16 (when the
    module has no other initialised constants) appends to the last function's
    section (labels ___str_N)."""
    unit = 2 if port == 'pic14' else 1      # pic14 COFF addresses are words
    secs = coff['sections']
    names = [s['name'] for s in secs if s['flags'] & STYP_TEXT and s['size'] > 0]
    has_fn = any(n.startswith('S_') for n in names)
    keep = {}
    for n in names:
        if n.startswith('IDC_'):
            continue            # pic14 const data (RETLW tables)
        if n == '.code' and has_fn:
            continue            # pic16 const data / string literals
        keep[n] = None
    for sym in coff['symbols']:
        if sym and STR_LABEL.match(sym['name']) and 0 < sym['sec'] <= len(secs):
            n = secs[sym['sec'] - 1]['name']
            if n in keep:
                cut = sym['value'] * unit
                keep[n] = cut if keep[n] is None else min(keep[n], cut)
    return keep


def extract(linked_path, sections):
    """Bytes of the given sections ({name: length or None}) of a linked COFF,
    in address order."""
    cof = parse_coff(linked_path)
    secs = [s for s in cof['sections'] if s['name'] in sections and s['flags'] & STYP_TEXT and s['data']]
    secs.sort(key=lambda s: s['addr'])
    return b''.join(s['data'][:sections[s['name']]] for s in secs), [s['name'] for s in secs]


def extract_unlinked(obj_path, sections):
    cof = parse_coff(obj_path)
    return b''.join(s['data'][:sections[s['name']]] for s in cof['sections'] if s['name'] in sections and s['data'])

# ---------------------------------------------------------------- prep ----


# (SDCC itself provides __builtin_memcpy/memset/strcpy/strncpy/strchr/unreachable
# and __builtin_offsetof.)  GCC builtins without an SDCC equivalent become calls
# to __pic_* functions, which the link resolves to stubs.
PRELUDE = r'''/* pic_corpus.py compat prelude */
#include <stdint.h>
#define __builtin_expect(x, y) (x)
#define __builtin_assume_aligned(p, ...) ((void *)(p))
#define __builtin_prefetch(...) ((void)0)
#define __builtin_trap() ((void)0)
#define __builtin_constant_p(x) 0
#define __builtin_memcmp memcmp
#define __builtin_strlen strlen
#define __builtin_malloc malloc
#define __builtin_calloc calloc
#define __builtin_free free
#define __builtin_abs abs
#define __builtin_popcount(x) __pic_popcount(x)
#define __builtin_popcountl(x) __pic_popcount(x)
#define __builtin_popcountll(x) __pic_popcount(x)
#define __builtin_parity(x) __pic_parity(x)
#define __builtin_clz(x) __pic_clz(x)
#define __builtin_clzl(x) __pic_clz(x)
#define __builtin_clzll(x) __pic_clz(x)
#define __builtin_ctz(x) __pic_ctz(x)
#define __builtin_ctzl(x) __pic_ctz(x)
#define __builtin_ctzll(x) __pic_ctz(x)
#define __builtin_ffs(x) __pic_ffs(x)
#define __builtin_bswap16(x) __pic_bswap16(x)
#define __builtin_bswap32(x) __pic_bswap32(x)
#define __builtin_exp(x) __pic_expf(x)
#define __builtin_expf(x) __pic_expf(x)
#define __builtin_log2f(x) __pic_log2f(x)
#define __builtin_sqrt(x) __pic_sqrtf(x)
#define __builtin_sqrtf(x) __pic_sqrtf(x)
#define __builtin_fabs(x) __pic_fabsf(x)
#define __builtin_fabsf(x) __pic_fabsf(x)
#define __builtin_inff() (3.402823466e+38f)
#define __builtin_inf() (3.402823466e+38f)
#define __builtin_huge_val() (3.402823466e+38f)
#define __builtin_huge_valf() (3.402823466e+38f)
#define __builtin_nanf(s) (0.0f)
#define __builtin_nan(s) (0.0f)
#define __builtin_isnan(x) __pic_isnan(x)
#define __builtin_isinf(x) __pic_isinf(x)
#define __builtin_isfinite(x) __pic_isfinite(x)
int __pic_popcount(unsigned long x);
int __pic_parity(unsigned long x);
int __pic_clz(unsigned long x);
int __pic_ctz(unsigned long x);
int __pic_ffs(long x);
unsigned int __pic_bswap16(unsigned int x);
unsigned long __pic_bswap32(unsigned long x);
float __pic_expf(float x);
float __pic_log2f(float x);
float __pic_sqrtf(float x);
float __pic_fabsf(float x);
int __pic_isnan(float x);
int __pic_isinf(float x);
int __pic_isfinite(float x);
long __pic_xchg(void *p, long v);
int strcasecmp(const char *a, const char *b);
float fminf(float a, float b);
float fmaxf(float a, float b);
#define __sync_synchronize() ((void)0)
#define __atomic_thread_fence(m) ((void)0)
#define __atomic_signal_fence(m) ((void)0)
#define __atomic_load_n(p, m) (*(p))
#define __atomic_store_n(p, v, m) ((void)(*(p) = (v)))
#define __atomic_fetch_add(p, v, m) ((*(p) += (v)) - (v))
#define __atomic_fetch_sub(p, v, m) ((*(p) -= (v)) + (v))
#define __atomic_add_fetch(p, v, m) (*(p) += (v))
#define __atomic_sub_fetch(p, v, m) (*(p) -= (v))
#define __sync_lock_release(p) ((void)(*(p) = 0))
#define __sync_lock_test_and_set(p, v) __pic_xchg((void *)(p), (long)(v))
#define __sync_add_and_fetch(p, v) (*(p) += (v))
#define __sync_sub_and_fetch(p, v) (*(p) -= (v))
#define __sync_fetch_and_add(p, v) ((*(p) += (v)) - (v))
#define __sync_fetch_and_sub(p, v) ((*(p) -= (v)) + (v))
#define __sync_bool_compare_and_swap(p, o, n) ((*(p) == (o)) ? (*(p) = (n), 1) : 0)
#define __sync_val_compare_and_swap(p, o, n) ((*(p) == (o)) ? (*(p) = (n), (o)) : *(p))
#define __extension__
#define __inline__ inline
#define __inline inline
#define __restrict__
#define __restrict
#define __volatile__ volatile
#define __const const
#define __signed__ signed
#define __typeof__ typeof
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
'''

# pic14 has no long long: 64-bit types are narrowed to long (prep also rewrites
# `long long` and LL literal suffixes).
PRELUDE_PIC14 = r'''#ifndef __SDCC_LONGLONG
typedef long int64_t;
typedef unsigned long uint64_t;
typedef long int_least64_t;
typedef unsigned long uint_least64_t;
typedef long int_fast64_t;
typedef unsigned long uint_fast64_t;
#define INT64_MAX INT32_MAX
#define INT64_MIN INT32_MIN
#define UINT64_MAX UINT32_MAX
#define INT64_C(x) x##L
#define UINT64_C(x) x##UL
#endif
'''


def skip_balanced(s, i):
    """s[i] == '('; index just after the matching ')', skipping literals."""
    depth = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c in '"\'':
            q = c
            i += 1
            while i < n and s[i] != q:
                i += 2 if s[i] == '\\' else 1
        elif c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


ATTR = re.compile(r'\b__attribute__\s*\(')
ASM = re.compile(r'\b(?:__asm__|__asm)\b((?:\s*(?:__volatile__|volatile|__inline__|inline|goto))*)\s*\(')
ALIGNAS = re.compile(r'\b(?:alignas|_Alignas)\s*\(')
BITFIELD = re.compile(r'(\b[A-Za-z_]\w*\s+[A-Za-z_]\w*\s*):\s*(\d+)\s*;')
ANON_BITFIELD = re.compile(r'(?m)(^|[;{])(\s*)(?:unsigned\s+|signed\s+)?(?!case\b|default\b)[A-Za-z_]\w*\s*:\s*(\d+)\s*;')
DEFINE_PREFIX = re.compile(r'#\s*(?:define|undef)\s*$')
LONGLONG = re.compile(r'\blong\s+long\b')
LLSUFFIX = re.compile(r'\b((?:0[xX][0-9a-fA-F]+|\d+)[uU]?)[lL][lL]([uU]?)\b')


def strip_gnu(src):
    out = []
    i = 0
    while True:
        m = None
        for rx in (ATTR, ASM, ALIGNAS):
            mm = rx.search(src, i)
            if mm and (m is None or mm.start() < m.start()):
                m = mm
        if not m:
            out.append(src[i:])
            break
        out.append(src[i:m.start()])
        end = skip_balanced(src, m.end() - 1)
        line_start = src.rfind('\n', 0, m.start()) + 1
        if DEFINE_PREFIX.match(src[line_start:m.start()].strip()):
            out.append(src[m.start():end])   # `#define __attribute__(x)` stays
            i = end
            continue
        if m.re is ASM:
            prev = src[:m.start()].rstrip()
            if not (prev and (prev[-1].isalnum() or prev[-1] == '_')):
                out.append('((void)0)')     # asm statement -> no-op expression
        # keep line numbers stable
        out.append('\n' * src.count('\n', m.start(), end))
        i = end
    return ''.join(out)


def prep_source(src, port):
    s = strip_gnu(src)
    # SDCC bit-fields are at most 16 bits wide: wider ones become plain members.
    s = BITFIELD.sub(lambda m: m.group(1) + ';' if int(m.group(2)) > 16 else m.group(0), s)
    s = ANON_BITFIELD.sub(lambda m: m.group(1) + m.group(2) if int(m.group(3)) > 16 else m.group(0), s)  # padding
    pre = PRELUDE
    if port == 'pic14':
        s = LONGLONG.sub('long', s)
        s = LLSUFFIX.sub(lambda m: m.group(1) + 'L' + m.group(2), s)
        pre += PRELUDE_PIC14
    return pre + '#line 1\n' + s

# ------------------------------------------------------------- toolchain ----


def run(cmd, cwd, log, timeout=600):
    with open(log, 'a') as fh:
        fh.write('$ ' + ' '.join(cmd) + '\n')
        fh.flush()
        try:
            p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=timeout, text=True, errors='replace')
        except subprocess.TimeoutExpired:
            fh.write('TIMEOUT\n')
            return 124, ''
        fh.write(p.stdout)
        return p.returncode, p.stdout


def lkr_path(device):
    gplink = os.path.realpath(shutil.which('gplink'))
    return os.path.normpath(os.path.join(os.path.dirname(gplink), '..', 'share', 'gputils', 'lkr', f'{device}_g.lkr'))


def sdcc_lib_dir(port):
    sdcc = shutil.which('sdcc')
    return os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(sdcc)), '..', 'share', 'sdcc', 'lib', port))


def enhanced(device):
    """pic14 enhanced midrange (16f1xxx and later) use the *e libraries."""
    return bool(re.match(r'1[26]l?f1\d{3}$', device))


def default_libs(port, device):
    if port == 'pic14':
        e = 'e' if enhanced(device) else ''
        return [f'libsdcc{e}.lib', f'libc{e}.lib', f'libm{e}.lib', f'pic{device}.lib'], []
    return [f'libdev{device}.lib', 'libc18f.lib', 'libm18f.lib', 'libsdcc.lib'], ['crt0iz.o']


# SDCC pic14 programs define the argument stack / interrupt save area in the
# common RAM at 0x70; library modules only reference it.
PIC14_SHAREBANK = ['PSAVE', 'SSAVE', 'WSAVE'] + [f'STK{i:02d}' for i in range(12, -1, -1)]


def write_stubs(path, proc, kinds):
    code = sorted(n for n, k in kinds.items() if k == 'code')
    data = sorted(n for n, k in kinds.items() if k != 'code')
    lines = [f'\tlist p={proc}', '\tradix dec']
    lines += [f'\tglobal {n}' for n in code + data]
    if proc.startswith('1') and proc[1] in '026' and not proc.startswith('18') \
            and any(n in PIC14_SHAREBANK for n in data):
        data = [n for n in data if n not in PIC14_SHAREBANK]
        lines.append('sharebank udata_ovr 0x0070')
        lines += [f'{n}\tres 1' for n in PIC14_SHAREBANK]
    if code:
        lines.append('__pic_stub_code code')
        lines += [f'{n}' for n in code]
        lines.append('\treturn')
    if data:
        lines.append('__pic_stub_data udata')
        lines += [f'{n}\tres 2' for n in data]
    lines.append('\tend')
    with open(path, 'w') as fh:
        fh.write('\n'.join(lines) + '\n')


MISSING = re.compile(r'External symbol "([^"]+)" in section "[^"]*" not found')
DATABANK = re.compile(r'^DATABANK\s+NAME=(\S+)\s+START=(0x[0-9A-Fa-f]+)\s+END=(0x[0-9A-Fa-f]+)')


CODEPAGE = re.compile(r'^CODEPAGE\s+NAME=(\S+)\s+START=(0x[0-9A-Fa-f]+)\s+END=(0x[0-9A-Fa-f]+)\s*$')


def ram_lkr(device, port, level, dst):
    """Linker script with more memory, for programs that do not fit the device.
    level 1 (pic16): the stock gpr0..gprN banks merged into one DATABANK
             (standard practice for PIC18 arrays > 256 B; real addresses).
    level 2: fake memory.  pic16: merged banks + RAM at 0x1000-0xFFFFFF (the
             12-bit operand fields just wrap) + ROM at 0x100000-0x1FFFFF.
             pic14: sfr0 + one DATABANK 0x20-0xFFFFFF instead of the banked/
             shared/linear regions (RELOC_F keeps the low 7 bits, BANKSEL the
             next two, as for real addresses) and the code pages merged into
             one + ROM at 0x10000-0x7FFFF (GOTO/CALL keep 11 bits, PAGESEL the
             next bits, as for real addresses).
    Instruction bytes stay real compiler/linker output; only operand addresses
    are not those of a real device."""
    out, lo, hi, plo, phi = [], None, None, None, None
    for ln in open(lkr_path(device)).read().splitlines():
        m = DATABANK.match(ln)
        c = CODEPAGE.match(ln)      # unprotected code pages only
        if port == 'pic16':
            if m and re.fullmatch(r'gpr\d+', m.group(1)):
                a, b = int(m.group(2), 16), int(m.group(3), 16)
                lo = a if lo is None else min(lo, a)
                hi = b if hi is None else max(hi, b)
                continue
        else:
            if m and m.group(1) != 'sfr0':
                continue
            if re.match(r'^\s*(SHAREBANK|LINEARMEM)\b', ln) or re.match(r'^\s*SECTION\s+NAME=\S+\s+(RAM|ROM)=', ln):
                continue
            if c:
                a, b = int(c.group(2), 16), int(c.group(3), 16)
                plo = a if plo is None else min(plo, a)
                phi = b if phi is None else max(phi, b)
                continue
        out.append(ln)
    if port == 'pic16':
        out.append(f'DATABANK   NAME=gprall     START={lo:#x}  END={hi:#x}')
        if level >= 2:
            out.append('DATABANK   NAME=fakeram    START=0x1000  END=0xFFFFFF')
            out.append('CODEPAGE   NAME=fakerom    START=0x100000  END=0x1FFFFF')
    else:
        out.append(f'CODEPAGE   NAME=pageall    START={plo:#x}  END={phi:#x}')
        out.append('CODEPAGE   NAME=fakerom    START=0x10000  END=0x7FFFF')
        out.append('DATABANK   NAME=fakeram    START=0x20  END=0xFFFFFF')
    with open(dst, 'w') as fh:
        fh.write('\n'.join(out) + '\n')
    return dst


def link(objs, libs, incdirs, device, cwd, out_base, log, hint_kinds, lkr, rounds=6):
    """gplink objs+libs; unresolved externals get stub definitions (code stubs
    unless the relocations in hint_kinds say data).  Returns path of the linked
    COFF or None, plus the stubbed symbol names."""
    kinds = {}
    stub_asm = os.path.join(cwd, '__stubs.asm')
    stub_obj = os.path.join(cwd, '__stubs.o')
    for _ in range(rounds):
        extra = []
        if kinds:
            write_stubs(stub_asm, device, kinds)
            rc, _o = run(['gpasm', '-c', '-p', device, '-o', stub_obj, stub_asm], cwd, log)
            if rc:
                return None, kinds
            extra = [stub_obj]
        cmd = ['gplink', '-w', '-r', '-m', '-c', '-s', lkr, '-o', out_base + '.hex']
        for d in incdirs:
            cmd += ['-I', d]
        rc, out = run(cmd + objs + extra + libs, cwd, log)
        if rc == 0 and os.path.exists(out_base + '.cof'):
            return out_base + '.cof', kinds
        new = {n for n in MISSING.findall(out) if n not in kinds}
        if not new:
            return None, kinds
        for n in new:
            kinds[n] = hint_kinds.get(n, 'code')
    return None, kinds


def link_any(objs, libs, incdirs, device, port, cwd, out_base, log, hint_kinds):
    """Stock linker script first, then the ram_lkr() levels.  Returns
    (linked COFF or None, status, stubs)."""
    tries = [('linked', lkr_path(device))]
    if port == 'pic16':
        tries.append(('linked-mergedram', 1))
    tries.append(('linked-fakemem', 2))
    stubs = {}
    for status, lkr in tries:
        if isinstance(lkr, int):
            lkr = ram_lkr(device, port, lkr, os.path.join(cwd, f'__ram{lkr}.lkr'))
        cof, stubs = link(objs, libs, incdirs, device, cwd, out_base, log, hint_kinds, lkr)
        if cof:
            return cof, status, stubs
    return None, 'unlinked', stubs

# -------------------------------------------------------------- programs ----


def build_program(src, a):
    set_ = os.path.basename(os.path.dirname(os.path.abspath(src)))
    stem = os.path.splitext(os.path.basename(src))[0]
    tag = f'{set_}__{stem}'
    bdir = os.path.join(a.work, 'build', a.cls, a.config, tag)
    shutil.rmtree(bdir, ignore_errors=True)
    os.makedirs(bdir)
    log = os.path.join(bdir, 'log.txt')
    # module name = stem, so section names are S_<stem>__<fn>
    csrc = os.path.join(bdir, stem + '.c')
    with open(src, encoding='latin-1') as fh:
        text = prep_source(fh.read(), a.port)
    with open(csrc, 'w', encoding='latin-1') as fh:
        fh.write(text)
    armgen_programs = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(src))), 'programs')
    base = ['sdcc', f'-m{a.port}', f'-p{a.device}', '--use-non-free', '--no-warn-non-free', '--std-c99',
            '-I', os.path.join(a.work, 'sdk', 'include', a.port)] + a.flags.split()
    obj = os.path.join(bdir, stem + '.o')
    headers = None
    # SDCC's headers first, then scripts/stubinc; pic14 "Out of stack Space"
    # (too few argument-passing stack bytes) is retried with --stack-size 64.
    for attempt, inc in (('sdcc', []), ('stubinc', ['-I', STUBINC])):
        cmd = base + inc + ['-I', armgen_programs, '-c', csrc, '-o', obj]
        rc, out = run(cmd, bdir, log, timeout=a.timeout)
        if rc and a.port == 'pic14' and 'Out of stack Space' in out:
            rc, out = run(cmd[:1] + ['--stack-size', '64'] + cmd[1:], bdir, log, timeout=a.timeout)
            attempt += '+stack64'
        if rc == 0 and os.path.exists(obj):
            headers = attempt
            break
    if headers is None:
        return tag, 'compile-fail', 0, ''
    cof = parse_coff(obj)
    names = code_sections(cof, a.port)
    libs, crt = default_libs(a.port, a.device)
    incdirs = [os.path.join(a.work, 'sdk', 'lib', a.port), sdcc_lib_dir(a.port)]
    linked, how, stubs = link_any([obj] + crt, libs, incdirs, a.device, a.port, bdir, os.path.join(bdir, stem),
                                  log, undefined_externals(cof))
    if linked:
        data, _ = extract(linked, names)
    else:
        data = extract_unlinked(obj, names)
    dst = os.path.join(a.out, a.cls, a.config, tag + '.bin')
    if len(data) < MIN_BYTES:
        return tag, f'small-{how}', len(data), headers
    with open(dst, 'wb') as fh:
        fh.write(data)
    note = headers + (f' stubs={len(stubs)}' if stubs else '')
    return tag, how, len(data), note


def cmd_programs(a):
    outdir = os.path.join(a.out, a.cls, a.config)
    os.makedirs(outdir, exist_ok=True)
    for f in os.listdir(outdir):
        if f.endswith('.bin'):
            os.remove(os.path.join(outdir, f))
    mdir = os.path.join(a.work, 'build', a.cls, a.config)
    os.makedirs(mdir, exist_ok=True)
    with ThreadPoolExecutor(a.jobs) as ex:
        res = list(ex.map(lambda s: build_program(s, a), a.sources))
    res.sort()
    with open(os.path.join(mdir, 'manifest.tsv'), 'w') as fh:
        for r in res:
            fh.write('\t'.join(map(str, r)) + '\n')
    ok = [r for r in res if r[1] in STATUSES]
    by = ', '.join(f'{k} {sum(1 for r in ok if r[1] == k)}' for k in STATUSES)
    fails = sum(1 for r in res if r[1] == 'compile-fail')
    print(f'{a.cls}/{a.config}: {len(ok)} samples ({by}), {sum(r[2] for r in ok)} code bytes; '
          f'{fails} failed to compile, {sum(1 for r in res if r[1].startswith("small"))} < {MIN_BYTES} B')

# ------------------------------------------------------------------ libs ----


def cmd_libs(a):
    outdir = os.path.join(a.out, a.cls, f'lib_{a.port}')
    os.makedirs(outdir, exist_ok=True)
    incdirs = [os.path.join(a.work, 'sdk', 'lib', a.port), sdcc_lib_dir(a.port)]
    rows = []
    for lib in a.libs:
        libpath = lib if os.path.isabs(lib) else os.path.join(sdcc_lib_dir(a.port), lib)
        lname = os.path.splitext(os.path.basename(libpath))[0]
        lname = lname[3:] if lname.startswith('lib') else lname
        xdir = os.path.join(a.work, 'libs', a.port, lname)
        shutil.rmtree(xdir, ignore_errors=True)
        os.makedirs(xdir)
        log = os.path.join(xdir, 'log.txt')
        _, listing = run(['gplib', '-t', libpath], xdir, log)
        members = [ln.split()[0] for ln in listing.splitlines() if ln.split() and ln.split()[0].endswith('.o')]
        for f in os.listdir(outdir):
            if f.startswith(f'lib{lname}__') and f.endswith('.bin'):
                os.remove(os.path.join(outdir, f))

        def one(member):
            mdir = os.path.join(xdir, os.path.splitext(member)[0])
            os.makedirs(mdir, exist_ok=True)
            mlog = os.path.join(mdir, 'log.txt')
            run(['gplib', '-x', libpath, member], mdir, mlog)
            obj = os.path.join(mdir, member)
            if not os.path.exists(obj):
                return member, 'extract-fail', 0
            cof = parse_coff(obj)
            names = code_sections(cof, a.port)
            if not names:
                return member, 'no-code', 0
            linked, how, _ = link_any([obj], [a.devlib], incdirs, a.device, a.port, mdir,
                                      os.path.join(mdir, '__linked'), mlog, undefined_externals(cof))
            if linked:
                data, _ = extract(linked, names)
            else:
                data = extract_unlinked(obj, names)
            if len(data) < MIN_BYTES:
                return member, f'small-{how}', len(data)
            mod = os.path.splitext(member)[0]
            # automake prefixes objects with the library name (libsdcc_a-foo.o)
            mod = re.sub(r'^lib\w*?_a-', '', mod)
            with open(os.path.join(outdir, f'lib{lname}__{mod}.bin'), 'wb') as fh:
                fh.write(data)
            return member, how, len(data)

        with ThreadPoolExecutor(a.jobs) as ex:
            res = list(ex.map(one, members))
        rows += [(lname,) + r for r in res]
        ok = [r for r in res if r[1] in STATUSES]
        by = ', '.join(f'{k} {n}' for k in STATUSES if (n := sum(1 for r in ok if r[1] == k)))
        print(f'{a.cls}/lib_{a.port}: lib{lname}: {len(ok)}/{len(members)} modules ({by}), '
              f'{sum(r[2] for r in ok)} code bytes')
    with open(os.path.join(a.work, 'libs', a.port, 'manifest.tsv'), 'a') as fh:
        for r in rows:
            fh.write('\t'.join(map(str, r)) + '\n')


def cmd_dump(a):
    c = parse_coff(a.file)
    for s in c['sections']:
        print(f"{s['name']:32s} addr={s['addr']:#08x} size={s['size']:6d} flags={s['flags']:#07x} relocs={len(s['relocs'])}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('programs')
    for k in ('work', 'out', 'cls', 'config', 'port', 'device'):
        p.add_argument('--' + k, required=True)
    p.add_argument('--flags', default='')
    p.add_argument('--jobs', type=int, default=4)
    p.add_argument('--timeout', type=int, default=240)
    p.add_argument('sources', nargs='+')
    p = sub.add_parser('libs')
    for k in ('work', 'out', 'cls', 'port', 'device', 'devlib'):
        p.add_argument('--' + k, required=True)
    p.add_argument('--jobs', type=int, default=4)
    p.add_argument('libs', nargs='+')
    p = sub.add_parser('dump')
    p.add_argument('file')
    a = ap.parse_args()
    {'programs': cmd_programs, 'libs': cmd_libs, 'dump': cmd_dump}[a.cmd](a)


if __name__ == '__main__':
    main()
