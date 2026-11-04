#!/usr/bin/env python3
"""Sunplus µ'nSP code in ROM images, by recursive descent from the vectors.

Ground truth for a µ'nSP model class: MAME runs these dumps on µ'nSP SoCs
(SPG2xx, V.Smile system ROMs, GPL162xx), but a dump also holds graphics,
audio and tables. Only words reached as instructions from the CPU's
interrupt vectors are kept.

The ROM is read as 16-bit words in the given byte order and mapped flat:
word i of the file is CPU word address i, as MAME maps SPG2xx program ROMs
and the V.Smile system ROM (vtech/vsmile.cpp). Word addresses below
CPU_ROM_START are internal RAM and I/O on these SoCs, so flow into them is
not followed. The vectors are the 16-bit words at 0xFFF5-0xFFFF (break, FIQ,
reset, IRQ0-IRQ7; bank 0).

Decoding follows MAME's µ'nSP disassembler at commit
df3bcbba30251a393d8bb33a356c6c2ee93c34e9 (src/devices/cpu/unsp/unspdasm.cpp,
unspdasm_jumps.cpp, unspdasm_other.cpp, unspdasm_exxx.cpp,
unspdasm_fxxx.cpp), with the µ'nSP 1.2 instructions (the Exxx bit
operations, `ds`/`fr` moves, `call mr`, `goto mr`). The µ'nSP 2.0 extended
group (0xFF80 prefix) ends a path without rejecting it.

Tracing is per function: a function starts at a vector, a `call` target,
the first word after traced code that is not fill, or any untraced `push`
word (the last two are gap functions);
its conditional and unconditional jumps are followed, `call` targets become
new functions, and `retf`, `reti`, a `pop` into `pc` (returns), an ALU write
to `pc` and `goto mr` end a path. A function that reaches an invalid encoding
(MAME's `<BAD>`, `<DUNNO>`, `<UNDEFINED>`, words 0x0000/0xFFFF) or runs
past the end of the ROM is dropped with everything only it reached: data
read as code meets such an encoding quickly. A gap function must also start
with a `push`, stay in ROM and end a path in a return; so must the functions
it calls. Precision of these rules (2026-11-04): seeded at every `push`-shaped
word of 1 MiB of random bytes and 30 non-µ'nSP corpus samples (ARM, Thumb,
Z80, 68000, MSP430, SH, x86-16, AVR, MIPS, 8051, Hexagon code; PCM,
pixels, tables, .rodata, text), 8 of 6,097 gap functions were kept, 58 words
in all.

Output: OUT_DIR/<file name prefix>.bin, the traced instruction words in
address order (gaps removed) as little-endian words, and one TSV line per ROM
on stdout:

    file, byte order, functions kept, functions dropped, words traced

Usage: unsp_trace.py [--byte-order le|be] OUT_DIR ROM...
"""
import argparse
import dataclasses
import os
import struct

CPU_ROM_START = 0x4000
# Gap functions: least size, and most fill words skipped before one.
MIN_GAP_FUNCTION_WORDS = 4
MAX_FILL_WORDS = 64
# A traced function of at least REPEATED_FUNCTION_MIN_WORDS words in which
# one word value is more than REPEATED_WORD_MAX_SHARE of the instruction
# words is fill or pixel data that decodes as straight-line code, not a
# function (our rule). In MAME's `pokermor` ROM (`29dl640e.u3`), vectors
# that point into 16-bit pixel data traced 1,399 of its 1,405 words through
# three such "functions" (409-557 words, one word 59-99%); in the 8 other
# µ'nSP ROMs no function over 25 words has a word over half (2026-11-04).
REPEATED_FUNCTION_MIN_WORDS = 64
REPEATED_WORD_MAX_SHARE = 0.5
VECTORS = range(0xFFF5, 0x10000)
# The reset vector, and the most word addresses the other ten vectors (break,
# FIQ, IRQ0-IRQ7) may span: their handlers sit together. In the 8 µ'nSP ROMs
# of the fw1 set with traceable code they span 0x14 to 0x194 words; the words
# at 0xFFF5 of MAME's `pokermor` ROM, which are 16-bit pixel data, span
# 0x2A18 (2026-11-04). Our rule, from these ROMs.
RESET_VECTOR = 0xFFF7
MAX_HANDLER_VECTOR_SPAN = 0x400
RETF = 0x9A90
RETI = 0x9A98
PC = 7
OP_CMP = 4
OP_TEST = 12
OP_STORE = 13
OP_JMP = 14
# MAME's `<BAD>` cases of disassemble_remaining, as (op1 << 4) | op0.
BAD_FORMS = frozenset(
    [0x05, 0x15, 0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0x85, 0x95, 0xA5, 0xB5, 0xC5, 0xD5,
     0x07, 0x17, 0x27, 0x37, 0x47, 0x57, 0x67, 0x77, 0x87, 0x97, 0xA7, 0xB7, 0xC7, 0xD7,
     0x1D, 0x5D, 0x6D, 0x20, 0x21, 0x22, 0x23, 0x24, 0x26, 0x28, 0x2A, 0x2B, 0x2C]
)
# Low six bits of the defined Fxxx group-5 instructions (int, fir_mov, irq,
# fiq, fraction, secbank, irqnest; break; nop; call mr; divs; divq; exp).
GROUP5_DEFINED = frozenset(list(range(0x00, 0x10)) + [0x20, 0x28, 0x30, 0x38, 0x25, 0x2D, 0x35, 0x3D]
                           + [base + step for base in (0x21, 0x22, 0x23, 0x24) for step in (0, 8, 16, 24)])

# Kinds of instruction. RETURN ends a path by returning (`retf`, `reti`, a
# `pop` into `pc`); END ends it otherwise (an ALU write to `pc`, `goto mr`,
# the 2.0 extended group).
NORMAL, BRANCH, JUMP, CALL, RETURN, END, INVALID = (
    "normal", "branch", "jump", "call", "return", "end", "invalid")


@dataclasses.dataclass
class Instruction:
    length: int
    kind: str
    target: int = 0


def writes_pc(op0, op_a):
    """Whether an ALU instruction with destination register op_a writes pc."""
    return op_a == PC and op0 not in (OP_CMP, OP_TEST, OP_STORE)


def decode_fxxx(op, ximm):
    group = (op >> 6) & 7
    if group == 1:
        if op & 0xF3C0 == 0xF040:
            return Instruction(2, CALL, ((op & 0x3F) << 16) | ximm)
        if op & 0xF3C0 == 0xF240:
            return Instruction(2, NORMAL)  # µ'nSP 2.0 bit operation on [A16]
        return Instruction(1, INVALID)
    if group == 2 and op & 0xFFC0 == 0xFE80:
        return Instruction(2, JUMP, ((op & 0x3F) << 16) | ximm)
    if group == 3 and op & 0xFFC0 == 0xFEC0:
        return Instruction(1, END)  # goto mr
    if group == 4:
        return Instruction(1, NORMAL if op & 0xF1F8 == 0xF108 else INVALID)
    if group == 5:
        return Instruction(1, NORMAL if op & 0x3F in GROUP5_DEFINED else INVALID)
    if group == 6 and op == 0xFF80:
        return Instruction(1, END)  # µ'nSP 2.0 extended group: length not decoded here
    if group == 0:
        is_ds_fr_move = op & 0xFFC0 == 0xFE00 or op & 0xF1F8 in (0xF020, 0xF028, 0xF030, 0xF038)
        # MUL: bits 7-3 are fixed 0 0001 (print_mul).
        return Instruction(1, NORMAL if is_ds_fr_move or op & 0x00F8 == 0x0008 else INVALID)
    return Instruction(1, NORMAL)  # muls


def decode_exxx(op):
    # µ'nSP 1.2 bit operations, mul, muls and 16-bit shifts.
    if (op & 0xF1C8 in (0xE000, 0xE100, 0xE140, 0xE008) or op & 0xF1C0 in (0xE040, 0xE180, 0xE1C0)
            or op & 0xF180 == 0xE080 or op & 0xF188 == 0xE108):
        return Instruction(1, NORMAL)
    return Instruction(1, INVALID)


def decode(op, ximm, pc):
    """The instruction at word address pc with first word op and next word ximm."""
    if op in (0x0000, 0xFFFF):
        return Instruction(1, INVALID)
    op0 = op >> 12
    op_a = (op >> 9) & 7
    op1 = (op >> 6) & 7
    op_n = (op >> 3) & 7
    op_b = op & 7
    if op0 == 0xF:
        return decode_fxxx(op, ximm)
    if op_a == PC and op1 < 2:
        offset = op & 0x3F
        target = pc + 1 + offset if op1 == 0 else pc + 1 - offset
        return Instruction(1, JUMP if op0 == OP_JMP else BRANCH, target)
    if op0 == 0xE:
        return decode_exxx(op)
    form = (op1 << 4) | op0
    if form in BAD_FORMS:
        return Instruction(1, INVALID)
    if form == 0x29:  # pop
        if op in (RETF, RETI):
            return Instruction(1, RETURN)
        if op_a + 1 < 8 and op_a + op_n < 8:
            return Instruction(1, RETURN if op_a + op_n == PC else NORMAL)
        return Instruction(1, INVALID)
    if form == 0x2D:
        return Instruction(1, NORMAL if is_push(op) else INVALID)
    if form == 0x4D:
        return Instruction(2, NORMAL) if op_n == 3 and op_a == op_b else Instruction(1, INVALID)
    if op1 == 4 and op_n in (1, 2, 3):
        one_operand = op0 in (OP_CMP, OP_TEST, 6)
        if op_n in (1, 2) and one_operand and op_a != op_b:
            return Instruction(1, INVALID)
        if op_n == 3 and (op0 in (OP_CMP, OP_TEST) or (op0 in (6, 9) and op_a != op_b)):
            return Instruction(1, INVALID)
        if op_n == 3:
            return Instruction(2, NORMAL)  # [A16] = Rb op Ra: writes memory
        return Instruction(2, END if writes_pc(op0, op_a) else NORMAL)
    if op0 == OP_STORE:
        return Instruction(1, NORMAL)
    return Instruction(1, END if writes_pc(op0, op_a) else NORMAL)


def is_push(op):
    """Whether op is a defined `push` instruction."""
    op_a = (op >> 9) & 7
    op_n = (op >> 3) & 7
    is_push_form = (op >> 12) == OP_STORE and (op >> 6) & 7 == 2
    return is_push_form and op_a + 1 >= op_n and op_a < op_n + 7


def trace_function(words, start, strict=False):
    """(instruction addresses, call targets) of the function at start, or None if it is dropped.

    `strict` is for functions found in gaps rather than reached by a call: they
    must also start with a `push` (the prologue of most called functions in
    these ROMs), stay in ROM, end at least one path in a return (`retf`,
    `reti`, `pop` into `pc`), and hold at least MIN_GAP_FUNCTION_WORDS words.
    """
    if strict and not is_push(words[start] if start < len(words) else 0):
        return None
    seen = {}
    calls = set()
    returns = 0
    work = [start]
    while work:
        pc = work.pop()
        if pc in seen:
            continue
        if pc >= len(words):
            return None
        if pc < CPU_ROM_START:
            if strict:
                return None
            continue  # RAM or I/O: not in the dump
        ximm = words[pc + 1] if pc + 1 < len(words) else 0
        instruction = decode(words[pc], ximm, pc)
        if instruction.kind == INVALID or pc + instruction.length > len(words):
            return None
        seen[pc] = instruction.length
        following = pc + instruction.length
        if instruction.kind == NORMAL:
            work.append(following)
        elif instruction.kind == BRANCH:
            work.extend((following, instruction.target))
        elif instruction.kind == JUMP:
            work.append(instruction.target)
        elif instruction.kind == CALL:
            calls.add(instruction.target)
            work.append(following)
        elif instruction.kind == RETURN:
            returns += 1
    if strict and (returns == 0 or sum(seen.values()) < MIN_GAP_FUNCTION_WORDS):
        return None
    return seen, calls


def is_repeated_word_run(words, seen):
    """Whether a traced function is mostly one repeated word (see
    REPEATED_FUNCTION_MIN_WORDS)."""
    body = [words[address] for pc, length in seen.items() for address in range(pc, pc + length)]
    if len(body) < REPEATED_FUNCTION_MIN_WORDS:
        return False
    most = max(body.count(word) for word in set(body))
    return most > REPEATED_WORD_MAX_SHARE * len(body)


def gap_starts(words, code):
    """Where a function may start after traced code: the first word after each
    traced run that is not fill (0x0000/0xFFFF, at most MAX_FILL_WORDS)."""
    covered = {word for pc, length in code.items() for word in range(pc, pc + length)}
    starts = set()
    for word in covered:
        start = word + 1
        if start in covered:
            continue
        fill = 0
        while start < len(words) and words[start] in (0x0000, 0xFFFF) and fill <= MAX_FILL_WORDS:
            start += 1
            fill += 1
        if start < len(words) and start not in covered and fill <= MAX_FILL_WORDS:
            starts.add(start)
    return starts


def has_vector_table(words):
    """Whether the words at VECTORS look like a vector table: the handler
    vectors other than reset lie within MAX_HANDLER_VECTOR_SPAN words."""
    handlers = [words[v] for v in VECTORS if v != RESET_VECTOR]
    return max(handlers) - min(handlers) <= MAX_HANDLER_VECTOR_SPAN


def trace(words):
    """Instruction words reached from the vectors, found in the gaps after
    traced code, or found at `push` words: ({address: length}, kept, dropped).
    Nothing for a ROM without a vector table: none of its code is
    established, so no gap or `push` word is either."""
    if len(words) < VECTORS.stop or not has_vector_table(words):
        return {}, 0, 0
    code = {}
    done = set()
    kept = dropped = 0
    pending = [(words[v], False) for v in VECTORS]
    scanned_pushes = False
    while pending:
        while pending:
            start, strict = pending.pop()
            if start in done:
                continue
            done.add(start)
            result = trace_function(words, start, strict)
            if result is None or is_repeated_word_run(words, result[0]):
                dropped += 1
                continue
            kept += 1
            seen, calls = result
            code.update(seen)
            # Callees of a gap function are no better established than it is.
            pending.extend((target, strict) for target in calls - done)
        pending = [(start, True) for start in gap_starts(words, code) - done]
        if not pending and not scanned_pushes:
            # Functions no traced code reaches directly (called through
            # pointers): every untraced `push` word starts a strict function.
            scanned_pushes = True
            covered = {word for pc, length in code.items() for word in range(pc, pc + length)}
            pending = [(w, True) for w in range(CPU_ROM_START, len(words))
                       if is_push(words[w]) and w not in covered and w not in done]
    return code, kept, dropped


def traced_bytes(words, code):
    """The traced instruction words in address order, as little-endian bytes
    (the byte order of the model's `unsp` class)."""
    covered = sorted({word for pc, length in code.items() for word in range(pc, pc + length)})
    return struct.pack(f"<{len(covered)}H", *(words[w] for w in covered))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--byte-order", choices=("le", "be"), default="le",
                        help="byte order of the 16-bit words in the files (default le)")
    parser.add_argument("out_dir")
    parser.add_argument("roms", nargs="+")
    args = parser.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    little_endian = args.byte_order == "le"
    for path in args.roms:
        with open(path, "rb") as f:
            data = f.read()
        count = len(data) // 2
        words = struct.unpack(("<" if little_endian else ">") + f"{count}H", data[:2 * count])
        code, kept, dropped = trace(words)
        sample = traced_bytes(words, code)
        name = os.path.basename(path)[:16]
        with open(os.path.join(args.out_dir, name + ".bin"), "wb") as f:
            f.write(sample)
        print(name, args.byte_order, kept, dropped, len(sample) // 2, sep="\t")


if __name__ == "__main__":
    main()
