#!/usr/bin/env python3
"""
Extract the instruction bytes of a raw firmware image using an IDA listing
(.lst) of it as the code map, so a dump can be used as ground truth without
its data tables, strings, vectors and erased flash.

IDA's reference logs (ida/tests/logs/<test>.lst) print every item as

    SEG:ADDR [SP] BYTES...   [label:] mnemonic operands

with the item's bytes (or 16/24/32-bit words, or octal words for PDP-11) in
the byte field and continuation lines for long items. Items whose mnemonic
is a data directive (db/dw/.byte/.word/dcb/...) are data; everything else is
an instruction. The word packing (byte order, phantom bytes) is not in the
listing, so it is found by matching the displayed words of a long code run
against the source image.

Filters: instructions repeated back to back (NOP/BRK sleds decoded from fill,
erased flash decoded as instructions) are dropped, and so are code runs of
fewer than MIN_RUN instructions (stray decodes inside data).

Usage:
    ida_listing_code.py LISTING SOURCE OUT.bin     (SOURCE: .bin, .hex, .s19, ...)
"""

import re
import sys

LINE = re.compile(r"^(.+?):([0-9A-F]{4,16}) (.*)$")
TOKEN = re.compile(r"^[0-9A-F]+$")
SP = re.compile(r"^(-[0-9A-F]{2}|[0-9A-F]{3})$")
DIRECTIVES = {
    "db", "dw", "dd", "dl", "dq", "dt", "ds", "dup", "byte", "word", "dword", "data", "equ", "align",
    ".byte", ".word", ".lword", ".long", ".short", ".half", ".quad", ".dword", ".float", ".double",
    ".data.b", ".data.w", ".data.l", ".array", ".ascii", ".asciz", ".string", ".space", ".align",
    "dcb", "dc", "dc.b", "dc.w", "dc.l", "fcb", "fdb", "fcc", "rmb", "und", ".bss", "org",
}
MIN_RUN = 8
MAX_REPEAT = 3

# Ways to lay a displayed token out in memory: name -> (token length, parse, bytes).
PACKINGS = {
    "bytes": (2, 16, lambda v: bytes([v])),
    "be16": (4, 16, lambda v: v.to_bytes(2, "big")),
    "le16": (4, 16, lambda v: v.to_bytes(2, "little")),
    "be24": (6, 16, lambda v: v.to_bytes(3, "big")),
    "le24": (6, 16, lambda v: v.to_bytes(3, "little")),
    "le24+0": (6, 16, lambda v: v.to_bytes(4, "little")),
    "0+be24": (6, 16, lambda v: v.to_bytes(4, "big")),
    "be32": (8, 16, lambda v: v.to_bytes(4, "big")),
    "le32": (8, 16, lambda v: v.to_bytes(4, "little")),
    "octal16": (6, 8, lambda v: v.to_bytes(2, "little")),
}


def load_source(path):
    """Raw bytes of the image. Intel HEX / S-records are decoded into their
    data bytes in file order: word-addressed targets (DSPs) count record
    addresses in words, so placing bytes by address would overlap records."""
    data = open(path, "rb").read()
    lines = [l.strip() for l in data.decode("latin1").splitlines() if l.strip()]
    if lines and all(l[:1] in (":", "S") for l in lines[:20]):
        out = bytearray()
        for l in lines:
            try:
                b = bytes.fromhex(l[1:] if l[0] == ":" else l[2:])
            except ValueError:
                continue
            if l[0] == ":":
                if len(b) > 4 and b[3] == 0:
                    out += b[4 : 4 + b[0]]
            elif l[1:2] in ("1", "2", "3"):
                out += b[1 + int(l[1]) + 1 : -1]
        return bytes(out)
    return data


def items(path):
    """(address, [tokens], text) per listing item, continuation lines merged."""
    out = []
    for raw in open(path, encoding="utf-8", errors="replace"):
        m = LINE.match(raw.rstrip("\n"))
        if not m:
            continue
        addr = int(m.group(2), 16)
        field, _, text = m.group(3).lstrip(" ").partition("  ")
        toks = field.split(" ")
        # Stack-pointer column: a 3-character token such as "000" or "-1C"
        # (bytes/words are 2/4/6/8 digits).
        if len(toks) > 1 and SP.match(toks[0]):
            toks = toks[1:]
        if not toks[0] or not all(TOKEN.match(t.rstrip("…")) for t in toks):
            continue
        truncated = toks[-1].endswith("…")
        toks = [t.rstrip("…") for t in toks]
        text = text.strip()
        if text.startswith(";"):
            text = ""
        if out and out[-1][0] == addr and not text:
            out[-1][1].extend(toks)  # continuation line
            continue
        if not text:
            continue
        out.append([addr, toks, text, truncated])
    return out


def mnemonic(text):
    t = text.split()
    if t and t[0].endswith(":") and len(t) > 1:
        t = t[1:]
    return t[0].lower() if t else ""


def code_runs(its):
    """Runs of consecutive instructions (a data item ends a run)."""
    runs, cur = [], []
    for addr, toks, text, truncated in its:
        if not truncated and mnemonic(text) not in DIRECTIVES:
            cur.append((addr, toks))
        elif cur:
            runs.append(cur)
            cur = []
    if cur:
        runs.append(cur)
    return runs


def pack(toks, packing):
    n, base, f = PACKINGS[packing]
    if any(len(t) != n for t in toks):
        return None
    try:
        return b"".join(f(int(t, base)) for t in toks)
    except (ValueError, OverflowError):
        return None


def find_packing(runs, source):
    longest = sorted(runs, key=len, reverse=True)[:5]
    for run in longest:
        probe = [t for _, toks in run[:12] for t in toks]
        for name in PACKINGS:
            b = pack(probe, name)
            if b and len(b) >= 8 and b in source:
                return name
    return None


def dedup(run):
    """Drop back-to-back repeats of the same instruction beyond MAX_REPEAT."""
    out, prev, count = [], None, 0
    for addr, toks in run:
        key = tuple(toks)
        count = count + 1 if key == prev else 1
        prev = key
        if count <= MAX_REPEAT:
            out.append((addr, toks))
    return out


def extract(listing, source_path):
    source = load_source(source_path)
    runs = code_runs(items(listing))
    packing = find_packing(runs, source)
    if packing is None:
        return None, "no packing of the listing's words matches the source"
    out = bytearray()
    kept = dropped = 0
    for run in runs:
        run = dedup(run)
        if len(run) < MIN_RUN:
            dropped += len(run)
            continue
        b = [pack(toks, packing) for _, toks in run]
        if any(x is None for x in b):
            dropped += len(run)
            continue
        out += b"".join(b)
        kept += len(run)
    return bytes(out), f"packing={packing} instructions kept={kept} dropped={dropped} source={len(source)}"


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    code, info = extract(sys.argv[1], sys.argv[2])
    if code is None:
        sys.exit(f"{sys.argv[1]}: {info}")
    with open(sys.argv[3], "wb") as f:
        f.write(code)
    print(f"{sys.argv[3]}: {len(code)} code bytes, {info}")


if __name__ == "__main__":
    main()
