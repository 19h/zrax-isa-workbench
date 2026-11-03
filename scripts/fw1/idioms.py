#!/usr/bin/env python3
"""Count per-MiB occurrences of TriCore and ARCompact return/nop idioms in files.

TriCore: RET16 = 00 90 (16-bit, halfword-aligned), CALL32 opcode 0x6D low byte.
ARCompact: j_s [blink] = 0x7EE0 (LE bytes e0 7e), nop_s = 0x78E0 (e0 78).
Usage: idioms.py LABEL FILE...
"""
import sys
label = sys.argv[1]
for p in sys.argv[2:]:
    d = open(p, "rb").read()
    mib = max(len(d) / 2**20, 1 / 16)
    def cnt(pat):
        n = i = 0
        while True:
            i = d.find(pat, i)
            if i < 0: return n
            if i % 2 == 0: n += 1
            i += 1
    print(f"{label:10} ret16={cnt(bytes([0x00,0x90]))/mib:8.0f} arc_j_s_blink={cnt(bytes([0xe0,0x7e]))/mib:8.0f} arc_nop_s={cnt(bytes([0xe0,0x78]))/mib:8.0f} size={len(d)}")
