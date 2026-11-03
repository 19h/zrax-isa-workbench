#!/usr/bin/env python3
"""Per-MiB density of SuperH idioms at halfword alignment: rts (000B), nop (0009), sts.l pr,@-r15 (4F22).

Prints little-endian and big-endian counts. Usage: shidiom.py LABEL FILE...
"""
import sys
for p in sys.argv[2:]:
    d = open(p, "rb").read(); mib = len(d) / 2**20
    def cnt(pat):
        n = i = 0
        while (i := d.find(pat, i)) >= 0:
            n += i % 2 == 0; i += 1
        return n / mib
    le = (cnt(b"\x0b\x00"), cnt(b"\x09\x00"), cnt(b"\x22\x4f"))
    be = (cnt(b"\x00\x0b"), cnt(b"\x00\x09"), cnt(b"\x4f\x22"))
    print(f"{sys.argv[1]:9} LE rts/nop/stspr={le[0]:6.0f}/{le[1]:6.0f}/{le[2]:6.0f}  BE={be[0]:6.0f}/{be[1]:6.0f}/{be[2]:6.0f}")
