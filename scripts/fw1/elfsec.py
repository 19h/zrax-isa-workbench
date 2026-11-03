#!/usr/bin/env python3
"""List ELF32/64 section headers (name, type, addr, offset, size) of one file."""
import struct, sys
d = open(sys.argv[1], "rb").read()
c64 = d[4] == 2; e = "<" if d[5] == 1 else ">"
if c64:
    shoff, = struct.unpack(e+"Q", d[0x28:0x30]); shentsize, shnum, shstrndx = struct.unpack(e+"HHH", d[0x3A:0x40])
else:
    shoff, = struct.unpack(e+"I", d[0x20:0x24]); shentsize, shnum, shstrndx = struct.unpack(e+"HHH", d[0x2E:0x34])
def sh(i):
    b = d[shoff+i*shentsize: shoff+(i+1)*shentsize]
    if c64: n,t,f,a,o,s = struct.unpack(e+"IIQQQQ", b[:40])
    else: n,t,f,a,o,s = struct.unpack(e+"IIIIII", b[:24])
    return n,t,f,a,o,s
strtab = sh(shstrndx)
for i in range(shnum):
    n,t,f,a,o,s = sh(i)
    nm = d[strtab[4]+n: d.index(b"\0", strtab[4]+n)].decode(errors="replace")
    print(f"{i:2} {nm:24} type={t:#x} flags={f:#x} addr={a:#x} off={o:#x} size={s:#x}")
