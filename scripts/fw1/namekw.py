#!/usr/bin/env python3
"""Compare zrax ISA with ISA keywords that appear in the original file name."""
import csv, re, collections
rows = list(csv.DictReader(open("all.tsv"), delimiter="\t"))
# keyword regex -> set of acceptable zrax isa ids
KW = [
    (r"(?<![a-z0-9])(pic16|pic12|pic10|pic18)", {"pic"}),
    (r"pic24|pic33|dspic", {"pic"}),
    (r"r32c", {"r32c"}), (r"m16c", {"m16c"}), (r"(?<![a-z])m32c", {"m32c", "r32c"}),
    (r"st20", {"st20"}), (r"st7(?![0-9])", {"st7"}), (r"stm8", {"stm8"}),
    (r"oakdsp|oak_dsp", {"oak_dsp"}), (r"ez80", {"z80"}), (r"(?<![a-z0-9])z80", {"z80"}),
    (r"(?<![a-z0-9])z8(?![0-9])|ez8", {"z8"}), (r"z8000|z8k", {"z8000"}),
    (r"tms320c3|c3x", {"ti_c3x"}), (r"c54x|c5400", {"ti_c5400"}), (r"c55x|c5500", {"ti_c5500"}),
    (r"c28x|c2000", {"ti_c28x"}), (r"c6x|c66x|c64x|c674", {"ti_c6000"}),
    (r"f2mc", {"f2mc16"}), (r"6816|hc16", {"hc16"}), (r"cr16|compactrisc", {"cr16"}),
    (r"6502|65c02", {"mcs6502"}), (r"65816|65c816", {"w65c816", "mcs6502"}),
    (r"6809", {"m6809"}), (r"6800(?![0-9])|6801|6803", {"m6800"}), (r"68hc11|hc11", {"m68hc11", "m6800"}),
    (r"68hc08|hc08|hcs08", {"hc08"}), (r"hc12|hcs12|s12x", {"hc12"}),
    (r"68k|68000|68020|68030|68040|coldfire", {"m68k"}),
    (r"8051|80c51|8052|c8051", {"i8051"}), (r"8096|80c196|mcs96", {"mcs96"}),
    (r"(?<![a-z0-9])8086|80186|80286", {"x86"}),
    (r"avr(?![a-z])|atmega|attiny", {"avr"}), (r"msp430", {"msp430"}),
    (r"h8300|h8s|h8/", {"h8300", "h8s"}), (r"sh2|sh-2|sh4|sh-4|superh|sh7", {"sh", "sh4"}),
    (r"v850|rh850", {"v850", "rh850"}), (r"rl78", {"rl78"}), (r"(?<![a-z])rx6|rx(?=_)", {"rx"}),
    (r"tricore|tc17|tc27|tc29|tc39", {"tricore"}), (r"c166|c167|xc16|st10", {"c166"}),
    (r"riscv|risc-v|rv32|rv64", {"risc_v32", "risc_v64"}), (r"xtensa|esp32|esp8266", {"xtensa", "risc_v32"}),
    (r"nds32|andes", {"nds32"}), (r"hexagon|qdsp6", {"hexagon"}), (r"mips", {"mips", "mips64"}),
    (r"ppc|powerpc|mpc5", {"ppc", "ppc64", "ppc_vle"}), (r"sparc", {"sparc", "sparc64"}),
    (r"aarch64|arm64", {"a_arch64"}), (r"(?<![a-z])cortex|nrf5|stm32", {"arm"}),
    (r"blackfin|bfin", {"blackfin"}), (r"sharc|adsp-21", {"sharc", "adsp21xx"}),
    (r"mn10200|mn102", {"mn10200"}), (r"mn10300|am33", {"mn10300"}), (r"tlcs", {"tlcs900", "tlcs90"}),
    (r"lanai|myri", {"lanai"}), (r"alpha", {"alpha"}), (r"pdp11|pdp-11", {"pdp11"}),
    (r"s390", {"s390", "s390x"}), (r"ia64|itanium", {"ia64"}), (r"loongarch|loong", {"loong_arch64", "loong_arch32"}),
    (r"microblaze", {"micro_blaze"}), (r"nios", {"nios2"}), (r"(?<![a-z])arc(?![a-z])", {"arc_compact", "arc_compact2", "arc"}),
    (r"csky|c-sky|ck8", {"csky"}), (r"m32r", {"m32r"}), (r"fr30|fr80|fr81", {"fr30"}),
    (r"dsp56|56300|56k", {"dsp56k"}), (r"spc700", {"spc700"}), (r"gameboy|lr35902", {"lr35902", "z80"}),
]
c = collections.Counter()
for r in rows:
    n = r["name"].lower()
    for pat, ok in KW:
        if re.search(pat, n):
            good = r["isa"] in ok
            c[(pat, good)] += 1
            if not good:
                print(f"MISMATCH kw={pat!r:28} zrax={r['isa']:12} conf={r['conf'][:4]} fmt={r['format']:10} {r['name'][:70]}")
            break
print()
for (p, g), n in sorted(c.items()):
    print(p, g, n)
