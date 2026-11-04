#!/usr/bin/env python3
"""The CPU MAME runs each fw1 program ROM on, and the zrax ISA it executes.

For every `code` or `mixed` row of mame_match.tsv, finds the device that the
ROM's driver (or a driver source it includes from its own directory, where
shared machine configurations live) creates with the region's tag, e.g.
`I8085A(config, m_subcpu, ...)` for region "subcpu", and maps the device type
to a zrax ISA id with CPU_ISA. Device types not in CPU_ISA, or a tag no
device claims, give an empty ISA: no label.

Output mame_cpus.tsv (no header), one row per program ROM:

    sha256, set, ROM name, region tag, device types (comma-separated), isa, layout

`isa` is empty unless every device type found maps to the same ISA. `layout`
says how much of the bus the dump holds: `whole`; `byte-lanes`, every other
byte of a wider bus (`ROM_LOAD16_BYTE`, `ROM_LOAD32_BYTE`, `ROM_SKIP`
without `ROM_GROUPWORD`), which holds no whole instruction of a CPU with
16-bit or wider instructions; or `word-lanes`, every other 16-bit word
(`ROM_LOAD32_WORD`, `ROM_GROUPWORD | ROM_SKIP`), whose words are whole
instruction words of a 68000 or another CPU with 16-bit instruction units.

Usage: mame_cpus.py MAME_SRC MAME_REGIONS.tsv MAME_MATCH.tsv OUT.tsv
       (MAME_SRC: the `src/mame` directory)
"""
import argparse
import os
import re

# MAME device type -> zrax JSON ISA id. Cores of SoC and custom devices are
# from their MAME device headers at the pinned commit (src/devices):
# TC0090LVC/TC0091LVC derive from z80_device (machine/tc009xlvc.h);
# TMPZ84C011/TMPZ84C015 from z80_device; ELAN_EP3A19A_SOC from m6502_device
# (machine/elan_ep3a19a_soc.h); IGS027A from arm7_cpu_device
# (mame/igs/igs027a.h); SPG24X, SPG28X and SPG2XX_128 from unsp_device
# (machine/spg2xx.h); the GPL162xx SoCs from unsp_20_device
# (machine/generalplus_gpl162xx_soc.h, generalplus_gpl162xx_b_soc.h);
# SH7032 from sh2_device; SCC68070 is a 68000 core.
CPU_ISA = {
    "Z80": "z80", "NSC800": "z80", "TMPZ84C011": "z80", "TMPZ84C015": "z80",
    "TC0090LVC": "z80", "TC0091LVC": "z80",
    "I8080": "i8085", "I8080A": "i8085", "I8085A": "i8085",
    "M68000": "m68k", "M68008": "m68k", "M68010": "m68k", "SCC68070": "m68k",
    "M68EC020": "m68k", "M68020": "m68k", "M68030": "m68k", "M68040": "m68k",
    "ARM7": "arm", "ARM9": "arm", "ARM710T": "arm", "IGS027A": "arm",
    "M6502": "mcs6502", "M6504": "mcs6502", "M6510": "mcs6502", "ELAN_EP3A19A_SOC": "mcs6502",
    "W65816": "w65816", "G65816": "w65816",
    "I8031": "i8051", "I8051": "i8051", "I8052": "i8051", "I80C31": "i8051", "I80C51": "i8051",
    # SH7750 (Aristocrat MK6) and SH7091 (NAOMI) are MAME's SH-4 device
    # types (devices/cpu/sh/sh4.h). The code model reports SH-4 only for code
    # with SH-4-only instructions and SuperH (`sh`) otherwise, so checks
    # accept `sh` for an `sh4` CPU (`verify_findings.isa_meets`), never `sh4`
    # for an SH-2.
    "SH7032": "sh", "SH7043A": "sh", "SH7604": "sh", "SH4": "sh4", "SH7750": "sh4", "SH7091": "sh4",
    "H83002": "h8300", "H83044": "h8300", "H8S2655": "h8300",
    "SPG24X": "unsp", "SPG28X": "unsp", "SPG2XX_128": "unsp",
    "GPL16218B": "unsp", "GPL16220A": "unsp", "GPL16230A": "unsp", "GPL16238B": "unsp",
    "GPL16250VA": "unsp", "GPL16258VB": "unsp",
    "I8086": "x86", "I8088": "x86", "I80186": "x86", "I80188": "x86", "I386": "x86", "I486": "x86",
}
# `TYPE(config, m_tag, ...)` or `TYPE(config, "tag", ...)`.
DEVICE = re.compile(r'\b([A-Z][A-Z0-9_]{1,30})\s*\(\s*config\s*,\s*(?:m_(\w+)|"(\w+)")')
LOCAL_INCLUDE = re.compile(r'^#include\s+"(\w+)\.h"', re.MULTILINE)
# Load macros that interleave a dump with others on a wider data bus.
BYTE_LANE_MACROS = {"ROM_LOAD16_BYTE", "ROM_LOAD32_BYTE", "ROM_LOAD64_BYTE"}
WORD_LANE_MACROS = {"ROM_LOAD32_WORD", "ROM_LOAD32_WORD_SWAP", "ROM_LOAD64_WORD", "ROM_LOAD64_WORD_SWAP"}


def read_text(path):
    with open(path, encoding="latin-1") as f:
        return f.read()


def driver_devices(mame_src, driver):
    """(device type, tag) of every device the driver and its local includes create."""
    path = os.path.join(mame_src, driver)
    text = read_text(path)
    sources = [text]
    for header in LOCAL_INCLUDE.findall(text):
        sibling = os.path.join(os.path.dirname(path), header + ".cpp")
        if os.path.isfile(sibling) and sibling != path:
            sources.append(read_text(sibling))
    devices = set()
    for source in sources:
        for device_type, member, quoted in DEVICE.findall(source):
            devices.add((device_type, member or quoted))
    return devices


def rom_layout(driver_text, sha1, macro):
    """`byte-lanes` or `word-lanes` for a dump interleaved on a wider bus, else `whole`.
    A driver's `<macro>_BIOS` variant loads like `<macro>`."""
    base = macro[:-len("_BIOS")] if macro.endswith("_BIOS") else macro
    if base in BYTE_LANE_MACROS:
        return "byte-lanes"
    if base in WORD_LANE_MACROS:
        return "word-lanes"
    for line in driver_text.splitlines():
        if sha1 in line.lower() and "ROM_SKIP(" in line:
            return "word-lanes" if "ROM_GROUPWORD" in line else "byte-lanes"
    return "whole"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mame_src", help="MAME src/mame directory")
    parser.add_argument("regions", help="mame_regions.py output")
    parser.add_argument("match", help="mame_match.py output")
    parser.add_argument("out", help="output TSV")
    args = parser.parse_args()
    code_regions = {}
    with open(args.regions) as f:
        for line in f:
            sha1, kind, tag, _rom_set, _rom, _macro, driver = line.rstrip("\n").split("\t")
            if kind == "code":
                code_regions.setdefault(sha1, []).append((tag.split(":")[-1], driver))
    cache = {}
    texts = {}
    rows = 0
    with open(args.match) as f, open(args.out, "w") as out:
        for line in f:
            fields = line.rstrip("\n").split("\t")
            sha256, sha1, kind, tag, rom_set, rom, macro = fields[:7]
            if kind not in ("code", "mixed"):
                continue
            types = set()
            layout = "whole"
            for region_tag, driver in code_regions.get(sha1, []):
                if driver not in cache:
                    cache[driver] = driver_devices(args.mame_src, driver)
                    texts[driver] = read_text(os.path.join(args.mame_src, driver))
                types |= {t for t, device_tag in cache[driver] if device_tag == region_tag}
                if layout == "whole":
                    layout = rom_layout(texts[driver], sha1, macro)
            isas = {CPU_ISA.get(t) for t in types}
            isa = isas.pop() if len(isas) == 1 else None
            row = (sha256, rom_set, rom, tag, ",".join(sorted(types)), isa or "", layout)
            out.write("\t".join(row) + "\n")
            rows += 1
    print(rows)


if __name__ == "__main__":
    main()
