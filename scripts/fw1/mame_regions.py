#!/usr/bin/env python3
"""Index MAME's ROM definitions by SHA-1: which memory region each ROM fills.

MAME drivers (`src/mame/**/*.cpp`) declare every ROM of a set inside
`ROM_START(set) ... ROM_END`, grouped by `ROM_REGION*(size, "tag", flags)`;
each `ROM_LOAD*("name", offset, size, CRC(...) SHA1(...))` line carries the
dump's SHA-1 (`ROMX_LOAD*` for the alternatives of a `ROM_SYSTEM_BIOS`). The region tag says what the bytes are for: a CPU's program
(`maincpu`, `audiocpu`, `mcu`, ...), graphics (`gfx1`, `sprites`, `tiles`,
...), or sound samples (`samples`, `oki`, `ymsnd`, `qsound`, ...).

Output (TSV, one row per ROM_LOAD with a SHA-1):
    sha1, kind, region tag, set, ROM name, load macro, driver path

`kind` is `code` for CPU program regions, `graphics` or `sound` for data
regions, and `other` for tags this script does not classify (`user1`,
`maincpu:key`, `mainbios`, ...), which carry no label.

Drivers also declare ROMs inside multi-line `#define` macros that a
`ROM_START` block uses, as `NEOGEO_BIOS` (snk/neogeo.cpp) and
`NEO_BIOS_AUDIO_64K(name, hash)` (with the game's ROM as arguments). Macros
defined in the driver and in the local headers it includes (`#include
"neogeo.h"`) are expanded where a ROM block uses them, parameters
substituted, nested uses included (at most MAX_MACRO_DEPTH levels). Macros
from other headers, and uses that span lines, are not expanded.

Usage:
    mame_regions.py MAME_SRC OUT.tsv      (MAME_SRC: the `src/mame` directory)
"""
import argparse
import os
import re

ROM_START = re.compile(r"^\s*ROM_START\s*\(\s*(\w+)\s*\)")
ROM_END = re.compile(r"^\s*ROM_END\b")
ROM_REGION = re.compile(r'^\s*ROM_REGION\w*\s*\(\s*[^,]+,\s*"([^"]+)"')
# Drivers define BIOS variants of the macros with the BIOS index first, as
# `ROM_LOAD16_WORD_SWAP_BIOS(9, "vs-bios.rom", ...)` (snk/neogeo.cpp).
ROM_LOAD = re.compile(r'^\s*(ROMX?_LOAD\w*)\s*\(\s*(?:\d+\s*,\s*)?"([^"]+)".*?SHA1\(\s*([0-9a-fA-F]{40})\s*\)')
DEFINE = re.compile(r"^\s*#\s*define\s+(\w+)(?:\(([^)]*)\))?(.*)$")
INCLUDE = re.compile(r'^\s*#\s*include\s+"([^"]+)"')
# The macro a line starts with, and what follows it.
MACRO_USE = re.compile(r"^\s*(\w+)\s*(.*)$")
# A string literal or an identifier, for parameter substitution.
TOKEN = re.compile(r'"[^"]*"|\b\w+\b')
MAX_MACRO_DEPTH = 8
MAX_INCLUDE_DEPTH = 4

# Region tags (last `:` component) by what MAME loads into them. Program
# regions belong to a CPU device of the same tag; the CPU type is in the
# machine configuration and is not resolved here.
CODE_TAG = re.compile(r"^(maincpu|subcpu|sub\d?|audiocpu|soundcpu|mcu|slave|master|iocpu|.*cpu\d*)$")
GRAPHICS_TAG = re.compile(
    r"^(gfx\d*|sprites?\d*|tiles?\d*|chars?\d*|fixed|fix|bg\d*|fg\d*|text|obj\d*|scroll\d*|road\d*|"
    r"zoom\d*|layer\d*|bitmap|tilemap\d*|\w*tiles\d*|k0\d+\w*|k05\d+\w*|gfxdata|textures?|polygons?|pixels?|"
    r"c\d+spr|reelgfx)$"
)
SOUND_TAG = re.compile(
    r"^(samples|pcm\d*|adpcm\w*|oki\d*|ymsnd\w*|ymz\w*|qsound|upd\d*|rf5c\d*\w*|segapcm|ics\d*\w*|msm\d*|"
    r"voice\d*|c140|c352|es5506\w*|x1snd|nile|k054539\w*|k007232\w*|ymf\w*|sound\d*|dac\d*|okim\d*|vlm|"
    r"swp\d+)$"
)


def kind_of(tag):
    tag = tag.split(":")[-1].lower()
    if CODE_TAG.match(tag):
        return "code"
    if GRAPHICS_TAG.match(tag):
        return "graphics"
    if SOUND_TAG.match(tag):
        return "sound"
    return "other"


def read_lines(path):
    with open(path, encoding="latin-1") as f:
        return f.read().splitlines()


def definitions(lines):
    """name -> (parameter names, body lines) of every `#define` in `lines`;
    a body line keeps its text without the continuation backslash."""
    macros = {}
    i = 0
    while i < len(lines):
        match = DEFINE.match(lines[i])
        i += 1
        if not match:
            continue
        name, parameters, rest = match.groups()
        body = [rest]
        while body[-1].rstrip().endswith("\\") and i < len(lines):
            body[-1] = body[-1].rstrip()[:-1]
            body.append(lines[i])
            i += 1
        names = [p.strip() for p in parameters.split(",")] if parameters else []
        macros[name] = (names, body)
    return macros


def driver_macros(path, mame_src, depth=0):
    """Macros of a driver or header and of the local headers it includes."""
    lines = read_lines(path)
    macros = {}
    if depth < MAX_INCLUDE_DEPTH:
        for line in lines:
            match = INCLUDE.match(line)
            if not match:
                continue
            for base in (os.path.dirname(path), mame_src):
                header = os.path.join(base, match.group(1))
                if os.path.isfile(header):
                    macros.update(driver_macros(header, mame_src, depth + 1))
                    break
    macros.update(definitions(lines))
    return macros


def call_arguments(text):
    """Arguments of a macro call whose text starts at `(`, split at top-level
    commas; None if the parentheses do not close on this line."""
    if not text.startswith("("):
        return None
    arguments, current, depth, quoted = [], [], 0, False
    for char in text:
        if char == '"':
            quoted = not quoted
        elif not quoted and char == "(":
            depth += 1
            if depth == 1:
                continue
        elif not quoted and char == ")":
            depth -= 1
            if depth == 0:
                arguments.append("".join(current).strip())
                return arguments
        elif not quoted and char == "," and depth == 1:
            arguments.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    return None


def substitute(line, values):
    """`line` with each parameter identifier outside string literals replaced."""
    return TOKEN.sub(lambda m: values.get(m.group(0), m.group(0)), line)


def expand(line, macros, depth=0):
    """The lines `line` stands for: the line itself, or a macro's body,
    expanded with its arguments. A load or region statement stays as
    written, even through a driver's own macro of that name
    (`ROM_LOAD_VROM`, sega/model3.cpp): its name gives the ROM layout."""
    match = MACRO_USE.match(line)
    is_statement = ROM_LOAD.match(line) or ROM_REGION.match(line)
    if not match or match.group(1) not in macros or is_statement or depth >= MAX_MACRO_DEPTH:
        yield line
        return
    names, body = macros[match.group(1)]
    values = {}
    if names:
        arguments = call_arguments(match.group(2))
        if arguments is None or len(arguments) != len(names):
            yield line
            return
        values = dict(zip(names, arguments))
    for body_line in body:
        yield from expand(substitute(body_line, values), macros, depth + 1)


def rom_loads(path, mame_src):
    """(sha1, kind, tag, set, rom name, macro) of every ROM_LOAD in one driver."""
    current_set = None
    tag = None
    macros = driver_macros(path, mame_src)
    for source_line in read_lines(path):
        lines = expand(source_line, macros) if current_set is not None else (source_line,)
        for line in lines:
            match = ROM_START.match(line)
            if match:
                current_set, tag = match.group(1), None
                continue
            if ROM_END.match(line):
                current_set, tag = None, None
                continue
            if current_set is None:
                continue
            match = ROM_REGION.match(line)
            if match:
                tag = match.group(1)
                continue
            match = ROM_LOAD.match(line)
            if match and tag is not None:
                macro, name, sha1 = match.groups()
                yield sha1.lower(), kind_of(tag), tag, current_set, name, macro


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mame_src", help="MAME src/mame directory")
    parser.add_argument("out", help="output TSV")
    args = parser.parse_args()
    rows = 0
    with open(args.out, "w") as out:
        for dirpath, _, files in os.walk(args.mame_src):
            for name in sorted(files):
                if not name.endswith(".cpp"):
                    continue
                path = os.path.join(dirpath, name)
                relative = os.path.relpath(path, args.mame_src)
                for sha1, kind, tag, rom_set, rom, macro in rom_loads(path, args.mame_src):
                    out.write("\t".join((sha1, kind, tag, rom_set, rom, macro, relative)) + "\n")
                    rows += 1
    print(rows)


if __name__ == "__main__":
    main()
