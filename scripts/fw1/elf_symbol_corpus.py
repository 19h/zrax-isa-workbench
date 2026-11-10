#!/usr/bin/env python3
"""Code samples of one large ELF image, cut from its function symbols.

A firmware image links code and read-only data into one executable section
(the MediaTek modem ELF's `ROM` is 32.6 MB of both), so taking the whole
section, as `build_corpus.py --elf` does, would teach a class the data as
well. This script takes only the bytes the symbol table names as functions
(`STT_FUNC` with a size, inside an `SHF_EXECINSTR` section), in address order.

One image is one program, so a split by file cannot hold anything out. The
functions are grouped into blocks of `--group-bytes` of address space and
every `--test-mod`th block is the test split: neighbouring functions, which
share a compilation unit, stay on one side.

Output layout: build_corpus.py's (OUT/samples/<class>/<id>.bin and
OUT/manifest.jsonl with id, class, group, source, size, split). The output
derives from the input firmware: keep OUT in a git-ignored directory.

Usage: python3 -I scripts/fw1/elf_symbol_corpus.py ELF OUT --class nanomips
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ELF_MAGIC = b"\x7fELF"
EI_CLASS = 4
EI_DATA = 5
ELFCLASS32 = 1
ELFDATA2LSB = 1
# Elf32_Ehdr: e_shoff at 32, then e_flags, e_ehsize, e_phentsize, e_phnum,
# e_shentsize, e_shnum, e_shstrndx.
E_SHOFF = 32
E_SHENTSIZE = 46
SHT_SYMTAB = 2
SHT_NOBITS = 8
SHF_EXECINSTR = 4
STT_FUNC = 2
SYMBOL_SIZE = 16
SAMPLE_BYTES = 64 * 1024
DEFAULT_GROUP_BYTES = 1024 * 1024
DEFAULT_TEST_MOD = 5


class Elf32:
    """Section headers and symbols of a 32-bit ELF."""

    def __init__(self, data):
        if data[:4] != ELF_MAGIC or data[EI_CLASS] != ELFCLASS32:
            raise SystemExit("not a 32-bit ELF")
        self.data = data
        self.order = "<" if data[EI_DATA] == ELFDATA2LSB else ">"
        shoff = struct.unpack_from(self.order + "I", data, E_SHOFF)[0]
        entry_size, count = struct.unpack_from(self.order + "HH", data, E_SHENTSIZE)
        # Elf32_Shdr: name, type, flags, addr, offset, size, link, info, ...
        self.sections = [
            struct.unpack_from(self.order + "10I", data, shoff + index * entry_size)
            for index in range(count)
        ]

    def executable_ranges(self):
        """(address, end, file offset) of each executable section with bytes."""
        return [
            (addr, addr + size, offset)
            for _, kind, flags, addr, offset, size, *_ in self.sections
            if flags & SHF_EXECINSTR and kind != SHT_NOBITS
        ]

    def function_symbols(self):
        """(address, size) of every sized function symbol."""
        symbols = []
        for _, kind, _, _, offset, size, *_ in self.sections:
            if kind != SHT_SYMTAB:
                continue
            for at in range(offset, offset + size, SYMBOL_SIZE):
                _, value, sym_size, info, _, _ = struct.unpack_from(
                    self.order + "IIIBBH", self.data, at
                )
                if info & 0xF == STT_FUNC and sym_size:
                    symbols.append((value, sym_size))
        return symbols


def file_range(address, size, ranges):
    """File offset of [address, address + size) if one section holds it all."""
    for start, end, offset in ranges:
        if start <= address and address + size <= end:
            return offset + address - start
    return None


def function_blocks(elf, group_bytes):
    """Function bytes per address block, each function once, in address order."""
    ranges = elf.executable_ranges()
    blocks = {}
    next_free = 0
    for address, size in sorted(set(elf.function_symbols())):
        # Aliases and overlapping symbols: take each address once.
        start = max(address, next_free)
        size -= start - address
        if size <= 0:
            continue
        offset = file_range(start, size, ranges)
        if offset is None:
            continue
        next_free = start + size
        blocks.setdefault(start // group_bytes, bytearray()).extend(
            elf.data[offset : offset + size]
        )
    return blocks


def write_samples(blocks, out, label, stem, test_mod):
    """Write the blocks as samples of at most SAMPLE_BYTES; return the rows."""
    directory = out / "samples" / label
    directory.mkdir(parents=True, exist_ok=True)
    rows = []
    for index, block in enumerate(blocks[key] for key in sorted(blocks)):
        split = "test" if index % test_mod == test_mod - 1 else "train"
        for at in range(0, len(block), SAMPLE_BYTES):
            sample = bytes(block[at : at + SAMPLE_BYTES])
            sample_id = hashlib.sha1(sample).hexdigest()[:16]
            (directory / f"{sample_id}.bin").write_bytes(sample)
            rows.append(
                {
                    "id": sample_id,
                    "class": label,
                    "group": f"elf-symbols:{stem}:{index}",
                    "source": "elf-symbols",
                    "size": len(sample),
                    "split": split,
                }
            )
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--class", dest="label", required=True)
    parser.add_argument("--group-bytes", type=int, default=DEFAULT_GROUP_BYTES)
    parser.add_argument("--test-mod", type=int, default=DEFAULT_TEST_MOD)
    args = parser.parse_args()
    elf = Elf32(args.elf.read_bytes())
    blocks = function_blocks(elf, args.group_bytes)
    rows = write_samples(blocks, args.out, args.label, args.elf.stem, args.test_mod)
    with open(args.out / "manifest.jsonl", "w") as manifest:
        manifest.writelines(json.dumps(row) + "\n" for row in rows)
    for split in ("train", "test"):
        picked = [row for row in rows if row["split"] == split]
        print(f"{split}: {len(picked)} samples, {sum(row['size'] for row in picked)} B")


main()
