#!/usr/bin/env python3
"""Find well-known magic numbers in raw-classified files (offset 0 and fixed offsets).

Run from the directory holding all.tsv.

Usage: magics.py FW1_DIR
"""
import argparse
import collections
import csv
import struct
import zlib

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("fw1_dir", help="directory of fw1 binaries named by SHA-256")
FW1_DIR = parser.parse_args().fw1_dir
rows = [r for r in csv.DictReader(open("all.tsv"), delimiter="\t") if r["format"] == "raw"]
AT0 = [
    (b"\x1f\x8b\x08", "gzip"), (b"\xfd7zXZ\x00", "xz"), (b"BZh", "bzip2"), (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\x04\x22\x4d\x18", "lz4"), (b"\x5d\x00\x00", "lzma?"), (b"hsqs", "squashfs"), (b"sqsh", "squashfs-be"),
    (b"070701", "cpio"), (b"UBI#", "ubi"), (b"\x85\x19", "jffs2-le"), (b"\x19\x85", "jffs2-be"),
    (b"\xd0\x0d\xfe\xed", "dtb"), (b"\x27\x05\x19\x56", "uimage"), (b"ANDROID!", "androidboot"),
    (b"PK\x03\x04", "zip"), (b"\x7fELF", "elf"), (b"MZ", "mz"), (b"\x55\xaa", "optionrom"),
    (b"dex\n", "dex"), (b"\x00asm", "wasm"), (b"\xca\xfe\xba\xbe", "java/fat"), (b"IMG4", "img4"),
    (b"MTK_BLOADER", "mtk"), (b"MMM\x01", "mtk-mmm"), (b"\x88\x16\x88\x58", "mtk-hdr"),
    (b"bplist00", "bplist"), (b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpeg"), (b"RIFF", "riff"), (b"OggS", "ogg"),
    (b"ID3", "mp3"), (b"fLaC", "flac"), (b"%PDF", "pdf"), (b"<?xml", "xml"), (b"{", "json?"), (b"#!", "script"),
    (b"\x30\x82", "der"), (b"-----BEGIN", "pem"), (b"LZIP", "lzip"), (b"\x89LZO", "lzo"), (b"\xfe\xed\xfe\xed", "dtb?"),
    (b"FWUP", "fwup"), (b"HDR0", "trx"), (b"\xd0\xcf\x11\xe0", "ole"), (b"7z\xbc\xaf", "7z"), (b"Rar!", "rar"),
    (b"\x1f\x9d", "compress"), (b"\x78\x9c", "zlib"), (b"\x78\xda", "zlib"), (b"\x78\x01", "zlib"), (b"\x78\x5e", "zlib"),
    (b"CHROMEOS", "chromeos"), (b"_FVH", "uefifv?"), (b"$IFD", "ifd?"), (b"\x5a\xa5\xf0\x0f", "intel-ifd"),
]
c = collections.Counter(); ex = collections.defaultdict(list)
for r in rows:
    with open(FW1_DIR + "/" + r["sha"], "rb") as f:
        d = f.read(0x200)
    tags = [t for m, t in AT0 if d.startswith(m)]
    if len(d) >= 0x3c and d[0x38:0x3c] == b"ARM\x64": tags.append("arm64-Image")
    if len(d) >= 0x28 and d[0x24:0x28] == b"\x18\x28\x6f\x01": tags.append("arm-zImage")
    if len(d) >= 0x10 and d[:4] == b"\x00\x00\x00\x00" and d[0x10:0x14] == b"\x5a\xa5\xf0\x0f": tags.append("intel-ifd")
    if any(t == "zlib" for t in tags):
        try:
            zlib.decompressobj().decompress(open(FW1_DIR + "/" + r["sha"], "rb").read(65536))
            tags = ["zlib(valid)"]
        except Exception:
            tags = [t for t in tags if t != "zlib"]
    for t in tags:
        c[t] += 1; ex[t].append((r["isa"], r["conf"][:4], r["name"][:40]))
for t, n in c.most_common():
    print(n, t, ex[t][:6])
