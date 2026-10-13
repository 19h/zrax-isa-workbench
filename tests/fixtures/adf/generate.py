#!/usr/bin/env python3
"""Build the Amiga disk image fixtures with amitools' file system code.

Writes gzip-compressed images into the output directory:

- ``ofs.adf.gz``: DD floppy, ``DOS\\0`` (OFS), no boot code;
- ``ffs.adf.gz``: DD floppy, ``DOS\\1`` (FFS), with boot code;
- ``dircache.adf.gz``: DD floppy, ``DOS\\5`` (FFS, international mode,
  directory cache);
- ``longnames.adf.gz``: DD floppy, ``DOS\\7`` (FFS, long file names);
- ``hd.adf.gz``: HD floppy, ``DOS\\3`` (FFS, international mode);
- ``rdb.hdf.gz``: a 1 MiB hard disk image with a Rigid Disk Block, an FFS
  partition ``DH0``, an OFS partition ``DH1`` and a file system header
  whose load segments hold a Hunk executable.

Every file is synthetic (see README.md). Timestamps are fixed at
2001-09-09 01:46:40 UTC, so the images are reproducible byte for byte.

Usage: python3 -I generate.py <amitools source directory> <output directory>

The amitools source directory is a checkout of
https://github.com/cnvogelg/amitools at commit
3b57f2052ee76c28bbc5e4256227f62dca7b1c9f (only ``amitools/fs`` and
``amitools/util`` are imported).
"""

import argparse
import gzip
import os
import struct
import sys
import time

# 2001-09-09 01:46:40 UTC: every timestamp amitools writes.
FIXED_TIME = 1_000_000_000

HUNK_HEADER = 0x3F3
HUNK_CODE = 0x3E9
HUNK_END = 0x3F2

# moveq #0,d0 (7000); rts (4E75)
RETURN_ZERO = 0x70004E75
# nop (4E71) twice
TWO_NOPS = 0x4E714E71
# nop (4E71); rts (4E75)
NOP_RETURN = 0x4E714E75

# The boot block code, entered at BB_ENTRY (offset 12) with SysBase in A6:
#   0x0C 43FA 0018  lea     dosname(pc),a1   ; 0x0E + 0x18 = 0x26
#   0x10 4EAE FFA0  jsr     -96(a6)          ; exec FindResident
#   0x14 4A80       tst.l   d0
#   0x16 670A       beq.s   fail             ; 0x18 + 0x0A = 0x22
#   0x18 2040       movea.l d0,a0            ; the dos.library resident tag
#   0x1A 2068 0016  movea.l 22(a0),a0        ; rt_Init, the completion function
#   0x1E 7000       moveq   #0,d0            ; boot succeeds
#   0x20 4E75       rts
#   0x22 70FF fail: moveq   #-1,d0           ; boot fails
#   0x24 4E75       rts
#   0x26 "dos.library", 0
BOOT_CODE = (
    bytes.fromhex("43fa0018 4eaeffa0 4a80 670a 2040 20680016 7000 4e75 70ff 4e75")
    + b"dos.library\0"
)


def hunk(code_longs):
    """A Hunk executable with one code hunk: HUNK_HEADER, no resident
    libraries, a table of one hunk (first 0, last 0, its size in longs),
    HUNK_CODE with the size and the code, HUNK_END."""
    words = [HUNK_HEADER, 0, 1, 0, 0, len(code_longs), HUNK_CODE, len(code_longs)]
    words += code_longs
    words.append(HUNK_END)
    return struct.pack(">%dI" % len(words), *words)


SMALL = hunk([RETURN_ZERO])
# 80 KiB of code: 161 FFS or 168 OFS data blocks, two extension blocks.
BIG = hunk([TWO_NOPS] * 20479 + [NOP_RETURN])
TEXT = b"zrax synthetic text file\n" * 30
LONG_NAME = "A file name that is longer than thirty characters"


def fix_time():
    """Make amitools stamp every block with FIXED_TIME."""
    os.environ["TZ"] = "UTC"
    time.tzset()
    real_localtime = time.localtime

    def localtime(secs=None):
        return real_localtime(FIXED_TIME if secs is None else secs)

    time.localtime = localtime


def write_gzip(path, data):
    """Write `data` gzip-compressed, with no file name and mtime 0."""
    with open(path, "wb") as out:
        out.write(gzip.compress(bytes(data), compresslevel=9, mtime=0))
    print(path, len(data))


def floppies(out, amitools):
    """The five floppy images."""
    ADFBlockDevice = amitools["ADFBlockDevice"]
    ADFSVolume = amitools["ADFSVolume"]
    FSString = amitools["FSString"]
    DosType = amitools["DosType"]
    images = [
        ("ofs.adf.gz", DosType.DOS0, False, None),
        ("ffs.adf.gz", DosType.DOS1, False, BOOT_CODE),
        ("dircache.adf.gz", DosType.DOS5, False, None),
        ("longnames.adf.gz", DosType.DOS7, False, None),
        ("hd.adf.gz", DosType.DOS3, True, None),
    ]
    for name, dos_type, hd, boot_code in images:
        blkdev = ADFBlockDevice(None, hd=hd)
        blkdev.create()
        volume = ADFSVolume(blkdev)
        volume.create(FSString("Zrax"), dos_type=dos_type, boot_code=boot_code)
        volume.create_dir(FSString("c"))
        volume.create_dir(FSString("c/deep"))
        volume.write_file(SMALL, FSString("hello"))
        volume.write_file(SMALL, FSString("c/run"))
        volume.write_file(BIG, FSString("c/deep/big"))
        volume.write_file(SMALL, FSString("café"))
        volume.write_file(TEXT, FSString("readme.txt"))
        # Three names with one hash ([FAQ] 4.2.1): a hash chain.
        for collision in ("file_1a", "file_24", "file_5u"):
            volume.write_file(SMALL, FSString(collision))
        if DosType.is_longname(dos_type):
            volume.write_file(SMALL, FSString(LONG_NAME))
        volume.close()
        write_gzip(os.path.join(out, name), blkdev.data)


def rigid_disk(out, amitools):
    """The Rigid Disk Block image: 32 cylinders of 2 heads and 32 sectors,
    cylinder 0 for the RDB, DH0 on cylinders 1-15, DH1 on 16-31."""
    RawBlockDevice = amitools["RawBlockDevice"]
    RDisk = amitools["RDisk"]
    DiskGeometry = amitools["DiskGeometry"]
    ADFSVolume = amitools["ADFSVolume"]
    FSString = amitools["FSString"]
    DosType = amitools["DosType"]
    path = os.path.join(out, "rdb.hdf")
    rawdev = RawBlockDevice(path)
    rawdev.create(32 * 2 * 32)
    rdisk = RDisk(rawdev)
    rdisk.create(DiskGeometry(32, 2, 32), disk_names=("ZRAX", "SYNTHETIC", "1.0"))
    partitions = [
        (FSString("DH0"), (1, 15), DosType.DOS3, 1),
        (FSString("DH1"), (16, 31), DosType.DOS0, 0),
    ]
    for drive, cylinders, dos_type, flags in partitions:
        rdisk.add_partition(drive, cylinders, dos_type=dos_type, flags=flags)
    # A stand-in for a file system handler: a Hunk executable.
    rdisk.add_filesystem(hunk([RETURN_ZERO] * 200), dos_type=DosType.DOS3, version=0x002D000D)
    trees = [
        ("Work", [("hello", SMALL), ("c/run", SMALL), ("readme.txt", TEXT)]),
        ("Data", [("tool", SMALL)]),
    ]
    for number, (volume_name, files) in enumerate(trees):
        partition = rdisk.get_partition(number)
        partdev = partition.create_blkdev()
        partdev.open()
        volume = ADFSVolume(partdev)
        dos_type = partition.part_blk.dos_env.dos_type
        volume.create(FSString(volume_name), dos_type=dos_type)
        for file_path, contents in files:
            if "/" in file_path:
                volume.create_dir(FSString(file_path.split("/")[0]))
            volume.write_file(contents, FSString(file_path))
        volume.close()
        partdev.close()
    rdisk.close()
    rawdev.close()
    with open(path, "rb") as image:
        data = image.read()
    os.remove(path)
    write_gzip(path + ".gz", data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("amitools", help="amitools source directory")
    parser.add_argument("out", help="output directory")
    args = parser.parse_args()
    fix_time()
    sys.path.insert(0, os.path.abspath(args.amitools))
    from amitools.fs.blkdev.ADFBlockDevice import ADFBlockDevice
    from amitools.fs.blkdev.RawBlockDevice import RawBlockDevice
    from amitools.fs.blkdev.DiskGeometry import DiskGeometry
    from amitools.fs.rdb.RDisk import RDisk
    from amitools.fs.ADFSVolume import ADFSVolume
    from amitools.fs.FSString import FSString
    import amitools.fs.DosType as DosType

    modules = {
        "ADFBlockDevice": ADFBlockDevice,
        "RawBlockDevice": RawBlockDevice,
        "DiskGeometry": DiskGeometry,
        "RDisk": RDisk,
        "ADFSVolume": ADFSVolume,
        "FSString": FSString,
        "DosType": DosType,
    }
    floppies(args.out, modules)
    rigid_disk(args.out, modules)


if __name__ == "__main__":
    main()
