# Amiga disk image fixtures

Five ADF floppy images and one Rigid Disk Block hard disk image for
`tests/adf.rs` and `web/tests/adf.test.mjs`, written by amitools' file
system code from a synthetic tree. `generate.py` rebuilds all six. They are
stored gzip-compressed; each is mostly zero blocks.

## Contents

Every file is synthetic:

| Path | Contents |
| --- | --- |
| `/hello`, `/c/run`, `/café`, `/file_1a`, `/file_24`, `/file_5u` | a 40 B Hunk executable: `HUNK_HEADER` (0x3F3), no resident libraries, a table of one hunk of one long, `HUNK_CODE` (0x3E9) holding `moveq #0,d0; rts` (`70004E75`), `HUNK_END` (0x3F2) |
| `/c/deep/big` | an 81,956 B Hunk executable: one code hunk of 20,480 longs, 20,479 × `nop; nop` (`4E714E71`) and `nop; rts` (`4E714E75`) |
| `/readme.txt` | 750 B of ASCII text (`zrax synthetic text file` and a line feed, 30 times), not a recognized format |
| `/A file name that is longer than thirty characters` | `longnames.adf.gz` only: the 40 B executable |

`file_1a`, `file_24` and `file_5u` share one hash value ([FAQ] 4.2.1), so
they form a hash chain in the root block's table. `/café` is stored in ISO
8859-1 and hashes differently with and without the international mode. The
volume name is `Zrax`.

| Image | Layout | Size | Boot code |
| --- | --- | --- | --- |
| `ofs.adf.gz` | DD floppy, `DOS\0` (OFS) | 901,120 B | none |
| `ffs.adf.gz` | DD floppy, `DOS\1` (FFS) | 901,120 B | 38 B at offset 12, below |
| `dircache.adf.gz` | DD floppy, `DOS\5` (FFS, international mode, directory cache) | 901,120 B | none |
| `longnames.adf.gz` | DD floppy, `DOS\7` (FFS, international mode, long file names) | 901,120 B | none |
| `hd.adf.gz` | HD floppy, `DOS\3` (FFS, international mode) | 1,802,240 B | none |
| `rdb.hdf.gz` | hard disk with a Rigid Disk Block, below | 1,048,576 B | none |

`/c/deep/big` needs 161 FFS or 168 OFS data blocks: 72 pointers in its
file header and two extension blocks.

The boot code of `ffs.adf.gz`, written for these fixtures (offsets in the
boot block):

```text
0x0C  43FA 0018  lea     dosname(pc),a1   ; 0x0E + 0x18 = 0x26
0x10  4EAE FFA0  jsr     -96(a6)          ; exec FindResident
0x14  4A80       tst.l   d0
0x16  670A       beq.s   fail             ; 0x18 + 0x0A = 0x22
0x18  2040       movea.l d0,a0            ; the dos.library resident tag
0x1A  2068 0016  movea.l 22(a0),a0        ; rt_Init, the completion function
0x1E  7000       moveq   #0,d0            ; boot succeeds
0x20  4E75       rts
0x22  70FF       moveq   #-1,d0           ; fail: boot fails
0x24  4E75       rts
0x26  "dos.library", 0
```

`rdb.hdf.gz` has 32 cylinders of 2 heads and 32 sectors (2048 blocks).
Cylinder 0 holds the Rigid Disk Block structures as amitools allocates them:
`RDSK` in block 0 (drive identification `ZRAX` / `SYNTHETIC` / `1.0`, flags
0x17), `PART` blocks 1 (`DH0`) and 2 (`DH1`), `FSHD` block 3 and `LSEG`
blocks 4 and 5. `DH0` covers cylinders 1-15 (960 blocks), is `DOS\3`, marked
bootable, and holds the volume `Work` with `/hello`, `/c/run` and
`/readme.txt`. `DH1` covers cylinders 16-31 (1024 blocks), is `DOS\0` and
holds the volume `Data` with `/tool`, the 40 B executable. The file system
header names `DOS\3`, version 45.13, and its load segments hold an 836 B
Hunk executable whose one code hunk is 200 × `moveq #0,d0; rts`, a stand-in
for a file system handler.

All timestamps are 2001-09-09 01:46:40 UTC (`generate.py` fixes the clock),
so the images are reproducible byte for byte.

## Generator and commands

Generated on 2026-10-13 on macOS AArch64 with Python 3.14.7 (Homebrew) and
amitools at commit `3b57f2052ee76c28bbc5e4256227f62dca7b1c9f`
(<https://github.com/cnvogelg/amitools>), run from source: `generate.py`
imports only `amitools/fs` and `amitools/util`, which are pure Python. The
amitools files were fetched from `raw.githubusercontent.com` at that commit
(`amitools/__init__.py`, every `.py` file under `amitools/fs`, and
`amitools/util/{__init__,slotarray,KeyValue,BlkDevTools,ByteSize,HexDump,Math}.py`);
a checkout of the commit works the same. From the repository root:

```sh
git clone https://github.com/cnvogelg/amitools /tmp/amitools
git -C /tmp/amitools checkout 3b57f2052ee76c28bbc5e4256227f62dca7b1c9f
python3 -I tests/fixtures/adf/generate.py /tmp/amitools tests/fixtures/adf
```

The script, for each floppy: creates the image with `ADFBlockDevice`,
formats it with `ADFSVolume.create` (DOS type, volume name, boot code),
creates `/c` and `/c/deep`, writes the files, and stores the image with
`gzip.compress(…, compresslevel=9, mtime=0)`. For the hard disk it creates a
raw image, `RDisk.create` with the geometry and drive names,
`add_partition` twice, `add_filesystem` once, then formats each partition
through `create_blkdev` and writes its files.

Two runs of the script produced identical files. The compressed bytes
depend on the zlib that Python uses; the decompressed images do not.

## Files

| File | Size | SHA-256 |
| --- | --- | --- |
| `ofs.adf.gz` | 3,813 B | `94d748fe3c23e534b5dd7440aeed909a522713b7199c3da9c2ff83f7fad9c93b` |
| `ffs.adf.gz` | 2,008 B | `fd8c0c6da7658c2041038bf1ea4d7909af6cb438121a42dd064d13ddb58f81bd` |
| `dircache.adf.gz` | 2,148 B | `08efe1763ee56cfc2c19841b29d50435db754341a9b89f9f8a4938dd72232344` |
| `longnames.adf.gz` | 2,065 B | `11d51830897258280056fc8a7d0c0b437aa53b856d4127fc8d0b148188e8bb9c` |
| `hd.adf.gz` | 2,824 B | `dcde98301799cc9de98c37db6eed38bb61cfb98719db2c87e01bd05345bf396d` |
| `rdb.hdf.gz` | 1,786 B | `6f28dc04593e49bde7b4b3a165301f2bbf9c89318974a8739e95a288e31d98d7` |

Decompressed:

| Image | Size | SHA-256 |
| --- | --- | --- |
| `ofs.adf` | 901,120 B | `ad96b4f3325181990fa68a9be366e3974baee07921e388c69b6c785c7c70aec0` |
| `ffs.adf` | 901,120 B | `0977a78a6b2fa75872c5d1b32c3fa60b29fb9e2480e135ff89bc57ff10832973` |
| `dircache.adf` | 901,120 B | `88b76e21177897b0aea177ca493c1cb8af795a5210e5d2b727017c3e34e71a34` |
| `longnames.adf` | 901,120 B | `cbef5ae13fa4cc4db77befda380c497356f98528557da643dbc010155e769b8e` |
| `hd.adf` | 1,802,240 B | `73385792cd52288c6c1aec2138be6c1625c20de5466112f4ad19f3ae484eb850` |
| `rdb.hdf` | 1,048,576 B | `be80d8a53f22ae60a0ddccc87832adf6eeddb1fcc8f8550e20b335bb4bc17350` |

[FAQ] is Laurent Clévy, "The .ADF (Amiga Disk File) format FAQ", v1.14; the
sources are listed in `docs/adf.md`.
