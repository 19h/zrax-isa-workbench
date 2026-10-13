# Partition table fixtures

Disk images made by macOS `hdiutil` for `tests/partitions.rs` and
`web/tests/partitions.test.mjs`. Each is a 1 MiB raw disk with one
partition table and one empty partition (no filesystem), stored
gzip-compressed because all but a few sectors are zero. `generate.sh`
rebuilds them. All other partition tables in the tests are built in the
test files from the UEFI 2.10 and Inside Macintosh layouts.

## Contents

| File | `hdiutil` layout | Table |
| --- | --- | --- |
| `hdiutil-apm.img.gz` | `SPUD` | Apple Partition Map: driver descriptor `ER` with 512 B blocks and 2048 blocks; entry 1 `Apple_partition_map` "Apple" (blocks 1-63), entry 2 `Apple_HFS` "disk image" (blocks 64-2047, status `0x40000033`); no drivers |
| `hdiutil-gpt.img.gz` | `GPTSPUD` | Protective MBR (type `0xEE`, start 1, size 2047); GPT revision 1.0 with 128 entries of 128 B at LBA 2, usable LBAs 34-2014, one Apple HFS/HFS+ entry "disk image" for LBAs 40-2007, backup array at LBA 2015 and backup header at LBA 2047 |
| `hdiutil-mbr.img.gz` | `MBRSPUD` | MBR with one inactive record, type `0xAF` (HFS), sectors 1-2047; bootstrap code area and disk signature all zeros |

Nothing in the images is third-party data: the partitions are empty, and
the only non-zero bytes are the tables `hdiutil` writes.

## Generator and commands

Generated on 2026-10-13 with `/usr/bin/hdiutil` and Apple gzip 487.40.2 on
macOS 27.2 (build 26B5101f), AArch64. From the repository root:

```sh
tests/fixtures/partitions/generate.sh
```

The script runs, for each layout,

```sh
hdiutil create -quiet -size 1m -layout <layout> -type UDIF -o <name>
gzip -9 -n -c <name>.dmg > hdiutil-<name>.img.gz
```

and prints the SHA-256 of the results. `-type UDIF` with no filesystem
writes a raw, uncompressed disk image (`.dmg` here is only the name).

`hdiutil` generates the GPT disk GUID and partition GUID at random, so the
GPT image, and the CRCs that cover those GUIDs, differ on every run. On
2026-10-13 the APM and MBR images reproduced byte for byte (same SHA-256 of
the uncompressed image); the GPT image did not.

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `hdiutil-apm.img.gz` | 1147 | `a97cb3ca7f70d20a81656f2dcc75d85a1714b352882a6a10025d53123da71eb7` |
| `hdiutil-gpt.img.gz` | 1339 | `3003dd584576ded9eed106ab267dbea66ee6a1bf1e646a44f0ddb2b681a0d22e` |
| `hdiutil-mbr.img.gz` | 1075 | `3661e24ad51e24ca8ec85b1e4802d62c32ae5f79baa29b3592646c0100ff0c64` |

Uncompressed, each image is 1048576 B:

| Image | SHA-256 |
| --- | --- |
| APM | `fac3fb63dc212827311f4f1e835c8b3f35ddb67bdc09985fdc204460aed1e5fc` |
| GPT | `87317b0b8f103476006d86bd709b0e712551365477879c3b14673d4802ead74e` |
| MBR | `79cd0c9bf4147a55ba116ed2f9a3077ae2f3854e4515132b73c32aa679ce7235` |
