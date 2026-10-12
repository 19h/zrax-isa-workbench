# Flash filesystem fixtures

Images for `tests/mtd.rs` and `web/tests/mtd.test.mjs`, written by the real
mtd-utils tools. `generate.sh` rebuilds them.

## Contents

Every image holds the same synthetic tree, built from two other committed
fixtures (no third-party code):

| Path | Contents |
| --- | --- |
| `/bin/tool.elf` | `compressed/payload.elf` (a 64-byte x86-64 ELF header and text) followed by `transforms/aarch64.text.bin` (unlinked `.text` of `transforms/sample.c`); 6640 B, two 4 KiB blocks |
| `/bin/tool-link.elf` | a hard link to `/bin/tool.elf` |
| `/lib/payload.elf` | `compressed/payload.elf` |
| `/boot/sparse.elf` | `payload.elf` at offset 0 and again at 12288, a hole between |
| `/etc/motd` | `zrax mtd fixture\n`, not a recognized format |
| `/var/empty` | an empty file |
| `/sbin` | a symlink to `bin` |

All timestamps are 2026-10-12 00:00:00 and every owner is root (`-U`).
The ELF headers name x86-64 although `tool.elf` carries AArch64 code; the
header is what the classifier must report.

The UBI image has three volumes (`ubinize.cfg`): `rootfs` (ID 0, dynamic,
640 KiB) holding the same tree as a Zstandard UBIFS image, `kernel` (ID 1,
static) holding `payload.elf` and six copies of `aarch64.text.bin`
(38560 B, three 15 KiB LEBs), and `data` (ID 2, dynamic, 64 KiB, empty).

## Generator and commands

Generated on 2026-10-12 with mtd-utils 2.2.1 (Alpine Linux 3.22 packages
`mtd-utils-jffs=2.2.1-r0` and `mtd-utils-ubi=2.2.1-r0`, image
`alpine:3.22` ID `sha256:b66e0ce64844f5c6435b0c4bfd965558199ab0f53270846861c979cb1ac29365`,
linux/amd64) in Docker 29.4.0 on macOS AArch64:

```sh
mkfs.jffs2 -l -U -e 64KiB -r root -o rootfs-le-zlib.jffs2
mkfs.jffs2 -l -U -e 64KiB -x zlib -r root -o rootfs-le-rtime.jffs2
mkfs.jffs2 -b -U -e 16KiB -X lzo -x zlib -x rtime -p -r root -o rootfs-be-lzo.jffs2
mkfs.ubifs -U -m 512 -e 15360 -c 64 -x lzo -r root -o rootfs-lzo.ubifs
mkfs.ubifs -U -m 512 -e 15360 -c 64 -x zstd -r root -o rootfs-zstd.ubifs
ubinize -o image.ubi -p 16KiB -m 512 -s 512 -Q 1515340872 ubinize.cfg
```

| File | Size (B) | SHA-256 | Layout |
| --- | --- | --- | --- |
| `rootfs-le-zlib.jffs2` | 5676 | `20f77b90175c822749c878b61b974bae13a3fe79893cb99b0fcbe4cea63facca` | little-endian JFFS2, zlib and stored nodes, 64 KiB erase blocks |
| `rootfs-le-rtime.jffs2` | 8644 | `91c8b12f578de9d754c6f3e22ff2d580ec8111633dc740592944f060183db7d4` | little-endian JFFS2, rtime and stored nodes |
| `rootfs-be-lzo.jffs2` | 16384 | `bdf7985ae2a3d4a73572d7f055d05bff45fcf654e5ebdbdad79d3242c80db27e` | big-endian JFFS2, LZO and stored nodes, padded to its 16 KiB erase block |
| `rootfs-lzo.ubifs` | 199680 | `a439987288028f359cb480fbace7b1be78e9547a22d1f5c7163924227fbb142c` | UBIFS format 4, 15 KiB LEBs, 512 B minimum I/O, LZO |
| `image.ubi` | 294912 | `19b8810c8078842453c908ad716149e436c4f12fa9b24139d6830d921cb1a0b4` | UBI, 18 PEBs of 16 KiB, VID headers at 0x200, data at 0x400, image sequence `0x5A524448` |

## Reproducibility

Regenerating on 2026-10-13 with `generate.sh <scratch-dir>` gave
byte-identical JFFS2 images. `mkfs.ubifs` writes a random UUID into the
superblock, so the UBIFS image and the UBI image differ in about 105 bytes
(the UUID and the CRCs over it) on every run; the committed hashes identify
the frozen artifacts the tests use.
