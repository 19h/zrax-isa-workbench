# FAT and exFAT fixtures

Small FAT12, FAT16, FAT32 and exFAT volumes for `tests/fat.rs` and
`web/tests/fat.test.mjs`, built with dosfstools, mtools and exfatprogs
from a synthetic tree. `generate.sh` rebuilds the FAT images and
`generate-exfat.sh` the exFAT image. The FAT16, FAT32 and exFAT images are
committed gzip-compressed (`gzip -9 -n`): they are mostly free clusters,
and FAT16 and FAT32 need at least 4,085 and 65,525 clusters.

## Contents

Every file is synthetic:

| Path | Contents |
| --- | --- |
| `/payload.elf` | `tests/fixtures/compressed/payload.elf`: a 256 B ELF64 header for x86-64 with no code |
| `/notes.txt` | ASCII text, not a recognized format |
| `/Long File Name Payload.elf` | `payload.elf` again, under a name that needs long-name entries |
| `/boot/payload.elf.gz` | `tests/fixtures/compressed/payload.elf.gz` |
| `/boot/deleted.elf` | `payload.elf`, deleted again; its entry remains as a deleted entry |
| `/frag/split.elf` | `payload.elf`, then lines `zrax split line NN` (FAT: 60 lines, 1396 B; exFAT: 300 lines cut to 6000 B) |
| `/frag/keep.txt` | ASCII text stored between the clusters of `split.elf` |

The recognized members, in walk order, are `/payload.elf`,
`/Long File Name Payload.elf`, `/boot/payload.elf.gz` and
`/frag/split.elf`. On the FAT images mtools stores the 8.3-compatible
names `payload.elf`, `boot`, `frag`, `split.elf` and `notes.txt` as
upper-case short names with the Windows NT lower-case flags in
`DIR_NTRes`, which the reader does not use (Microsoft's FAT specification
1.03, "FAT Directory Structure", says never to look at the byte), so they
are listed as `/PAYLOAD.ELF`, `/BOOT/payload.elf.gz` and
`/FRAG/SPLIT.ELF`. `payload.elf.gz` and `Long File Name Payload.elf` have
long-name entries.

| Image | Layout |
| --- | --- |
| `fat12.img` | 128 KiB, 512 B sectors and clusters, 1 reserved sector, 2 FATs of 1 sector, 512 root entries, 221 clusters. `split.elf` occupies clusters 8, 10 and 11 (`hole.txt` held cluster 8 and was deleted before it was written; `keep.txt` is cluster 9). Boot code at 0x3E (mkfs.fat's "not a bootable disk" message loop). |
| `fat16.img.gz` | 2304 KiB, 512 B sectors and clusters, 2 FATs of 18 sectors, 512 root entries, 4,539 clusters; `split.elf` fragmented as on FAT12. |
| `fat32.img.gz` | 34 MiB, 512 B sectors and clusters, 32 reserved sectors, 2 FATs of 536 sectors, 68,528 clusters, root directory at cluster 2, FSInfo at sector 1, backup boot sector at 6. mtools allocates from the FSInfo hint, so `split.elf` is contiguous here. Boot code at 0x5A. |
| `exfat.img.gz` | 2 MiB, 512 B sectors, 4 KiB clusters, 1 FAT at sector 24, cluster heap at sector 32, 508 clusters; allocation bitmap at cluster 2, up-case table at clusters 3-4 (5,836 B, FAT-chained), root directory at cluster 5. Every file except `split.elf` is contiguous (`NoFatChain`); `split.elf` is clusters 12 and 14 through the FAT, with `keep.txt` at 13. The boot code area is zero-filled. |

Volume IDs and timestamps of the FAT images are fixed, so they are
reproducible byte for byte. The exFAT image is not: mkfs.exfat takes the
volume serial number from the clock and the Linux driver stamps creation
and access times when it writes.

## Generator and commands

Generated on 2026-10-13 in the Docker image `arm64v8/ubuntu:24.04`
(`sha256:b44ffd8afd8ddbe91a08120a3aba4d4d105c17ccfadd835beb5097da5d196d65`)
on macOS AArch64, with the Ubuntu packages dosfstools `4.2-1.1build1`
(mkfs.fat 4.2), mtools `4.0.43-1build1`, exfatprogs `1.2.2-1build1`,
coreutils `9.4-3ubuntu6.3` and gzip `1.12-1ubuntu3.2`. The exFAT image was
written by the exfat driver of the container's kernel (Linux 7.0.14,
OrbStack). From the repository root:

```sh
docker run --rm -v "$PWD/tests/fixtures:/fixtures" arm64v8/ubuntu:24.04 bash -c \
    'apt-get update && apt-get install -y dosfstools=4.2-1.1build1 mtools=4.0.43-1build1 \
     && bash /fixtures/fat/generate.sh'
docker run --rm --privileged -v "$PWD/tests/fixtures:/fixtures" arm64v8/ubuntu:24.04 bash -c \
    'apt-get update && apt-get install -y exfatprogs=1.2.2-1build1 \
     && bash /fixtures/fat/generate-exfat.sh'
```

On a Linux host with the tools installed, `generate.sh` runs directly
(`MKFS_FAT`, `FSCK_FAT` and `MTOOLS_BIN` name other binaries);
`generate-exfat.sh` needs root for the loop mount.

`generate.sh`, for each image:

1. sets every source file's time to 2025-10-12 00:00:00 UTC
   (`1760227200`) and exports `SOURCE_DATE_EPOCH` with that value;
2. runs `mkfs.fat --invariant -i 5a524146 -n <label> -F <bits> -s 1 -C
   <image> <KiB>` (`ZRAXFAT12` on 128 KiB, `ZRAXFAT16` on 2304 KiB,
   `ZRAXFAT32` on 34816 KiB);
3. copies the tree with `mcopy -m` and `mmd`, deleting `frag/hole.txt`
   after `frag/keep.txt` is written and before `frag/split.elf` is, and
   deleting `boot/deleted.elf` last;
4. checks the image with `fsck.fat -n`;
5. compresses `fat16.img` and `fat32.img` with `gzip -9 -n`.

`generate-exfat.sh` runs `mkfs.exfat -L ZRAXEXFAT -c 4096 -b 4096` on a
2 MiB file, mounts it with `mount -o loop`, copies the tree (the first
4 KiB of `split.elf`, then `keep.txt`, then the rest of `split.elf`
appended), deletes `boot/deleted.elf`, unmounts, checks with `fsck.exfat
-n` and compresses the image.

On 2026-10-13 a second run of `generate.sh` reproduced the three FAT files
with the SHA-256 values below.

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `fat12.img` | 131072 | `002350040d9f42844a6199b74e8bdae12b17b8d699e7b3b43f2145c2550a54a0` |
| `fat16.img.gz` | 3216 | `ed9f0f1601bd187f993fbc64bda7ba5da97c4f79fe5239d0e05a64b3feb41dc1` |
| `fat32.img.gz` | 35659 | `1081777bf8c0c9d57a0998cd02e103979045337969691aeae66fcb991920985b` |
| `exfat.img.gz` | 7801 | `3b5db5509b5d62d2b1dd87a1db677dcc44b1389b71c17a748d02034f83ad9a6f` |

Decompressed:

| Image | Size (B) | SHA-256 |
| --- | --- | --- |
| `fat16.img` | 2359296 | `034d422ddc645117b9aef479e40e234eedf423dce6bf8fa29da2d10e9c2a2704` |
| `fat32.img` | 35651584 | `299a9820a6ddb4798e848907d9753dfe1f46c6bb7eb5f8bcb6c5130177844f14` |
| `exfat.img` | 2097152 | `549abbcf15ebd97c50d508c86b8ab934e39f758acf25776c5ca84dc8691beb6c` |
