# ext filesystem fixtures

Small ext2 and ext4 images for `tests/ext.rs` and `web/tests/ext.test.mjs`,
built with e2fsprogs from a synthetic directory tree. `generate.sh` rebuilds
both images.

## Contents

Both images hold the same tree. Every file is synthetic:

| Path | Contents |
| --- | --- |
| `/payload.elf` | `tests/fixtures/compressed/payload.elf`: a 256 B ELF64 header for x86-64 with no code |
| `/boot/payload.elf.gz` | `tests/fixtures/compressed/payload.elf.gz`, its gzip stream |
| `/notes.txt` | 42 B of ASCII text, not a recognized format |
| `/bin/link` | a symlink to `../payload.elf` |
| `/bin/sparse.elf` | `payload.elf`, then one line of ASCII text at 64, 128, 192, 256 and 300 KiB, 310 KiB in all, with holes between the lines |
| `/many/member-entry-000.bin` ... `/many/member-entry-159.bin` | 160 hard links to the empty file `/many/empty`, enough entries for `e2fsck -D` to index the directory as an htree |
| `/many/hardlink.elf` | a hard link to `/payload.elf` |
| `/many/member-entry-160.elf` | a separate copy of `payload.elf` |
| `/lost+found` | created by `mke2fs` |

The recognized members, in walk order, are `/payload.elf`,
`/bin/sparse.elf`, `/boot/payload.elf.gz` and `/many/member-entry-160.elf`.

| Image | Layout |
| --- | --- |
| `ext2.img` | 256 blocks of 1 KiB, 32 inodes of 128 B, one block group, features `ext_attr dir_index filetype sparse_super large_file`. `/bin/sparse.elf` uses direct, single-indirect and double-indirect blocks. `/many` is an htree directory (hash version 1, 6 index entries). |
| `ext4.img` | 64 blocks of 4 KiB, 32 inodes of 256 B, one block group, 64-byte group descriptors, features `ext_attr dir_index filetype extent 64bit flex_bg sparse_super large_file huge_file dir_nlink extra_isize metadata_csum` (CRC32C), no journal. `/bin/sparse.elf` has six extents under a depth-1 extent tree. `/many` is an htree directory. |

Volume UUIDs, the htree hash seed and all timestamps are fixed, so the
images are reproducible byte for byte.

## Generator and commands

Generated on 2026-10-12 with e2fsprogs 1.47.0 (5-Feb-2023), Ubuntu package
`1.47.0-2.4~exp1ubuntu4.1` (arm64), in the Docker image
`arm64v8/ubuntu:24.04`
(`sha256:b44ffd8afd8ddbe91a08120a3aba4d4d105c17ccfadd835beb5097da5d196d65`)
on macOS AArch64. The script also needs GNU coreutils and findutils, which
the image provides. From the repository root:

```sh
docker run --rm -v "$PWD/tests/fixtures:/fixtures" arm64v8/ubuntu:24.04 \
    bash /fixtures/ext/generate.sh
```

On a Linux host with e2fsprogs installed, `tests/fixtures/ext/generate.sh`
runs directly; `MKE2FS`, `E2FSCK` and `DEBUGFS` name other tool binaries.

The script:

1. builds the tree in a temporary directory and sets every timestamp to
   2025-10-12 00:00:00 UTC (`1760227200`);
2. runs `mke2fs -d` with a fixed UUID, hash seed and volume label:
   - ext2: `mke2fs -q -F -t ext2 -b 1024 -I 128 -N 32 -m 0 -O ^resize_inode`
     on 256 blocks;
   - ext4: `mke2fs -q -F -t ext4 -b 4096 -I 256 -N 32 -m 0
     -O ^has_journal,^resize_inode` on 64 blocks;
3. runs `e2fsck -fyD` to build the htree index of `/many`;
4. pins the inode times with `debugfs -w set_inode_field`;
5. checks the result with `e2fsck -fn`.

On 2026-10-13 the same command reproduced both files with the SHA-256
values below.

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `ext2.img` | 262144 | `c3c56a7b25cfe1cadd96f0b8d6aa5bce35025bbb3fdb4dfe5f5bed36c7473d2a` |
| `ext4.img` | 262144 | `a05c819b4067d1d1a40682045aac8511cea6591d03a965337cac28f9e4585847` |
