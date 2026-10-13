# UDF fixtures

Small UDF images for `tests/udf.rs` and `web/tests/udf.test.mjs`, written by
macOS from one synthetic tree. Each image is stored gzip-compressed
(`gzip -9 -n`, no name or time stamp); the tests decompress them.
`generate.sh` rebuilds all of them.

## Contents

Every file is synthetic and comes from committed fixtures:

| Path | Contents |
| --- | --- |
| `/bin/payload.elf` | `tests/fixtures/compressed/payload.elf`: a 256 B ELF64 header for x86-64 with no code |
| `/deep/a/b/c/kernel.macho` | `tests/fixtures/apple/kernel.macho`: an 8 KiB arm64 Mach-O header with no code |
| `/docs/readme.txt` | 42 B of ASCII text, not a recognized format |
| `/docs/café-€.elf` | `payload.elf` again, under a name outside Latin-1, which UDF records with 16-bit OSTA CS0 characters |

Every file and directory time is 2026-10-13 00:00 (`touch -t 202610130000`).
The recognized members, in walk order, are `/bin/payload.elf`,
`/deep/a/b/c/kernel.macho` and `/docs/café-€.elf`; `newfs-201.img` lists
`/fragmented.elf` first, and `newfs-4k.img` is empty.

| Image | Writer and options | What it exercises |
| --- | --- | --- |
| `hdiutil-102.iso` | `hdiutil makehybrid -udf -udf-version 1.02 -udf-volume-name ZRAX_UDF102` | `NSR02`, version 2 descriptors, a read-only partition at sector 272, file entries with one `short_ad` each, anchors at 256 and N - 256 (299) |
| `hdiutil-150.iso` | the same with `-udf-version 1.50 -udf-volume-name ZRAX_UDF150` | the same structures, domain revision 1.50 |
| `hdiutil-bridge.iso` | `hdiutil makehybrid -iso -udf -iso-volume-name ZRAX_BRIDGE -udf-volume-name ZRAX_BRIDGE` | a UDF bridge disc: an ECMA-119 primary volume descriptor and terminator at 0x8000 and 0x8800 before `BEA01`, `NSR02` and `TEA01`; UDF 1.50 |
| `newfs-102.img` | `/sbin/newfs_udf -r 1.02 -v ZRAX_UDF102` on a 1 MiB zero-filled file, filled through the macOS UDF file system | file entries with their data in the allocation descriptor field, an overwritable partition at 257, anchors at 256 and N |
| `newfs-201.img` | `newfs_udf -r 2.01 -v ZRAX_UDF201`, the tree, then 4 KiB text files until the volume is full, every other one deleted, and `fragmented.elf` written into the holes | `NSR03`, extended file entries, `fragmented.elf` (`payload.elf` padded with `zrax synthetic fragmented member ` to 40 KiB) in seven `short_ad` extents, 36 text files and 37 deleted directory entries, a root directory recorded in two extents |
| `newfs-250.img` | `newfs_udf -r 2.50 -v ZRAX_UDF250` | a metadata partition (type 2 map `*UDF Metadata Partition`, metadata file at block 1, mirror at 237) holding the file set, entries and directories; the Mach-O in a `long_ad` extent of the physical partition |
| `newfs-512.img` | `newfs_udf -r 2.01 -b 512 -v ZRAX_UDF512` | 512 B logical blocks: the anchor at 0x20000, the recognition sequence still 2048 B apart, anchors at 256, N - 256 and N |
| `newfs-4k.img` | `newfs_udf -r 2.01 -b 4096 -v ZRAX_UDF4K` on a 2 MiB file, not filled | 4096 B logical blocks: the recognition sequence one sector (4 KiB) apart, the anchor at 1 MiB; an empty root directory (macOS does not mount 4096 B blocks from a disk image of 512 B sectors) |

## Generator and commands

Generated on 2026-10-13 on macOS 27.2 (build 26B5101f), AArch64, with the
system `hdiutil` (DiskImages framework 710), `/sbin/newfs_udf` and the
macOS UDF file system (`udf.fs` and `udf.kext` 2.5), `cp`, `dd`, `gzip` and
Python 3. From the repository root:

```sh
tests/fixtures/udf/generate.sh
```

The script builds the tree in a temporary directory, writes the three
`hdiutil` images with `hdiutil makehybrid -quiet`, then for each `newfs_udf`
image creates a zero-filled file with `dd`, formats it, attaches it with
`hdiutil attach -nobrowse -noverify -noautoopen -mountpoint ... -imagekey
diskimage-class=CRawDiskImage`, copies the tree with `cp -RX` (no extended
attributes), and detaches it. Every image is compressed with `gzip -9 -n`.

The images are not reproducible byte for byte: volume identifiers, volume
set identifiers and descriptor timestamps carry the time of writing. Two
runs on 2026-10-13 a minute apart produced compressed images of the same
sizes. The tests check structure and member contents, not these bytes.

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `hdiutil-102.iso.gz` | 3212 | `6d7e561471799819cee59127e8a4483a5b4c6a4fe88ba38e5a00038cdb2c9ef0` |
| (decompressed) | 1138688 | `32c9e1b3c41a1bdebefcea0d13b9373387f27374d3436f18e5a6f1c54235c4fa` |
| `hdiutil-150.iso.gz` | 3223 | `5992f8729a63b7ce18700527b9fbc92f0a39c130870dd12cba5e7bbbf67c0f4e` |
| (decompressed) | 1138688 | `9e34a1bf4024c7f95db461b7f35e50b6e0511488b093ecfa49064f37e7e14b1c` |
| `hdiutil-bridge.iso.gz` | 4085 | `9a9f9059b8267a1c743aa7ca73a42f27d0f4e8435b56e6a09b707ad0e2081de3` |
| (decompressed) | 1138688 | `081c6448a6f450d16af3633051b8e0829e719288dde9bfd40b8e29475e7f6a4c` |
| `newfs-102.img.gz` | 3484 | `7e7f1d2ce0ec9853b530ca53e2c6453b68c3217a813000a9d357f925f2ba6012` |
| (decompressed) | 1048576 | `05a457f30024f167edac30624a16f091dd300d6a290a072f80cebddba6e53af6` |
| `newfs-201.img.gz` | 6882 | `74284404e8e1d09b8de9f89b0808cf9cd14699adeb2edb66b40b55f8923ec8be` |
| (decompressed) | 1048576 | `3666d32db7acab0e767eb5380f0b9193f926201702531e1b6ffd375f6a87aff1` |
| `newfs-250.img.gz` | 3701 | `b1bfda7d590f9f21afe2f6366fd0ab7203135e1c73d4e7ff884f6c0390d985e7` |
| (decompressed) | 1048576 | `3cd136c1f9ba6722bb041667980c0672bcb1bc5af7fb8dfa1ffa235a46328c4f` |
| `newfs-512.img.gz` | 3472 | `a08bd11139a5fefdaaf3bc77e304d3cf0de0552a5cec5eb73e6c636a0e7267be` |
| (decompressed) | 1048576 | `69bb7ad19569f4c109a265cbe1416fd42f02adaeb9461658e9969c1825507d12` |
| `newfs-4k.img.gz` | 3444 | `8e2161a94176603725f48955e7c7a116fa6222b108750a9f65451e7aadf951d2` |
| (decompressed) | 2097152 | `1c700214e8f2ba827fc061d4395308b64c1bc101479a9233d42f13a8a3792933` |
