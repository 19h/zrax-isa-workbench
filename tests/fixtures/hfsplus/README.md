# HFS+ and HFSX volume fixtures

Small raw volume images for `tests/hfsplus.rs` and
`web/tests/hfsplus.test.mjs`, created by macOS from synthetic inputs.
`generate.sh` rebuilds both images.

## Contents

Every member is synthetic and built by `generate.sh` from committed
fixtures:

| Input | Built from |
| --- | --- |
| `payload.elf` | `tests/fixtures/compressed/payload.elf`: a 256 B ELF64 header for x86-64 with no code |
| `zrax.macho` | `tests/fixtures/apple/kernel.macho` (an 8 KiB arm64 Mach-O header with no code), padded with the repeated ASCII text `zrax synthetic inline member ` to 24 KiB |
| `large.macho` | the same Mach-O, padded with `zrax synthetic resource fork member ` to 200 KiB |
| `fragmented.elf` | `payload.elf`, padded with `zrax synthetic fragmented member ` to 40 KiB |
| `notes.txt` | 43 B of ASCII text, not a recognized format |

`hfsplus.img` is a journaled HFS+ volume (`H+` version 4, last mounted
version `HFSJ`) named `ZRAX`: 1 MiB, 256 allocation blocks of 4 KiB, a
512 KiB journal, a catalog B-tree of depth 2 (an index root over two leaves)
with 4 KiB nodes, and 8 KiB attribute nodes.

| Path | What macOS stored |
| --- | --- |
| `/payload.elf` | a hard link (`hlnk`/`hfs+`) to `iNode27` in the metadata folder, which holds `payload.elf` |
| `/links/hardlink.elf` | a second hard link to `iNode27` |
| `/links/symlink.elf` | a symbolic link to `../payload.elf` |
| `/notes.txt` | `notes.txt` |
| `/Applications/Zrax.app/Contents/MacOS/Zrax` | `zrax.macho`, decmpfs type 7: LZVN in the `com.apple.decmpfs` attribute (300 B attribute) |
| `/Library/large.macho` | `large.macho`, decmpfs type 8: four LZVN chunks in the resource fork (1,799 B) |
| `/bin/fragmented.elf` | `fragmented.elf` in ten one-block extents: eight in the catalog record and two in an extents overflow record |
| `/.journal`, `/.journal_info_block` | the journal files `newfs_hfs` creates |
| `/.HFS+ Private Directory Data\r`, and the file metadata folder (four U+0000 characters and `HFS+ Private Data`) | the hard-link metadata folders macOS creates |

`hfsx.img` is a case-sensitive HFSX volume (`HX` version 5, catalog
`keyCompareType` `0xBC`) named `ZRAXX`, not journaled: 512 KiB, 1,024
allocation blocks of 512 B, so the 4 KiB catalog nodes span eight blocks.

| Path | What macOS stored |
| --- | --- |
| `/CASE/payload.elf` | `payload.elf` |
| `/case/payload.elf` | `zrax.macho`, uncompressed (`cp`) |
| `/case/large.macho` | `large.macho`, decmpfs type 8 in a resource fork of four 512 B blocks |

The recognized members, in walk order, are `/payload.elf`,
`/Applications/Zrax.app/Contents/MacOS/Zrax`, `/bin/fragmented.elf` and
`/Library/large.macho` in `hfsplus.img`, and `/CASE/payload.elf`,
`/case/large.macho` and `/case/payload.elf` in `hfsx.img`.

## Generator and commands

Generated on 2026-10-13 on macOS 27.2 (build 26B5101f), AArch64, with the
system `hdiutil` (DiskImages framework 710), `newfs_hfs` (`hfs-753.40.4`),
`ditto` and Python 3. From the repository root:

```sh
tests/fixtures/hfsplus/generate.sh
```

The script:

1. builds the inputs above in a temporary directory with Python;
2. creates a raw read/write image (`UDRW`, which `hdiutil` stores as a raw
   disk image without a partition map) with
   `hdiutil create -size 1m -layout NONE -fs "Journaled HFS+" -volname ZRAX`;
3. attaches it with `hdiutil attach -nobrowse -noverify -noautoopen
   -mountpoint`, copies `payload.elf` and `notes.txt` with `cp`, writes the
   two Mach-O files with `ditto --hfsCompression` (ditto leaves files of
   16 KiB or less uncompressed, stores the 24 KiB file in the attribute and
   the 200 KiB file in the resource fork), and makes the links with `ln`
   and `ln -s`;
4. fragments the free space (40 one-block files, a filler that takes the
   remaining blocks, then every other one-block file deleted), copies
   `fragmented.elf` with `cp`, and deletes the fragmentation files;
5. detaches the image and copies it to `hfsplus.img`;
6. creates `hfsx.img` the same way with `-size 512k -fs "Case-sensitive
   HFS+" -fsargs "-b 512" -volname ZRAXX`, copies the files with `cp` and
   `ditto --hfsCompression`, and detaches it.

The images are not reproducible byte for byte: the volume dates, the
volume identifier in the Finder information, the journal contents and the
allocation of the fragmented file differ from run to run. The tests check
structure and member contents, not these bytes.

## Sizes and SHA-256

The volumes are committed as `gzip -9 -n` files, which `generate.sh`
writes after the volumes; the tests decompress them.

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `hfsplus.img` (inside `hfsplus.img.gz`) | 1048576 | `e031e53bb8d2254bd7455da2424f9dbe7a5d8f7dd32d4589e2f6296a48ca8bc5` |
| `hfsx.img` (inside `hfsx.img.gz`) | 524288 | `caafdb485ed15e334361dd9bc7cdd8de250049d3507f9ba61fc5dc8992f69916` |
| `hfsplus.img.gz` | 7961 | `1d0d40449da4b33701de9b382359f1ef55bb2d46dd2e09ebe0aeea4ae24cfad7` |
| `hfsx.img.gz` | 1747 | `51a2de38dc73395ebfb7e9cda2a3054229428fdf937056c83a938fa9b554d0bc` |
