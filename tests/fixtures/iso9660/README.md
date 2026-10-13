# ISO 9660 fixtures

Three small ISO 9660 images of the same synthetic tree for `tests/iso9660.rs`
and `web/tests/iso9660.test.mjs`, written by real tools. Each image is stored
gzip-compressed (`gzip -9 -n`, no name or time stamp); the tests decompress
them before classifying. `generate.sh` rebuilds all three.

## Contents

Every file is synthetic:

| Path | Contents |
| --- | --- |
| `/boot/boot.bin` | `boot.asm` assembled with `nasm -f bin`: 34 bytes of x86 real-mode code (clear the segment registers, print a line through INT 10h, `hlt`), the line, zero fill to 2048 B |
| `/bin/payload-with-a-long-name.elf` | `tests/fixtures/compressed/payload.elf`: a 256 B ELF64 header for x86-64 with no code |
| `/deep/l1/l2/l3/l4/l5/l6/l7/l8/deep.elf` | the same ELF in a directory at level 10 of the hierarchy, the root being level 1 (ECMA-119 6.8.2.1 allows eight) |
| `/docs/readme.txt` | 38 B of ASCII text, not a recognized format |

Every file and directory time is 2026-10-13 00:00 (`touch -t 202610130000`).
The El Torito catalog has one bootable no-emulation default entry for
platform 80x86 that loads 4 virtual sectors of `/boot/boot.bin`.

| Image | Writer and options | What it exercises |
| --- | --- | --- |
| `rockridge.iso.gz` | bsdtar `--format iso9660 --options iso9660:boot=boot/boot.bin,boot-type=no-emulation,boot-load-size=4,!pad,volume-id=ZRAX_RR` | Rock Ridge (`ER` `RRIP_1991A` in a `CE` continuation area, `NM`, `PX`), the deep directory relocated into `rr_moved` (`CL`, `RE`, `PL`), Joliet level 3, El Torito, boot catalog file `boot.catalog` |
| `joliet.iso.gz` | the same with `!rockridge,volume-id=ZRAX_JOLIET` and `--exclude ./deep` (libarchive refuses the deep directory without Rock Ridge) | Joliet names (UCS-2 level 3), ISO 9660 level 1 identifiers in the primary hierarchy |
| `hdiutil.iso.gz` | `hdiutil makehybrid -quiet -iso -joliet -udf -eltorito-boot tree/boot/boot.bin -no-emul-boot -iso-volume-name ZRAX_HD -joliet-volume-name ZRAX_HD` | UDF bridge (`BEA01`, `NSR02`, `TEA01` after the terminator), Joliet level 1, SUSP `SP`/`ER` (`IEEE_P1282`) with `PX`, `TF` and Apple `AA` entries but no `NM`, so names are the ISO 9660 identifiers; deep directories recorded in place; heavy zero padding |

The tests expect these members, in walk order (the boot image first):
`/bin/payload-with-a-long-name.elf` and
`/deep/l1/l2/l3/l4/l5/l6/l7/l8/deep.elf` (rockridge),
`/bin/payload-with-a-long-name.elf` (joliet),
`/BIN/PAYLOAD-WITH-A-LONG-NAME.ELF` and
`/DEEP/L1/L2/L3/L4/L5/L6/L7/L8/DEEP.ELF` (hdiutil).

## Generator and commands

Generated on 2026-10-13 on macOS 27.2 (build 26B5101f), AArch64, with:

- bsdtar 3.5.3 (libarchive 3.7.4, zlib 1.2.12), the system `/usr/bin/bsdtar`;
- hdiutil from the same macOS;
- NASM 3.02 (Homebrew);
- gzip from the same macOS.

From the repository root:

```sh
tests/fixtures/iso9660/generate.sh
```

`BSDTAR` and `NASM` name other binaries; without `hdiutil` the script skips
`hdiutil.iso.gz`. The script builds the tree in a temporary directory, runs
the writers as listed above and compresses each image with `gzip -9 -n`.

The writers take the volume time stamps of the descriptors, and some
directory record and Rock Ridge `TF` time stamps, from the clock. Two runs on
2026-10-13 a few seconds apart produced images of the same sizes that
differ only in those time fields. The tests do not depend on them.

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `rockridge.iso.gz` | 2653 | `07155bf4181b6ddab07e87f1fc88ebc717bae59b8d5a159ae5da6e2b9e66fb7a` |
| (decompressed) | 126976 | `c660996e8b3bd5b215547b1270d6c76911044de205c8c3c1b3b8a8d3e0593751` |
| `joliet.iso.gz` | 1202 | `6f875b960a03bd3b6ea55c357317eba8eb224556e7b4e1d2654f391eba67b80b` |
| (decompressed) | 83968 | `7bf4293278928b2a7e934a4d97e58fb8afe388ead90c62a1c432e6d655f854f4` |
| `hdiutil.iso.gz` | 5561 | `404e3c3bd82ab0321e8e84092351a26ffb34e99f9cadb2130adec573c226fbc0` |
| (decompressed) | 1157120 | `d138b6524cf7d76920276cc77e2604da1135308b41186f4d02663a9ce642f503` |
| `boot.asm` | 664 | `3266d72fdd6d90c03179536a81c77e403a98959bb8cbd75cf6f0c85a912d84d6` |

The assembled `boot.bin` (2048 B) has SHA-256
`730970a999baff3c9dce36bea7785d29f6fe356f92ef0205623c00825b729932`.
