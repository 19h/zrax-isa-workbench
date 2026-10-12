# Archive fixtures

Fixtures for `tests/archives.rs` and `web/tests/archives.test.mjs`, written
by real archivers so the parsers are checked against their output and not
only against builders written from the same reading of the specifications.
`generate.sh` rebuilds them all.

## Members

Every archive holds the same synthetic members:

- `bin/payload.elf` (256 B, also committed as `payload.elf`): a 64-byte
  ELF64 little-endian header with `e_machine = 0xB7` (AArch64), followed by
  192 B of the repeated ASCII text `zrax archive fixture `. It has no
  program headers or code; it is not a runnable program.
- `notes.txt` (51 B): one line of ASCII text, not a recognized format.
- The tar fixtures add the same ELF under a 118-byte path,
  `long/` + 50 × `d` + `/` + 50 × `e` + `/payload.elf`, which does not fit
  the 100-byte `name` field. The tar and CPIO fixtures also hold the `bin`
  directory entry (except `pax.tar` and `gnu.tar`).

All file times are 2026-10-12 00:00:00 UTC; owners are `root` (0:0).

## Generators and commands

Generated on 2026-10-12, macOS AArch64 (Darwin 27.2), with the commands in
`generate.sh`:

| File | Writer | Layout it exercises |
| --- | --- | --- |
| `stored.zip` | Info-ZIP `zip -X -0` | method 0 |
| `deflate.zip` | Info-ZIP `zip -X -9` | method 8 |
| `descriptor.zip` | Info-ZIP `zip -X -9 -fd` | data descriptors with signature, 32-bit sizes |
| `zip64.zip` | Info-ZIP `zip -X -9 -fz` | ZIP64 end record and locator; local ZIP64 fields with both sizes; central ZIP64 field with the saturated uncompressed size; saturated directory offset in the end record |
| `encrypted.zip` | Info-ZIP `zip -X -9 -P zrax` | traditional PKWARE encryption (flag bit 0) with data descriptors |
| `bzip2.zip` | 7-Zip `7zz a -tzip -mtc=off -mm=BZip2` | method 12 |
| `lzma.zip` | 7-Zip `-mm=LZMA` | method 14 with the ZIP LZMA header and an end-of-stream marker (flag bit 1) |
| `xz.zip` | 7-Zip `-mm=XZ` | method 95 |
| `deflate64.zip` | 7-Zip `-mm=Deflate64` | method 9 (opaque) |
| `aes.zip` | 7-Zip `-pzrax -mem=AES256` | AE-x encryption, method 99 (opaque) |
| `zstd.zip` | Python `zipfile`, `ZIP_ZSTANDARD` | method 93 |
| `ustar.tar` | bsdtar `--format ustar` | POSIX ustar; the long path split into `prefix` and `name` |
| `pax.tar` | Python `tarfile`, `PAX_FORMAT` | pax extended header (`x`) with a `path` record; 10240-byte record padding |
| `gnu.tar` | Python `tarfile`, `GNU_FORMAT` | GNU magic; `././@LongLink` long name (`L`); 10240-byte record padding |
| `newc.cpio` | bsdcpio `-o -R 0:0 -H newc` | newc, 512-byte block padding |
| `odc.cpio` | bsdcpio `-o -R 0:0 -H odc` | odc |
| `binary.cpio` | bsdcpio `-o -R 0:0 -H bin` | old binary in the host byte order (little-endian) |
| `initramfs.cpio.gz` | `gzip -n -9 -c newc.cpio` | gzip-compressed newc, as Linux initramfs images ship |

Tool versions: Info-ZIP Zip 3.0 (Apple build), 7-Zip 26.03 (arm64), Python
3.14.7, bsdtar 3.5.3 and bsdcpio 3.5.3 (libarchive 3.7.4), Apple gzip
487.40.2.

The `crc` CPIO format (`070702`), big-endian binary CPIO, GNU base-256
sizes, sparse members, package layouts (APK, JAR, IPA, Nordic DFU, PDX) and
corrupt variants have no writer here; `tests/archives.rs` builds them from
the documented layouts.

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `payload.elf` | 256 | `ee083ccfb76de0aa40c3067509624825c97799adc3e725d071fd131c98635d80` |
| `aes.zip` | 507 | `a0e87e481b81b67173c649ff56c774f7330086fd6e88faa9f9780a8a223be0cd` |
| `bzip2.zip` | 452 | `e37f3179bc69b4517c7c786caaf8550c335a3b609f7d79ff3f7743eb38923ff6` |
| `deflate.zip` | 321 | `1dec5a9331ce1d14ed40baa6c2e5cafdcbea336b795c3220d9e88d5d3f233ada` |
| `deflate64.zip` | 407 | `a8610648ff16d99a9f6ec04139c1b3329ece863111ff277bbe9a910c68d7c7be` |
| `descriptor.zip` | 355 | `83ddf47c4883ea5c584121c8cd846c14c323aec6205123e5b548bd112d5371cf` |
| `encrypted.zip` | 377 | `b9487b1c43e0c74b53b05cc94f2ca62e564953fc4dcc5c32c6a1dd5bdb7af1bb` |
| `lzma.zip` | 411 | `e18ce6072c77d8de68e7cbaff5e24089d1a3f86cfb2bd1b758056264e315dd47` |
| `stored.zip` | 529 | `4a974cb1d9cc5118cf68ee0f8137f3ec0a3ee2ff729f845f1a136eaa972312b4` |
| `xz.zip` | 457 | `c5313f40be0825650e7f61c5e62e206511b5e8522ef9701f06e28fbc16f01dc5` |
| `zip64.zip` | 461 | `92385eec40189f77005aeb60f0235063c39d0e8991a297bbd7179d4797b6b908` |
| `zstd.zip` | 346 | `c1f46758344185fc2db5449b9dff2c6e525f09c3ef5aaef05220d7fbc640754f` |
| `gnu.tar` | 10240 | `f4a7a0129bd646406fada1f9dad23fe13c70f41848d81580b1c4960d660cdb18` |
| `pax.tar` | 10240 | `566f5db22ea2742b208d0bf6d221cb60d34e7f00c91c2d5df590f01af1eb557e` |
| `ustar.tar` | 4608 | `f07a2db9c1a74d96807bc1636cec8a0aa3733e367d02c80dae4d7c0f23c30c6e` |
| `binary.cpio` | 512 | `50955caa5698f71af0644c12e1b5eeb7492dc92e54b79386a65074fe76a3937e` |
| `newc.cpio` | 1024 | `9d7081e167dae2e93a24133ea8c4c1f691231a6dcd714cb0d9d6c02e1d6728f4` |
| `odc.cpio` | 1024 | `8567be38d7ff004de0b327f9367ba6c7e977d9000dacb00181937efb8b3c28c4` |
| `initramfs.cpio.gz` | 242 | `68c8357d87911fd8ae02a9e875c731c096583730b078aa92cb1785dc0793d998` |

Rebuilding with other tool versions, or 7-Zip's random AES salt, changes
the bytes; the tests check structure, not digests.
