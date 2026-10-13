# Router firmware wrappers

`src/formats/router.rs` and its submodules (`trx.rs`, `chk.rs`, `seama.rs`,
`tplink.rs`, `safeloader.rs`) parse the wrappers that consumer router
firmware ships in: Broadcom TRX, Netgear CHK, D-Link SEAMA, TP-Link firmware
headers and TP-Link SafeLoader factory images. They are built on the shared
container model ([compressed streams and the container
model](compressed-streams.md)). None of these headers names an
architecture, so every container leaves its target open and the ISA comes
from the components, each classified from its own bytes. Board IDs,
hardware IDs, vendor and support-list strings and kernel load addresses are
reported in notes and metadata and never used as ISA evidence.

## Implemented layouts

Primary source for every layout: OpenWrt firmware-utils at
[`a1d9589f1ea1b96529ac10fef5d164ff3aa03dc7`](https://github.com/openwrt/firmware-utils/tree/a1d9589f1ea1b96529ac10fef5d164ff3aa03dc7/src),
directory `src/`.

| JSON format ID | Layout | Recognition | Integrity | Primary source |
| --- | --- | --- | --- | --- |
| `trx` | Broadcom TRX `HDR0`: length, CRC-32, flags, version 1 (28-byte header, three partition offsets) or 2 (32-byte header, four offsets, the fourth a Cybertan code header) | Strong: `HDR0` at offset 0 | CRC-32 verified | `trx.c` ("mjn3's trx replacement - v0.81.1"), `otrx.c`, `asustrx.c`; Linux v6.12 `drivers/mtd/parsers/parser_trx.c` (partition roles); Broadcom `include/trxhdr.h` (flag names, 36-byte `BCMTRXV2` header) |
| `netgearchk` | Netgear CHK: header length, region and version digits, kernel and root filesystem lengths and checksums, image and header checksums, board ID | Strong: `2A 23 24 5E` at offset 0 | All four Netgear checksums verified | `mkchkimg.c` |
| `seama` | D-Link SEAMA entity (header, MD5, metadata, image) or seal (header with image size 0, metadata, then whole entities) | Strong: `5E A3 A4 17` at offset 0 | Image MD5 verified (a mismatch is a parse error, as `seama -x` rejects it) | `seama.h`, `seama.c`, `oseama.c` |
| `tplink` | TP-Link header, `mktplinkfw` layout (version word 1, or 2 with `-m 2`): vendor and firmware version strings, hardware ID and revision, region, load and entry address, kernel at 0x200, root filesystem | Weak: complete header structure | Salted MD5 verified with the `mktplinkfw.c` salts (normal or bootloader by `boot_len`); a mismatch is noted, since other tools may salt differently | `mktplinkfw.c`, `mktplinkfw-lib.c` |
| `tplink` | TP-Link header, `mktplinkfw2` layout (version word 2 or 3): firmware version string, hardware ID, revision and additional version, constants `0x55AA` and `0xA5`, optional prepended bootloader | Weak: complete header structure | Salted MD5 verified with the `mktplinkfw2.c` salts, which differ from `mktplinkfw`'s; a mismatch is noted | `mktplinkfw2.c`, `mktplinkfw-lib.c` |
| `tplink` | TP-Link SafeLoader factory image: size, salted MD5, vendor, cloud or unspecified header, `fwup-ptn` partition table at 0x1014 | Weak: size, header type, table and partition bounds | MD5 of the salt and the bytes from 0x14 verified (`put_md5`); a mismatch is noted | `tplink-safeloader.c` (`generate_factory_image`, `put_partitions`, `safeloader_parse_image`, `read_partition_table`) |

The format variant (`format.variant_name`) is the layout label: `Broadcom
TRX`, `Netgear CHK`, `D-Link SEAMA`, `TP-Link header (mktplinkfw layout)`,
`TP-Link header (mktplinkfw2 layout)`, `TP-Link SafeLoader factory image`,
or `Ambiguous TP-Link image`. The classification variant adds the header
version (`Broadcom TRX v2`) or the SEAMA kind (`D-Link SEAMA seal`).

Detection order in `formats::detect_format`: the strong check (TRX, CHK,
SEAMA magics) runs after the ZX Spectrum TZX check and before the
magic-bearing compressed streams; none of the earlier formats starts with
one of these magics. The weak TP-Link check runs after the ZX Spectrum TAP
check and before zlib and LZMA-alone, so the magic-less layouts never
shadow a format with a signature.

## Components

| Layout | Components | Classified |
| --- | --- | --- |
| TRX | One per partition offset. With three offsets: loader, kernel, root filesystem (Linux `parser_trx.c`); with one or two: kernel, root filesystem. The version 2 fourth partition (Cybertan code header) is opaque. Bytes after the TRX length (`trx -F`) are listed when they are a recognized format | Always, except the bin header |
| CHK | Kernel at the header length; root filesystem after it when its length is not zero. The kernel is often a whole TRX | Always |
| SEAMA entity | The image after the metadata | Always |
| SEAMA seal | Each entity as a whole SEAMA file (a nested seal holds the rest of the file), classified as its own SEAMA container | Always |
| TP-Link headers | `mktplinkfw2` bootloader, kernel, root filesystem | Always |
| SafeLoader | `os-image` and `file-system` (with optional `@N`) as firmware components; `partition-table`, `soft-version`, `support-list` and `extra-para` opaque; other names listed only when they are a recognized format | By role |

Root filesystems are classified like any firmware component, so a
SquashFS, JFFS2 or UBI root filesystem is parsed as that format
([read-only filesystems](rofs.md), [flash filesystems](mtd.md)) and its
recognized files are listed. On 2026-10-13 a TRX v1 image built by hand
with a raw `AArch64` kernel and a SquashFS root filesystem reported the
kernel as `aarch64` and the root filesystem as a SquashFS container whose
members are x86-64 ELF files.

## Raw LZMA kernels

OpenWrt stores router kernels as raw LZMA-alone streams, which have no
magic. OpenWrt v24.10.0 `include/image-commands.mk` defines `Build/lzma` as
`lzma e -lc1 -lp2 -pb2` (used by the TP-Link recipes in
`target/linux/ath79/image/common-tp-link.mk`), and
`target/linux/bcm47xx/image/Makefile` (`Image/Prepare`) writes
`vmlinux.lzma` with `lzma e -si -so -eos -lc1 -lp2 -pb2` (unknown size and
an end marker) and a CFE variant with `-d16` and default properties. This
is a convention of the wrapper's producer, not a header field, so a
component is decoded only when it has no codec magic
(`compressed::sniff`) and starts with an LZMA-alone header whose properties
byte is `0x5D` (the xz-utils and LZMA SDK default,
`compressed::is_plausible_lzma`) or `0x6D` (`lc=1 lp=2 pb=2`), with a
power-of-two dictionary of at least 4 KiB (`compressed::has_lzma_header`).
The decoded bytes are classified and the slice reports the stored range
plus a decoded range with transform `LZMA`; the note names the properties
and says the decode follows the OpenWrt convention. LZMA-alone has no
integrity check. A component that has such a header but does not decode is
opaque with a note, because it is most likely compressed data. Magic-bearing
components (gzip loaders, uImages, nested TRX images) are left to their own
parsers.

## Wire units and byte order

All offsets and sizes are bytes. TRX headers are little-endian; CHK, SEAMA,
TP-Link and SafeLoader headers are big-endian. TRX partition offsets are
from the start of the header; CHK parts follow the header; SEAMA images
follow the metadata; TP-Link root filesystem offsets are relative to the
header that precedes the kernel (the start of the file, or the second header
of a `mktplinkfw2` bootloader image); SafeLoader partition bases are
relative to 0x1014. TP-Link kernel load and entry addresses are read as
big-endian fields; some boards store them little-endian (`mktplinkfw -e`,
`mktplinkfw2` `FLAG_LE_KERNEL_LA_EP`), which the header does not record. No
header byte order is reported as code byte order.

## Checksums

- TRX: `crc32buf` of `trx.c`, CRC-32/JAMCRC: reflected polynomial
  `0xEDB88320`, initial register `0xFFFFFFFF`, no final XOR (the complement
  of zlib's CRC-32; check value `0x340BC6D9` for `123456789`), over the
  bytes from offset 12 (the flags/version word) to the length, stored
  little-endian. Version 2 images from `trx -2` count the 8 bytes at
  `offsets[3] + 22` (the Cybertan `stable` and `try1`-`try3` fields) as
  `0xFF`, "like CFE does"; `trx.c` applies this even when `offsets[3]` is
  zero, which puts those bytes in the header, and the parser does the same,
  clipped to the CRC range. Version 2 images are also accepted with a plain
  CRC (other writers). Because `asustrx` recomputes the CRC to the end of
  the file without updating the length, a CRC over 12 to the end of the
  file is accepted too. The note names the convention, the range and the
  variant that matched. A mismatch is a parse error.
- CHK: `netgear_checksum_add`/`_fini` (two wrapping byte sums folded to 16
  bits; derived check value `0x091501DD` for `123456789`) of the kernel, the
  root filesystem, both together, and the 40-byte header with its checksum
  field zero followed by the board ID. Every mismatch is a parse error.
- SEAMA: the MD5 of the image is verified; a mismatch is a parse error.
- TP-Link `mktplinkfw` and `mktplinkfw2`: as `inspect_fw` does, the MD5
  field is replaced by the layout's salt (the bootloader salt when
  `boot_len` is not zero) and the whole file is hashed. SafeLoader: the MD5
  of `md5_salt` followed by the bytes from 0x14 to the image size
  (`put_md5`). Both are recognized from their structure, so a mismatch is
  a note, not an error. On 2026-10-13 the tool-made fixtures `tplink-v1.bin`,
  `tplink-v2.bin`, `safeloader.bin` and the entity in `image.seama` all
  verified.

All of these are integrity checks; none authenticates the image.

## Validation and resource bounds

- TRX: version 1 or 2; length at least the header size and within the file;
  used offsets form a non-empty prefix of the table, each at or after the
  header, before the length, and strictly increasing (Linux `parser_trx.c`
  ends each partition where the next begins). Flags are listed with the
  names of Broadcom `trxhdr.h` and the note says their meaning to router
  boot loaders is not established.
- CHK: header length 40 to 104 B (board ID at most 64 B, `MAX_BOARD_ID_LEN`);
  kernel length not zero; every part inside the file; only `0x00`/`0xFF`
  after the image.
- SEAMA: every header has the magic; every entity range inside the file;
  only padding after an entity; a seal stops at padding or the end of the
  file. Metadata notes list at most 16 strings of at most 128 characters;
  a seal lists at most 4096 entities (`MAX_COMPONENTS`) and counts the rest.
- TP-Link headers: the 512-byte header must be complete; the version word
  must match the layout; printable, NUL-terminated, non-empty strings
  (`mktplinkfw` vendor and firmware version, `mktplinkfw2` firmware
  version); `mktplinkfw2` constants `0x55AA` at 0x8C and `0xA5` at 0x90;
  kernel offset 0x200 (or, with a `mktplinkfw2` bootloader, after the
  bootloader and a second header with the same version word); kernel length
  not zero; every range inside the file; the root filesystem after its
  header and outside the kernel; the file no longer than a non-zero firmware
  length; only erased flash and JFFS2 end marks (`DE AD C0 DE` at 4 KiB
  boundaries, `pad_jffs2` in `mktplinkfw-lib.c`) after the image. Combined
  images leave the root filesystem fields zero (`mktplinkfw`) or
  `0xFFFFFFFF` (`mktplinkfw2`), or point the offset at the end of the
  kernel (`-O`).
- SafeLoader: image size at least 0x1814 B and within the file; `?NEW`
  headers are not recognized; vendor information at most 4092 B; 1 to 32
  `fwup-ptn` lines (names of 1 to 31 printable characters, `0x` and 1 to 8
  hex digits) followed only by NUL/`0xFF` fill; partitions after the table,
  in order, without overlap, inside the image; only padding after the last
  partition.
- Bytes that validate as two TP-Link layouts are reported as `Ambiguous
  TP-Link image` with an unknown ISA and nothing extracted.
- Decoded LZMA components are capped at 64 MiB each and 256 MiB per
  container (`MAX_EXTRACTED`); container nesting is capped at six levels.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| R1 | Router kernels without a codec magic are LZMA-alone with properties `0x5D` or `0x6D` | A TRX or TP-Link image whose kernel decodes with other properties (stock vendor firmware); it is classified from its stored bytes instead |
| R2 | A third TRX offset means the first partition is a loader (Linux `parser_trx.c`) | A vendor TRX with kernel, root filesystem and a third data partition |
| R3 | The fourth version 2 TRX partition is a Cybertan code header (`trx -2` in the bcm47xx `trx-v2-with-loader` recipe) | A v2 TRX whose fourth partition holds code, or Broadcom's 36-byte `BCMTRXV2` header: a first partition at 0x24 gets a note with the unread fifth offset |
| R4 | `mktplinkfw` images always have the kernel at 0x200 (`fill_header` writes `sizeof(struct fw_header)`) | Stock TP-Link images with a bootloader before the kernel (not recognized under this rule) |
| R5 | A `mktplinkfw2` bootloader image's root filesystem offset is relative to the second header (`prepend_bootloader` keeps the inner image's fields; the tool's own comment is unsure) | Extract such an image with `mktplinkfw2 -i -x` and compare the root filesystem it writes |
| R6 | SafeLoader factory images end with their last partition | Stock TP-Link factory images with data between the last partition and the declared size |
| R7 | TP-Link structure is specific enough without the MD5 | A scan of 54,590 local files (439 MB: the repository's `testbins`, `test_binaries` and `tests/fixtures`, plus a local object and raw-code corpus) on 2026-10-13 found router layouts only in the seven router fixtures; vendor firmware was not scanned |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| TP-Link bootloader salts | Taken from firmware-utils `0179ab1e` source; no fixture with a bootloader exercises them |
| Broadcom 36-byte TRX v2 header (`TRX_V2_MAX_OFFSETS 5`) | A first partition at 0x24 gets a note; the fifth offset is not read and its bytes stay in the fourth partition; its CRC convention is not established |
| ASUS TRX tail (`asustrx`) | The CRC to the end of the file is accepted; the 64-byte tail (version, product ID) is not parsed |
| Alternate TRX magics (`brcm,trx-magic`, `trx -M`) | Not recognized |
| OpenWrt sysupgrade metadata (`append-metadata`, fwtool trailer) | Not a TP-Link or CHK structure: the bytes after the image are not fill, so a TP-Link sysupgrade image is not recognized and a CHK with a trailer is a parse error; TRX lists the trailer only if it is a recognized format |
| SafeLoader `?NEW` (QNEW) header | Not recognized: upstream calls the format "not understood" and the size and MD5 semantics are not established |
| SafeLoader sysupgrade images | Raw flash ranges without this header; not recognized |
| TP-Link `mktplinkfw` bootloader fields | Reported in a note; `mktplinkfw` never writes a bootloader, so where one is stored is not established and nothing is extracted |
| Netgear DNI headers (`mkdniimg.c`) and other TP-Link generators | Not implemented |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`),
`cargo test --all-features --locked` passed: 553 tests, 6 ignored (the
existing ignores that need external data), including `tests/router.rs`
(26 tests) and 27 unit tests in `src/formats/router*`, with every-prefix
truncation sweeps and every-byte mutation sweeps (all three mutations on
header bytes, one on payload bytes) over the seven committed wrappers.
After `./build-web.sh`, `web/tests/router.test.mjs` passed 4 of 4
(`/pkg/zrax.js`, `/dist/zrax.js`, `/web/index.html` and
`/dist/index.html`). The full browser suite (`npm test`) passed 73 of 77
with 4 skips (D10/RX113 firmware not in the repository). Two earlier full
runs under heavy machine load each had one timing failure in
`workbench.test.mjs`, a different entropy-map test each time. Rerun alone,
`detail refinement ...` passed, and `failed architecture classification
retains entropy and hex inspection` passed 10 of 11 runs on this branch and
7 of 8 on the base commit.

The fixtures are synthetic ([fixture provenance](../tests/fixtures/router/README.md)).
The TRX, CHK and SEAMA fixtures are byte-identical to what the upstream
firmware-utils tools write from the same parts, the TP-Link MD5s pass the
upstream inspectors, and the SafeLoader image extracts with
`tplink-safeloader -x`. No vendor firmware was parsed; behavior on real
vendor images is not verified.
