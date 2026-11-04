# SoC boot ROM images: Allwinner, Rockchip, MediaTek, Qualcomm

`src/formats/socboot2.rs` and its submodules (`egon.rs`, `rockchip.rs`,
`mediatek.rs`, `qualcomm.rs`) parse the images that system-on-chip boot ROMs
load: Allwinner `eGON.BT0` and TOC0, Rockchip RKFW, RKAF, RKBOOT and
idbloaders, MediaTek preloaders, legacy Qualcomm MBN headers, and Qualcomm
SBL ELF images after a NAND preamble. They are
built on the shared container model
([compressed streams and the container model](compressed-streams.md)): the
boot image is reported as the format, and the code it carries is classified
from its own bytes. Only three fields name an instruction set; everywhere
else the code model answers from the extracted code.

## Implemented layouts

| JSON format ID | Layout (variant) | Recognition and checks | Architecture evidence | Primary source |
| --- | --- | --- | --- | --- |
| `allwinneregon` | `eGON.BT0 boot image` | Strong: `eGON.BT0` at offset 4. Length a multiple of 4 B covering the 96 B header and inside the file; stamp checksum over `[0, length)` verified (a mismatch is a parse error); U-Boot SPL header version and device tree name; data after the image listed when it is a recognized format | The jump word at 0: A32 `B` (top byte `0xEA`) gives Arm, 32-bit, little-endian; RISC-V `JAL x0` (low 12 bits `0x06F`) gives RISC-V 64-bit (XLEN assumed). The target must lie inside the image past the 20 shared header bytes, otherwise no ISA is claimed and the code model classifies the image | U-Boot `5e3b01c8` `include/sunxi_image.h`, `tools/sunxi_egon.c`; sunxi-tools `bc96c0ae` `fel.c` |
| `allwinneregon` | `TOC0 secure boot image` | Strong: `TOC0.GLH` and magic `0x89119800`. Checks in the order of `toc0_verify`: length inside the file, name and magic, stamp checksum, length a multiple of 512 B, `MIE;` end marker; item count bounded by the image | None. Items (certificate, firmware, key) are opaque | U-Boot `5e3b01c8` `include/sunxi_image.h`, `tools/sunxi_toc0.c` |
| `rockchipimage` | `RKFW update image` | Strong: `RKFW`. Loader (`BOOT` or `LDR `) and RKAF ranges inside the file; optional 32-character lowercase hex MD5 trailer (not verified); only erased flash after it | None: the chip code names a chip family. The loader and the RKAF package are classified on their own | rockchip-mkbootimg `23486905` `rkrom.h`, `img_maker.c`; rkflashtool `fc2181c5` `rkunpack.c` |
| `rockchipimage` | `RKAF firmware package` | Strong: `RKAF`. RKCRC (MSB-first polynomial `0x04C10DB7`) at `length` verified; at most 16 parts, each inside the package; `SELF` and empty parts skipped | None. Each part is a child: `PARM` wrappers, the `parameter` part and text parts are opaque; `KRNL` wrappers yield their contents | rockchip-mkbootimg `23486905` `rkafp.h`, `rkcrc.h`, `afptool.c`; rkflashtool `fc2181c5` `rkcrc.c` |
| `rockchipimage` | `RKBOOT loader` | Strong: `BOOT` and header size `0x66`. Three entry tables (0x471, 0x472, loader) with 57 B or larger entries of the right type; every entry inside the file; RKCRC after the last table or entry verified | None. Entries are RC4-descrambled (0x471/0x472 as one stream, loader entries per 512 B block) and classified on their own | rockchip-linux U-Boot `1c535d65` `tools/rockchip/boot_merger.[ch]` |
| `rockchipimage` | `idbloader (header v1)` | Strong: the stored bytes `3B 8C DC FC` (RC4 of the magic `0x0FF0AA55`). Header descrambled as one 512 B block; init and boot stages in 512 B blocks inside the file; stages descrambled per block unless `disable_rc4` is set; the chip tag (`RK33`, ...) noted | None: the chip tag names a chip family | U-Boot `5e3b01c8` `tools/rkcommon.c` |
| `rockchipimage` | `idbloader (header v2)` | Strong: `RKNS`. One to four images in sectors inside the file; SHA-256 or SHA-512 header and image hashes checked when `boot_flag` names them; a mismatch is a note, since the header field may hold a signature | None | U-Boot `5e3b01c8` `tools/rkcommon.c` |
| `mediatekpreloader` | `EMMC_BOOT preloader`, `SF_BOOT preloader`, `SDMMC_BOOT preloader`, `UFS_BOOT preloader` | Strong: the NUL-padded device name (`UFS_BOOT` on its 8 characters). Device header version 1; BRLYT at the header's size field with name, version 1 and magic `BBBB`; NAND types rejected; then the GFH as below | As for the GFH | U-Boot `5e3b01c8` `tools/mtk_image.[ch]`; MediaTek `fbtool.c` (`c0779f00`); mtkclient `7cb40e72` |
| `mediatekpreloader` | `GFH preloader` | Strong: a `GFH_FILE_INFO` record at 0 (`MMM`, size `0x38`, type 0, `FILE_INFO`). File length at least jump offset plus signature, inside the file; GFH chain records inside the content offset; code from the jump offset to the signature; a SHA-256 hash (signature type 1, 32 B) checked over the image before it | `GFH_BROM_CFG` with `cfg_bits & 0x1000` and `jump_bl_arm64 == 0x64` gives AArch64 for the container and the code child; otherwise no ISA is claimed and the code model classifies the code | U-Boot `5e3b01c8` `tools/mtk_image.[ch]`; MediaTek `fbtool.c` (`strip_pl_hdr`) |
| `mediatekimage` | `MediaTek partition image` | Strong: `mtk_hdr` magic `0x58881688` (little-endian) at 0. Each 512 B header: nonzero payload size, payload inside the file; with the extension magic `0x58891689` at 0x30, header size 512 (0x34) and a power-of-two alignment up to 4 KiB (0x44) that places the next header. Headers chain while the next one starts with the magic, at most 16; padding after the last payload is skipped and other bytes are an opaque `Trailing data` member | None: the header names no processor; each payload is a member classified from its own bytes | Magisk `native/src/boot/bootimg.hpp` (`mtk_hdr`); extension fields from fw1 images (S15) |
| `qualcommmbn` | `SBL MBN (80-byte header)` | Strong: codeword `0x844BDCD1` and magic `0x73D71034` at 0; a virtual block cookie at 0 is a parse error. A NAND preamble (autodetect magic in the third word) is skipped by finding the first 512 B boundary that holds an SBL header (codeword and magic, and a third word that is neither an autodetect magic nor the cookie magic `0xD48B54C6`); `image_src` (the file offset of the code) must lie past the header; code inside the file; signature and certificate chain listed as opaque when the pointers place them after the code | `booting_image_config` `0xF` gives AArch64 (little-endian), `0x0` gives AArch32 (byte order from the code); `0xFFFFFFFF` or other values claim nothing | coreboot `99a3e1e8` `util/qualcomm/mbn_tools.py`, `mbncat.py` |
| `qualcommmbn` | `SBL ELF (NAND preamble)` | Strong: codeword and magic at 0 with a NAND preamble, and the ELF magic on the first 512 B boundary that holds an SBL header or an ELF image. Virtual block cookies (codeword, magic, `0xD48B54C6`; 12 B) are removed at each 128 KiB file boundary after the ELF start while present (S12, S13); the ELF's extent (ELF header, program header table, segment file ranges, section header table) must lie inside the run of cookies. Cookies and erased flash after the ELF up to the end of the run belong to the image | None from the preamble. The rebuilt ELF image is a child, classified by its `e_machine` | coreboot `99a3e1e8` `util/qualcomm/mbn_tools.py` (`image_preamble`, `insert_SBL1_magicCookie`, `VIRTUAL_BLOCK_SIZE`, `MAGIC_COOKIE_LENGTH`, `SBL_VIRTUAL_BLOCK_MAGIC_NUM`); cookie placement from a vendor image (see source conflicts) |
| `qualcommmbn` | `MBN (40-byte header)` | Weak (no magic): version 3, a known image ID, nonzero code, image size equal to code plus signature plus certificate chain rounded up to 4 B, signature and certificate pointers directly after the code, the whole image present and only erased flash after it | None: the image ID names a boot role. The code at 0x28 goes to the code model | coreboot `99a3e1e8` `util/qualcomm/mbn_tools.py`, `ipqheader.py` |

Pinned URLs have the form `https://github.com/<repository>/blob/<revision>/<path>`;
the full revisions are in the module documentation of `socboot2.rs`.

## Detection order

The magic-bearing layouts are checked in one block right before the
magic-bearing compressed streams, after the executable and firmware formats.
None of their magics collides with an earlier format. The 40-byte MBN header
is checked with the other structure-only layouts, right before zlib and
LZMA-alone, and is recognized only from a complete image, so a prefix of it
(as `container::is_recognized` sees it) is not recognized.

## Wire units and byte order

Every header is little-endian, and all offsets and sizes are bytes except:
Rockchip idbloader fields count 512-byte blocks (v1) or sectors (v2), and the
idbloader v2 hash offset counts 4-byte words. MediaTek BRLYT addresses are
bytes on eMMC, NOR and SD; NAND layouts use pages and are rejected. Allwinner
images carry no load address, so the eGON section address is the image
offset; the TOC0 firmware load address, the MediaTek GFH load address and
code entry (`load_addr + jump_offset`) and the Qualcomm destination address
are reported as metadata or as the entry point. Header byte order is never
reported as code byte order: A32 and RISC-V jump words are fetched
little-endian, AArch64 is always little-endian, and the AArch32 SBL byte
order comes from the code. Virtual block cookie positions are file offsets
counted from the start of the NAND preamble, not from the ELF image.

## Validation and resource bounds

- eGON and TOC0 checksums and RKAF and RKBOOT CRCs must match; a mismatch is
  a parse error.
- RKBOOT entry counts are single bytes (at most 255 per table). Each
  descrambled entry is at most 64 MiB (`MAX_PAYLOAD`) and all of them
  together at most 256 MiB (`container::MAX_EXTRACTED`); entries beyond that
  stay opaque and a note says how many.
- RKAF lists at most 16 parts, idbloader v2 at most 4 images. The TOC0 item
  count must fit the checksummed image. GFH records are at least 8 B and lie
  inside the content offset, so the record walk is bounded by the file.
- The SBL header or ELF image after a NAND preamble is searched for at 512 B
  steps up to 1 MiB (2048 candidates).
- Virtual block cookies are followed through at most 64 MiB (`MAX_PAYLOAD`)
  of the file from the ELF start, so at most 512 cookies, and the rebuilt ELF
  is one copy of at most that size. An ELF image that needs more is a parse
  error (`Unsupported`); one that needs bytes past a 128 KiB boundary without
  a cookie is a parse error (`Missing SBL virtual block cookie`).
- The eGON device tree name is read up to 64 B and only as printable ASCII.
- Trailing bytes after an RKFW, RKAF, RKBOOT or 40-byte MBN image must be
  erased flash (`0x00`/`0xFF`). After an eGON, TOC0, idbloader, MediaTek,
  SBL or SBL ELF image, non-padding data is listed as a member only when it
  is a recognized format (U-Boot proper after an SPL).
- Container nesting (RKFW, RKAF, RKBOOT inside one another) is capped at six
  levels by `lib.rs`.

## Source conflicts resolved here

The spec notes for this family said that RKBOOT entries are RC4-scrambled in
512-byte chunks "when RC4 is enabled". `boot_merger.c` at the pinned revision
(read on 2026-10-12) shows otherwise: `writeFile` applies `P_RC4` to every
entry, 0x471/0x472 entries as one stream over the size padded to 2048 B and
loader entries per 512-byte block, and `unpackEntry` reverses it without
reading `rc4Flag`. `getBoothdr` sets `rc4Flag = 1` when RC4 is disabled,
which only governs the ID block that flashing tools build. The parser follows
the source.

coreboot's `insert_SBL1_magicCookie` (pinned revision, read on 2026-11-02)
appends a cookie after every 128 KiB of its input, so in its output the k-th
cookie sits at k × 128 KiB + (k − 1) × 12 B. A vendor-built NAND SBL ELF
image (32-bit Arm, a small preamble with the ELF at 0x2800, five cookies;
examined on 2026-11-02, not in the repository) has its cookies at exact
multiples of 128 KiB of the file instead: each block after the first starts
with the cookie and holds the next 128 KiB − 12 B of the image. With those
12-byte runs removed, all seven non-empty segments other than the hash
segment match their SHA-384 digests in the hash segment; with them left in,
only the first segment (which ends before 0x20000) does. The parser follows
the image. The generator's placement is a parse error at the second
boundary, which a test pins.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| S1 | An A32 `B` jump word means the boot ROM enters in AArch32; a 64-bit SoC's SPL may switch to AArch64 (U-Boot's sun50i polyglot `tst x0, x0` is `b #0x84` in A32) | AArch64 code behind an A32 jump: the container still reports Arm and the code model's AArch64 answer appears as a warning |
| S2 | A RISC-V `JAL x0` jump does not encode XLEN; 64-bit is assumed, as for the RISC-V `Image` header (kernel images, K5) | An RV32 eGON image would be reported as RISC-V 64-bit; no RV32 eGON image was available |
| S3 | RKBOOT entries are always scrambled, with the stream/block split above | Descrambled 0x471 and loader entries of a `boot_merger` loader classify as code; plain entries would come out as noise and the code model would be inconclusive |
| S4 | The idbloader v1 header is always scrambled; the stages are scrambled exactly when `disable_rc4` is 0 | The descrambled init stage starts with an ASCII chip tag; otherwise a note says so (also the case for SPI images, whose 2-of-4 KiB layout is not de-interleaved) |
| S5 | A MediaTek `GFH_BROM_CFG` without the AArch64 hand-off does not establish AArch32 (UNCONFIRMED in the sources) | The code model decides; disagreeing hand-off fields claim nothing |
| S6 | `UFS_BOOT` uses the generic device header (only its name is confirmed) | A UFS image with another header layout fails the BRLYT or GFH checks and becomes a parse error |
| S7 | The BRLYT GFH addresses at 0x0C and 0x1C are equal (U-Boot writes both); when they differ, the first that holds a `GFH_FILE_INFO` (0x1C first, as `fbtool.c` reads it) is used | A note reports differing addresses |
| S8 | A SHA-256 signature field (type 1, 32 B) covers `[GFH, end - 32)` as U-Boot's `put_hash` writes it | MediaTek-built images were not tested; a mismatch is reported as not verified, not as an error |
| S9 | Qualcomm code, signature and certificate chain are stored back to back, as the writer's pointers say | Non-contiguous pointers: the signature and certificates are not listed and a note says so; the 40-byte header is then not recognized at all |
| S10 | The SBL `image_src` is the file offset of the code (80, or 80 plus the preamble size) | The preamble fixture; an `image_src` inside the header is a parse error |
| S11 | idbloader v2 image hashes cover the sector-padded image range | A mismatch is a note, not an error |
| S12 | Qualcomm virtual block cookies sit at every 128 KiB boundary of the file, counted from the preamble, as in the one image examined, not where the generator puts them | A cookie missing inside the ELF's extent is a parse error naming the boundary; the generator's placement fails at 0x40000. The hash segment digests would confirm a rebuild, but the parser does not check them |
| S13 | An ELF after a NAND preamble with no cookie at the first 128 KiB boundary past its start carries no cookies | Cookies placed elsewhere (counted from the ELF start, say) would stay inside the ELF bytes; only the unchecked hash segment digests would show it |
| S14 | An ELF image's file extent is the furthest end of its header tables and segment ranges; section contents outside every segment lie before the section header table | An ELF with section contents after its section header table would be cut short, and the rest reported as trailing data |
| S15 | The `mtk_hdr` extension (magic `0x58891689` at 0x30) holds the header size at 0x34 and the payload alignment at 0x44; these offsets come from 18 fw1 images (header size 512 and alignment 16 in all), not from a published layout | An image whose next header is not at the aligned payload end: the walk stops and the rest becomes `Trailing data` |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Allwinner TOC1, `eGON.BT1`, `eGON.BRM` | Not recognized: no layout in the sources read |
| TOC0 items | Opaque; certificate signatures and the firmware digest are not verified, and whether items are encrypted is not established |
| Rockchip `LDR ` loaders inside RKFW | Listed as opaque; the layout was not found in the sources read |
| Rockchip `RKFP`, idbloader SPI layout | `RKFP` is not recognized; SPI idbloaders (2 KiB of every 4 KiB) are not de-interleaved |
| RKFW MD5 trailer, RKBOOT sign flag, idbloader v2 signatures | Reported as present and not verified |
| MediaTek NAND and SPI-NAND layouts | BRLYT types `0x10002` and `0x10009` are a parse error (`Unsupported`): their addresses are pages, and the NAND device header was not read |
| MediaTek signed preloaders | Signature types other than 0 and 1 are listed as opaque and not verified; the GFH file-type and signature-type tables beyond those values are UNCONFIRMED and not interpreted |
| `MTK_BLOADER_INFO`; MediaTek partition header fields other than size, name, header size and alignment | `MTK_BLOADER_INFO` is not recognized; the load address, mode, image type and list-end fields of `mtk_hdr` are not interpreted |
| Qualcomm MBN versions 5, 6 and 7 as standalone files | Not recognized: words 2 and 3 are QTI sizes rather than pointers; modern images are ELF and classified by `e_machine` |
| Qualcomm pointers at or above 2^32 | The writer clamps them to `0xFFFFFFFF`; such 40-byte headers fail the pointer checks and are not recognized |
| IPQ8064 combined SBL (`mbncat.py`) | Parsed as an SBL whose code is the concatenated MBNs; the first contained header is classified as a nested container |
| Qualcomm SBL ELF hash segment | Segment digests, signature and certificate chain are not verified; a note says so |
| Qualcomm virtual block cookies in an 80-byte SBL image | Not removed: code that spans a 128 KiB boundary keeps the cookie bytes. No such image was available |
| Qualcomm ELF images with cookies but no preamble | The file starts with the ELF magic and is classified as a plain ELF by `e_machine`; cookies are not removed |
| Qualcomm cookie placement of `insert_SBL1_magicCookie` | Not implemented (S12): a parse error at the second boundary |

## Verification

On 2026-10-12 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`, Node
v25.8.1, Playwright Chromium), `tests/socboot2.rs` (18 tests) and the 14 unit
tests in `src/formats/socboot2*` passed, including every-prefix truncation
sweeps and every-byte `0x00`/`0xFF`/bit-flip mutation sweeps over small
instances of all eleven layouts. `web/tests/socboot2.test.mjs` (4 tests)
passed through `/pkg/zrax.js`, `/dist/zrax.js`, `/web/index.html` and
`/dist/index.html`. The whole native suite (`cargo test --all-features
--locked`) passed with 508 tests and 6 ignored (pre-existing: five in
`src/extensions` and the D10 test that needs external fixtures). All fixtures are synthetic: the containers are built
by the tests from the documented layouts around clang-generated A32, AArch64
and RV64 code (`tests/fixtures/socboot2/README.md`). No vendor-built image of
any of these formats was tested, so behavior on vendor images, including
Allwinner's own boot0 header, MediaTek-built preloaders and Rockchip loaders
from Rockchip's tools, is not verified.

On 2026-11-03 (macOS AArch64, rustc 1.99.1 `58cf8f9c3`, Node v25.8.1,
Playwright Chromium), after adding the SBL ELF layout: `tests/socboot2.rs`
(25 tests), the 19 unit tests in `src/formats/socboot2*` and the 4
`file_extent` unit tests in `src/formats/elf.rs` passed. The every-prefix and
every-byte mutation sweeps now include a small SBL ELF instance, and a
bounded sweep covers an instance with three cookies (cuts around the ELF
start and every cookie and every 4093 B; mutations of the ELF and program
headers and of every cookie byte). The whole native suite passed with 2940
tests and 7 ignored (also 7 ignored on the base commit).
`web/tests/socboot2.test.mjs` (4 tests, now with an SBL ELF fixture) passed;
the whole browser suite ran 397 tests with 393 passed and 4 skipped (they
need D10 and RX113 firmware that is not in the repository). A differential
snapshot of the 80-byte SBL and 40-byte MBN paths over 52,543 inputs (seven
fixtures, every truncation, every single-byte `0x00`/`0xFF`/bit-flip
mutation) matched the base commit except for the renamed message
`Missing SBL header or ELF image after the NAND preamble`. The vendor image
described under source conflicts classifies as an Arm ELF image inside an
`SBL ELF (NAND preamble)` container; its rebuilt ELF is byte-identical to an
independently stripped copy whose segments match the hash segment digests.
No other vendor-built SBL ELF image was tested.
