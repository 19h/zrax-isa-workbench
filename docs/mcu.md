# MCU update images

`src/formats/mcu.rs` and its submodules parse four microcontroller update
formats into the shared container model
([compressed streams and the container model](compressed-streams.md)): UF2
block files, STM32 DfuSe files, Silicon Labs Gecko Bootloader (GBL v3) files
and Cypress/Infineon `.cyacd`/`.cyacd2` text. Only UF2 names a target, through
its family ID. The other three formats carry USB IDs, product IDs or silicon
IDs, which identify a device, not an instruction set, so their payloads go to
the code model.

## Implemented layouts

| JSON format ID | Layout (variant) | Recognition | Architecture evidence | Primary source |
| --- | --- | --- | --- | --- |
| `uf2` | `UF2 block file`: 512-byte blocks; flags `0x1` (not main flash, skipped), `0x1000` (file container, named files), `0x2000` (family ID), `0x4000` (MD5 record), `0x8000` (extension tags); payload at most 476 B (452 B with MD5); `blockNo`/`numBlocks` runs; flash blocks reassembled by `targetAddr` | Strong: `magicStart0` `0x0A324655` and `magicStart1` `0x9E5D5157` at 0; every block must also carry `magicEnd` `0x0AB16F30` at 508 | `familyID` is the format's target field ("board family ID"; a bootloader "should disregard the entire block" of another family). The 78 IDs of `uf2families.json` map to the application core's ISA (table below). Without a family ID, the code model decides | [microsoft/uf2 `README.md`](https://github.com/microsoft/uf2/blob/90e9741f217f5a40c98ba74d663e408041037578/README.md) and `utils/uf2families.json` at `90e9741f`; pico-sdk 2.1.1 `boot/uf2.h`; RP2350 datasheet (build `80d627281ed5`), section 5.5, Table 469 and erratum RP2350-E10 |
| `dfuse` | `DfuSe 1.1a file`: 11-byte prefix, `bTargets` target prefixes (274 B) with address/size elements, 16-byte DFU suffix; every element is a load section | Strong: `DfuSe` at 0 | None. `idVendor`/`idProduct`/`bcdDevice` are metadata; the code model decides | dfu-util v0.11 `src/dfuse.c`, `src/dfu_file.c`; MicroPython v1.24.0 `tools/pydfu.py`, `tools/dfu.py`; [USB DFU 1.1](https://www.usb.org/sites/default/files/DFU_1.1.pdf), Appendix B. ST UM0391 was not available |
| `gbl` | `GBL v3 file`: little-endian tag stream from the header tag to the end tag; tag order and single-occurrence rules of the reference parser; program, erase-and-program, program LZ4 and program LZMA tags are load sections | Strong: header tag `0x03A617EB` at 0 | None. Gecko bootloaders run on EFR32/EFM32 parts, but a vendor is not evidence (AGENTS.md 3.1); the code model decides | gecko_sdk v4.5.1 (`8a2efd2c`) `platform/bootloader/parser/gbl/btl_gbl_format.h`, `btl_gbl_format.c`, `btl_gbl_parser.c`; simplicity_sdk v2025.6.3 (`8ddb6e57`) for the delta tags; Silicon Labs "Gecko Bootloader File Format" (docs.silabs.com) |
| `cyacd` | `.cyacd bootloadable`: 12-hex-digit header (silicon ID, revision, checksum type), `:` rows of array ID, row number, length, data and checksum | Weak: no magic. The header and every row must parse and every row checksum must match | None. The silicon ID names a device; the code model decides | Cypress Bootloader Host `cybtldr_parse.c`, `cybtldr_api2.c` (2011-2012, as mirrored in SCSI2SD `7ae322c1`); cyflash `cyacd.py` (`6d742d67`) |
| `cyacd` | `.cyacd2 DFU image`: 24-hex-digit header starting with file version `01` (silicon ID, revision, checksum type, app ID, product ID), `@APPINFO`/`@EIV` rows, `:` rows of byte address and data | Weak: as above; rows carry no checksum | None. Silicon and product IDs are metadata | Infineon AN213924 rev *H, ".cyacd2 file format"; Infineon `mtb-example-psoc4-dfu-host` (`65115d86`) `source/cybtldr_parse.c` |

### UF2 family table

`FAMILIES` in `src/formats/mcu/uf2.rs` holds all 78 entries of
`uf2families.json` at the pinned commit (SHA-256 `9d8f561e…c194`; checked
against a fresh download on 2026-10-12), each with its short name,
description and target. The core assignments are not part of the UF2
specification; they come from the vendor documents collected in the format
research notes, with the evidence class given below (V: vendor page or
datasheet; P: primary document read; S: secondary source; U: not
established from a source).

| Target | Families | Evidence |
| --- | --- | --- |
| `arm`, 32-bit, little-endian | SAML21, NRF52, STM32L1, STM32L0, STM32WL, RTL8710B, LPC55, STM32G0, GD32F350, RTL8720D, STM32L5, STM32G4, MIMXRT10XX, XR809, STM32F7, SAMD51, STM32F4, STM32F2, STM32F1, NRF52833, STM32F0, BK7231U, SAMD21, STM32F3, STM32F407, STM32H5, STM32H7, STM32WB, BK7231N, STM32F407VG, RTL8710A, NRF52840, NRF52820, RTL8720C, RP2040, RP2350_ARM_S, RP2350_ARM_NS, STM32L4, RZA1LU, STM32F411xE, STM32F411xC, NRF52832xxAA, NRF52832xxAB, AT32F415, RA4M1, MAX32690, MAX32650, MAX32666, MAX78002, PY32F071-UVK5-V3 | V or P for most; S for GD32F350, XR809, RTL8710A, AT32F415, PY32F071; U for STM32L1 (Cortex-M3) and RP2040 (Cortex-M0+), both kept as Arm. BK7231U/N are ARM968E-S (A32 and Thumb), RZA1LU is Cortex-A9; all others are M-profile |
| `xtensa`, 32-bit, little-endian | ESP32, ESP8266, ESP32S2, ESP32S3 | V |
| `risc_v32`, 32-bit, little-endian | ESP32C3, ESP32C2, ESP32H2, ESP32C6, ESP32P4, ESP32C5, ESP32C61, ESP32H21, ESP32H4, ESP32S31, BL602, RP2350_RISCV, GD32VF103, M0SENSE, MaixPlay-U4, CH32V | V or P; S for M0SENSE, MaixPlay-U4, CH32V. ESP32S31 is RISC-V despite its prefix (P) |
| `avr`, 8-bit, little-endian | ATMEGA32 | U (the part name is an AVR) |
| `i8051`, 8-bit, big-endian | FX2 | V |
| none (code model) | BK7251, KL32L2, CSK4 (core not established); CSK6 (Arm core plus a Cadence HiFi4 DSP); RP2XXX_ABSOLUTE (content for any RP2 core) | U or S |
| none, opaque | RP2XXX_DATA (data partition download) | P |

Families with a coprocessor of another ISA (MAX32690 and MAX78002 RISC-V
coprocessors, the ESP32-S2/S3 ULP) map to the application core that the UF2
bootloader programs. An unlisted family ID names no ISA. RP2350 Arm and
RISC-V images have distinct IDs, so the same chip yields `arm` or `risc_v32`
from the field alone.

## Reassembly and components

- UF2 blocks are independent. Flash blocks (no `0x1`, no `0x1000`, not
  ignored) are grouped by family ID; within a group, any two blocks that
  write the same byte are an error (`Duplicate`/`Overlapping UF2 blocks`).
  Consecutive blocks whose addresses continue each other form one load
  section (`UF2 blocks` transform, stored range from the first block to the
  end of the last); a single-block section is the stored payload. Address
  gaps are never materialized: the analyzed payload is the sections
  concatenated.
- A UF2 file with one family reports its family's target on the container.
  A file with several families (concatenated per-family files) yields one
  child per family, labelled with the family's short name and description,
  each with its own target and its own classification.
- UF2 file-container blocks are grouped by file name and `fileSize`; a file
  whose blocks cover `0..fileSize` exactly once becomes a child (`UF2 file
  container` transform) listed only when its bytes are a recognized format.
- picotool's RP2350-E10 workaround block (one `RP2XXX_ABSOLUTE` block
  numbered 0 of 2) and blocks tagged `UF2_EXTENSION_RP2_IGNORE_BLOCK` are
  noted and left out of the image.
- DfuSe elements are load sections in file order at their element
  addresses, labelled `Target <alternate> element <n>`.
- GBL plaintext program tags are load sections at `flashStartAddress`.
  Program LZ4 tags hold a raw LZ4 block stream (no frame), decoded by the new
  `compressed::Codec::Lz4Block`; program LZMA tags hold an LZMA-alone stream,
  decoded by `Codec::Lzma`. A compressed tag that does not decode is listed
  as an opaque component with a note. The bootloader tag's image is a child
  classified on its own. SE upgrade, metadata, delta and encrypted-data tags
  are opaque children. Certificate and signature tags are noted as present
  and not verified.
- `.cyacd` rows of one array with consecutive row numbers and equal length
  merge into one section labelled `Array <id> rows <first>-<last>`;
  `.cyacd2` rows on consecutive lines with contiguous byte addresses merge
  into one section. Both carry the `ASCII hex` transform; stored ranges are
  the row text.

## Wire units and byte order

All UF2, DfuSe and GBL integers are little-endian; all sizes are bytes.
UF2 `targetAddr` is a flash byte address (esptool writes flash offsets, and
RP2350 relocates non-absolute images into partitions), DfuSe element
addresses are byte addresses in the memory the alternate setting selects,
GBL `flashStartAddress` is a byte address. `.cyacd` silicon ID, row number
and data length are big-endian, and section addresses are flash row numbers
within the array (the row size and array base are not encoded, so they are
not converted to byte addresses). `.cyacd2` header fields and row addresses
are little-endian, and row addresses are byte addresses. Header byte order is
never reported as code byte order; a UF2 family target fixes the code byte
order of the family's core.

## Validation and resource bounds

| Check | Behavior |
| --- | --- |
| UF2 file size | A non-zero multiple of 512 B, else `Truncated UF2 block` |
| UF2 per block | All three magics; `payloadSize` at most 476 B (452 B with an MD5 record); `blockNo < numBlocks`; file container plus family ID or extension tags is `Ambiguous`; extension tags 4-byte aligned, sized at least 4 B and inside `data[]`; flags outside the five defined bits are noted and ignored |
| UF2 numbering | In file order, runs numbered `0..numBlocks` with one family and one `numBlocks` per run (esptool restarts per file, concatenated files restart per family); an incomplete run is `Missing UF2 blocks` except the E10 workaround |
| UF2 MD5 records and SHA-2 tags | Noted, not verified |
| DfuSe suffix | `UFD` signature, `bLength` at least 16 B, CRC-32 register (initial `0xFFFFFFFF`, no final inversion) over every byte but the last four, `bcdDFU` `0x011A`; checked before the targets |
| DfuSe targets | `bVersion` 1; `Target` signature; `dwTargetSize` inside the file; `dwNbElements` at most `dwTargetSize / 8`; element sizes must fill `dwTargetSize` exactly; nothing may follow the last target; a `DFUImageSize` that differs from the size before the suffix is noted |
| GBL tags | Header tag first, length 8, `version` major `0x03`; every tag inside the file; unknown tags rejected; tag order and single occurrence as in `btl_gbl_format.c` (the SE upgrade tag at order 3 or 6); fixed-size tags checked (encryption init 16 B, certificate 136 B, signature 64 B, application info 28-64 B, version dependencies a multiple of 8 B) |
| GBL encryption | With header type bit `0x1`, any tag other than the always-plaintext tags is an error, and the container is opaque |
| GBL end tag | Length 4; `gblCrc` equals the zlib CRC-32 of every byte before it (the reference parser's residue `0xDEBB20E3`); only `0x00`/`0xFF` padding may follow |
| `.cyacd` | Printable ASCII lines ending in LF or CRLF, no empty lines, even hex digit counts; header exactly 12 digits with checksum type 0 or 1; rows `N + 6` bytes, `N > 0`, checksum the two's complement of the 8-bit byte sum; no repeated (array, row) pair; at least one row |
| `.cyacd2` | Header exactly 24 digits, file version 1, checksum type 0 or 1; rows more than 4 bytes; no overlapping byte ranges; `@APPINFO:0x<start>,0x<length>` (at most 8 digits each) and `@EIV:<hex>` at most once each; unknown `@` rows rejected |
| Payload and components | Load sections and decoded data at most 64 MiB (`MAX_PAYLOAD`); load sections and UF2 per-family regions capped at 4096 (`MAX_COMPONENTS`), the rest counted in a note; GBL children capped at 4096 |

The `.cyacd` header's checksum type selects the checksum of the bootloader's
command packets (type 0: 16-bit two's complement of the byte sum; type 1:
CRC-16 with reflected polynomial `0x8408`), which the host computes per packet
(`CyBtldr_ComputeChecksum`). No packet checksum is stored in the file, so the
type is reported as `cyacd_packet_checksum` and not verified; the stored row
checksum is the one-byte sum whatever the type.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| M1 | A UF2 family ID names the ISA of the family's application core | A UF2 for a coprocessor (MAX32690 RISC-V, ESP32-S3 ULP) under the main family ID would classify against the field; the code model's disagreement is reported as a warning (`uf2_rp2350_riscv_and_esp32s3_family_ids_name_their_own_isas`) |
| M2 | The family-to-core rows marked S or U in the table are right | Check each against the vendor datasheet; a wrong row would show as a field/code-model warning on real files |
| M3 | UF2 blocks of one run appear in file order | `uf2conv.py` and esptool write sequentially; an out-of-order file is rejected as `Invalid UF2 blockNo` |
| M4 | UF2 tag size counts the 4-byte header but not the padding to the next tag | README example (`0x09` for `0.1.2`), parsed in `extension_tags_skip_padding_and_stop_at_the_zero_word`; a MakeCode or picotool file with tags would confirm |
| M5 | Real UF2 files set only the five defined flags | Undefined bits are noted and ignored; a file that uses a new flag to change payload meaning would be misread |
| M6 | DfuSe `bTargetNamed` is a 32-bit boolean | pydfu reads 4 bytes, dfu-util tests byte 7; a file with a flag only in a high byte would differ |
| M7 | `gblCrc` equals the zlib CRC-32 of the preceding bytes | Derived from the residue `0xDEBB20E3`; compute on a GBL from Simplicity Commander (not available here) |
| M8 | GBL tags have no padding between them and nothing but erased flash after the end tag | The reference parser streams `8 + length` bytes per tag; walk a Commander-generated GBL |
| M9 | GBL program LZ4 tags hold one standard LZ4 block stream | `btl_decompress_lz4.c` starts in the token state; a Commander LZ4 GBL that does not decode would be listed as opaque with a note |
| M10 | A non-empty `@EIV` row means the `.cyacd2` data rows are encrypted | Generate `.cyacd2` with and without encryption in cymcuelftool |
| M11 | `.cyacd` headers are exactly 6 bytes | cyflash requires 6; the Cypress host accepts 5; a 10-digit header would not be recognized |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| UF2 MD5 records, SHA-2 tags | Reported as present and not verified |
| GBL ECDSA signatures and certificates | Reported as present and not verified |
| GBL AES-CCM encryption | Opaque; the key is a device token, not in the file |
| GBL delta tags, SE upgrade images, metadata tags | Opaque children |
| GBL encryption header tag `0xFB0505FB` | Rejected as unknown, as in the v4.5.1 reference parser |
| GBL with a bootloader tag and program data | Children are classified before load sections (`classify_container`), so the bootloader image supplies the primary ISA and the program data is not classified separately |
| UF2 file containers alongside flash blocks without a family ID | A recognized contained file supplies the primary ISA before the flash sections, for the same reason |
| `.cyacd` row size and array base | Not encoded; sections keep row numbers |
| `.cyacd`/`.cyacd2` truncation at a line boundary | Undetectable (no row count or end record); `.cyacd` rows cut inside are rejected by their length and checksum, `.cyacd2` rows have neither |
| `.cyacd`/`.cyacd2` comment lines (`#`) | Not accepted; support in the Infineon host is unclear |
| `.cyacd` silicon ID to device family | Not mapped; the encodings are not established from a primary source |
| Plain DFU 1.1 files (raw firmware plus suffix, no `DfuSe` prefix), TI Stellaris and NXP LPC DFU prefixes | Not recognized |
| DfuSe alternate settings | The memory each alternate setting selects (flash, option bytes, OTP) is not encoded, so all elements are load sections |
| Weak recognition from a prefix (`container::is_recognized`) | `.cyacd` text cut inside a row is not recognized, so archive members are only recognized whole |

## Verification

On 2026-10-12 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`
2026-09-05):

- `tests/mcu.rs`: 28 tests passed. They cover a positive case per layout,
  family-ID targets (RP2350 Arm, RP2350 RISC-V, ESP32-S3 Xtensa), the code
  model without a family ID, two families as two children with stored and
  decoded ranges, address gaps, duplicate/overlapping/missing blocks, the
  MD5 payload limit, file containers and not-main-flash blocks, RP2 data
  and E10 workaround blocks, extension tags, DfuSe suffix and element
  defects, GBL plain/LZ4/LZMA program tags, bootloader children,
  encryption, signatures, CRC/order/unknown-tag errors and trailing bytes,
  `.cyacd` checksums and packet checksum types, `.cyacd2` byte addresses,
  `@APPINFO` and `@EIV`, every-prefix truncation sweeps, and every-byte
  mutation sweeps (`0x00`, `0xFF`, bit flip) through detection, the parser
  and classification.
- Unit tests: 13 in `src/formats/mcu*` and 3 for the LZ4 block decoder
  (`src/formats/compressed/lz4_block.rs`), passed.
- `web/tests/mcu.test.mjs`: 4 tests passed (classification through
  `/pkg/zrax.js` and `/dist/zrax.js`; the workbench at `/web/` and
  `/dist/`).
- The whole native suite passed (520 tests, 6 ignored), and the whole
  browser suite passed (71 tests, 4 skipped for D10/RX113 firmware that is
  not in the repository).
- Cross-check, not committed: UF2 files written by `uf2conv.py` at the
  pinned commit (`-f RP2350_ARM_S`, `-f RP2350_RISCV`, `-f ESP32S3`, no
  family, and two families concatenated) and a DfuSe file written by
  MicroPython v1.24.0 `tools/dfu.py` from the committed code fixtures were
  recognized, their DFU CRC verified, and classified as `arm`, `risc_v32`
  and `xtensa` as the family IDs name.

All committed fixtures are synthetic: `tests/fixtures/mcu` holds machine code
compiled from `tests/fixtures/transforms/sample.c` (see its README), and the
containers are built in the tests from the documented layouts. GBL files
from Simplicity Commander, `.cyacd`/`.cyacd2` files from PSoC Creator or
cymcuelftool, and esptool or picotool UF2 files were not available, so the
behavior on those generators' output is not verified.
