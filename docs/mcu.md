# MCU update images

`src/formats/mcu.rs` and its submodules parse seven microcontroller update
formats into the shared container model
([compressed streams and the container model](compressed-streams.md)): UF2
block files, STM32 DfuSe files, Silicon Labs Gecko Bootloader (GBL v3) files,
Cypress/Infineon `.cyacd`/`.cyacd2` text, USB DFU files (any firmware followed
by the DFU suffix), Silicon Labs Ember bootloader (EBL) files and Nordic nRF5
DFU init packets. UF2 names a target through its family ID, and EBL through
the platform field of the application address table in its header. The other
formats carry USB IDs, product IDs, silicon IDs or hardware versions, which
identify a device, not an instruction set, so their payloads go to the code
model; Nordic init packets carry metadata only.

## Implemented layouts

| JSON format ID | Layout (variant) | Recognition | Architecture evidence | Primary source |
| --- | --- | --- | --- | --- |
| `uf2` | `UF2 block file`: 512-byte blocks; flags `0x1` (not main flash, skipped), `0x1000` (file container, named files), `0x2000` (family ID), `0x4000` (MD5 record), `0x8000` (extension tags); payload at most 476 B (452 B with MD5); `blockNo`/`numBlocks` runs; flash blocks reassembled by `targetAddr` | Strong: `magicStart0` `0x0A324655` and `magicStart1` `0x9E5D5157` at 0; every block must also carry `magicEnd` `0x0AB16F30` at 508 | `familyID` is the format's target field ("board family ID"; a bootloader "should disregard the entire block" of another family). The 78 IDs of `uf2families.json` map to the application core's ISA (table below). Without a family ID, the code model decides | [microsoft/uf2 `README.md`](https://github.com/microsoft/uf2/blob/90e9741f217f5a40c98ba74d663e408041037578/README.md) and `utils/uf2families.json` at `90e9741f`; pico-sdk 2.1.1 `boot/uf2.h`; RP2350 datasheet (build `80d627281ed5`), section 5.5, Table 469 and erratum RP2350-E10 |
| `dfuse` | `DfuSe 1.1a file`: 11-byte prefix, `bTargets` target prefixes (274 B) with address/size elements, 16-byte DFU suffix; every element is a load section | Strong: `DfuSe` at 0 | None. `idVendor`/`idProduct`/`bcdDevice` are metadata; the code model decides | dfu-util v0.11 `src/dfuse.c`, `src/dfu_file.c`; MicroPython v1.24.0 `tools/pydfu.py`, `tools/dfu.py`; [USB DFU 1.1](https://www.usb.org/sites/default/files/DFU_1.1.pdf), Appendix B. ST UM0391 was not available |
| `gbl` | `GBL v3 file`: little-endian tag stream from the header tag to the end tag; tag order and single-occurrence rules of the reference parser; program, erase-and-program, program LZ4 and program LZMA tags are load sections | Strong: header tag `0x03A617EB` at 0 | None. Gecko bootloaders run on EFR32/EFM32 parts, but a vendor is not evidence (AGENTS.md 3.1); the code model decides | gecko_sdk v4.5.1 (`8a2efd2c`) `platform/bootloader/parser/gbl/btl_gbl_format.h`, `btl_gbl_format.c`, `btl_gbl_parser.c`; simplicity_sdk v2025.6.3 (`8ddb6e57`) for the delta tags; Silicon Labs "Gecko Bootloader File Format" (docs.silabs.com) |
| `cyacd` | `.cyacd bootloadable`: 12-hex-digit header (silicon ID, revision, checksum type), `:` rows of array ID, row number, length, data and checksum | Weak: no magic. The header and every row must parse and every row checksum must match | None. The silicon ID names a device; the code model decides | Cypress Bootloader Host `cybtldr_parse.c`, `cybtldr_api2.c` (2011-2012, as mirrored in SCSI2SD `7ae322c1`); cyflash `cyacd.py` (`6d742d67`) |
| `cyacd` | `.cyacd2 DFU image`: 24-hex-digit header starting with file version `01` (silicon ID, revision, checksum type, app ID, product ID), `@APPINFO`/`@EIV` rows, `:` rows of byte address and data | Weak: as above; rows carry no checksum | None. Silicon and product IDs are metadata | Infineon AN213924 rev *H, ".cyacd2 file format"; Infineon `mtb-example-psoc4-dfu-host` (`65115d86`) `source/cybtldr_parse.c` |
| `dfusuffix` | `DFU 1.1 file`: firmware, optional vendor suffix fields, then `bcdDevice`, `idProduct`, `idVendor`, `bcdDFU` `0x0100`, `UFD`, `bLength`, `dwCRC`; the firmware is one child | Strong once valid: `UFD` at `len - 8` and a matching `dwCRC` (the two criteria Appendix B gives the host). Checked after the `DfuSe` prefix and before the UF2, GBL and EBL magics | None. USB IDs are metadata; the child is classified on its own bytes | [USB DFU 1.1](https://www.usb.org/sites/default/files/DFU_1.1.pdf) (2004-08-05), Appendix B and its sample program; dfu-util v0.11 `src/dfu_file.c`, `src/suffix.c`, `src/dfuse.c` |
| `silabsebl` | `EBL v2 file`: big-endian tag stream; header tag `0x0000` (version, signature `0xE350`, `flashAddr`, `aatCrc`, up to 128 AAT bytes), program `0xFE01` and erase-then-program `0xFD03` tags as load sections, manufacturing program `0x02FE` and metadata `0xF608` tags as opaque children, end tag `0xFC04`; encrypted files: `0xFB05`, `0xFA06`, `0xF907` data, `0xF709` MAC, end | Strong: tag `0x0000` at 0 with a header length of 12-140 B, version major `0x02` and `0xE350` at 6, or tag `0xFB05` at 0 with length 6 and `0xE350` at 8. The header tag ID is zero, which many files start with, so the signature alone would be a 16-bit key | The AAT's `platInfo` byte (type `0x0AA7` tables only): platform 4 (`CortexM3`, also written by EFR32 builds) is `arm`, 32-bit, little-endian; any other platform names no ISA and the code model decides | Silicon Labs UG103.6 rev. 1.6, chapter 5; Gecko SDK Suite v2.6 `platform/base/hal/micro/cortexm3/common/ebl.h`, `bootloader-ccm.h`, `platform/base/hal/micro/micro-types.h` (vendor files read from the `tomyqg/gecko_sdk_suite` mirror at `095c3631`); gecko_sdk v4.5.1 (`8a2efd2c`) `platform/service/legacy_hal/inc/bootloader-common.h`, `platform/bootloader/api/ember_btl_interface.h`, `ember_btl_common.c`, `sl_legacy_bootloader_device_info.h.jinja`; Simplicity Commander "EBL Commands" |
| `nordicinitpacket` | `nRF DFU init packet`: one `dfu.Packet` protocol buffer (proto2) with a `command` or `signed_command`, the `InitCommand` (firmware and hardware versions, `sd_req`, type, sizes, hash, debug flag, boot validations) and the signature | Weak: no magic. At most 512 B, first byte `0x0A` or `0x12`, and the whole buffer must parse with the documented field numbers and wire types within the bootloader's field limits, with exactly one command, an `InitCommand`, a hash and the size its type requires | None; metadata only (`hw_version` names a device family) | pc-nrfutil v6.1.7 (`804bc0ff`) `nordicsemi/dfu/dfu-cc.proto`, `init_packet_pb.py`, `package.py`; nRF5 SDK 17.1.0 `components/libraries/bootloader/dfu/` `dfu-cc.proto`, `dfu-cc.options`, `nrf_dfu_types.h`, `nrf_dfu_validation.c` (read from the `bluerange-io/bluerange-mesh` mirror at `7131ad13`, `sdk/sdk17_1`) |

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
- A DFU file has one child, `DFU firmware`: the file without its last
  `bLength` bytes ("In no case is the DFU suffix ever sent to the device"),
  at offset 0. It is classified on its own bytes, so a GBL, UF2 or EBL file
  inside reports its own format and ISA, and raw code goes to the code model.
  Vendor fields of a suffix longer than 16 B are noted, not interpreted. The
  `DfuSe` layout reads its suffix through the same code
  (`mcu::dfu_suffix::read`).
- EBL program and erase-then-program tags are load sections at their
  `flashAddr`, labelled `Load section <n>`. The header's AAT is not a section
  (the bootloader writes it to `flashAddr` from the header); its reset vector
  is reported as the entry point. Manufacturing program tags (customer
  information block or user data) are opaque children labelled
  `Manufacturing data at <address>`, metadata tags opaque `Metadata`
  children, and in an encrypted file every encrypted data tag is an opaque
  child and the container is opaque.
- A Nordic init packet is a metadata-only container: no sections, no
  children, unknown ISA with confidence 0. Inside an nRF DFU ZIP the `.dat`
  member is recognized (the ZIP parser lists recognized members) while the
  raw `.bin` is not.

## Wire units and byte order

All UF2, DfuSe and GBL integers are little-endian; all sizes are bytes.
UF2 `targetAddr` is a flash byte address (esptool writes flash offsets, and
RP2350 relocates non-absolute images into partitions), DfuSe element
addresses are byte addresses in the memory the alternate setting selects,
GBL `flashStartAddress` is a byte address. `.cyacd` silicon ID, row number
and data length are big-endian, and section addresses are flash row numbers
within the array (the row size and array base are not encoded, so they are
not converted to byte addresses). `.cyacd2` header fields and row addresses
are little-endian, and row addresses are byte addresses. DFU suffix fields
are little-endian in file order (the specification's "end-for-end swapped"
suffix), and `bLength` counts bytes. EBL tag IDs, lengths and data fields are
big-endian ("network (big) endian order", `ebl.h`), the AAT fields inside the
header are little-endian ("native (little) endian order"), and the end tag's
CRC is little-endian; `flashAddr` is a flash byte address. Nordic init
packets are protocol buffers: varints in 7-bit groups, sizes in bytes; the
SHA-256 hash is stored in reverse byte order (pc-nrfutil
`calculate_sha256_hash`) and reported in file order. Header byte order is
never reported as code byte order; a UF2 family target fixes the code byte
order of the family's core, and the EBL `CortexM3` platform fixes
little-endian, the AAT's native order.

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
| DFU suffix | Recognized only when `UFD` sits at `len - 8` and `dwCRC` (CRC-32 register, initial `0xFFFFFFFF`, no final inversion, over every byte but the last four) matches; then `bLength` from 16 B to `len - 1` B (at least one byte of firmware) and `bcdDFU` `0x0100`. `0x011A` without the `DfuSe` prefix is `Missing DfuSe prefix` (dfu-util refuses to send such a file raw); other values are `Unsupported`. A 16-byte file is `Truncated DFU file` |
| EBL tags | First tag the header (or the encryption header); every tag inside the file; unknown IDs rejected; payload sizes as `ebl.h` lists them (header 12-140 B, program tags at least 6 B with an even data length, metadata at least 1 B, end exactly 4 B, encryption header exactly 6 B, encryption init at least 16 B, encrypted data at least 4 B, MAC exactly 16 B); order: header, then program, manufacturing, metadata tags, then end; or encryption header, encryption init, encrypted data, MAC, end |
| EBL header | Signature `0xE350`; version major `0x02` (`EBL_MAJOR_VERSION`, mask `0xFF00`); encryption header signature `0xE350`; `aatCrc` reported, not verified |
| EBL end tag | `eblCrc` equals the zlib CRC-32 of every byte before it (the residue `0xDEBB20E3` of UG103.6 Table 5.2); only `0x00`/`0xFF` padding may follow |
| Nordic init packet | At most 512 B (`INIT_COMMAND_MAX_SIZE`); wire types 0 and 2 only; field number 0, unknown fields, wrong wire types, repeated singular fields, varints over 64 bits, `uint32` values over 32 bits, enum values outside the `.proto` and booleans other than 0/1 rejected; hash at most 32 B, signature at most 64 B, `sd_req` at most 16 values (packed or not), boot validations at most 3 with at most 64 B each (`dfu-cc.options`); required fields of `Hash`, `BootValidation`, `SignedCommand` and `ResetCommand` present; exactly one of `command` and `signed_command`; `op_code` `INIT` when present; an `InitCommand`, a hash and a non-zero firmware size for the type (`update_data_size_get`) |
| Payload and components | Load sections and decoded data at most 64 MiB (`MAX_PAYLOAD`); load sections and UF2 per-family regions capped at 4096 (`MAX_COMPONENTS`), the rest counted in a note; GBL and EBL children capped at 4096 |

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
| M12 | Plain DFU files use `bcdDFU` `0x0100` | The specification gives `0100h` and dfu-suffix writes `0x0100` or `0x011A`; a tool writing `0x0110` would produce an `Unsupported` error. Run `dfu-suffix -a` on a binary (not available here) and parse it |
| M13 | The DFU suffix may wrap any firmware, so it is checked before the MCU magics at offset 0 | A UF2 or GBL file with a valid suffix becomes a DFU file with that child; formats detected before the MCU block (ELF, PE, Mach-O and the other executable formats, automotive containers, option ROMs, FPGA bitstreams) keep claiming files that carry a suffix (`dfu_suffix_firmware_with_a_header_reports_its_own_format`) |
| M14 | EBL platform 4 (`CortexM3`) means Arm Cortex-M code, and no other platform value has an established ISA | `micro-types.h` lists micros 1-34 under platform 4 (EM3xx and EFR32), and EFR32 builds set `SL_PLAT 4`; an EBL whose code disagrees produces the "Container names arm" warning |
| M15 | The AAT fields are those of `HalAppAddressTableType` with 32-bit pointers, read only for type `0x0AA7` | Commander's `ebl print` shows the same fields (top of stack, reset vector, type `0x0AA7`); compare on a Commander-generated EBL (not available here) |
| M16 | EBL program data length is even and tags have no padding between them | `eblProg3xx_t` says "must be multiple of 2"; Commander's example tags are 1924, 2052 and 1772 B long; an odd-length tag from a real tool would be rejected |
| M17 | The EBL header holds 12 to 140 B | `ebl.h` minimum 12, `AAT_MAX_SIZE` 128; Commander and pygbl write 140; a longer header would be rejected |
| M18 | Nordic init packets always carry a hash and the firmware size for their type | pc-nrfutil `_validate` and the nRF5 SDK bootloader require the size; the SDK always compares the hash. A packet from another generator without them is not recognized |
| M19 | Unknown protobuf fields do not occur in init packets | Strict for weak recognition; a newer `dfu-cc.proto` with added fields would not be recognized until the field table is extended |

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
| TI Stellaris and NXP LPC DFU prefixes (dfu-util `probe_prefix`) | Not split off; the DFU firmware child includes the prefix bytes |
| DFU suffix on a file whose format is detected before the MCU block | That format claims the file (an ELF with a suffix is an ELF); the suffix is not reported |
| DFU suffix `idVendor`/`idProduct` to device | Not mapped; reported as metadata |
| DFU files inside archives | Archive members are first checked on their first 4 KiB (`RECOGNITION_PREFIX`), which a suffix at the end of a larger file is not part of; such a member is listed only when its firmware itself starts with a recognized format |
| EBL `aatCrc` and the header's `imageCrc` | Reported (`aatCrc`) and not verified: UG103.6 describes them in words, and the exact byte ranges and storage order were not confirmed against a real file |
| EBL AES-CCM encryption and MAC | Opaque; the MAC is reported as present and not verified |
| EBL tag size limit `EBL_MAX_TAG_SIZE` (2080 B) | Not enforced; it bounds the bootloader's tag buffer, and the evidence that it bounds files was not established |
| EBL platforms other than 4 (XAP2b, C8051, AVR test builds) | Reported by name; no ISA is mapped |
| Nordic init packet signatures and the firmware hash | Reported as present and not verified; the image is a separate file, and the public key is in the bootloader |
| Init packets of other Nordic DFU generations (legacy nRF5 SDK DFU, nRF Connect SDK packages) | Not recognized; their layouts were not researched here |
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

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`
2026-09-05, Node 25.8.1), for the DFU suffix, EBL and Nordic init packet
layouts:

- `tests/mcu_wrappers.rs`: 16 tests passed. They cover DFU files around raw
  Thumb code, a GBL file and an ELF (which stays an ELF), vendor suffix
  fields and wildcard IDs, CRC, `bLength` and `bcdDFU` defects, `DfuSe`
  files keeping their layout; EBL files with the `CortexM3` platform (target,
  entry point, section offsets), other platforms and AAT types left to the
  code model, a platform/code disagreement, manufacturing and metadata tags
  as opaque children, encrypted files (opaque, MAC not verified, order),
  CRC, order, unknown-tag, length, version and padding checks; the two
  protoc-encoded init packets, init packets built from the wire layout
  (field order, unpacked `sd_req`, every rejection rule), a stored nRF DFU
  ZIP whose `.dat` member is listed; every-prefix truncation sweeps and
  every-byte mutation sweeps (`0x00`, `0xFF`, bit flip) for each layout.
- Unit tests: 8 new in `src/formats/mcu/dfu_suffix.rs`, `ebl.rs` and
  `nordic.rs` (21 in `src/formats/mcu*` in all), passed.
- `web/tests/mcu-wrappers.test.mjs`: 4 tests passed (classification through
  `/pkg/zrax.js` and `/dist/zrax.js`; the workbench at `/web/` and
  `/dist/`).
- `DfuSe` now reads its suffix through `dfu_suffix::read`. A differential
  snapshot over 8,044 inputs (`DfuSe` files with `bcdDFU` `0x011A` and
  `0x0100`, a GBL and a UF2 file, every truncation and every single-byte
  mutation; detection, parser `Debug` output and payload JSON, hashed)
  was identical before and after the change.
- The whole native suite passed (1,501 tests, 6 ignored), and the whole
  browser suite passed (176 tests, 4 skipped for D10/RX113 firmware that is
  not in the repository).
- After integration with the partition table, FAT, ISO 9660, console disc
  and Java image families on the same day, the whole native suite passed
  (1,737 tests, 6 ignored). IDA's test corpus (4,621 files) classified as
  before. A scan of 82,323 local files (macOS system, Homebrew and
  toolchain files up to 8 MiB) found no EBL or init packet, and six USB
  DFU files: the Broadcom BCM2070x Bluetooth firmware in
  `/usr/share/firmware/bluetooth`, whose suffix CRC verified and whose
  firmware child the code model classified as Arm Thumb.

All committed fixtures are synthetic: `tests/fixtures/mcu` holds machine code
compiled from `tests/fixtures/transforms/sample.c` and two init packets
encoded by protoc from committed text inputs (see its README), and the other
containers are built in the tests from the documented layouts. GBL and EBL
files from Simplicity Commander, `.cyacd`/`.cyacd2` files from PSoC Creator
or cymcuelftool, esptool or picotool UF2 files, dfu-suffix output and nrfutil
packages were not available, so the behavior on those generators' output is
not verified. The EBL layout in particular was built from vendor headers and
documentation only; no real EBL file was parsed.
