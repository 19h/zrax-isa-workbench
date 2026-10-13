# UEFI capsules

`src/formats/capsule.rs` and its submodules (`fmp.rs`, `payload.rs`,
`json.rs`, `ux.rs`, `vendor.rs`) parse firmware update capsules into the
shared container model ([compressed streams and the container
model](compressed-streams.md)). A capsule starts with an
`EFI_CAPSULE_HEADER`; its `CapsuleGuid` decides the layout of the body.

A capsule names no ISA. Its body, its FMP payload images and its embedded
drivers are children classified from their own bytes, so a capsule that
wraps a firmware volume or a flash image reports what the UEFI family
([UEFI and PC flash images](uefi.md)) finds in it, and an embedded PE or TE
driver reports its own `Machine`. Payload images are pushed before embedded
drivers: a driver supplies the primary ISA only when no payload has one.
Authentication data, vendor code, JSON payloads and display images are
opaque. Signatures are reported as present and never verified.

## Implemented layouts

All layouts report the JSON format ID `ueficapsule`; the layout is the
format variant.

| Variant | Recognition | Body | Primary source |
| --- | --- | --- | --- |
| `UEFI capsule (EFI_CAPSULE_GUID)` | Strong: `3B6686BD-0D76-4030-B70E-B5519E2FC5A0` at 0 | One child from `HeaderSize` to `CapsuleImageSize`, classified on its own (EDK2 `GenFv` writes firmware volumes there) | UEFI 2.10 8.5.3.1; EDK2 `vUDK2018` `IntelFrameworkPkg/Include/Guid/Capsule.h`; EDK2 `edk2-stable202408` `BaseTools/Source/C/GenFv/GenFvInternalLib.c` (`GenerateCapImage`, `mDefaultCapsuleGuid`) |
| `FMP capsule` | Strong: `6DCBD5ED-E82D-4C44-BDA1-7194199AD92A` at 0 | `EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER`, `ItemOffsetList`, embedded drivers and payload items (see below) | UEFI 2.10 23.3.1-23.3.3; EDK2 `MdePkg/Include/Guid/FmpCapsule.h`, `MdeModulePkg/Library/DxeCapsuleLibFmp/DxeCapsuleLib.c` (`ValidateFmpCapsule`, `ProcessFmpCapsuleImage`), `BaseTools/Source/Python/Capsule/GenerateCapsule.py` |
| `Nested FMP capsule` | Weak: any other GUID; `CapsuleImageSize` equals the file size; an FMP capsule at `HeaderSize` whose `CapsuleImageSize` is the rest of the file and which parses completely | The inner FMP capsule as one child | EDK2 `DxeCapsuleLib.c` `IsNestedFmpCapsule`, `IsValidCapsuleHeader` |
| `JSON capsule` | Strong: `67D6F4CD-D6B8-4573-BF4A-DE5E252D61AE` at 0 | `EFI_JSON_CAPSULE_HEADER` (`Version` 1, `CapsuleId`, `PayloadLength`), then the JSON payload as an opaque child | UEFI 2.10 23.5.1-23.5.3 |
| `Windows UX capsule` | Strong: `3B8C8162-188C-46A4-AEC9-BE43F1D65697` at 0 | `DISPLAY_DISPLAY_PAYLOAD` (`Version` 1, `Checksum`, `ImageType`, `Mode`, `OffsetX`, `OffsetY`), then the image as an opaque child | EDK2 `MdePkg/Include/IndustryStandard/WindowsUxCapsule.h`, `DxeCapsuleLib.c` `DisplayCapsuleImage` (the Microsoft specification it cites was not read) |
| `Intel capsule` | Strong: `539182B9-ABB5-4391-B69A-E3A943F72FCC` at 0 | As `EFI_CAPSULE_GUID` | `UEFITool` `A75` (commit `19a4dab7`) `common/ffs.h`, `common/ffsparser.cpp` `parseCapsule` |
| `Lenovo capsule` | Strong: `E20BAFD3-9914-4F4F-9537-3129E090EB3C` or `25B5FE76-8243-4A5C-A9BD-7EE3246198B5` at 0 | As `EFI_CAPSULE_GUID` | `UEFITool` `A75` |
| `Toshiba capsule` | Strong: `3BE07062-1D51-45D2-832B-F093257ED461` at 0 | `HeaderSize` (0x10), `FullSize` (0x14), `Flags` (0x18); the body from `HeaderSize` to `FullSize` | `UEFITool` `A75` `TOSHIBA_CAPSULE_HEADER` |
| `AMI Aptio signed capsule`, `AMI Aptio unsigned capsule` | Strong: `4A3CA68B-7723-48FB-803D-578CC1FEC44D` or `14EEBB90-890A-43DB-AED1-5D3C4588A418` at 0 | `EFI_CAPSULE_HEADER`, then `RomImageOffset` (0x1C) and `RomLayoutOffset` (0x1E, u16 each); the ROM image from `RomImageOffset` to `CapsuleImageSize` | `UEFITool` `A75` `APTIO_CAPSULE_HEADER` |

The UEFI Specification 2.10 was read in its HTML edition
(`uefi.org/specs/UEFI/2.10/`, Wayback snapshots `20240919080943` for chapter
8 and `20240428002726` for chapter 23). EDK2 sources are pinned to
`edk2-stable202408` (commit `b158dad150bf02879668f72ce306445250838201`) unless
noted. No Intel, Lenovo, Toshiba or AMI document was read; those layouts are
`UEFITool`'s.

## FMP capsules

| Item | Handling |
| --- | --- |
| Capsule header | `HeaderSize` must be below `CapsuleImageSize` (EDK2 `ValidateFmpCapsule`); the FMP header is at `HeaderSize` |
| `EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER` | `Version` 1; `EmbeddedDriverCount` and `PayloadItemCount`; the count must fit the body as u64 offsets; each offset lies after the offset list and inside the body and is above the previous one; a capsule without items must end after the 8-byte header and is noted as not processed (UEFI 2.10 23.3.3) |
| Item extents | Each item runs to the next offset, the last to `CapsuleImageSize` (UEFI 2.10 23.3.3) |
| Embedded drivers | Children `Embedded driver N`, classified on their own (EFI drivers are PE32, PE32+ or TE images for `LoadImage()`), pushed after every payload child |
| `EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER` | Version 1 (32 B), 2 (40 B, `UpdateHardwareInstance`) or 3 (48 B, `ImageCapsuleSupport`); the item size must equal the header, `UpdateImageSize` and `UpdateVendorCodeSize` together |
| `EFI_FIRMWARE_IMAGE_AUTHENTICATION` | Present when `ImageCapsuleSupport` has `CAPSULE_SUPPORT_AUTHENTICATION`, or when the `CertType` at update-image offset 0x10 is `EFI_CERT_TYPE_PKCS7_GUID` or `EFI_CERT_TYPE_RSA2048_SHA256_GUID` (the evidence `GenerateCapsule.py` `IsSigned` uses); `wRevision` 0x0200, `WIN_CERT_TYPE_EFI_GUID`, `dwLength` of at least 24 B and `8 + dwLength` inside the update image; an opaque child labeled with the signature type and "not verified" |
| `EFI_FIRMWARE_IMAGE_DEP` | Walked only when `ImageCapsuleSupport` has `CAPSULE_SUPPORT_DEPENDENCY`, with the operand lengths of EDK2 `ValidateDependency`, up to its END opcode; an unknown opcode, an unterminated version string or a missing END is a parse error; the expression is not evaluated |
| `FMP_PAYLOAD_HEADER` | When the next bytes are `MSS1`: `HeaderSize` of at least 16 B inside the update image; `FwVersion` and `LowestSupportedVersion` in notes and metadata (EDK2 `FmpPayloadHeaderLibV1`) |
| Firmware image | The rest of the update image: a child `Payload N (UpdateImageTypeId)` classified on its own |
| Vendor code | An opaque child `Payload N vendor code` |

Notes and metadata name the capsule GUID, `HeaderSize`, `Flags` (spec bits
by name, the GUID-defined low half, undefined bits, and the combinations
UEFI 2.10 8.5.3.1, 23.3.3 and 23.5.3 rule out), and for each payload item
its `UpdateImageTypeId`, `UpdateImageIndex`, header version,
`UpdateHardwareInstance`, `ImageCapsuleSupport` and contents. Metadata keys
are `capsule_guid`, `capsule_header_size`, `capsule_flags`,
`capsule_embedded_driver_count`, `capsule_payload_count`,
`capsule_payload_N_type_id`, `capsule_payload_N_image_index`,
`capsule_payload_N_fw_version`, `capsule_payload_N_lowest_supported_version`,
`capsule_json_capsule_id`, `capsule_rom_image_offset` and
`capsule_rom_layout_offset`, with payload numbers from 1.

## Wire units and byte order

Every structure is packed and little-endian. All offsets and sizes are
bytes. `HeaderSize`, `CapsuleImageSize`, `FullSize` and `RomImageOffset` are
measured from the start of the capsule; `ItemOffsetList` entries from the
start of the FMP capsule header (the capsule body). Children and slices are
in file coordinates: the body child of an `EFI_CAPSULE_GUID` capsule with
the 0x20-byte header EDK2 writes starts at 0x20. Header byte order says
nothing about code byte order.

## Validation and resource bounds

- Strong recognition requires the GUID, a complete header, and a body
  offset (`HeaderSize`, or `RomImageOffset` for AMI Aptio) of at least the
  header size (28 B; 32 B for Aptio), at most `CapsuleImageSize` (or
  `FullSize`) and at most the file size. A capsule longer than the file is
  recognized and reported as truncated, not analyzed as raw code.
- Bytes after `CapsuleImageSize` may only be erased flash or zero fill
  (noted); anything else is a parse error. UEFI 2.10 8.5.5 requires the file
  size to equal `CapsuleImageSize`.
- FMP item counts are checked against the body size before the offset list
  is read or allocated: at most `(body size - 8) / 8` items, so at most
  131070 can be declared and at most one per 8 bytes of body is read.
- At most 4096 children per capsule (`MAX_COMPONENTS`); further ones are
  counted in a note. Notes and metadata cover the first 32 payload items;
  the rest are counted.
- The dependency walk advances at least one byte per opcode and stops at
  the end of the update image.
- No child is copied: every child borrows the input.
- The Windows UX checksum (8-bit sum of `CapsuleImageSize` bytes) is
  verified; a mismatch is a parse error.

## Assumption register

| ID | Assumption | Source | Falsification probe |
| --- | --- | --- | --- |
| C1 | The body of an `EFI_CAPSULE_GUID` capsule starts at `HeaderSize`, not at the Framework header's `OffsetToCapsuleBody` | EDK2 `GenFv` writes the 28-byte UEFI header with this GUID; `UEFITool` reads the body at `HeaderSize` | A Framework (Capsule Specification 0.9) capsule with `OffsetToCapsuleBody` != `HeaderSize`; its body child would start at the wrong offset |
| C2 | Authentication data without `CAPSULE_SUPPORT_AUTHENTICATION` is recognized by its `CertType` | `GenerateCapsule.py` `IsSigned` | A version 1 or 2 payload whose firmware image happens to hold a PKCS7 or RSA2048 GUID at offset 0x10 would lose its first bytes to an authentication child |
| C3 | A dependency expression is present only when `CAPSULE_SUPPORT_DEPENDENCY` is set | UEFI 2.10 23.3.2; `GenerateCapsule.py` sets the bit whenever it writes one | EDK2 `FmpDxe` also probes for an expression without the bit; a capsule that relies on that leaves the expression in the firmware image child |
| C4 | The EDK2 `FMP_PAYLOAD_HEADER` is the only header between the authentication or dependency data and the firmware image | EDK2 `FmpDxe`, `GenerateCapsule.py` | Vendor payloads with other headers are classified with those headers in front |
| C5 | Toshiba and AMI Aptio headers are as `UEFITool` A75 defines them | `UEFITool` only | Vendor capsules whose ROM image does not start at `RomImageOffset` or `HeaderSize` |
| C6 | The AMI Aptio area between the header and `RomImageOffset` holds the certificate and ROM layout table | One ASUS capsule (below): a `WIN_CERTIFICATE_UEFI_GUID` with `EFI_CERT_TYPE_RSA2048_SHA256_GUID` at 0x20 ending at `RomLayoutOffset` | Not parsed; only `RomImageOffset` and `RomLayoutOffset` are reported |
| C7 | A nested FMP capsule's outer GUID is a platform ESRT firmware class | EDK2 `IsNestedFmpCapsule` | Not checkable from the file; the note says so |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Signatures (PKCS7, RSA2048/SHA-256, AMI Aptio) | Reported, not verified |
| Dependency expressions | Walked for their length, not evaluated |
| Framework capsule header fields and split capsules (Capsule Specification 0.9) | Not interpreted; a split capsule (`CapsuleImageSize` larger than the file) is a truncation error |
| Capsules with an undocumented GUID that do not wrap an FMP capsule (device-specific capsules, ESRT GUIDs used directly) | Not recognized; classified as whatever their bytes are |
| Capsule-on-disk name capsules, `EFI_MEMORY_RANGE_CAPSULE_GUID` | Not recognized (no file format; built in memory) |
| AMI Aptio `FW_CERTIFICATE` and `ROM_AREA` tables | Not parsed (no primary source) |
| `UpdateImageIndex` 0 | Reported; `SetImage()` expects 1 or more, which is not enforced |
| JSON payload contents | Not parsed (the schema is outside the UEFI specification) |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly), `tests/capsule.rs`
(18 tests) and 6 unit tests in `src/formats/capsule*` passed. The fixtures
are built in the tests from the documented layouts around the committed
`tests/fixtures/uefi/sample.fd` volume and the PE image in
`tests/fixtures/uefi/pe32-sections.bin`; the tests include a parse of every
prefix of each of the ten layouts' fixtures and 0x00/0xFF/bit-flip mutations
of every byte. `web/tests/capsule.test.mjs` (4 tests, Node 25.8.1,
Playwright Chromium) passed through `/pkg/`, `/dist/`, `/web/index.html` and
`/dist/index.html`. On the same date the whole native suite passed with
1865 tests and 6 ignored, and the whole browser suite ran 216 tests: 212
passed and 4 were skipped because they need D10/RX113 firmware that is not
in the repository.

Two tests read external data and skip without it:

- `IDA_INPUT_DIR=/Users/int/hexrays/ida/tests/input` (IDA's test inputs,
  read in place): none of the 44328 files of at most 64 MiB (larger
  files were not read) is detected as a capsule, strong or weak; the three real firmware volumes (`pc_uefi_fv_diskio_64.fv`,
  `pc_uefi_fv_mixed_64.fv`, `arm64_uefi_fv_diskio.fv`) wrapped in an
  `EFI_CAPSULE_GUID` capsule keep their own ISA, and each wrapped as an FMP
  payload with each of five EFI images (`pc_test_efi_pe.pe`,
  `pc_test_efi_pe_64.pe`, `arm_efi_dxecore.pe`, `pc_test_efi_te.te`,
  `arm_efi_memoryinit_64.te`) as an embedded driver (15 pairs) reports the
  volume's ISA as primary and the driver's own ISA for the driver.
- `UEFI_CAPSULE_DIR`: a local directory (not committed) with an ASUS Pro WS
  WRX80E-SAGE SE WIFI BIOS 1901 capsule (AMI Aptio signed, 32 MiB ROM image
  at 0x1000, which the UEFI family classifies as an x86-64 flash device
  image) and three FMP capsules written by EDK2 `GenerateCapsule.py`
  (`edk2-stable202408`, run locally with Python 3 and OpenSSL 3.6.4 around
  `sample.fd` and the fixture PE image: unsigned with an embedded driver;
  PKCS7-signed with throwaway keys; and a two-payload JSON-configured
  capsule with a signed payload, a dependency expression and an embedded
  driver). All four classified as `ueficapsule` with the expected
  components; after the generated certificates (2242 B) and dependency
  expression (48 B), the firmware volume was found and classified as
  x86-64.

After integration on the same day, the native suite passed 1,943 tests
with 6 ignored, and IDA's corpus (4,621 files) classified as before. The
gated test was run again on the ASUS download folder as found, which also
holds what an extraction tool wrote: the capsule classified as before; a
4 KiB `FREEFORM` file in the extracted firmware holds a copy of the Aptio
capsule header with no body (reported as such, no components), and a
4 KiB `capsule_header.bin` cut from the capsule is a "Truncated capsule"
parse error. The test accepts both, as the comment on it says.

Not verified: signatures (never checked), Intel, Lenovo and Toshiba
capsules, AMI Aptio unsigned capsules, JSON and Windows UX capsules and
nested FMP capsules from real vendors (only synthetic fixtures), image
header versions 1 and 2 from real tools, and RSA2048/SHA-256 FMP
authentication written by EDK2 GenFds.
