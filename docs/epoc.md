# Symbian E32 images (EPOC)

`src/formats/epoc.rs` parses Symbian OS E32 image files, the executables
(`.exe`), libraries (`.dll`, `.app`) and device drivers (`.ldd`, `.pdd`)
that the Symbian loader runs, into the shared container model
([compressed streams and the container model](compressed-streams.md)). They
are called EPOC images after the `EPOC` signature in their header. The
format ID is `epoc` (`FileFormat::Epoc`), as before.

The header's CPU identifier names the ISA. The code and data parts of an
uncompressed image are load sections that the code model classifies under
that target; the contents of a compressed image are an opaque component,
since no codec of this classifier decodes Symbian's own deflate or
byte-pair coding. Before this parser the module reported 32-bit
little-endian ARM for every input it recognized without reading the header,
and a UID-only fallback also claimed files that are not E32 images (see
[Detection](#detection)).

## Implemented layouts

| JSON format ID | Layout (`epoc_header_format`) | Recognition | Architecture evidence | Primary source |
| --- | --- | --- | --- | --- |
| `epoc` | `V`: `iFlags & 0x0F000000` = `0x02000000`, every executable since Symbian OS 8.1b. Header CRC at 0x14, module version 0x18, compression type 0x1C, CPU (16-bit) at 0x7A, then `E32ImageHeaderComp` (uncompressed size, 0x7C) and `E32ImageHeaderV` (security information, exception descriptor, export description) to `iCodeOffset` (at least 0x9C) | Strong: `EPOC` at 0x10 | `iCpuIdentifier` | K1 `f32image.h` |
| `epoc` | `J`: format bits `0x01000000`, or bits 0 with `KImageOldJFlag` (0x08, tools before 2.00). CPU word at 0x14, compression type at 0x1C; a compressed image stores `iUncompressedSize` at 0x7C and its contents from 0x80 | Strong: as above | `iCpu` (word at 0x14) | K2 `e32imageheaders.h` |
| `epoc` | `original` (EKA1): format bits 0 without the old J flag. CPU word at 0x14, code and data checksums at 0x18 and 0x1C, no compression | Strong: as above | `iCpu` (word at 0x14) | K2, K3 |

The classification variant names the CPU (`ARMv4`, `ARMv5`, `ARMv6`,
`x86`, `M*CORE`), or is `Symbian E32 image` when the header names none.

Sources, all retrieved on 2026-10-13 from `raw.githubusercontent.com`
(Symbian Foundation mirrors, EPL 1.0, Nokia):

| Tag | Repository and commit |
| --- | --- |
| K1 | `SymbianSource/oss.FCL.sf.os.kernelhwsrv`, commit `0c3208650587ac0230aed8a74e9bddb5288023eb` (2010-11-02, tag 201043_12) |
| K2 | `SymbianSource/oss.FCL.sf.tools.rndtools`, commit `29f348bac14c2472f9a0e371ca2b4493b7bb2974` |
| K3 | `SymbianSource/oss.FCL.sftools.dev.ide.carbidecpp`, commit `4420f338bc4e522c563f8899d81201857236a66a` |

| Tag | File | Used for | SHA-256 |
| --- | --- | --- | --- |
| K1 | `userlibandfileserver/fileserver/inc/f32image.h` | `TCpu` (line 35), `KImageCrcInitialiser` (49), `iFlags` bits (61-107), `E32ImageHeader` (135-193), `E32ImageHeaderComp` (199), `E32ImageHeaderV` (210-226), `E32ImageHeaderV::ValidateHeader` (612-883), `ValidateExportDescription` (889) | `2491d1767cfe70762246f08dd4012257980588a2a03767c9299a1774118bbd7d` |
| K1 | `kernel/eka/euser/us_func.cpp` | `crcTab` (51), `checkSum` (81-98), `Mem::Crc` (657-676), `TCheckedUid::Check` (1986-1995), `CrcTab32` (2023), `Mem::Crc32` (2102-2110) | `e3d375f977c290b002c4eca47fd36910bdd41e17f11ae66fd2a0dca2dea90ed5` |
| K1 | `kernel/eka/include/e32ldr_private.h` | Compression UIDs (392-400) | `8e2dd5218b6b588b4f5c3e0b873f956c8fbee0bf02385002bd253ea5cab1cd28` |
| K1 | `kernel/eka/include/e32uid.h` | UID1 values (31-32) | `14b60497593ec8e35e2984be75235395baf20beeea8aad48f0d5c86ba52bf5c4` |
| K1 | `kernel/eka/include/e32const.h` | `KMaxCheckedUid` (51), `TFloatingPointType` (3148-3157) | `87f811c9c627b92418ee57b01073b793200533c3a89bbc6765791f30be3252e2` |
| K1 | `kernel/eka/include/e32cmn.h` | `TVersion` (2062), `SCapabilitySet` (3432), `SSecurityInfo` (3449) | `3651ca75a1e9d1241fc14fe683796bc7445691b30191a67913195aab276830fb` |
| K1 | `userlibandfileserver/fileserver/sfile/sf_deflate.h` | The loader's deflate coding constants | `e8cf298dcea44b972facd281d310e818c35fc5078f59138b967dcebb75a183e8` |
| K1 | `kernel/eka/include/e32rom.h` | `TRomImageHeader` (974) | `840c9d9c00623ff2fd3c29b0a529e3cee4827b14acc28a12706447984da69f6e` |
| K2 | `launcher/inc/e32imageheaders.h` | `KImageOldJFlag`, `KImageOldElfFlag` (144-145), `HdrFmtFromFlags` (199), `ABIFromFlags`, `EptFromFlags`, `ImpFmtFromFlags`, `CompressionType`, `TotalSize` (307), `CpuIdentifier` (334): the header formats before 8.1b | `56d59750552fb97abc8d4d7ae41edee6213719773c856e635dd396276643bb91` |
| K3 | `debuggercdi/com.nokia.cdt.debug.cw.symbian/src/com/nokia/cdt/debug/cw/symbian/binaryparser/SymbianE32BinaryObject.java` | Lines 43-72: the field order of the original header (`iCpu`, `iCheckSumCode`, `iCheckSumData`, `iVersion`, `iTime`) | `e3c9af6f184b09bdb719f3dd29f16641e50e14e26dfd45a682dea9412ea0aa6e` |

### Header

The first 0x7C bytes are shared by every header format (`E32ImageHeader`,
K1). The parser reads:

| Offset | V field | J and original field | Use |
| --- | --- | --- | --- |
| 0x00-0x08 | `iUid1`, `iUid2`, `iUid3` | same | Notes and `epoc_uid1`-`epoc_uid3`; UID1 `0x10000079` is `KDynamicLibraryUidValue`, `0x1000007A` `KExecutableImageUidValue` |
| 0x0C | `iUidChecksum` | `iCheck` | Verified (below) |
| 0x10 | `iSignature` | same | `EPOC` (0x434F5045); detection |
| 0x14 | `iHeaderCrc` | `iCpu` (TCpu, 32 bits) | V: verified; J and original: the CPU (K2 `CpuIdentifier`) |
| 0x18 | `iModuleVersion` | `iCheckSumCode` (original) | V: major (high half), minor (low half); original: reported, not verified; J: not interpreted |
| 0x1C | `iCompressionType` | same (J); `iCheckSumData` (original) | Compression; original: reported, not verified |
| 0x20 | `iToolsVersion` | `iVersion` | `TVersion`: signed 8-bit major and minor, 16-bit build |
| 0x2C | `iFlags` | same | Header format, DLL, ABI, entry point type, import format, hardware floating point |
| 0x30, 0x34, 0x44 | `iCodeSize`, `iDataSize`, `iBssSize` | same | Part sizes in bytes |
| 0x48 | `iEntryPoint` | same | Offset into the code part |
| 0x4C, 0x50 | `iCodeBase`, `iDataBase` | same | Link addresses of the parts |
| 0x60 | `iTextSize` | same | Text at the start of the code part |
| 0x64, 0x68 | `iCodeOffset`, `iDataOffset` | same | File offsets of the parts; `iCodeOffset` is also the header size |
| 0x7A | `iCpuIdentifier` (16 bits) | - | V: the CPU |
| 0x7C | `iUncompressedSize` | same (compressed J only) | V: bytes after the header once decompressed; J: not interpreted |
| 0x80-0x8C | `iS`: `iSecureId`, `iVendorId`, `iCaps[2]` | - | Metadata |
| 0x98, 0x9A | `iExportDescSize` (16 bits), `iExportDescType` | - | The header ends at 0x98 + the 3 bytes of these fields + the description, rounded up to 4 (`ValidateExportDescription`) |

`TCpu` (K1 line 35) maps to the target:

| Value | Enumerator | Target | Variant |
| --- | --- | --- | --- |
| 0x0000 | `ECpuUnknown` | None: the code model may answer from the code part | `Symbian E32 image` |
| 0x1000 | `ECpuX86` | x86, 32-bit, little-endian | `x86` |
| 0x2000 | `ECpuArmV4` | ARM, 32-bit, little-endian | `ARMv4` |
| 0x2001 | `ECpuArmV5` | ARM, 32-bit, little-endian | `ARMv5` |
| 0x2002 | `ECpuArmV6` | ARM, 32-bit, little-endian | `ARMv6` |
| 0x4000 | `ECpuMCore` | C-SKY, 32-bit, little-endian: the classifier maps `EM_MCORE` to C-SKY (`src/formats/elf.rs`, machine 0x27; `tests/idaref.rs`, `mcore_`) | `M*CORE` |
| other | not a `TCpu` value | None, noted | `Symbian E32 image` |

The UID checksum is `TCheckedUid::Check` (K1 `us_func.cpp`): the CRC-16 of
the odd bytes of the 12 UID bytes in the high half and of the even bytes
in the low half, where `Mem::Crc` is polynomial 0x1021, register 0, most
significant bit first, no final XOR. The parser uses the SIS family's
`uid_checksum` (`src/formats/sis.rs`), the same algorithm. The V header CRC
is `Mem::Crc32` (reflected polynomial 0xEDB88320, register 0, no final XOR)
over `iCodeOffset` header bytes with `iHeaderCrc` replaced by
`KImageCrcInitialiser` 0xC90FDAA2 (`ValidateHeader`, lines 662-668). Both
checks matched on every intact IDA sample (below); a mismatch is noted with
the computed value and the image is still reported, since the loader's
rejection does not change what the header says.

### Detection

`epoc::detect` is true exactly when the four bytes at 0x10 are `EPOC`. The
check stays where it was in `formats::detect_format` (after the Palm
containers, before the WinOLS project files), and since it is strong a
damaged image is an `epoc` parse error rather than raw code.

The UID-only fallback (one of five known UID1 values with UID2 and UID3
each zero or `0x100xxxxx`, or UID2 `0x10003A12` with a `0x100xxxxx` UID3)
is removed rather than tightened.
The sources give no way to recognize an E32 image without its signature:
`E32ImageHeaderV::ValidateHeader` rejects any header whose `iSignature` is
not `EPOC` (`KErrCorrupt`, line 658), and the original header has the same
field (K3). A matching UID checksum would not help either: every Symbian
file that starts with UIDs carries one, including the inputs the fallback
claimed. In IDA's corpus those were `TRomImageHeader` ROM images (K1
`e32rom.h`: UIDs and their checksum, then the entry point and addresses; no
signature and no CPU field) and pre-v9 SIS packages (UID3 `0x10000419`).
Both now go to the other detectors and the code model.

## Wire units and byte order

All header fields are little-endian. Offsets and sizes are bytes; code and
data offsets are file offsets of an uncompressed image and offsets in the
uncompressed image of a compressed one (`ValidateHeader` checks them
against `iCodeOffset + iUncompressedSize`). Section offsets are file
offsets, section addresses are the link addresses `iCodeBase` and
`iDataBase`, and the reported entry point is `iCodeBase + iEntryPoint`.
The code byte order is little-endian for every named CPU: the loader reads
the header in place as a native structure (`ValidateHeader` dereferences
the buffer), so a CPU that loads a little-endian header is little-endian.

## Validation and resource bounds

Errors, in this order (`Symbian E32 image parse error: …`):

1. Fewer than 0x7C bytes (`Truncated E32 image header: N B of 124 B`), no
   signature, header format bits other than 0, `0x01000000` and
   `0x02000000` (`Unsupported E32 header format`), a V header shorter than
   0x9C bytes.
2. `iCodeOffset` below the format's header (0x9C for V, 0x7C otherwise),
   a V export description that does not end at `iCodeOffset`, or a stored
   header (0x80 B for a compressed J image, else `iCodeOffset`) beyond the
   file.
3. `iTextSize` above `iCodeSize`, or `iEntryPoint` at or after the end of
   the code part.
4. A code part beyond the image; data bytes without a data offset; a data
   part that starts inside the code part or ends beyond the image. The
   image is the file for an uncompressed image and `iCodeOffset +
   iUncompressedSize` for a compressed V image; the J format's
   uncompressed size is not interpreted, so its parts are not checked.

Arithmetic on header values is done in `u64` or with bounds-checked
slices; sections borrow the input and are concatenated for the code model
only up to `MAX_PAYLOAD` (64 MiB); a part that would exceed it is noted and
not analyzed. Nothing is allocated from a header value. The import, export
and relocation sections are not parsed, so the bytes after the data part
are not checked, and the whole file is the container (`epoc_image_size`).

Not enforced from `ValidateHeader` (the classifier reports what the header
says): UID1 against the DLL flag (noted for V), the module version range,
heap and stack sizes, alignment, the export directory, the import and
relocation offsets, and the CPU-dependent ABI and entry point checks.

## Notes and metadata

Notes give the header format and UID1 kind, the CPU and the target it
names, the UIDs with the UID checksum verdict, the V header CRC verdict
(or that the J and original headers have none, and the original format's
unverified code and data checksums), the flags (DLL or EXE; for ARM the
ABI and entry point type; the import format; VFP hardware floating point),
the tools and (V) module version, a V UID1 that contradicts the DLL flag,
the code and data parts with their link addresses and the BSS size, or the
compression, and that the import, export and relocation sections are not
parsed. Metadata keys are `epoc_uid1`, `epoc_uid2`, `epoc_uid3`,
`epoc_header_format`, `epoc_cpu`, `epoc_flags`, `epoc_compression`,
`epoc_code_base`, `epoc_data_base`, `epoc_entry_offset` and, for V,
`epoc_uncompressed_size`, `epoc_secure_id`, `epoc_vendor_id`,
`epoc_capabilities` and `epoc_export_description`, plus the generated
`epoc_image_size`, `epoc_section_N` and `epoc_component_N`.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| A1 | Before the V format, the CPU is the 32-bit word at 0x14 | K2 `CpuIdentifier` returns `(TCpu)iHeaderCrc` for formats below V; K3 lists `iCpu` after `iSignature`. All six intact J and original samples in IDA's corpus hold 0x2000 there. An original-format image from an x86 or M*CORE build (none available) would show whether those builds used the same field |
| A2 | `ECpuArmV4` 0x2000 names ARMv4 in every format | The original-format comment (K3) says only "0x2000 = ARM"; the variant `ARMv4` is the `TCpu` name of K1 and K2. An EKA1 image built for ARMv5 or later with CPU 0x2000 would make the variant too narrow |
| A3 | The code byte order is little-endian for every named CPU | The header is read in place by the loader on the target (`ValidateHeader`). A big-endian E32 image would carry byte-swapped UIDs and `COPE` at 0x10, which this parser does not detect; none is known |
| A4 | `ECpuMCore` is reported as C-SKY | The classifier maps `EM_MCORE` to C-SKY elsewhere; no M*CORE E32 image was available, so the mapping is not verified against code |
| A5 | The original format's words at 0x18 and 0x1C are the code and data checksums and are only reported | K3 names them "sum of all 32 bit words in .text/.data". In IDA's samples the word sum over the whole code part matched for 3 of 5 original images and not for the two CommWarrior samples, so the definition is not established and the checksums are not verified |
| A6 | A compressed J image stores its contents from 0x80 | K2 `TotalSize` returns `sizeof(E32ImageHeaderComp)`; `arm_calcsoft_app.epoc` has a word at 0x7C and high-entropy bytes from 0x80. Its `iUncompressedSize` plus 0x7C equals the stored file size, so whether K2's "file size - sizeof(E32ImageHeader)" means the stored or the uncompressed file is not established, and the value is not interpreted |
| A7 | Symbian deflate (0x101F7AFC) is not RFC 1951 | `sf_deflate.h`: a 4 KiB window (`KDeflateDistanceMag` 12), 256 literals, 28 length codes and one end code, 44 distance codes (`TEncoding`), against RFC 1951's 32 KiB window and 286 literal/length codes. Probed on 2026-10-13: the contents of the five deflate samples in IDA's corpus (four V from 0x9C, `arm_calcsoft_app.epoc` from 0x80) fail Python's `zlib` as raw RFC 1951 data ("invalid block type") and as zlib streams |
| A8 | The time fields at 0x24 are not needed | The V comment calls them milliseconds since 2000, but the samples' values fit Symbian `TTime` microseconds since year 0; they are not reported |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Symbian deflate and byte-pair compression | Not decoded: neither is a codec in `compressed::`, so the contents are an opaque `Compressed contents` component and the code is not analyzed; the ISA comes from the header alone |
| Compressed contents' length | Not stored in the header; a truncated compressed image is still parsed (only a truncated header is an error) |
| Import, export and relocation sections | Not parsed or checked |
| ROM images (`TRomImageHeader`, execute-in-place images from Symbian ROMs) | Not implemented: a different structure without signature or CPU field; such files go to the code model |
| Pre-v9 SIS packages | Not implemented (see [Symbian SIS packages](sis.md)) |
| x86, M*CORE and unknown-CPU images | Verified only against synthetic fixtures |

## Changes from the previous parser

The previous `epoc.rs` read only the UIDs and reported every recognized
input as 32-bit little-endian ARM (variant `Symbian E32`), and recognized
files without the signature by their UIDs. Intentional changes:

- The ISA comes from the CPU identifier: x86 images are `x86`, M*CORE
  images `csky`, and images with `ECpuUnknown` or an undefined value have
  no named ISA (the code model may answer from the code part). The variant
  names the CPU.
- Files without `EPOC` at 0x10 are no longer `epoc`, whatever their UIDs.
- A damaged header (truncated, undefined header format, inconsistent
  sizes, parts outside the image) is an `epoc` parse error instead of ARM.
- Uncompressed images list their code and data parts as load sections;
  compressed images list their contents as an opaque `Compressed contents`
  slice.
- The routing moved from the legacy `parse_detected` path to the container
  model (`formats::parse_container_model` and the model arm of
  `classify_depth`, as for bFLT), so a parse error is no longer retried as
  raw code. `epoc::detect` and `epoc::parse` keep their names and
  signatures; `epoc::parse_container` is new.
- E32 members of SIS packages are classified by the new parser, so a
  member with a damaged header is listed with an unknown ISA.

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly), `tests/epoc.rs` (16
tests) and the module's unit tests (4) passed: every `TCpu` value in each
of the three header formats, unknown CPUs with and without code, the V,
J and original layouts with code and data sections, compressed V and J
images (deflate, byte-pair, an unknown method), the UID checksum against a
value from a real header and its mismatch, header CRC mismatches, the V
DLL/UID1 and floating-point notes, the former fallback inputs (a pre-v9
SIS header, a ROM image header, an E32 image with its signature
overwritten) not claimed, 13 corrupted-field errors with their exact
messages, every-prefix sweeps over an uncompressed V and an original
image (every prefix is an error), header-prefix sweeps over compressed V
and J images, and every-byte mutation sweeps (`0x00`, `0xFF`, each bit
flip) over four images. The fixtures are synthetic, built from the
documented layout by `tests/support/e32_image.rs` around the repository's
clang-compiled ARM testbin, with the UID checksum and header CRC computed
bit by bit there; one UID checksum is checked against IDA's
`arm_abook_app.epoc` header (`0x1E7CC9F8`). No Symbian tool (`elf2e32`,
`petran`) was available locally, so no image was generated by one.

With `IDA_INPUT_DIR=/Users/int/hexrays/ida/tests/input` (IDA's test
inputs, read in place and not redistributed) the gated test passed: the 12
intact E32 samples (`arm_abook_app`, `arm_app`, `arm_app_caribe`,
`arm_app_qfileman1`, `arm_bytepair`, `arm_calcsoft_app`,
`arm_commwarrior_infected`, `arm_filelist_app`, `arm_installserver`,
`arm_puttyengine`, `arm_trkdriver_ldd`, `arm_voicerecorder`) report
`epoc`, 32-bit little-endian ARM with their CPU variant (seven V, one J,
four original), matching UID checksums and, for V, matching header CRCs;
`arm_bad_export_cnt`, `arm_bad_huffman`, `arm_compressed_bad` and
`arm_worm_comwar_b` are parse errors; the 13 samples without the signature
are not claimed. `tests/sis.rs` passed with its gated test as well.

`tests/idaref.rs` with `IDAREF_DIR` set to the same directory (4,618
supported files) was run before and after the change. The `arm_` row went
from 758 correct, 82 inconclusive and 5 errors to 749 correct, 87
inconclusive and 9 errors (overall 88.2% to 88.0% correct, 0.2% wrong both
times; the suite's thresholds still pass). A per-file dump of format,
primary ISA and slices over the 4,692 files the suite reads changed for
exactly these 24 files, all `.epoc`:

| Files | Before | After |
| --- | --- | --- |
| `arm_bad_export_cnt`, `arm_bad_huffman`, `arm_compressed_bad`, `arm_worm_comwar_b` | `epoc`, ARM | `epoc` parse errors (header size beyond the file, export descriptions that do not end the header, a code part cut short) |
| `arm_ekern_eka2`, `arm_euser_eka2`, `arm_huge_codeseg`, `arm_rom`, `arm_rom2`, `arm_rom3`, `arm_rom_sysagt`, `arm_corrupted_bad` | `epoc` by the UID fallback, ARM | Raw, ARM from the code model (ROM image headers; `arm_corrupted_bad` a pre-v9 SIS file) |
| `arm_bad_filename_ptr`, `arm_sis`, `arm_sis_ptr0_bad`, `arm_uncomperr_sis6` | `epoc` by the UID fallback, ARM | Inconclusive (pre-v9 SIS packages) |
| `arm_bad_impend` (SIS 9) | Primary ARM from `!:\sys\bin\Slick.exe` | Primary unknown: the member's header is damaged (code size 0xFFFFFFFF, wrong header CRC) |
| `arm_abook_app`, `arm_bytepair`, `arm_calcsoft_app`, `arm_filelist_app`, `arm_puttyengine`, `arm_trkdriver_ldd`, `arm_voicerecorder` | `epoc`, ARM | Unchanged ISA; now with the opaque `Compressed contents` slice |

The whole native suite (`cargo test --all-features --locked`) passed 2,258
tests with 6 ignored. After `./build-web.sh`, `web/tests/epoc.test.mjs` (4
tests) and `web/tests/sis.test.mjs` (4 tests, whose executable fixture now
has a complete V header from `web/tests/e32-image.mjs`) passed through
`/pkg/zrax.js`, `/dist/zrax.js` and both workbench pages, and the full
browser suite passed 260 of 264 tests with 4 skips (D10/RX113 firmware not
in the repository).

Not verified: x86, M*CORE and unknown-CPU images, ARMv6 images, data
parts and BSS of real images other than `arm_commwarrior_infected.epoc`
(the only sample with a data part in an uncompressed image that parses),
and anything about the compressed contents beyond their range.

At integration on the same day the native suite passed 2,258 tests with 6
ignored, and the gated `tests/epoc.rs` and `tests/sis.rs` passed with
`IDA_INPUT_DIR` set. On IDA's corpus (4,621 files) nine files that the UID
fallback or the unconditional ARM result had counted as correct changed:
`arm_bad_export_cnt`, `arm_bad_huffman`, `arm_compressed_bad` and
`arm_worm_comwar_b` became parse errors (damaged or truncated headers);
the pre-v9 SIS packages `arm_bad_filename_ptr`, `arm_sis`,
`arm_sis_ptr0_bad` and `arm_uncomperr_sis6` became inconclusive; and the
SIS 9 package `arm_bad_impend` now has an unknown primary ISA, because its
executable's header is damaged. Correct fell from 88.2% to 88.0%; wrong
stayed 0.2%.
