# Symbian SIS packages

`src/formats/sis.rs` (with `sis/controller.rs` and `sis/data.rs`) parses
the software installation packages of Symbian OS v9 and later (`.sis`,
`.sisx`). The family is built on the shared container model
([compressed streams and the container model](compressed-streams.md)).

A SIS 9 file is a 16-byte Symbian file header followed by one
`SISContents` field. Everything after the header is a tree of `SISField`s
(type, length, value, padding). `SISContents` holds two optional CRC-16s,
the `SISController` with the package metadata (normally zlib-compressed)
and `SISData` with the files. The package names no processor, so the
container has no target; its files are children, and the ones in a
recognized format (E32 executables, archives) are listed and classified on
their own bytes.

## Implemented layouts

| JSON format ID | Layout (`format.variant_name`) | Recognition | Architecture evidence | Primary sources |
| --- | --- | --- | --- | --- |
| `symbiansis` | `Symbian OS v9 SIS package`: header, `SISContents` (checksums, `SISCompressed<SISController>`, `SISData`), only `0x00`/`0xFF` after it | Strong: UID1 `0x10201A7A` at 0 and the `SISContents` field type 12 at 0x10 (64 bits of key). The UID checksum and every field are then checked by the parser, so a damaged package is a parse error | None in the format. The primary ISA comes from the first listed file with a known ISA, in the order below; E32 executables are classified by the existing EPOC parser | S1, S2, S3 below |

| ID | Source | Pin |
| --- | --- | --- |
| S1 | "Symbian OS v9.X SIS File Format Specification", version 1.1, June 2006, Symbian Software Ltd (the code cites it as SGL.GT0188.251) | `https://web.archive.org/web/20101011053920/http://developer.symbian.org/wiki/images/b/b7/SymbianOSv9.x_SIS_File_Format_Specification.pdf`, 359,986 B, SHA-256 `73176539a69e30f18308a9d3ab68354083cd1963064b45e17b2ffcf01e93115b`; fetched 2026-10-13 |
| S2 | The device installer's reader, Symbian Foundation `appinstall` (EPL 1.0): `installationservices/swi/source/sisfile/` (`sisparser.cpp`, `sisfield.cpp`, `siscontents.cpp`, `siscontroller.cpp`, `sisinfo.cpp`, `siscompressed.cpp`, `sisdata.cpp`, `sisdataunit.cpp`, `sisfiledata.cpp`, `sisfiledescription.cpp`, `sisinstallblock.cpp`, `sisif.cpp`, `siselseif.cpp`, `sisstring.cpp`, `siscapabilities.cpp`, `sislogo.cpp`, `sissignaturecertificatechain.cpp`), `installationservices/swi/inc/swi/sisfieldtypes.h`, `sisfield.h`, `installtypes.h` | `github.com/SymbianSource/oss.FCL.sf.mw.appinstall` commit `760927eba63e3324cceee974b9ed582da90cb9a3`; SHA-256 of `sisparser.cpp` `e976c92452c984cb97e34048b7752b0fcddb4da12674196880ceb4e50298c94f`, `sisfield.cpp` `d047f310707c75a5addf5e17943be65920f27e23957530362428609aeb1b8c1f`, `siscontents.cpp` `81bbcc211e43fae31a9d6db84f2d93440b35715a82b48418cefb943e69d29fe4`, `siscontroller.cpp` `47a5e56dd3dcf29e4439f1f19451d338b31555abbe6484a38deded0e9a3c0ae3`, `sisfieldtypes.h` `b198f54b309067118a92c62184898156a8ad721ecc4970ae6d06603987c06028` |
| S3 | MakeSIS's library, same repository: `secureswitools/swisistools/source/sisxlibrary/fieldroot.cpp` (CRC-16), `siscontents.cpp` (header UIDs, UID checksum, CRC preparation), `siscompressed.h` and `siscompressed.cpp` (zlib streams), `structure.h`, `container.h` | same commit; SHA-256 of `fieldroot.cpp` `035a22d891eb1c7cc8dca0d0d62874d064d556eabec079d2352cb7edb8a71660`, `siscontents.cpp` `223de10656b66e517a19074667122ef550b837a9c8aa47917a576e7b9151cccd`, `siscompressed.h` `828075e0b6ababef598bf2f3b614c117f3117847fff9ef73e6b4a71c95cde272` |

Detection order in `formats::detect_format`: the strong check runs after
the Psy-Q check and before the magic-bearing compressed streams. It comes
long before the EPOC check, which then also accepted known E32 UID1 values
including `0x10201A7A`: before this family, a SIS 9 package whose UID3 lay
in `0x10000000`-`0x100FFFFF` was reported as an E32 image, and any other
went to the code model. The EPOC check now needs the `EPOC` signature
([Symbian E32 images](epoc.md)). An E32 image carries `EPOC` at 0x10, not
type 12, so E32 images (including IDA's `arm_bad_huffman.epoc`, which has
the SIS UID1 and an E32 header) stay with the EPOC parser.

## Structure

| Structure (type) | Members read, in order | Used for | Sources |
| --- | --- | --- | --- |
| File header | UID1, UID2, UID3, UID checksum (4 B each, little-endian) | UID1 must be `0x10201A7A`; the UID checksum must match; UID3 compared with the package UID; UID2 in metadata | S1 3.1; S2 `ReadSymbianHeaderL`, `CheckUidCrc` |
| `SISContents` (12) | [`SISControllerChecksum` (34)], [`SISDataChecksum` (35)], `SISCompressed` (3), `SISData` (30) | Checksums, controller, data, in exactly this order | S1 4.2.1; S2 `CContents::ConstructL` |
| `SISCompressed` (3) | u32 algorithm, u64 uncompressed size, stored bytes | Algorithm 0 (stored) or 1 (deflate, as zlib streams) | S1 4.1.3; S2 `CCompressed`; S3 `CompressData` |
| `SISController` (13) | `SISInfo`, `SISSupportedOptions`, `SISSupportedLanguages` (counted), `SISPrerequisites`, `SISProperties`, [`SISLogo`], `SISInstallBlock`, 0..N `SISSignatureCertificateChain` (counted), `SISDataIndex` | Package identity, files, embedded packages, signatures | S1 4.2.4; S2 `CController::ConstructL` |
| `SISInfo` (14) | `SISUid`, unique vendor `SISString`, names and vendor names (`SISArray<SISString>`), `SISVersion`, `SISDateTime`, u8 install type, u8 install flags | Notes and metadata (first-language names) | S1 4.2.5; S2 `CInfo` |
| `SISInstallBlock` (28) | `SISArray<SISFileDescription>`, `SISArray<SISController>` (embedded packages), `SISArray<SISIf>` | Every branch is walked: which one installs depends on the device | S1 4.4.3; S2 `CInstallBlock` |
| `SISIf` (26), `SISElseIf` (27) | `SISExpression` (skipped), `SISInstallBlock`, and for `SISIf` a `SISArray<SISElseIf>` | Files of conditional branches | S1 4.4.1-4.4.2 |
| `SISFileDescription` (24) | target and MIME type `SISString`s, [`SISCapabilities` (length a multiple of 4)], `SISHash` (u32 algorithm, `SISBlob`), u32 operation, u32 options, u64 length, u64 uncompressed length, u32 file index | Child labels and SHA-1 checks | S1 4.2.14-4.2.16; S2 `CFileDescription` |
| `SISData` (30) | `SISArray<SISDataUnit>`; each unit a `SISArray<SISFileData>`; each file a typed `SISCompressed` | The stored files | S1 4.5; S2 `CData`, `CDataUnit`, `CFileData` |

Other members (`SISSupportedOptions`, `SISPrerequisites`, `SISProperties`,
`SISExpression`, signature contents) are checked for their type and length
and skipped. Fields after the members a structure defines are skipped as
unknown extensions, as the installer does (S1 2.3; S2
`SkipUnknownFieldsL`).

The data unit of a controller is the sum of the data indices from the
outermost controller down to it (S1 2.8 and 4.1.12): an embedded package
with data index 1 inside the main package (index 0) uses unit 1, and a
package it embeds with index 1 uses unit 2. A file description names file
`file index` of its controller's unit; the first description of a file
labels it.

## Components

| Component | Label | Classified |
| --- | --- | --- |
| A stored file whose first 4 KiB (decoded), and then whole contents, are a recognized format | The target path of the description that names it (`!:\sys\bin\hello.exe`); `Logo (data unit U file I)` for a logo without a target; `Data unit U file I` when no description names the file or its target is empty | As an archive member (`if_recognized`): E32 executables by the EPOC parser, other recognized formats by theirs |
| Any other stored file (resources, icons, text, data) | Not listed | Counted in a note |

A deflated file is a decoded child: its offset and stored size are the
zlib stream's in the file, and its decoded range is the file
(`transform` `zlib`). A stored file is listed as its stored bytes. The
package's own data unit is listed first, then the units of embedded
packages in stored order, so the main package's executable decides the
primary ISA.

Notes: the package name, UID, version and vendor; install type, flags and
language count; a header UID3 that differs from the package UID; stored
files, data units and descriptions; install targets (8 shown, the rest
counted); how many examined files were listed; SHA-1 results; files that
do not decode, use an unsupported algorithm or exceed the limits;
descriptions that name no stored file; embedded packages; signature chains;
both CRC-16 results; stub packages (no data units); skipped unknown fields
and padding after `SISContents`. Metadata: `sis_package_uid`,
`sis_package_name`, `sis_vendor`, `sis_vendor_name`, `sis_version`,
`sis_install_type`, `sis_install_flags`, `sis_creation_time` (labelled not
authenticated), `sis_languages`, `sis_header_uid2`,
`sis_controller_compression`, `sis_controller_crc`, `sis_data_crc`,
`sis_signature_chains`, `sis_file_descriptions`, `sis_data_units`,
`sis_stored_files`, `sis_embedded_packages`, and the generated
`sis_image_size` and `sis_component_<i>`.

## Wire units and byte order

All meta-data is little-endian (S1 2.9), on every device. Lengths and
sizes are bytes; offsets in error messages are file offsets, or
`controller offset 0x…` inside the decoded controller. A field's length
is 31 bits, or 63 bits when bit 31 of the first word is set: the second
word then holds the high bits shifted left by one, with bit 31 of the
length in its bit 0 (S1 2.12.1.2; S2 `CField::ReadLengthL`). Every field
is padded with zero bytes to a 4-byte boundary (S1 2.12.2); inside a
`SISArray` an element omits its type (S1 4.1.2). Strings are UCS-2
little-endian (S1 2.10). Months in `SISDate` count from 0 and are shown
from 1. The package encodes no code byte order; each listed file's own
parser reports one.

## Validation and resource bounds

- Header: 16 bytes, UID1 `0x10201A7A` and a matching UID checksum (CRC-16
  of the UIDs' odd bytes in the high half, even bytes in the low half; the
  installer rejects a mismatch with `KErrCorrupt`).
- Every field's header and value lie inside the enclosing value (the file
  for `SISContents`); arrays hold their declared element type and are
  filled exactly by their elements, padding included
  (`KErrSISArrayReadError`); typed members have the type the structure
  requires; strings have an even length; `SISCapabilities` lengths are
  multiples of 4 (all as the installer checks them).
- The controller is decoded to exactly its declared size, at most 64 MiB
  (`MAX_PAYLOAD`); an algorithm other than 0 or 1 is an error for the
  controller. The installer itself rejects sizes from `KMaxTInt / 2`
  (about 1 GiB) up.
- Embedded packages: at most 8 levels below the main package, as the
  installer processes (S1 2.5); deeper embedding is an error. Conditional
  install blocks: at most 32 nested levels per controller (our bound; S1
  sets none, and each level is a recursion).
- Only `0x00`/`0xFF` may follow `SISContents` (counted in a note); any
  other byte is an error, although the installer ignores such bytes.
- Files: at most 4096 listed (`MAX_COMPONENTS`), the rest counted. A
  deflated file is first decoded to its first 4 KiB; only a recognized
  prefix leads to a full decode, of at most its declared size, 64 MiB per
  file and 256 MiB per package (`MAX_EXTRACTED`, counted by declared
  size before decoding). A file that does not decode to its declared size,
  a stored file whose size differs from its declaration and an unknown
  algorithm are noted and the file is not listed.
- Integrity: the controller and data CRC-16s (polynomial 0x1021, initial
  value 0, no reflection or final XOR, over the whole field from its type
  through its zero padding; S1 4.2.2-4.2.3, S3 `DoTheCrc`) are verified
  and a mismatch is noted, not rejected: the installer does not check them
  (S2 `SIS_CRC_CHECK_ENABLED` is disabled because files made before
  DEF063815 carry wrong CRCs). A field over 64 MiB is reported as not
  verified. The SHA-1 in each listed file's `SISHash` is compared with the
  decoded file. Signatures and certificates are reported as present and
  never verified.
- Memory: element lists grow only with elements actually present (each at
  least 4 bytes), strings keep at most 256 characters, notes at most 8
  names.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| A1 | Algorithm 1 is a zlib (RFC 1950) stream, though S1 says RFC 1951 | S3 compresses with `deflateInit`; on 2026-10-13 every deflated stream reachable in IDA's four SIS 9 packages (4 controllers, 42 files) started `78 9C`. A package from another tool with raw DEFLATE would fail to decode its controller |
| A2 | The CRC-16s cover the whole field, type through zero padding | S1 says "over the whole of the SISCompressed<SISController>"; S3 adds the header and padding; on 2026-10-13 the stored CRCs of `arm_logexportv11_sis9` (0xDCAA, 0x15A2) and the controller CRC of `arm_bad_impend` (0x9514) matched the computation, while the tampered samples' did not |
| A3 | The UID checksum is the CRC-16 above over alternate UID bytes | S2 `CheckUidCrc`, S3 `UidChecksum`; matched all four SIS 9 samples |
| A4 | `SISHash` is the SHA-1 of the uncompressed file | S1 4.2.14.4; matched all five files of `arm_logexportv11_sis9` |
| A5 | Data units are found by summing data indices down the embedding chain | S1 2.8 and 4.1.12 with a worked example; no sample with embedded packages was available |
| A6 | A file description with an empty target names a file that is not installed (a text, run or logo file) | S1 4.2.14.1 |
| A7 | The embedding limit of 8 counts levels below the main package | S1 2.5 says the installer processes "the nesting of SIS files down to a depth of 8"; probe with a 9-level package on a device |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Pre-v9 EPOC SIS files (UID3 `0x10000419`; EPOC release 3-6, Symbian OS up to v8) | Not implemented: no Symbian specification was found, only a reverse-engineered description (A. Thoukydides, "SIS File Format" 1.07, 2001) that says it "probably contains both errors and omissions" and gives UID2 as always `0x1000006D`, while two of IDA's four pre-v9 samples (`arm_sis.epoc`, `arm_uncomperr_sis6.epoc`) carry `0x10003A12`. No format claims them: since the E32 parser fix ([Symbian E32 images](epoc.md)) the EPOC check needs the `EPOC` signature, so they go to the code model |
| E32 executables inside a package | Classified by the EPOC parser from their own header's CPU identifier ([Symbian E32 images](epoc.md)); an executable with a damaged header is listed with an unknown ISA and the parse error in a note |
| Signatures, certificate chains, capabilities | Counted or skipped; never verified or decoded |
| Conditions (`SISExpression`), options, languages, prerequisites, properties | Not evaluated; every conditional branch's files are listed |
| Files in no recognized format (resources, icons, text, data) | Counted, not listed |
| Stub packages (preinstalled PA/PP types, removable-media stubs) | Parsed; noted as having no data units |
| Packages over 64 MiB of controller, or deflated files over the limits above | Controller: a parse error; files: noted, not decoded |

## Verification

On 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly `f248f4038`),
`cargo test --all-features --locked` passed: 1,862 tests in 54 test
binaries, 6 ignored (the existing ignores that need external data). They
include `tests/sis.rs` (14 tests) and 7 unit tests in `src/formats/sis.rs`:
deflated and stored controllers and files with stored offsets and decoded
ranges, notes and metadata, signature chains, embedded packages with summed
data indices and main-unit-first ordering, conditional blocks and logos,
CRC-16 and SHA-1 mismatches (and a SHA-1 pinned to a digest computed with
Python's `hashlib`), stub packages, files that do not decode, an unknown
algorithm, header, controller and structure errors, data after
`SISContents`, the embedding and block-nesting bounds, the component and
extraction limits, an every-prefix truncation sweep and an every-byte
mutation sweep (`0x00`, `0xFF` and each bit flip) of two packages. The
fixtures are synthetic, built in the tests from the layouts above: no SIS
tool (MakeSIS, SignSIS) was available locally, so no package was generated
by one.

With `IDA_INPUT_DIR=/Users/int/hexrays/ida/tests/input` (IDA's test inputs,
read in place and not redistributed), `arm_logexportv11_sis9.epoc`
classified as a package whose `!:\sys\bin\LogExport.exe` (22,407 B
stored, 30,933 B decoded) is a 32-bit little-endian Arm E32 image, with
both CRC-16s and the SHA-1 matching; `arm_bad_impend.epoc` classified with
its data CRC-16 and its executable's SHA-1 reported as not matching and
one deflated file reported as not decoding; `arm_bad_stkovr.epoc` (a
controller zlib stream that does not inflate) and
`arm_bad_uncompressed_size.epoc` (a `SISFileData` length beyond its data
unit) failed with bounded parse errors; and `arm_bad_huffman.epoc` (SIS
UID1, wrong UID checksum, `EPOC` at 0x10) stayed an EPOC image. Without the
variable that test is skipped. Of the 44,347 files under that directory,
only these five start with UID1 `0x10201A7A`, and only the four SIS 9
packages are claimed by this family; before it, the four were inconclusive
(code model below threshold) and `arm_bad_huffman.epoc` was EPOC.

After `./build-web.sh`, `web/tests/sis.test.mjs` passed 4 of 4
(`/pkg/zrax.js`, `/dist/zrax.js`, `/web/index.html` and `/dist/index.html`),
and the full browser suite passed 212 of 216 with 4 skips (D10/RX113
firmware not in the repository).

After integration with the families added since (through ARM AIF and PE
ARM64EC detection) on the same day, the native suite passed 1,895 tests
with 6 ignored and the gated test passed again. On IDA's corpus (4,621
files), `arm_bad_impend.epoc` and `arm_logexportv11_sis9.epoc` went from
inconclusive to Arm, and `arm_bad_stkovr.epoc` and
`arm_bad_uncompressed_size.epoc` from inconclusive to parse errors; no
other file changed.

On 2026-10-13, after the E32 parser fix ([Symbian E32 images](epoc.md)),
the tests build their executables with complete V headers, and the gated
test passed with two changed expectations: `arm_bad_impend.epoc`'s
`!:\sys\bin\Slick.exe` (code size 0xFFFFFFFF, wrong header CRC) is listed
with an unknown ISA, so the package's primary ISA is unknown, and
`arm_bad_huffman.epoc` is an EPOC parse error.

Not verified: packages with embedded SIS files, conditional blocks or
63-bit lengths from a real tool (only synthetic ones were tested), signed
packages beyond counting their chains, and pre-v9 files.
