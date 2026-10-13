# PC/GEOS geodes

`src/formats/geos.rs` parses PC/GEOS geodes, the `.geo` executables
(applications, libraries and drivers) of PC/GEOS 1.x and of PC/GEOS 2.0 and
later, into the shared container model ([compressed streams and the container model](compressed-streams.md)).
Each resource with data is a component. Resources whose allocation flags
carry `HAF_CODE` are classified as 16-bit x86 code; every other resource
(dgroup, local-memory and object blocks, other data) is opaque and never
reaches the code model.

No header field names a processor. The PC/GEOS sources fix the platform:
the memory manager "uses real mode memory addressing" with "the segmented
addressing scheme used by the 80x86 processors" (`TechDocs/ascii/Concepts/cmemory.txt`
section 15.2), Esp, the system's assembler, "is an 80x86 assembly language
specially designed for GEOS programming" (`TechDocs/ascii/Esp/eintro.txt`
section 1.1), and the relocation types rewrite x86 far calls into `INT 80h`
to `INT 8Fh` and store `handle >> 4` as a real-mode segment
(`Include/Internal/geodeStr.def`). That platform evidence is applied only
to resources the geode itself marks as code.

## Implemented layouts

| JSON format ID | Layout (`format.variant_name`) | Recognition | Architecture evidence | Primary sources |
| --- | --- | --- | --- | --- |
| `geosgeode` | `PC/GEOS 2.0+ geode`: 256-byte `GeosFileHeader2`, executable header, core block, tables, resources; positions relative to the end of the file header | Strong: `C7 45 C1 53` (`'G' or 0x80, 'E', 'A' or 0x80, 'S'`) at 0 | `HAF_CODE` resources are 16-bit x86 (platform); other resources opaque | `Include/Internal/fileStr.def` `GeosFileHeader`; `Tools/include/os90File.h` `GeosFileHeader2`; `Tools/include/geode.h` `ExecutableFileHeader2`, `GeodeHeader2`; `Tools/glue/geo.c` |
| `geosgeode` | `PC/GEOS 1.x geode`: 200-byte `GeosFileHeader` (`GeosFileHeaderOld`), the same tables; positions are file offsets | Strong: `C7 45 CF 53` (`'G' or 0x80, 'E', 'O' or 0x80, 'S'`) at 0 | As above | `fileStr.def` `GeosFileHeaderOld`; `os90File.h` `GeosFileHeader`; `geode.h` `ExecutableFileHeader`, `GeodeHeader`; `geo.c` (`geosRelease < 2`) |

The signature starts every PC/GEOS file on a DOS filesystem (`fileStr.def`:
"Standard file header for FAT filesystems"), so both layouts are recognized
from it alone, and a damaged geode is a parse error rather than raw code. A
PC/GEOS file of another type (VM file, data file, directory) is a parse
error naming its type. Marcus Groeber's `Tools/geodump` reader agrees on
both signatures (`GEOS_ID 0x53CF45C7`, `GEOS2_ID 0x53C145C7`) and on the
position bases.

Structures read, in file order:

| Structure | Fields read | Primary source |
| --- | --- | --- |
| 2.0 file header (256 B) | signature (0), long name (0x04, 36), file type (0x28), flags (0x2A, `GFHF_DBCS` 0x0400), release (0x2C), protocol (0x34), token (0x38), creator (0x3E), copyright notice (0xA8, 32), created date and time (0xC8, 0xCA) | `os90File.h`; `Include/file.def` (`GeosFileType`, `GeosFileHeaderFlags`, `FileDate`, `FileTime`) |
| 1.x file header (200 B) | signature (0), file type (0x04), flags (0x06), release (0x08), protocol (0x10), token (0x14), creator (0x1A), long name (0x20, 36), copyright in the reserved bytes (0xA8, 32) | `os90File.h` `GeosFileHeaderCore`; `geo.c` |
| Executable header (24 B) | attributes (0), geode type (2: 1 application, 2 library, 3 driver), heap space in paragraphs (4, 2.0) or kernel protocol (4, 1.x), resource, imported library and exported entry counts (8, 10, 12), udata size (14), process class (16), application object (20) | `geodeStr.def` `ExecutableFileHeader`; `geode.h`; `Include/geode.def` `GeodeAttrs` |
| Core block (64 B) | attributes and type copies (2, 4), release and protocol copies (6, 14), serial (18), permanent name (20, 8) and extension (28, 4), driver table (40), library entry (44), exported entry count (50), imported library count (52), resource count (56) | `geodeStr.def` `GeodeHeader` up to `GH_endOfVariablesFromFile`; `geodesLoad.asm` `AllocateCoreBlock` |
| Imported libraries (14 B each) | name (8, blank padded), attributes, expected protocol | `geodeStr.def` `ImportedLibraryEntry`; `geodesLoad.asm` (`CheckHack <size ImportedLibraryEntry eq 14>`) |
| Exported entry points (4 B each) | offset, resource (0, 0 for an empty slot) | `geo.c` ("two words with the low word containing the offset and the high the resource number") |
| Resource table (10 B per resource, four arrays) | sizes (words), file positions (dwords), relocation table sizes (words, bytes), allocation flags (words: `HeapFlags` low, `HeapAllocFlags` high) | `geo.c` ("This thing comes in four pieces"); `geodesLoad.asm`; `Include/heap.def`; `geode.h` `RESF_*` |
| Resource data and relocations | `size` bytes at the position; the relocation table (`GeodeRelocationEntry`, 4 B) right after the data padded to a paragraph | `geo.c` (`roff == foff + ((size+15) & ~15)`); `geodesResource.asm` `LoadResourceData`, `DoLoadResource`; `geodump.c` |

Resource 0 is the core block (`geo.c`: "the global segment takes on the
resource ID and persona of the core block"; `geodesLoad.asm`: "first
resource (core block) is skipped") and resource 1 dgroup (`PreLoadResources`
"load dgroup specially"). Component labels name what the flags say a
resource holds: `code` (`HAF_CODE` 0x0200), `dgroup`, `object block`
(`HAF_OBJECT_RESOURCE` 0x0400), `LMem block` (`HF_LMEM` 0x0008), `fixed
data` (`HF_FIXED` 0x0080) or `data`.

Source pins: all files from `github.com/bluewaysw/pcgeos` at commit
`8f0ca5d8f1cdd57d60438f813203eabb0a8cff55` (fetched 2026-10-13):

| File | SHA-256 |
| --- | --- |
| `Include/Internal/fileStr.def` | `3a6d0f2b5e2cb5509b7e504f58062923238629a8506c07311be55d79c49ac3f7` |
| `Include/Internal/geodeStr.def` | `66cc92fa0969d9fe0be99e641ab3cf503155bc4ce3911a4967f1e461d623b6c5` |
| `Include/geode.def` | `bb6c64a3315cb9d567c9b853198b53343d3f87c5d4dcb396e08475c4e510a28d` |
| `Include/file.def` | `6795782e50a76a4c8bbbc23f362b807500c1e33efd2188829370dd01737a5278` |
| `Include/heap.def` | `c17a46ee1dfc6712eb6f17af0f69489a149a95762614b883d6efffff53db29d9` |
| `Include/unicode.def` | `423bc2e4b4d8380a3208aef4a277da8a96f933851c93d4fe3be0836ad96721ad` |
| `Tools/include/geode.h` | `08203ee2378fc7a3679781e84bc771fb04fe27b566f46a379756da126eb333a0` |
| `Tools/include/os90File.h` | `d96ae2301b9ee8a7703791a14aceaf62fd1ae44fb825d5913da9e0ba05f8f503` |
| `Tools/glue/geo.c` | `36502f5293fd78bbc3e41900a5e33566481a6384dadd41fff3d1482b0445b0d9` |
| `Tools/geodump/geodump.c` | `57fd33fc6ca13794b4826889a2b1673514087e6a3daccd13f6ab97fc2e150782` |
| `Tools/geodump/geos.h` | `99c13de2f01ea850ef95193b07d5080ffe94a34bae4c06965cfeea6b0deaa2dc` |
| `Tools/geodump/geos2.h` | `14e0b808b16944cae275f719a8134b663375161b6106b15a5622153fc961e2bc` |
| `Library/Kernel/Geodes/geodesLoad.asm` | `0316770200aae88cbbb0862ba16a3140ca9e16a845d59391da6abadc8dfc8bae` |
| `Library/Kernel/Geodes/geodesResource.asm` | `c5c9e7657dfdfed11a25559c43f5e7c4d065d16c72df044695912e1e37e9771e` |
| `TechDocs/ascii/Concepts/cmemory.txt` | `cacda17749c1d0b1ba3fed3761710227db3e124a43030c4c01aa1584264d465c` |
| `TechDocs/ascii/Esp/eintro.txt` | `0fd7c998d7478d74d92f0104c3bfd9411cfd29a5973e85bfe5727975fb6eb636` |

Detection order in `formats::detect_format`: the check runs after EROFS and
before the magic-bearing compressed streams. No earlier format starts with
`C7 45 C1 53` or `C7 45 CF 53`.

## Wire units and byte order

All offsets and sizes are bytes, and every field is little-endian (`glue`
swaps the whole header to 8086 order and writes the tables low byte
first). 2.0 resource positions are relative to the end of the 256-byte file
header ("All file offsets are from the end of this header", `os90File.h`;
the kernel never sees that header); 1.x positions are file offsets.
Component offsets in slices and metadata are always file offsets. Resource
relocation counts are the relocation table sizes divided by 4. The 2.0 heap
space requirement is in paragraphs (16 B), as `GeodeEnsureEnoughHeapSpace`
says. The code byte order is little-endian (x86).

## Validation and resource bounds

- The file header, the 24-byte executable header and the 64-byte core
  block must be present; a truncation names the structure and its offset.
- The file type must be the executable type (1 in 2.0, 0 in 1.x).
- The executable header's resource, imported library and exported entry
  counts must equal the core block's: the kernel sizes the core block from
  the first and lays out its tables from the second, and `glue` writes both
  from one value. IDA's `pc_bad_class.geo` differs only there.
- A geode has at least two resources (core block and dgroup).
- Every exported entry point other than an empty slot names an existing
  resource.
- Counts are words, so the tables are at most 65,535 entries (14, 4 and
  10 B each); each table is bounds-checked before it is read, and nothing
  is allocated before its bytes are known to be present.
- Every resource with data or relocations must start after the tables,
  lie inside the file, and have a relocation table size that is a multiple
  of 4 B and lies inside the file after the paragraph-padded data. The
  padding of a resource without relocations may be missing at the end of
  the file. Resource sizes are words (at most 65,535 B; `glue` refuses more
  than 65,520 B).
- Bytes after the last resource may only be `0x00` or `0xFF` (noted with
  their size); anything else is a parse error.
- At most `MAX_COMPONENTS` (4,096) components are listed; the rest are
  counted in a note. Components borrow the input; nothing is copied or
  decoded.
- The imported library note and metadata name at most 32 geodes and count
  the rest.

## Notes and metadata

Notes give the geode type and long name, the permanent name and extension,
the attributes (`GeodeAttrs` names), release, protocol, token and creator,
the expected kernel protocol (1.x), the imported geodes with their expected
protocols (drivers marked), the exported entry count with the library entry
routine, driver table, process class and application object locations
(resource and offset), the resource, code and relocation counts, the
uninitialized data size, the heap space requirement, and any core-block
copy (attributes, type, release, protocol) that differs from the header it
copies. Relocations are counted, not applied, so code bytes are classified
as stored. Metadata keys are `geos_long_name`, `geos_permanent_name`,
`geos_geode_type`, `geos_attributes`, `geos_release`, `geos_protocol`,
`geos_token`, `geos_creator`, `geos_file_flags`, `geos_serial`,
`geos_resource_count`, `geos_export_count`, `geos_import_count`,
`geos_imports`, `geos_notice` and `geos_created`, plus the generated
`geos_image_size` and `geos_component_N`.

Names in the 8-bit GEOS character set are shown as printable ASCII with
other bytes escaped (`\xNN`): the upper half of that character set is not
Latin-1. When `GFHF_DBCS` is set in a 2.0 header, the long name is read as
16-bit characters, which `Include/unicode.def` defines with Unicode values.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| G1 | `HAF_CODE` marks every resource that holds executable code, and nothing else | A geode whose code runs from a resource without `HAF_CODE` would show it as opaque. IDA's `pc_nontsec.geo` has one: resource 2 (flags 0x0052) starts with `8C C8 8E D8` (`mov ax, cs; mov ds, ax`), x86 that the geode does not mark as code; how it is used was not examined, and it is listed as opaque `data` by design |
| G2 | Geode code is 16-bit real-mode x86 | Reported bit width is 16. Code that uses 80386 instructions in real mode would still be x86 but use 32-bit operand prefixes; not distinguished |
| G3 | 2.0 positions are relative to the 256-byte header, 1.x positions absolute | All seven IDA 2.0 samples end their last relocation table exactly at the end of the file. No 1.x sample was available: 1.x is checked only against the synthetic fixture built from `os90File.h`, `geode.h`, `geo.c` and `geodump.c` |
| G4 | Relocations follow the data padded to 16 B | `pc_dhcp.geo`: resource 2 (974 B at 0x1DA) has 0x70 B of relocations at 0x5AA, the next paragraph boundary |
| G5 | The serial (`GH_geodeSerial`) is a time stamp, not a checksum | `geodeStr.def` says "time stamp (SWAT uniqueness)"; `geodump.c` labels it "CRC?". Reported as a serial, never verified |
| G6 | A file starting with the signature is a PC/GEOS file | Rejecting non-executable types keeps VM and data files from being reported as geodes; a non-GEOS file starting with `C7 45 C1 53` (x86 `mov word [di-0x3F], ...`) would become a parse error |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| PC/GEOS VM files, data files, directories and links (same signature) | Parse error naming the file type; their structure is not parsed |
| Relocations | Counted and bounds-checked, not applied or validated entry by entry (source, type, library number) |
| dgroup and other data resources | Opaque, even when they hold code-like bytes |
| XIP images, patch files, compressed XIP resources (`COMPRESSED_XIP` in the kernel) | ROM-image features, not `.geo` files; not recognized |
| Geodes that use 80386 instructions | Reported as 16-bit x86 |
| Copy protection, passwords (`FilePassword`) | Not interpreted |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly), `tests/geos.rs` (15
tests) and the module's unit tests (5) passed, with every-prefix and
every-byte mutation sweeps (`0x00`, `0xFF`, two bit flips) over a 2.0 and a
1.x library geode. All fixtures are synthetic, built in the tests from the
documented layout around nasm-assembled code (`tests/fixtures/geos/`). With
`IDA_INPUT_DIR` set to IDA Pro's test inputs, the gated test also passed:
`pc_dhcp.geo`, `pc_nontsec.geo`, `pc_uiec.geo`, `pc_vga.geo`, `pc_wdb.geo`
and `pc_www.geo` report `geosgeode`, x86, 16-bit, with 3, 5, 90, 10, 8 and
50 components of which 1, 1, 58, 8, 3 and 34 are code; `pc_bad_class.geo`
is a parse error (exported entry count 1 in the executable header, 129 in
the core block); every prefix of `pc_dhcp.geo` is an error and its byte
mutations do not panic. Those samples are read in place and not
redistributed; without the variable the test skips. `web/tests/geos.test.mjs`
(4 tests) passed through `/pkg/zrax.js`, `/dist/zrax.js` and both workbench
pages. 1.x geodes are not verified against real files.

After integration with the partition table, FAT, ISO 9660, console disc,
Java image, MCU wrapper, minidump and NetWare families on the same day,
the native suite passed 1,821 tests with 6 ignored, and the gated test
passed again with `IDA_INPUT_DIR` set. On IDA's corpus (4,621 files),
`pc_dhcp.geo`, `pc_nontsec.geo`, `pc_vga.geo` and `pc_wdb.geo` went from
inconclusive to the expected x86, and `pc_bad_class.geo` from inconclusive
to a parse error; no other file changed.
