# Psy-Q LNK object files

`src/formats/psyq.rs` parses the relocatable object files (`.OBJ`) that the
SN Systems assemblers and compilers write for their linker `psylink`. They
are best known from Sony's PlayStation Psy-Q SDK (`ccpsx`, `aspsx`); SN
Systems used the same LNK format for its Saturn and Mega Drive tool chains.
The family is built on the shared container model
([compressed streams and the container model](compressed-streams.md)).

An object is the signature `LNK`, a version byte and a stream of records.
Each record is a one-byte opcode and a body without a length, so the
parser decodes every record to reach the next one. The PROGRAMTYPE record
(opcode 46, printed as "Processor type" by SN's `DUMPOBJ`) is the format's
own target field. BYTES records hold section contents; each section with
contents is a component, `.text` as code and every other section as
opaque data.

## Implemented layouts

| JSON format ID | Layout (`format.variant_name`) | Recognition | Architecture evidence | Primary sources |
| --- | --- | --- | --- | --- |
| `psyqobject` | `PsyQ LNK object`: `LNK`, version 2, records up to END, only `0x00`/`0xFF` after END | Strong: `LNK`, version byte 2 and a documented opcode (an even value up to 86) as the first record | PROGRAMTYPE 7: MIPS, 32-bit, little-endian (`R3000`); 8: SuperH, 32-bit, big-endian (`SH-2`); 0: M68k, 32-bit, big-endian (`68000`). Any other value, or no PROGRAMTYPE record, names no ISA: the code model answers from `.text` | PCSX-Redux `psyq-obj-parser.cc`; psy-k 0.4.0 `src/lib.rs` (pins below) |

No SN Systems document of the format is public. The sources are two
independent readers, pinned and fetched on 2026-10-13:

| Source | Where | Pin |
| --- | --- | --- |
| PCSX-Redux `tools/psyq-obj-parser/psyq-obj-parser.cc` | `github.com/grumpycoders/pcsx-redux` | commit `919c597633c8add4c2f8dc8a7fdae3bd333f37fd`; 72,061 B; SHA-256 `7f78822e8f661a6ac1c650252fe6998b65a97822481eaff809e73a4593809c34` |
| psy-k 0.4.0 `src/lib.rs` | crates.io `psy-k` 0.4.0, `github.com/ttkb-oss/psy-k` | git `e25c309c48cf5a1ae133e092f661fb874cc0f47f`; crate SHA-256 `531ff24380e23e7675e9610e33998e38fe575d14311ebaac5829822585017cfc`; `src/lib.rs` SHA-256 `8da1569f8da15e338d8233528151f92a8a3f426c82130867ac7c423f9a3bd855` |
| SN `DUMPOBJ` output for Psy-Q 3.3-4.7 PlayStation objects | psy-k `tests/data/cmd/**/*.TXT` (written by psy-k `bat/dump.bat` with `DUMPOBJ.EXE`) | same crate |

PCSX-Redux names the record opcodes (`PsyqOpcode`), the expression
operators (`PsyqExprOpcode`) and the relocation types, and treats `.text`
as the code section. psy-k decodes the same records under `DUMPOBJ`'s names
and adds records 4, 20 and 44, expression operators 20 and 32-74, and the
processor type identifiers (`cputype`).

Detection order in `formats::detect_format`: the strong check runs after
EROFS and before the magic-bearing compressed streams. No earlier format
starts with `LNK` followed by `02`.

## Records

| Opcode | Record | Body after the opcode | Used for | Sources |
| --- | --- | --- | --- | --- |
| 0 | END | none | End of the stream | Both |
| 2 | BYTES | u16 size, bytes | Contents of the current section | Both |
| 4 | RUN_AT_OFFSET | u16, u16 | Skipped | psy-k |
| 6 | SWITCH | u16 section ID | Selects the current section | Both |
| 8 | ZEROES | u32 size | Zero fill of the current section, counted | Both |
| 10 | RELOCATION | u8 type, u16 offset, expression | Counted; not applied | Both |
| 12 | EXPORTED_SYMBOL | u16 symbol, u16 section, u32 offset, string | Names in a note | Both |
| 14 | IMPORTED_SYMBOL | u16 symbol, string | Names in a note | Both |
| 16 | SECTION | u16 section ID, u16 group, u8 alignment, string | Section table | Both |
| 18 | LOCAL_SYMBOL | u16 section, u32 offset, string | Names in a note | Both |
| 20 | GROUP_SYMBOL | u16 number, u8 type, string | Skipped | psy-k |
| 28 | FILENAME | u16 number, string | Source files in a note | Both |
| 44 | SET_MX_INFO | u16 offset, u8 value | Skipped | psy-k |
| 46 | PROGRAMTYPE | u8 processor type | Target | Both |
| 48 | UNINITIALIZED | u16 symbol, u16 section, u32 size, string | Names in a note | Both |
| 50, 52, 56, 58, 60 | INC_SLD_LINENUM, INC_SLD_LINENUM_BY_BYTE, SET_SLD_LINENUM, SET_SLD_LINENUM_FILE, END_SLD | 2, 3, 6, 8, 2 B | Skipped | Both |
| 74 | FUNCTION | 28 B of fields, string | Names in a note | Both |
| 76, 78, 80 | FUNCTION_END, BLOCK_START, BLOCK_END | u16 section, u32 offset, u32 line | Skipped | Both |
| 82 | SECTION_DEF | 14 B of fields, string | Skipped | Both |
| 84 | SECTION_DEF2 | 14 B of fields, u16 dimension count (0), string tag, string name | Skipped | Both, for no dimensions |
| 86 | FUNCTION_START2 | 36 B of fields, string | Names in a note | PCSX-Redux |

Strings are a length byte and that many bytes, without a terminator.
Relocation expressions are written in prefix order: constant (0, u32);
symbol address (2), `sectbase` (4), `sectstart` (12), `grouporg` (20,
psy-k) and `sectend` (22), each with a u16 index; and binary operators, the
even opcodes from 32 to 74 (PCSX-Redux has `+` 44, `-` 46 and `/` 50;
psy-k all of them), each followed by two expressions. The parser counts the
operands still owed instead of recursing, so an expression is bounded by
its bytes.

## Components

| Component | Label | Classified |
| --- | --- | --- |
| `.text` section with BYTES records | `.text (section 0x<ID>)` | Raw code (never a nested container), with the PROGRAMTYPE target and CPU variant when the type is mapped; by the code model alone otherwise |
| Any other section with BYTES records (`.rdata`, `.data`, `.sdata`, `.ctors`, ...) | `<name> (section 0x<ID>)` | Opaque: data never reaches the code model |

A section written in one BYTES record is the stored payload as-is. A
section written in several is reassembled (transform `LNK BYTES records`):
its stored range runs from the first payload to the end of the last, with
the other records in between, and its decoded bytes are the payloads
concatenated. Sections with only ZEROES (`.bss`, `.sbss`) or no contents
are listed in the section note, not as components.

Notes: the processor type and its name, the sections with their BYTES and
zero-fill sizes (8 listed), the relocation count, exported, imported,
local and uninitialized symbols, functions named by debug records and
source files (8 names each, the rest counted, 64 characters per name with
other bytes shown as `.`). Metadata: `psyq_version`,
`psyq_processor_type`, `psyq_sections`, `psyq_relocations`,
`psyq_exported_symbols`, `psyq_imported_symbols`, and the generated
`psyq_image_size` and `psyq_component_<i>`.

## Wire units and byte order

Every record field is little-endian, for every target (psy-k reads all
records little-endian; its Saturn test object has little-endian IDs). Sizes
and offsets are bytes. Section offsets in symbols and relocations are
section-relative; objects carry no load addresses. The code byte order is
the target's (little-endian for the PlayStation R3000, big-endian for the
SH-2 and 68000), not a header byte order.

## Validation and resource bounds

- Header: at least 4 bytes, `LNK`, version 2.
- Every record decodes inside the file; the stream ends with END; only
  `0x00`/`0xFF` follow it (counted in a note).
- Unknown opcodes are errors. Records whose layout the sources do not
  confirm are errors too, because without record lengths they cannot be
  skipped: psy-k's untested records 22-26, 30-42 and 62-72,
  INC_SLD_LINENUM_BY_WORD (54) and SECTION_DEF2 with dimensions. The same
  holds for the untested expression operands 6, 8, 10, 14, 16 and 18.
- A SECTION alignment must be zero or a power of two, and section IDs
  unique. BYTES, ZEROES and RELOCATION need a SWITCH to a declared section
  (resolved when used, as PCSX-Redux does); UNINITIALIZED needs a declared
  section. A second PROGRAMTYPE record is an error (PCSX-Redux: "Already got
  program type").
- Zero fill is summed in 64 bits with an overflow check and never
  materialized, so a huge ZEROES record allocates nothing.
- Components: at most 4096 (`MAX_COMPONENTS`), the rest counted. A
  reassembled section is at most 64 MiB (`MAX_PAYLOAD`) and all reassembled
  sections at most 256 MiB (`MAX_EXTRACTED`); a section over either limit
  is noted, not extracted. The section table, symbol counts and kept names
  grow only with records actually present.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| P1 | PROGRAMTYPE 7 is the PlayStation R3000, little-endian | Both sources; `DUMPOBJ` prints "Processor type 7" for 30 Psy-Q PlayStation objects and libraries (psy-k test data); all seven valid IDA test objects carry it, and on 2026-10-13 the code model alone classified each one's concatenated `.text` as little-endian MIPS (confidence 31 % for the 36 B of `mips_obj1`, 70-99 % for the others) |
| P2 | PROGRAMTYPE 8 is the Saturn SH-2 and 0 the 68000 | One source: psy-k `cputype` lists both as found in the wild; probe with a Psy-Q Saturn (`GNUSHLIB`) or Mega Drive (`LIBSN68`) object |
| P3 | Types 1-6 (psy-k: 68010-68040, 65816, Z80) and 9 name no confirmed processor | psy-k calls 1-6 speculative; PCSX-Redux accepts 9 together with big-endian MIPS relocations for N64 objects but never names it. An SN N64 object with type 9 would let it be mapped |
| P4 | `.text` is the only code section | PCSX-Redux `isText`; an assembler object with code in a custom-named section would be reported as opaque data |
| P5 | Record fields are little-endian for big-endian targets too | psy-k's Saturn test object; probe with a Saturn library module |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Psy-Q `LIB` archives (`LIB`, version 1, modules wrapping objects) | Not recognized; extract the objects first |
| Relocations | Counted, not applied; the fields they patch keep the values stored in the object |
| Records 22-42 and 62-72, INC_SLD_LINENUM_BY_WORD, SECTION_DEF2 with dimensions, operands 6-18 | Parse errors: the readers mark them untested or disagree on their size |
| SN N64 objects (processor type 9 if P3 holds) | No target; the code model answers from `.text` |
| Debug records (SLD line numbers, functions, blocks, definitions) | Decoded only to reach the next record; function names are listed |
| Section groups, alignment and bss layout | Not reported beyond the section note |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`),
`cargo test --all-features --locked` passed: 1498 tests, 6 ignored (the
existing ignores that need external data), including `tests/psyq.rs` (13
tests) and 7 unit tests in `src/formats/psyq.rs`: positive objects for
processor types 7, 8 and 0, an undocumented type (9) and a missing
PROGRAMTYPE record, single- and multi-record sections, the component
limit, 13 record and expression error cases plus data after END, an
every-prefix truncation sweep and an every-byte mutation sweep (`0x00`,
`0xFF` and each bit flip). With
`IDA_INPUT_DIR=/Users/int/hexrays/ida/tests/input` (IDA's test inputs, read
in place and not redistributed), `mips_obj1`, `mips_obj2`, `mips_cdsfile`,
`mips_gs_135`, `mips_mcgui`, `mips_noheap` and `mips_tuto0` classified as
little-endian MIPS objects, and the damaged `mips_bad_relocs` (unknown
opcode 117), `mips_bad_relocs2` and `mips_huge_bss` (data after an early END
record) and `mips_bad_symname` (a second PROGRAMTYPE record) failed with
those errors; without the variable the test is skipped. After
`./build-web.sh`, `web/tests/psyq.test.mjs` passed 4 of 4 (`/pkg/zrax.js`,
`/dist/zrax.js`, `/web/index.html` and `/dist/index.html`), and the full
browser suite passed 172 of 176 with 4 skips (D10/RX113 firmware not in the
repository).

After integration with the partition table, FAT, ISO 9660, console disc,
Java image, MCU wrapper, minidump, NetWare and PC/GEOS families on the same
day, the native suite passed 1,841 tests with 6 ignored. On IDA's corpus
(4,621 files), `mips_noheap` and `mips_obj1` went from inconclusive to
MIPS; `mips_bad_relocs`, `mips_bad_relocs2` and `mips_huge_bss` (classified
MIPS by the code model alone) and `mips_bad_symname` (inconclusive) became
parse errors. `mips_huge_bss` is `mips_obj2` with the BYTES record at
0x2E8 shortened from 0x188 to 0x180 B, so the record stream loses sync; no
other file changed.

The committed fixtures are synthetic, built in the tests from the record
layouts above with a repository MIPS testbin as `.text`. No SN Systems tool
was available, so no object was generated by `ccpsx` or `psylink` for this
work. Saturn, Mega Drive and N64 objects were not available: processor
types 0 and 8 are tested on synthetic objects only, and their mapping is not
verified on real files.
