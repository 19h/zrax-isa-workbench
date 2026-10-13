# Windows minidumps and kernel crash dumps

`src/formats/minidump.rs` and its submodules parse Windows user-mode
minidumps and the header of Windows kernel crash dumps into the shared
container model ([compressed streams and the container model](compressed-streams.md)).
The processor architecture recorded in the dump is its target; dumped
memory that lies inside a listed module image is classified as code for
that target, unless the module's PE headers are in the dump and place the
range outside every executable section. That memory and all other memory
(stacks, heaps, mapped data) is opaque.

## Implemented layouts

| JSON format ID | Layout (variant) | Architecture evidence | Primary source |
| --- | --- | --- | --- |
| `minidump` | `MDMP, little-endian`: `MINIDUMP_HEADER`, stream directory, system information, thread list, module list (names, file versions), exception, memory list and 64-bit memory list streams | `MINIDUMP_SYSTEM_INFO.ProcessorArchitecture` names the ISA (table below); MSIL, neutral, unknown and unlisted values name none, and the ISA then comes from module memory through the code model | Microsoft `minidumpapiset.h` reference; Win32 metadata; Breakpad `minidump_format.h` |
| `minidump` | `MDMP, big-endian`: the same structures with every field, and the UTF-16 strings, byte-swapped; the signature reads `PMDM` | As above | Breakpad v2024.02.16 `minidump.cc` (`Minidump::Read`: the signature is the byte-order marker); rust-minidump v0.22.0 `Minidump::read` |
| `windowskerneldump` | `PAGEDUMP, 32-bit header`: the 4 KiB `DUMP_HEADER32` | `MachineImageType`, read as an `IMAGE_FILE_MACHINE_*` value (assumption M5) | Win32 metadata `DUMP_HEADER32`; QEMU v8.2.0 `win_dump.c` (signatures) |
| `windowskerneldump` | `PAGEDU64, 64-bit header`: the 8 KiB `DUMP_HEADER64` | As above | Win32 metadata `DUMP_HEADER64`; QEMU v8.2.0 `win_dump_defs.h` (offsets) |

Pinned sources:

| Source | Pin |
| --- | --- |
| Microsoft Learn `minidumpapiset.h` pages (`MINIDUMP_HEADER`, `MINIDUMP_DIRECTORY`, `MINIDUMP_STREAM_TYPE`, `MINIDUMP_LOCATION_DESCRIPTOR`, `MINIDUMP_THREAD_LIST`, `MINIDUMP_THREAD`, `MINIDUMP_MODULE_LIST`, `MINIDUMP_MODULE`, `MINIDUMP_MEMORY_LIST`, `MINIDUMP_MEMORY_DESCRIPTOR`, `MINIDUMP_MEMORY64_LIST`, `MINIDUMP_EXCEPTION_STREAM`, `MINIDUMP_EXCEPTION`, `MINIDUMP_SYSTEM_INFO`, `MINIDUMP_STRING`) and `sysinfoapi.h` `SYSTEM_INFO` | MicrosoftDocs/sdk-api commit `656e9656bfaef34dd29cd7ee9e1146aec17e924c`, `sdk-api-src/content/minidumpapiset/` and `sysinfoapi/` |
| Win32 metadata as generated into `windows-rs`: `Win32/System/Diagnostics/Debug/mod.rs` (packed `MINIDUMP_*` structures, `MINIDUMP_VERSION`, `DUMP_HEADER32`, `DUMP_HEADER64`, `DUMP_TYPE_*`, `DMP_*` sizes) and `Win32/System/SystemInformation/mod.rs` (`PROCESSOR_ARCHITECTURE_*`) | `windows-rs` tag `0.58.0`; SHA-256 `7ef3ec757f2254c595a129700f0bd5be2f5bcc8f3041cac590497e73c1298f7b` and `a91bf11f9ab1f2f6a0c9c65bf2f2d7d30662bc811ec4990ab6dee1b17a22e4de` |
| Google Breakpad `src/google_breakpad/common/minidump_format.h` and `src/processor/minidump.cc` | tag `v2024.02.16`; SHA-256 `6e88e2f06e4fe60b8a3dee7f1e39e001c799f69ac3f244d3e36295c38c834c3c` and `c97563995de2d442d6b7b4a195dabfe991824c7a65c889a2dd0b0bd80bfaa651` |
| rust-minidump `minidump-common/src/format.rs` and `minidump/src/minidump.rs` | tag `v0.22.0`; SHA-256 `4d9baaa3b3b52b4311efaadb12921088141becba8890ae977f0a2807eaa7f820` and `93bedd27718981ec0f30d061d9ef87efcb0b53d4a2ab6409f7947f235ca94a43` |
| Microsoft "PE Format" (`desktop-src/Debug/pe-format.md`): the PE signature offset at 0x3C, the COFF file header (`NumberOfSections`, `SizeOfOptionalHeader`, the 96-section loader limit), the section table (`VirtualSize`, `VirtualAddress`, `SizeOfRawData`, `Characteristics`) and the section flags `IMAGE_SCN_CNT_CODE` and `IMAGE_SCN_MEM_EXECUTE` | MicrosoftDocs/win32 commit `ca8274decead49403d70ceeed4af8d4ca74eaf11`; SHA-256 `b17271a341f9b6e3204cf3f04ed905c25c03fd4cadb7a57bd4aaf38cf56a2fe0` |
| QEMU `include/qemu/win_dump_defs.h` and `dump/win_dump.c` | tag `v8.2.0`; SHA-256 `5317ba7740854dd0f811c8e5de96262238deffd061ad607d1fddf9d967c2111a` and `ff334a23a420d9627f0c2cb06cb7adede37afe0434d5210900ba377cae9538b9` |

### Processor architectures

| `ProcessorArchitecture` | Name | Target | Code byte order |
| --- | --- | --- | --- |
| 0 | `PROCESSOR_ARCHITECTURE_INTEL` | x86, 32-bit | little |
| 1 | `MIPS` | MIPS, 32-bit | from the code |
| 2 | `ALPHA` | Alpha, 64-bit | little |
| 3 | `PPC` | PowerPC, 32-bit | from the code |
| 4 | `SHX` | SuperH, 32-bit | from the code |
| 5 | `ARM` | ARM, 32-bit | from the code |
| 6 | `IA64` | IA-64 | little |
| 7 | `ALPHA64` | Alpha, 64-bit | little |
| 8 | `MSIL` | none | |
| 9 | `AMD64` | x86-64 | little |
| 10 | `IA32_ON_WIN64` (WoW64) | x86, 32-bit | little |
| 11 | `NEUTRAL` | none | |
| 12 | `ARM64` | AArch64 | little |
| 13 | `ARM32_ON_WIN64` | ARM, 32-bit | from the code |
| 14 | `IA32_ON_ARM64` | x86, 32-bit | little |
| 0x8001 | SPARC (Breakpad) | SPARC, 32-bit | big |
| 0x8002 | PPC64 (Breakpad) | PowerPC 64 | from the code |
| 0x8003 | ARM64 (Breakpad, old value) | AArch64 | little |
| 0x8004 | MIPS64 (Breakpad) | MIPS64 | from the code |
| 0x8005 | RISC-V (Breakpad) | RISC-V 32 | little |
| 0x8006 | RISC-V 64 (Breakpad) | RISC-V 64 | little |
| 0xFFFF | `UNKNOWN` | none | |

Values 0-14 and 0xFFFF are Microsoft's (Win32 metadata; 0, 5, 6, 9, 12
and 0xFFFF also in the `SYSTEM_INFO` and `MINIDUMP_SYSTEM_INFO` pages);
0x8001-0x8006 are Breakpad-defined. No source states a code byte order
per value: it is fixed where the ISA fixes the instruction order and
otherwise taken from the first module-memory component of the same family
(reported `bi_endian` when undetermined).

## Components

- Every non-empty range of the memory list and of the 64-bit memory list
  is a component, in stream order, at its stored file offset, labeled
  `Memory at 0x<address>`.
- A range that lies entirely inside one listed module image
  (`BaseOfImage` to `BaseOfImage + SizeOfImage`) is labeled with the
  module's file name and classified by the code model as raw code, never
  as a nested container (a mapped PE image is not in file layout). When the
  dump names a target, it is the component's target.
- When the range holding a module's base address starts with a PE header
  (`MZ`, the PE signature at the offset at 0x3C, at most 96 section headers
  inside the range), only module ranges that overlap a section with
  `IMAGE_SCN_CNT_CODE` or `IMAGE_SCN_MEM_EXECUTE` are code. A section
  spans `VirtualSize` or `SizeOfRawData` bytes from the image base plus its
  `VirtualAddress`, whichever is larger. The module's other ranges (its
  headers, data and resources) are opaque. Section tables are read for the
  first 4,096 modules, which bounds the memory a dump of many modules
  sharing one header can claim; later modules, and modules whose headers
  are not dumped, keep all their ranges as code.
- Every other range is opaque. A range inside a thread's stack descriptor
  is labeled `(thread 0x<id> stack)`.
- A kernel dump has one opaque component: everything after the header.

## Notes and metadata

Notes: the byte-swapped layout, a non-zero header checksum (not
verified), the processor architecture with OS version, platform ID and
processor count, the thread count, the exception code and address (with
the module that contains the address) and thread, the module count, and
the memory range tally (code and opaque ranges, module ranges outside the
executable sections, empty ranges skipped, ranges past the component
limit). Metadata keys start with `minidump_`:
`version_high`, `flags`, `timestamp`, `checksum`, `streams` (stream
types in directory order), `processor_architecture`, `processor_level`,
`processor_revision`, `processors`, `os_version`, `platform_id`,
`product_type`, `csd_version`, `thread_count`, `exception_code`,
`exception_flags`, `exception_address`, `exception_thread`,
`module_count`, `module_<i>` (path, base, size, file version),
`memory_ranges` and `memory_size`. Kernel dumps report `kernel_version`,
`machine_image_type`, `processors`, `bug_check_code`,
`bug_check_parameters`, `dump_type` and `required_dump_space`.

## Wire units and byte order

All offsets (RVAs) are byte offsets from the start of the file; sizes are
bytes; addresses are the dumped process's virtual addresses. Minidump
fields are little-endian unless the signature reads byte-swapped, in
which case every field and every UTF-16 unit is big-endian. Kernel dump
headers are little-endian. Header byte order is never reported as code
byte order.

## Validation and resource bounds

- Recognition: `MDMP` with `Version & 0xFFFF == 0xA793`, `PMDM` with the
  big-endian version word, or `PAGE` followed by `DUMP` or `DU64`. A file
  with the signature but another version word is not claimed. Strong
  detection runs just before the magic-bearing compressed streams.
- The 32-byte header, the whole directory and every directory entry's
  location (all streams, also unknown types) must lie inside the file.
- A second thread list, module list, memory list, exception, system
  information or 64-bit memory list stream is an error (as in Breakpad's
  reader).
- Thread, module and memory lists must be exactly `4 + count * entry`
  bytes, or 4 bytes longer (padding after the count; Breakpad and
  rust-minidump); the 64-bit memory list exactly `16 + count * 16`. Counts
  are therefore bounded by the stream size before anything is allocated.
- System information needs at least 56 B, the exception stream 168 B.
- Every memory range's bytes must lie inside the file; 64-bit list ranges
  follow `BaseRva` in descriptor order. Module images and memory ranges
  whose end address overflows 64 bits are errors.
- `MINIDUMP_STRING` lengths must be even and at most 65,534 B (32,767
  UTF-16 units, the longest Windows path). At most 1,024 units are decoded
  (Breakpad's limit); longer strings end with `…`. Names are read for the
  first 4,096 modules only, so shared string RVAs cannot make the parser
  allocate more than a few MiB of text. RVA 0 means no string.
- At most 4,096 memory components (`MAX_COMPONENTS`) are listed and at
  most 4,096 modules described in metadata; the rest are counted in a
  note. Stream lists in metadata name at most 32 types.
- Containment queries use sorted ranges with binary search, so the cost is
  `O((modules + ranges) log modules)` for any input. Memory bytes are
  borrowed, never copied.
- Kernel dumps: the whole 4 KiB or 8 KiB header must be present.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| M1 | Memory inside a listed module image is that module's code or data, and only such memory is worth classifying | `memory_outside_modules_is_opaque_and_without_modules_nothing_is_code`; on 2026-10-13 IDA's full-memory sample `pc_windbg_windmp.windmp` gave 66 module ranges classified x86 and 29 opaque before section tables were read (M7) |
| M7 | A module's dumped PE header describes the module as loaded, so a range outside its executable sections holds no code | `dumped_pe_headers_limit_module_code_to_executable_sections`; on 2026-10-13 `pc_windbg_windmp.windmp` kept 14 module ranges as code and 52 became opaque, its ISA unchanged (x86), and the "ISA unknown" warnings on module ranges fell from 53 to 1. Self-modifying or unpacked code outside the listed sections would falsify it |
| M2 | A byte-swapped signature means big-endian fields throughout (Breakpad, rust-minidump) | `byte_swapped_dump_reads_big_endian_and_takes_code_order_from_the_code`; no big-endian dump from a real big-endian host was available: not verified on real data |
| M3 | The dump's byte order is not the code byte order; the code supplies it where the architecture leaves it open | The same test: a byte-swapped MIPS dump takes big-endian code order from the MIPS code, not from the header |
| M4 | 4 padding bytes after a list count are alignment, not data (Breakpad, rust-minidump) | `list_counts_may_carry_four_padding_bytes` |
| M5 | `MachineImageType` holds an `IMAGE_FILE_MACHINE_*` value. No primary source states it; the field name, Volatility `crashinfo` output (0x8664 for a Windows 7 x64 dump) and `file(1)` magic discussions (0x14C for 32-bit, 0x8664 for 64-bit) agree | A kernel dump whose `MachineImageType` is not a PE machine for its CPU; no kernel dump was available to test: not verified on real data |
| M6 | The kernel dump offsets follow from the Win32 metadata field types under C layout (the 64-bit physical memory union padded from 700 to 704 B) | QEMU's packed `WinDumpHeader64` gives the same offsets (`DumpType` at 0xF98, `RequiredDumpSpace` at 0xFA0) |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Header `CheckSum` | No algorithm is documented; reported, never verified |
| Thread contexts, thread names, handle data, unloaded modules, memory info list, misc info, comments, CodeView records | Not parsed; their stream types are listed in `minidump_streams` |
| Thread stacks outside the memory lists | Not extracted separately; in Microsoft dumps the same stack bytes are in the memory list |
| Memory info list protections (`PAGE_EXECUTE_*`) | Not used to decide what is code; module containment decides (M1) |
| Kernel dump bodies: physical memory runs, bitmap (`SDMP`/`FDMP`) and triage layouts | Not parsed: no primary source for the bitmap and triage layouts, and physical pages cannot be attributed to modules without page tables. The body is one opaque component |
| Kernel dump `MajorVersion`/`MinorVersion` | Reported raw (`kernel_version`); their meaning (free/checked build, build number) is not stated by a primary source |
| Time Travel Debugging traces (`TTDLog`, IDA's `pc_windbg_ttd_*.windmp`) | Not minidumps; not recognized by this family |
| `ProcessorArchitecture` 8 (MSIL) and 11 (neutral) | No target; the ISA comes from module memory |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly), `tests/minidump.rs`
(16 tests) and the module's 12 unit tests passed. The fixtures are
synthetic, built in the tests from the documented layouts with compiled
code from `testbins/`; they cover both minidump byte orders, both memory
lists, list padding, missing system information and module streams,
architectures without a CPU, corrupted counts, sizes, RVAs, strings and
address ranges, every prefix of a minidump and of a 64-bit kernel
header, and byte mutations (0x00, 0xFF, bit flips) of every structure
byte. `web/tests/minidump.test.mjs` (4 tests) passed through `/pkg/`,
`/dist/` and both workbench pages.

With `IDA_INPUT_DIR` pointing at IDA's test inputs (read-only, not
redistributed), the three `MDMP` samples classified as Windows minidumps:
`pc_windbg_windmp.windmp` (9,577,835 B, full memory, 95 ranges in the
64-bit list) and `pc_windbg_windmp_highdll.windmp` (1,718,770 B,
sign-extended 32-bit module addresses) as x86, and
`pc_windbg_bitness_64.windmp` (114,124 B) as x86-64; 64 prefixes of each
were parse errors. A temporary sweep of 0x00/0xFF/bit-flip mutations over
their first 4-5.5 KiB (every 7th, 11th and 29th byte) ran without a
panic. The two `TTDLog` samples are not minidumps. No kernel dump and no
big-endian minidump was available: those layouts are verified only on
synthetic data.

After integration with the partition table, FAT, ISO 9660, console disc,
Java image and MCU wrapper families on the same day, `cargo test
--all-features --locked` passed 1,765 tests with 6 ignored. On IDA's test
corpus (4,621 files), `pc_windbg_bitness_64.windmp` and
`pc_windbg_windmp_highdll.windmp` went from inconclusive to the expected
x86-64 and x86; no other file changed.

With section tables read from dumped PE headers (same day), the suite
passed 1,771 tests with 6 ignored, including 19 in `tests/minidump.rs`
(the IDA sample test run with `IDA_INPUT_DIR` set) and 3 unit tests in
`src/formats/minidump/image.rs`; every corpus outcome was unchanged.
