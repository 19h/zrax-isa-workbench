# Mach-O load commands

`src/formats/macho.rs` reads the Mach-O header (`cputype`, `cpusubtype`) and
fat headers, and its submodules read the load commands that follow the
header: `macho/commands.rs` (the walk and the fixed-size commands),
`macho/segments.rs` (segments, sections and the code they hold),
`macho/platform.rs` (`LC_BUILD_VERSION`, `LC_VERSION_MIN_*`),
`macho/thread.rs` (`LC_UNIXTHREAD`) and `macho/report.rs` (notes and
metadata). `lib.rs` merges them into the header result (`read_macho_commands`,
`read_fat_slices`, `classify_fileset`).

The ISA still comes from `cputype` alone. Load commands never change the
ISA, bit width, byte order or variant; they add notes and metadata, locate
the instruction sections that extension detection scans, and list the
entries of an `MH_FILESET` as slices classified on their own.

## Sources

| Source (pinned) | Path | SHA-256 |
| --- | --- | --- |
| apple-oss-distributions/xnu `xnu-12377.121.6` (`ac9718fb1af618d5ce8678d0dc6e8a58f252216f`) | `EXTERNAL_HEADERS/mach-o/loader.h` | `f99be61ea63eb480f9ee6daba7c04af377be4932c62e04ef044895f2e556bbd3` |
| same | `EXTERNAL_HEADERS/mach-o/fixup-chains.h` | `17db8c0939e96cbba9f0f4078340101b7ca49b8b6aafae34c9fe981b36791021` |
| same | `osfmk/mach/vm_prot.h` | `9bd46e36981064d2bf7230d455284e5ffc0d810c3d5fa4b9a99dafe238cb13ef` |
| same | `bsd/kern/mach_loader.c` | `234fe095dd92cbea6135d56781619b44ccf17fe6ffd95c9c8fa06f7bb1fd4e30` |
| apple-oss-distributions/cctools `cctools-1035.1.102` (`e0d56624eca2a76c2ace4c21850df9e666de4ca5`) | `include/mach-o/loader.h` | `14648c4d0bfb774428c102b22fbc88be185363c71354f07bebb9c2088fa11828` |
| same | `include/mach-o/fat.h` | `19925cdb5fed9b5b7981b05420856f65b99abb54bca34ea95e0e581da8cc580f` |
| same | `include/mach/i386/thread_status.h`, `_structs.h` | `8d30c2ca50d10710241cf1fbe77e44319ab3be388ecd8ac460c03a3e7c7490d0`, `946dda55ff7eec9dbb2025313abfb9fe755883bbb9e9549dbc1be26b4a3feaeb` |
| same | `include/mach/arm/thread_status.h`, `_structs.h` | `5887f1dfc23a72109541947b2577abf742db13b51fb95bda477084ebc648da6e`, `169d76eddee4c0ac1219fd20098dcc8ff35de22cf9fe494b6ad2c75a83464916` |
| same | `include/mach/ppc/thread_status.h`, `_structs.h` | `401229e3755d9e5ea2237bd5de417f978314bab3a2e2f194e73d6bb8ddf8f971`, `fc38952d80d221f6521fea275c4f791b1ca430307610f8ab25f07a6997da708a` |
| apple-oss-distributions/dyld `dyld-1378` (`fd8d0c4d52320ebf64db34f3cb280310d905c5ae`) | `common/MachOFile.cpp` | `24852b5c5371ea46bd823cd246a747506da4d207e7ebe5f26b239ce046bfc980` |

ld64 was not needed: its Mach-O structures are the same `mach-o/loader.h`
that cctools ships.

## Implemented commands

The JSON format IDs are unchanged: `macho` for a thin image (including an
`MH_FILESET`) and `machofat` for a fat binary.

| Command | Read | Reported as |
| --- | --- | --- |
| `LC_SEGMENT`, `LC_SEGMENT_64` | `segname`, `vmaddr`, `vmsize`, `fileoff`, `filesize`, `maxprot`, `initprot`; every `section`/`section_64` (`sectname`, `segname`, `addr`, `size`, `offset`, `flags`) | Summary note; `macho_segment_<n>` and `macho_section_<n>` metadata; section count; instruction sections scanned for extensions |
| `LC_BUILD_VERSION` | `platform`, `minos`, `sdk`; `ntools` checked against `cmdsize` | `Platform <name> (LC_BUILD_VERSION); minimum OS <x.y>; SDK <x.y>`; `macho_platform`, `macho_min_os`, `macho_sdk` (`_1`, `_2`... for further records) |
| `LC_VERSION_MIN_MACOSX`, `_IPHONEOS`, `_TVOS`, `_WATCHOS` | `version`, `sdk` | As above, with the platform the command names |
| `LC_MAIN` | `entryoff` | Entry point at the address the segments map the offset to; `macho_entry_file_offset`; generic `entry_point` |
| `LC_UNIXTHREAD` | Each `flavor`/`count`/state triple; the program counter of the flavors below | Entry point (generic `entry_point`), or a note that the flavor is not decoded |
| `LC_UUID` | `uuid` | `macho_uuid` (8-4-4-4-12) |
| `LC_CODE_SIGNATURE` | `dataoff`, `datasize` | Present, not verified; `macho_code_signature` |
| `LC_ENCRYPTION_INFO`, `_64` | `cryptoff`, `cryptsize`, `cryptid` | Encrypted range left out of extension detection when `cryptid` is not 0; `macho_encryption` |
| `LC_DYLD_CHAINED_FIXUPS` | `dataoff`, `datasize` | Present; `macho_chained_fixups` |
| `LC_FILESET_ENTRY` | `vmaddr`, `fileoff`, `entry_id` | One slice per entry, labelled with its ID; `macho_fileset_entry_<n>` |

Other commands are walked and skipped. The header's `flags` become the
generic `flags` metadata; the instruction bytes scanned become `code_size`.

Platform names: `PLATFORM_MACOS` 1 to `PLATFORM_XROSSIMULATOR` 12 (xnu;
11 and 12 are shown as visionOS), `PLATFORM_UNKNOWN` 0 and 13 to 24
(firmware, sepOS and the ExclaveCore/ExclaveKit platforms of macOS, iOS,
tvOS, watchOS and visionOS) from cctools. Other values are shown in hex.

Thread states whose program counter is decoded:

| `cputype` | Flavor | Program counter |
| --- | --- | --- |
| `CPU_TYPE_X86` | `x86_THREAD_STATE32` (1) | `eip`, byte 40, 4 B |
| `CPU_TYPE_X86_64` | `x86_THREAD_STATE64` (4) | `rip`, byte 128, 8 B |
| `CPU_TYPE_ARM` | `ARM_THREAD_STATE` (1) | `pc`, byte 60, 4 B |
| `CPU_TYPE_ARM64` | `ARM_THREAD_STATE64` (6) | `pc`, byte 256, 8 B |
| `CPU_TYPE_POWERPC` | `PPC_THREAD_STATE` (1) | `srr0`, byte 0, 4 B |
| `CPU_TYPE_POWERPC64` | `PPC_THREAD_STATE64` (5) | `srr0`, byte 0, 8 B |

## Extension detection

Before load commands were read, extension detection scanned the whole
input with the header's ISA. It now scans the stored bytes of the sections
flagged `S_ATTR_PURE_INSTRUCTIONS` or `S_ATTR_SOME_INSTRUCTIONS`:

- zero-fill sections (`S_ZEROFILL`, `S_GB_ZEROFILL`,
  `S_THREAD_LOCAL_ZEROFILL`) and the parts of a section outside its
  segment's file range (a dSYM's `__TEXT`) store nothing;
- bytes in an `LC_ENCRYPTION_INFO(_64)` range with `cryptid` other than 0
  are opaque and left out;
- bytes past the end of the input (a truncated file) are left out;
- the ranges are joined in file order; one range is borrowed from the
  input, several are concatenated up to 64 MiB (`MAX_PAYLOAD`).

A note names the sections and bytes scanned and what was left out. The
whole input is still scanned, as before, when the load commands cannot be
read (with a warning) or when the image has `MH_DYLIB_IN_CACHE` and is read
on its own, such as a dyld shared cache member, because its file offsets
then refer to the containing cache.

Fat binaries: each slice's own instruction sections supply code-pattern
extensions for that slice, with the slice's ISA. The first slice, which
supplies the primary result, also supplies the primary scan, its notes
(prefixed `First slice:`) and its metadata. Before, the primary scan covered
every slice with the first slice's ISA.

## Filesets

An `MH_FILESET` (a kernel collection, as Apple silicon kernelcaches are
built) lists its images with `LC_FILESET_ENTRY`. Each entry's Mach-O header
is at its `fileoff`, and its own segments and sections use file offsets of
the fileset file. Each entry is classified on its own: its header names its
ISA, bit width, byte order and variant, and its instruction sections, read
in the fileset's coordinates, supply its code-pattern extensions (and the
ISA through the code model if the header named none). Entries are listed
in command order as slices labelled with the entry ID, at the entry's file
offset, with the size of the entry's header and load commands. The
primary result keeps the fileset header's ISA; its extensions are those of
the first entry in the same ISA family, because the fileset's own segments
overlap its entries' segments. Entries are not nested further.

## Wire units and byte order

All sizes are bytes and all offsets are file offsets of the input, except
`LC_MAIN`'s `entryoff`, which counts from the image's header. Addresses
(`vmaddr`, section `addr`, fileset `vmaddr`, program counters) are target
addresses. The header and load commands use the byte order of the magic;
fat headers are big-endian. Load commands never set the code byte order:
the header's byte order is reported as before.

## Validation and resource bounds

| Check | Source | On failure |
| --- | --- | --- |
| `[header end, header end + sizeofcmds)` lies in the input | dyld `isMachO` | Warning; load commands not read |
| `ncmds <= sizeofcmds / 8` | bounds the walk | Warning |
| Each `cmdsize >= 8`, a multiple of 4, ending inside `sizeofcmds` | dyld `forEachLoadCommand` (the 8-byte rule of `loader.h` is not enforced, as dyld does not enforce it) | Warning |
| Each command at least its structure size | xnu `mach_loader.c` | Warning |
| Segment `cmdsize` = structure + exactly `nsects` sections | dyld `validSegments` | Warning |
| `ntools` records fit `cmdsize` | `loader.h` | Warning |
| Thread states fit `cmdsize` | xnu `load_threadstate` | Warning |
| Fileset `entry_id` offset after the 32 B structure, NUL-terminated inside the command | `loader.h` | Warning |
| Fileset entry `fileoff` is not 0 and its header and load commands fit the input | | Warning for that entry; it is not listed. Entries that start past the end of the input are counted in one warning |
| Repeated `LC_UUID`, `LC_CODE_SIGNATURE`, `LC_DYLD_CHAINED_FIXUPS`, `LC_ENCRYPTION_INFO`, or two entry-point commands | xnu refuses two entry points | Note; the first is kept |

Every warning leaves the header result unchanged. Segments and sections are
bounded by `sizeofcmds`, so allocation is proportional to the input.
Metadata lists at most 64 segments and 128 sections (a note counts the
rest); at most 4096 fileset entries are classified (`MAX_COMPONENTS`).

## Differential snapshot

Following AGENTS.md section 6, `detect_payload` ran on 2026-10-13 over every
Mach-O and fat file in `tests/` and `testbins/` (one,
`tests/fixtures/apple/kernel.macho`), the 546 files of IDA's test inputs
that start with a Mach-O or fat magic
(`IDA_INPUT_DIR=/Users/int/hexrays/ida/tests/input`, read in place; the
`0xCAFEBABE` files among them include Java class files), and the 1,343
Mach-O and fat files of this Mac's `/usr/bin`, `/usr/lib`, `/usr/libexec`
and `/System/Library/Kernels`, read in place: every whole file, up to 15
prefixes of each file up to 4 MiB, and 0x00/0xFF/bit-flip mutations of up
to 48 header and load-command bytes of every third file up to 1 MiB,
105,354 inputs in all, on the base commit (`09460de`) and on this change,
with a temporary test that was deleted afterwards.

| Field | Change |
| --- | --- |
| Format, primary ISA, bit width, byte order, confidence, source, variant | None |
| Candidates | None |
| Errors | None (2,406 inputs are errors in both, with the same text) |
| Notes | Only additions after the existing notes |
| Metadata | Only additions (`entry_point`, `section_count`, `code_size`, `flags` and `macho_*` keys) |
| Slices | Fat slices: only code-pattern extensions added. Filesets: entry slices added (two IDA kernel collections and their prefixes) |
| Primary extensions | Code-pattern extensions only; on whole files 86 of 1,890 changed (see below) |

The extension changes on whole files: fat binaries whose first slice no
longer takes code-pattern extensions found in their other slices (`CSSC`
from the second arm64e slice of 73 `/usr/bin` and `/usr/libexec` tools,
`AVX`/`AVX2`/`BMI1`/`BMI2`/`MOVBE` from the x86-64h slice of `sqlite3`,
`PAC` from the arm64e slice of `arm_ios_arm64e_swift_imports64.macho`),
which those slices now report themselves, two fat IDA inputs whose first
slice loses an extension found outside its instruction sections (`MMX` in
`pc_mac_objc_xcodeframework64.macho`; `PCLMULQDQ` in the prelinked kernel
`pc_testkernelcache_64.macho`, from kext code in `__PRELINK_TEXT,__text`,
whose flags are 0), and one whose first slice gains `SSE4.1` from its own
code (`locationd`); the x86-64 kernel collection
`pc_kernelcache_osx_11_0_64.macho`, whose `AES-NI`, `AVX`, `AVX-512` and
`BMI2` now belong to the `com.apple.kec.corecrypto` and
`com.apple.vecLib.kext` entries; a few thin files whose extensions came
from data (`CRC32` in `arm_iphone.macho`'s `__TEXT,__const`) or bytes
outside every section (`VFP` in `arm_badoffsets_tudou.macho`); and a few
small files where the section-limited scan finds extensions the whole-file
scan diluted (`PAC` in `arm_ios_arm64_32_v8_64.macho`, `MTE` in
`arm_ios_arm64e_mte64.macho`, `VFP` in three Arm files).

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| M1 | A fileset entry's load commands use file offsets of the fileset file | Observed on `pc_kernelcache_osx_11_0_64.macho` and `..._aux_64.macho` (x86-64): each kext's `__TEXT` `fileoff` equals its header offset; `fileset_entries_parse_in_fileset_coordinates`. Not confirmed by `loader.h` text; an arm64 kernel collection was not available |
| M2 | An `MH_DYLIB_IN_CACHE` image read on its own does not locate its bytes | dyld cache members are listed with their header and load commands only; `an_in_cache_image_read_on_its_own_scans_the_whole_input_as_before` |
| M3 | Instruction-flagged sections hold all the code worth scanning | Falsified for prelinked kernels: `pc_testkernelcache_64.macho` keeps its kexts in `__PRELINK_TEXT,__text` with flags 0, so their code is no longer scanned (see known boundaries) |
| M4 | `LC_MAIN`'s `entryoff` counts from the image's header | `__TEXT` maps file offset 0 in the clang-built fixtures and in `/bin/ls` (entry 0x100000978 from `entryoff` 0x978); an image whose `__TEXT` starts elsewhere would report a shifted entry |
| M5 | The program-counter offsets of the listed flavors | Entry points of the IDA x86-64 kernel collections (`0xFFFFFF8000100000`) and of the synthetic thread states in `tests/macho.rs` |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Code signatures, chained fixups | Presence and range only; signatures not verified, fixup chains not walked |
| Fat slices after the first | Code-pattern extensions only; their platform, entry point and other commands are not reported |
| `ARM64_32` thread states, `x86_THREAD_STATE` (7) and other flavors | Not decoded; noted |
| `LC_VERSION_MIN_*` simulator builds | Reported as the named OS; the bytes do not say simulator |
| Dylib, rpath, symbol table and other commands | Walked, not reported |
| Nested filesets | An entry's own fileset entries are not classified |
| Prelinked kernels (kernelcaches before kernel collections) | The kexts in `__PRELINK_TEXT` are neither listed nor scanned: that section's flags do not mark instructions, and its embedded Mach-O images are not parsed |
| A load command error | The whole command list is reported as not read, as dyld rejects such an image |

## Verification

On 2026-10-13, on macOS 27.2 AArch64 with rustc 1.100.0-nightly
(`f248f4038`, 2026-09-05) and Node.js 25.8.1:

- `tests/macho.rs`: 23 tests passed. 21 use synthetic images built in the
  test (arm64, PowerPC and PowerPC64 big-endian, ARMv7 with an encrypted
  `__text`, thread states, platforms, a two-entry `MH_FILESET`, an
  in-cache image, a dSYM, a truncated file, repeated and corrupted
  commands, and every-prefix and byte-mutation sweeps) or the clang-built
  fixtures (executables, object, a fat binary built from them). Two read
  real samples in place: with `IDA_INPUT_DIR` set, the two IDA kernel
  collections (220 and 14 entries); with `MACHO_HOST_DIR=/usr/bin`, 300
  Mach-O and fat files whose primary and slice ISAs match their headers.
  Without the variables they skip.
- Module unit tests: 9 new, passed.
- `cargo test --all-features --locked`: 2,656 passed, 0 failed, 6 ignored
  (2,624 passed and 6 ignored on the base commit the same day).
- `web/tests/macho.test.mjs`: 4 tests passed (`/pkg`, `/dist`,
  `/web/index.html`, `/dist/index.html`); the whole browser suite: 302
  passed, 4 skipped (D10/RX113 firmware not in the repository), 0 failed.
- The differential snapshot above.

Not verified: arm64 kernel collections (no sample was available), Mach-O
files for other CPU types than those in the corpora, and the thread-state
layouts of `CPU_TYPE_X86` and `CPU_TYPE_ARM` against real `LC_UNIXTHREAD`
binaries (checked against the cctools structures and synthetic images
only).

After integration on the same day (with the application-bundle host hook
in `classify_depth`), the native suite passed 2,816 tests with 6 ignored,
`tests/macho.rs` passed with `IDA_INPUT_DIR` and `MACHO_HOST_DIR=/usr/bin`
set, IDA's corpus (4,621 files) classified as before, and a Mach-O
PyInstaller build still listed its 73 bundle members beside the host.
