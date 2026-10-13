# DOS-family headers: LE/LX without an MZ stub, `ZM` PE images

`src/formats/mz.rs` parses DOS MZ executables and the NE, LE and LX headers
an MZ stub points at; the PE detection in `src/formats/mod.rs` finds a PE
signature through the same DOS header. This document covers these
extensions and fixes of that family:

- LE and LX headers at offset 0 with no MZ stub in front of them;
- PE images whose DOS header starts with the byte-swapped signature `ZM`;
- the module type that LE and LX headers report, behind a stub or not
  ([Module type](#module-type));
- the ISA of an LE or LX header behind a stub whose CPU type has no
  mapping ([CPU type](#cpu-type)).

None adds a format ID: a header without a stub reports the existing
`le` and `lx` IDs, a `ZM` image the existing `pe` ID.

## Implemented layouts

| Layout | JSON format ID (detection) | Variant name | Recognition | Architecture evidence | Primary source |
| --- | --- | --- | --- | --- | --- |
| LX header at offset 0 | `lx` (display name "LX") | `BareLx { cpu: N, os: N }` | Weak: the whole header, object table and object page table validate (below), confidence 0.85 | CPU type field (`08h`): 80286 is 16-bit x86, 80386 and 80486 are 32-bit x86 | IBM, "LX - Linear eXecutable Module Format Description", June 3, 1992 (`lxexe.txt`), Figure 2, Object Table, Object Page Table |
| LE header at offset 0 | `le` (display name "LE") | `BareLe { cpu: N, os: N }` | Weak, as LX, with 4-byte page entries and a last page size | CPU type field, as LX | Windows SDK `IMAGE_VXD_HEADER` (Wine `wine-9.0` `include/winnt.h` lines 2582-2634); Open Watcom `bld/watcom/h/exeflat.h` (`le_map_entry`, `last_page`) and `bld/exedump/c/os2exe.c` (`dmp_obj_page`) |
| PE behind a `ZM` DOS header | `pe` (display name "PE") | none | Strong: `ZM` at 0 and `PE\0\0` at `e_lfanew` (0x3C), the same check as for `MZ` | COFF machine field, as for any PE image | MS-DOS 2.0 `v2.0/source/DOSSYM.ASM` lines 571-589 and `EXEC.ASM` lines 332-336; Microsoft "PE Format", "MS-DOS Stub (Image Only)" and "Signature (Image Only)" |

The classification of a header without a stub is the one the existing
LE/LX parser gives behind a stub: the same ISA, bit width, variant (for
example `OS/2 80386`) and notes, plus the note `No MZ stub; the LX header
starts at offset 0x0`. Only the detection differs: behind a stub the file
is reported by its DOS header (`mz`, variant `Lx { cpu: 2, os: 1 }`), which
is the existing behaviour and is kept; without a stub there is no DOS
header, so the detection reports `le` or `lx`.

A `ZM` PE image gets the note `DOS header signature is ZM, the byte-swapped
MZ that the MS-DOS loader also accepts; whether PE loaders accept it is not
verified`. Everything else is the PE parser's result.

### Sources

All fetched on 2026-10-13; SHA-256 of the fetched files:

| Source | Pin | SHA-256 |
| --- | --- | --- |
| IBM LX specification (`lxexe.txt`) | <http://www.textfiles.com/programming/FORMATS/lxexe.txt> | `a93d8bb249b774957d463d81c60eb80d9a8f3792dff7047feaefb0e5b6599840` |
| MS-DOS 2.0 `v2.0/source/DOSSYM.ASM` | `microsoft/MS-DOS` commit `2d04cacc5322951f187bb17e017c12920ac8ebe2` | `6ced8dec5ea565c9ae782051735550bd9fbae69b983e645425d47075aa8b1dc3` |
| MS-DOS 2.0 `v2.0/source/EXEC.ASM` | same commit | `7a7259f642cf89ade60ca231f114e92f1d898c4b23f6ca1c004b207545233504` |
| MS-DOS 4.0 `v4.0/src/INC/EXE.INC` (same constants) | same commit | `5c86dd64dcabbc28b4cab5e21599f41fc41cce48f853c49cae178988d6bc62c3` |
| Microsoft "PE Format" `desktop-src/Debug/pe-format.md` | `MicrosoftDocs/win32` commit `ca8274decead49403d70ceeed4af8d4ca74eaf11` | `b17271a341f9b6e3204cf3f04ed905c25c03fd4cadb7a57bd4aaf38cf56a2fe0` |
| Wine `include/winnt.h` | tag `wine-9.0` | `070971366a2c6c351da742a5496e5d973ddc404410e466cfad1fd432d1b3575d` |
| Open Watcom `bld/watcom/h/exeflat.h` | `open-watcom/open-watcom-v2` commit `08213659bcc7b4f6d3f0c3891ed8c24d29910de1` | `81ba50d26dae80e45a2dbc6e75edd38772c33c7ca45f7525f5718946a8d2f1e6` |
| Open Watcom `bld/exedump/c/os2exe.c` | same commit | `d2a544abb6c634caa22eb46b1e1fcdf24d1f808df0503ecd2931f2cadf20d00b` |
| Open Watcom `bld/exedump/c/wdmp.c` | same commit | `ae5e3edc5f282166c9f27983b96973419e83a30220a73871df4777cedff04971` |
| OS/2 toolkit `exe386.h` (osFree copy) | `osfree-project/osfree` commit `81e2f166d00d83bcc56514e431c5edd074fd43a8`, `tools/UNI2/UNI/exe386.h` | `684b604ec66362d7818a5f4e69f360f7a2fe26ca34437658328b88de3b1628e9` |

What each source establishes:

- `ZM`: `DOSSYM.ASM` defines `exe_valid_signature EQU 5A4Dh` (the bytes
  `MZ`) and `exe_valid_old_signature EQU 4D5Ah` (the bytes `ZM`); the EXEC
  loader compares the first word of the file with both and loads either as
  an EXE. MS-DOS 4.0 keeps both. The PE specification names the stub's
  `e_lfanew` and the PE signature but not the stub's own signature bytes;
  `winnt.h` defines only `IMAGE_DOS_SIGNATURE 0x5A4D`.
- No stub: the LX specification marks the DOS 2.0 section "(Discarded)",
  makes the header tables relative to the linear header and the data pages
  relative to the file. Open Watcom's `wdump` (`wdmp.c`, `dmp_exe`) reads
  an LE/LX header at offset 0 when the file has no DOS header.
- Documented values: CPU types `01h` 80286, `02h` 80386, `03h` 80486 (LX
  specification, `exe386.h` `E32CPU286/386/486`, `exeflat.h`
  `OSF_CPU_286/386/486`); OS types `00h` unknown, `01h` OS/2, `02h`
  Windows, `03h` DOS 4.x, `04h` Windows 386; format level 0; page size
  4096 ("For the initial version of this linear EXE format the page size is
  4Kbytes", `exeflat.h` `OSF_DEF_PAGE_SIZE 4096`).
- Module type: the LX specification's `MODULE FLAGS` list `00038000h =
  Module type mask` and the values of the masked field; `exe386.h` has the
  same values (`E32MODEXE` to `E32MODVDEV`, `E32MODMASK 0x38000L`), and
  `wdump` (`os2exe.c`, `dmp_mod_flags_lelx`) compares the masked value with
  each type.

## Module type

The module type is the value of the module flags (`10h`) under the mask
`38000h`, compared whole: the virtual device driver type `28000h` contains
the library type's bit `8000h`, so testing single bits reads a VxD as a
library. The `Type:` note, behind a stub and without one:

| Masked value | LX specification | `Type:` note |
| --- | --- | --- |
| `00000h` | Program module | `Executable` |
| `08000h` | Library module | `DLL` |
| `18000h` | Protected Memory Library module | `DLL` |
| `20000h` | Physical Device Driver module | `Physical device driver` |
| `28000h` | Virtual Device Driver module | `Virtual device driver` |
| `10000h`, `30000h`, `38000h` | not defined | `Unknown (0x10000)` and so on |

The other module flags do not change the type. Open Watcom writes `8020h`
for a Windows 3.x VxD (`exeflat.h`, `VXD_DEVICE_DRIVER_3x`), whose type
field is the library type: such a file (IDA's `pc_drv.le`) reports
`Type: DLL`, which is what its header says.

## CPU type

The CPU type (`08h`) is the ISA evidence of an LE or LX header. The LX
specification defines `01h` (80286), `02h` (80386) and `03h` (80486); the
stubbed parser also maps `04h` (Pentium, 32-bit x86), `20h` (i860) and
`40h` to `42h` (MIPS), values without a primary source here (A5). A header
without a stub must carry `01h` to `03h`.

Behind a stub, any other value (`00h`, `21h`, or a value no source lists)
names no ISA: the parser's result is `Isa::Unknown` with the CPU type as
its ID, bit width 0 and confidence 0, the variant keeps its form (`OS/2
Unknown`), and the note is `CPU: Unknown (0x21)`. The DOS header still
makes the detection strong (`mz`, variant `Lx { cpu: 33, os: 1 }`). As for
any format result with an unknown ISA, the classifier then runs the code model
over the file; if that identifies an ISA, the payload takes it with source
`combined` and the note `ISA identified from the code, not the container`,
otherwise the ISA stays unknown.

## Wire units and byte order

- All offsets are in bytes. In the header, the object table, object page
  table, resident name, entry and fixup table offsets are relative to the
  linear header; the data pages, iterated pages and non-resident name
  offsets are relative to the file. With the header at offset 0 both are
  file offsets.
- `B-ORD` (`02h`) and `W-ORD` (`03h`) give the byte and word order of the
  format: 0 little-endian, 1 big-endian. A header without a stub must have
  both 0 or both 1 and is read in that order. Behind a stub the existing
  parser reads the header little-endian whatever these bytes say, and that
  behaviour is kept. The ISA's byte order does not come from these fields:
  every accepted CPU type is x86, which is little-endian.
- LX object page table entries are 8 bytes: page data offset (shifted left
  by the page offset shift at `2Ch`, relative to the data pages), data size
  and flags. LE entries are 4 bytes: a 24-bit page number, most significant
  byte first (`os2exe.c` builds the number that way whatever the header
  order), and a flags byte; page n starts at (n - 1) * 4096 bytes after the
  data pages, and the last page holds the last page size at `2Ch`.
- EIP (`1Ch`) is relative to the EIP object; it is reported as the entry
  point, as it is behind a stub.

## Validation and resource bounds

A header without a stub has only a two-byte key, so it is weak (AGENTS.md
section 3.2): `detect_format` checks it among the weak layouts, after the
MBR check and before the zlib, LZMA-alone and TI structure-only checks, so
it only sees inputs no magic-bearing format claimed, and only a complete
validation recognizes it. A header that fails any check is not recognized
and the input goes on to raw classification. The checks, in order (the
order of the error messages `mz::parse` gives for a `BareLe` or
`BareLx` type):

1. The signature `LE` or `LX` at offset 0 and at least the 172-byte (`ACh`)
   header the LX specification defines.
2. `B-ORD` and `W-ORD` both 0 or both 1.
3. Format level 0; CPU type 1, 2 or 3; OS type 0 to 4; page size 4096.
4. At least one object; the object table (24-byte entries) at or after
   `ACh` and inside the file.
5. Every object with pages: a 1-based page table index whose run ends
   within the module page count.
6. The EIP and ESP objects are 0 or existing objects; a program module
   (module type 0 in the mask `38000h`) names its EIP object, which the
   specification requires for a program to load.
7. The object page table (module page count entries) at or after `ACh` and
   inside the file; the data pages offset at or after `ACh` when there are
   pages.
8. LX: page offset shift at most 31; the iterated pages offset 0 or equal to
   the data pages offset (required by OS/2 2.0 per the specification); every
   page's data size at most 4096 B and, when nonzero, inside the file. LE:
   last page size at most 4096 B; every page number at most the module page
   count; the data pages ((count - 1) * 4096 B plus the last page size)
   inside the file.

Every table is located with checked arithmetic and bounded by the file
size before a loop walks it; nothing is allocated from a header value, and
the walk is linear in the file size. Fixup, loader and non-resident name
checksums are not verified: the specification calls them cryptographic but
does not define them, and a linker that does not implement them writes 0. Fixups, imports, resources and
entry tables are not parsed.

`e_lfanew` is located with checked arithmetic for both `MZ` and `ZM`, so an
offset near `u32::MAX` is a non-match on 32-bit targets (WebAssembly) as
well as 64-bit ones; the same check now guards the extended header lookup
in `mz::detect`.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| A1 | A header without a stub validates exactly like one behind a stub once file-relative offsets are rebased | `ida_stubbed_samples_validate_once_unbound_and_keep_their_classification`: IDA's `pc_drv.le`, `pc_popple_unchecked.le`, `pc_tomb.le`, `pc_vxd.le` (LE) and `pc_os2_exe.lx` (LX) with the stub removed and the data pages, iterated pages and non-resident names offsets rebased all validate and keep their stubbed ISA and variant |
| A2 | The entry address is not bounded by the EIP object's virtual size | `pc_tomb.le` (DOS/4GW) has EIP `0x3A584` in object 1 of virtual size `0x20710`; only the object number is checked |
| A3 | The object table's reserved word need not be zero | `pc_vxd.le` stores object names (`LCOD`, `ICOD`, ...) there; it is not checked |
| A4 | LX page flags need not be in the 1992 list (0 to 4) | IDA's bare samples carry flag 5 (OS/2 Warp compressed pages, not in the pinned specification, UNCONFIRMED); flags are not checked, only data extents |
| A5 | Only CPU types 1 to 3 are documented | The Pentium (`04h`), i860 (`20h`) and MIPS (`40h`-`42h`) values the stubbed parser maps have no primary source here (`21h` has a constant but no mapping); a header without a stub carrying them is not recognized (`header_and_table_corruptions_are_not_recognized_and_name_the_field`). A sample with such a value and a primary source would extend the list |
| A6 | Text starting with `LE` or `LX` is not recognized | `ascii_text_starting_with_le_or_lx_is_not_an_executable`: the order bytes rule out ASCII text |
| A7 | A `ZM` header alone is not evidence of an executable | Without `PE\0\0` at `e_lfanew` a `ZM` file is not reported as MZ, NE, LE or LX (`zm_without_a_pe_signature_is_not_a_dos_executable`); only the PE signature makes it strong |
| A8 | The module type is the masked value, not a set of bits | `module_types_are_the_whole_type_field_behind_and_without_a_stub`; with `IDA_INPUT_DIR`, `ida_stubbed_samples_report_the_module_type_of_their_type_field`: `pc_vxd.le` (`28000h`) is a virtual device driver. A file of a documented type whose masked value differs would falsify it |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Windows PE loaders and `ZM` | Not verified; the note says so. MS-DOS acceptance is from the MS-DOS 2.0 source |
| `ZM` DOS, NE, LE or LX files (no PE signature) | Not recognized, as before; only the PE signature was in scope |
| Big-endian LE/LX behind a stub | Read little-endian, as before (kept; see `linear_result`) |
| LE/LX members of archives and filesystems | Recognized only when the prefix the container checks holds every page (weak detection needs the whole input) |
| Fixups, imports, entry tables, resources, iterated and compressed page data | Not parsed or decoded; the ISA comes from the CPU type field |
| LE/LX headers at an offset other than 0 without an MZ stub (bound DOS extenders that append the header after their own image) | Not recognized: nothing points at the header |
| Module types the specification does not define (`10000h`, `30000h`, `38000h`) | Reported as `Type: Unknown (0x…)`; the header still classifies by its CPU type |
| Windows 3.x VxDs with the library type (`8020h`) | `Type: DLL`: the type field names a library, and nothing else in the header is checked to tell a VxD apart |
| Unmapped CPU types behind a stub | Unknown ISA from the header (`unknown_cpu_types_behind_a_stub_name_no_isa`); any ISA comes from the code model. Without a stub such headers are not recognized |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly):

- `tests/mz.rs`: 18 tests passed, with `IDA_INPUT_DIR` set to IDA's
  `tests/input` (without it the four IDA tests skip). The 12 unit tests in
  `src/formats/mz.rs` (6 existing, 6 new) passed.
- IDA samples, read-only: `pc_nomz.le`, `pc_huge_imports.lx`,
  `pc_huge_obj.lx`, `pc_bad_fixups.lx` and `pc_bad_iterate2.lx` are
  recognized as LX, 32-bit x86, `OS/2 80386` (fixups, imports and the
  oversized object are not parsed, so they do not matter);
  `pc_bad_nfixups.lx` (8,388,610 pages), `pc_bad_nimports.lx` (no objects),
  `pc_bad_nojbs.lx` (page size `0x1505C60B`), `pc_bad_npages.lx` (object 2
  page run), `pc_bad_pagesize.lx` (page size `0x80001000`) and
  `pc_bad_vxd.le` (CPU type `0x102`) are not recognized and fail
  `mz::parse` with the named error; every truncation and every byte mutated
  to `0x00`, `0xFF` and a bit flip of these eleven files is bounded.
  `pc_import_samedll.pe` (`ZM`) is PE, 32-bit x86, with the `ZM` note.
  Before this change the eleven bare files were inconclusive raw data,
  except `pc_bad_iterate2.lx`, which the code model had called C166, and
  `pc_import_samedll.pe` was inconclusive.
- Differential snapshot (AGENTS.md section 6), run on the base commit
  `0873885` and on this change: 1,904,355 distinct inputs from 760 files:
  the 725 IDA inputs starting with `MZ`, `ZM`, `LE`, `LX` or `NE`,
  `testbins/ia64_le_ftpm-efi.bin`, and 34 synthetic MZ, NE, stubbed LE/LX,
  PE, `ZM` and bare fixtures. Each file whole; files up to 8 KiB with every
  truncation and every byte set to `0x00`, `0xFF` and one bit flip;
  larger files with the truncations up to 512 B, around `e_lfanew` and at
  32 spread lengths, and those mutations in the DOS header, the first 64 B
  at `e_lfanew` and 32 spread positions. Per input, the `detect_format`
  and `mz::detect`/`mz::parse` results and the `detect_payload` JSON
  were hashed. All 1,789,570 inputs derived from `MZ` files are identical.
  The 42,384 changed inputs derived from bare files come from the five
  recognized IDA samples, the two synthetic fixtures and one mutation each
  of `pc_bad_nfixups.lx` and `pc_bad_pagesize.lx` that repairs the broken
  field; the 3,885 changed `ZM` inputs are `pc_import_samedll.pe` and the
  synthetic `ZM` PE images (now PE). A `ZM` file without a PE signature
  is unchanged.
- `tests/idaref.rs` with `IDAREF_DIR` set to IDA's `tests/input`
  passed. For the `pc_` prefix, base `0873885` had 1,640 correct, 3 wrong
  and 148 inconclusive; this change has 1,646 correct, 2 wrong and 143
  inconclusive (overall 88.1% correct, 0.2% wrong of 4,618 supported files).
- `web/tests/mz.test.mjs` (4 tests) passed after `./build-web.sh`, through
  `/pkg/zrax.js`, `/dist/zrax.js` and both workbench pages. The whole
  browser suite (`npm test`: 216 tests) passed 212 and skipped 4 (they need
  D10 and RX113 firmware that is not in the repository).
- `cargo test --all-features --locked`: 1,865 passed, 6 ignored (base:
  1,841 passed, 6 ignored), without `IDA_INPUT_DIR`, so the four IDA tests
  of `tests/mz.rs` returned early there.

After integration with the families added since (through Symbian SIS) on
the same day, `cargo test --all-features --locked` passed 1,919 tests with
6 ignored, and `tests/mz.rs` passed 18 of 18 with `IDA_INPUT_DIR` set. On
IDA's corpus (4,621 files), `pc_bad_fixups.lx`, `pc_huge_imports.lx`,
`pc_huge_obj.lx`, `pc_nomz.le` and `pc_import_samedll.pe` went from
inconclusive to x86 and `pc_bad_iterate2.lx` from wrong (C166) to x86; no
other file changed.
