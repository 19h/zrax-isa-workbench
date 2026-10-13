# Atari 8-bit disk images and executables

`src/formats/atari8.rs` and its submodules (`atr.rs`, `dos2.rs`, `xex.rs`)
parse ATR disk images and Atari DOS binary load files into the shared
container model ([compressed streams and the container
model](compressed-streams.md)). An ATR image lists the files of its Atari
DOS 2.x file system as children, each reassembled from its sector chain,
followed by the OS boot record. A binary load file, standalone or on a
disk, loads its segments as sections at their 6502 addresses and reports
RUNAD and INITAD as entry points.

Primary sources:

- [HRM] Avery Lee, "Altirra Hardware Reference Manual", 2026-01-02 edition
  (`https://www.virtualdub.org/downloads/Altirra%20Hardware%20Reference%20Manual.pdf`,
  SHA-256 `1909927618a7f4a6771d2dc7ef1785ba9b13453edba57122165f57c1504d1c89`,
  downloaded 2026-10-13). Sections are cited by number.
- [ALT] Altirra 4.31 source, unofficial mirror `irismessage/altirra` at
  commit `48272b277ba8dc09b73cedc933d77112a0a8a1c7`:
  `src/ATIO/source/diskimage.cpp` (`LoadATR`, `SaveATR`),
  `src/ATIO/source/diskfsdos2.cpp`, `src/Altirra/source/hleprogramloader.cpp`
  and the AltirraOS kernel `src/Kernel/source/Shared/boot.s`.
- [A800] atari800 5.2.0 (`atari800/atari800`, tag `ATARI800_5_2_0`, commit
  `fefb7d4ae07d0662990ea4a26b0eecb407c7afaf`): `src/afile.h`, `src/sio.c`
  (`SIO_Mount`, `SIO_SizeOfSector`), `src/binload.c`.
- [ASIO] AtariSIO (`HiassofT/AtariSIO`, commit
  `bbccb15265259a1408f36d7ed9b89bb08bbb711d`): `tools/AtrImage.cpp`,
  `tools/Dos2xUtils.cpp`, `tools/ComBlock.cpp`.
- [IAD] Bill Wilkinson, "Inside Atari DOS" (COMPUTE! Books, 1982), chapters
  2, 20 and 21, read from the Internet Archive copies
  `web.archive.org/web/2021id_/https://www.atariarchives.org/iad/chapter2.php`
  (and `chapter20.php`, `chapter21.php`).
- [MAP] Ian Chadwick, "Mapping the Atari", revised edition (COMPUTE! Books,
  1985), entries 12-13, 576-579 and 736-739, read from
  `web.archive.org/web/2021id_/https://www.atariarchives.org/mapping/memorymap.php`.
- [XEX5] B. Watson, `xex.5` (bw-atari8-tools 0.2.1, 2025-02-25),
  `slackware.uk/~urchlay/repos/bw-atari8-tools/plain/xex.5?h=0.2.1`.
- [JIN] Jindroush, "ATR File Format Description" (`afmtatr.htm`, pigwa.net
  mirror): a secondary description; the fields it marks with "?" are not
  used.
- [LD65] cc65 2.19 (tag `V2.19`, commit
  `555282497c3ecf8b313d87d5973093af19c35bd5`): `doc/ld65.sgml` "The FORMAT
  section", `src/ld65/xex.c`.

## Implemented layouts

| JSON format ID | Variant | Layout | Recognition | Components | Primary source |
| --- | --- | --- | --- | --- | --- |
| `atr` | `ATR disk image` | 16-byte header, then sectors 1 to n of 128, 256 or 512-8192 bytes; 256-byte images with sectors 1-3 stored as 128 bytes, or in 256-byte slots (physical or SIO2PC) | Strong: magic `96 02`, a documented sector size and a declared size of 1 to 65,535 whole sectors | DOS 2.x files in directory order (binary load files as 6502 code, others opaque), then the boot sectors | [A800] `afile.h`, `SIO_Mount`; [ALT] `LoadATR`; [ASIO] `AtrImage.cpp`; [HRM] 10.1 |
| `atr` (file system) | — | Atari DOS 2.0S, 2.0D and 2.5: VTOC at sector 360, directory at 361-368, 125- or 253-byte data sectors with a 3-byte link trailer | Sector size 128 or 256, at least 720 sectors, VTOC code 2, and the boot, VTOC and directory sectors in use in the VTOC bitmap | One child per file, labeled `NAME.EXT` | [IAD] 2; [ALT] `diskfsdos2.cpp`; [ASIO] `Dos2xUtils.cpp` |
| `atr` (boot record) | — | Sector 1: flags, boot sector count, load address, initialization address; the loader at load address + 6 | Sector 1 not empty | `Boot sectors 1-N`, 6502 code, last | [MAP] 12, 576-579; [ALT] `boot.s`; [IAD] 20 |
| `atarixex` | `Atari DOS binary load file` | `FF FF`, then segments of start and inclusive end address (2 + 2) and the loaded bytes; markers optional after the first segment | Weak: every segment valid, the segments tile the file exactly, and one of them loads a run address (RUNAD) or a complete init address (INITAD) | Segments as sections at their load addresses | [MAP] 736-739; [XEX5]; [A800] `binload.c`; [ALT] `hleprogramloader.cpp`; [ASIO] `ComBlock.cpp` |

Notes give the geometry and boot-sector layout, the file system census (file
count, the VTOC's free and total counts as recorded), each skipped entry or
broken chain, and the boot record fields. Metadata records `atr_sector_size`,
`atr_sector_count`, `atr_dos_files`, `atr_boot_sectors`,
`atr_boot_load_address` and `atr_boot_init_address`; for binary load files
`atarixex_segments`, `atarixex_loaded_size`, `atarixex_runad` and
`atarixex_initad`. The generated `atr_component_<n>` and
`atarixex_section_<n>` entries give stored offsets.

## Detection

ATR is checked right before the magic-bearing compressed streams. No format
above it starts with `96 02`; the formats above that are keyed at later
offsets (ISO 9660 at 0x8001, ext at 0x438, tar at 257) would need their
complete structures inside the disk's sectors. The 16-bit magic is not
strong on its own, so the header must also name one of the seven sector
sizes and declare a whole number of sectors (1 to 65,535) in the layout
that sector size selects. The file length is not part of the test: a
truncated image is recognized and rejected as truncated, and an ATR image
inside an archive is recognized from the member prefix that
`container::is_recognized` examines.

A binary load file has only its two-byte marker. It is checked among the
weak layouts, right before zlib and LZMA-alone, and only when the marker is
followed by valid segments that end exactly at the end of the file, so
erased flash (`FF` throughout), trailing data and a trailing marker are not
taken for one. A standalone file must also load a run address or a complete
init address, through which DOS starts a program: erased flash with a few
programmed bytes tiles into short segments at 0xFFxx (16 of 200,000
deterministic noise buffers did before this rule, none after) but
practically never loads the vectors. A file of segments without vectors is
left to the code model. Inside an ATR image, a DOS file is classified as
6502 code when its segments tile it; the vectors are not required there,
since the disk structure has been validated.

## CPU evidence

The Atari 8-bit computers use "a MOS 6502, with an 8-bit data bus and 16-bit
address bus"; "some versions of the computer use a customized variant
called a 6502C" ([HRM] 2.1), the "6502C (Sally)", which "uses the same NMOS
6502 core" ([HRM] 3.6), and "the 6502 is a little endian processor" ([HRM]
1.4). ATR images and DOS binary load files exist only for this family, so
the code they load is NMOS 6502 code: binary load files and boot sectors get
the target `mcs6502`, 8-bit, little-endian, with the variant `6502`. The ATR
container itself names no ISA: its primary ISA comes from the first child
that has one, and the boot sectors are pushed after the files, so a DOS boot
loader decides the ISA only of a disk without programs.

## Wire units and byte order

All header fields, addresses and counts are little-endian. ATR sizes are in
16-byte paragraphs; sector numbers start at 1 and are 16-bit ([HRM] 10.1);
child and section offsets are file offsets including the 16-byte header.
DOS 2.x sector links are 10-bit sector numbers; data byte counts are bytes.
Binary load segment addresses are 6502 byte addresses; end addresses are
inclusive.

## Validation and resource bounds

- ATR: the declared size must be a whole number of sectors in the layout the
  sector size selects (128-byte boot sectors when a 256-byte image's size
  leaves 128 over a multiple of 256, slots otherwise) and at most 65,535
  sectors. Bytes after the declared image must be `0x00`/`0xFF` padding
  (noted) or the image is rejected.
- DOS 2.x: at most 64 directory entries; the first entry with flags 0 ends
  the directory. Each chain is followed until its zero link and must stay
  on the disk, avoid the 128-byte boot sectors of a double-density image,
  carry the file's number in every sector, declare at most 125 (or 253)
  bytes per sector and visit no sector twice (a per-sector mark, so every
  chain is bounded by the sector count). A broken chain skips that file
  with a note; at most 16 problems are listed and the rest counted. A
  directory sector count that disagrees with the chain is noted. Extraction
  stops at `MAX_EXTRACTED` (256 MiB), which no 65,535-sector disk reaches.
- Boot record: the count 0 means 256 sectors ([ALT] `boot.s`); at most the
  three 128-byte boot sectors of a double-density image are listed, and the
  record is opaque when its sectors would load beyond 0xFFFF.
- Binary load files: an end address below the start, a truncated header or
  segment, or bytes after the last segment are errors. The walk allocates
  nothing during detection; at most 4,096 segments are listed as sections
  (the rest counted) and 16 init addresses are listed (the rest counted).

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| A1 | Header bytes 2-3 and 6 hold the paragraph count, as [A800], [ASIO], [ALT] `SaveATR` and [JIN] agree; byte 7 (paragraph bits 24-31 to [A800] and [ASIO], an APE checksum byte to [JIN]) is ignored | `atr_header_and_size_damage`: a size that is not whole sectors is not an ATR header, a file shorter than its header declares is a truncation error, and trailing data that is not padding is an error; an image over 256 MiB cannot be described |
| A2 | A 256-byte-sector image whose size is a multiple of 256 stores sectors 1-3 in slots, physical when any of image bytes 0x180-0x2FF is nonzero ([A800] `SIO_Mount`); [ALT] uses a different test | `double_density_layouts_place_short_boot_sectors` builds all three layouts; a physical image whose bytes 0x180-0x2FF are all zero (sector 3 empty, unused slot halves zero) is read as SIO2PC, which shifts sectors 2 and 3 |
| A3 | A disk holds DOS 2.x when its VTOC code is 2 and the bitmap keeps sectors 1-3 and 360-368 in use ([ALT] `Validate`) | `disks_without_a_dos2_file_system_classify_their_boot_record`; a MyDOS disk with VTOC code 2 is read as DOS 2.x and its subdirectories and 16-bit-link files are only noted |
| A4 | DOS 2.5 is a 1040-sector single-density disk with VTOC code 2, where flags 0x03 mark a visible file ([ALT] `IsVisible`, [ASIO] `SetAtariDirectory`) | `dos25_enhanced_density_lists_files_flagged_0x03`; the second VTOC at sector 1024 is not read |
| A5 | A file that tiles into binary load segments is a 6502 program and anything else on the disk is data | A BASIC program or text that happens to tile would be classified as code; DOS.SYS (loaded by the boot code, not a binary load file) is listed as opaque |
| A6 | The OS loads 128 bytes of each boot sector at consecutive addresses and enters at load address + 6 ([ALT] `boot.s`, [IAD] 20) | `implausible_or_empty_boot_records_are_opaque`; a boot count above 3 on a double-density disk is not modeled |
| A7 | Any number of `FF FF` markers may precede a segment, so no segment starts at 0xFFFF ([A800], [ALT], [ASIO] skip them all) | `repeated_markers_are_skipped`; a loader that reads a second `FF FF` as a start address would load such a file differently |
| A8 | RUNAD is reported when both of its bytes are loaded; an init call when one segment loads both INITAD bytes, as DOS calls INITAD after each segment ([MAP] 738; [ALT] presets INITAD before each segment) | `without_a_run_address_the_first_init_call_is_the_entry`; the emulators' default run address (the first segment's start) is not reported |
| A9 | A standalone binary load file that loads neither RUNAD nor INITAD is not a program worth claiming; inside an ATR image such a file is still classified as a binary load file | `standalone_binary_load_files_must_load_a_run_or_init_address`; a real data file loaded by a program's own loader would be left to the code model |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| XFD (headerless), DCM, ATX, PRO and CAS images | Not recognized: no header (XFD) or another format |
| DOS 1.x files, MyDOS subdirectories and 16-bit sector links, SpartaDOS and other file systems | Noted, not extracted; a SpartaDOS disk reports its boot record only |
| SpartaDOS X executables (`FA FF`, `FE FF`) | Not recognized ([ALT]: they "must be loaded under SpartaDOS X") |
| Binary load files whose init code reads raw data from the rest of the file ([XEX5] "raw data blocks"), or that end in padding | Not recognized: they do not tile into segments |
| ATR header flags, the APE checksum and write protection | Not interpreted (the sources disagree on their positions) |
| VTOC free counts and bitmap against the chains | Reported as recorded, not verified |
| Boot sectors of 512-byte and larger sectors | Not interpreted |
| Deleted files | Counted, never recovered |
| Binary load files inside archives and other filesystems | Listed only when the member prefix that `container::is_recognized` examines holds the whole file, since a prefix does not tile into segments |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`):
`tests/atari8.rs` (16 tests) and the 15 unit tests in
`src/formats/atari8.rs` and `src/formats/atari8/` passed, within a full
`cargo test --all-features --locked` run of 1,878 passing tests with 6
ignored. The integration tests use the cc65-linked `program.xex`
([fixture README](../tests/fixtures/atari8/README.md)) and synthetic files
and disks built in the test from the documented layouts: binary load files
with optional markers, init-only and data-only files, and every invalid
segment form; single-density, double-density (all three boot-sector
layouts) and DOS 2.5 disks with multi-sector, single-sector, deleted, DOS
1.x, MyDOS and open entries; broken chains (loops, foreign file numbers,
links beyond the disk or into a boot sector, oversized counts); disks
without a file system, with empty, 256-sector and out-of-range boot
records; header damage and trailing data; every prefix of both binary load
files (only prefixes that end after a segment are recognized) and every
61st prefix of a single- and a double-density image (recognized and
rejected as truncated once the header is present); and mutations (`0x00`,
`0xFF`, bit flip) of every byte of the binary load files, of the ATR
header, boot record, VTOC, directory and sampled file sectors, and of every
link trailer byte of a three-sector (single-density) and a two-sector
(double-density) file. `web/tests/atari8.test.mjs` (4 tests) passed
through `/pkg/` and `/dist/` and in both workbench pages, within a full
browser run of 216 tests: 212 passed and 4 skipped (D10 and RX113 firmware
not in the repository).

Not verified: images written by real drives, emulators or disk tools (no
such ATR images were available; dir2atr and other ATR writers were not
installed), DOS 2.0S, 2.0D or 2.5 boot code (none is redistributed), MyDOS
and SpartaDOS disks, and how DOS or an emulator loads the files this parser
accepts or rejects.

At integration on the same day, standalone binary load files were also
required to load a run or init address: the integration noise check (200,000
deterministic buffers) had found 16 erased-flash-like buffers recognized as
binary load files, and none after the change. The native suite then passed
2,124 tests with 6 ignored; IDA's corpus (4,621 files) and a scan of 82,323
local files classified as before.
