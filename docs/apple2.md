# Apple II disk images

`src/formats/apple2.rs` and its submodules (`dos33.rs`, `prodos.rs`,
`twoimg.rs`) parse Apple II disk images into the shared container model
([compressed streams and the container model](compressed-streams.md)): raw
16-sector DOS 3.3 images in DOS or ProDOS sector order (`.dsk`, `.do`,
`.po`), raw ProDOS volume images (`.po`, `.hdv`, 140 KiB `.dsk`), and 2IMG
images (`.2mg`) holding either. Every file is a child labeled by its name or
path; binary and system files are 6502 code, every other file type is
opaque, and the boot sector or loader blocks follow the files as a 6502
child.

Primary sources:

- [CP2] CiderPress II, `fadden/CiderPress2` at commit
  `7a055a200e31f752f3a92bb9fe6ae6f67cd55534` (2026-07-24), fetched
  2026-10-13 from `raw.githubusercontent.com`:
  - `DiskArc/FS/DOS-notes.md` (SHA-256
    `f2ba157ae8cbbd0daaaa1cfc616c5e70ad1675aea577d2de3357f2bd830b0816`),
    `DOS.cs` (`6fc31132a0ced6312eeec8f41bb4f8057f015eca82a99856cd40521c871834f2`),
    `DOS_VTOC.cs` (`cbf76ea39b633ad084efa4fbbf50e76c130b323be9eccdaeb4267b23d7bcffda`),
    `DOS_FileEntry.cs` (`065ed7e4a5c82cd7314750108437a8c365fdd6d51a6f590868a5b08410f14a4d`);
  - `DiskArc/FS/ProDOS-notes.md`
    (`51c59e5ecf760d7021f00f71e47ff93e662dd44dc347b32d678f7254ea44acd8`),
    `ProDOS.cs` (`73aceba0e1b2cf2c82144735ff0003e3b51e54a27a4a915337eaa6ce2c1609f0`),
    `ProDOS_FileEntry.cs` (`02ad3af3211a1fefd54ed93a551d872b13c4b8d1439d3deb30c0040305c3f66a`),
    `ProDOS_FileDesc.cs` (`9df10894c398f1788c01d8b8c8b2263cc0cf762bf17f29603cf1e75e5a16c7dd`);
  - `DiskArc/Disk/TwoIMG-notes.md`
    (`06d6064c951dda0516588ece778ba350ddd54c937e00bba2ab93f4c22d27f8a2`),
    `TwoIMG.cs` (`e866d2ea827b062ccb4820ec6ec4bc979d1a60475ac4ccb95594776895889ec5`),
    `Unadorned-notes.md` (`4d12769695c595b1611c926dcac79c5123bba31bba29828cb673b6c9dc53a693`),
    `DiskArc/GeneralChunkAccess.cs` (skew tables,
    `782cb8439853a53a42a9fd6f26351565f65fa8b97554d352bfa7bcc8a04f0a22`).
- [BAD] Don Worth and Pieter Lechner, "Beneath Apple DOS", the reference
  [CP2] `DOS-notes.md` names; archive.org `Beneath_Apple_DOS_alt` text
  (SHA-256 `219f367bfd042c2acd829ddffb2024f845624e674c1c8959f19dfeea8afa4147`):
  chapter 4 pp. 4-2 to 4-12 (VTOC, catalog, file entries, track/sector
  lists, binary files) and chapter 5 p. 5-6 (boot).
- [TRM] Apple, "ProDOS 8 Technical Reference Manual" as published at
  `prodos8.com/docs/techref/` (fetched 2026-10-13): Preface; "Memory Use";
  "Writing a ProDOS System Program"; Appendix B, "File Organization" (B.1
  to B.5, Figures B-3, B-4, B-6 to B-8 and B-15).
- [2IMG] "Disk Images", magnet.ch emutech, web.archive.org snapshot
  `19981206023530` of `http://www.magnet.ch/emutech/Tech/`, the description
  [CP2] `TwoIMG-notes.md` names as its primary reference.
- [A2REF] Apple, "Apple II Reference Manual" (1979), chapter 1: "It is a
  Synertek/MOS Technology 6502 microprocessor" (archive.org
  `Apple_II_Reference_Manual_1979_Apple`, text SHA-256
  `e71930f8877a12e22d2f6fef61be3303ef8f98b4fdceef2c688c7878bc57492e`).
- [A2C] Apple, "Apple IIc Technical Reference Manual" (1985), section 2.1
  "The 65C02 Microprocessor" and Appendix A (archive.org `a2ctrm`, text
  SHA-256 `e3bc7a6c2343e4863d7527e24068fbbbbf189355fccaf6974ddc01b49ea28d7a`).

No Apple II disk tool is installed locally, so every fixture is built in
the tests from the documented layouts; no rule is taken from a tool's
output.

## Implemented layouts

| JSON format ID | Variant | Layout | Recognition | Components | Primary source |
| --- | --- | --- | --- | --- | --- |
| `apple2dos` | `DOS 3.3, DOS order` / `DOS 3.3, ProDOS order` | 35 or 40 tracks of 16 sectors of 256 B (143,360 or 163,840 B); VTOC at track 17 sector 0; catalog chain; track/sector lists | Weak: exact size, VTOC and catalog (see Detection) | Files in catalog order; boot sector | [BAD] pp. 4-2 to 4-12; [CP2] `DOS-notes.md`, `DOS.cs` |
| `apple2dos` | `DOS 3.3, ambiguous sector order` | A catalog that validates equally in both orders | Weak | None: nothing is extracted | [CP2] `DOS.TestImage` |
| `prodos` | `ProDOS, ProDOS order` | 512-byte blocks; volume directory key block 2; seedling, sapling, tree, extended (GS/OS) storage; subdirectories | Weak: image exactly the volume, volume directory | Files by path in directory order; boot blocks 0-1 | [TRM] Appendix B; [CP2] `ProDOS-notes.md`, `ProDOS.cs` |
| `prodos` | `ProDOS, DOS order` | A 140 or 160 KiB ProDOS volume stored in DOS sector order | Weak | As above | [TRM] Figure B-15 |
| `prodos` | `ProDOS, ambiguous sector order` | A 140 or 160 KiB volume directory valid in both orders | Weak | None | — |
| `twoimg` | `2IMG` | 64-byte header (`2IMG`, creator, header length 52 or at least 64, version 1, image format 0/1/2, flags, block count, data, comment and creator chunks); data in DOS order, ProDOS order or nibbles | Strong: magic, header length, version and image format | The DOS 3.3 or ProDOS files and boot code of the data; or the data, listed only when recognized; or opaque nibble data | [2IMG]; [CP2] `TwoIMG-notes.md`, `TwoIMG.cs` |

The JSON `format.variant_name` is the layout name; for 2IMG the container
variant also names the filesystem and order (`2IMG, ProDOS, ProDOS
order`). Notes give the volume (DOS volume number, tracks, order; ProDOS
volume name, blocks, order), how a raw image's order was found, the catalog
census and file types (DOS), the directory walk (ProDOS), the 2IMG creator,
flags, comment and creator data, what was listed, what was left out, each
problem below the catalog or volume directory, and the boot code. Metadata
records `apple2_dos_volume`, `apple2_tracks`, `apple2_catalog_sectors`,
`apple2_sector_order`, `apple2_volume_name`, `apple2_total_blocks`,
`apple2_directory_count`, `apple2_file_count`, `apple2_twoimg_creator`,
`apple2_twoimg_image_format`, `apple2_twoimg_data_offset`,
`apple2_twoimg_comment`, one `apple2_load_address_<n>` per code file (the
load address, file type and size of component `n`) and one
`apple2_component_<n>` per child.

## Detection

Raw images have no magic. `apple2::detect_weak` tries DOS 3.3 first, then
ProDOS:

1. DOS 3.3: the input is exactly 35 or 40 tracks of 4,096 B. In the VTOC
   (track 17 sector 0, which is at the same place in both orders) 122
   pairs per list, 256 B per sector, 16 sectors per track, the track count
   of the image and DOS release 3 must be set, and the first catalog sector
   must be on the disk (not track 0, not the VTOC). The catalog chain is
   followed to its end: every link on the disk, never the VTOC, no sector
   twice. Every active entry up to the first never-used one must name a
   track/sector list on the disk.
2. The sector order: both orders are tried. The order whose catalog chain
   reaches more sectors decides, and the catalog must validate in it. In the
   wrong order a standard catalog (track 17, sectors 15 down to 1) reads
   sector 1, the end of the chain, where it expects sector 14, so its chain
   is two sectors long ([CP2] `DOS.TestImage` scores 29 against 3); a
   catalog damaged in its own order is therefore not taken in the other.
   With chains of equal length, the order in which the catalog validates is
   taken; when it validates in both, the image is `Dos33Ambiguous`.
3. ProDOS: the image is exactly the volume (`total_blocks` blocks, or a
   65,535-block volume in 65,536 blocks), at least 5 blocks, tried in
   ProDOS order and, for 140 and 160 KiB, in DOS order. Block 2's previous
   pointer is 0; the header has storage type 0xF, a name of a letter then
   letters, digits or periods, an entry length of at least 0x27 with the
   entries fitting a block, and a bitmap pointer in blocks 3 to
   `total_blocks - 1`. The volume directory chain (every block inside the
   volume, claimed once, its previous pointer the block before) and every
   active entry (storage type 1-5 or 0xD, a name, a key block in 2 to
   `total_blocks - 1`) must validate, and `file_count` must equal the number
   of entries with a nonzero storage type ([TRM] B.2.2). Valid in both
   orders is `ProDosAmbiguous`.

The weak check runs with the other weak checks, after the FAT and MBR
checks (which need the `55 AA` boot signature these images do not carry)
and before zlib and LZMA-alone. Detection reads the VTOC and the catalog
chain, or the volume directory, and nothing below them.

2IMG is recognized by `apple2::detect`, just before the magic-bearing
compressed streams: `2IMG`, a header length of 52 or at least 64, version
1 and image format 0, 1 or 2. Those 16 bytes are the key, so a stray
`2IMG` is not enough; offsets, lengths and the data size are checked by the
parser, so a damaged 2IMG file is an `Apple II disk image parse error`.

## Wire units and byte order

| Item | Byte order | Units |
| --- | --- | --- |
| VTOC, catalog, track/sector lists, `B` file header | Little-endian 16-bit fields | Tracks and sectors (decimal in notes); 256-byte sectors |
| DOS order image | — | DOS sector `s` of track `t` at file offset `(16 * t + s) * 256` |
| ProDOS order image | — | Block `b` at `512 * b`; DOS sector `s` of track `t` at `(16 * t + p[s]) * 256`, `p = [0, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 15]` ([TRM] Figure B-15: `2 * offset + half - 1`) |
| ProDOS block in a DOS-order image | — | Block `8 * t + k` is DOS sectors `p[2k]` (first half) and `p[2k + 1]` of track `t` |
| ProDOS directory fields, EOF, aux type | Little-endian (EOF 24-bit) | Blocks of 512 B; EOF in bytes |
| Index blocks | Split | Pointer `i`: low byte at `i`, high byte at `256 + i` ([CP2] `GetBlockPtr`) |
| 2IMG header | Little-endian 16- and 32-bit | Bytes; offsets from the start of the file |
| File names | High-bit ASCII (DOS), ASCII (ProDOS) | DOS names print as [CP2] `GenerateCookedName` prints them; ProDOS bytes outside printable ASCII print as `?` |
| Load addresses | — | 6502 byte addresses, `0x{:04X}` |

## Members

- DOS 3.3: entries are read in catalog order up to the first never-used
  entry ([CP2]: "the catalog scan can stop the first time an entry with T=0
  is encountered"); deleted entries (list track 0xFF) are counted. A file's
  track/sector lists give its data sectors in order; track 0 pairs are
  sparse sectors (zeros) and the file ends at the last nonzero pair. The
  label is the name. A `B` file's child is the memory image after the
  4-byte load address and length, `length` bytes long and cut to what is
  stored; every other type's child is its whole sectors, opaque.
- ProDOS: entries are walked depth first in directory order, labeled
  `/VOLUME/DIR/FILE`. Seedling, sapling and tree storage are read up to
  the EOF, sparse pointers as zero blocks; the EOF must fit the storage
  type (512 B, 128 KiB, 16 MiB). An extended file lists its data fork under
  its path and its resource fork as `<path> (resource fork)`, opaque. BIN
  ($06) files load at their aux type ("the ProDOS BASIC system program uses
  this field to record the load address of a ... binary file", [TRM]
  B.2.4) and SYS ($FF) files at 0x2000 ([TRM] "Writing a ProDOS System
  Program"); both are 6502 code. Every other type is opaque. Pascal areas
  (storage type 4) are named in a note and not extracted.
- Files stored in one run are borrowed at their stored offset. Others are
  owned with the transform `DOS 3.3 track/sector list`, `ProDOS index
  blocks` or `DOS sector order` (a ProDOS block of a DOS-order image), and
  report their first stored run as the stored range.
- Code children carry the target MOS 6502, 8-bit, little-endian, and are
  classified as raw code (`Classify::Code`), never as a nested container:
  a binary file is a memory image. Opaque children never reach the code
  model.
- 2IMG: as [CP2] `AnalyzeFileSystem` does, 140 and 160 KiB data is tried
  in both orders with the header's order first. A DOS 3.3 catalog is read
  in the order its chain supports, as for raw images, except that the
  header's order wins a tie; a ProDOS volume directory in the header's
  order, or in the other when it validates only there. A disagreement with
  the header is noted. A data chunk with neither filesystem is one child
  `Disk data`, listed only when it is a recognized format (an Apple
  Partition Map, for example), and nibble data (format 2) is one opaque
  child.

## Boot code

The boot sector (track 0 sector 0, which the disk controller ROM reads to
0x0800 and runs, [BAD] p. 5-6) or the ProDOS loader blocks 0 and 1 ([TRM]
"Memory Use": "reads the loader program from blocks 0 and 1 ... into memory
starting at location $800") are a child `Boot code (...)` with the 6502
target, after the files, unless the area holds one repeated byte (noted as
"No boot code"). It comes last so that a file, not a boot loader, supplies
the primary ISA; on a disk without code files the boot code does.

## Checksums

DOS 3.3, ProDOS and 2IMG have no checksums. The DOS free-sector bitmap and
the ProDOS volume bitmap are not read or verified; the 2IMG lock flag and
volume number are reported as stored.

## Validation and resource bounds

- Every read is bounds-checked; sectors and blocks are fixed-size arrays
  read at constant offsets, and offsets are computed with checked
  arithmetic.
- DOS: each catalog sector is read once (a revisit is an error); each
  track/sector list sector is read once per volume, so a loop or a list
  shared by two files ends with a note and the walk of all files reads at
  most 640 list sectors (40 tracks) and 78,080 pairs. A pair or link off the
  disk ends the file with a note; the sectors before it are listed.
- ProDOS: each directory, index, master index or extended key block is read
  once per volume (a loop or cross-link ends that directory or file with a
  note); directories deeper than 64 levels are not walked. Damage below the
  volume directory (headers, parent fields, file counts, pointers outside
  the volume) is noted and skips what it names; at most 16 problems are
  listed and the rest counted.
- Files are limited to 64 MiB each (`MAX_PAYLOAD`) and 256 MiB in all
  (`MAX_EXTRACTED`, charged before a file is read); at most 4,096 components
  are listed.
- 2IMG: the data chunk must be inside the file and after the header, and
  hold whole blocks matching the block count (ProDOS order), whole 4,096 B
  tracks (DOS order) or 35 tracks of 6,656 B (nibbles); a comment or
  creator chunk that overlaps an earlier chunk or leaves the file is noted
  and ignored; bytes after the last chunk are noted. Comments are quoted up
  to 256 characters.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| A1 | DOS 3.3 and ProDOS 8 exist for one platform family, the Apple II, whose CPU is a 6502 ([A2REF]) or 65C02 ([A2C]); binary and system files therefore hold 6502 code. The ProDOS file system is also used by SOS (Apple III) and GS/OS (Apple IIgs) ([CP2] `ProDOS-notes.md`); that GS/OS BIN files hold only 6502 code is not confirmed by a primary source | A GS/OS volume whose BIN file holds native 65C816 code: the code model's family would differ and `apply_target` would add the warning `container names MOS 6502; code model found ...` |
| A2 | A `B` or BIN file is code. A binary file may also hold a picture or other data loaded with `BLOAD` | A hi-res screen saved as a `B` file at 0x2000 is classified as 6502 code; not told apart |
| A3 | DOS 3.3 writes release 3 in the VTOC ([CP2] `DOS.Format`; [BAD] p. 8-32 lists releases 1, 2 or 3), so other releases are not DOS 3.3 | A DOS 3.3 disk with another release byte is not detected; [CP2] does not check the byte |
| A4 | In the wrong sector order a catalog chain is shorter than in its own order | `prodos_order_dos_images_are_found_from_the_longer_catalog_chain` (15 against 2); `catalogs_that_validate_equally_in_both_orders_are_ambiguous` for the equal case; a catalog broken after its second sector validates only in the other order with chains of two sectors on both sides, and is then read in that order (`a_catalog_broken_after_two_sectors_is_read_in_the_order_where_it_validates`) |
| A5 | A ProDOS `file_count` that differs from the active entries means the volume directory is not valid ([CP2] only warns) | A real volume with a stale count is not detected as a raw image; inside 2IMG it is listed as having no filesystem |
| A6 | Index block pointers keep the low byte at `i` and the high byte at `256 + i` ([CP2] `GetBlockPtr`). The prodos8.com text of [TRM] B.3.3 says bytes 0-127 and 128-255, which cannot hold 256 pointers; it is treated as an erratum | `index_pointers_split_low_and_high_bytes_by_block_half`; a sapling with more than 128 data blocks would read wrong blocks under the TRM wording |
| A7 | The boot sector or blocks 0-1 run at 0x0800 on the 6502 ([BAD] p. 5-6, [TRM] "Memory Use") | Boot code is a separate slice after the files and never decides the ISA of a disk with code files |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| DOS 3.2 and 3.1 (13 sectors, 116,480 B), 50- and 80-track DOS volumes, 32-sector embedded volumes | Not recognized |
| Physical-order (Copy II+ `.img`) and CP/M-order images | Not recognized |
| Nibble images (`.nib`, `.nb2`, WOZ) and 2IMG nibble data | Not decoded; 2IMG nibble data is one opaque child |
| DOS hybrid disks (DOS 3.3 with an embedded ProDOS, Pascal or CP/M volume) | A ProDOS volume directory that validates beside a DOS catalog is noted; its files are not listed |
| DOS MASTER and other DOS volumes embedded in ProDOS | Not recognized |
| Pascal areas (storage type 4) | Named in a note; not extracted |
| DOS `R` (EDASM relocatable), `I`/`A` BASIC, ProDOS `CMD` ($F0), `REL` ($FE), `S16` ($B3) and other code-bearing types | Opaque: only `B`, BIN and SYS are classified as code |
| GS/OS lower-case name flags | Names are shown as stored (upper case) |
| DOS free-sector bitmap, ProDOS volume bitmap, catalog sector counts, track/sector list sector offsets, ProDOS header pointers and `blocks_used` | Not checked |
| Copy-protected disks with a moved VTOC or catalog | Not recognized |
| A raw image inside an archive or filesystem | Recognized only from the whole image (the weak check needs the exact size), so members found by a 4 KiB prefix are not extracted |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly 2026-09-05):

- `tests/apple2.rs` (29 tests) and the 13 unit tests in `src/formats/apple2`
  passed. They cover DOS 3.3 in both orders and with 40 tracks, the
  ambiguous and damaged-catalog order cases, VTOC, catalog,
  track/sector-list and binary-header damage, hybrid disks, ProDOS volumes
  in both orders (seedling, sapling, sparse tree, extended and empty files,
  a subdirectory), header, chain, entry and subdirectory damage, the
  4,096-component limit, 2IMG in both orders, order probing, header and
  chunk errors, data without a filesystem and nibble data, every prefix of
  the ProDOS and 2IMG fixtures (the DOS fixture at a 128 B stride), and
  0x00/0xFF/bit-flip mutations of every byte of the DOS structure sectors,
  of the whole 16 KiB ProDOS volume, of the 2IMG header and volume
  directory, and of track 0 of a DOS-order ProDOS volume (the rest of the
  DOS image at a 97 B stride), a sample of them through the whole
  classifier.
- `cargo test --all-features --locked`: 1,889 passed, 6 ignored.
- `web/tests/apple2.test.mjs` (4 tests: `/pkg/` and `/dist/` modules, the
  source and packaged workbench) passed after `./build-web.sh`. The whole
  browser suite ran 216 tests: 211 passed, 4 skipped (they need D10 and
  RX113 firmware that is not in the repository), and 1 failed once with
  "WebAssembly compilation aborted: Network error" in
  `compressed.test.mjs` through `/pkg/`; that file passed (4 of 4) when run
  again on its own.

All fixtures are synthetic, built in the tests from the documented layouts
with a hand-assembled 20-byte 6502 routine as code; no Apple II software is
redistributed. No image made by a real Apple II, emulator or disk tool was
tested: behavior on such images is not verified. The code model does not
recognize the short synthetic routine (it reports the heuristic as
inconclusive); the 6502 ISA of the code children comes from the platform
target.

After integration with the families added since on the same day, the
native suite passed 2,166 tests with 6 ignored, and IDA's corpus (4,621
files, none an Apple II disk image) classified as before.
