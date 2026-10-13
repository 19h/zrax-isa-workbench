# Amiga disk images

`src/formats/adf.rs` and its submodules (`boot.rs`, `volume.rs`, `walk.rs`,
`rdb.rs`) parse Amiga disk images into the shared container model
([compressed streams and the container model](compressed-streams.md)): ADF
floppy images holding an AmigaDOS volume (the Old and Fast File Systems with
their international, directory cache and long-name variants), bootable ADF
floppies without one, hard disk images with a Rigid Disk Block, and
unpartitioned hardfiles. The directory tree is walked from the root block's
hash table; regular files that start with a recognized format are members,
reassembled from their data blocks, and the boot block code is a child with
a 68000-family target. AmigaDOS names no processor for the files it holds:
members are classified from their own bytes (an Amiga Hunk executable names
the 68000 family itself, `src/formats/amiga_hunk.rs`).

Primary sources:

- [FAQ] Laurent Clévy, "The .ADF (Amiga Disk File) format FAQ", v1.14
  (April 8th, 2017), `doc/FAQ/adf_info.txt` in ADFlib at commit
  `73880de78bf472a1cc7d60f07fc217e02d571268` (ISO 8859-1 text, SHA-256
  `f72650896a1dcfdcf064594ee00227d479e2ac70fb84f72ac34daf6148ec8001`).
  Sections are cited by number.
- [ADFLIB] ADFlib (<https://github.com/adflib/ADFlib>) at the same commit:
  `src/adf_blk.h` (block structures and type constants), `src/adf_raw.c`
  (`adfBootSum`, `adfNormalSum`, `adfReadBootBlock`, `adfReadRootBlock`),
  `src/adf_dir.c` (`adfGetRDirEntLimited`, `adfReadEntryBlock`,
  `adfGetHashValue`, `adfIntlToUpper`), `src/adf_file_block.c`
  (`adfGetFileBlocks`, `adfReadDataBlock`, `adfReadFileExtBlock`),
  `src/adf_file_util.c` (`adfFileRealSize`), `src/adf_vol.h`
  (`adfVolCalcRootBlk`), `src/adf_dev_flop.c` and `src/adf_dev_type.c`
  (floppy geometries).
- [AMITOOLS] amitools (<https://github.com/cnvogelg/amitools>) at commit
  `3b57f2052ee76c28bbc5e4256227f62dca7b1c9f`: `amitools/fs/DosType.py`,
  `block/BootBlock.py`, `block/Block.py`, `block/EntryBlock.py`,
  `block/FileHeaderBlock.py`, `block/FileListBlock.py`,
  `block/FileDataBlock.py`, `block/RootBlock.py`, `ADFSFile.py`,
  `ADFSVolume.py`, `FileName.py`, `blkdev/PartBlockDevice.py`.
- [RKRM] Amiga ROM Kernel Reference Manual: Devices, 3rd edition, chapter 11
  "Amiga BootStrap", section "Bootblock Booting"; the 2.04 Includes (V37.4)
  `devices/bootblock.i` and `devices/bootblock.h` (revision 36.6),
  `devices/hardblocks.h` (revision 36.3) and `dos/filehandler.h` (revision
  36.5). Read from the Amiga Developer CD v2.1 HTML edition on
  discmaster.textfiles.com: `Devices_Manual_guide/node007D.html` (SHA-256
  `efc56b97bf07c900067feb28e71d397c8816ebf60bd0948a9e7b172efb0e5437`),
  `Includes_and_Autodocs_2._guide/node0044.html` (`bootblock.i`,
  `d5df9c3567c95e9e0fd2f6d74bb5bfc660dca9596ca69ce34bda3575971feffb`),
  `node0041.html` (`hardblocks.h`,
  `eefdce65f2cd070870b733996ad4af8567379a452f6c353c00b16ac72396beff`) and
  `node0066.html` (`filehandler.h`,
  `37acdae3c1fdeb7b4425042ee795ecc509842b1b17742cb27ea9645c4dfae09e`).
- [HRM] Amiga Hardware Reference Manual, 3rd edition, chapter 1
  "Components of the Amiga" and "The MC68000 and the Amiga Custom Chips"
  (same CD, `Hardware_Manual_guide/node0003.html`, SHA-256
  `d0f18a18fef3d43e29896b22d7a760f3f07abbd43b296ed4ce2d3026af3ef148`, and
  `node0004.html`,
  `c42a01563958247ac435ba30fc34b698c60c3817fbff76e09c724aac26231a19`).
- [LINUX] Linux v6.6 `fs/affs/super.c` (root block search, SHA-256
  `e55d242e23f741c3b914014bc4c51bfcecbac2962a073bbdc7a772e2eb10443e`) and
  `block/partitions/amiga.c` (Rigid Disk Block partitions,
  `d91380ea6167481b4237b46e618311cd1b8a4bd0a2fcce4128d2aac1e7ec1339`).

amitools at the commit above wrote the fixtures
([fixture README](../tests/fixtures/adf/README.md)); no rule is taken from
it that the other sources do not state, except the long-name entry layout
(see the assumption register).

## Implemented layouts

| JSON format ID | Variant | Layout | Recognition | Components | Primary source |
| --- | --- | --- | --- | --- | --- |
| `adf` | `AmigaDOS DD floppy`, `AmigaDOS HD floppy` | 80-83 cylinders × 2 heads × 11 (DD) or 22 (HD) sectors of 512 B; boot block (blocks 0-1) with `DOS` and a DOS type 0-7; root block in the middle (880 or 1760 for 80 cylinders) | Strong: exact size, `DOS` and DOS type 0-7 at offset 0, root block types and checksum | Regular files in a recognized format, by path; then the boot block code | [FAQ] 3, 4.1-4.5; [ADFLIB] `adf_dev_type.c` |
| `adf` | `Bootable non-DOS DD floppy`, `Bootable non-DOS HD floppy` | A floppy image whose boot block Kickstart runs (`DOS`, a valid boot checksum, code) and which holds no AmigaDOS root block: a disk with a loader of its own | Strong: exact size, `DOS`, boot block checksum over non-zero code | The boot block code | [RKRM] "Bootblock Booting" |
| `amigahdf` | `Rigid Disk Block` | `RDSK` in one of blocks 0-15; `PART` list with `DosEnvec` geometry; `FSHD` list with `LSEG` chains | Strong: `RDSK` and its checksum (after block 0, also a valid first `PART` block) | Each AmigaDOS partition's recognized files as `DH0:/path`; other partitions if recognized; file system handlers; partition boot block code | [RKRM] `hardblocks.h`, `filehandler.h`; [FAQ] 6; [LINUX] `amiga.c` |
| `amigahdf` | `Unpartitioned hardfile` | One AmigaDOS volume over the whole input, any whole number of blocks (as UAE creates them) | Strong: whole blocks, `DOS` and DOS type 0-7, root block in the middle | As an AmigaDOS floppy | [FAQ] 7 |

DOS types ([FAQ] 4.1; [AMITOOLS] `DosType.py`): bit 0 selects FFS (else
OFS), bit 1 the international mode, bit 2 alone (4, 5) the directory cache
with international mode, bits 1 and 2 (6, 7) long file names with
international mode.

The JSON `format.variant_name` is the layout name. Notes give the floppy
geometry or the hard disk layout, the volume (name, file system, DOS type,
blocks, root block), the root block's hash table size when it is not 72,
the bitmap blocks and their checksums, the boot code found, a walk census
and every problem below the root. Metadata records `adf_dos_type`,
`adf_filesystem`, `adf_volume_name`, `adf_block_count`, `adf_root_block`,
`adf_created` and `adf_modified` (from `c_days` and `v_days`, as stored:
AmigaDOS dates carry no time zone), `adf_boot_checksum`,
`adf_boot_dos_block`, the walk counts (`adf_directory_count`, `adf_regular_file_count`, `adf_member_count`,
`adf_link_count`), for Rigid Disk Block images `adf_rdb_block`,
`adf_geometry`, `adf_disk_vendor`, `adf_disk_product`, `adf_disk_revision`
and per partition `adf_partition_<n>` with the volume keys under
`adf_partition_<n>_…`, and one `adf_component_<n>` entry per child.

## Detection

`adf::detect` tries, in order:

1. an ADF floppy: the input is exactly 80-83 cylinders × 2 heads × 11 or 22
   sectors × 512 B (901,120 B and 1,802,240 B for 80 cylinders), the boot
   block starts with `DOS`, and either the fourth byte is a DOS type 0-7
   and the root block at `blocks / 2` has type `T_HEADER` (2), secondary
   type `ST_ROOT` (1) and a valid checksum (`Floppy`), or the boot block
   checksum is valid and the code area after offset 12 is not all zero
   (`BootFloppy`; any fourth byte, since Kickstart checks only `DOS` and the
   checksum);
2. a Rigid Disk Block: one of the first 16 blocks starts with `RDSK`, its
   `rdb_SummedLongs` is 64-128 and those longs sum to zero, and when that
   block is not block 0, `rdb_PartitionList` names a valid `PART` block (a
   disk image stored as the first member of a tar archive has its `RDSK`
   block at block 1, where its pointers miss; the archive check then claims
   the file and lists the disk as its member);
3. an unpartitioned hardfile: a whole number of at least 4 blocks, `DOS`
   and a DOS type 0-7, and a valid root block at `(2 + n - 1) / 2` or `n /
   2` for `n` blocks.

Every layout pairs a signature (24 or 32 bits) with a 32-bit checksum at a
position fixed by the image size, so none matches ordinary data and all are
strong. The check runs right after `ti_c55x` and before the first
container family (automotive): the chiptune, console, filesystem and
firmware checks that follow probe offsets inside the image (SNDH at 12,
headers at 0x100, superblocks at 0x400 and 0x438, descriptors at 0x8000),
which an Amiga boot block or a file stored in FFS data blocks may hold,
while this check cannot claim their inputs (it needs `DOS` at offset 0 or
`RDSK` with its checksum). Detection reads at most the boot block, two root
block candidates, 16 blocks and one partition block, whatever the input
size.

## Wire units and byte order

| Item | Byte order | Units |
| --- | --- | --- |
| Every field | Big-endian (the 680x0 order) | Longs of 32 bits |
| Block numbers in a volume | — | 512-byte blocks from the volume's first block (the image, or the partition's `LowCyl × Surfaces × BlocksPerTrack`) |
| Block numbers in Rigid Disk Block structures | — | 512-byte blocks from the start of the disk |
| Root block | — | `(reserved + highKey) / 2` ([FAQ] 4.2; [LINUX] `(reserved + size - 1) / 2`), then `blocks / 2` ([ADFLIB], [AMITOOLS]); reserved is 2 for floppies and hardfiles and `de_Reserved` for partitions |
| Names | ISO 8859-1 | BCPL strings: a length byte (at most 30; 110 on long-name volumes) and the characters |
| Dates | — | Days since 1978-01-01, minutes past midnight, ticks of 1/50 s |
| File size | — | `byte_size` in bytes; data blocks hold 488 B (OFS, after a 24-byte header) or 512 B (FFS) |
| Offsets in notes, metadata and slices | — | File bytes |

## Members

- The walk starts at the root block and descends depth first. Each
  directory's 72 hash table slots are read in order, each slot's chain
  through `hash_chain` to 0 ([FAQ] 4.2.2; [ADFLIB] `adfGetRDirEntLimited`);
  subdirectories are walked after their parent's entries, in table order.
- An entry block must lie in the volume past the boot blocks, have type
  `T_HEADER`, its own number in `header_key` ([AMITOOLS]), a valid
  checksum, a name of 1-30 characters (1-110 on `DOS\6`/`DOS\7`, read at
  0x148) without `/` or `:` ([FAQ] 4.2), and secondary type `ST_USERDIR`,
  `ST_FILE`, `ST_LINKFILE`, `ST_LINKDIR` or `ST_SOFTLINK`. A defect skips
  the rest of that chain with a note. Links are counted and not followed.
  An entry whose name hashes to another slot ([FAQ] 4.2.1 and 5.4, with the
  international upper case when the DOS type has the international mode)
  is listed and counted: AmigaDOS would not find it by name.
- A regular file's block count is `ceil(byte_size / data size)`; the file
  header must hold `min(count, 72)` pointers in `high_seq` ([ADFLIB]
  `adfGetFileBlocks`), from the end of its table backwards ([FAQ] 4.4:
  "the first is at datablock[71-0]"). Further pointers come from extension
  blocks (`T_LIST`, `ST_FILE`, own number, the header as parent, valid
  checksum), each but the last holding 72.
- A file is read up to its first 4 KiB; when that prefix is a recognized
  format (`container::is_recognized`) the whole file is read and listed with
  `if_recognized`. FFS data blocks are raw and the last is cut to the size;
  OFS data blocks must have type `T_DATA`, the file header in `header_key`,
  sequence numbers from 1, a data size of at most 488 B and a valid
  checksum, and their data must add up to `byte_size` ([AMITOOLS]
  `ADFSFile.read`). An FFS file in consecutive blocks is borrowed at its
  stored offset; other files are owned with the transform `AmigaDOS FFS data
  blocks` or `AmigaDOS OFS data blocks`, and their slice gives the first
  stored run (the first FFS run, or the first OFS block's data).
- Directory cache blocks (`DOS\4`, `DOS\5`) are not read: the hash tables
  are authoritative, and the note says so.

## Boot code

The boot block is the first two blocks of a floppy or hardfile
(`BOOTSECTS`, "1K bootstrap") and the first `de_BootBlocks` blocks of a
partition (2 when the environment does not say; at most 64, our bound). Its
checksum is the complement of the sum of all longs but the second, added
with carry wraparound ([FAQ] 4.1; [ADFLIB] `adfBootSum`). Kickstart runs the
code when "the boot blocks start with the three characters "DOS" and pass
the longword checksum (with carry wraparound)", entering it at `BB_ENTRY`,
offset 12, with the I/O request in A1 and `SysBase` in A6 ([RKRM]). Such a
boot block with any non-zero byte after offset 12 gives a child `Boot block
code` (`DH0: boot block code` on a partition) from offset 12 to the end of
the boot blocks, classified as code with target 68000 family, 32-bit,
big-endian. A boot block whose checksum fails, or whose code area is zero,
gives only a note.

The boot code comes after the files (and on a hard disk after the file
system handlers), so the first recognized file supplies the primary ISA and
the boot code does only when no file is recognized.

## Rigid Disk Block

- `rdb_BlockBytes` must be 512 (otherwise an error). The geometry, the drive
  identification (when `RDBFF_DISKID` is set), a bad block list and drive
  initialization code are noted; bad block replacement is not applied and
  the drive initialization code is not extracted.
- The partition list from `rdb_PartitionList` is followed through `pb_Next`
  until 0xFFFFFFFF, at most 128 partitions (our bound; [LINUX] reads 16).
  Each `PART` block must pass its checksum; a failing block, a block beyond
  the input or a loop ends the list with a note.
- A partition's extent comes from its `DosEnvec`: start `LowCyl × Surfaces ×
  BlocksPerTrack`, size `(HighCyl - LowCyl + 1) × Surfaces ×
  BlocksPerTrack` blocks ([LINUX]). `de_SizeBlock` must be 128 and
  `de_SectorPerBlock` 1; other values, missing entries or an empty geometry
  skip the partition with a note. A partition that ends beyond the input is
  walked over the blocks present.
- The file system is the one the partition's boot block names ([FAQ] 6.3:
  "Don't rely only on the PART and FSHD 'DosType' field"); a different
  `de_DosType` is noted. An AmigaDOS partition is walked like a floppy, with
  `de_Reserved` reserved blocks (2 if 0) and its drive name before each path
  (`DH0:/c/Dir`). A partition with another file system (PFS, SFS, a foreign
  format) is noted and listed as `Partition <n> (<drive>)` only if its bytes
  are a recognized format.
- The file system header list from `rdb_FileSysHeaderList` is followed the
  same way. Each `FSHD` block's `LSEG` chain is concatenated
  (`lsb_LoadData`, `SummedLongs - 5` longs per block); when the result
  starts with `HUNK_HEADER` it is a child `File system DOS\3 version 45.13`
  (transform `RDB LoadSeg blocks`), otherwise a note.

## Checksums

- Verified: the root block (detection), every entry, extension and OFS data
  block read, the bitmap blocks the root block lists (reported), the boot
  block (it decides whether the code is classified), and every `RDSK`,
  `PART`, `FSHD` and `LSEG` block read.
- Not verified: the bitmap's content against the blocks files use, bitmap
  extension blocks, directory cache blocks, the OFS `next_data` chain (the
  pointer tables are used instead, as [FAQ] 4.4 allows) and file comments.

## Validation and resource bounds

- Every read goes through block reads that check the volume's bounds and the
  input's length; block numbers below the reserved blocks or past the
  volume are defects. Offsets are computed with checked arithmetic or in
  `u64` before conversion.
- Each entry block is read at most once per walk (a bit set over the blocks
  present), which ends hash chain loops, directory loops and cross-links;
  each Rigid Disk Block structure is read at most once per image.
- A file may not need more data blocks than the input holds for its volume,
  so pointer tables are never sized by an unchecked count; extension chains
  stop after the blocks the size needs.
- Members are limited to 64 MiB each (`MAX_PAYLOAD`) and 256 MiB in all
  (`MAX_EXTRACTED`, charged before a file is read); at most 4096 members are
  listed and 65,536 files examined; directories deeper than 64 levels are not
  walked; at most 16 problems are listed and the rest counted. Load segment
  chains are limited to 64 MiB.
- The image size must match the layout exactly for floppies; damage below
  the root block (and in partitions) is a note, damage to what detection
  requires is an error when `parse_container` is called directly.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| A1 | The ADF and AmigaDOS volume formats exist only for the Amiga, whose CPU is a 680x0 ([HRM]: the 68000 in the A1000, A500 and A2000, the 68030 in the A3000, the 68010, 68020 and 68030 as options), and Kickstart runs boot block code on that CPU ([RKRM]: entered with A1 and A6 set) | A boot block for another processor would be misattributed; none is known, and the code model's result is overridden only for the boot code child, never for files |
| A2 | A boot block "holds code" when any byte after offset 12 is not zero; no source says whether Kickstart refuses an all-zero code area | `bootable_non_dos_floppies_list_their_boot_code`: a valid checksum over zeros is neither bootable nor a `BootFloppy` |
| A3 | A bootable non-DOS floppy is any floppy-sized image with `DOS`, a valid boot checksum and code but no root block, whatever its fourth byte: [RKRM] names only the three characters and the checksum | A disk whose root block is merely damaged but whose boot block is valid is reported as non-DOS with the root defect in the note |
| A4 | The root block of an odd-sized volume is at `(reserved + n - 1) / 2` ([FAQ], [LINUX]) or `n / 2` ([ADFLIB], [AMITOOLS]); both are tried | `unpartitioned_hardfiles_are_volumes_of_any_size` places the root at both |
| A5 | A floppy image missing its last block is an unpartitioned hardfile of one block fewer: its middle is still the root block | `prefixes_are_not_floppies_and_claim_nothing_missing` |
| A6 | Long-name volumes (`DOS\6`, `DOS\7`) keep entry names as a BCPL string at 0x148 of at most 110 characters; this layout is from [AMITOOLS] only, not from an AmigaOS 3.2 document | The `longnames.adf.gz` fixture is written by amitools itself, so it cannot falsify this; an image written by AmigaOS 3.2 would |
| A7 | Every extension block but a file's last holds 72 pointers ([ADFLIB] `adfFileRealSize` and the count checks in `adfGetFileBlocks`) | A writer that leaves extension blocks partly empty would see its files skipped with "lists N data blocks, not 72" |
| A8 | An entry's `parent` field is not checked; the walk position decides the path | A cross-linked entry whose parent names another directory is listed under the directory that links it |
| A9 | An `RDSK` block after block 0 belongs to the file only when its partition list starts at a valid `PART` block (our rule; [RKRM] allows any of the first 16 blocks) | `a_rigid_disk_image_inside_a_tar_archive_is_the_archive_member`; a real disk with its RDB in blocks 1-15 and no valid first partition block is not recognized |
| A10 | A hardfile reserves 2 blocks, as floppies do; the UAE mountlist in [FAQ] 7 uses 1, which moves the root block only for odd block counts (both positions are tried) | A full reserved-1 hardfile whose block 1 holds file system data would see that block refused as a boot block |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Other floppy sizes (40-cylinder 5.25" disks, ADF with error bytes `*513`, extended ADF `UAE--ADF`/`UAE-1ADF` track images, DMS/IPF/SCP captures) | Not recognized as floppies; a whole number of blocks with `DOS` and a root block in the middle is an unpartitioned hardfile |
| Non-DOS disks without a bootable boot block (data disks of games, custom formats) | Not recognized: no source gives a way to identify them |
| PFS, SFS, `muFS` and other file systems | PFS/SFS partitions are listed only when a recognized format; MultiUser DOS types (`muF\x`) are not handled |
| Blocks other than 512 B (`rdb_BlockBytes`, `de_SizeBlock`, `de_SectorPerBlock` > 1) | Error for the RDB, note and skip for a partition |
| Bad block replacement, drive initialization code | Noted, not applied or extracted |
| Directory cache blocks, file comments and comment blocks, protection bits, deleted files | Not read; deleted files are not undeleted |
| Hard and soft links | Counted, never followed |
| Amiga archives and compressed files on the disk (LhA, LZX, DMS, PowerPacker) | Listed only when their format is recognized |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`):
`tests/adf.rs` (21 tests) and the 17 unit tests in `src/formats/adf.rs` and
`src/formats/adf/` passed, within a full `cargo test --all-features
--locked` run of 1,885 passing tests with 6 ignored. The integration tests use six fixtures written by
amitools at `3b57f205` (OFS, FFS, directory cache, long-name and HD
floppies, and a Rigid Disk Block disk with an FFS and an OFS partition and a
file system header; every member is compared byte for byte with the
executable rebuilt in the test), synthetic images built in the test from
the [FAQ] layouts (OFS, FFS and international floppies, a bootable non-DOS
floppy, hardfiles with even and odd block counts and both root positions,
damaged root, entry, data and extension blocks, hash chain and directory
loops, cross-links, a hard link, 66 nested directories), Rigid Disk Block
corruptions with recomputed checksums, the disk fixture as the first member
of a ustar archive (classified as tar with the disk as its member), a parse of every prefix of the OFS
and HD fixtures and of block-boundary prefixes of the Rigid Disk Block
fixture, and mutations (`0x00`, `0xFF`, bit flip) of the boot blocks, root
blocks, structure block fields and sampled bytes. `web/tests/adf.test.mjs`
(4 tests) passed through `/pkg/` and `/dist/` and in both workbench pages,
within a full browser run of 212 passing tests with 4 skipped (D10 and
RX113 firmware not in the repository).

Not verified: images written by AmigaOS itself (no such image was used:
every fixture comes from amitools or from the tests' own builder), images
written by AmigaOS 3.2 on long-name volumes, partitions with more than 2
boot blocks, Rigid Disk Blocks outside block 0, and whether Kickstart boots
the boot blocks this reader classifies.

After integration with the families added since on the same day, the
native suite passed 2,092 tests with 6 ignored, and IDA's corpus (4,621
files, none an Amiga disk image) classified as before.
