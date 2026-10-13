# Commodore disk and tape images

`src/formats/cbm.rs` and its submodules (`dos.rs`, `t64.rs`) parse the
disk images of the Commodore 1541, 1571 and 1581 drives (D64, D71, D81)
and T64 tape images into the shared container model ([compressed streams
and the container model](compressed-streams.md)). Every file of the
directory is a child, labeled by its type and PETSCII name: a PRG file is
6502-family code after its load address, SEQ, USR and REL files and 1581
partitions are opaque data, and DEL entries are skipped.

Primary sources:

- [VICE] The VICE manual, `vice/doc/vice.texi`, chapter "The emulator file
  formats": sections "The T64 tape image format", "The D64 disk image
  format" (with "Variations on the D64 layout", "BAM layout" and "Error
  codes"), "The D71 disk image format" and "The D81 disk image format".
  The disk sections are Peter Schepers' documents as edited for VICE.
  VICE-Team/svn-mirror tag `r46282`, commit
  `eb723e0f2780b62f9fca1e305eb4134bda2a4ba0`; the fetched file has SHA-256
  `a5fab0ba1d17bb1b1d5bba4f7e2bfb4f73886e5fb92dbe927f401ae5e05c49fb`.
- [VICE-SRC] VICE sources at the same commit: `src/tape/t64.c`
  (`magic_headers`, `t64_header_read`, `t64_open`; SHA-256
  `1e69649306fc0e7471471ac4c956e00d8e72aeae58aa804d0301d2af5ffdd0c6`),
  `src/tape/t64.h` (field offsets; `79f1099e...`), `src/tape/tape.c`
  (`tape_receive_trap`; `53294fdb...`), `src/diskimage.h` (image sizes;
  `88dbb901...`), `src/diskimage/diskimage.c` (`sector_map_d64`),
  `src/vdrive/vdrive-bam.c` (`vdrive_bam_create_empty_bam`,
  `vdrive_bam_free_block_count`; `02360cfd...`), `src/vdrive/vdrive-iec.c`
  (`iec_read_sequential`, `iec_write_sequential`; `d1b80fb5...`) and
  `src/cbmdos.h` (`CBMDOS_FT_*`; `5e29e648...`).
- [MAGIC] file(1) `magic/Magdir/c64` v1.16, tag `FILE5_46` (SHA-256
  `c8f2495654b4a0b4501c0209e918fc795389d78f60ad8f518fb60a49d46affad`): D64
  is `0x12014100`, D71 `0x12014180` at 0x16500, D81 `0x28034400` at
  0x61800, all big-endian 32-bit compares.
- [MAME] MAME at `17842be91dad10fab10e3ff657dc1e89ebc0ba27`:
  `src/mame/commodore/c64.cpp` (`m6510_device`), `vic20.cpp`
  (`m6502_device`), `plus4.cpp` (`m7501_device`) and `c128.cpp`
  (`m8502_device` beside a `z80_device`).

Peter Schepers' original text files were not fetched; the VICE copy is the
pinned one.

## Implemented layouts

| JSON format ID | Variant | Layout | Recognition | Children | Primary source |
| --- | --- | --- | --- | --- | --- |
| `d64` | `D64 disk image (35 tracks)` | 683 sectors of 256 B: tracks 1-17 of 21 sectors, 18-24 of 19, 25-30 of 18, 31-35 of 17; 174,848 B, or 175,531 B with 683 error bytes | Weak: exact size, BAM at 18/0 starting `12 01 41` (directory link 18/1, DOS version `A`), directory chain from 18/1 inside the image | One per file: PRG as 6502-family code after the load address; SEQ, USR, REL opaque | [VICE] D64; [MAGIC] |
| `d64` | `D64 disk image (40 tracks)` | 768 sectors: tracks 36-40 of 17 sectors; 196,608 B, or 197,376 B with 768 error bytes | Weak: as above | As above | [VICE] "Variations on the D64 layout" |
| `d71` | `D71 disk image` | 1,366 sectors: tracks 36-70 repeat the zones of tracks 1-35; 349,696 B, or 351,062 B with error bytes | Weak: exact size, BAM at 18/0 starting `12 01 41 80` (double-sided flag), directory chain from 18/1 | As D64 | [VICE] D71; [MAGIC] |
| `d81` | `D81 disk image` | 3,200 sectors: 80 tracks of 40; 819,200 B, or 822,400 B with error bytes | Weak: exact size, header at 40/0 `28 03 44 00`, version `D` (0x44) and its complement 0xBB in the BAM sectors 40/1 and 40/2, directory chain from 40/3 | As D64; 1581 partitions (type 5, `CBM`) opaque over their consecutive sectors | [VICE] D81; [MAGIC] |
| `t64` | `T64 tape image` | 64-byte header, 32-byte records, then the data | Strong: `C64 tape image file`, `C64S tape file` or `C64S tape image file` at offset 0 ([VICE-SRC] `magic_headers`) | One per normal record (entry type 1): CBM type PRG as 6502-family code loaded at the start address; other CBM types opaque | [VICE] T64; [VICE-SRC] `t64.c`, `t64.h`, `tape.c` |

Detection positions: T64 is checked with the magic-bearing formats, right
before the compressed streams; the disk images are the first of the weak
checks. Every weak check below them reads an image's first sectors, which
hold file data on these disks (track 1 sector 0 is the first file sector,
not a boot sector), so a disk image must not lose to them. In the other
direction, recognition needs one of eight exact sizes, three to eight fixed
signature bytes deep inside the image and a complete directory chain, so
an input of another family is claimed only when it also carries a CBM DOS
BAM and directory.

A child's label is its type, its name in quotes and, for a program, its
load address: `PRG "GAME" at 0x0801`, `SEQ "NOTES"`, `CBM "PART"
partition`; ` (locked)` and ` (not closed)` follow from the type byte's
bits 6 and 7. Notes give the disk name, ID, DOS type, geometry, file count
and blocks free; the platform CPU rule; the error-byte summary; skipped DEL
entries; and every damaged entry (up to 16 in full, the rest counted).
Metadata records `cbm_disk_name`, `cbm_disk_id`, `cbm_dos_type`,
`cbm_blocks_free` and `cbm_directory_sectors` for disks,
`cbm_tape_description`, `cbm_t64_version` and `cbm_directory_entries` for
tapes, and one `cbm_component_<n>` entry per child.

## Architecture evidence

Neither format has an ISA field. Both exist only for the Commodore 8-bit
computers: the 1541, 1571 and 1581 drives and the C64S T64 container hold
files that the computer's KERNAL loads into the memory of its main CPU
(VICE emulates "the Commodore C64, C64DTV, C128, VIC20, PET, PLUS4, SCPU64
and CBM-II computers" with "an accurate 6502/6510 emulator"), and [MAME]
names those CPUs: a 6510 (C64), a 6502 (VIC-20), a 7501 (C16 and Plus/4)
and an 8502 (C128), all 6502 family. A PRG file is therefore a child with
the target `mcs6502`, 8-bit, little-endian, classified as raw code
(`as_code`), and the code model never overrides it. No CPU variant is
reported, because a disk does not say which of these machines it was
written for.

The container itself names no target: its primary ISA is that of the first
listed program, in directory order (the file `LOAD"*",8` loads). A disk or
tape without a PRG file has an unknown ISA.

## Wire units and byte order

- Sectors are 256 B, addressed by track (from 1) and sector (from 0) and
  stored in track order; the offset of track T sector S is 256 times the
  sectors of tracks 1 to T-1 plus S ([VICE] offset tables). Track 18 starts
  at 0x16500, the D71's track 53 at 0x41000, the D81's track 40 at 0x61800.
- Error bytes, when present, follow the sectors, one per sector in the same
  order. Codes 0x01 (no error) and 0x00 ("unused and never occur") count as
  no error; any other code is reported, with the first such sector.
- Chained sectors: byte 0 is the next track, byte 1 the next sector, bytes
  2-255 data. In the last sector (track 0) byte 1 is the index of the last
  used byte, so it holds `byte 1 - 1` data bytes; VICE writes
  `buf[1] = length - 1` ([VICE-SRC] `iec_write_sequential`). Values 0 and 1
  give an empty last sector.
- Directory entries are 32 B, eight per sector: type at 0x02 (bits 0-3 the
  file type, bit 6 locked, bit 7 closed), first track and sector at 0x03,
  name of 16 B padded with 0xA0 at 0x05, size in sectors at 0x1E
  (little-endian). Only the first entry's bytes 0-1 are the sector link.
- A PRG file starts with its load address, low byte first ([VICE] monitor
  "File commands": `load` uses "the address specified by the first two
  bytes read from the file"). The child holds the bytes after it; its
  stored range is the first sector and the sectors adjacent to it, and its
  decoded range (transform `D64 sector chain`, used for all three drives)
  is the reassembled program.
- T64 numbers are little-endian ([VICE-SRC] `get_number`). A record's data
  are `end - start` bytes in 16-bit arithmetic (an end address of 0 stands
  for 0x10000) at its data offset, without a load address; VICE copies them
  to the start address ([VICE-SRC] `tape_receive_trap`). The child is the
  stored data.
- Names are PETSCII. They are shown in the power-on (uppercase and graphics)
  character set: 0x20-0x5D as ASCII except the quote and 0x5C (the pound
  sign), every other byte as `\xNN`. Disk names end at the first 0xA0; T64
  names and descriptions lose trailing spaces, 0xA0 and NULs. VICE's own
  conversion (`charset_p_toascii`) maps 0x41-0x5A to lowercase instead.

## Validation and resource bounds

- The image size must be one of the eight sizes above; a prefix of an image
  is never a disk image, and parsing it is an error.
- The BAM or header signature must match ([MAGIC] bytes); the D81 BAM
  sectors must carry the version `D` and its one's complement.
- The directory chain starts at 18/1 (40/3) whatever the BAM points to, as
  the drive does, and may leave the directory track ([VICE]: "Just follow
  the chain anyhow"). Every link must name a sector of the disk and no
  sector may be linked twice, so the walk ends within the disk's sector
  count (683 to 3,200). A broken directory is a parse error and prevents
  detection.
- File chains follow the same rules; a chain that leaves the disk or visits
  a sector twice skips that file with a note. The chain's sector count is
  compared with the directory's block count, and a mismatch is noted.
- A PRG of two bytes or fewer holds no program and is listed as opaque, with
  a note; a program that runs past 0xFFFF is noted.
- At most 4,096 entries are examined (`MAX_COMPONENTS`); the rest are
  counted in a note. Reassembled files stop at 256 MiB in total
  (`MAX_EXTRACTED`); a single file is at most 3,200 x 254 B.
- 1581 partitions must start on a sector of the disk, be at least one
  sector long and end inside the image.
- T64: the header (64 B) and the whole directory (32 B per declared entry,
  at most 65,535) must be present before any record is read. A zero
  directory size or used count is read as 1 and a used count above the
  directory size is an error, as in VICE's `t64_header_read`. A record's
  data offset must lie between the end of the directory and the end of the
  file. Sizes are repaired as VICE's `t64_open` does: a record ends where
  the next record's data begin (in offset order), the last one at most at
  the end of the file; each repair is noted. Records with no data or whose
  data would pass 0xFFFF are skipped with a note. Entry types other than 1
  (normal) are skipped with a note, since VICE reads only those.
- Damage notes are capped at 16, then counted.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| C1 | Every CBM DOS PRG file and every T64 PRG record is a program for the 6502-family main CPU of a Commodore 8-bit computer | A D64 holding a C128 program that only runs on the Z80 (C128 CP/M uses its own disk format, not PRG files; not checked against a CP/M disk image) or a SuperCPU 65816 program would be reported as `mcs6502` |
| C2 | Formatting writes the directory link 18/1 and DOS version `A` (1581: `28 03 44 00`, `D`/0xBB) and real images keep them | `bam_signature_and_directory_chain_are_required`; a real disk whose BAM link was altered (VICE: "doesn't matter, and don't trust what is there") is not recognized |
| C3 | A D71 BAM has the double-sided flag 0x80 | `d71_files_reach_the_second_side` rejects 0x00; a D71 that holds a single-sided disk is not recognized |
| C4 | The last sector's byte 1 is the index of its last used byte | `the_last_sector_holds_bytes_up_to_its_index`; VICE's reader returns a whole sector for values 0 and 1, where this parser returns none |
| C5 | The low four bits of the type byte are the file type | VICE notes that "some routines ... ignore bit 3"; types 5-15 (6-15 on the 1581) are skipped with a note |
| C6 | A T64 CBM type other than PRG (`0x?2`) is data | T64 files with type 0x01 or 0x44 for programs (file(1) mentions both) are listed as opaque; not checked against such files |
| C7 | VICE's end-address repair is the right reading of broken T64 records | `t64_end_addresses_are_repaired_as_vice_does` (conv64's 0xC3C6) |
| C8 | Error code 0x00 is not an error | VICE: "Codes $0 and $C to $E are unused and never occur"; an image whose tool wrote 0x00 for errors would be misreported as clean |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| 42-track D64 (205,312 and 206,114 B), D67, D80, D82, D1M/D2M/D4M, DHD, D90, G64, P64, X64 | Not recognized |
| 40-track BAM extensions (SpeedDOS 0xC0, Dolphin DOS 0xAC, PrologicDOS 0x90 with the name moved to 0xA4) | Not read; blocks free counts tracks 1-35. PrologicDOS 40-track disks (DOS version `P`) are not recognized |
| D71 second BAM at 53/0 | Not read; the free counts of tracks 36-70 come from 18/0 |
| 1581 sub-directories inside partitions | The partition is one opaque child; its own directory is not walked |
| REL side sectors, GEOS VLIR files and info blocks | Not decoded; REL data and GEOS (USR) files are opaque |
| C128 auto-boot sector at 1/0 | Not parsed (the manual gives no layout) |
| T64 entry types 2-5 (C64S header, snapshot, block, stream) | Skipped with a note |
| Disk images inside archives and filesystems | Not listed: weak layouts need the whole image, and members are recognized from their first 4 KiB |
| BAM consistency (free counts against bitmaps, chains against allocation) | Not checked; disks with "0 blocks free" tricks stay recognized |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly f248f4038),
`tests/cbm.rs` (15 tests) and the module unit tests (10) passed, and
`cargo test --all-features --locked` passed 1,872 tests with 6 ignored. The fixtures are
synthetic, built in the tests from the layouts above with hand-assembled
6502 code; no Commodore software is redistributed. The sweeps cover every
prefix of a D64 and a T64 and 0x00/0xFF/bit-flip mutations of the BAM,
header, directory and file sectors of a D64 and a D81 (plus every 97th or
4,099th byte) and of every byte of a T64. After `./build-web.sh`,
`web/tests/cbm.test.mjs` (4 tests) classified a D64, a D81 and a T64
through `/pkg/zrax.js` and `/dist/zrax.js` and loaded a D64 into the
workbench; the whole browser suite passed 212 tests with 4 skipped (they
need D10 and RX113 firmware that is not in the repository). No real disk or
tape image was classified: behavior on images from the wild is not
verified.

After integration with the families added since on the same day, the
native suite passed 2,054 tests with 6 ignored, and IDA's corpus (4,621
files, none a Commodore image) classified as before.
