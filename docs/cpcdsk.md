# CPC and Spectrum +3 disk images

`src/formats/cpcdsk.rs` and its submodules (`image`, `cpm`, `header`)
parse the disk images that Amstrad CPC and ZX Spectrum +3 emulators use
(the CPCEMU `MV - CPC` format and the Extended `EXTENDED CPC DSK` format),
the CP/M 2.2 filesystem that AMSDOS and +3DOS write on those disks, and the
128-byte AMSDOS and +3DOS file headers, inside a disk image or as
standalone files. The family is built on the shared container model
([compressed streams and the container model](compressed-streams.md)).

A disk image is a disk information block and one track block per track and
side, each a Track-Info block with a sector information list followed by
the sector data. The image names no processor. When track 0 selects an
AMSDOS or +3DOS format, the CP/M directory is read and every file is
reassembled from its allocation blocks. A file whose first record is an
AMSDOS or +3DOS header is a headered file: binary and CODE files are Z80
code, everything else is opaque data. Headerless files are listed when
they are a recognized format. The boot sector the system executes is a Z80
child after the files.

## Implemented layouts

| JSON format ID | Layout (`format.variant_name`) | Recognition | Architecture evidence | Primary sources |
| --- | --- | --- | --- | --- |
| `cpcdsk` | `CPCEMU disk image`: one track block size for every track | Strong: `MV - CPC` at offset 0 | None for the image. Headered binary and CODE files and the boot sectors are Z80 children (8-bit, little-endian, variant `Z80`); other files are classified from their own bytes | [DSK], [CAP32], [MAME], [LIBDSK] |
| `cpcdsk` | `Extended CPC disk image`: a track size table and a stored length per sector | Strong: `EXTENDED CPC DSK` at offset 0 | As above | [EDSK], [CAP32], [MAME], [LIBDSK] |
| `plus3dos` | `+3DOS file`: a +3DOS header record and the file body | Strong: `PLUS3DOS` and the soft-EOF byte 0x1A at offset 0; the checksum and issue are checked by the parser | CODE files: Z80, 8-bit, little-endian, loaded at the header's address. BASIC programs, arrays, screens: none | [P3MAN], [Z88DK] |
| `amsdos` | `AMSDOS file`: an AMSDOS header record and the file body | Weak: the header checksum and every field below | Binary files: Z80, 8-bit, little-endian, loaded at the header's address with its entry point. BASIC, screen and ASCII files: none | [AMSHDR], [AMSROM], [IDSK] |

The sources, fetched on 2026-10-13:

| Tag | Source | Pin |
| --- | --- | --- |
| [DSK] | Kevin Thacker, "Disk image file format" (cpctech), mirrored in `aaru-dps/docs` `dsk.html` | git `9c00831023ba8d59db709af7467d2775032858e5`; SHA-256 `08c7257e366c7a912b43732e8f380f8cbb989855aa599f0ab3c6a7e0b94b7465` |
| [EDSK] | Marco Vieth, Ulrich Doewich, Kevin Thacker, "Extended DSK image definition" Rev.5, with John Elliott's and Simon Owen's extensions, `aaru-dps/docs` `extdsk.html` | same commit; SHA-256 `7c695c352eb1c62d613586111e3b272d1d7f31c0dbbe2f969c0fed1174e0a2de` |
| [CAP32] | Caprice32 `src/slotshandler.cpp` (`dsk_load`), `src/z80.h`, `README.md` | git `6c12c4c92360065cdc229ac9ada7551f941436b8`; `slotshandler.cpp` SHA-256 `8728d6f762e42ccd69d2d7ca33f1b4027617f83c397317ac9fdb88187cb876b5` |
| [MAME] | MAME `src/lib/formats/dsk_dsk.cpp` (`dsk_format::identify`, `load`) | git `cefe05365473b5f2b77f5a91bf028347b2e50ee9`; SHA-256 `56678064c183437fa4cc8c6f4f37a47a5bf08c10428ad83339b3c0023debbd51` |
| [LIBDSK] | LibDsk 1.5.12 `lib/drvcpcem.c`, `lib/dskgeom.c` (mirror `lipro-cpm4l/libdsk`) | git `1a6803566a0e4a766f7f51acb9baf9e11551ba77`; SHA-256 `14e99a3437a79477d682f49ee0d0d28a53bba0bf70ac154b83f0c97d3a1b0794`, `aa5d63672966fe3fb22feb5fbd9f5c4c2fd467b70241e8b0c211afa5f8350d75` |
| [AMSROM] | Kevin Thacker, "Disassembly of AMSDOS ROM" (`amsdos.asm`, cpctech), Wayback snapshot `20240520144707` | SHA-256 `17608eb6924745c7b8d94f8cafd3703cf7c5c0abbb0dd7efb44e101ee9b18848` |
| [AMSHDR] | cpcwiki.eu "AMSDOS Header", oldid 125127 (a summary of the CPC firmware guide, chapter 9 page 4), Wayback snapshot `20250428022245` | SHA-256 of the decompressed page `5d2aaeb1be0cce8f084be5314acf41398a0e1eab3074c3ebff35a0f1b1354c46` |
| [IDSK] | iDSK `src/GestDsk.h`, `src/GestDsk.cpp` (`StAmsdos`, `CheckAmsdos`, `GetMinSect`) | git `bd620361720b2f45aafd9c100a1000c56957cb05`; SHA-256 `b83167f5e5bbf756d4812fda8d062bb226ac570947cb3d21b3aa752cbac5701a`, `19ab406df17f2f7b363359deeff21173893788d97a1760e89b6b85af79eb6d19` |
| [P3MAN] | ZX Spectrum +3 manual, chapter 8 part 27 "Guide to +3DOS" and part 26 "Using machine code" (World of Spectrum transcription) | SHA-256 `3b3fa8f10651504499b66bd9ee2f14f5fb9863c9c268fb8919c7dd5c9813bd98` (part 27), `83cb177c0dd3ff22064d82a9bad02418c7f103e5ab6a20dd5f895a0b963654b2` (part 26) |
| [Z88DK] | z88dk `src/appmake/zx-util.c` (+3DOS header writer) | git `9138a24f323af11d173c2afa87eecdbf45db4876`; SHA-256 `30092d0bbd8b6615f405c936d7bcae73c02932d9a3d7ee79f145a84563d0f7df` |
| [DRI] | Digital Research, "CP/M 2.2 Operating System Manual", chapter 5 (Figure 5-2, Table 5-2) and section 6.10 (Figure 6-4, Tables 6-8 to 6-10), gaby.de HTML transcription | SHA-256 `0656dc6d00f6666f8991132df2a48be27c827091a5623fff42227726186a725c` (chapter 5), `c81dea4c9d3729ff71bde9052e73858f2c31e61d759c91316be67186869f28bb` (chapter 6) |
| [CPM22F] | John Elliott, "CP/M 2.2 disc formats" (seasip.info) | SHA-256 `5bc333e1a160e1f93dfa5c594f250c75578984e80518b3577334f0e6b40b3d9c` |
| [AMSFMT] | John Elliott, "Amstrad CP/M disc formats" (seasip.info, 11-9-1998) | SHA-256 `fe5b571ec812c8600b08b9e5920888c0be8a1a68b443fd13a065553454f6027d` |

The CPC firmware guide (Amstrad SOFT 968) itself was not fetched: the
copies on cpcwiki.eu answered with a Cloudflare challenge (HTTP 403).

Detection order in `formats::detect_format`: the strong check runs after
the Psy-Q objects and before the magic-bearing compressed streams; no
earlier format starts with `MV - CPC`, `EXTENDED CPC DSK` or `PLUS3DOS`.
[DSK] says `MV - CPC` alone identifies a disk image, and [CAP32], [MAME]
and [LIBDSK] check those 8 bytes; [MAME] identifies extended images by the
16 bytes `EXTENDED CPC DSK` (the 8-byte tag `EXTENDED` that [CAP32] and
[LIBDSK] compare is an ordinary word). A different remainder of the
34-byte signature is noted. The weak AMSDOS check runs after the MBR check
and before zlib and LZMA-alone.

## Disk image

| Offset | Size | Standard | Extended |
| --- | --- | --- | --- |
| 0x00 | 34 B | `MV - CPCEMU Disk-File\r\nDisk-Info\r\n` | `EXTENDED CPC DSK File\r\nDisk-Info\r\n` |
| 0x22 | 14 B | Creator | Creator |
| 0x30 | 1 | Tracks per side | Tracks per side |
| 0x31 | 1 | Sides (1 or 2) | Sides (1 or 2) |
| 0x32 | 2 | Track block size including the Track-Info block | Unused |
| 0x34 | 204 B | Unused | Track block sizes / 256, one per track and side; 0 = unformatted, no block |

Track blocks follow from 0x100 in the order track 0 side 0, track 0 side
1, track 1 side 0, and so on. A Track-Info block is `Track-Info\r\n` (the
first 10 bytes are checked, as [CAP32] does), the track (0x10) and side
(0x11) numbers, data rate and recording mode (0x12, 0x13), sector size code
N (0x14), sector count (0x15), gap 3 (0x16), filler (0x17), and from 0x18
eight bytes per sector: C, H, R, N, ST1, ST2 and, in extended images, the
stored length. Sector data starts 0x100 after the block, or at the next
256-byte boundary after the sector list when more than 29 sectors extend
the block ([LIBDSK]). Standard images store `128 << N` bytes per sector
with the track's N, 0x1800 bytes for N = 6 ([DSK]); extended images store
each sector's stored length, which is a multiple of `128 << N` for weak
sectors kept as several copies ([EDSK]); the first copy is read.

## Filesystem

The format follows from the lowest sector ID on track 0 side 0 ([IDSK]
`GetMinSect`; AMSDOS itself decides on bits 7-6 of the first ID it reads,
[AMSROM] `SELECT FORMAT`):

| Lowest ID | Format | Sectors per track | Reserved tracks | Blocks (DSM + 1) | Source |
| --- | --- | --- | --- | --- | --- |
| 0x41 | AMSDOS system (and vendor) format | 9 x 512 B | 2 | 171 | [AMSROM] XDPB `0xCA43`; [P3MAN] type 1 |
| 0xC1 | AMSDOS data format | 9 x 512 B | 0 | 180 | [AMSROM] `0xC5CA`; [P3MAN] type 2 |
| 0x01 | +3DOS/PCW disk specification in bytes 0-15 of sector 1 (disk type 0 or 3) | From the specification | From the specification | `(tracks - reserved) × sectors × sector size / block size` ([LIBDSK] `set_pcw_fs`) | [P3MAN] "Disk specification" |
| 0x01 | +3DOS/PCW default format when the specification is all 0xE5 and the track has 9 sectors | 9 x 512 B | 1 | 175 | [AMSFMT]; [P3MAN] type 0 XDPB |
| 0x01 | AMSDOS IBM format when the specification is invalid or unwritten and the track holds sectors 1-8 | 8 x 512 B | 1 | 156 | [AMSROM] `0xC5C0` |

The AMSDOS formats use 1 KiB blocks and 64 directory entries in blocks 0
and 1 (BSH 3, DRM 63, AL0 0xC0). Logical sector `s` of a track is the
sector with ID `first + s`, wherever the sector list stores it. Logical
tracks are one per cylinder on single-sided formats; for a double-sided
specification they alternate between sides, or run up side 0 and back down
side 1 ([P3MAN]; [AMSFMT] "up and over").

Directory entries ([DRI] Figure 5-2; [CPM22F]): user (0), name and type (1,
11 bytes, bit 7 attributes), EX (12), S1 (13), S2 (14), RC (15), and 16
allocation bytes holding 8-bit block numbers while DSM < 256 and 16-bit
little-endian ones otherwise. An entry is extent `(32 × S2 + EX) / (EXM +
1)` of its file and holds `(EX & EXM) × 128 + RC` records of 128 bytes;
EXM follows from the block size and DSM ([DRI] Table 6-9). User 0xE5 is an
unused entry; users above 15 (CP/M 3 password, label and time-stamp
entries) are counted and ignored.

A file's entries are sorted by extent number, which must run 0, 1, 2, ...
without gaps or repeats; every extent but the last must be full; the
blocks its records need must be non-zero, outside the directory, inside
the format, and distinct within the file. A file sharing blocks with an
earlier file is counted as cross-linked and still read. Damage skips the
file with a note.

## Headers

| Header | Layout | Recognized inside a disk image | Standalone |
| --- | --- | --- | --- |
| AMSDOS | user (0), name (1, 8 B), extension (9, 3 B), zero (12, 4 B), tape block number and last-block flag (16, 17: zero), file type (18: bit 0 protected, bits 1-3 BASIC, binary, screen image, ASCII, bits 4-7 version), data length (19), load address (21), first-block flag (23), logical length (24), entry address (26), real length (64, 24-bit), checksum (67: 16-bit sum of bytes 0-66) | The checksum matches and is not zero ([AMSROM] `0xCF05`; [IDSK] `CheckAmsdos`) | Additionally: user 0-15, a printable name not starting with a space, bytes 12-17 zero, contents 0-3 with version 0 (ASCII: version 1), first-block flag 0 or 0xFF, logical length non-zero and equal to the real length, and a file size between `128 + length` and `128 + length` rounded up to a record |
| +3DOS | `PLUS3DOS` (0), 0x1A (8), issue (9), version (10), file length including the header (11, 32-bit), +3 BASIC header (15: type, length, parameter 1, parameter 2), reserved, checksum (127: sum of bytes 0-126 modulo 256) | The signature and checksum ([P3MAN]: "If the signature and checksum are as expected, then a header is present") | Additionally: issue 1, a file length of at least 128 B and no more than the input |

+3DOS is tried first: its signature is explicit, while an AMSDOS checksum
can match by chance. AMSDOS and +3DOS do not recognize each other's
headers ([P3MAN]).

| Header contents | Component |
| --- | --- |
| AMSDOS binary (contents 1, unprotected) | Z80 code, loaded at the load address, entered at the entry address |
| AMSDOS protected binary | Opaque: the stored form of protected files is not documented in the sources |
| AMSDOS BASIC, protected BASIC, screen image, ASCII, unallocated contents | Opaque |
| +3DOS CODE (type 3) | Z80 code loaded at parameter 1; the header has no entry address |
| +3DOS CODE of 6912 B at 0x4000 | Opaque: the display file (`SCREEN$`) |
| +3DOS BASIC program (type 0, autostart line when parameter 1 < 0x8000), numeric or character array, other types | Opaque |

## Components

| Component | Label | Classified |
| --- | --- | --- |
| Headered binary or CODE file, body after the header | `user:NAME.EXT` | Raw Z80 code (target Z80, 8-bit, little-endian, variant `Z80`), never a nested container |
| Other headered file, body after the header | `user:NAME.EXT` | Opaque |
| Headerless file whose first 4 KiB are a recognized format | `user:NAME.EXT` | As that format (an archive-style member) |
| CP/M boot sector of the system format (track 0, sector 0x41), unless all its bytes are equal | `CP/M boot sector (track 0, sector 0x41)` | Raw Z80 code: AMSDOS `\|CPM` loads it at 0x0100 and starts it there ([AMSROM] `0xC20A`-`0xC221`) |
| +3 bootstrap: sector 1 of a disk with a valid specification whose bytes sum to 3 modulo 256, from offset 0x10 | `+3 bootstrap (track 0, sector 1)` | Raw Z80 code: `DOS BOOT` loads the sector at 0xFE00 and enters it at 0xFE10 ([P3MAN]) |

Files are pushed in directory order and the boot sector last, so the first
headered binary decides the disk's primary ISA. A file stored in one run is
borrowed with its file offset; a file spread over several sectors is
reassembled (transform `CP/M allocation blocks`) with the first run as its
stored range. Headerless files in no recognized format are counted, not
listed. PCW bootstraps (sector checksum 1 for the PCW9512, 255 for the
PCW8256, [AMSFMT]) are noted and not analyzed.

Notes: the image summary (layout, tracks, sides, creator), the format, the
directory census (entries, files, extents, unused, other and invalid
entries), the header kinds found, one note per headered file (32 listed,
the rest counted) with its load and entry addresses and size, skipped
files with the defect (16 listed), the boot sector, the track census
(formatted, unformatted, sectors) and copy-protection facts (sectors with
ST1/ST2 flags, weak sectors, short sectors, misnumbered Track-Info blocks,
sector IDs naming another cylinder or head), and data after the last
track (a LibDsk `Offset-Info` block, padding, or other data). Metadata:
`cpcdsk_creator`, `cpcdsk_tracks`, `cpcdsk_sides`,
`cpcdsk_unformatted_tracks`, `cpcdsk_filesystem`, `cpcdsk_file_count`,
`cpcdsk_headered_file_count`, and the generated `cpcdsk_image_size` and
`cpcdsk_component_<i>`. Standalone files report `amsdos_user`,
`amsdos_file_name`, `amsdos_file_type`, `amsdos_load_address`,
`amsdos_entry_address`, `amsdos_logical_length`, or `plus3dos_version`,
`plus3dos_file_length`, `plus3dos_basic_type`, `plus3dos_parameter_1`,
`plus3dos_parameter_2`, and a load section `<name> at 0x<address>`.

## Wire units and byte order

All multi-byte fields are little-endian: disk information block, Track-Info
blocks, directory entries, both headers. Sizes are bytes; CP/M lengths are
128-byte records; block numbers count blocks of the format's block size
from the first data track. Offsets in slices, notes and metadata are file
offsets in the input; load and entry addresses are Z80 byte addresses.

## Validation and resource bounds

- Disk information block: 256 B present; sides 1 or 2; extended images at
  most 204 track blocks (the size table); standard images a track size of
  at least 256 B. Every declared track block must lie in the file, start
  with `Track-Info`, and hold its sector list and every sector's data;
  standard images need a size code of at most 6. These are errors.
- Unformatted tracks, missing or short sectors, FDC status flags, weak
  sectors and foreign IDs are notes. A track 0 that selects no format
  leaves the image without a filesystem (a note), not an error.
- Disk specification: disk type 0 or 3, sidedness 0-2 with bits 2-5 clear,
  tracks and sectors non-zero, sector shift at most 7, block shift 3-7, 1-16
  directory blocks, a data area left after the reserved tracks, at most
  65536 blocks, and no 1 KiB blocks beyond 256 blocks (no EXM exists).
- Entries: user 0-15, printable name, EX at most 31, S2 at most 15, RC at
  most 0x80; others are counted as invalid.
- Files are at most 512 extents of 16 KiB (8 MiB) by the entry fields;
  extraction stops at 4096 components (`MAX_COMPONENTS`) and 256 MiB in
  total (`MAX_EXTRACTED`), with the rest counted. Headerless files are
  read only as far as the 4 KiB recognition prefix unless recognized.
- Every read is bounds-checked; directory and file reads stop at the first
  missing sector. Allocation grows only with structures present in the
  input: the block map is at most 65536 entries, the directory at most 16
  blocks of 16 KiB.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| C1 | A disk image names no processor | MAME loads DSK images for the Tatung Einstein ([MAME] `load`, "theatre europe on einstein"); a DSK for a machine whose files carry no AMSDOS or +3DOS header gets no ISA from this family |
| C2 | AMSDOS headers exist only on the Amstrad CPC, and the CPC runs Z80 code | [AMSROM] disassembles AMSDOS as Z80 instructions (`c3bcc1 jp $c1bc`); [CAP32] emulates the CPC464/664/6128 with a Z80 core. The CPC firmware guide was not fetched (see above). A CPC binary that classifies as another ISA would show the code-model warning |
| C3 | +3DOS headers exist only on the Spectrum +3 (and +2A), which runs Z80 code | [P3MAN] part 26: "Z80 machine code i.e. the set of instructions that the Z80 processor chip uses" |
| C4 | The lowest sector ID on track 0 selects the format | AMSDOS reads the first ID under the head ([AMSROM]); a disk whose track 0 mixes ID ranges could be read differently by the real system |
| C5 | Successive sides map logical track `t >= cylinders` to cylinder `2 × cylinders - 1 - t`, head 1 | [AMSFMT] "up and over"; [P3MAN]'s table for this case reads "side 1 last track-1 = logical track n/2" and conflicts: not verified on a real successive-sides disk |
| C6 | A +3DOS header's file length includes the 128-byte header | [Z88DK] `total_len += 128` before writing bytes 11-14; probe with a file saved by a real +3 |
| C7 | A protected AMSDOS binary is not stored in clear | Not established either way: such files are opaque. A probe is a protected binary saved by AMSDOS and compared with its unprotected save |
| C8 | `SCREEN$` is CODE of 6912 B at 0x4000 | Spectrum BASIC convention by our reading, not stated in the fetched sources; used only to keep a picture away from the code model |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Raw sector dumps without a DSK header, other image formats (MFM HFE, SCP, IPF) | Not recognized by this family |
| Sparse CP/M files (an extent before the last not full) | Skipped with a note |
| CP/M 3 password, label and time-stamp entries | Counted and ignored; CP/M 3 byte counts (S1) are not used, so headerless files are record-granular |
| Disks with several filesystems (flippy second sides, partitioned PCW16 disks with a DOS boot sector) | Only the filesystem of track 0 side 0 is read |
| Copy-protected disks whose track 0 has no AMSDOS or +3DOS sector IDs | No filesystem; tracks and protection facts are noted |
| Standalone AMSDOS files longer than 4 KiB inside archives and filesystems | Not recognized from the 4 KiB prefix other families read, so not listed there |
| PCW bootstraps and CP/M system tracks beyond the boot sector | Noted or ignored, not analyzed |
| `Offset-Info` blocks ([LIBDSK]) | Noted, not used |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`),
`cargo test --all-features --locked` passed 1,880 tests with 6 ignored
(the existing ignores that need external data), including
`tests/cpcdsk.rs` (18 tests) and 15 unit tests in `src/formats/cpcdsk.rs`
and its submodules: data, system, IBM, +3 specification and +3 default
volumes in both image layouts, interleaved and reassembled files, a
two-extent file listed out of order, the CP/M and +3 boot sectors, a
protected track, an unformatted track, six kinds of directory damage,
unknown sector IDs, trailing data, standalone +3DOS and AMSDOS files with
corrupted checksums, issue, lengths and fields, an every-prefix truncation
sweep of four fixtures, and a mutation sweep (`0x00`, `0xFF` and three bit
flips of every byte, parsed directly; part of them also classified). After
`./build-web.sh`, `web/tests/cpcdsk.test.mjs` passed 4 of 4 (`/pkg/zrax.js`,
`/dist/zrax.js`, `/web/index.html` and `/dist/index.html`). The full
browser suite passed 212 of 216 with 4 skips (D10/RX113 firmware not in the
repository); it ran on a build before the last edits, which only rewrapped
string literals and rewrote two expressions without changing behavior, and
the family's browser test was run again on the final build.

The fixtures are synthetic, built in the tests from the layouts above with
hand-assembled Z80 routines (each byte documented in the test) and the
repository's synthetic ELF header as a headerless member. No disk tool
(iDSK, cpcxfs, LibDsk utilities, cpmtools, z88dk) was installed, so no
image written by a real tool or emulator was tested: the readers' agreement
with real CPC and +3 disks, copy-protected dumps and the successive-sides
mapping is not verified.

After integration with the families added since on the same day, the
native suite passed 2,199 tests with 6 ignored; IDA's corpus (4,621 files)
and a scan of 82,323 local files classified as before, so the weak AMSDOS
header check claimed none of them.
