# UDF volumes

`src/formats/udf.rs` and its submodules parse UDF volumes (the OSTA Universal
Disk Format, a profile of ECMA-167) into the shared container model
([compressed streams and the container model](compressed-streams.md)): DVD
and Blu-ray discs, packet-written CD and DVD media, UDF hard disks, and UDF
bridge discs that also carry ISO 9660. Regular files whose first bytes are a
recognized format are listed as members, labeled by their path, and
classified from their own bytes. The volume names no processor.

| Submodule | Contents |
| --- | --- |
| `udf.rs` | Layouts, detection, the descriptor tag check, readers, the opened file system, summary notes |
| `udf/recognition.rs` | Volume recognition sequence, anchor volume descriptor pointer, sector size |
| `udf/volume.rs` | Main and reserve volume descriptor sequences, partition maps, integrity sequence, file set descriptor |
| `udf/partition.rs` | Block-to-sector mapping of physical, sparable, metadata and virtual partitions |
| `udf/entry.rs` | File entries, extended file entries, ICB indirection, allocation descriptors, data pieces |
| `udf/walk.rs` | File identifier descriptors, the directory walk, members and the census of what is skipped |
| `udf/text.rs` | OSTA CS0 strings, dstrings, entity identifiers, timestamps |

## Implemented layouts

| JSON format ID | Layout (variant) | Detection | Primary source |
| --- | --- | --- | --- |
| `udf` | UDF (`UDF`): `NSR02` or `NSR03` in the volume recognition sequence from 0x8000, a verified anchor at sector 256 | Strong | [ECMA-167 3rd edition (June 1997)](https://ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf) (SHA-256 `6efe0f59…c34b7`), 2/8.3, 2/9.1-9.3, 3/7.2, 3/8.4.2.1, 3/10.2; [OSTA UDF 2.60](https://web.archive.org/web/20240116224411/http://www.osta.org/specs/pdf/udf260.pdf) (SHA-256 `e338ef7f…ae71b`), 2.1.7, 2.2.3 |
| `udf` | UDF bridge (`UDF bridge (UDF and ISO 9660)`): an ECMA-119 descriptor set before the UDF extended area, and a UDF volume that opens through its root directory | Strong, with the whole volume structure checked | ECMA-167 2/8.3.1.1; UDF 2.60 6.11.4 |

What is read, with its source:

| Structure | Fields used | Source |
| --- | --- | --- |
| Volume structure descriptors | Standard identifier (1), one per max(2048, sector size) bytes from byte 32768, until the first unknown identifier; an NSR descriptor before the first `TEA01`; with 4096 B sectors also the second half of each sector | ECMA-167 2/8.3, 2/9.1; Linux v6.11 `fs/udf/super.c` `udf_check_vsd` |
| Descriptor tag | Identifier, version 2 or 3, checksum, CRC-ITU-T (initial value 0) over the CRC length, tag location | ECMA-167 3/7.2, 4/7.2; UDF 2.60 2.2.1, 2.3.1; Linux `udf_read_tagged` |
| Anchor volume descriptor pointer | Main and reserve sequence extents; anchors at N - 256 and N noted | ECMA-167 3/10.2, 3/8.4.2.1; UDF 2.60 2.2.3 |
| Volume descriptor sequence | Primary volume, partition and logical volume descriptors (the highest sequence number of each class prevails), volume descriptor pointers, terminating descriptor; the reserve sequence when the main one lacks a descriptor | ECMA-167 3/8.4, 3/10.1, 3/10.3, 3/10.5, 3/10.6, 3/10.9; Linux `udf_process_sequence`, `udf_load_sequence` |
| Partition maps | Type 1; type 2 `*UDF Virtual Partition`, `*UDF Sparable Partition`, `*UDF Metadata Partition` | ECMA-167 3/10.7; UDF 2.60 2.2.8-2.2.10 |
| Logical volume integrity | Integrity type, file and directory counts, UDF revisions (notes only) | ECMA-167 3/10.10; UDF 2.60 2.2.6 |
| File set descriptor | Root directory ICB, file set identifier, system stream directory (noted); the highest file set number in the extent | ECMA-167 4/14.1; UDF 2.60 2.3.2 |
| File entry and extended file entry | ICB tag (strategy 4 or 4096, file type, flags), information length, extended attribute and allocation descriptor lengths, stream directory ICB | ECMA-167 4/14.6, 4/14.9, 4/14.17; UDF 2.60 2.3.5, 2.3.6; Linux `udf_read_inode` |
| Indirect entries | Strategy 4096: the indirect entry in the next block names the newer ICB | ECMA-167 4/14.7; UDF 2.60 6.6; Linux `udf_read_inode` |
| Allocation descriptors | `short_ad`, `long_ad`, `ext_ad`, data in the entry; extent types; continuation extents (allocation extent descriptors) | ECMA-167 4/12, 4/14.5, 4/14.14; UDF 2.60 2.3.10, 2.3.11 |
| File identifier descriptors | Characteristics (deleted, parent), identifier, ICB; Linux's checks | ECMA-167 4/14.4; UDF 2.60 2.3.4; Linux `udf_verify_fi` |
| Names | OSTA CS0 with compression ID 8 or 16 | UDF 2.60 2.1.1, 6.4 |
| Sparing table | Tag identifier 0, `*UDF Sparing Table`, map entries | UDF 2.60 2.2.12; Linux `udf_load_sparable_map`, `udf_get_pblock_spar15` |
| Metadata partition | The metadata file (type 250) or its mirror (251) | UDF 2.60 2.2.10, 2.2.13; Linux `udf_load_metadata_files` |
| Virtual allocation table | 2.00 VAT (file type 248, header length) and 1.50 VAT (`*UDF Virtual Alloc Tbl` trailer) in the last four sectors | UDF 2.60 2.2.11; [OSTA UDF 1.50](https://web.archive.org/web/20250101031426/http://www.osta.org/specs/pdf/udf150.pdf) (SHA-256 `f4ecee7e…a8e8a`) 2.2.10; Linux `udf_find_vat_block`, `udf_load_vat` |

The Linux sources are those of tag `v6.11` (`fs/udf/super.c`, `misc.c`,
`inode.c`, `directory.c`, `partition.c`, `ecma_167.h`, `osta_udf.h`). The
documents were read from these copies:

| Document | SHA-256 |
| --- | --- |
| ECMA-167 3rd edition | `6efe0f591e21da2b17288076b2653dc616800bdc94f83e74acba9279c84c34b7` |
| OSTA UDF 2.60 | `e338ef7f06cb4c8ef9511fef337b3b12bf3ba29a3a2de85ae84dfd316f5ae71b` |
| OSTA UDF 1.50 | `f4ecee7ebc3f0132e5f846a7f8cadd3cee19d8246202e1643699ffe3ec8a3e8a` |

## Coexistence with ISO 9660

A UDF bridge disc (`hdiutil makehybrid -iso -udf`, DVD-Video, many DVD-ROM
and Windows installation discs) carries an ECMA-119 descriptor set at 0x8000
and the UDF extended area after it. Both families can read it. UDF reports
the disc when its volume opens: the descriptor sequence, partitions, file set
descriptor and root directory read, and the root's first file identifier
descriptor verifies. DVD and Blu-ray content, files larger than 4 GiB and
long names live in the UDF hierarchy, while the ISO 9660 hierarchy is often
a stub. When the UDF part does not open, the disc stays ISO 9660, which notes
the UDF descriptors as before.

The check sits before ISO 9660 in `detect_format`, after the console disc
checks (whose video partitions may be bridge volumes of their own). A bridge
disc's El Torito boot images are listed only by the ISO 9660 reading; the
UDF reading notes the boot record. This changed what the classifier reports
for bridge discs: before this family, ISO 9660 reported them (see
[ISO 9660](iso9660.md)).

## Wire units and byte order

All numbers are little-endian. Part 3 structures (anchors, volume
descriptors, partition starts, sparing table locations) address logical
sectors of the volume; Part 4 structures (file set, entries, directories,
allocation descriptors) address logical blocks relative to a partition by
partition reference number. UDF makes the logical block the size of the
logical sector (UDF 2.60 2.2.4.2); a logical volume descriptor whose block
size differs from the sector size the anchor validated with is an error.
The sector size is not recorded: 512, 1024, 2048 and 4096 B are tried in
turn, as Linux `udf_fill_super` tries block sizes, and the first whose
anchor verifies at sector 256 is used. The recognition sequence is in 2048 B
descriptors from byte 32768 whatever the sector size, one per sector for
4096 B sectors. Offsets in notes, metadata and members are file bytes.

## Validation and resource bounds

- Every descriptor read is verified: tag checksum, descriptor version 2 or
  3, CRC over the recorded CRC length (which must fit the descriptor), and
  the tag location (except for file identifier descriptors, which Linux
  does not check either).
- Recognition reads at most 64 volume structure descriptors (ours; Linux
  reads up to byte 0x800000).
- A descriptor sequence reads at most 4096 sectors and follows at most 64
  volume descriptor pointers (Linux `UDF_MAX_TD_NESTING`); the integrity
  sequence at most 256 descriptors; the file set extent at most 256 blocks.
- The map table must fit the logical volume descriptor and hold its map
  count; map lengths are 6 (type 1) and 64 (type 2); sparable maps name 1 to
  4 tables with a power-of-two packet length; sparing tables are read up to
  1 MiB.
- File entries must fit one block; data in the entry must match the
  information length (as Linux requires). ICB indirection stops after 1024
  indirect entries (Linux `UDF_MAX_ICB_NESTING`), continuation extents after
  16384 and extents per file after 262144 (ours).
- VATs are read up to 4 MiB (ours); the VAT ICB is looked for in the last
  four sectors of the input (Linux `udf_find_vat_block`).
- Directories are read up to 64 MiB, at most 65536 of them, 64 levels deep,
  with paths up to 4096 B; every ICB is read once, so repeated and cyclic
  references are counted and not followed.
- Descriptor reads (entries, continuation extents, directory data) are
  charged to a budget of 16 times the input size (at least 1 MiB; ours);
  when it runs out, the walk stops and says so.
- Regular files are recognized from their first 4 KiB; members are capped
  at 64 MiB each, 4096 members and 256 MiB extracted per volume (the shared
  container limits). A file is charged to the extraction limit before its
  extents are mapped.
- A file stored in one piece is listed as-is (borrowed). A file in several
  extents, or with unrecorded (zero) extents, is reassembled and listed with
  the transform `UDF extents`, its stored range being the first stored
  extent.

## Truncated volumes

A volume is truncated when its last partition ends past the end of the input
(containers hand on the first 64 MiB of a larger disc). It is read when the
anchor, a descriptor sequence, the file set descriptor and the root
directory's entry are present, and when a metadata partition's metadata file
or a virtual partition's VAT is present. Directories past the end are read up
to the end and counted; file entries past it are counted; files are listed
only when all of their data is present. The notes say what was present.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| U1 | The logical block size is the logical sector size, which the anchor at sector 256 reveals | Every fixture and synthetic sector size (512, 2048, 4096 B) reads; a block size other than the sector size is an error (`corrupted_volume_descriptors_are_parse_errors`) |
| U2 | An NSR descriptor before the first `TEA01` marks UDF, as in Linux; `BEA01` is not required | `an_nsr_descriptor_after_the_terminator_does_not_count`; a writer that puts NSR without an extended area would still be recognized |
| U3 | On a single-volume set every partition map names this volume, whatever volume sequence number it records | Linux does not compare them; a multi-volume set (maximum volume sequence number above 1) is checked and noted |
| U4 | The VAT ICB is among the last four sectors of the input | `virtual_partitions_read_entries_through_the_vat`; an image padded after its last recorded sector would not find it (Linux also tries the device's last block) |
| U5 | A 1.50 VAT's ICB has file type 0 (UDF 1.50 2.2.10) | Synthetic only: no write-once media was available to write a real one |
| U6 | File type 0 is a regular file, as Linux reads it | Not seen on the fixtures, which record type 5 |
| U7 | A bridge disc whose UDF root directory reads is better described by UDF than by ISO 9660 | The ISO 9660 fixture `hdiutil.iso` lists the same files under their real names in UDF; its El Torito image is only noted |
| U8 | Bytes after the last partition belong to the volume (anchors at N, padding), so the whole input is consumed | hdiutil and newfs_udf images end with anchors or zero sectors |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Multisession discs whose UDF session starts after sector 0 | Not read: an image file does not tell the session start, which Linux asks the drive for (`udf_get_last_session`) |
| Anchors only at N - 256 or N, or at 512 on open media | Noted, not used: detection needs the anchor at 256 |
| Multi-volume sets | Partitions of other volumes are not read; noted |
| Named streams, extended attributes, the system stream directory | Not read; counted or noted |
| Symbolic links, devices, FIFOs, sockets | Counted, not followed |
| Real-time files (file type 249) | Counted, not read (UDF 2.60 2.3.5.2.1) |
| Files with the ICB transformed flag, or `ext_ad` extents whose recorded or information length differs from the extent length | Counted, not read: the recorded bytes are not the file's |
| Hard links | A file entry named by several directory entries is listed under the first path in walk order |
| El Torito images of a bridge disc | Listed by the ISO 9660 reading only; the UDF reading notes the boot record |
| Unallocated space, free space bitmaps, the metadata bitmap file | Not read; they describe free space, not files |

## Verification

On 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly 2026-09-05),
`tests/udf.rs` (29 tests; two of them skip without `IDA_INPUT_DIR` and
`UDF_SAMPLE`) and the 23 unit tests in `src/formats/udf.rs` and
`src/formats/udf/` passed, with the whole native suite (2,676 passed, 6
ignored). With `IDA_INPUT_DIR=/Users/int/hexrays/ida/tests/input`, 44,391
of IDA Pro's test inputs were scanned and none was detected as UDF (none is
one). `UDF_SAMPLE` was run on a scratch UDF 2.60 image written by
`newfs_udf -r 2.60` (3 members); no real DVD or Blu-ray image was
available, so commercial discs are not verified. After `./build-web.sh`,
`web/tests/udf.test.mjs` (6 tests) passed through `/pkg/zrax.js`,
`/dist/zrax.js` and both workbench pages, and the whole browser suite
passed (304 passed, 4 skipped for want of the D10 and RX113 firmware).
Sparable and virtual partitions, `ext_ad` and continuation extents, and ICB
indirection are tested on synthetic volumes built from the documented
layouts only: macOS `newfs_udf` cannot write sparable or write-once media
to an image file.

After integration on the same day, the native suite passed 2,784 tests
with 6 ignored, and IDA's corpus (4,621 files, no UDF volumes)
classified as before.
