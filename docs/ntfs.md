# NTFS volumes

`src/formats/ntfs.rs` and its submodules read NTFS volumes, read-only, into
the shared container model
([compressed streams and the container model](compressed-streams.md)). The
reader checks the boot sector, locates the master file table (`$MFT`)
through its own runlist, applies and verifies the update sequence fixups of
every MFT record it reads, follows attribute lists into extension records,
reads resident, non-resident, sparse and LZNT1-compressed data, builds each
file's path from the parent references of its `$FILE_NAME` attributes, and
lists each regular file and named data stream whose first bytes are a
recognized format as a child labelled with its path. Each member is then
classified from its own bytes. The volume names no processor.

| Submodule | Contents |
| --- | --- |
| `ntfs.rs` | Layout, bounds-checked readers, the volume's present bytes, trailing data and the backup boot sector, `$Volume` (label, version, flags), `$MFTMirr` comparison, summary notes and metadata |
| `ntfs/boot.rs` | Boot sector and the ntfs-3g checks that detection requires |
| `ntfs/record.rs` | MFT records: update sequence fixups, header checks, attribute records (resident and non-resident), `$FILE_NAME` values, MFT references, where record bytes are stored |
| `ntfs/runlist.rs` | Mapping pairs arrays: runs, sparse runs, signed LCN deltas |
| `ntfs/mft.rs` | `$MFT` bootstrap (record 0 and its attribute list), records by number, files across base and extension records, extents joined into streams, the metadata read budget |
| `ntfs/data.rs` | Stream reads: resident values, stored and sparse runs, `initialized_size`, LZNT1 compression units |
| `ntfs/walk.rs` | The two-pass MFT walk, paths, orphans, links, encrypted and WOF files, member extraction and limits, notes |
| `compressed/lznt1.rs` | The LZNT1 codec (`compressed::Codec::Lznt1`), added for this family |

## Implemented layouts

| JSON format ID | Variant | Layout | Architecture evidence | Primary source |
| --- | --- | --- | --- | --- |
| `ntfs` | `NTFS` | Boot sector with the OEM ID `NTFS    ` at offset 3 at the start of the input; NTFS 1.2 to 3.1 records (headers of 42 or 48 bytes) | None. No field names a processor; members are classified from their own bytes | tuxera/ntfs-3g tag `2022.10.3` (commit `78414d93613532fd82f3a82aba5d4a1c32898781`): `include/ntfs-3g/layout.h` (SHA-256 `ae5e45ac…35a4f6`), `include/ntfs-3g/param.h`, `libntfs-3g/bootsect.c`, `mst.c`, `mft.c`, `attrib.c`, `runlist.c`, `volume.c`, `compress.c`, `dir.c`; Richard Russon and Yuval Fledel, "NTFS Documentation" (linux-ntfs), flatcap/ntfs-docs commit `641edd36dc5f6b62c2aae6658c5a60a4d6d3fe29` |

The LZNT1 codec follows [MS-XCA] "Xpress Compression Algorithm" v20240423
(revision 10.0), section 2.5 "LZNT1 Algorithm Details", and decodes the
section 3.3 example (59 B to the 142 B string) in its unit tests. Where the
specification leaves a case open it follows ntfs-3g `ntfs_decompress`:

| Case | Behavior |
| --- | --- |
| Chunk header 0, or the end of the input | End of the buffer; the end header is optional ([MS-XCA] 2.5.1.2) |
| Signature bits 14-12 other than 3 | Error ("MUST always be 3") |
| Uncompressed chunk | Its bytes as they are (any size up to 4096; ntfs-3g requires exactly 4096) |
| Compressed word | Displacement in the high D bits, D the largest of 4 to 12 with 2^(D-1) below the bytes already decoded in the chunk; length + 3 bytes from displacement + 1 back, copied byte by byte |
| A word that reaches before its chunk, or a chunk that decodes past 4096 B | Error (ntfs-3g `return_overflow`) |
| A chunk shorter than 4096 B followed by another chunk | Zero-filled to 4096 B, as ntfs-3g fills it ([MS-XCA] lets only the last chunk be short) |
| Output limit | An error for `decode_limited`; `decode_prefix` stops at the limit, as ntfs-3g stops at the end of the compression unit |

The Sleuth Kit `sleuthkit-4.12.1` (`tsk/fs/fs_dir.c`) is the source of the
`$OrphanFiles` directory name under which files the root does not reach are
listed.

## Detection

Detection is strong and reads only the first 512 B, so
`container::is_recognized` finds a volume from a member's first 4 KiB. It
requires what ntfs-3g `ntfs_boot_sector_is_ntfs` and
`ntfs_boot_sector_parse` require, and the end marker:

- `NTFS    ` at offset 3 and `55 AA` at 510 (ntfs-3g only warns about the
  marker);
- `bytes_per_sector` a power of two from 256 to 4096;
- `sectors_per_cluster` a power of two up to 128, or 240 to 253 meaning
  `1 << (256 - value)` sectors, for a cluster of at most 2 MiB
  (`NTFS_MAX_CLUSTER_SIZE`);
- zero `reserved_sectors`, `fats`, `root_entries`, `sectors`,
  `sectors_per_fat` and `large_sectors`;
- `clusters_per_mft_record` and `clusters_per_index_record` each 1 to 64
  clusters (a power of two) or -31 to -9 (`1 << -value` bytes); MFT records
  of 512 B to 64 KiB (the upper bound is ours), index records of at least
  512 B;
- a positive `number_of_sectors` whose byte size fits 64 bits;
- `mft_lcn` and `mftmirr_lcn` positive, different, and below the cluster
  count.

The check runs right after the virtual disk and Apple disk image checks in
`detect_format`, before the archive, filesystem, ISO 9660, partition-table
and FAT checks. A fixed VHD or a raw UDIF data fork starts with its guest
disk's first sector, so those containers must keep their inputs; the checks
after it probe offsets that lie inside an NTFS volume (the tar magic at 257,
superblocks at 0x400 and 0x438, `CD001` at 0x8001), where any file's data
may be stored, and no format they claim starts with an NTFS boot sector. The
weak MBR check already refuses a sector with the `NTFS    ` OEM ID, so an
NTFS volume is never taken for a partition table either way.

## Wire units and byte order

All structures are little-endian. Cluster numbers (LCNs) count clusters of
`bytes_per_sector * sectors_per_cluster` bytes from the boot sector, which
is file offset 0; virtual cluster numbers (VCNs) count clusters of an
attribute's value. Record `N` is at `$MFT` byte `N * record size`, mapped
through `$MFT`'s runs. Update sequence strides are 512 B whatever the
sector size. Offsets in notes, metadata and members are file bytes.

A member stored as it is is borrowed from the image: its slice is the stored
bytes. Other members name their transform, and their slice gives the file
offset and size of their first stored run:

| Transform | Member |
| --- | --- |
| `NTFS update sequence` | A resident value that crosses a stride end (whose stored bytes are the update sequence number) or spans two runs of `$MFT`; the decoded range is the fixed-up value |
| `NTFS runs` | A value in several runs, with sparse runs (zeros), or with bytes past `initialized_size` (zeros) |
| `NTFS LZNT1` | An LZNT1-compressed value; the slice is its first stored run of compressed chunks |

## Members

- The walk reads every MFT record from 16 up in record order, twice: the
  first pass indexes the directories (name and parent of their first
  `$FILE_NAME` that is not a DOS 8.3 alias) and collects the regular files
  and the directories with named streams; the second examines them. Records
  0 to 15 are system files and are not walked; `$MFT`, `$Volume` (label,
  version, flags), the root (record 5) and `$MFTMirr` are read on their own.
- Only base records in use are read (`MFT_RECORD_IN_USE`, a zero
  `base_mft_record`); records not in use (deleted, or never used) are
  skipped without checking their contents.
- A file's attributes come from its base record or, with an
  `$ATTRIBUTE_LIST` (resident or not, at most 256 KiB), from the records the
  list names, in list order. A listed attribute is found by type, name, and
  instance (first extent) or lowest VCN (later extents); an extension record
  must be in use and name the base record. The extents of one attribute are
  joined in VCN order: the first starts at VCN 0 and holds the sizes, each
  later one starts where the one before ends, and the runs may not map more
  clusters than the allocated size.
- Paths: from the file's first name that is not a DOS alias, the parent
  references are followed up to the root (record 5, sequence number 5). A
  parent that is not an indexed directory, a reference whose sequence number
  is not the parent's (a reused record), or a cycle make the file an orphan,
  listed as `/$OrphanFiles/<name>`. A parent below record 16 other than the
  root (`$Extend` and its children) marks a system file, which is not read.
  Directories more than 64 levels below the root are not walked; their
  files are counted. Paths are remembered per directory, so each is built
  once.
- Hard links: a file with several names is examined once, under its first
  name; the count of such files is noted.
- Data streams: the unnamed `$DATA` stream is listed as the path, each named
  `$DATA` stream as `path:name` (directories: only their named streams). The
  first 4 KiB (or the whole stream, if smaller) go to
  `container::is_recognized`; only recognized streams are extracted and
  listed (`Classify::IfRecognized`).
- Not read, and counted in notes: files with `FILE_ATTR_ENCRYPTED`, an
  encrypted `$DATA` attribute or a `$EFS` logged utility stream (EFS data is
  opaque without the file's key); links (reparse tags `0xA000000C`
  symbolic link, `0xA0000003` mount point, `0xA000001D` WSL symbolic link)
  and Interix symbolic links (system files starting with `IntxLNK\1`, as
  ntfs-3g `ln -s` writes them); WOF files (tag `0x80000017`, whose data is
  XPRESS or LZX in a `WofCompressedData` stream); streams compressed with a
  method other than 1, a compression unit other than 16 clusters, or on
  clusters larger than 4 KiB. Files with other reparse tags are counted and
  their streams examined as stored.
- Compression units: a unit whose first cluster is sparse holds zeros; a
  unit whose clusters are all stored holds its bytes as they are; otherwise
  its stored clusters hold LZNT1 chunks that decode to the unit, padded with
  zeros. For the recognition prefix only the first 4 KiB of the first unit
  are decoded.

## Checksums and authentication

NTFS metadata has no checksums. The update sequence numbers of every MFT
record read are verified: a stride whose last two bytes differ from the
update sequence number is a torn write, and the record is an error (record
0) or a problem note. The boot sector's checksum field at 0x50 is not
verified, as its algorithm is not documented in the sources. The first four
records (or one cluster of records) are compared, after fixups, with their
`$MFTMirr` copy, and a difference is noted; `$MFT` is always the copy read.
The backup boot sector after the volume is compared with the boot sector.
EFS-encrypted data is never decrypted, and nothing is authenticated.

## Validation and resource bounds

- A complete volume (`number_of_sectors * bytes_per_sector` bytes) may be
  followed by its backup boot sector (a sector that is itself a valid NTFS
  boot sector, or the start of a copy of the boot sector when the input ends
  inside it) and then only `0x00`/`0xFF` padding; other trailing bytes are a
  parse error.
- Record checks ([NTFS-3G] `is_valid_record`, `ntfs_mft_record_check`,
  `ntfs_attr_inconsistent`): `FILE` magic (`BAAD` and other magics are
  errors, a zero magic an empty slot); an update sequence array of `1 +
  size / 512` entries ending before offset 510; `bytes_allocated` equal to
  the record size; `bytes_in_use` within it; 8-aligned attributes in
  non-decreasing type order ending with the end marker; attribute lengths,
  names, values and mapping pairs inside their records; `$FILE_NAME`,
  `$STANDARD_INFORMATION`, `$VOLUME_NAME` and `$VOLUME_INFORMATION`
  resident and long enough; an NTFS 3.1 header's own record number must
  match.
- Runlists ([NTFS-3G] `ntfs_mapping_pairs_decompress_i`): a header byte with
  a length field of 1 to 8 bytes and an LCN delta of 0 to 8 bytes, a
  positive length (zero only for sparse runs, which are dropped), LCNs not
  below -1 (-1 is sparse), stored runs inside the volume's clusters, an end
  marker inside the attribute, and runs ending at `highest_vcn` when it is
  not 0.
- `$MFT` ([NTFS-3G] `ntfs_mft_load`): record 0, read where the boot sector
  points, must be a base record in use with a non-resident, uncompressed,
  unencrypted `$DATA` whose first run starts at `mft_lcn`. Its later
  extents may be in extension records, which are read through the runs
  known so far. The runs must be stored (no sparse run), must not overlap,
  must map `data_size`, and `$MFT` must hold at least 16 records. The root
  (record 5) must be a directory in use.
- At most 4,194,304 MFT records are walked (ours: 4 GiB of 1 KiB records);
  further ones are counted. Records past `initialized_size` are empty.
- Bytes of MFT records and attribute lists parsed are limited to 16 times
  the bytes of the volume present, at least 16 MiB (ours): a consistent
  volume parses each record about three times, while attribute lists that
  share clusters or name records repeatedly would otherwise make the walk
  unbounded. At the limit the walk stops and a note counts what was not
  indexed or examined.
- At most 4096 members are listed and 65,536 data streams examined. A
  member larger than 64 MiB is not extracted; extraction stops when the
  members reach 256 MiB in total. Notes count what was left out.
- Problems are listed in up to 16 notes; further problems are counted.

## Truncated volumes

Containers decode at most 64 MiB of a component (`MAX_PAYLOAD`): a
partition table, virtual disk or disk image hands on the first 64 MiB of a
larger NTFS partition. A volume whose `number_of_sectors` times
`bytes_per_sector` exceeds the bytes present is read as a truncated volume:

- Detection is unchanged: it needs only the boot sector.
- `$MFT`'s record 0 (and any extension record its attribute list names)
  and the root directory's record must be present; otherwise the volume is
  the error `Truncated volume: N sectors of S need T B, P B present`.
- Every cluster number is still checked against the declared volume; a
  defect inside the bytes present is an error or a note, as for a complete
  volume.
- A read past the end of the input is absent, never an error: MFT records
  past it are counted ("N MFT records lie past the X present and were not
  read"); a stream is listed only when all of its data is present, and
  streams or files whose data, attribute list or extension records lie past
  the end are counted. A directory whose attribute list is cut keeps the
  name its base record holds, so the paths below it are still built; a
  file whose parent directory's record is cut is counted, not listed as an
  orphan.
- `$Volume` and `$MFTMirr` past the end of the input are noted and not
  read.
- A note states "Volume truncated: X of Y present; files are listed only
  when all of their data is present".
- The whole input belongs to the volume (`consumed`).

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| N1 | The parent references of `$FILE_NAME` attributes name the same directories as the `$I30` indexes, so paths can be built without reading the indexes | Holds for the three ntfs-3g fixtures (every expected path in `tests/ntfs.rs`); 7-Zip 26.03 (`7zz l`, an independent reader) lists the file of every member path the parser reports for `ntfs.img` and `ntfs-512.img`. A volume whose index and parent references disagree (a chkdsk case) is not tested |
| N2 | The first name that is not a DOS alias, in attribute (list) order, is a sensible label for a file with hard links | `linked.exe` in `ntfs.img` is listed under its first listed name, a 200-character link; Windows-written link order not verified |
| N3 | Records 0 to 15 and everything below `$Extend` are system files with nothing to list | [LAYOUT] `NTFS_SYSTEM_FILES`; the fixtures' `$Extend` children (`$ObjId`, `$Quota`, `$Reparse`) are not listed. Records 16 to 23 are walked like user records |
| N4 | `$MFT` extension records name record 0 with a nonzero sequence number, so only a zero `base_mft_record` marks a base record | mkntfs gives `$MFT` sequence number 1 (`mkntfs.c`), and ntfs-3g writes `MK_LE_MREF(0, 1)` into `$MFT`'s extension records (`ntfs_mft_rec_alloc`), whose record part alone is 0. An `$MFT` extension record with a zero base reference would be read as a base record; not seen in a real volume |
| N5 | LZNT1 units decode as ntfs-3g decodes them (signature 3 required, short chunks zero-filled) | The ntfs-3g fixtures (written by ntfs-3g's compressor) decode to their inputs byte for byte with 4 KiB and 512 B clusters; data compressed by Windows `RtlCompressBuffer` is not tested |
| N6 | The update sequence stride is 512 B for every sector size | [LAYOUT] `NTFS_BLOCK_SIZE`; `ntfs-4k.img` (4096 B sectors, 4 KiB records, nine update sequence entries) parses |
| N7 | 16 times the bytes present is enough metadata reading for a consistent volume | The fixtures and synthetic volumes stay far below it; a synthetic volume whose 79 attribute lists share 256 KiB of clusters reaches it. Not tested on large real volumes |
| N8 | A truncated volume is a prefix of the whole volume | The sweep `prefixes_are_truncated_volumes_that_list_only_members_inside_them` checks every listed member of 7,585 prefixes of `ntfs.img` and 5,839 of each other fixture against the whole volume |
| N9 | The first 4 KiB decide whether a stream is a recognized format | As for the other filesystem families; a weak format that needs its whole input is not listed |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| `$I30` directory indexes (`$INDEX_ROOT`, `$INDEX_ALLOCATION`) | Not read; paths come from parent references (N1) |
| `$LogFile` | Not read or replayed; a dirty volume is noted |
| EFS-encrypted files | Not decrypted; counted |
| WOF (CompactOS) files: XPRESS4K/8K/16K and LZX in `WofCompressedData` | Not decoded; counted |
| Compression methods other than LZNT1, units other than 16 clusters, clusters above 4 KiB | Not decoded; counted per method and unit |
| Reparse points | Links counted, not followed; other tags noted, their data read as stored |
| Deleted files (records not in use) and slack space | Not read |
| Alternate data streams of the root directory, `$Extend` streams such as `$UsnJrnl:$J` | Not read |
| The backup boot sector of NT 3.51 (in the middle of the volume) | Not looked for |
| Boot code in `$Boot` | Not listed: `$Boot` starts with the volume's own boot sector |
| Volumes inside partition tables, VHDs or disk images | Reached as children of those families; a volume must start at the input's start |
| Volume shadow copies, `$Secure`, quotas, object IDs | Not read |
| Files over 64 MiB | Not extracted |

## Verification

On 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly `f248f4038`,
wasm-pack 0.14.0, Node 25.8.1): `tests/ntfs.rs` (29 tests), the 11 unit
tests in `src/formats/ntfs/` and the 9 LZNT1 unit tests in
`src/formats/compressed/lznt1.rs` passed, along with the rest of
`cargo test --all-features --locked` (2,673 passed, 6 ignored, none of them
NTFS tests). The integration tests use three ntfs-3g fixtures
(`tests/fixtures/ntfs/README.md`: 512 B sectors with 4 KiB clusters, 4096 B
sectors, 512 B clusters; resident, fragmented, sparse, LZNT1 and
attribute-list files, named streams, hard links, an Interix and a Windows
symbolic link, a deleted file, a fragmented `$MFT` in `ntfs-4k.img`) and
synthetic volumes built from the documented layout (`$DATA` extents in
extension records, an `$MFT` attribute list, records split across `$MFT`
runs, orphans, cycles, stale parent references and DOS aliases, 70-level
paths, encrypted, WOF, linked and dedup files, unsupported compression,
torn, `BAAD` and unknown records, damaged `$MFT` and root records, boot
sector field mutations, volume flags, the metadata read limit). They
include parses of 7,585 prefixes of `ntfs.img`, 5,839 of each other fixture
and 5,000 of the synthetic volume, mutations (`0x00`, `0xFF`, bit flip) of
the boot sector and MFT records of the synthetic volume and of two
fixtures, and every 997th byte of `ntfs-512.img` through the whole
classifier. `web/tests/ntfs.test.mjs` (6 tests) passed through `/pkg/` and
`/dist/` and in both workbench pages; the browser suite passed 304 of 308
tests with 4 skipped (D10 and RX113 firmware not in the repository).

The IDA Pro test inputs (`/Users/int/hexrays/ida/tests/input`, 7,371
files, scanned with `IDA_INPUT_DIR` set) hold no file with an NTFS boot
sector, and no NTFS image was found on this machine
(`ZRAX_NTFS_IMAGE` unset; the test skips), so no volume written by Windows
was tested. Not verified: volumes written by Windows (cluster allocation,
`$MFT` extension records, compression by `RtlCompressBuffer`), NTFS 1.2 and
3.0 volumes, 256 B sectors, clusters above 64 KiB, very large volumes and
the record and stream limits.

After integration on the same day, the native suite passed 2,677 tests
with 6 ignored, and IDA's corpus (4,621 files, no NTFS volumes) classified
as before.
