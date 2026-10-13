# HFS+ and HFSX volumes

`src/formats/hfsplus.rs` and its submodules read HFS Plus and HFSX volumes,
read-only, into the shared container model
([compressed streams and the container model](compressed-streams.md)). The
reader checks the volume header (or the HFS wrapper around it), opens the
extents overflow, catalog and attributes B-trees, walks the catalog from the
root folder, resolves hard links, decodes decmpfs (`AppleFSCompression`)
files, and lists each regular file whose first bytes are a recognized format
as a child labelled with its path. Each member is then classified from its
own bytes. The volume names no processor.

| Submodule | Contents |
| --- | --- |
| `hfsplus.rs` | Layouts, bounds-checked readers, placement in the input (plain or wrapped), size and trailing-data checks, B-tree opening, node read budget, journal notes, summary notes and metadata |
| `hfsplus/header.rs` | Volume header and its detection checks, fork data and extent records, HFS master directory block of a wrapper |
| `hfsplus/fork.rs` | Fork extents from the fork data record and the extents overflow B-tree, reads of fork bytes (borrowed from one run or reassembled) |
| `hfsplus/btree.rs` | Header node, node descriptor and record offset checks, keyed records, the `SearchTree` descent, leaf-chain cursor, extent key lookup |
| `hfsplus/catalog.rs` | Catalog keys, folder, file and thread records, exported names, enumeration of a folder's children |
| `hfsplus/decmpfs.rs` | `com.apple.decmpfs` attribute lookup, decmpfs header, chunk tables, decoding through `compressed::decode_limited` |
| `hfsplus/walk.rs` | Catalog walk, metadata folders, hard and directory links, member extraction and limits, startup file, notes |

## Implemented layouts

| JSON format ID | Variant | Layout | Architecture evidence | Primary source |
| --- | --- | --- | --- | --- |
| `hfsplus` | `HFS+` | Volume header `H+` version 4 at file offset 1024 | None. No field names a processor; members are classified from their own bytes | Apple Technical Note TN1150 "HFS Plus Volume Format" (2004-03-05 revision, <https://developer.apple.com/library/archive/technotes/tn/tn1150.html>, SHA-256 `fd1ca22de7ec38c044bcc726b5bc14b5b0ee63f1b242039f8bc4f3728e247cb5`); apple-oss-distributions/hfs tag `hfs-715.120.4`: `core/hfs_format.h`, `core/BTreesPrivate.h`, `core/BTreeTreeOps.c`, `core/hfs_catalog.c`, `core/hfs_catalog.h` |
| `hfsx` | `HFSX` | Volume header `HX` version 5 at 1024; case-sensitive or case-insensitive names by the catalog's `keyCompareType` | None | TN1150 "HFSX"; `hfs_format.h` |
| `hfsplus` | `HFS+ in an HFS wrapper` | HFS master directory block `BD` at 1024 with `drEmbedSigWord` `H+`; the volume header at `drAlBlSt * 512 + drEmbedExtent.startBlock * drAlBlkSiz` | None | TN1150 "HFS Wrapper"; `hfs_format.h` `HFSMasterDirectoryBlock` |

decmpfs compression, which the closed-source AppleFSCompression defines, is
taken from xnu tag `xnu-11215.1.10` (`bsd/sys/decmpfs.h`,
`bsd/kern/decmpfs.c`: the header, `MAX_DECMPFS_XATTR_SIZE` and type 1) and
from three open-source readers that agree on the other types: The Sleuth Kit
`sleuthkit-4.12.1` (`tsk/fs/decmpfs.h`, `tsk/fs/decmpfs.c`), libyal/libfshfs
commit `78321de1eda54b30261adf59b938781128591b2e` ("Hierarchical File System
(HFS).asciidoc") and sgan81/apfs-fuse commit
`66b86bd525e8cb90f9012543be89b1f092b75cf3` (`ApfsLib/Decmpfs.cpp`).

| decmpfs type | Stored | Codec | Decoded |
| --- | --- | --- | --- |
| 1 | After the header in the attribute | None (the data itself; the attribute is 16 B plus the file size, as xnu checks) | Yes |
| 3 | After the header in the attribute | zlib; a first byte whose low nibble is `0xF` marks stored data | Yes |
| 4 | Resource fork: block table at the Resource Manager `dataOffset` + 4 | zlib per 64 KiB chunk; the same stored marker | Yes |
| 7 | After the header in the attribute | LZVN; a first byte `0x06` marks stored data | Yes |
| 8 | Resource fork: little-endian offset table at 0 | LZVN per 64 KiB chunk; the same stored marker | Yes |
| 11 | After the header in the attribute | LZFSE | Yes |
| 12 | Resource fork: offset table at 0 | LZFSE per 64 KiB chunk | Yes |
| 5, 9, 10, 13, 14, `0x80000001`, `0x80000002` | | sparse, raw (`0xCC`), LZBITMAP, dataless | No; counted in a note |

zlib and LZFSE use the existing codecs. Raw LZVN streams (no block header)
are decoded by `compressed::Codec::Lzvn`, added for this family: the stream
is framed as one `bvxn` block for the LZFSE decoder, as `complzvn`
kernelcache payloads already were.

## Detection

Detection is strong. It runs after the other magic-bearing container
families (it follows the Nintendo 3DS and Switch check) and before the
magic-bearing compressed streams. The first 1024 bytes of a volume are boot
blocks, so formats that start at offset 0 are checked first, and the
partition-table, ISO 9660 and disc checks keep describing whole disks whose
partitions hold HFS+ volumes.

The signature and version are 32 bits, so detection also requires a
consistent volume header:

- `H+` with version 4, or `HX` with version 5 or later (a later HFSX version
  is detected and then refused, as TN1150 requires);
- `blockSize` a power of two of at least 512;
- `totalBlocks` nonzero and `freeBlocks` at most `totalBlocks`;
- non-empty catalog and extents overflow files whose first extent has
  blocks, whose eight inline extents lie inside the volume, and whose
  logical size does not exceed the volume.

A wrapper is detected when the master directory block has `BD` and an
embedded `H+`, `drAlBlkSiz` is a nonzero multiple of 512, the embedded extent
lies inside `drNmAlBlks`, and the embedded volume header passes the checks
above. Detection reads 512 B at 1024 (and, for a wrapper, at the embedded
volume), so `container::is_recognized` finds a plain volume from a 4 KiB
member prefix. The volume size, the B-trees and the files are checked when
the container is parsed, so a damaged volume with a consistent header is a
parse error, not raw code.

## Wire units and byte order

All volume structures are big-endian. decmpfs headers, the zlib block table
entries and the LZVN and LZFSE offset tables are little-endian; the Resource
Manager header of a type 4 fork is big-endian. The journal header is in the
byte order of the host that wrote it and is read in the order its
`ENDIAN_MAGIC` gives (the fixture's is little-endian).

Allocation block numbers count blocks of `blockSize` bytes from the start of
the volume; a wrapped volume starts at its embedded offset. B-tree node `N`
is at fork offset `N * nodeSize`. Offsets in notes, metadata and members are
file bytes.

A member stored in one extent is borrowed from the image: its offset and size
are the stored bytes. A member in several extents is reassembled; its slice
gives the file offset and size of its first stored run, and its decoded range
the whole file, with the transform `HFS+ extents`. A decmpfs member's slice
gives the stored compressed bytes (the data after the header in the
attribute, or the resource fork's first run) and its decoded range the
decoded file, with the transform `decmpfs zlib`, `decmpfs LZVN`, `decmpfs
LZFSE` or `decmpfs attribute data` (type 1).

## Members

- The walk starts at the root folder (CNID 2). The root's thread record
  (keyed CNID 2 and an empty name) and the root folder record (keyed parent 1)
  must exist; otherwise the volume is a parse error.
- A folder's children are the catalog records keyed with its CNID as parent.
  They are read in key order from its thread record, which a search finds
  without comparing names (an empty name sorts first), and the leaf chain is
  followed until a record of another parent. Subfolders are walked depth
  first in key order, after the folder's files.
- Names are exported as macOS exports them: U+0000 as U+2400 and `/` as `:`.
  Paths join the exported names with `/`.
- The file metadata folder (four U+0000 characters and `HFS+ Private Data`)
  and the directory metadata folder (`.HFS+ Private Directory Data` and a
  carriage return) in the root are not walked directly.
- File hard links (`hlnk`/`hfs+`) and directory hard links (link chain flag,
  `fdrp`/`MACS`, reference of at least 16) are resolved, as `cat_lookupbykey`
  resolves them, only when the link's creation date equals the root's or a
  metadata folder's. A file link leads to `iNode<ref>` in the file metadata
  folder; that file is examined once, under the path of the first link the
  walk meets. A directory link leads to `dir_<ref>` in the directory metadata
  folder, which is walked under the link's path. Further links to an examined
  file or folder are counted.
- Symbolic links (`S_IFLNK`) are counted, not followed. Devices, FIFOs and
  sockets are counted, not read. A file mode of 0 (permissions never
  initialized) is read as a regular file, as TN1150 describes.
- A regular file's data fork is read through its extents and the extents
  overflow records. Its first 4 KiB (or the whole file, if smaller) go to
  `container::is_recognized`; only recognized files are extracted and listed
  (`Classify::IfRecognized`).
- A file with `UF_COMPRESSED` in `ownerFlags` is a decmpfs file, as xnu's
  `decmpfs_file_is_compressed` decides. Its `com.apple.decmpfs` attribute is
  looked up in the attributes B-tree; the first chunk is decoded for the
  recognition check and the whole file only if it is listed.
- The startup file, if the volume has one, is listed last as `Startup file`
  when it starts with a recognized format.

## Checksums and authentication

HFS+ volume metadata has no checksums. The journal header and block list
checksums are not verified, and the journal is never replayed. The codecs'
own checks are verified: the zlib Adler-32 of each zlib unit, and the LZFSE
and LZVN stream structure, with each unit's decoded size checked against the
size decmpfs states.

## Validation and resource bounds

- A volume of `totalBlocks` blocks that the input holds may be followed by
  bytes shorter than one block (the remainder of a disk that is not a
  multiple of the block size, where the alternate volume header lies) or by
  `0x00`/`0xFF` padding; other trailing bytes are a parse error. A volume
  larger than the input is read as a truncated volume (see below). In a
  wrapper, the volume must fit the embedded extent.
- An HFSX version other than 5 is refused.
- B-tree headers: header node kind 1, height 0 and at least three records;
  `nodeSize` a power of two from 512 B (4 KiB for the catalog and attributes
  B-trees) to 32 KiB; `btreeType` 0; `kBTBigKeysMask` set; `totalNodes`
  nodes fit the fork; `treeDepth` at most 16 (`kMaxTreeDepth`) and zero
  exactly when `rootNode` is zero; `rootNode` below `totalNodes`;
  `maxKeyLength` fits a node. A damaged header is a parse error.
- Nodes: number below `totalNodes`; a known kind; `numRecords + 1` record
  offsets starting at 14, strictly increasing and ending before the offset
  table; each key within its record.
- Searches follow `SearchTree`: node 0 is never in the path, each node's
  height equals its level, level 1 holds leaves and the others index nodes,
  so a search reads at most 16 nodes. A leaf-chain walk reads each leaf once;
  a chain that returns to a leaf, or leads to a node that is not a leaf, is an
  error for that folder.
- Fork extents must lie in the volume. Extents overflow records continue a
  fork at the block count covered so far and must add blocks; a missing record
  skips the file with a note.
- decmpfs: the attribute is 16 B to 3,802 B (`MAX_DECMPFS_XATTR_SIZE`) with
  the `cmpf` magic; the chunk count must be the size in 64 KiB units; chunk
  tables must lie in the fork; chunks are at most 65,537 B; each unit must
  decode to exactly its size. An attribute stored in extents
  (`kHFSPlusAttrForkData`) is not supported.
- B-tree node reads are limited to 64 times the volume size (for a truncated
  volume, 64 times the bytes present), because every search reads one node
  per level; when the limit is reached the walk stops and a note counts the
  folders not walked. The factor is ours.
- Folders deeper than 64 levels below the root are not walked. Each folder is
  walked once.
- At most 4096 members are listed and 65,536 regular files examined. A
  metadata folder is indexed up to 65,536 entries.
- A member larger than 64 MiB is not extracted (for decmpfs files, a decoded
  size or resource fork above 64 MiB); extraction stops when the members
  reach 256 MiB in total. Notes count what was left out.
- Problems below the root are listed in up to 16 notes; further problems are
  counted.

## Truncated volumes

Containers decode at most 64 MiB of a component (`MAX_PAYLOAD`): the DMG
family hands on the first 64 MiB of a larger `Apple_HFS` partition, and
virtual disks and compressed streams do the same. A volume whose
`totalBlocks` times `blockSize` ([TN1150] "Volume Header") exceeds the bytes
present is read as a truncated volume:

- Detection is unchanged: it needs only the volume header.
- The structures needed before anything can be listed must be present: the
  volume header, the header nodes of the extents overflow, catalog and (if
  any) attributes B-trees, the extents overflow nodes that locate the
  catalog's and attributes file's extents, and the catalog nodes that hold
  the root folder's thread and folder records. Without them the volume is
  the error it was before: `Truncated volume: N blocks of B need S B, P B
  present` (or `Truncated HFS wrapper: ...` for a wrapper whose embedded
  extent passes the end of the input).
- Every block, extent and node number is still checked against the
  declared volume; a defect inside the bytes present is an error or a note,
  as for a complete volume.
- A read past the end of the input is absent, never an error: B-tree nodes
  past it are skipped (a folder's enumeration stops at the first absent
  leaf), and a note counts them per tree: "N nodes of the catalog B-tree
  that the walk needed lie past the X present; their records were not
  read".
- A regular file is listed only when all of its data fork (or, for decmpfs,
  its resource fork) is present, together with the extents overflow and
  attributes records that locate it. Others are counted: "N regular files
  were not listed: file data, or B-tree records that locate it, lie partly
  or wholly past the X present". A decmpfs file whose resource fork is
  absent is not counted as decoded.
- Hard links whose indirect node folder was cut count as absent files, not
  as broken links.
- A journal or startup file past the end of the input is noted ("the
  journal lies past the X present and was not read").
- A note states "Volume truncated: X of Y present; files are listed only
  when all of their data is present", with X and Y in B, KiB or MiB.
- The whole input belongs to the volume (`consumed`).

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| H1 | A folder's records follow its thread record contiguously in leaf order | Holds for both macOS fixtures (catalog depths 1 and 2); a synthetic catalog split over nine leaves under an index root is walked completely (`catalogs_with_index_nodes_are_searched_and_damage_is_noted`) |
| H2 | An empty name sorts before every other name, so the search needs no Unicode comparison | TN1150 "Catalog Tree Usage" and the binary order of HFSX; both fixtures (case-folding and binary) find every folder's records |
| H3 | Attribute keys sort by `fileID` first | TN1150 marks the attributes key "not finalized"; `hfs_format.h` defines the layout read here, and the fixtures' attributes are found |
| H4 | `UF_COMPRESSED` marks a decmpfs file | xnu `decmpfs_file_is_compressed`; the fixtures' compressed files have it (`ownerFlags` 0x20) and the others do not |
| H5 | decmpfs types 3, 4, 11 and 12 are laid out as TSK, libfshfs and apfs-fuse read them | Only types 7 and 8 come from macOS (`ditto --hfsCompression` on macOS 27.2 writes LZVN); 1, 3, 4, 11 and 12 are synthetic in `tests/hfsplus.rs`. Not verified against files macOS wrote |
| H6 | An LZFSE unit has no stored-data marker | apfs-fuse says it does not know; libfshfs describes a `0xFF` marker for resource fork chunks. Not implemented: such a chunk fails to decode and the file is skipped with a note |
| H7 | Hard links resolve only with the root's or a metadata folder's creation date | `cat_lookupbykey`; the fixture's links carry the metadata folder's date |
| H8 | The first 4 KiB decide whether a file is a recognized format | As for the other filesystem families; a weak format that needs its whole input is not listed |
| H9 | 64 times the volume size is enough node reading for a consistent volume | Both fixtures and all synthetic volumes walk without reaching it; not tested on large real volumes |
| H10 | A truncated volume is a prefix of the whole volume, so what lies in the bytes present is what the whole volume holds there | The Xcode tools DMG's `Apple_HFS` partition read whole (191,931,904 B through `hdiutil attach -readonly -nomount`) lists 41 members; its first 64 MiB list 4, byte-identical to theirs in the whole, and the 37 others start at 0x8139000 or later. The sweep `prefixes_are_truncated_volumes_that_list_only_members_inside_them` checks every listed member of a prefix against the whole fixture |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Classic HFS (`BD` without an embedded `H+`) | Not detected |
| A volume larger than the bytes given, including a volume that a container cut at the 64 MiB extraction limit (for example the `Apple_HFS` partition of a DMG larger than 64 MiB) | Read as a truncated volume when its B-tree header nodes and root folder are present: files whose data lies in the bytes present are listed, the rest are counted. Files and folders whose catalog records lie past the end are not known; their number is not reported, only the B-tree nodes the walk asked for |
| A truncated volume whose catalog or attributes file continues in extents overflow nodes past the end of the input | The extents cannot be resolved: the "Truncated volume" parse error |
| The wrapper's own HFS files | Not read; noted |
| Journal | Located and its header read; never replayed. Transactions are noted as possibly stale metadata |
| decmpfs types 5, 9, 10, 13, 14 and dataless files | Not decoded; counted in a note |
| decmpfs attribute stored in extents | Not supported; the file is skipped with a note |
| Resource forks of uncompressed files, named forks, other extended attributes | Not read |
| Alternate volume header | Not read or compared |
| Allocation bitmap, `freeBlocks`, `fileCount`, `folderCount`, `nextCatalogID` | Not checked against the catalog |
| Content protection (`kHFSContentProtectionBit`, per-file keys) | Not detected; encrypted data would be read as stored |
| Partition maps, disk images | Handled by their own families (APM, GPT); a volume must start at the input's start or be wrapped |
| Files over 64 MiB | Not extracted |

## Verification

On 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly), `tests/hfsplus.rs`
(24 tests), the 10 unit tests in `src/formats/hfsplus/` and the raw LZVN unit
test in `src/formats/compressed/lzss.rs` passed, along with the rest of
`cargo test --all-features --locked` (2,277 passed, 6 ignored, none of them
HFS+ tests). The integration tests use two macOS fixtures
(`tests/fixtures/hfsplus/README.md`: a journaled HFS+ volume with hard and
symbolic links, LZVN decmpfs files in the attribute and the resource fork and
a file continued in the extents overflow file; a case-sensitive HFSX volume
with 512 B blocks) and synthetic volumes built from the TN1150 layouts (HFS
wrapper, decmpfs types 1, 3, 4, 11 and 12, unsupported types, a catalog of
nine leaves under an index root, leaf-chain cycles, wrong node heights, record
offsets out of order, depth limits). They include a parse of every prefix of
both fixtures, mutations (`0x00`, `0xFF`, bit flip) of every volume header
byte, the first 120 B of each B-tree header node and every third byte of the
used B-tree nodes, every 997th byte of the journaled fixture through the
whole classifier, and every seventh stored byte of its decoded members.
`web/tests/hfsplus.test.mjs` (4 tests) passed through `/pkg/` and `/dist/`
and in both workbench pages.

A local volume that is not committed (300 MiB, journaled, 300 plain copies
of `/usr/bin` files written with `ditto --hfsCompression`, a hard link and a
file seven folders deep) listed the 213 Mach-O files the copies hold, 212 of
them decoded from LZVN resource forks, in 0.3 s. The IDA Pro test inputs
(`/Users/int/hexrays/ida/tests/input`) hold no file with an HFS+, HFSX or HFS
signature at offset 1024, so no third-party volume was tested.

Not verified: decmpfs types 1, 3, 4, 11 and 12 written by macOS (only LZVN
could be produced locally), volumes written by other implementations (Linux
`mkfs.hfsplus`, Mac OS 9), real HFS wrappers, directory hard links (Time
Machine), volumes with more than one catalog extent, the startup file, the
node read limit, and journals with transactions other than the edited
fixture.

At integration on the same day the fixtures were recompressed with
`gzip -9 -n` (1,572,864 B of volumes in 9,708 B of files; the tests
decompress them), the native suite passed 2,351 tests with 6 ignored, and
IDA's corpus (4,621 files) classified as before. A downloaded Xcode tools
DMG whose `Apple_HFS` partition is 183 MiB was cut at 64 MiB by the DMG
family, and this parser reported the cut volume as truncated.

Truncated volumes, on 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly
`f248f4038`, wasm-pack 0.14.0, Node 25.8.1): `tests/hfsplus.rs` (28 tests)
and the 10 unit tests in `src/formats/hfsplus/` passed within `cargo test
--all-features --locked` (2,425 passed, 6 ignored). The prefix sweep now
parses every prefix of both fixtures up to the end of the catalog file and,
after it, every 61st prefix and the prefixes at and around each 512 B
boundary: each prefix is either the old "Truncated volume" error (before the
catalog's root nodes) or a truncated volume whose members are byte-identical
to the whole volume's and lie inside the prefix. A synthetic catalog with a
leaf moved to the last block, a journal moved past the cut, a truncated HFS
wrapper and the cut fixtures cover the notes. `web/tests/hfsplus.test.mjs`
(6 tests, one of them a 768 KiB prefix) passed through `/pkg/` and `/dist/`;
the browser suite passed 278 tests with 4 skipped (D10 and RX113 firmware
not in the repository). A differential snapshot against the previous commit
over both fixtures (2,275,040 inputs: the whole volumes, every prefix and
single-byte mutations of every 7th byte and every 3rd of the first 16 KiB)
changed 796,680 outcomes, all of inputs whose `totalBlocks` times
`blockSize` exceeds the input: old "Truncated volume" errors that are now
truncated volumes (prefixes, and 8 mutations of the high byte of
`totalBlocks`). Seven DMG fixtures with HFS+ and FAT partitions (324,858
inputs) did not change.

`Additional_Tools_for_Xcode_26.2.dmg` (87,179,210 B, read in place; not
committed): the HFS+ volume of its `Apple_HFS` partition (46,858 blocks of
4 KiB, 191,930,368 B) is cut at 64 MiB; the cut volume lists 4 members (two universal Mach-O binaries, `HAPAccessoryKit`
and `HomeKit Accessory Simulator`, decoded from zlib decmpfs resource forks,
and two gzip files) and counts 615 regular files whose data lies past
64 MiB; the disk image's primary ISA is now x86-64 instead of unknown. The
whole partition, read through `hdiutil attach -readonly -nomount`, lists 41
members; the 4 are byte-identical to theirs there and the 37 others start
at 0x8139000 or later. The test
`a_local_dmg_lists_the_files_in_the_first_64_mib_of_its_cut_volume` runs on
it when `ZRAX_LOCAL_DMG` names the file (skipped otherwise). The IDA Pro
test inputs hold no HFS+ volume (not verified on third-party volumes).
