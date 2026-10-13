# APFS containers

`src/formats/apfs.rs` and its submodules read APFS containers, read-only,
into the shared container model
([compressed streams and the container model](compressed-streams.md)). The
reader checks the container superblock in block 0, picks the latest
checkpoint whose superblock checksum verifies, opens the container object
map, reads each volume superblock, and walks the file-system tree of every
unencrypted, unsealed volume from its root directory. Each regular file
whose first bytes are a recognized format is a child labelled
`/<volume name>/<path>`; decmpfs (`AppleFSCompression`) files are decoded
first. Encrypted volumes are listed as opaque children, and the EFI driver
of the EFI jumpstart, when the container has one, last. Each member is then
classified from its own bytes. The container names no processor.

| Submodule | Contents |
| --- | --- |
| `apfs.rs` | Layout, detection, bounds-checked little-endian readers, parse entry point (block 0, trailing data, notes and metadata) |
| `apfs/object.rs` | Fletcher-64, object headers, block reads that tell a cut-off container from an address beyond it, the object read budget |
| `apfs/superblock.rs` | `nx_superblock_t`, the checkpoint descriptor scan, feature notes, the EFI jumpstart driver |
| `apfs/omap.rs` | `omap_phys_t`, object map lookups by identifier and transaction |
| `apfs/btree.rs` | `btree_node_phys_t` and `btree_info_t`, fixed and variable tables of contents, node checks, seek and leaf cursor |
| `apfs/volume.rs` | `apfs_superblock_t`: name, role, flags, features, counts |
| `apfs/records.rs` | `j_key_t`, inode, directory entry, extended attribute and file extent records, extended fields |
| `apfs/walk.rs` | Volume lookup, directory walk, data stream reads, the `com.apple.decmpfs` and `com.apple.ResourceFork` attributes, member extraction and limits, notes |
| `formats/decmpfs.rs` (shared with HFS+) | decmpfs header, compression types, chunk tables of the resource fork, decoding through `compressed::decode_limited`; APFS supplies its error variant, reads and checks through `decmpfs::Family` |

## Implemented layouts

| JSON format ID | Variant | Layout | Architecture evidence | Primary source |
| --- | --- | --- | --- | --- |
| `apfs` | `APFS container` | An APFS container from offset 0: `nx_superblock_t` in block 0, checkpoints, object maps, volumes, file-system trees | None. No container or volume field names a processor; members are classified from their own bytes | Apple, "Apple File System Reference", revision of 2020-06-22 (<https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf>, SHA-256 `74c3db584971aea2b11549ca25799ead824e1bd8994e94cd3f8665ce5aea79cc`): "Objects", "EFI Jumpstart", "Container", "Object Maps", "Volumes", "File-System Objects", "File-System Constants", "Data Streams", "Extended Fields", "B-Trees", "Encryption", "Sealed Volumes" |

The reference leaves some details open; they are taken from two
open-source readers, which agree where both cover them:

| Source | Pin | Used for |
| --- | --- | --- |
| sgan81/apfs-fuse | commit `66b86bd525e8cb90f9012543be89b1f092b75cf3`: `ApfsLib/Util.cpp` (SHA-256 `58bff1e2e5b2ff3ebfed3693eb1a50e443f715deaf85a959a17e2846170b2052`), `ApfsContainer.cpp` (`fab00f415ce643da3ce65581ff765fe5730f6c93696207a71d72d9d3b62fd563`), `ApfsVolume.cpp` (`31ad91fd7e0662aa9ff724188217143ab88b7a865c08160f8ee1168412cf06fd`), `BTree.cpp` (`48fe216685f0722949e0131d96735e8f6e1ac76cc609e5902940d7a78dbefb2c`), `ApfsDir.cpp` (`fff36ac15715a6206f2189563e8329c1203c72ded5d691bc2cb29f858c46c5f6`), `Decmpfs.cpp` (`f9b16053d9bc095af35fd022fd51b04c794144ca726fd913538db7fcc1bed58b`) | The Fletcher-64 algorithm and the rejection of all-zero and all-one checksums, the scan of the whole checkpoint descriptor area, the volume's own transaction for its lookups, the fixed index-entry value size, the choice of hashed directory keys, holes, decmpfs types and chunk tables |
| libyal/libfsapfs | commit `cc122619a0fa5cecf7c077742ac62251fb85fb6c`: `libfsapfs/libfsapfs_checksum.c`, `fsapfs_container_superblock.h`, `fsapfs_volume_superblock.h`, `fsapfs_object_map.h`, `libfsapfs_container_superblock.c` | Fletcher-64 (same result), the structure offsets, the container superblock type `0x80000001` |
| apple-oss-distributions/xnu | tag `xnu-11215.1.10`: `bsd/sys/decmpfs.h`, `bsd/sys/xattr.h`, `bsd/sys/stat.h` | `decmpfs_disk_header`, `DECMPFS_XATTR_NAME`, `CMP_Type1`, the dataless types, `XATTR_RESOURCEFORK_NAME`, `UF_COMPRESSED` |

decmpfs types, decoded by `src/formats/decmpfs.rs`, which the HFS+ family
uses too (see [HFS+ and HFSX volumes, "The shared decmpfs
decoder"](hfsplus.md#the-shared-decmpfs-decoder) for the checks in which the
two families still differ):

| Type | Stored | Codec | Decoded |
| --- | --- | --- | --- |
| 1 | After the header in `com.apple.decmpfs` | None (the data itself) | Yes |
| 9 | After the header | None: a `0xCC` marker byte, then the data itself (apfs-fuse "Uncompressed, Attr") | Yes |
| 3 | After the header | zlib; a first byte whose low nibble is `0xF` marks stored data | Yes |
| 4 | `com.apple.ResourceFork`: block table at the Resource Manager `dataOffset` + 4 | zlib per 64 KiB chunk; the same stored marker | Yes |
| 7 | After the header | LZVN (`compressed::Codec::Lzvn`); a first byte `0x06` marks stored data | Yes |
| 8 | `com.apple.ResourceFork`: little-endian offset table at 0 | LZVN per 64 KiB chunk; the same stored marker | Yes |
| 11 | After the header | LZFSE | Yes |
| 12 | `com.apple.ResourceFork`: offset table at 0 | LZFSE per 64 KiB chunk | Yes |
| Others (5, 10, 13, 14, `0x80000001`, `0x80000002`, ...) | | sparse, uncompressed resource fork, LZBITMAP, dataless | No; counted in a note |

Either attribute may be embedded in its record (`XATTR_DATA_EMBEDDED`) or
stored as a data stream (`XATTR_DATA_STREAM`), whose extents are keyed by
the stream's identifier. macOS 27.2 writes both forms: `ditto
--hfsCompression` stored a 300 B type 7 `com.apple.decmpfs` attribute as a
stream, and type 8 headers embedded with the resource fork as a stream.

## Detection

Detection is strong and reads 48 bytes: `NXSB` at 32 (`NX_MAGIC`), `o_oid`
1 (`OID_NX_SUPERBLOCK`) at 8, `o_type` `0x80000001` (`OBJ_EPHEMERAL |
OBJECT_TYPE_NX_SUPERBLOCK`) at 24, `nx_block_size` at 36 a power of two
from 4096 to 65,536 (`NX_MINIMUM_BLOCK_SIZE`, `NX_MAXIMUM_BLOCK_SIZE`), and
`nx_block_count` at 40 such that the container holds at least 1 MiB
(`NX_MINIMUM_CONTAINER_SIZE`) without overflowing 64 bits. The checksum is
not part of detection, so a damaged block 0 is a parse error rather than raw
code.

The check runs in `detect_format` after the firmware package wrappers and
before the magic-bearing compressed streams. Block 0 starts with the
superblock's checksum, which no earlier family keys on in practice; the
offsets that earlier families probe inside a container (the MBR signature at
510, `H+` and EROFS at 1024, ext at 0x438, GPT at 512 or 4096, ISO 9660 at
0x8001) hold `nx_fs_oid` slots and counters, which are zero in containers,
or later blocks, which are checksummed objects. All three fixtures reach the
APFS check through `detect_format`. A container in a GPT partition (type
`7C3457EF-0000-11AA-AA11-00306543ECAC`) or in an Apple disk image's
`Apple_APFS` partition is reached as a child of the partition table or disk
image and classified on its own.

## Wire units and byte order

Every integer is little-endian. Block numbers (`paddr_t`, physical object
identifiers, extent starts) count blocks of `nx_block_size` bytes from the
start of the container. Virtual object identifiers are resolved through an
object map as of a transaction: the container's map with the checkpoint's
`o_xid`, a volume's map with the volume superblock's `o_xid`. File extent
offsets and lengths are bytes. Offsets in notes, metadata and members are
file bytes.

A member stored in one extent is borrowed from the input: its offset and
size are the stored bytes. A member in several extents or with hole extents
is reassembled; its slice gives the file offset and size of its first stored
extent, and its decoded range the whole file, with the transform `APFS
extents`. A decmpfs member's slice gives the stored compressed bytes (after
the 16-byte header in `com.apple.decmpfs`, or the first run of
`com.apple.ResourceFork`) and its decoded range the decoded file, with the
transform `decmpfs zlib`, `decmpfs LZVN`, `decmpfs LZFSE`, `decmpfs raw`
(type 9) or `decmpfs attribute data` (type 1). The EFI driver is stored or
reassembled the same way (`APFS EFI jumpstart extents`).

## Checkpoints and objects

- Block 0 must hold a whole block. Its superblock locates the checkpoint
  descriptor area (`nx_xp_desc_base`, `nx_xp_desc_blocks`), whose present
  blocks are all read, as apfs-fuse reads them: zero blocks are skipped, and
  a block counts only if its Fletcher-64 checksum verifies, its type is
  `OBJECT_TYPE_NX_SUPERBLOCK` with identifier 1, its magic and geometry are
  valid and its block size and count equal block 0's. The one with the
  largest `o_xid` is used; without one, block 0 is used if its own checksum
  verifies; otherwise the container is a parse error. A descriptor area
  that is not contiguous (the high bit of `nx_xp_desc_blocks`, a B-tree of
  fragments) is not read; block 0 is used and the fact noted.
- Every object is read from one block, its checksum verified once per
  block, and its `o_oid` compared with the identifier asked for. Object map
  values must not be deleted, encrypted or headerless, and must be one block
  long.
- B-tree nodes: the type is `OBJECT_TYPE_BTREE` for the root and
  `OBJECT_TYPE_BTREE_NODE` otherwise, with the tree's subtype; the root and
  leaf flags agree with the position and level; hashed and headerless nodes
  and trees, and ephemeral trees, are not supported; `bt_node_size` must
  equal the block size; the table of contents fits its space; every key
  lies in the key area and every value in the value area; keys do not
  decrease within a node or along the leaves. Fixed entries (`kvoff_t`) take
  `bt_key_size` and, in leaves, `bt_val_size`, and 8-byte child identifiers
  in index nodes.
- The object map tree must be physical with 16-byte keys and values. A file
  system tree's children are virtual unless `BTREE_PHYSICAL` is set; its
  root is virtual unless `apfs_root_tree_type` says physical.

## Members

- Volumes are the non-zero `nx_fs_oid` entries (at most
  `nx_max_file_systems`, at most 100). A volume superblock must have type
  `OBJECT_TYPE_FS` and `APSB`.
- An encrypted volume (`APFS_FS_UNENCRYPTED` clear) is listed as an opaque
  child labelled `/<name>`: its superblock block. Its tree and files are
  never read. If every child is opaque, the container is opaque.
- A sealed volume (`APFS_INCOMPAT_SEALED_VOLUME`, or integrity metadata or a
  file extent tree) is noted and not walked: its file extents are in the
  file extent tree, which is not read. A volume with incompatible features
  this reader does not know is noted and not walked.
- Snapshots (`apfs_num_snapshots`, `om_snap_count`) are noted, never read.
- The walk starts at `ROOT_DIR_INO_NUM` (2). A directory's entries are its
  `APFS_TYPE_DIR_REC` records, read from the first key of that object and
  type; hashed keys (`j_drec_hashed_key_t`) are used on case- or
  normalization-insensitive volumes, plain keys (`j_drec_key_t`) otherwise.
  Entries are walked in name order; subdirectories depth first after the
  directory's files. A `/` in a name is shown as `:`.
- A regular file's records are those of its inode number from
  `APFS_TYPE_INODE` to `APFS_TYPE_FILE_EXTENT`: the inode (with the size
  from `INO_EXT_TYPE_DSTREAM`), its `com.apple.decmpfs` and
  `com.apple.ResourceFork` attributes, and the extents of its `private_id`
  (searched separately when it is not the inode number, as for clones).
  Extents must cover the bytes read contiguously; extent block 0 is a hole
  and reads as zeros.
- A file is examined once, however many hard links lead to it, under the
  first path the walk meets; further links are counted. Symbolic links are
  counted, not followed; devices, FIFOs, sockets and whiteouts are counted.
  An entry of unknown type takes its type from the inode's mode.
- The first 4 KiB of a file (decoded first for decmpfs files) go to
  `container::is_recognized`; only recognized files are extracted and
  listed (`Classify::IfRecognized`).
- `UF_COMPRESSED` in `bsd_flags` marks a decmpfs file.
- The EFI jumpstart (`nx_efi_jumpstart`): `JSDR`, version 1, a driver
  length of at most 64 MiB and extents that fit the block; the driver is
  listed last as `EFI jumpstart driver` (`Classify::Always`).

## Checksums and authentication

Every object read is verified with Fletcher-64 before it is used. File data
has no checksums; the codecs' own checks apply (zlib Adler-32, LZFSE and
LZVN structure, each unit's decoded size). Keybags are noted, never
unwrapped, and nothing is decrypted. Sealed-volume hashes are not read or
verified.

## Validation and resource bounds

- Bytes after the container are accepted when they are shorter than one
  block or are `0x00`/`0xFF` padding; otherwise the container is a parse
  error. A container shorter than `nx_block_count` blocks is parsed as far
  as its bytes go: each read of a block that is not present fails with
  "Truncated container", is noted, and is counted.
- Object reads are limited to 64 times the number of blocks present (the
  factor is ours); at the limit the walk stops and a note counts the
  directories not walked. Checksums are verified once per block, and at
  most 65,536 object map lookups are cached per map.
- B-trees have at most 16 levels; every child must be exactly one level
  below its parent, so a descent cannot cycle; an index node must have
  entries.
- Directories deeper than 64 levels are not walked; each directory is
  walked once. At most 262,144 entries are read from one directory and
  65,536 extents from one stream.
- At most 4096 members are listed and 65,536 regular files examined. A
  member larger than 64 MiB is not extracted (for decmpfs files, a decoded
  size or attribute above 64 MiB); extraction stops when the members reach
  256 MiB in total. Notes count what was left out.
- A stream's extents are all located, and their blocks found present,
  before its bytes are assembled; they must start at 0 and follow each
  other without a gap.
- decmpfs: the `cmpf` magic, a chunk count of the size in 64 KiB units that
  the fork can hold, chunk tables inside the fork, chunks of at most
  65,537 B, the `0xCC` marker of type 9, each unit decoding to exactly its
  size.
- Problems inside a volume are listed in up to 16 notes per volume; further
  problems are counted.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| A1 | Fletcher-64 is computed as apfs-fuse and libfsapfs compute it | Every object of the three hdiutil fixtures and of 16 downloaded application disk images verifies; a different algorithm would fail them all |
| A2 | The latest checkpoint is the descriptor area's verified superblock with the largest `o_xid`, and its omap lookups use that xid | The fixtures' block 0 copies equal the latest descriptor superblock; the synthetic test with an older block 0 resolves the volume only through the descriptor copy |
| A3 | Hashed directory keys are used exactly on case- or normalization-insensitive volumes (apfs-fuse; the reference gives no rule) | Both fixtures are hashed (the case-sensitive one has `NORMALIZATION_INSENSITIVE`); a key whose length does not match the expected form is an error for that directory, so a volume that breaks the rule shows "Invalid directory entry key" notes |
| A4 | File extents are keyed by the inode's `private_id` (the reference says "the file-system object's identifier") | Equal in every fixture file; a clone with a different `private_id` is searched separately. Not tested on cloned files |
| A5 | Extent block 0 is a hole (apfs-fuse) | Synthetic only (`holes_read_as_zeros_and_gaps_are_errors`); no fixture is sparse |
| A6 | decmpfs types 1, 3, 4, 9, 11 and 12 are laid out as apfs-fuse reads them | Types 7 and 8 come from `ditto --hfsCompression`; the iOS developer disk image's 64 type 9 files and 41 recognized zlib files decode to the bytes the mounted volume returns. Types 1, 11 and 12 are synthetic only (`tests/apfs.rs`) |
| A7 | An LZFSE unit has no stored-data marker | apfs-fuse does not know of one; such a chunk would fail to decode and the file would be skipped with a note |
| A8 | The container superblock always has type `0x80000001` | libfsapfs requires it; every fixture and downloaded image has it. A container with another storage flag is not detected |
| A9 | Encrypted volumes' trees cannot be read without keys | The encrypted fixture's tree root is not a valid node; the reference says the tree is encrypted |
| A10 | 64 object reads per block present suffice for a consistent container | The fixtures and downloaded images walk without reaching it; not tested on large real containers |
| A11 | The first 4 KiB decide whether a file is a recognized format | As for the other filesystem families; a weak format that needs its whole input is not listed |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| A container cut at the 64 MiB disk-image extraction limit (most application DMGs larger than 64 MiB) | The container superblock and checkpoint are read; the container object map usually lies beyond the cut, so no volume is read (noted). 14 of 16 downloaded images with an `Apple_APFS` partition were cut this way |
| Encrypted volumes, keybags | Opaque; never decrypted |
| Sealed (system) volumes: integrity metadata, file extent tree, hashed headerless trees | Noted; not walked |
| Snapshots | Noted; not read |
| Fusion containers | Noted; blocks on the second device are not available |
| Non-contiguous checkpoint areas; ephemeral objects (space manager, reaper) | Not read; block 0 is used for a non-contiguous area |
| decmpfs types other than 1, 3, 4, 7, 8, 9, 11, 12; dataless files | Not decoded; counted |
| A `com.apple.decmpfs` attribute larger than 3,802 B (`MAX_DECMPFS_XATTR_SIZE`, which xnu applies on every file system) | Read, as before the decoder was shared with HFS+, which refuses it; not changed by the refactor |
| Extended attributes other than the two decmpfs ones, firmlinks, volume groups | Not read |
| B-tree nodes larger than one block | Not supported (noted) |
| Files over 64 MiB | Not extracted |
| Containers inside other files at offsets other than 0 | Reached only through a partition table or disk image family |

## Verification

On 2026-10-13 (macOS 27.2 AArch64, build 26B5101f, rustc 1.100.0-nightly),
`tests/apfs.rs` (30 tests) and the 16 unit tests in `src/formats/apfs*`
passed, along with the rest of `cargo test --all-features --locked`
(2,461 tests passed, 6 ignored: the repository's existing ignores). Two of
the 30 tests scan local samples and return early without their environment
variables; in that run they were skipped. The
integration tests use three macOS fixtures (`tests/fixtures/apfs/README.md`:
a case-insensitive container with a two-level file-system tree, hard and
symbolic links, LZVN decmpfs files with the attribute and the resource fork
as data streams and a file in ten extents; a case-sensitive container; a
container whose only volume is encrypted) and synthetic containers built
from the reference layouts (checkpoint choice and damaged superblocks,
plain name keys and index nodes, decmpfs types 1, 3, 4, 9, 11 and 12,
unsupported and damaged decmpfs files, three volumes with a repeated and an
empty name, sealed, encrypted and snapshot volumes, the EFI jumpstart,
holes and gaps, damaged nodes, keys out of order, a node that names itself
as its child, a member cut off by truncation), a container in a synthetic
GPT partition, every prefix up to two blocks and every block boundary of a
fixture, mutations (`0x00`, `0xFF`, bit flip; each also with the block's
checksum recomputed, so the damage reaches the structure checks) of the
first 64 bytes and every 13th byte of every checksummed block of two
containers, every 611th byte of every object block through the whole
classifier, and every 37th stored byte of the decoded members.
After `./build-web.sh`, `web/tests/apfs.test.mjs` (4 tests) passed through
`/pkg/` and `/dist/` and in both workbench pages. The whole browser suite
ran 284 tests: 279 passed, 4 were skipped (the existing skips that need D10
and RX113 firmware not in the repository) and 1 failed,
`workbench.test.mjs` "failed architecture classification retains entropy
and hex inspection" (its input is 4,096 zero bytes, which the APFS check
does not detect), which read the entropy value before it was shown while
the machine's load average was above 300; rerun alone and with its file
(18 tests), it passed.

With `IDA_INPUT_DIR=/Users/int/hexrays/ida/tests/input`, none of IDA's
44,391 test inputs was detected as an APFS container. With
`APFS_SAMPLE_DIR=/Users/int/Downloads` (application disk images read in
place, not committed), 16 `Apple_APFS` partitions in disk images of at most
256 MiB were reached through the disk image family and parsed, with every
superblock checksum the reader met verifying: two whole containers
(`PlayCover_3.1.0.dmg`, 13,558 blocks: 91 directories and 160 files walked,
8 members; `Compresto 1.25`, 7,926 blocks: 94 directories and 94 files, 9
members) and 14 cut at the 64 MiB extraction limit, whose container object
map lies beyond the cut, so no volume was read. Among them,
`AudirvanaStudio_3.3.104.dmg` holds a container of 40,950 blocks of 4 KiB
(about 160 MiB), of which 16,384 are present; its checkpoint xid 6
superblock is read, its container object map at block 0x8243 is not
present, and nothing is listed.

With `APFS_SAMPLE_DIR=/Library/Developer/DeveloperDiskImages` (Apple's
Xcode developer disk images on the build machine, read in place), 7 of the
8 images hold an APFS container (the eighth, a watchOS image, holds an HFS+
volume): the four sealed cryptex volumes (`Xcode_*_Cryptex_DDI`) are noted
and not walked, and the three others (iOS, tvOS, xrOS) list 41, 39 and 41
members. Every regular file
of those three is a decmpfs file (iOS and xrOS: 114, 50 zlib and 64 type 9;
tvOS: 109, 48 zlib and 61 type 9), and every one decodes. With the iOS
image mounted read-only (`hdiutil attach -readonly`), its 41 members, and
its 64 type 9 files when the walk was temporarily made to list every
attribute-stored file, were byte for byte the files the kernel returns.

Not verified: decmpfs types 1, 11 and 12 written by macOS (only LZVN, zlib
and type 9 files from Apple were available), containers with more than one
volume or with snapshots, Fusion containers, EFI jumpstarts, cloned files,
sparse files, block sizes other than 4 KiB, containers written by other
implementations, and the object read limit on large containers.

After integration on the same day (with truncated-volume reading in the
HFS+, ext, FAT and ISO 9660 families), the native suite passed 2,471
tests with 6 ignored, and IDA's corpus (4,621 files) classified as
before. Through the DMG family, the watchOS developer disk image
`022-22632-017.dmg` classified as AArch64 from the Mach-O files of its
volume (an HFS+ volume, as above, not an APFS one); the images whose
volumes are sealed cryptexes still name no ISA.

Shared decmpfs decoder, on 2026-10-13 (macOS 27.2 AArch64, build 26B5101f,
rustc 1.100.0-nightly `f248f4038`): `src/formats/apfs/decmpfs.rs` was
replaced by `src/formats/decmpfs.rs`, which HFS+ shares; APFS keeps its own
checks through `decmpfs::Family` (no attribute limit of its own, short
resource forks refused first, empty type 1 data reported as truncated).
`cargo test --all-features --locked` passed 2,628 tests with 6 ignored,
among them `tests/apfs.rs` (30 tests; the two sample scans returned early
without `APFS_SAMPLE_DIR` and `IDA_INPUT_DIR`, so they were skipped), the
13 unit tests in `src/formats/apfs/` and the 8 in `src/formats/decmpfs.rs`;
`web/tests/apfs.test.mjs` (4 tests) passed after `./build-web.sh`. The
differential snapshot recorded in [HFS+ and HFSX volumes](hfsplus.md)
("Verification") covered the three APFS fixtures, 36 containers from the
`tests/apfs.rs` builders and the developer disk images' seven APFS
containers: no APFS outcome changed, including the iOS image's notes
counting 64 type 9 ("raw") and 50 zlib files.
