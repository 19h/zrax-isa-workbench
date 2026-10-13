# EROFS images

`src/formats/erofs.rs` and its submodules (`inode.rs`, `zmap.rs`,
`walk.rs`) parse EROFS filesystem images into the shared container model
([compressed streams and the container model](compressed-streams.md)): the
superblock, compact and extended inodes, directories, the uncompressed and
compressed data layouts, and a directory walk from the root that lists the
regular files in a recognized format as members. EROFS names no processor:
the container result has an unknown ISA with confidence 0, and the ISA
comes from the members, each classified from its own bytes.

Primary source: Linux v6.11 (commit
`98f7e32f20d28ec452afb208f9cffc08448a2652`), `fs/erofs/erofs_fs.h` for the
on-disk structures and `super.c`, `inode.c`, `internal.h`, `data.c`,
`dir.c`, `zmap.c`, `decompressor.c`, `decompressor_deflate.c`,
`decompressor_lzma.c` and `zdata.c` for how the kernel reads them;
`include/uapi/linux/magic.h` for `EROFS_SUPER_MAGIC_V1`;
`Documentation/filesystems/erofs.rst` for the overview. `MicroLZMA` is
defined by Linux v6.11 `include/linux/xz.h` and `lib/xz/xz_dec_lzma2.c`.
erofs-utils 1.9.4 (`mkfs.erofs`, `dump.erofs`, `fsck.erofs`) built the
fixtures and was used to cross-check extents and contents; no rule is taken
from it.

## Implemented layouts

| JSON format ID | Layout | Recognition | Components | Primary source |
| --- | --- | --- | --- | --- |
| `erofs` | Superblock at 1024 (128 B plus `sb_extslots * 16`), block sizes 512 B to 64 KiB, compact (32 B) and extended (64 B) inodes, inline xattr areas skipped | Strong: magic `0xE0F5E1E2` at 1024 and `blkszbits` 9-16 | Regular files in a recognized format, labelled with their path, in walk order | `erofs_fs.h` `struct erofs_super_block`, `erofs_inode_compact`, `erofs_inode_extended`; `super.c` `erofs_read_superblock`; `inode.c` `erofs_read_inode` |
| `erofs` (data) | Flat-plain (layout 0) and flat-inline (layout 2, tail after the inode) | — | Stored contiguously: borrowed at its offset; with a tail: reassembled (transform `EROFS tail packing`) | `data.c` `erofs_map_blocks_flatmode` |
| `erofs` (data) | Chunk-based (layout 4): 4-byte block map or 8-byte chunk indexes, holes (`EROFS_NULL_ADDR`) as zeros | — | Borrowed when the chunks are one stored run, else reassembled (`EROFS chunks`) | `data.c` `erofs_map_blocks`, `struct erofs_inode_chunk_index` |
| `erofs` (data) | Compressed with full (layout 1, 8 B per lcluster) or compact (layout 3, 2 B and 4 B packs) indexes; PLAIN, HEAD1, HEAD2 and NONHEAD lclusters; big pclusters (CBLKCNT); tail-packed pclusters (`ztailpacking`); interlaced plain pclusters; fragments in the packed inode | — | Decoded extent by extent (`EROFS LZ4`, `EROFS LZMA`, `EROFS DEFLATE`, `EROFS mixed compression`, `EROFS fragment`); stored offset is the first pcluster | `zmap.c`, `decompressor.c`, `zdata.c` |
| `erofs` (codecs) | LZ4: raw LZ4 blocks (`Codec::Lz4Block`); LZMA: `MicroLZMA` (`Codec::MicroLzma`, new); DEFLATE: raw DEFLATE (`Codec::Deflate`) | — | Each extent must decode to exactly its length | `decompressor.c` `z_erofs_lz4_decompress_mem`; `decompressor_lzma.c`; `decompressor_deflate.c`; `xz.h` |
| `erofs` (directories) | Directory blocks of 12-byte `erofs_dirent` records and names, read through the directory's own layout (including compressed directories) | — | Subdirectories walked; symlinks, devices, FIFOs and sockets ignored | `dir.c` `erofs_readdir`, `erofs_fill_dentries` |

The JSON `format.variant_name` is `EROFS`. Notes give the block size and
count, the inode count and root nid, the checksum result, the compression
algorithms, extra devices, a walk census and every problem below the root;
metadata records `erofs_block_size`, `erofs_block_count`,
`erofs_inode_count`, `erofs_root_nid`, `erofs_meta_blkaddr`, the feature
lists, `erofs_uuid`, `erofs_superblock_checksum`, `erofs_volume_name`,
`erofs_packed_nid`, `erofs_compression_algorithms`, the walk counts and one
`erofs_component_<n>` entry per member.

## Detection

EROFS is recognized by its 4-byte magic at 1024 with a supported block size
(`erofs::detect`), so a damaged image is an `EROFS parse error` instead of a
raw-code guess. The check sits right after ext2/3/4 and before the
magic-bearing compressed streams in `detect_format`: the first kilobyte is
left unused by EROFS, so every executable and firmware format with a header
at offset 0 is checked first.

## Wire units and byte order

| Item | Byte order | Units |
| --- | --- | --- |
| Superblock, inodes, dirents, chunk tables, map headers, lcluster indexes | Little-endian | Block addresses in filesystem blocks of `1 << blkszbits` bytes; inode location `meta_blkaddr * blksz + nid * 32` |
| `i_size` | Little-endian (u32 compact, u64 extended) | Bytes |
| Compressed extents | — | Logical positions in bytes (`(lcn << lclusterbits) | clusterofs`); pclusters at `pblk * blksz`, one lcluster or CBLKCNT blocks |
| Fragments | — | Byte offsets in the packed inode's decoded data (`h_fragmentoff`, or the 64-bit map header without bit 63 for whole-file fragments; with full indexes bits 32-63 come from the tail head's block address) |

## Members

- The walk starts at `root_nid` and reads each directory through its own
  data layout, block by block. `.` and `..` are skipped; every inode is
  examined once, which handles hard links and directory cycles (a
  directory entry naming an ancestor). Paths are built from the walk.
- A regular file is read up to its first 4 KiB; when that prefix is a
  recognized format (`container::is_recognized`), the whole file is read
  and listed with `if_recognized`. Files stored as one run are borrowed at
  their stored offset; others are owned with a transform naming how they
  were rebuilt.
- Compressed files are decoded extent by extent. Each extent starts at a
  HEAD or PLAIN lcluster and ends at the next one or at `i_size`; a head at
  or after `i_size` in the last lcluster only ends the tail extent. The
  tail extent is tail-packed (inline after the index entry or pack of the
  last lcluster, `h_idata_size` bytes) or a fragment when the map header
  says so. With `zero_padding` (and always for LZMA and DEFLATE) leading
  zeros of the pcluster's first block are skipped; LZ4 and DEFLATE extents
  must reach their stream end exactly at the extent length, `MicroLZMA`
  extents decode exactly the extent length. PLAIN extents are copied, or
  un-rotated by their offset in the block when interlaced.
- The packed inode (`packed_nid`) is decoded once, on the first fragment,
  and may not itself use fragments. A file that is wholly a fragment
  reports the stored pcluster of the packed inode that holds its offset.

## Checksums

With `sb_csum` the superblock checksum is verified: CRC32C (seed `~0`, no
final inversion) of bytes 1024 to the end of block 0 (or of one block's
worth for blocks of 1 KiB or less) with the field zeroed. Because block 0
holds the first inodes and inline directories of small images, that
checksum covers them as well. EROFS has no other metadata or data
checksums; nothing else is reported as verified.

## Validation and resource bounds

- Superblock checks in the kernel's order: magic, `blkszbits` 9-16,
  `dirblkbits` 0, checksum, incompatible features within the v6.11 set
  (`0x7F`; others, for example `48bit` `0x80`, are refused), extension
  slots within the first page, a NUL in `volume_name`, compression
  algorithms within LZ4, LZMA, DEFLATE and Zstandard and one configuration
  record each inside the image.
- The image must hold `blocks * blksz` bytes; only padding (`0x00`/`0xFF`)
  or an AVB footer (hashtree, vbmeta and footer appended by `avbtool`) may
  follow, otherwise the image is an error. The root inode must be a
  directory.
- Damage below the root (bad inodes, directory blocks, chunk tables,
  indexes or pclusters) skips that entry or member with a note; at most 16
  problems are listed and the rest counted.
- Reads are bounds-checked against the image; inode, directory, chunk-table
  and index reads are charged to a budget of twice the image size (at
  least 1 MiB), after which the walk stops with a note. Directory and file
  reads are limited to 64 MiB (`MAX_PAYLOAD`).
- Decoded bytes (recognition probes and members together) are limited to
  512 MiB per image; members to 64 MiB each and 256 MiB in all
  (`MAX_EXTRACTED`); at most 4096 members are listed and 65536 regular
  files examined; directories deeper than 64 levels are not walked.
- Index scans are bounded by the lclusters of the bytes read (at most
  `MAX_PAYLOAD / blksz` for a full read); compact entries are decoded
  exactly as `unpack_compacted_index` does, with checked indices.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| E1 | One-block lclusters (`h_clusterbits & 7 == 0`), as erofs-utils always writes; other sizes are refused as unsupported (UNCONFIRMED for other writers) | An image whose map header has nonzero cluster bits |
| E2 | Scanning lclusters in order gives the same extents as the kernel's lookback through `delta[0]` for valid images | The decoded contents of every compressed file in the six fixtures and in 27 further `mkfs.erofs` images matched the source files on 2026-10-13, except one image noted under known boundaries |
| E3 | Blocks up to 64 KiB are valid (the kernel accepts up to its page size) | A kernel with larger pages, or an image with `blkszbits > 16` |
| E4 | Extents with `Z_EROFS_LI_PARTIAL_REF` (deduplicated, full indexes) need partial decoding and are not decoded | A `-Ededupe` image whose extents carry the flag |
| E5 | `MicroLZMA` decoding does not check that the whole compressed input was consumed (the kernel does for full decodes) | A pcluster with trailing garbage after a valid stream |
| E6 | The interlaced rotation of a tail-packed plain pcluster shorter than the rotation is not defined by these sources; it is refused | An image built with interlaced plain tail pclusters |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Zstandard extents | Not decoded (no image was available to check the framing); the member is skipped with a note |
| Legacy LZ4 images without `zero_padding` (before Linux 5.4) | Not decoded: the kernel decodes them partially |
| Partial references to a shared pcluster | Not decoded |
| Extra devices (`DEVICE_TABLE`), chunks on them | Noted; chunks on another device are not in the file and the member is skipped |
| Xattrs, long xattr prefixes, ACLs | Skipped; not reported |
| Features after v6.11 (`48bit`, metadata box, ...) | Refused as unsupported incompatible features |
| Symlinks, device nodes, FIFOs, sockets | Ignored |
| Images from erofs-utils 1.9.4 with `-Efragments,ztailpacking` and big pclusters | One such stress image did not round-trip: its packed inode's tail extent decodes to bytes that differ from the source file, and `fsck.erofs --extract` 1.9.4 produced the same bytes as this reader; not used as a fixture |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`):
`tests/erofs.rs` (14 tests) and the 7 unit tests in `src/formats/erofs/`
passed, with the 2 `MicroLZMA` unit tests in
`src/formats/compressed/microlzma.rs`. The integration tests use six
`mkfs.erofs` 1.9.4 fixtures (`tests/fixtures/erofs/README.md`: flat, chunk
indexes with extended inodes, LZ4HC big pclusters with tail packing, LZ4
full indexes, DEFLATE, `MicroLZMA` fragments) whose members are compared
byte for byte with the source tree rebuilt in the test, synthetic images
built from the `erofs_fs.h` layouts (directory cycles, hard links, an
extended inode across a block boundary, chunk holes, 70 nested
directories), a parse of every prefix of every fixture, and mutations
(`0x00`, `0xFF`, bit flip, with and without a recomputed superblock
checksum) of every byte of the first three blocks and every 61st byte of
each fixture. Outside the committed tests, 27 further images of a larger
tree (300 KiB to 1 MiB files; LZ4, LZ4HC with 16 and 64 KiB pclusters,
deduplication, compressed directories, `--max-extent-bytes`, MicroLZMA,
mixed LZ4 and LZMA, DEFLATE with tail packing, fragments, chunk sizes) were
decoded and every member matched its source, except in the one image noted under
known boundaries. `web/tests/erofs.test.mjs` (4 tests) passed through
`/pkg/` and `/dist/` and in both workbench pages.

Not verified: images from other writers (AOSP builds, `mkfs.erofs` other
than 1.9.4), Zstandard, legacy and partial-reference extents, block sizes
other than 4 KiB outside the reader's own arithmetic, images larger than
70 KiB in the committed tests, and kernel behavior itself (no kernel mount
was run).
