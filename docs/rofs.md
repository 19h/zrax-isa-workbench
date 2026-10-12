# Read-only filesystem images

`src/formats/rofs.rs` and its submodules (`squashfs.rs`, `cramfs.rs`,
`romfs.rs`) parse SquashFS, CramFS and romfs images into the shared container
model ([compressed streams and the container model](compressed-streams.md)).
Each image is a container whose children are its regular files. A directory
walk finds every regular file; a file is listed only when its first block is
a format the classifier recognizes, and only then is the whole file read.
None of these formats names an ISA, so the container target is always unknown
and the ISA comes from the listed members.

## Implemented layouts

| JSON format ID | Variant | Layout | Recognition | Primary source |
| --- | --- | --- | --- | --- |
| `squashfs` | `SquashFS 4.0` | Little-endian 96-byte superblock; compressor options block; inode, directory, fragment, export, id and xattr id tables; basic and extended directory and regular file inodes; directory headers, entries and extended-directory index entries; block lists with the stored bit (`1 << 24`), sparse blocks (size 0) and fragment tails. Compressor IDs 1 gzip (zlib streams), 2 LZMA (LZMA-alone streams), 3 LZO (raw LZO1X blocks), 4 xz, 5 LZ4 (raw LZ4 blocks), 6 zstd. Members enumerated | Strong: `hsqs` at offset 0 | Linux v6.11 (`98f7e32f20d2`) `fs/squashfs/squashfs_fs.h`, `super.c`, `block.c`, `inode.c`, `dir.c`, `file.c`, `fragment.c`, `id.c`, `export.c`, `xattr_id.c`; squashfs-tools 4.6.1 (`d8cb82d98403`) `squashfs_fs.h`, `unsquash-4.c`, `*_wrapper.h` |
| `squashfs` | `SquashFS 1.x-3.x or big-endian` | `squashfs_super_block_3` in the image's byte order (`hsqs` or `sqsh`): version, bytes used, block size, inode and fragment counts. A big-endian 4.0 superblock is noted and not interpreted. Members not enumerated | Strong: `hsqs` with major version 1-3, or `sqsh` at offset 0 | squashfs-tools 4.6.1 `squashfs_compat.h`, `unsquash-1.c`, `unsquash-2.c`, `unsquash-3.c` |
| `squashfs` | `Streamed SquashFS` | `HSQS`/`SQSH` and a zeroed 96-byte placeholder (squashfs-tools 4.7 and later keep the real superblock in the last 96 bytes). Members not enumerated | Strong: streamed magic and zero placeholder | squashfs-tools 4.7.5 (`708c59ae8085`) `squashfs_fs.h`, `unsquash-4.c` |
| `cramfs` | `CramFS` | Superblock at offset 0, or at 512 after a boot-code pad, in either byte order; `fsid` CRC-32; inode bitfields; directory walk; per-page zlib blocks; holes; extended block pointers (direct and uncompressed flags) | Strong: `0x28CD3D45` in either byte order at offset 0, or at 512 followed by the `Compressed ROMFS` signature | Linux v6.11 `include/uapi/linux/cramfs_fs.h`, `fs/cramfs/inode.c`, `fs/cramfs/README`; util-linux v2.40.2 (`1cebcc34373e`) `disk-utils/cramfs.h`, `cramfs_common.c`, `mkfs.cramfs.c`, `fsck.cramfs.c` |
| `romfs` | `romfs` | Big-endian superblock with word-sum checksum; file headers (next, type and exec bits, spec, size, checksum) on 16-byte boundaries; directory chains; regular files stored as-is | Strong: `-rom1fs-` at offset 0 | Linux v6.11 `Documentation/filesystems/romfs.rst`, `include/uapi/linux/romfs_fs.h`, `fs/romfs/super.c`; genromfs `e4225b49` `genromfs.c` |

The raw LZO1X and raw LZ4 block decoders are `compressed::Codec::Lzo1x`
(reusing the LZO1X bitstream decoder of the lzop codec) and
`compressed::Codec::Lz4Block` (`lz4_flex::block`). Neither has a magic and
neither is recognized standalone.

## Members, coordinates and reporting

- Every regular file is examined in directory order. Its first block (the
  first data block, or the fragment tail of a SquashFS file smaller than a
  block; the first 4 KiB page for CramFS; the first 4 KiB for romfs) is read
  and checked with `container::is_recognized`. Only recognized files are
  read in full and listed, with `Classify::IfRecognized`, so each member is
  classified on its own bytes.
- A member's label is its path from the root (`/bin/busybox`). Names are
  path components: `.` and `..` are skipped, and a name that is empty or
  holds `/` or NUL is a parse error.
- Slice `offset` and `size` are stored file coordinates. A SquashFS member
  whose blocks are all stored, whole and back to back, and a romfs member,
  are the stored bytes themselves. Otherwise the slice covers the stored
  blocks (SquashFS: from the first data block through the last, or the
  fragment block for a file held only in a fragment; CramFS: from the block
  pointer table through the last block) and `decoded` gives the assembled
  file. A SquashFS fragment tail stored outside that range is part of the
  decoded file but not of the slice. The transform names the codec (`zlib`, `LZMA`, `LZO1X`,
  `xz`, `LZ4 block`, `Zstandard`), or `SquashFS block list` / `CramFS block
  list` when the file was assembled from stored and sparse blocks without
  decoding.
- Notes count the regular files and the listed members, and say what was
  left out: files over the member or extraction limits, files larger than
  64 MiB, files whose data did not decode (with the first path and reason),
  and directories past the walk limits. Metadata `<prefix>_regular_files`
  gives the regular file count.
- Symlinks, device nodes, FIFOs, sockets and romfs hard links are not
  members. A SquashFS inode named by several directory entries is examined
  once per path.

## Wire units and byte order

| Format | Byte order | Units |
| --- | --- | --- |
| SquashFS 4.0 | Little-endian throughout | Table starts and data block starts are absolute file offsets in bytes. An inode reference is a table-relative metadata block offset in bits 16-47 and an offset into that block's decoded 8 KiB in bits 0-15. Block list entries are u32: stored size in bits 0-23, stored bit 24 |
| SquashFS 1.x-3.x | The image's: `hsqs` little-endian, `sqsh` big-endian | Bytes; only superblock fields are read |
| CramFS | The builder's host order, revealed by the magic | Inode `namelen` and `offset` are in 4-byte units; sizes and plain block pointers are bytes (a pointer is the file offset where its block ends); direct block pointers are 4-byte units. All offsets count from the start of the input, also after a 512-byte pad |
| romfs | Big-endian | Bytes; headers and names aligned to 16 bytes |

Byte order describes the machine that built the image, not the code in it,
and is never reported as code byte order.

## Validation and resource bounds

- SquashFS superblock checks follow the kernel's order
  (`squashfs_fill_super`): magic, version 4.0, compressor ID, `bytes_used`
  within the input (and at least 96 B), block size a power of two from
  4 KiB to 1 MiB matching `block_log`, root inode offset at most 8 KiB, the
  compressor options, then the table indexes. The id, export and xattr id
  indexes must end exactly at the next table, their block offsets must
  increase by at most 8194 B and end before the index; the fragment index
  must end by the next table; the directory table must start by the next
  table and after the inode table.
- SquashFS metadata blocks hold 1 B to 8 KiB stored and decoded. The inode
  and directory tables must tile their ranges exactly (`inode_table_start`
  to `directory_table_start`, and the directory table to the first block of
  the next table) and decode to at most 64 MiB each. References must name a
  block start and an offset inside that block. Directory headers hold at
  most 256 entries, names at most 256 B, entry types 1-7; inode number 0 is
  rejected; a block list may not run past the inode table; block sizes with
  bits 25-31 set, stored blocks larger than the block size, and fragment
  indexes past the fragment count are rejected.
- `bytes_used` bounds a SquashFS image, CramFS `size` (with
  `FSID_VERSION_2`) bounds a CramFS image and the superblock `size` bounds a
  romfs image. Only `0x00`/`0xFF` padding may follow; mksquashfs pads to
  4 KiB, genromfs to 1 KiB.
- CramFS: unsupported flags (outside the low byte, holes, wrong signature,
  shifted root, extended pointers) are rejected; the root must be a
  directory whose entries start at 76 or 588 (or 0 for an empty
  filesystem) unless `SHIFTED_ROOT_OFFSET` is set; with
  `FSID_VERSION_2` the file count must be nonzero and the CRC-32 over the
  image (field taken as zero) must match. Stored blocks are at most 8 KiB
  compressed or 4 KiB uncompressed and must decode to exactly the page or
  the file's remainder.
- romfs: size at least 16 B; the first `min(size, 512)` bytes must sum to 0.
  File header checksums are verified and reported, but a mismatch is only a
  note, because Linux does not check them.
- Walks stop at 64 directory levels or a 4096 B path and count what they did
  not walk. Loops are errors: a SquashFS walk may not read more listing
  bytes than the directory table holds, a CramFS walk more entry bytes than
  the image holds, and a romfs walk more headers than `size / 32`.
- Members are capped at 4096 (`MAX_COMPONENTS`), each member at 64 MiB
  (`MAX_PAYLOAD`), and all bytes probed, decoded or listed per image at
  256 MiB (`MAX_EXTRACTED`), including shared fragment and fragment-table
  blocks. Each read is charged before it happens, so decoding work per image
  is bounded too. Nested containers stop at six levels (`MAX_NESTING`).
- Structural damage (superblock, tables, inodes, directories) is a
  `Read-only filesystem parse error`. A regular file whose data does not
  decode or lies outside the image is left out and counted in a note.

## Integrity

| Check | Behavior |
| --- | --- |
| CramFS `fsid.crc` (CRC-32) | Verified; mismatch is an error |
| romfs superblock word sum | Verified; mismatch is an error |
| romfs file header word sums | Verified; mismatch is a note |
| zlib Adler-32, xz block checks, zstd content checksums inside blocks | Verified by the codec layer when present |
| SquashFS | The format has no checksums |

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| R1 | CramFS blocks are 4 KiB pages; the builder's page size is not recorded | A `mkfs.cramfs -b 16384` image: its members must show as unreadable in the notes instead of being listed |
| R2 | SquashFS inode and directory tables are contiguous and end where the next table begins, as mksquashfs writes them | An image from another writer (squashfs-tools-ng `gensquashfs`, vendor tools) that leaves gaps fails with "crosses the table end" or a decode error |
| R3 | Directory entries name basic types 1-7 and may point at extended inodes | Extended directory and file inodes behind type-1/2 entries (`squashfs_lists_recognized_members_with_stored_offsets_and_decoded_ranges`); a real mksquashfs image with xattrs was not tested |
| R4 | A member's first block is enough to recognize it | A member whose format is recognized only from its complete contents is not listed |
| R5 | CramFS and legacy SquashFS byte order is the builder's, not the target's | A big-endian CramFS holding little-endian ELF members reports the members' ISA (`cramfs_lists_members_in_both_byte_orders_and_after_a_pad`) |
| R6 | xz BCJ filter options record what mksquashfs tried, not an ISA | xz options with the x86 and Arm filter bits are only noted, as "not ISA evidence", and the member's own ELF header gives the ISA (`squashfs_decodes_the_blocks_of_every_compressor_and_reports_options`); an `-Xbcj x86` mksquashfs image of AArch64 binaries was not tested |
| R7 | romfs `.` and `..` entries are skipped and hard links never followed, so genromfs trees cannot loop | A romfs directory reachable only through a hard link is not walked; a forged loop is an error (`romfs_checksums_and_loops`) |
| R8 | Compressor framing per block: zlib streams, LZMA-alone streams, raw LZO1X, xz streams, raw LZ4 blocks, zstd frames (`*_wrapper.c`) | Fixtures for every compressor (`squashfs_decodes_the_blocks_of_every_compressor_and_reports_options`) are built in the tests, not by mksquashfs |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| SquashFS 1.x-3.x and big-endian images | Recognized; version, byte order, block size, inode and fragment counts noted; compressor noted as not recorded (zlib in squashfs-tools); members not enumerated, because the big-endian inode and directory bitfield layout and the 1.x/2.x block lists are not established |
| Big-endian SquashFS 4.0 superblock | Noted and not interpreted; Linux and squashfs-tools reject it |
| Streamed SquashFS (4.7 and later) | Recognized; members not enumerated (no tested image of the trailing-superblock layout) |
| Vendor SquashFS magics (`shsq`, `qshs`, `tqsh`, LZMA-patched 3.x) | Not recognized; no primary source |
| SquashFS xattrs, export table, uid/gid table, compressor flags | Indexes validated; contents not read |
| CramFS images with a page size other than 4 KiB | Members reported unreadable (see R1) |
| Filesystems embedded at a nonzero offset in a larger file | Not found; data after an image must be padding |
| Members larger than 64 MiB | Counted in a note, not listed |
| Images made by mksquashfs, mkfs.cramfs or genromfs | Not verified: none of these tools was available, so every fixture is synthetic |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`),
`tests/rofs.rs` (24 tests) and the family's 16 unit tests passed, with
every-prefix truncation and every-byte mutation sweeps (`0x00`, `0xFF`, bit
flip) over two SquashFS 4.0 images, three legacy SquashFS superblocks, two
CramFS images and a romfs image. The raw LZO1X and LZ4 block codecs have
unit tests in `src/formats/compressed`. `web/tests/rofs.test.mjs` (4
Chromium tests) passed through `/pkg/zrax.js`, `/dist/zrax.js` and both
workbench pages. All fixtures are built in the tests from the documented
layouts, with the committed synthetic `payload.elf` and generated ELF headers
as members; no tool-made image was tested and no third-party image is
redistributed.
