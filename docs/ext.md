# ext filesystem images

`src/formats/ext.rs` and its submodules read ext2, ext3 and ext4 filesystem
images, read-only, into the shared container model
([compressed streams and the container model](compressed-streams.md)). The
reader checks the superblock and the group descriptors, walks the directory
tree from the root inode, and lists each regular file whose first bytes are
a recognized format as a child labelled with its path. Each member is then
classified from its own bytes. The filesystem names no processor.

| Submodule | Contents |
| --- | --- |
| `ext.rs` | Layout naming, feature table, bounds-checked readers, block access, metadata read budget, notes and metadata |
| `ext/superblock.rs` | Superblock geometry checks, superblock checksum, checksum seed, superblock backups and descriptor block locations (`meta_bg`) |
| `ext/groups.rs` | Group descriptors (32- and 64-byte), location checks, descriptor checksums |
| `ext/inode.rs` | Inode location, `i_extra_isize`, inode checksum, file size |
| `ext/map.rs` | Block maps (direct, single, double and triple indirect), extent trees, file reads with holes |
| `ext/walk.rs` | Directory walk, directory entry checks, htree index blocks, directory block checksums, member extraction and limits |

## Implemented layouts

| JSON format ID | Variant | Layout | Architecture evidence | Primary source |
| --- | --- | --- | --- | --- |
| `ext` | `ext2`, `ext3` or `ext4` | Superblock at file offset 1024 (`s_magic` `0xEF53` at file offset `0x438`); revision 0 and 1; block sizes 1 to 64 KiB; group descriptors of 32 B, or `s_desc_size` (64 B to 1 KiB) with `64bit`; descriptor tables after the superblock and, with `meta_bg`, in each meta group; `flex_bg` inode tables anywhere in the filesystem; inodes with block maps or extent trees; linear and htree directories | None. `s_creator_os` names an operating system (Linux, Hurd, Masix, FreeBSD, Lites), not a processor. Members are classified from their own bytes | Linux v6.11 (commit `98f7e32f20d28ec452afb208f9cffc08448a2652`): `fs/ext4/ext4.h`, `fs/ext4/ext4_extents.h`, `fs/ext4/super.c`, `fs/ext4/balloc.c`, `fs/ext4/inode.c`, `fs/ext4/extents.c`, `fs/ext4/dir.c`, `fs/ext4/namei.c`, and `Documentation/filesystems/ext4/` (`super.rst`, `group_descr.rst`, `inodes.rst`, `ifork.rst`, `directory.rst`, `checksums.rst`) |

The variant follows the libblkid naming convention (util-linux v2.40.2
`libblkid/src/superblocks/ext.c`, `probe_ext2`, `probe_ext3` and
`probe_ext4`). It is a convention, not a field:

| Variant | Feature set |
| --- | --- |
| `ext3` | `has_journal`; ro-compat features only from `sparse_super`, `large_file`, `btree_dir`; incompat features only from `filetype`, `recover`, `meta_bg` |
| `ext2` | No journal; the same ro-compat set; incompat features only from `filetype`, `meta_bg` |
| `ext4` | Any other feature set (`extents`, `64bit`, `flex_bg`, `metadata_csum`, ...) |

## Detection

Detection is strong and runs after the other magic-bearing container
families (it follows the ZX Spectrum tape check) and before the
magic-bearing compressed streams. An ext image leaves its first kilobyte
to a boot loader, so formats whose headers start at offset 0 are checked
first.

`s_magic` is only two bytes, so detection also requires a consistent
superblock, as `ext4_fill_super` checks it:

- `s_log_block_size` at most 6 (64 KiB blocks);
- revision 0 or 1; with revision 1, `s_first_ino` at least 11 and
  `s_inode_size` a power of two from 128 B to the block size;
- without `bigalloc`, a cluster size equal to the block size and
  `s_blocks_per_group` at most 8 times the block size; with `bigalloc`,
  `s_clusters_per_group` at most 8 times the block size and
  `s_blocks_per_group` equal to it times the cluster ratio;
- `s_inodes_per_group` from the inodes in one block to 8 times the block
  size;
- `s_first_data_block` below the block count, and not 0 for 1 KiB blocks
  without `bigalloc`;
- with `64bit`, `s_desc_size` a power of two from 64 B to 1 KiB;
- a group count of at most `2^32` minus the descriptors per block, and
  `s_inodes_count` equal to the group count times `s_inodes_per_group`.

A superblock that fails any of these is not detected. The image size, the
features and the checksums are checked when the container is parsed, so a
damaged image with a consistent superblock is a parse error, not raw code.
Detection reads only the first 2 KiB, so `container::is_recognized` finds
an ext image from a member prefix of that size.

## Wire units and byte order

All fields are little-endian. Block numbers count filesystem blocks of
`1024 << s_log_block_size` bytes; logical block numbers count blocks of a
file. Offsets in notes and metadata, and member offsets, are file bytes.

A member stored in one contiguous run from its first byte is borrowed from
the image: its offset and size are the stored bytes. Any other member
(holes, unwritten extents, several runs) is reassembled into owned bytes.
Its slice then gives the file offset and size of the first stored run, and
its decoded range gives the whole file, with the transform `ext block map`
or `ext extent map`.

## Members

- The walk starts at inode 2. Directory blocks are read as linear arrays of
  `ext4_dir_entry_2` records, and each record is checked as
  `__ext4_check_dir_entry` checks it (minimum and 4-byte-aligned `rec_len`,
  room for the name, no overrun, no record ending within 12 B of the block
  end, inode number in range). A bad record skips the rest of its block, as
  the kernel does, with a note.
- The type of an entry comes from its inode's `i_mode`, not from the
  directory record's `file_type`.
- With 64 KiB blocks, `rec_len` is decoded as `ext4_rec_len_from_disk`
  decodes it (0 and `0xFFFF` mean the whole block).
- In an htree directory (`dir_index` and `EXT4_INDEX_FL`), the index blocks
  (`dx_root` in block 0, `dx_node` blocks whose first record spans the
  block) are skipped, as `__ext4_read_dirblock` identifies them. They hold
  no entries besides `.` and `..`. The hash tree is not used.
- Directories are walked in entry order, depth first. Each inode is examined
  once: further names of an inode (hard links, a directory linked twice, a
  cycle) are counted in a note.
- A regular file is read through its block map or extent tree. Its first
  4 KiB (or the whole file, if smaller) go to `container::is_recognized`;
  only recognized files are extracted and listed (`Classify::IfRecognized`).
  Symlinks, devices, FIFOs and sockets are not followed or read.
- Holes and unwritten extents read as zeros.
- Encrypted files and directories (`EXT4_ENCRYPT_FL`) are not read; they are
  counted in a note. Files and directories with inline data are not read;
  they are counted in a note.

## Checksums

| Checksum | Verified | On mismatch |
| --- | --- | --- |
| Superblock `s_checksum` (CRC32C, `metadata_csum`) | Yes; `s_checksum_type` must be 1 | Parse error |
| Group descriptor `bg_checksum` (CRC32C low 16 bits with `metadata_csum`, CRC16 with `gdt_csum`) | Yes | Parse error |
| Inode checksum (`metadata_csum`, Linux creator OS only, as the kernel checks it) | Yes, for each inode read | The entry is skipped with a note |
| Extent block tail (`metadata_csum`) | Yes, for each extent block read | The file or directory is skipped with a note |
| Directory leaf block tail (`metadata_csum`) | Yes, for each leaf block read | The block is skipped with a note |
| Bitmaps, htree index blocks (`dx_tail`), extended attribute blocks, journal | No; the notes say "not verified" | |

The CRC32C and the chained CRC16 helpers are in `src/formats/checksum.rs`
(`crc32c_update`, `crc16_modbus_update`). CRC32C is the Castagnoli CRC
(reflected polynomial `0x82F63B78`); ext4 keeps the raw register (seed
`0xFFFFFFFF`, no final XOR). The metadata seed is `s_checksum_seed` with
`csum_seed`, otherwise the CRC32C of `s_uuid`.

## Validation and resource bounds

- Bytes after a filesystem of `s_blocks_count` blocks may only be `0x00`
  or `0xFF` padding; otherwise the image is a parse error. An image shorter
  than the filesystem is read as a truncated filesystem (see below).
- Incompatible features outside the kernel's `EXT4_FEATURE_INCOMPAT_SUPP`
  are refused: `compression`, `journal_dev` (an external journal, not a
  filesystem), `dirdata` and unnamed bits.
- Group descriptors must fit in the filesystem before they are read. Each
  block bitmap, inode bitmap and inode table must lie in its own group, or
  anywhere after `s_first_data_block` with `flex_bg` and for the last group
  (`ext4_check_descriptors`).
- Inodes in an uninitialized part of an inode table (`INODE_UNINIT`, or at
  or beyond `s_inodes_per_group - bg_itable_unused`, with `gdt_csum` or
  `metadata_csum`) are not read. Inodes with mode 0 or no links are not in
  use.
- Extent trees: header magic `0xF30A`, depth at most 5, `eh_max` nonzero
  and within the node, `eh_entries` at most `eh_max`, each child one level
  shallower, index entries strictly increasing, leaf extents nonempty,
  sorted, non-overlapping, below logical block `2^32` and inside the
  filesystem. Each logical block is resolved through one index path.
- Block maps: every block number must lie in the filesystem; 0 is a hole.
  Indirect blocks are at most three levels deep.
- Only the blocks needed are mapped: the first 4 KiB of a file, then the
  whole file if it is extracted. A directory is mapped up to the smaller of
  its size and the block count.
- Metadata reads (inode records, directory, extent and indirect blocks) are
  limited to twice the filesystem size (for a truncated filesystem, twice
  the bytes present). When the limit is reached the walk stops and a note
  counts the directories not walked.
- Directories deeper than 64 levels below the root are not walked.
- At most 4096 members are listed and 65,536 regular files examined.
- A member larger than 64 MiB is not extracted; extraction stops when the
  members reach 256 MiB in total. Notes count what was left out.
- Problems below the root are listed in up to 16 notes; further problems
  are counted. An unreadable or non-directory root inode is a parse error.

## Truncated filesystems

Containers decode at most 64 MiB of a component (`MAX_PAYLOAD`), so a
larger filesystem in a disk image, virtual disk or compressed stream
reaches this parser cut. Linux refuses such a filesystem
(`ext4_check_geometry`: "bad geometry: block count %llu exceeds size of
device"); this reader lists what the bytes present hold:

- Detection is unchanged: the superblock alone.
- The superblock (with its checksum), the descriptor of group 0 and the
  root inode's record must be present. Without them the image is the error
  it was before: `Truncated filesystem: N blocks of B need S B, P B
  present`.
- Block numbers, descriptor locations and inode record locations are still
  checked against the declared filesystem; a defect in the bytes present is
  an error or a note, as for a complete image.
- Group descriptors are read up to the first one past the end of the input
  (descriptor blocks follow the groups they describe, with and without
  `meta_bg`); inodes of the later groups are absent.
- An inode record, extent or indirect block past the end of the input is
  skipped, and a note counts the distinct blocks the walk asked for: "N
  metadata blocks that the walk needed (group descriptors, inode tables,
  extent or indirect blocks) lie past the X present; they were not read".
- A directory's blocks are read up to the first one past the end of each
  of its runs (the rest of the run lies past it too, so it is counted
  without being visited); its other runs are still read: "N directory
  blocks lie past the X present; their entries were not read".
- A regular file is listed only when every block of its data and every
  block that maps it is present. Others are counted: "N regular files were
  not listed: file data, or blocks that map it, lie partly or wholly past
  the X present".
- A note states "Volume truncated: X of Y present; files are listed only
  when all of their data is present"; the whole input is consumed.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| E1 | The variant name is libblkid's feature convention | `mke2fs -t ext2` and `-t ext4` fixtures are named `ext2` and `ext4`; a synthetic image with `has_journal` is named `ext3`; unit test `layouts_follow_the_libblkid_feature_convention`. No `mke2fs -t ext3` image was tested |
| E2 | Skipping htree index blocks loses no entries | `/many` in both fixtures is an htree directory (`e2fsck -D`); its member in a leaf block is listed. An empty leaf whose only record spans the block is also skipped, and it holds no entries |
| E3 | Directories have no holes, so mapping a directory up to the block count reads all of it | A sparse directory with entries beyond the block count would lose them; not tested |
| E4 | The first 4 KiB of a file decide whether it is a recognized format | A weak format that needs its whole input is not listed from a filesystem; not tested |
| E5 | Twice the filesystem size is enough metadata reading for a consistent filesystem | Both fixtures walk without reaching the limit; not tested on large real images |
| E6 | `meta_bg` descriptor blocks are where `descriptor_loc` puts them | Synthetic 33-group `meta_bg` image and the unit test `meta_bg_descriptor_blocks_follow_each_meta_groups_backup`; no `mke2fs -O meta_bg` image was tested |
| E7 | Inode checksums are defined only for a Linux creator OS | Follows `ext4_inode_csum_verify`; the fixtures are Linux-created; other creators were not tested |
| E8 | 64 KiB-block `rec_len` encoding follows `ext4_rec_len_from_disk` | Synthetic 64 KiB-block image with a `0xFFFF` record and the unit test `large_block_rec_len_encodes_the_high_bits_in_the_low_bits`; no real 64 KiB-block image was tested |
| E9 | Group descriptor blocks lie in the order of their groups, so the descriptors present are those before the first absent one | `descriptor_loc` places them after the superblock or, with `meta_bg`, in the first group of each meta group; a hostile superblock that breaks the order loses groups (they are reported absent), it never lists missing bytes |
| E10 | A truncated image is a prefix of the whole filesystem | `prefixes_are_truncated_filesystems_that_list_only_members_inside_them` checks every member of each sampled prefix of both fixtures against the whole parse; not tested on a real cut partition |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Inline data (`inline_data`) | Files and directories are not read; counted in a note |
| Encrypted files and directories | Opaque; not read; counted in a note. Entry names in encrypted directories are not decrypted |
| Journal | Not replayed. With `recover` set, a note says that file contents may be stale |
| Partition tables, filesystems at an offset | Not detected; only an image whose superblock is at file offset 1024 |
| Trailing data other than padding | Parse error, for example a disk dump with further partitions after the filesystem |
| Truncated images | Read as truncated filesystems when the root inode is present; files whose blocks are all present are listed, the rest counted. Files in directories whose blocks or inodes lie past the end are not known; only the metadata and directory blocks the walk asked for are counted |
| Bitmaps, htree index, extended attribute and journal checksums | Not verified |
| htree hashes | Not computed; entries are found by the linear read |
| Symlinks | Not followed; fast and slow symlinks are not read |
| `bigalloc` | Geometry checks implemented; not tested on a real image |
| Extended attributes, fs-verity Merkle trees, quota and orphan files | Not read |
| Files over 64 MiB | Not extracted |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly), `tests/ext.rs` (22
tests) and the 12 unit tests in `src/formats/ext/` passed, along with the
rest of `cargo test --all-features --locked` (535 passed, 6 ignored, none
of them ext tests). The integration tests use two `mke2fs` fixtures
(`tests/fixtures/ext/README.md`: ext2 with block maps and a double-indirect
block, ext4 with `64bit`, `flex_bg`, `metadata_csum` and a depth-1 extent
tree, both with an htree directory and hard links) and synthetic images
built from the `ext4.h` layouts (ext3, `gdt_csum`, `meta_bg`, 64 KiB
blocks, unwritten extents, encrypted and inline files, depth, cycle and
size limits). They include a parse of every prefix of both fixtures,
mutations (`0x00`, `0xFF`, bit flip) of every superblock byte, the first
64 B of the descriptor table, every inode record and every 97th byte of the
fixtures, and of every used byte of a synthetic image. `web/tests/ext.test.mjs` (4 tests) passed
through `/pkg/` and `/dist/` and in both workbench pages; the whole browser
suite passed 73 tests with 4 skips, which need D10 and RX113 firmware that
is not in the repository.

Not verified: images written by other tools (Android `make_ext4fs`,
`genext2fs`, BSD or Hurd), `mke2fs` images with `meta_bg`, `bigalloc`,
`inline_data`, `encrypt`, `casefold` or a journal, 64 KiB-block images
other than the synthetic one, filesystems larger than 512 KiB, and the
triple-indirect block map outside
the unit test `block_maps_resolve_direct_single_double_and_triple_indirect_blocks`.

Truncated filesystems, on 2026-10-13 (macOS 27.2 AArch64, rustc
1.100.0-nightly `f248f4038`): `tests/ext.rs` (23 tests) and the 13 unit
tests in `src/formats/ext/` passed within `cargo test --all-features
--locked` (2,425 passed, 6 ignored). The prefix sweep parses every prefix
of both fixtures up to one block past the root inode's record and, after
it, every 61st prefix and the prefixes at and around each block boundary:
each is the old "Truncated filesystem" error exactly when it ends before
the root inode's record, and otherwise a truncated filesystem whose members
are byte-identical to the whole image's and lie inside the prefix. The unit
test `blocks_past_the_end_of_a_truncated_filesystem_are_absent` covers an
indirect block past the end. `web/tests/ext.test.mjs` (4 tests) passed
through `/pkg/` and `/dist/`. A differential snapshot against the previous
commit over both fixtures (777,076 inputs: the whole images, every prefix
and single-byte mutations of every 7th byte and every 3rd of the first
16 KiB) changed 379,136 outcomes, all of prefixes whose filesystem exceeds
them: old "Truncated filesystem" errors that are now truncated
filesystems. Not verified: a real filesystem cut by a
container (no ext image larger than 64 MiB was at hand), and `meta_bg`
filesystems cut before a later meta group's descriptors.
