# Flash filesystems on raw MTD

`src/formats/mtd.rs` and its submodules `ubi.rs`, `ubifs.rs` and `jffs2.rs`
parse UBI images, UBIFS volume images and JFFS2 images into the shared
container model ([compressed streams and the container model](compressed-streams.md)).
None of these formats names a processor: UBI volumes are classified from
their own contents, and UBIFS and JFFS2 regular files are listed when they
are a recognized format, so the ISA comes from the files (ELF headers, nested
containers, or the code model).

## Implemented layouts

| JSON format ID | Layout | Recognition | Primary source |
| --- | --- | --- | --- |
| `ubi` | PEBs with a 64-byte erase-counter header (`UBI#`) and a 64-byte volume-identifier header (`UBI!`); header CRCs verified; PEB size discovered; volume table from the layout volume (`0x7FFFEFFF`), copy 0 or copy 1; each volume rebuilt from its LEBs in `lnum` order and listed as a child named after the volume | Strong: `UBI#` at offset 0 | Linux v6.11 `drivers/mtd/ubi/ubi-media.h`, `io.c` (`validate_ec_hdr`, `validate_vid_hdr`), `attach.c` (`ubi_compare_lebs`, `scan_peb`), `vtbl.c` (`vtbl_check`, `process_lvol`, `check_av`) |
| `ubifs` | Superblock node in LEB 0; every node in the main-area LEBs scanned (24-byte common header, magic `0x06101831`, CRC); inode, directory-entry, data and truncation nodes resolved by sequence number; regular files rebuilt from 4 KiB data blocks; recognized files listed with full paths | Strong: node magic and superblock node type at offset 0 | Linux v6.11 `fs/ubifs/ubifs-media.h`, `key.h`, `scan.c`, `io.c` (`ubifs_check_node`), `sb.c` (`validate_sb`), `super.c` (node length ranges), `file.c` (`read_block`) |
| `jffs2` | Nodes with magic `0x1985` in the image's byte order; header CRC (computed with `JFFS2_NODE_ACCURATE` set), node, name and data CRCs; inode and directory-entry nodes resolved by version; cleanmarkers, padding, summary and xattr nodes counted; regular files rebuilt from their data nodes; recognized files listed with full paths | Weak: every node and every CRC in the image must validate, with only erased (`0xFF`) or zeroed flash between nodes | Linux v6.11 `include/uapi/linux/jffs2.h`, `fs/jffs2/scan.c`, `readinode.c`, `nodelist.c`, `compr_rtime.c`, `compr_rubin.c`, `compr_zlib.c`, `compr_lzo.c`; `OpenWrt` v24.10.0 `530-jffs2_make_lzma_available.patch` |

The format variants are `UBI image`, `UBIFS image`, `JFFS2 image
(little-endian)` and `JFFS2 image (big-endian)`. Spec notes with the struct
offsets (compiler-verified against the kernel headers) were collected from
the same sources on 2026-10-12.

### Data encodings

| Container | Type | Decoder |
| --- | --- | --- |
| UBIFS | 0 none, 1 LZO, 2 zlib, 3 Zstandard | Stored; raw LZO1X (`Codec::Lzo1x`, the whole input must be consumed); raw DEFLATE (the kernel's `deflate` transform, window bits `-11`); Zstandard frames |
| JFFS2 | `0x00` none, `0x01` zero | Stored; zero fill |
| JFFS2 | `0x02` rtime | `Codec::Rtime`, a port of `jffs2_rtime_decompress` |
| JFFS2 | `0x03` rubinmips, `0x05` dynrubin | `Codec::RubinMips`, `Codec::DynRubin`, a port of `rubin_do_decompress` (fixed `bits_mips` table, or eight probability bytes before the coded bits) |
| JFFS2 | `0x06` zlib | A valid zlib header without a preset dictionary is skipped and the rest inflated as raw DEFLATE without the Adler-32, as `jffs2_zlib_decompress` does; otherwise a zlib stream |
| JFFS2 | `0x07` LZO | Raw LZO1X, whole input consumed |
| JFFS2 | `0x08` LZMA (`OpenWrt` only) | Raw LZMA with the encoder's fixed properties (`lc=lp=pb=0`, 8 KiB dictionary), decoded through the LZMA-alone decoder with a synthesized header and the declared size |

Other types (JFFS2 `0x04` copy, unknown UBIFS types) make the file
unsupported: it is named in a note and not extracted. The new codecs live in
`src/formats/compressed/lzo.rs` (`lzo1x_stream`) and
`src/formats/compressed/jffs2.rs`; they have no magic and map to
`FileFormat::Raw`.

## Wire units and byte order

All offsets and sizes are bytes. UBI headers and volume table records are
big-endian; UBIFS nodes are little-endian; JFFS2 nodes use the byte order of
the first node magic (`85 19` little-endian, `19 85` big-endian). None of
these is reported as the code byte order.

Checksums: UBI and UBIFS use `crc32(0xFFFFFFFF, ...)` without final
inversion (the zlib CRC-32 inverted); JFFS2 uses `crc32(0, ...)` without
final inversion. Both are computed with the reflected polynomial
`0xEDB88320` by `checksum::crc32_update`.

Coordinates: a UBI LEB of PEB `p` starts at `p * peb_size + data_offset`; a
UBIFS LEB `n` starts at `n * leb_size` (as `mkfs.ubifs` writes an image and
as a UBI volume is rebuilt); JFFS2 has no LEBs. Child `offset` and
`stored_size` are file coordinates of the stored bytes: for a UBI volume,
from the first LEB's data to the end of the last LEB's used bytes (other
volumes' PEBs may lie in between); for a file, from its first stored data
node to the end of its last. `decoded` gives the rebuilt size
(`UBI volume`, `UBIFS file`, `JFFS2 file`).

## Validation and resource bounds

- UBI PEB size: the smallest power of two from 512 B to 16 MiB, at least
  `data_offset + 172`, with a valid erase-counter header of PEB 0's geometry
  at an odd multiple of it (headers of a larger PEB size lie only at even
  multiples, and bad PEBs are skipped). Trailing bytes after the last whole
  PEB may only be padding.
- UBI headers: PEB 0's erase-counter header must be valid (version 1,
  offsets ordered, erase counter at most `0x7FFFFFFF`). A later header with a
  failed CRC, or a bad block, is counted and skipped, as the kernel's attach
  does; a header whose CRC matches but whose fields contradict PEB 0 or the
  image sequence is an error. VID headers are checked as `validate_vid_hdr`
  does. Two copies of a LEB with the same sequence number are an error.
- UBI volume table: a copy whose record CRC fails (or whose name length
  disagrees with the name) is corrupt and the other copy is used; a record
  that is invalid with a matching CRC is an error. Volume IDs must fit the
  table's `min(128, leb_size / 172)` slots. A volume with the update marker
  set, a static volume missing a LEB, or a static LEB whose data CRC fails is
  listed as opaque with the reason.
- UBIFS superblock: node length 4096 and CRC; simple key format; LEB size
  15 KiB to 16 MiB (own upper bound); power-of-two minimum I/O size; area
  sizes within the LEB count; fanout and format version (3 to 5, or newer
  with read-only compatibility version 0) as `validate_sb` checks them. A
  node fault in a main-area LEB stops the scan of that LEB with a note; the
  nodes before it are kept.
- UBIFS nodes: per-type length ranges from `super.c`, 8-byte alignment,
  padding nodes and `0xCE` padding bytes, erased flash to the end of the
  LEB. At most 1,048,576 nodes are recorded (own bound).
- JFFS2: every node must validate; an unknown node type with the
  incompatible feature bits is an error, other unknown types are counted.
  A node that must be decoded may declare at most 64 KiB (own bound: the
  largest Linux page size); zero-fill nodes may cover any range.
- Trees: paths follow directory entries to the root inode (1 in both
  filesystems) through at most 128 levels and 4096 bytes; cycles and
  orphans are counted as unreachable. Paths are built for at most 65,536
  regular files (own bound).
- Extraction: a member's first 4 KiB are assembled first and only a
  recognized format is extracted. At most 4096 children per container
  (`MAX_COMPONENTS`), 64 MiB per file (`MAX_PAYLOAD`) and 256 MiB of listed
  contents per container (`MAX_EXTRACTED`). Decoding and zero fill while
  assembling, including recognition prefixes and data that later nodes
  overwrite, stop after 512 MiB per container (own bound,
  `MAX_DECODE_WORK`), so overlapping nodes and hard links cannot multiply
  the work. Hard links reuse the first examination of their inode. What was
  left out is counted in notes.
- Container nesting is capped at six levels by `lib.rs`, so a UBIFS volume
  inside a UBI image is classified with its own bounds.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| M1 | The PEB size is a power of two and erase-counter headers repeat at it | `peb_size_is_the_first_power_of_two_with_a_matching_header`, `peb_size_discovery_skips_bad_blocks`; a NOR part with a non-power-of-two erase block would fail to parse |
| M2 | The highest sequence number wins for UBI LEB copies, unless the newer copy's copy flag is set and its data CRC fails | `ubi_leb_copies_resolve_by_sequence_number_and_copy_crc` |
| M3 | Scanning every UBIFS main-area node and keeping the newest per key gives the live tree, as a journal replay would | `ubifs_newest_sequence_numbers_win_over_flash_order`, `ubifs_deletions_and_truncations_are_applied`; an image whose deletion entries were garbage-collected while older entries survive would show deleted files (see known boundaries) |
| M4 | UBIFS inode numbers are not reused (`highest_inum` only grows), so old data nodes never join a new file | Not tested; a reused inode number would merge data blocks into holes of the new file |
| M5 | A JFFS2 file is its inode nodes applied in version order, truncated to the newest node's `isize` (`jffs2_do_read_inode_internal`) | `jffs2_newer_versions_overwrite_older_data_and_set_the_size` |
| M6 | The rtime and rubin ports decode what the kernel encoders write | Round trips through ports of `jffs2_rtime_compress` and the rubin encoder, and an `mkfs.jffs2` rtime image (`mkfs_jffs2_images_decode_in_both_byte_orders_and_every_codec`); rubin is not verified against kernel-written data |
| M7 | `OpenWrt` JFFS2 LZMA nodes are raw LZMA with properties `0x00` and an 8 KiB dictionary | A Python `lzma` `FORMAT_RAW` stream with those properties (`jffs2_lzo_lzma_and_dynrubin_nodes_decode`); not verified against an `OpenWrt` image |
| M8 | A 16-bit magic plus every CRC is enough to recognize JFFS2 without false positives | `jffs2_requires_every_crc_and_rejects_unknown_incompatible_nodes`, `jffs2_prefixes_are_recognized_only_at_node_boundaries` |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| UBIFS index | Not walked; the tree comes from a node scan. After garbage collection removed deletion entries, a scan can list files the index no longer has |
| UBIFS encryption and authentication | Encrypted files (`UBIFS_CRYPT_FL`) are named and not extracted; HMACs and signatures are not verified |
| UBIFS name hashes, minimum I/O alignment, LPT and orphan areas | Not checked or not read |
| UBI fastmap | Ignored; every PEB is scanned |
| UBI dynamic volumes | Rebuilt up to the highest mapped LEB; unmapped LEBs below it read as `0xFF`, reserved LEBs above it are not materialized |
| UBI `vtbl_check` device checks | Alignment against the minimum I/O size and reserved PEBs against the device size are not checked, because an image does not record the device |
| JFFS2 erase blocks | The size is not recorded; nodes crossing erase-block boundaries are not detected |
| JFFS2 summary, xattr and xref nodes | Counted, not interpreted |
| JFFS2 `JFFS2_COMPR_COPY` (`0x04`) | No kernel decoder; files using it are noted and not extracted |
| JFFS2 inode reuse after deletion on NAND | Not modelled; stale nodes of a deleted inode with higher versions could mix into a new file with the same number |
| Raw NAND dumps | Spare (OOB) areas are removed by the generic transform in `src/transform.rs` when the stored dump does not parse (`ubi_nand_dump_with_spare_areas_parses_after_spare_removal`); ECC is not applied |
| Symlinks, devices, FIFOs, sockets | Counted as other entries, not listed |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly 2026-09-05), with the
fixtures generated by mtd-utils 2.2.1 on 2026-10-12
([provenance](../tests/fixtures/mtd/README.md)):

- `tests/mtd.rs`: 33 tests passed, covering both JFFS2 byte orders and every
  implemented JFFS2 codec except rubinmips (rtime, zlib and LZO from
  `mkfs.jffs2`; LZMA, LZO and dynrubin synthetic), UBIFS with LZO, zlib,
  Zstandard and stored blocks (synthetic) and an `mkfs.ubifs` LZO image, UBI
  static and dynamic volumes (synthetic) and a `ubinize` image with a
  Zstandard UBIFS volume, every-prefix sweeps of each synthetic layout, and
  0x00/0xFF/bit-flip mutation sweeps of synthetic and tool-made images.
- Unit tests in `src/formats/mtd*` (17) and the new codec tests in
  `src/formats/compressed/jffs2.rs` and `lzo.rs` (5) passed. rubinmips is
  verified only by a round trip through a port of the kernel encoder.
- `web/tests/mtd.test.mjs`: 4 tests passed through `/pkg/zrax.js`,
  `/dist/zrax.js`, `/web/index.html` and `/dist/index.html`.
- The full native suite (`cargo test --all-features --locked`: 555 passed,
  6 ignored) and the full browser suite (73 passed, 4 skipped because the
  D10 and RX113 firmware is not in the repository) passed.

Not verified: images written by a running kernel (all fixtures come from
the offline tools or from the tests), rubinmips and dynrubin data from the
kernel compressors, `OpenWrt` LZMA nodes, fastmap images, and big-endian
UBIFS (which does not exist on flash).
