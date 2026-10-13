# Compressed and packed disc containers

`src/formats/discimg.rs` and its submodules (`gcz.rs`, `ciso.rs`, `wbfs.rs`,
`cso.rs`) parse the containers that console disc images are stored in:
Dolphin GCZ, GameCube and Wii CISO, WBFS (Wii Backup File System) and PSP
CSO and ZSO. They build on the shared container model
([compressed streams and the container model](compressed-streams.md)). Each
container decodes to one disc per child (WBFS: one per used slot), and the
child is classified on its own, so the console disc parsers
([console disc images](discs.md)) or [ISO 9660](iso9660.md) describe it.
None of these containers names an ISA: the container target is always
unknown, and the ISA comes from the decoded disc.

## Implemented layouts

| JSON format ID | Variant | Layout | Recognition | Children | Primary source |
| --- | --- | --- | --- | --- | --- |
| `gcz` | `GCZ disc image` | 32-byte header (magic, sub-type, compressed data size, data size, block size, block count); 64-bit block pointers (bit 63: stored as-is); one Adler-32 per block; zlib blocks of the block size | Strong: 0xB10BC001 (little-endian) at 0, a power-of-two block size and a block count of `ceil(data size / block size)` | `Disc image` (transform `GCZ`) | Dolphin `2606` `CompressedBlob.h`, `CompressedBlob.cpp`, `DiscUtils.cpp`, `DolphinTool/ConvertCommand.cpp` |
| `ciso` | `CISO disc image` | 0x8000-byte header: `CISO`, block size (little-endian), a map of 0x7FF8 bytes (0 unused, 1 used); used blocks in map order from 0x8000 | Strong: `CISO`, a block size that is a nonzero multiple of 32 KiB, and 0 or 1 in every map byte present (up to 0x8000); at least 0x18 bytes | `Disc image` (transform `CISO`) | Dolphin `2606` `CISOBlob.h`, `CISOBlob.cpp`; wit `fc1c0b840cb3` `lib-ciso.h`, `lib-ciso.c` |
| `wbfs` | `WBFS image` | Head (`WBFS`, partition size in hd sectors, big-endian; hd and WBFS sector shifts; version; disc table); one disc info per slot in WBFS sector 0 (a copy of the disc header's first 0x100 bytes, a big-endian WBFS sector per disc block, 0 when not allocated) | Strong: `WBFS`, a nonzero partition size, an hd sector of 512 B to 32 KiB and a WBFS sector of 32 KiB to 2 GiB | `Disc slot <n> (<game ID>)` per used slot (transform `WBFS`) | wit `fc1c0b840cb3` `libwbfs/file-formats.h`, `libwbfs.h`, `libwbfs.c`, `wbfs-interface.c`; Dolphin `2606` `WbfsBlob.h`, `WbfsBlob.cpp` |
| `cso` | `CSO v1 image` | 0x18-byte little-endian header (`CISO`, header size, uncompressed size, block size, version 0 or 1, index shift); `blocks + 1` index entries (31-bit position shifted by the index shift; high bit: stored as-is); raw DEFLATE blocks | Strong: `CISO`, a power-of-two block size of at least 2 KiB and a version of 0 to 2, when the input is not a GameCube CISO | `Disc image` (transform `CSO`) | maxcso v1.13.0 `README_CSO.md`, `src/input.cpp`; PPSSPP v1.17.1 `Core/FileSystems/BlockDevices.cpp` |
| `cso` | `CSO v2 image` | As v1 with version 2: header size 0x18 and unused bytes 0 required; a block stored in at least the block size is stored as-is, others are LZ4 (high bit) or DEFLATE; the final entry's high bit clear | As v1, version 2 | `Disc image` (transform `CSO`) | maxcso v1.13.0 `README_CSO.md` ("Format (version 2)"), `src/input.cpp` |
| `cso` | `ZSO image` | As v1 with `ZISO` and raw LZ4 blocks | Strong: `ZISO`, the same header checks | `Disc image` (transform `ZSO`) | maxcso v1.13.0 `README_ZSO.md`, `src/cso.h`, `src/input.cpp` |

ZSO is reported as `cso` with its own variant: maxcso describes it as the
CSO v1 format with another magic and codec.

Sources, fetched on 2026-10-13:

| Source | Pin | Files and SHA-256 | Used for |
| --- | --- | --- | --- |
| Dolphin | tag `2606`, commit `6094cfcf7b8fba733b3116fdf3414d51c1c0e4a4` | `Source/Core/DiscIO/CompressedBlob.h` `e1028248b1831ddedf29678c7df1d10c0cb0c1a7e502968c70a29471953f5610`, `CompressedBlob.cpp` `c258763f88360f6235a8f7cd995bf97f2d9feab0e4c358638e6b8c2976671a08`, `CISOBlob.h` `ce6f1d4a0ebf50235efad4d9c8870e7bfa5ebed84cf6505f153a9fd2aab590d3`, `CISOBlob.cpp` `0eb02ea4515a9566df327033bfc7008fe4708aeb8bb459fe07e58a03fc911f75`, `WbfsBlob.h` `421c86c78ea736817a28a10c2961b40d5224824b0ab6c4b3c7d803eb9a94e20c`, `WbfsBlob.cpp` `4891bc43184df9f89aef492fc5c09ad4aa657e7e060c705d5c456d5297ffd2d0`, `Blob.cpp` `bc8e3ba16d132bf8c5a5b9aaad89dc81c1f5a7b0bf72f01597bc8ececf805ece`, `DiscUtils.h` `88e3992519ff6d77a3ccddff3ff9d3eb16b5add6e20efea67820b2656be6f046`, `DiscUtils.cpp` `d3d0234d3aeff9bb2fb49d402bac20236c2aee632fd2916863a5b4c0d5df5a71`, `Source/Core/DolphinTool/ConvertCommand.cpp` `d965160a5969dc6582dacbf2e537eed0d98667b7b6ed1ae6cf13348eb1788da0` | GCZ header, tables, codec, hash scope and mismatch handling; CISO header and reads; WBFS header checks and slot 0 reads; GCZ block size rule and sub-types |
| Wiimms ISO Tools | commit `fc1c0b840cb3ac41ca6e4f1d5e16da12b47eab58` (2022-08-27) | `project/src/libwbfs/file-formats.h` `130a976473c07e00498e28e04cc536b9e3a7835d7664087ad23c612c055ab76f`, `libwbfs/libwbfs.c` `b5d35d304bf4d76a244613552a740ceec62e51512eb2fa0d03443f21ed2819e7`, `lib-ciso.h` `5a745a6c3220fb60487f41218c9f1dc423c27fdcd501848d28df9ff2c40dbd53`, `lib-ciso.c` `b1006f107fbe45db32eb633e6eeefb72355914f00383361bf7180a4b9fc670a0`, `wbfs-interface.c` `62762d4bc0d15e0589b3e04e27ac77c9caa0b75c5ee2dbb9278dc1446f64bb0b` | WBFS head and disc info layout, geometry, slot values, block validity; CISO block size and map validation, disc size |
| PPSSPP | tag `v1.17.1`, commit `d479b74ed9c3e321bc3735da29bc125a2ac3b9b2` | `Core/FileSystems/BlockDevices.cpp` `9f408b465b9bcd5042a6b219caced6dd9a62211e95dc6d47f8802df306356294` | CSO header, block size rule, index, raw DEFLATE, plain blocks, expected file size |
| maxcso | tag `v1.13.0`, commit `80e6e8349814dd5c96e6504140d09afd4ecde1fe` | `README_CSO.md` `f522835a699c55b87c07f993f7242641f978350c46880474229d76a04df69635`, `README_ZSO.md` `58d4e3cd659b8989e0b1969e76154b3a7096b95bdc5663910e3f3eed88cc5449`, `src/cso.h` `40c8e1c435d3a1ffec72616f1d0739f2b5a2557fb21ce4f4d8b2ab0f158ef09c`, `src/input.cpp` `b2c267c95427bef630de61a2575fffa18c90e7f7683bcd4df25d34ad8b79caea` | CSO v1 and v2 and ZSO layouts, index padding, LZ4 decoding past padding, version and block size limits |

## Children and classification

- **One child per disc.** The child holds the first `min(disc size,
  64 MiB)` bytes of the disc. Blocks that are not stored (CISO map entry 0,
  WBFS sector 0) read as zeros. A disc larger than 64 MiB gets the note
  "`<label>` is N B; only the first 64 MiB were decoded and are analyzed".
  The child is classified like any other component (`Classify::Always`),
  so a GameCube disc reports its DOL and apploader as PowerPC, a Wii disc
  its opaque partitions, and an ISO 9660 image its files.
- **Disc sizes.** GCZ: the data size. CSO and ZSO: the uncompressed size.
  CISO: the end of the last used block (wit's `max_virt_off`; Dolphin
  reports the whole map, 0x7FF8 blocks, as an upper bound). WBFS: the end of
  the last allocated block, at most a dual-layer disc (143432 * 2 Wii
  sectors of 32 KiB); WBFS records no disc size, and Dolphin reports the
  dual-layer size for every disc.
- **WBFS slots.** Every slot whose disc table byte is nonzero is read, in
  slot order, and labeled with the game ID of its disc header copy. Dolphin
  reads only slot 0; libwbfs reads them all. A used slot whose disc info
  would lie outside WBFS sector 0, or that has no allocated block, has no
  child and a note. The primary ISA comes from the first disc that has one:
  a Wii disc's partitions are encrypted, so a GameCube disc in a later slot
  supplies it.
- **Stored coordinates.** A child's offset and size give the stored bytes:
  the block data after the GCZ tables, the used CISO blocks after 0x8000,
  the CSO data area after the index, or for WBFS the first run of
  consecutive WBFS sectors of the disc (its blocks may be scattered and
  shared with other discs). The decoded range carries the transform name.
- **Notes and metadata.** Notes give the block counts and how each block is
  stored, the disc size, the GCZ sub-type (0 GameCube, 1 Wii, all ones not
  set; DolphinTool `ConvertCommand`), the GCZ hash result, the WBFS
  geometry and each slot's allocation, and that the container names no
  ISA. Metadata: `gcz_*` (sub-type, block size, blocks, stored blocks, disc
  size, compressed data size), `ciso_*` (block size, used blocks, disc
  size), `wbfs_*` (hd sector size, partition size, WBFS sector size, used
  slots, version), `cso_*` (version, block size, index shift, disc size),
  plus `<prefix>_image_size` and one `<prefix>_component_<n>` per disc.

## GCZ block hashes

The GCZ table holds one Adler-32 per block. It covers the stored bytes: the
zlib stream, or the raw block. `Compress` in `CompressedBlob.cpp` hashes the
bytes it writes and `GetBlock` the bytes it reads; the header comment
"hash of decompressed data" does not match the code. Every block that lies
in the file is checked, decoded or not, which costs one pass over the file.

A mismatch is a note, not an error: `GetBlock` logs "is corrupt ... Hash of
block N is X instead of Y" and still returns the block, so the disc Dolphin
presents does not change. The note gives the count and the first block with
both values. A decoded block must still be a valid zlib stream whose own
Adler-32 (of the decoded bytes) matches and that decodes to exactly the
block size, which `GetBlock` requires ("Wrong block size"); anything else is
a parse error naming the block.

## Wire units and byte order

All offsets and sizes are bytes. GCZ, CISO, CSO and ZSO headers and tables
are little-endian (Dolphin writes GCZ in host order and documents it as not
big-endian safe; the CISO block size is "stored as little endian"; CSO and
ZSO are little-endian by maxcso's documents). WBFS fields are big-endian.
WBFS positions are in hd sectors (the partition size) and WBFS sectors (the
block table), both from the start of the file. CSO index positions are
`(entry & 0x7FFFFFFF) << index_shift` bytes. Header byte order says nothing
about the code inside the disc.

## Validation and resource bounds

- GCZ: block size a power of two (Dolphin's writer rule), 512 B to 64 MiB
  (our bounds); block count `ceil(data size / block size)`; both tables
  inside the file before they are read; block pointers non-decreasing and
  within the compressed data size; a block stored as-is exactly the block
  size.
- CISO: block size a nonzero multiple of 32 KiB (wit `SetupCISO`); the
  whole 0x8000-byte header present; every map byte 0 or 1.
- WBFS: the shift ranges above; the head sector present; each used slot's
  disc info inside WBFS sector 0 and inside the file; every allocated block
  below the partition's WBFS sector count (`n_wbfs_sec`, at most 0xFFFF;
  wit reports others as "invalid WBFS block").
- CSO and ZSO: block size a power of two of at least 2 KiB (PPSSPP) and at
  most 64 MiB (our bound; maxcso writes at most 256 KiB); version at most 2
  (maxcso); index shift at most 32 (our bound: a 31-bit position shifted
  further would pass 2^63); the index inside the file before it is read;
  positions non-decreasing and the first one after the index; for version
  2, header size 0x18, unused bytes 0 and the final entry's high bit clear.
  Each block must hold every disc byte of its block: the block size, or the
  rest of the disc for the last block (PPSSPP wants the block size from
  every block; maxcso trims the last block's output).
- Truncation: a file shorter than the end of its stored data (a truncated
  image, or the first part of a split WBFS) gets a note; a block that the
  decoded prefix needs and that lies outside the file is a parse error.
  Bytes after the stored data must be zero or 0xFF padding.
- Bounds: each disc is decoded up to 64 MiB (`MAX_PAYLOAD`); every codec
  call goes through `compressed::decode_limited` or `decode_prefix` with the
  block size as the limit. WBFS decodes at most 256 MiB across its discs
  (`MAX_EXTRACTED`) and lists at most 4096 (`MAX_COMPONENTS`), with notes for
  what was left out. Every table is validated against the file size before
  it is allocated or walked, and every loop is bounded by the input.

## Detection position

The checks run before the console disc and ISO 9660 checks in
`detect_format`: a CISO keeps its block map where the Wii and GameCube
magics are looked for (0x18, 0x1C) and stores the disc's first block at
0x8000, where ISO 9660 looks for its volume descriptor. Every layout starts
with its own magic at offset 0, and no earlier check recognizes those
magics.

A GameCube CISO and a PSP CSO both start with `CISO`. The GameCube block
size at 0x04 must be a multiple of 32 KiB, where a PSP CSO has its header
size (0 or 0x18 in practice), and every GameCube map byte is 0 or 1, where a
PSP CSO's index at 0x18 holds file offsets past 0x18. The GameCube check
runs first; a PSP header whose header size field reads as a block size still
fails the map check at its index
(`ciso_and_psp_cso_are_told_apart_by_their_structure`).

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| D1 | GCZ hashes cover the stored bytes, not the decoded ones | A Dolphin-written GCZ whose hashes match `adler32` of the decoded blocks instead would report a mismatch for every compressed block |
| D2 | Every GCZ block, including the last, decodes to the block size | `ConvertToGCZ` pads the last block; a GCZ from another writer with a short last block is a parse error (`decodes to N B instead of the B B block size`) |
| D3 | The GCZ sub-type is informative | It is noted and never used for classification; the disc's own magic decides |
| D4 | A CISO disc ends with its last used block | A disc with trailing unused blocks decodes shorter than Dolphin's upper bound; the missing bytes would be zeros in Dolphin too |
| D5 | WBFS block 0 entries of value 0 mean "not allocated" and read as zeros | libwbfs writes 0 for unused blocks (`wbfs_add_disc`); Dolphin would read WBFS sector 0 for them instead |
| D6 | WBFS has `286864 >> (wbfs shift - 15)` blocks per disc (libwbfs, rounded down) | Dolphin rounds up, reading one more entry from the disc info's padding; a WBFS whose extra entry is nonzero would decode differently in Dolphin |
| D7 | Any nonzero disc table byte marks a used slot | wit's slot values 1, 2 and flags 4/8 are all nonzero; Dolphin requires slot 0 nonzero |
| D8 | CSO and ZSO index entries start at 0x18 whatever the header size field says | maxcso reads the index at `sizeof(CSOHeader)`; PPSSPP uses the field only for version 2, which must hold 0x18 |
| D9 | A ZSO or CSO v2 LZ4 block decodes until it reaches the block size, ignoring padding after it | maxcso decodes with `LZ4_decompress_safe_partial` for this reason; the `zso_lz4_blocks_with_alignment_padding_decode` test pads every block |
| D10 | A file shorter than its stored data is a truncated or split image whose missing blocks are not in it | Only blocks the decoded prefix needs are required; a damaged index that points past the end of the file is a parse error only when such a block is needed |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Split WBFS images (`.wbf1`, ... parts) | Only the given file is read; blocks in other parts are outside the file (a note, or a parse error when the decoded prefix needs them) |
| Discs larger than 64 MiB | Only the first 64 MiB are decoded and classified |
| Dolphin WIA, RVZ, TGC and NFS containers | Not implemented (other magics, not part of this family's sources) |
| maxcso DAX and JISO/CISO variants other than v1, v2 and ZSO | Not recognized |
| WBFS free-block table and inode info (`wbfs_inode_info_t`) | Not read |
| WBFS disc header copy | Only its game ID is used, for the label; it is not compared with the disc's own header |
| Wii partitions inside any container | Encrypted; the Wii disc parser keeps them opaque |
| Signatures, tickets and partition hashes of the discs | Not verified |

## Verification

Not verified against real files: no GCZ, CISO, WBFS, CSO or ZSO image was
available. IDA's test inputs (`IDA_INPUT_DIR`) were scanned on 2026-10-13
for files starting with the four magics and held none. All fixtures are
synthetic, built in the tests from the layouts above around a synthetic
GameCube disc, a synthetic Wii disc and the committed bsdtar ISO 9660 image
(`tests/fixtures/iso9660/joliet.iso.gz`); none of the writers (Dolphin,
wit, maxcso, ciso) is installed locally.

On 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly `f248f4038`,
Node v25.8.1 with Playwright Chromium):

- `tests/discimg.rs`: 27 tests passed, including every-prefix truncation
  sweeps of the GCZ, CSO v1, CSO v2 and ZSO fixtures (every prefix is a
  parse error), strided truncation sweeps of the CISO and WBFS fixtures
  (every prefix errors or decodes the same disc), and 0x00/0xFF/bit-flip
  mutation sweeps of every fixture (every byte of the GCZ fixture; headers,
  tables and sampled data of the others) through the parser and
  `detect_payload`. The `IDA_INPUT_DIR` test ran against IDA's test inputs
  and found no disc container.
- Unit tests in `src/formats/discimg*` (11) and the new raw LZ4
  stop-at-limit test in `src/formats/compressed/lz4_block.rs` passed.
- `cargo test --all-features --locked`: 1880 passed, 0 failed, 6 ignored
  (the existing ignored tests).
- `web/tests/discimg.test.mjs`: 4 tests passed (GCZ, CISO, WBFS, CSO and
  ZSO built in the test, through `/pkg/zrax.js` and `/dist/zrax.js`, and the
  workbench pages); the whole browser suite: 212 passed, 4 skipped (the
  D10/RX113 firmware tests, whose firmware is not in the repository).

After integration on the same day, the native suite passed 2,029 tests
with 6 ignored, and IDA's corpus (4,621 files) classified as before.
