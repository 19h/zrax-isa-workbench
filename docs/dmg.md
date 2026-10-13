# Apple disk images

`src/formats/dmg.rs` and its submodules (`koly.rs`, `plist.rs`, `rsrc.rs`,
`blkx.rs`, `udif.rs`, `encrypted.rs`) parse Apple UDIF disk images
(`.dmg`) and recognize encrypted disk images, in the shared container
model ([compressed streams and the container model](compressed-streams.md)).
`src/formats/compressed/adc.rs` adds the Apple Data Compression codec that
UDIF chunk type `0x80000004` uses. A disk image stores a disk, not code, and
names no ISA: the container target is always unknown. Each volume
partition becomes a child that is classified on its own, so the filesystem
or partitioned disk inside reports itself and supplies the primary ISA.

## Implemented layouts

| JSON format ID | Variant (`format.variant_name`) | Layout | Recognition | Primary source |
| --- | --- | --- | --- | --- |
| `appledmg` | `UDIF disk image` | 512-byte `koly` trailer at the end; data fork; block tables (`mish`) in an XML property list or a binary resource fork; chunks: zero fill, raw, ignore, ADC, zlib, bzip2, LZFSE, LZMA (xz), comment, end | Strong: `koly`, version 4 and header size 512 in the last 512 bytes; the data fork, XML property list and resource fork lie before the trailer; the property list starts with `<?xml version` where the trailer puts it (or, with no property list, the resource fork starts with a resource header that fits it) | libdmg-hfsplus `includes/dmg/dmg.h`, `dmg/io.c`; 7-Zip `DmgHandler.cpp`; darling-dmg `src/dmg.h`, `src/DMGDisk.cpp` |
| `appledmg` | `Encrypted disk image (encrcdsa)` | Encrypted Encoding version 2 header at 0 (block cipher, block size, data size and offset, key protector count), then the encrypted data | Strong: `encrcdsa` and version 2 at offset 0 | libdmg-hfsplus `includes/dmg/filevault.h`; dmg2img `vfdecrypt.h`; apfs-fuse `DiskImageFile.cpp`; keramics `cdsaencr.md` |
| `appledmg` | `Encrypted disk image (cdsaencr)` | Encrypted data, then a 1276-byte Encrypted Encoding version 1 footer | Strong: `cdsaencr` in the last 8 bytes of a file of at least 1276 bytes | apfs-fuse `DiskImageFile.cpp` (`DmgCryptHeaderV1`); keramics `cdsaencr.md` |

Apple publishes no UDIF specification; the layout comes from the readers
below, and every field the parser checks was confirmed against images
`hdiutil` wrote (see [fixtures](../tests/fixtures/dmg/README.md)). Sources,
fetched on 2026-10-13:

| Source | Pin | SHA-256 of the fetched file | Used for |
| --- | --- | --- | --- |
| libdmg-hfsplus `includes/dmg/dmg.h` | planetbeing/libdmg-hfsplus `7ac55ec64c96f7800d9818ce64c79670e7f02b67` | `ea24d800b634cafc250a1a3fed8e130ee5f638245d4407ff8043a3fcb52de21c` | `UDIFResourceFile`, `BLKXTable`, `BLKXRun`, chunk types, checksum type 2 |
| libdmg-hfsplus `dmg/io.c` | same | `87658bdb293eca6a46bebf6b565f7b79c8e5ee2875645ca8cb217bc3539f047d` | `extractBLKX`: chunk positions, zero, ignore and raw chunks |
| libdmg-hfsplus `dmg/resources.c` | same | `23c35db31e4b52b154e56c8a8a17fa8b493ec8acea9bbe8abff5c5fc6e400374` | Property list layout, big-endian table fields |
| libdmg-hfsplus `dmg/dmglib.c`, `dmg/checksum.c` | same | `27496e41694887b71acfaafac13bc693afdb8840ce4b6b6323c41b13b72542de`, `c8ef3ff9a934731424aaea8a391b023d4c84c65b86fed75d21c75eeba9ffcb44` | Data fork, table and master CRC-32 (IEEE polynomial) |
| libdmg-hfsplus `dmg/adc.c` | same | `cff4e41b8a3b771629a4a7084d308cf95329f9780e68aef56d890a771f230ed1` | ADC tokens |
| libdmg-hfsplus `includes/dmg/filevault.h` | same | `928b7000d2c92d484139fce838dad18111dac257ce93732cbe8e64c5dfb60389` | `encrcdsa` header |
| 7-Zip `CPP/7zip/Archive/DmgHandler.cpp` | ip7z/7zip `9128b80e3a471108678e2b3ec3c985861c8d7b0f` | `62ba133aef4962c0a624ac05b689d45a78562c395a3151db2e077340073b63fb` | Trailer and fork range checks, `CFile::Parse` table validation, chunk position (data fork offset + data start + compressed offset), `NeedCrc` (ignore chunks left out of the table CRC), master CRC, data fork CRC, resource fork mode, type `0x80000008` as xz, ADC decoder, map partition names, the code-signature pair at 0x128 |
| darling-dmg `src/dmg.h`, `src/DMGDisk.cpp`, `src/DMGPartition.cpp` | darlinghq/darling-dmg `1a6de10c5886c40a414090701b2520bd0417ce29` | `5e27a3bfec0f8e2efeac8cb960a668731f6d85872b923e2f6ad1bdb562ef4bf5`, `cf6fea1ca0719dc6c9cad571d56f4c2628151e8fcd2a13edc3c3fd10f309b0e9`, `dcf0c9217d7937ff80f7b6fde39e00993537fab58b465f7498c30354409a9072` | Trailer at the end, `CFName`/`Name`, `name (type : n)` names, chunks relative to the data fork |
| dmg2img `vfdecrypt.h`, `vfdecrypt.c`, `adc.c` | Lekensteyn/dmg2img `a3e413489ccdd05431401357bf21690536425012` | `a3bf8ab56a3b37d6a4b3fe359eb60824ea0ca9c02d2d4735a13d9623436f7eb8`, `808d3e8f55d3a0c17b6fb923d658a81cfabf514ae7e65a02181b9d9052ab4a8c`, `281952504990cb38a00112add0effa5e74c81164c337a88a22d59bff9d3d0b94` | Encrypted headers; data decrypted in whole blocks |
| apfs-fuse `ApfsLib/DiskImageFile.cpp` | sgan81/apfs-fuse `66b86bd525e8cb90f9012543be89b1f092b75cf3` | `aaddd6b689459ce9eb80066e802fe66b3a88092b06d864402af9530e50c5f042` | `DmgCryptHeaderV1` (0x4FC bytes, signature last), `DmgCryptHeaderV2`, detection order |
| keramics `docs/formats/src/udif.md`, `cdsaencr.md`, `adc.md` | keramics/keramics `4712c949645a1499635bc109692d4a9aedb9ba01` | `5ebe53697dcd7a1792a64c417571c1b5e121c93ca6ae01ad52e88d1d6bd3780d`, `2cd58a2c0b2b2d5e362d9b226b588f842fa6827bcefb0327e19d83acdf311724`, `c77bb38518127423bd6f48e571206099d0390a2fa1c701430064ceecc4d64fb7` | Cross-check of the trailer, table and chunk fields, flags, image types, CSSM algorithm IDs (`0x80000001` AES) |
| Apple, *Inside Macintosh: More Macintosh Toolbox* (1993), chapter 1, "Resource File Format", pp. 1-121 to 1-124, Figures 1-11 to 1-17 | `MoreMacintoshToolbox.pdf` from the Apple developer documentation archive | `8feb303c0f375a3bb7b1ef0309ec3746f075e26a43cb2e16bd285791e3d73bc8` | Resource header, data, map, type list, reference list, name list |

## The partition children

- **One table per partition.** Each `blkx` entry is a block table for one
  partition of the disk (`hdiutil` writes a GPT or MBR disk as tables for
  the protective MBR, GPT header and table, free space, the volume, and the
  backup GPT; Apple's developer disk images hold one `Whole_Disk` table).
  The child's label is the table's `CFName` (else `Name`), trimmed, e.g.
  `disk image (Apple_HFS : 4)` or `(DOS_FAT_32 : 1)`.
- **Volumes only.** Tables whose partition type (the `type` of a
  `name (type : n)` name, else the whole name) contains `Apple_Free`,
  `DDM`, `Apple_partition_map`, `GPT`, `MBR`, `Driver`, `Patches` or the EFI
  system partition GUID (7-Zip's list of names that are not file systems)
  are decoded to verify their checksums but never become children: a
  protective MBR or a GPT header without the disk it maps describes nothing.
- **Assembled or sliced.** A partition stored as one raw chunk is a
  borrowed slice of the file at that chunk. Otherwise its first
  `min(size, 64 MiB)` bytes are assembled: zero-fill and ignore chunks as
  zeros, raw chunks copied, compressed chunks decoded through
  `compressed::decode_limited` (zlib, bzip2, LZFSE, xz) or the new ADC
  codec. The child's stored range is the span of the file that holds its
  chunks, and its `decoded` range names the chunks: `UDIF zlib chunks`,
  `UDIF bzip2 chunks`, `UDIF LZFSE chunks`, `UDIF LZMA chunks`,
  `UDIF ADC chunks`, `UDIF raw chunks`, or `UDIF chunks` when they mix.
- **Recognized formats only.** A volume is listed when its bytes are a
  recognized format (`container::is_recognized` on the decoded bytes);
  otherwise a note names it as not classified. Volumes are pushed in table
  order and decoded before the map tables, so the extraction budget goes to
  them first.
- **Checksums.** The data fork CRC-32 is verified when the trailer stores
  one and the data fork is at most 64 MiB; the master CRC-32 over the
  tables' checksum values is verified whenever there are tables (a later
  segment of a segmented image has none); each table's CRC-32 is
  verified when its whole partition was decoded (or holds only free space,
  whose CRC-32 is 0). A mismatch is a parse error. Notes say which were
  verified and which not, and why.
- **Encrypted images** are opaque: the container is `opaque`, its one child
  `Encrypted data` (from the data offset to the end for version 2, from 0 to
  the footer for version 1) is opaque, and a note gives the cipher
  (`AES-128` for CSSM algorithm `0x80000001`, otherwise the ID), block
  size, data size and key protector count. Nothing is decrypted.
- Metadata: `dmg_flags`, `dmg_image_variant`, `dmg_sector_count`,
  `dmg_data_fork`, `dmg_xml_plist`, `dmg_resource_fork`, `dmg_segment`,
  `dmg_running_data_fork_offset`, `dmg_data_fork_checksum`,
  `dmg_master_checksum`, `dmg_code_signature`, and per table
  `dmg_partition_<i>` (sectors, size, chunk kinds and counts, checksum
  status, how much was decoded); for encrypted images
  `dmg_encryption_version`, `dmg_cipher`, `dmg_block_size`,
  `dmg_encrypted_size` and `dmg_key_protectors`.

## Wire units and byte order

| Structure | Byte order | Units |
| --- | --- | --- |
| `koly` trailer | Big-endian | Fork offsets and lengths in bytes (file offsets); sector count in 512-byte sectors; checksum sizes in bits |
| Block table and chunks | Big-endian | First sector, sector counts and chunk sectors in 512-byte sectors (chunk sectors relative to the table's); data start and compressed offsets and lengths in bytes, relative to the data fork offset |
| Resource fork | Big-endian | Offsets relative to the fork, the map, the type list, the name list or the resource data, as Inside Macintosh defines them; a reference's data offset is 24 bits |
| XML property list | UTF-8 text | Table bytes in standard base64 (RFC 4648) with whitespace between symbols |
| ADC stream | Big-endian 16-bit distances | Lengths and distances in bytes; distances count back from the end of the output |
| Encrypted Encoding v2 header, v1 footer | Big-endian | Block size, data size and offset in bytes |

## Validation and resource bounds

- Trailer: signature, version 4 and header size 512 (7-Zip's 12-byte
  `k_Signature`); each fork satisfies `offset <= trailer && length <=
  trailer - offset`. A trailer that names neither a property list nor a
  resource fork is unsupported.
- Property list: `plist`, `dict`, `resource-fork` `dict`, `blkx` `array` of
  `dict`s; only the first `resource-fork` and `blkx` are read. The reader
  accepts the XML declaration and processing instructions, comments, a
  `DOCTYPE` without an internal subset, the five predefined entities and
  character references; CDATA sections and internal subsets are errors.
  Nesting is limited to 32 `dict`/`array` levels, the walk consumes input
  on every step, and at most 4096 tables are read (more is an error).
- Base64: whitespace is skipped, the symbols with padding must form groups
  of four, padding may only end the text, and unused bits must be zero.
- Resource fork: the header's data and map ranges lie in the fork, the map
  is at least 28 bytes, type list items and reference lists lie in the map,
  each resource's length-prefixed data lies in the resource data, names in
  the name list (characters 0x20-0x7E kept, others shown as `?`); at most
  4096 `blkx` resources.
- Block table: signature `mish`, version 1, size exactly 204 + 40 × chunk
  count (7-Zip `CFile::Parse`), first sector and sector count below 2^54;
  chunk sectors start at 0 and are contiguous (comments and the end chunk
  included); the chunks cover exactly the table's sector count; the end
  chunk is the last record and must be present; chunk offsets are computed
  with checked addition.
- Chunks: stored bytes must lie in the data fork (in a multi-segment image
  a chunk outside it is in another segment, and the partition is not
  decoded); a raw chunk stores exactly its sectors; a compressed chunk
  must decode to exactly its sectors (at most 64 MiB; larger chunks decode
  only their first bytes through `decode_prefix`); an undocumented chunk
  type leaves the partition undecoded with a note.
- At most 64 MiB are assembled per partition and 256 MiB of owned bytes per
  image (`MAX_PAYLOAD`, `MAX_EXTRACTED`); the rest of a larger partition is
  not decoded and its CRC-32 not verified, which a note says. Zero fill is
  appended up to that limit, never allocated from a declared size beyond
  it.
- ADC: every input byte belongs to a token; a token cut by the end of the
  input, a match before the start of the output, or output beyond the limit
  is an error.
- Encrypted Encoding v2: the header's 76 bytes, key protector descriptors
  (20 bytes each) that end before the data offset, a non-zero block size,
  and the data, rounded up to whole blocks, inside the file.
- Strong detection means a corrupt image whose trailer is intact is a parse
  error. A truncated image loses its trailer and is not claimed (only an
  `encrcdsa` header survives a cut, and its data must then be missing,
  which is an error; the truncation sweep checks both).

## Detection order

`dmg::detect` runs in `detect_format` right after the virtual disks and
before the archive, read-only and flash filesystem, ext, EROFS, console
disc, ISO 9660, partition table and FAT checks. A raw (UDRO) image's data
fork starts with the disk's first sector, an MBR, a GPT or a volume, which
those checks would otherwise claim; only the trailer at the end says it is
a disk image. Compressed images start with a zlib, bzip2, LZFSE or xz
stream, which the compressed-stream checks after it would claim. The
checks before it are executable and firmware formats whose headers a
disk's first sector or a codec stream does not carry, as for the virtual
disks. A future HFS+ or APFS volume check must also run after it. The
trailer is checked before the encrypted header and footer; an image cannot
be both.

An image appended to other data (a `.dmg` as the last member of a tar
archive, a MacBinary wrapper) is not claimed: its forks are at offsets
relative to the image, so the property list is not where the trailer puts
it. `container::is_recognized` cannot see a disk image from a member's
first bytes, so archive and filesystem members that are disk images are not
listed.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| D1 | Every UDIF image has the 512-byte trailer at the very end (7-Zip also reads rare old images with the trailer at offset 0) | An image with `koly` at offset 0 and a data fork offset of 512 (7-Zip's "front koly" mode) would not be detected; none was available to test |
| D2 | Chunk positions are data fork offset + table data start + compressed offset (7-Zip, darling-dmg; libdmg-hfsplus leaves out the data fork offset, which is 0 in every image it writes) | Every hdiutil and Apple image has data fork offset 0 and data start 0, so a reader that differs would still pass them; an image with a non-zero data fork offset would show it |
| D3 | A table's CRC-32 covers the decoded partition with ignore (type 2) chunks left out and zero-fill (type 0) chunks included | `hdiutil_images_decode_every_codec_and_verify_every_crc`: all 8 tables of 6 images, and 12 Apple developer disk images, verify; including the ignore chunks fails |
| D4 | Chunk type `0x80000008` holds xz streams (7-Zip decodes it as xz; keramics calls it LZMA) | `hfs-ulmo.dmg` chunks start with `FD 37 7A 58 5A 00` and verify; an LZMA-alone chunk would fail to decode |
| D5 | The master CRC-32 covers the tables' checksum bytes in table order | Verified in every fixture and the 12 Apple images; a reordered or differently sized input would mismatch |
| D6 | Partition-map, boot-record, driver and free-space tables describe nothing on their own | A table of one of those types whose bytes are a recognized volume is not listed; the EFI system partition (a FAT volume) is deliberately among them |
| D7 | The encrypted v2 data is stored in whole blocks of the header's block size | `hdiutil` AES-128 (`encrypted.dmg`): data size 14449 B at 0x1DE00, file size `0x1DE00 + 29 × 512`; dmg2img reads the data block by block |
| D8 | `cdsaencr` in the last 8 bytes marks an Encrypted Encoding v1 image (apfs-fuse, vfdecrypt's detection); the v1 footer's other fields beyond the block size are not used (apfs-fuse and keramics read the bytes at 1256-1263 differently) | Only a synthetic v1 footer is tested; no v1 image was available |
| D9 | `hdiutil` UDRW images are raw disks without a trailer | `hdiutil imageinfo` reports `CRawDiskImage` for `-format UDRW` on macOS 27.2 |
| D10 | A segment's chunks lie in the concatenation of the segments' data forks, and only the first segment holds the tables (keramics); later segments repeat the master checksum | `hdiutil segment` (`segmented.dmg`, `segmented.002.dmgpart`): the first segment's tables name chunks past its 32 KiB data fork; the second has an empty `resource-fork` dictionary, running data fork offset 32768 and the same master CRC-32 |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Encrypted images (v1, v2) | Opaque; not decrypted, key protectors not parsed beyond their count |
| Segmented images (`.dmgpart`) | Segments are not joined: each segment parses on its own. In the first, partitions with a chunk in another segment are not decoded (noted); a later segment has no tables, so it lists no partitions and its master CRC-32 is not verified (noted) |
| Images without a property list or resource fork (UDIF stubs, keramics) | Not detected; `parse_container` reports them as unsupported |
| Trailer at offset 0 (old images, 7-Zip only) | Not detected |
| Checksum types other than CRC-32 (keramics lists 4, MD5) | Reported with their type and size, not verified |
| Data fork CRC-32 over a data fork larger than 64 MiB | Not verified (noted), to keep classification fast |
| Partitions larger than 64 MiB, images with more than 256 MiB of decoded partitions | Only the first 64 MiB per partition and 256 MiB per image are decoded; their CRC-32 is not verified (noted) |
| HFS+, HFSX and APFS volumes | Decoded, but listed only when a parser recognizes them (none in this family; another family adds HFS+) |
| Code signature (the reserved pair at 0x128, 7-Zip) | Reported with its range, not parsed or verified |
| Sparse images, sparse bundles, NDIF, MacBinary-wrapped images | Not recognized |
| `koly` images embedded in other files | Not claimed (see detection order) |

## Verification

On 2026-10-13 (macOS 27.2 AArch64, build 26B5101f, rustc 1.100.0-nightly
`f248f4038` 2026-09-05, `hdiutil` of DiskImages framework 710, Node v25.8.1
with Playwright Chromium), `cargo test --all-features --locked` passed:
2,287 tests, 6 ignored (the repository's existing ignores), including the
20 tests of `tests/dmg.rs` and 25 unit tests (20 in `src/formats/dmg*`, 5
in `src/formats/compressed/adc.rs`). The CRC-32 of every block table of
the six HFS+ fixtures matched, so every codec (zlib, bzip2, LZFSE, xz,
ADC, raw) reproduced what `hdiutil` compressed byte for byte. The sweeps
cover every prefix of every fixture and of two synthetic images (an image
must not be claimed, and an `encrcdsa` prefix must fail to parse), and
0x00, 0xFF and bit-flip mutations of every 4th trailer byte, every 64th
property-list byte and 16 data-fork positions of each `hdiutil` fixture,
every trailer byte, every 4th property-list or resource-fork byte and 128
data-fork positions of the synthetic images, and the first 1024 bytes of
the encrypted image; every 64th trailer byte is also mutated through the
full classification.

With `DMG_SAMPLE_DIR=/Library/Developer`, the 12 Apple developer disk
images on the build machine (13-43 MB, each one `Whole_Disk` table of
zlib, ignore and in some raw chunks) parsed with their data fork, master
and table CRC-32s verified. No parser on this branch recognizes their
volumes, so they are noted as not classified (the one inspected,
`CoreDevice/CandidateDDIs/iOS_DDI.dmg`, holds `H+` at 1024). A scan of
IDA Pro's test inputs (44,328 files of at most 64 MiB) detected none as an
Apple disk image; a scan of 303,688 local files (`/Library/Developer`,
`/System/Library/AssetsV2`, `/usr/lib`, `/usr/bin`, `/opt/homebrew/Cellar`)
detected exactly those 12 images. After `./build-web.sh`,
`web/tests/dmg.test.mjs` (4 tests) passed through `/pkg/zrax.js`,
`/dist/zrax.js`, `/web/index.html` and `/dist/index.html`; the whole
browser suite ran 264 tests, 260 passed and 4 skipped (the existing skips
that need D10 and RX113 firmware not in the repository).

Not verified: Encrypted Encoding version 1 images and binary resource
forks (only synthetic ones were tested), images with a non-zero data fork
offset or table data start, checksum types other than CRC-32, and images
written by tools other than `hdiutil` and Apple's build of its developer
disk images.

After integration on the same day the native suite passed 2,316 tests
with 6 ignored, `DMG_SAMPLE_DIR=/Library/Developer` verified the 12
developer disk images again, and IDA's corpus (4,621 files) classified as
before. Two downloaded application images were recognized with their
master CRC-32s verified: one holds an `Apple_HFS` partition and one an
`Apple_APFS` partition, both cut at the 64 MiB extraction limit and, at
this commit, not in a recognized format.
