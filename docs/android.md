# Android images

`src/formats/android.rs` and its submodules (`boot.rs`, `sparse.rs`,
`ota.rs`, `bootloader.rs`, `super_image.rs`, `dtbo.rs`, `vbmeta.rs`) parse
Android boot and vendor_boot images, sparse images, update_engine OTA
payloads, Pixel/Nexus bootloader packs, dynamic-partition `super` images,
DTB/DTBO table images and AVB vbmeta images into the shared container model
([compressed streams and the container model](compressed-streams.md)).
None of these formats names a CPU: every container result has an unknown
ISA with confidence 0, and the ISA comes from the kernels, partition images
and pack members, each classified from its own bytes.

## Implemented layouts

| JSON format ID | Layout | Recognition | Components | Primary source |
| --- | --- | --- | --- | --- |
| `androidboot` | Boot image header v0, v1, v2 (`page_size` pages; kernel, ramdisk, second stage, v1/v2 recovery DTBO at its absolute offset, v2 DTB) and v3, v4 (fixed 4096 B pages; kernel, ramdisk, v4 boot signature) | Strong: `ANDROID!` | Kernel and ramdisk decoded when they start with a codec magic (`compressed::sniff`: gzip, LZ4 legacy and frame, Zstandard, xz, bzip2, lzop, ...; LZMA-alone with the Linux default properties); second stage stored; DTB, recovery DTBO, boot signature, GKI certificate block and AVB vbmeta opaque | AOSP [`mkbootimg` `d2bb0af5`](https://android.googlesource.com/platform/system/tools/mkbootimg/+/d2bb0af5ba6d3198a3e99529c97eda1be0b5a093/include/bootimg/bootimg.h) `bootimg.h`, `mkbootimg.py`, `unpack_bootimg.py`, `gki/certify_bootimg.py` |
| `androidboot` (variant) | v0 whose `header_version` (0x28) is larger than 4: the size of a device-tree image appended after the second stage, as Qualcomm (LineageOS `mkbootimg --dt`) and Samsung images use it | Strong | Appended device tree opaque | [LineageOS `mkbootimg.py` `90054adc`](https://github.com/LineageOS/android_system_tools_mkbootimg/blob/90054adc0017398ae868e990e85fd8dc58020c75/mkbootimg.py); Magisk v30.7 `bootimg.hpp` `e8a58776` |
| `androidvendorboot` | vendor_boot header v3 (one vendor ramdisk, DTB) and v4 (vendor ramdisk table, DTB, bootconfig), on the vendor `page_size` after `ceil(header_size / page_size)` header pages | Strong: `VNDRBOOT` | One component per ramdisk table entry (`Vendor ramdisk <name> (<type>)`), decoded like boot ramdisks; DTB and bootconfig opaque | `bootimg.h`, `mkbootimg.py` at `d2bb0af5` |
| `androidsparse` | libsparse v1: 28-byte file header, 12-byte chunk headers (larger declared sizes skipped), RAW, FILL, DONT_CARE and CRC32 chunks | Strong: `3A FF 26 ED` | One `Expanded image` component (transform `Android sparse`, stored range the whole file), classified always | AOSP [`system/core` `a3b721a3`](https://android.googlesource.com/platform/system/core/+/a3b721a32242006b59cb12bd62c9133632af3a2d/libsparse/sparse_format.h) `libsparse/sparse_format.h`, `sparse_read.cpp`, `sparse_crc32.cpp` |
| `androidota` | update_engine payload major version 2 (24-byte header with metadata signature size) and major version 1 (20-byte header; `kernel`/`root` operations in manifest fields 2 and 1); protobuf `DeltaArchiveManifest` | Strong: `CrAU` | One component per partition, labelled with `partition_name`, reassembled from REPLACE, REPLACE_BZ, REPLACE_XZ, ZERO and DISCARD at `dst_extents * block_size` (transform `Android OTA`); partitions with delta or unknown operations opaque | AOSP [`update_engine` `dc84c255`](https://android.googlesource.com/platform/system/update_engine/+/dc84c2552b2d4cf00d2a843cb1c091d99d0499f1/update_metadata.proto) `update_metadata.proto`, `payload_consumer/payload_metadata.cc`; major version 1 from tag `android-10.0.0_r1`; [protobuf encoding guide](https://protobuf.dev/programming-guides/encoding/) |
| `androidbootloader` | Qualcomm `BOOTLDR!` pack: `num_images`, `start_offset`, `bootldr_size`, 68-byte entries, bodies back to back | Strong: `BOOTLDR!` | One component per image, labelled with its name | AOSP `device/lge/hammerhead` `releasetools.py` `e2e99344` (also `bullhead` `2994b6be`, `flo` `9d9fee95`) |
| `androidbootloader` | ASUS fugu (Nexus Player) `BOOTLDR!`: revision 1 (IFWI and droidboot sizes) or chunks `IFWI!!!!`, `DROIDBT!`, `SPLASHS!` to the end of the file | Strong: `BOOTLDR!`; validated against both `BOOTLDR!` layouts, ambiguous if both validate | `IFWI`, `droidboot` (an Android boot image); `splash` opaque | AOSP `device/asus/fugu` `releasetools.py` `25a29d70` |
| `androidbootloader` | Qualcomm meta image v1: 76-byte header, `img_hdr_sz / 80` entries of name, absolute offset and size | Strong: `3C D6 1A CE` | One component per entry in use (offset and size nonzero) | CAF `meta_image/meta_format.h` (OnePlusOSS mirror `018b5519`); AOSP `device/huawei/angler` `releasetools.py` `cf92cd8e` |
| `androidbootloader` | FBPK v2: 112-byte `PackHeader`, `PackEntry` records at `header_size` with stride `entry_header_size`, absolute 64-bit data offsets | Strong: `FBPK`, version 2 | One component per non-empty entry, labelled `name` or `name (product)`; type 0 (partition table) opaque | Google `fbpack.py`/`fbpacktool.py` (Pixel `fw_unpack` tools on source.android.com, 2021) |
| `androidbootloader` | FBPK v1: 84-byte header, 56-byte entry headers each followed by its data, `next_offset` chains entries | Strong: `FBPK`, version 1 | As FBPK v2 | Community only: `anestisb/qc_image_unpacker` `src/packed_image.h` `28a783a9`, BANG `android_fbpk.ksy` `96370e4f` |
| `androidsuper` | Full `super` image (`ImageBuilder`): 4096 reserved bytes, geometry and backup at 4096 and 8192, `metadata_slot_count` primary and backup copies of `metadata_max_size`, partition data; liblp metadata v10.0 to v10.2 (header, partition, extent, group and block device tables) | Strong: geometry magic `67 44 6C 61` at 4096 | One member per partition whose extents are in the file, labelled with its name and listed when it holds a recognized format: one linear extent borrowed at its stored offset, several linear and zero extents assembled (transform `LP extents`) | AOSP [`system/core` `a3b721a3`](https://android.googlesource.com/platform/system/core/+/a3b721a32242006b59cb12bd62c9133632af3a2d/fs_mgr/liblp/include/liblp/metadata_format.h) `fs_mgr/liblp/include/liblp/metadata_format.h`, `reader.cpp`, `utility.cpp`, `images.cpp`, `writer.cpp` |
| `androidsuper` (variant) | `super_empty` image (`WriteToImageFile`): geometry at 0, one metadata copy at 4096, no partition data | Strong: geometry magic at 0 | None; partitions described in metadata | As above |
| `androiddtbo` | DTB/DTBO table: 32-byte `dt_table_header`, 32-byte `dt_table_entry` records at `dt_entries_offset`, blobs inside `total_size`; version 1 entries compressed with zlib or gzip | Strong: `D7 B7 AB 1E` | One member per distinct blob (`DT entry <n> (id 0x…, rev 0x…)`), classified as a device tree; compressed blobs decoded; blobs that are not device trees opaque | AOSP [`system/libufdt` `9b70f594`](https://android.googlesource.com/platform/system/libufdt/+/9b70f594cf149c7c73989c78f03d210f8aa1c1f6/utils/src/dt_table.h) `utils/src/dt_table.h`, `mkdtboimg.py`, `mkdtimg_core.c` |
| `androidvbmeta` | AVB vbmeta image: 256-byte header, authentication block (hash, signature), auxiliary block (public key, its metadata, descriptors); property, hashtree, hash, kernel cmdline and chain partition descriptors | Strong: `AVB0` | None; the container is opaque (metadata only) and its descriptors are summarized in notes | AOSP [`external/avb` `76117860`](https://android.googlesource.com/platform/external/avb/+/761178607206f4cb2af79ed9eec52d8cbd814adb/libavb/avb_vbmeta_image.h) `libavb/avb_vbmeta_image.h`, `avb_vbmeta_image.c`, `avb_descriptor.h` and the descriptor headers |

The JSON `format.variant_name` is the layout label (`Android boot image`,
`BOOTLDR! bootloader pack`, `FBPK bootloader pack`, ...). The first note
names the header version or pack layout, and metadata records the header
fields (`android_boot_header_version`, `android_boot_page_size`, load
addresses, `android_os_version`, `android_os_patch_level`,
`android_board_name`, `android_cmdline`, `android_sparse_*`,
`android_ota_*`, `android_fbpk_platform`, `android_bootloader_version`,
`android_super_*` for the geometry, groups, block devices and partitions,
`android_dtbo_*` for the table and each entry, `android_vbmeta_*` for the
header) and one `android_component_<n>` entry per component.

## Architecture evidence

No header field in this family names an ISA. Load addresses (`kernel_addr`,
`tags_addr`, `0x10008000`), board and product names, FBPK `platform`, and
partition names are never used as ISA evidence. The ISA comes from:

- the decoded kernel's own header (arm64 or RISC-V `Image`, Arm `zImage`,
  x86 `bzImage`, ELF), through the kernel family;
- nested containers (a `boot` partition in an OTA payload, a boot image in
  a sparse image, a droidboot image in a fugu pack, an EROFS or ext
  partition in a `super` image, a `super` image in a sparse image);
- the code model on the bytes of a component that is not a recognized
  format (second stage, IFWI, unrecognized pack members). A decoded cpio
  ramdisk is a CPIO container ([archives](archives.md)), which lists its
  members that are in a recognized format.

The first component with a known ISA becomes the container's primary
result, with a note naming it; the kernel is listed first in boot images.
Device trees, recovery DTBOs inside boot images, bootconfig text, AVB
vbmeta images, boot signatures, GKI certificates, FBPK partition tables and
fugu splash screens are data and are marked opaque, so they never reach the
code model. The device trees of a DTBO table image are classified by the
device tree parser, which names no ISA; a blob that is not a device tree is
opaque. A vbmeta image is an opaque container without members.

## Wire units and byte order

| Layout | Byte order | Units |
| --- | --- | --- |
| Boot, vendor_boot | Little-endian (host order in `bootimg.h`; every AOSP host and target is little-endian) | Sizes and offsets in bytes; sections padded to whole pages; `recovery_dtbo_offset` is an absolute file offset |
| Vendor ramdisk table | Little-endian | `ramdisk_offset` relative to the vendor ramdisk section |
| AVB footer | Big-endian | Last 64 bytes of the partition image; `vbmeta_offset` absolute |
| Sparse | Little-endian | `chunk_sz` in output blocks; `total_sz` in input bytes including the chunk header |
| OTA payload header | Big-endian | Bytes; `data_offset` and `signatures_offset` relative to `blob_start` (end of the metadata signature) |
| OTA manifest | Protobuf varints | Extents in blocks of `block_size` (default 4096) |
| `BOOTLDR!`, meta image, FBPK | Little-endian | Bytes; entry offsets absolute except Qualcomm `BOOTLDR!` bodies (cumulative from `start_offset`) and FBPK v1 data (after its entry header) |
| `super` metadata | Little-endian | Extents and `first_logical_sector` in 512-byte sectors; table offsets relative to the end of the metadata header; sizes in bytes |
| DTB/DTBO table | Big-endian | `dt_offset` from the start of the table header; sizes in bytes |
| vbmeta image, descriptors | Big-endian | Hash and signature offsets relative to the authentication block; public key, its metadata and descriptors relative to the auxiliary block |

`os_version` is decoded as `(A << 25) | (B << 18) | (C << 11) | ((Y - 2000) << 4) | M`
into "OS version A.B.C; security patch level Y-M", with "not set" for a zero
half.

## Validation and resource bounds

- Every section, table, chunk, blob and member must lie inside the file;
  sizes and offsets are added with checked 64-bit arithmetic. A truncated or
  inconsistent structure is an `Android image parse error` that names the
  record and the offset, never a raw-code guess.
- Boot page sizes must be powers of two from 2 KiB to 128 KiB; sizes other
  than the `mkbootimg.py` choices (2, 4, 8 and 16 KiB) are noted. Bytes after
  the last section are explained (AVB footer, Samsung `SEANDROIDENFORCE`, LG
  bump trailer, GKI certificate block) or noted with their size.
- The boot image `id` is recomputed as mkbootimg's SHA-1 (each section
  followed by its size as a little-endian u32) and reported as matching or
  not; it is an identifier, not a signature. SHA-1 is implemented in
  `formats::checksum` and checked against the FIPS 180-4 and RFC 3174 test
  vectors.
- Vendor ramdisk table entries must be at least 108 B and fit
  `vendor_ramdisk_table_size`; each ramdisk must lie inside the vendor
  ramdisk section.
- Sparse images: major version 1, header sizes at least 28 and 12 B, block
  size a nonzero multiple of 4, `total_chunks` checked against the bytes
  available before the walk, RAW data exactly `chunk_sz * blk_sz`, FILL and
  CRC32 data exactly 4 B, DONT_CARE without data, unknown chunk types
  rejected (libsparse would read the next header from inside the data), the
  chunks covering exactly `total_blks`, and only padding after the last
  chunk. CRC32 chunks are verified against the IEEE CRC-32 of the expanded
  data so far; a nonzero `image_checksum` (libsparse writes 0 and never
  checks it) is compared with the CRC-32 of the whole expansion.
- Sparse expansion stops at 64 MiB (`MAX_PAYLOAD`); DONT_CARE blocks are
  zeros. The full expanded size is reported, and CRC32 chunks after the cut
  are reported as not verified.
- OTA manifests are read with a bounded protobuf reader: varints of at most
  10 bytes, every length-delimited field bounded by its message, groups and
  unknown wire types rejected, nesting fixed at manifest, partition,
  operation and extent. Every operation's data range is checked against the
  file and the payload signature before anything is decoded, and only
  padding may follow the payload.
- OTA partition images are at most 64 MiB each and 256 MiB per payload
  (`MAX_EXTRACTED`); a partition beyond the budget stays opaque with a note.
  Allocation is bounded by those caps, never by an extent address beyond
  them. Operations that write only beyond the cut are not decoded, and the
  bytes written across all operations are capped at 256 MiB.
- REPLACE_BZ and REPLACE_XZ blobs are decoded with the shared bzip2 and xz
  decoders, limited to the operation's extent size. `data_sha256_hash` is
  verified for every operation that has one, and `new_partition_info.hash`
  is verified for every partition that is reassembled completely; a
  mismatching operation hash leaves the partition opaque.
- `super` images: the geometry is checked as `ParseGeometry` checks it
  (magic, `struct_size` 52, SHA-256, slot count, `metadata_max_size` a
  multiple of 512) and the metadata as `ReadMetadataHeader` and
  `ParseMetadata` do (magic, major 10 and minor at most 2, header size 128
  or 256, header SHA-256, every table inside `tables_size` with 64-bit
  products, entry sizes 52, 24 and 48 B and block devices of at least
  64 B, `tables_size <= metadata_max_size`, tables SHA-256, attributes per
  version, extent and group indices, linear block device indices, at least
  one block device, metadata region before the first logical sector). A
  damaged primary geometry or slot-0 copy falls back to the backup, with a
  note; other slots are not compared. Partitions with an extent on another
  block device, beyond the file or of an unknown type are noted and not
  extracted; partitions of several extents are assembled only when their
  first 4 KiB are a recognized format, up to 64 MiB each and 256 MiB per
  image.
- DTBO tables: `header_size` and `dt_entry_size` 32, version 0 or 1,
  `total_size` inside the file, the entry table inside `total_size`
  (count checked against the bytes before reading), each blob after the
  entry table and inside `total_size`. Shared blobs are listed once.
  Compressed blobs are decoded within the extraction budget. Bytes after
  `total_size` are explained (AVB footer) or noted.
- vbmeta images: checked as `avb_vbmeta_image_verify` checks them (major
  version 1, NUL-terminated release string, block sizes multiples of 64,
  blocks inside the file, hash and signature inside the authentication
  block, public key and its metadata inside the auxiliary block, known
  algorithm, hash size of its digest), plus the descriptors inside the
  auxiliary block. Descriptors are walked as `avb_descriptor_foreach`
  walks them and checked as their `*_validate_and_byteswap` functions do;
  at most 64 are summarized. The SHA-256 or SHA-512 of the header and the
  auxiliary block is compared with the stored hash and reported as
  matching or not; the RSA signature and the descriptors' digests are not
  verified.
- Packs list at most 4096 components (`MAX_COMPONENTS`). Qualcomm
  `BOOTLDR!` names must be printable ASCII terminated by a NUL inside their
  64 bytes, `start_offset` must not point into the table, and
  `bootldr_size` must equal the sum of the image sizes or the file size.
  FBPK v2 needs `header_size >= 112` and `entry_header_size >= 104`, and entry
  data may not overlap the entry table. FBPK v1 entries must chain forward
  (`next_offset` at or after the end of the entry's data).

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| A1 | Boot and vendor_boot fields are little-endian on every device (UNCONFIRMED) | An `ANDROID!` image whose `page_size` is a power of two only when byte-swapped |
| A2 | A v0 `header_version` above 4 is the size of an appended device tree after the second stage | Lineage `--dt` and Samsung images (`boot_header_version_above_4_is_an_appended_device_tree_size`); a vendor image that stores something else there fails with a truncation error |
| A3 | Page sizes from 32 to 128 KiB occur in non-AOSP images (UNCONFIRMED; accepted, noted) | A vendor image with such a page size; Samsung PXA headers (`page_size >= 0x02000000`) are rejected |
| A4 | Ramdisk contents are a cpio archive, unpacked by the CPIO container; the kernel, listed first, supplies the primary ISA | A boot image whose kernel is unknown and whose ramdisk holds code of another architecture |
| A5 | OTA `data_offset` is relative to `blob_start`, after the metadata signature; the payload signature follows the blobs directly (the README's `payload_signatures_message_size` field is not written by `PayloadFile::WritePayload`) | A signed payload from `delta_generator`; `payload.size() == blob_start + signatures_offset + signatures_size` |
| A6 | `bootldr_size` equal to the file size marks Pixel and Pixel 2 packs (Kaitai, secondary source, UNCONFIRMED) | `bootloader-marlin-*.img`, `bootloader-walleye-*.img` |
| A7 | FBPK v1 `pad1`/`pad2` are zero; nonzero values are refused because their meaning is UNCONFIRMED | A Pixel 3 to 5 pack with a nonzero field |
| A8 | FBPK `crc32`/`checksum` algorithms are UNCONFIRMED; a value equal to the IEEE CRC-32 of the entry data is reported as a match, anything else as not verified | Compute IEEE CRC-32 of each entry in a Tensor `bootloader-*.img` |
| A9 | FBPK v2 `platform` and `slot_type` have no confirmed meaning; they are reported, never used | Headers of several Pixel 6 to 9 packs |
| A10 | Pack members are independent images (often ELF, which carries `e_machine`; UNCONFIRMED per member) | Classify unpacked members of real packs |
| A11 | A meta image with `meta_hdr_sz != 76` cannot be read: the CAF reader and Kaitai disagree where the table starts | A meta image with a header extension |
| A12 | The geometry magic at 4096 identifies a full `super` image; the 4096 reserved bytes before it are not checked (ImageBuilder writes zeros there; devices are not established) | A `super` partition dump with nonzero reserved bytes |
| A13 | Block device entries larger than 64 B are a stride, as liblp reads them; smaller ones are refused (liblp does not check and would read past the entry) | A table with `block_devices.entry_size != 64` |
| A14 | Primary and backup metadata copies and all slots are identical in images built on a host (`ImageBuilder` writes the same blob to each); only slot 0 is read | A `super` partition dumped from a device after an A/B update |
| A15 | DTBO blobs are device trees (`mkdtimg` checks `fdt_check_header`); ACPI tables (`ACPIO` magic `0x41435049`) are not recognized | An `acpio.img` built with `mkdtboimg --dt_type acpi` |
| A16 | vbmeta images with `required_libavb_version_minor` above 3 keep the layout of 1.3 (accepted with a note) | A vbmeta image from a newer avbtool using a new descriptor or field |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Boot image signatures, AVB vbmeta, GKI certificates, OTA metadata and payload signatures | Located and reported; not verified (no keys) |
| Samsung PXA header, DHTB, Tegra `-SIGNED-BY-SIGNBLOB-`, `CHROMEOS`, NOOK/Acclaim/Amonet pre-headers | Not recognized: the file does not start with `ANDROID!` (PXA: unsupported page size error) |
| MediaTek 512-byte payload header | Stripped from kernel and ramdisk sections with a note (Magisk `mtk_hdr`) |
| Recovery DTBO inside a boot image | Opaque component of the boot image (a standalone DTBO table image is parsed) |
| ACPIO tables (`mkdtboimg --dt_type acpi`) | Not recognized |
| `super` images on several block devices (retrofit), `super_<device>.img` | Only extents on block device 0 are in the file; others are noted |
| vbmeta RSA signatures, descriptor digests, hashtrees | Not verified (no keys; partition data is not in the image) |
| cpio ramdisks | Decoded and unpacked by the CPIO container; only members in a recognized format are listed |
| OTA delta operations (MOVE, BSDIFF, SOURCE_COPY, SOURCE_BSDIFF, PUFFDIFF, BROTLI_BSDIFF, ZUCCHINI, LZ4DIFF_*) | The partition is opaque with a note; applying them needs the source partition |
| Operation types outside 0 to 13 (the spec notes' type table; `REPLACE_ZSTD` is not in it) | Unknown types: the partition is opaque with a note |
| OTA zip packaging (`payload.bin` inside the OTA zip) | The ZIP container lists `payload.bin` as an OTA payload member; `META-INF` signatures are not verified |
| Sparse images beyond 64 MiB expanded | Only the first 64 MiB are expanded and analyzed |
| FBPT partition tables | Opaque; the table is not decoded |
| EROFS, ext and `super` images inside sparse images and OTA partitions | Classified through their own families |
| F2FS partitions | Classified as raw |

## Verification

On 2026-10-12 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`):
`tests/android.rs` (30 tests) and the 13 unit tests in `src/formats/android`
passed, with every-prefix truncation sweeps of each layout and a sweep over
every byte of eleven fixtures with `0x00`, `0xFF` and bit-flip mutations;
the SHA-1 unit test passed against the FIPS 180-4 and RFC 3174 vectors.
`web/tests/android.test.mjs` (4 Chromium tests) passed through `/pkg/`,
`/dist/` and both workbench pages. All fixtures are synthetic, built in the
tests from the documented layouts; kernel and member payloads are the
committed AArch64 code sample and x86-64 ELF header plus the committed
`lz4 -l`, `xz` and `bzip2` streams of the compressed-stream fixtures. No
real Android image, OTA payload or bootloader pack was available: behavior
on vendor files is not verified, and mkbootimg, img2simg and
`delta_generator` were not available to cross-check the layouts.

On 2026-10-13 (same platform and toolchain), the `super`, DTBO and vbmeta
layouts were added: `tests/android_images.rs` (15 tests) passed, as did
the 18 unit tests now in `src/formats/android` (5 of them for the new
layouts) and the 30 tests of `tests/android.rs`. The new tests cover a
full `super` image with a borrowed partition, an assembled partition of
two out-of-order linear extents and a zero extent, an empty partition and
one on a second block device; a `super_empty` image; geometry, header and
table checksum failures with fallback to the backup copies; every prefix
of the full image; a sparse image of a `super` image whose partition is
the committed EROFS fixture; DTBO tables of versions 0 and 1 (shared,
gzip and zlib blobs, an unknown compression, an AVB footer); vbmeta images
with all five descriptor kinds, a hash mismatch and algorithm `NONE`; and
mutation sweeps. `web/tests/android-images.test.mjs` (2 Chromium tests)
passed through `/pkg/` and `/dist/`. These fixtures are synthetic too:
lpmake, mkdtimg and avbtool were not installed, so the layouts were not
cross-checked against images those tools write, and the vbmeta RSA
signatures are placeholders.
