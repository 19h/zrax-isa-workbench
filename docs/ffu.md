# Full Flash Update images

`src/formats/ffu.rs` and its submodules (`header.rs`, `manifest.rs`,
`store.rs`, `disk.rs`, `hash.rs`) parse Microsoft Full Flash Update (FFU)
images into the shared container model ([compressed streams and the
container model](compressed-streams.md)). An FFU holds the blocks of one
disk (FFU V1) or of several disks, one per store (V2), not code, and names
no ISA: the container target is always unknown. Each store's disk is
assembled from its write descriptors and is one child, `Store N disk`,
classified on its own, so the GPT on it, the FAT EFI system partition and
the PE or ELF files there report themselves and supply the primary ISA.

## Implemented layouts

| JSON format ID | Variant (`format.variant_name`) | Layout | Recognition | Primary source |
| --- | --- | --- | --- | --- |
| `ffu` | `FFU image` (`FFU v1`, `FFU v2`) | Security header, signed catalog, hash table; image header and manifest (with img2ffu's device targeting entries when the header is 28 B); one store (store header 1.0, full flash 2.0) or `NumOfStores` stores (store header 2.0, full flash 2.0, with store count, index, payload size and device path); validation entries; write descriptors with `DISK_BEGIN` and `DISK_END` locations; the payload blocks of each store in store order | Strong: `SignedImage ` at offset 4, `cbSize` of at least 32 B and at most one chunk, non-zero chunk size | Microsoft "FFU image format" (manufacturing documentation for Windows 10 Mobile, ms.date 2017-05-02); cross-checked with `WPinternals` and img2ffu |

Sources, fetched on 2026-10-13:

| Source | Pin | SHA-256 of the fetched file | Used for |
| --- | --- | --- | --- |
| Microsoft "FFU image format" | Wayback Machine capture `20190918215141` (raw `id_` capture) of `https://docs.microsoft.com/en-us/windows-hardware/manufacture/mobile/ffu-image-format`, updated 2019-01-25. The page is no longer served: `learn.microsoft.com/en-us/windows-hardware/manufacture/mobile/ffu-image-format` returned 404 on 2026-10-13, as do its Wayback captures from 2023 on | `123a1825612ddc373a3186c193c2d7e0ba769ebff4ed21d584cb240549ea2a01` | Every structure (`SECURITY_HEADER`, `IMAGE_HEADER`, `STORE_HEADER` with the V2 fields, `VALIDATION_ENTRY`, `BLOCK_DATA_ENTRY`, `DISK_LOCATION`, `DISK_ACCESS_METHOD`), the region order and padding, the V1 and V2 version table |
| Its diagram `images/oem-ffuv2-image-format.png` | Wayback capture (2019) | `7f3b0411f12da68072a4f4ab79c4f5d1f7056e5aa511aff01082d354a18aa705` | V2: store headers back to back, each with its entries and padding, then the payloads in store order |
| Microsoft Learn "`ALG_ID`" (`windows/win32/seccrypto/alg-id`) | Live page | `3c5046585fd06efe6b3f91701bcaf1e993b18aa3fe7e92402d67aef1f564697b` | `CALG_SHA_256` (`0x800C`) and `CALG_SHA1` (`0x8004`) |
| `WPinternals` `WPinternals/Models/FFU.cs` | Commit `d270cace796bfe74d1719ba3201bddadb3c508dd` | `6766f630dc1014aff7756364f945109775409a63b83209c8b7122edc7d4c06b1` | Field offsets, validation entries at 248 followed by the write descriptors, `dwBlockCount` payload blocks per descriptor, padding to the chunk size, a file that ends with the last payload block |
| img2ffu `Img2Ffu.Library/Reader` and `Writer` | Commit `d0dda2b2e138dd0412018bc733e64d1a92c385b0` | `Reader/Data/Store.cs` `42c7294cec8fc296876635bee8638570ff34e9a27ac6655fbab9c3ffef944624`, `Reader/Data/ImageFlash.cs` `ee160e0fe286059fbb50cb43a7fa3dd77d51492f63e4271083a0b05390072004`, `Reader/Data/SignedImage.cs` `ef1eed9ada87a3a58c857886ef3099b791b60068119da62b92e48a4bc20d9eec`, `Reader/FullFlashUpdateReaderStream.cs` `1ae09672ee8e35e080d9f6ee087db3ff2dd2e40dccfb518f29f44fcab6d90518`, `Writer/FFUFactory.cs` `f2dbeed4462f52024eee101d987e3d5f85724f508f9bec487d7a145c5bf4b703`, `Writer/Data/StoreHeader.cs` `529067fefedf1599aa756ed9ada6d5d993dd9ce4e68f5d071d8463ce5800f6c3`, `Writer/Manifest/ManifestIni.cs` `13491a214ccb3da263e730aef5f2cc7b0ca664c0dc0e0cc27cba4c92f4d65208`, `Writer/Flashing/BlockPayloadsGenerator.cs` `c33cc5bc98c7fe4b195f3679e6b65b3029ae9a514f9a2b2db08ac06ea9048fa2`, `Writer/Data/DeviceTargetInfo.cs` `f4404257f4dd1e57859d4001b574b0a98a0b4d12b54bc90b86d62e220db4db69` | V2 fields without alignment padding, the image header's device targeting count and entries, the manifest keys, the disk size from `MinSectorCount` x `SectorSize`, `DISK_END` index 0 as the last block, later writes replacing earlier ones, one SHA-256 per chunk from the image header on, the write order the test builders follow |
| Qualcomm emmcdl `inc/ffu.h`, `src/ffu.cpp` (nijel8 fork) | Commit `3c5ac42189eb1ddc66afd58bc71e25577859f355` | `53a330baf0689b90b38106b170569f11a3b41ab3989596173860a8647e60f6e0`, `4f3c97849e4471c15d1d9a7b1971f2f41dd3d8d206838f6036e72ff6bf1ac502` | `DISK_END` offsets `-(dwBlockIndex + 1) x dwBlockSizeInBytes` from the end; it also defines `DISK_SEQ` = 1, which Microsoft's enumeration does not list, and aligns the validation entries to 16 bytes, which `WPinternals` and img2ffu do not (see the assumption register) |

## The disk children

- **Assembly.** For each store, the payload blocks are taken in descriptor
  order, `dwBlockCount` blocks per write descriptor, and copied to each of
  the descriptor's locations: `DISK_BEGIN` block `i` at byte `i x block
  size`, `DISK_END` block `i` at `disk size - (i + 1) x block size`
  (index 0 is the last block), the blocks of a multi-block run in ascending
  order. Later writes replace earlier ones, so the erase-then-write pattern
  img2ffu uses for the GPT ends with the final GPT in place. Blocks that are
  not written read as zeros.
- **Disk size.** The store header gives none. The `n`-th `[Store]` section
  of the manifest gives `MinSectorCount` x `SectorSize`, the smallest disk
  the store is for, as the img2ffu reader takes it. Without it, `DISK_END`
  blocks cannot be placed: they are skipped with a note, and the disk ends
  with the last block written from its start (the backup GPT is then
  missing, and a partition that runs past the last written block is cut).
- **The child.** The first `min(disk size, 64 MiB)` bytes, owned, with the
  transform `FFU blocks`. Its stored range is the store's payload (offset
  and size in the file); its decoded range is the disk. It is listed only
  when the disk is a recognized format (`Classify::IfRecognized`), normally
  a GPT disk; otherwise a note says so. A disk is data and never goes to the
  code model on its own.
- **Order.** The stores whose manifest section says `IsMainOSStore = True`
  come first (with a note), then the others in store order, so that a boot
  or firmware store does not decide the primary ISA of the image.
- Metadata: `ffu_store_count`, `ffu_chunk_size`, `ffu_payload_offset`,
  `ffu_payload_size`, `ffu_store_N_version`, `ffu_store_N_block_size`,
  `ffu_store_N_write_descriptors`, `ffu_store_N_payload_blocks`,
  `ffu_store_N_gpt_tables` (initial, flash-only and final table index and
  count, as stored), `ffu_store_N_platform_id`, `ffu_store_N_device_path`
  (V2), `ffu_store_N_disk_size`, `ffu_store_N_disk_analyzed`,
  `ffu_manifest_size`, `ffu_manifest_version`, `ffu_os_version`,
  `ffu_device_platform_ids`, `ffu_partition_N` (manifest partitions: name,
  type GUID, sectors, filesystem), `ffu_device_target_N`,
  `ffu_catalog_size`, `ffu_hash_algorithm`, `ffu_hash_table_size` and
  `ffu_chunk_hashes` (`match`, `mismatch` or `not verified`).

## Signatures and hashes

- The signed catalog (a catalog file whose signature "must match one of the
  certificates on the device") is reported as present with its size and
  offset; its signature is not verified. An empty catalog is noted.
- The hash table holds one digest per chunk "from the image header to the
  end of the FFU". With `CALG_SHA_256` or `CALG_SHA1`, when the table holds
  exactly one digest per chunk and the chunks lie in the file, the chunks
  are hashed and compared, up to 64 MiB of chunks; the note gives how many
  matched. A mismatch is a note naming the first chunk that differs, not an
  error: the image is still parsed. Matching hashes show the image is intact
  relative to the table; the catalog signature that would authenticate the
  table is not verified.
- Validation entries (partial-update checks against the device's current
  contents) are counted, not applied.

## Wire units and byte order

| Field | Byte order | Units |
| --- | --- | --- |
| Every header field | Little-endian | |
| `dwChunkSizeInKb`, image header `dwChunkSize` | | KiB |
| `cbSize`, catalog, hash table, manifest, descriptor lengths, `dwBlockSizeInBytes`, `StorePayloadSize` | | Bytes |
| `DISK_LOCATION.dwBlockIndex`, `dwBlockCount`, GPT table indices | | Blocks of `dwBlockSizeInBytes` |
| `VALIDATION_ENTRY.dwSectorIndex` | | Device sectors |
| Manifest `MinSectorCount`, `TotalSectors` | | Sectors of `SectorSize` bytes |
| `szPlatformId` | | ASCII, NUL-separated IDs |
| `DevicePath` | Little-endian | UTF-16 code units (`DevicePathLength` counts characters, no NUL) |

Regions are padded to the next chunk boundary after the security region and
after the image header region, and to the next block boundary (file offset)
after each store's descriptors.

## Validation and resource bounds

- Security header: signature, `cbSize` from 32 B to one chunk, chunk size
  not 0; catalog and hash table inside the file.
- Image header: signature, `cbSize` from 24 B to one chunk; manifest inside
  the file; device targeting count at most the entries the rest of the file
  can hold (28 B each), every string inside the file. A chunk size that
  differs from the security header's is noted; the security header's places
  the store headers (`WPinternals`, emmcdl).
- Store headers: store header 1.0 or 2.0 with full flash 2.0 (minor
  versions are not checked), every store after the first a V2 store; block
  size from 512 B to 64 MiB (bounds of this parser); V2 store count not 0
  and the same in every store, store index equal to the position; device
  path inside the file; validation entries and write descriptors filling
  their regions exactly; access methods 0 and 2 only; a `DISK_END` run of
  `n` blocks needs index `n - 1` or more (it would pass the end of the disk
  otherwise). Store headers follow each other, so their offsets increase
  and the loop is bounded by the file.
- Payloads: each store's `blocks x block size` bytes in the file, in store
  order; data after the last payload must be erased flash (`0x00` or
  `0xFF`), noted with its size; anything else is an error. A V2
  `StorePayloadSize` that differs from the descriptors' total is noted.
- Disks: write descriptors must stay inside the manifest's disk; at most
  64 MiB of each disk is assembled, at most 256 MiB of copies per store
  (four times that range, so a table that writes the same blocks over and
  over is refused), and at most 256 MiB of disks (`MAX_EXTRACTED`) and
  4,096 disks (`MAX_COMPONENTS`) per image, with a note for the rest. At
  most 64 MiB of chunks are hashed.
- Manifest: at most 4,096 sections and 16,384 entries are kept, each value
  at most 256 characters for display; at most 256 partitions go to the
  metadata and 16 are named in the note.
- Every count is checked against the bytes that hold it before a loop, and
  every offset computation is checked or bounded by the file size. The
  payload must be complete, so an image cut anywhere is an error (the sweep
  checks every prefix of the first 12 KiB and of the last 2 KiB, and up to
  2,048 prefixes between).

## Detection order

`ffu::detect` runs in `detect_format` after the other magic-bearing
container families and before the magic-bearing compressed streams. No
format above starts with a 16-byte key like this one at offset 0; the
families above that probe later offsets (ext at 0x438, EROFS and HFS+ at
1024, ISO 9660 at 0x8001, the console discs at 0x18 and 0x1C) would need
their structures inside the signed catalog or the hash table, which fill the
first chunk. The disk inside an FFU is not stored contiguously from offset
0, so it cannot claim the file either.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| F1 | The V2 fields follow the 248-byte header without alignment padding (`StorePayloadSize` at 252, `DevicePathLength` at 260, the path at 262), as img2ffu reads and writes them; Microsoft's declaration does not state the packing, and natural alignment would put `StorePayloadSize` at 256 | `v2_image_lists_one_disk_per_store_with_the_main_os_store_first` builds the packed layout; a DISM-captured V2 FFU would confirm it (not verified: none was available) |
| F2 | Validation entries start right after the store header (248 B, or after the V2 device path), as `WPinternals` and img2ffu read them; emmcdl aligns them to 16 bytes (256) in code that its fork has commented out | `validation_entries_are_counted_and_must_fill_their_region`; a Lumia FFU with validation entries (partial update) would confirm it (not verified) |
| F3 | `DISK_END` block index 0 is the last block of the disk (img2ffu reader and writer, emmcdl), and a multi-block `DISK_END` run fills ascending blocks from its first block, as a write after `SetFilePointer` would; every known writer uses one block per `DISK_END` entry | `later_writes_replace_earlier_ones_and_runs_fill_consecutive_blocks`; a run written by Microsoft tools with more than one block would test the order (not verified) |
| F4 | The disk size is the matching `[Store]` section's `MinSectorCount` x `SectorSize` (img2ffu reader); that Lumia V1 manifests carry these keys is not confirmed | `blocks_from_the_end_need_the_manifest_disk_size` covers the absent case; a Lumia FFU would show whether its backup GPT is placed (not verified) |
| F5 | Each store's descriptors are padded to a block boundary of the file, and the payloads follow the last store back to back, without padding between them | `v2_image_lists_one_disk_per_store_with_the_main_os_store_first` checks the payload offsets; a V2 FFU whose stores have different block sizes would test it (not verified) |
| F6 | The hash table holds one digest per chunk from the image header to the end of the payload (img2ffu `GenerateHashTable`, `VerifyFFU`) | `chunk_hashes_are_verified_with_the_named_algorithm`; a hash table of any other size is reported as not verified rather than as a mismatch |
| F7 | A 28-byte image header carries a device targeting count at 24, and the entries follow the manifest (img2ffu only; Microsoft's header is 24 B) | `device_targeting_entries_follow_the_manifest`; other header sizes are read as Microsoft's 24-byte header followed by unknown fields |
| F8 | The store the manifest marks as the main OS store describes the image best, so its disk is listed first | `v2_image_lists_one_disk_per_store_with_the_main_os_store_first` reports the main OS store's x86-64 over the other store's AArch64 |
| F9 | The platform ID (`Microsoft.MSM8994.P6211` and the like) names a device, not an ISA, so it is reported and never mapped to one | Every FFU reports an unknown container target |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Compressed FFUs (img2ffu's "V1 compressed", full flash 3.0, with a compression algorithm field and per-descriptor data sizes for XPRESS or LZNT1 blocks) | Not in Microsoft's documentation; reported as an unsupported store header version |
| `DISK_SEQ` (access method 1, emmcdl only) | Unsupported access method error |
| Catalog signature | Present, not verified |
| Validation entries and partial updates | Counted; not applied. A partial update's disk holds only the blocks it writes, the rest reads as zeros |
| Padding between regions | Not checked |
| Disks larger than 64 MiB | Only the first 64 MiB are assembled and analyzed |
| Real FFU images | Not tested: no FFU was available (none in IDA's test inputs or on the test machine); every fixture is synthetic |

## Verification

On 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly `f248f4038`
2026-09-05, Node v25.8.1 with Playwright Chromium), `cargo test
--all-features --locked` passed: 2,453 tests, 6 ignored (the repository's
existing ignores), including the 21 tests of `tests/ffu.rs` and the 17 unit
tests of `src/formats/ffu*`. The fixtures are synthetic V1 and V2 images
built in the tests from the documented layout, in img2ffu's write order,
around a 320-sector GPT disk whose EFI system partition is
`tests/fixtures/fat/fat12.img`; the assembled disk equals the GPT disk byte
for byte, and the image classifies as x86-64 from the ELF in the FAT
volume. The sweeps cover every prefix of the first 12 KiB and of the last
2 KiB plus up to 2,048 strided prefixes of the V1 and V2 images (each must
fail), and 0x00, 0xFF and bit-flip mutations of the security header, the
start of the catalog and hash table, the image header and manifest, every
store header with its descriptors and up to 256 payload positions, with
every 16th of those positions also mutated through the full
classification. With `IDA_INPUT_DIR` set to IDA Pro's test inputs (7,359
files), none was detected as an FFU; a scan of 2,085,065 local files
(`~/Downloads`, `~/Documents`, `~/Desktop`, `/Library`, `/Applications`,
`/opt/homebrew`) found none with the `SignedImage ` signature at offset 4.
`FFU_SAMPLES_DIR` was not set, so no real FFU was parsed. After
`./build-web.sh`, `web/tests/ffu.test.mjs` (4 tests) passed through
`/pkg/zrax.js`, `/dist/zrax.js`, `/web/index.html` and `/dist/index.html`;
the rest of the browser suite was not run. Behavior on images written by
Microsoft tools (DISM and the Windows manufacturing tools) is not verified.

After integration on the same day, the native suite passed 2,548 tests
with 6 ignored, and IDA's corpus (4,621 files, no FFU images) classified
as before.
