# Virtual disk images

`src/formats/vdisk.rs` and its submodules (`qcow2.rs`, `vmdk.rs`, `vhd.rs`,
`vhdx.rs`, `vdi.rs`) parse QEMU QCOW2, VMware VMDK hosted sparse extents,
Microsoft VHD and VHDX, and VirtualBox VDI images into the shared container
model ([compressed streams and the container model](compressed-streams.md)).
A virtual disk stores a guest disk, not code, and none of these formats
names an ISA: the container target is always unknown. The container has one
child, `Guest disk`, at guest offset 0, which is classified on its own, so
the partition table, filesystem or image inside reports itself and supplies
the primary ISA.

## Implemented layouts

| JSON format ID | Variant (`format.variant_name`) | Layout | Recognition | Primary source |
| --- | --- | --- | --- | --- |
| `qcow2` | `QCOW2 image` (`QCOW2 v2`, `QCOW2 v3`) | Header (72 B, v3 at least 104 B), header extensions, backing file name, L1 table, L2 tables of one cluster (8-byte entries, 16-byte extended entries with 32 subclusters), standard, zero, unallocated and compressed (deflate, zstd) clusters | Strong: `QFI\xfb` and version 2 or 3 | QEMU `v11.1.1` `docs/interop/qcow2.rst`; `block/qcow2.h` |
| `vmdk` | `VMDK sparse extent` (`VMDK <createType>`) | Hosted sparse extent header (512 B), embedded descriptor, grain directory and grain tables, zeroed-grain entries, compressed grains behind markers, the stream-optimized footer when `gdOffset` is `GD_AT_END` | Strong: `KDMV` and version 1 to 3 | VMware Technical Note "Virtual Disk Format 5.0" (EN-000777-00, 2011-12-20); QEMU `v11.1.1` `block/vmdk.c` |
| `vhd` | `VHD image` (`VHD fixed`, `VHD dynamic`, `VHD differencing`) | Footer (512 B, or 511 B before Virtual PC 2004) with its copy at 0, dynamic disk header (1024 B), BAT, blocks of a sector bitmap and data | Strong: the cookie `conectix` at offset 0, or a footer at the end of the file whose checksum is valid and that describes the file (a fixed disk's current size is every byte before the footer; a dynamic disk's data offset locates `cxsparse`) | Microsoft "Virtual Hard Disk Image Format Specification" 1.0 (2006-10-11); QEMU `v11.1.1` `block/vpc.c`; VirtualBox `v7.2.20` `src/VBox/Storage/VHD.cpp` |
| `vhdx` | `VHDX image` (`VHDX fixed`, `VHDX dynamic`, `VHDX differencing`) | File type identifier, two headers, two region tables, metadata table and items (file parameters, virtual disk size, disk ID, sector sizes, parent locator), BAT with interleaved sector bitmap entries, sector bitmap blocks | Strong: `vhdxfile` at offset 0 | [MS-VHDX] protocol revision 8.0 (2024-04-23), sections 2.2-2.6; QEMU `v11.1.1` `block/vhdx.c`, `block/vhdx.h` |
| `vdi` | `VDI image` (`VDI dynamic`, `VDI fixed`, `VDI undo`, `VDI differencing`) | Pre-header (text, signature, version), header 1.1 (384 or 400 B), block map, blocks with optional service bytes | Strong: signature `0xBEDA107F` at 0x40 and header version 1.x (or the old 0.2, reported as unsupported) | VirtualBox `v7.2.20` `src/VBox/Storage/VDICore.h`, `VDI.cpp`, `include/VBox/vd.h`; QEMU `v11.1.1` `block/vdi.c` |

Sources, fetched on 2026-10-13:

| Source | Pin | SHA-256 of the fetched file | Used for |
| --- | --- | --- | --- |
| QEMU `docs/interop/qcow2.rst` | tag `v11.1.1` (identical to `v10.1.0`) | `55c4d0fa03fe0690f444b3ed5ba58e7b075b7ba3f30778a6087e92ac6bc0d5d4` | QCOW2 header, features, extensions, L1/L2 entries, compressed and extended L2 entries |
| QEMU `block/qcow2.h` | tag `v11.1.1` | `b790fdb0e7f81bf491a83f63ff2b070fd3879598572daefb3962b9e829373791` | `L1E_*`/`L2E_*` masks, `MAX_CLUSTER_BITS` |
| VMware "Virtual Disk Format 5.0" technical note | EN-000777-00, updated 2011-12-20 (`vmdk_50_technote.pdf`, Wayback Machine capture 20191108160341 of `vmware.com/support/developer/vddk/`) | `88ce1615a703d1d4e3df3c227846bb9ecda4d929129c191ea4ffe7df3294ad59` | Sparse extent header, grain directory and tables, descriptor, markers, footer |
| QEMU `block/vmdk.c` | tag `v11.1.1` | `75dd58a247840b6fcf8be25e548bef67688317fb59c04b31f646f5af51101af3` | Version 3, zlib grain streams, footer at the file size minus 1536, `numGTEsPerGT` up to 512 |
| Microsoft VHD specification | Version 1.0, 2006-10-11 (`Virtual Hard Disk Format Spec_10_18_06.doc`, download.microsoft.com) | `f2aca9d584b41a2b83ec12190236befa33097b97a7296b1fccff6138438a062d` | Footer, dynamic header, BAT, blocks, differencing disks, checksum |
| QEMU `block/vpc.c` | tag `v11.1.1` | `715c139b85528655feeee037f2fe9ded25bfc8cc9f53ff8876f0f66f37bf51d4` | Bitmap size, block size and BAT checks |
| VirtualBox `src/VBox/Storage/VHD.cpp` | tag `v7.2.20` (`f2792cf44f66`) | `4e6295bd8695dca324bb230738f691af5cb334ff6a837e5d6a79897ecf5bdb3d` | Parent name in UTF-16BE, sector bitmap bit order |
| [MS-VHDX] | Revision 8.0, 2024-04-23 (`[MS-VHDX].pdf`) | `1419e02e8dd2f6f223b44230e88518c90f6e6af09f902b17f86576fb548d46f4` | Every VHDX structure |
| QEMU `block/vhdx.h`, `block/vhdx.c` | tag `v11.1.1` | `4ec82961ae7f9cb84224f1e37730ea6f97085c4764eaf3e48e10b6f72da76830`, `89c1b6ba2472f3177d0ad20920c5b0541ad988b51687a87882e39f31c2c857b4` | BAT entry count (the specification's formulas are figures), identical headers, the v0.95 unmapped state |
| VirtualBox `VDICore.h`, `VDI.cpp`, `include/VBox/vd.h` | tag `v7.2.20` | `88f19bdae9f396c90591878b5d7732a5511d0bb7f949682da2cd564524308ff1`, `dee6c21157a2d911bbf411d101d19700acad384836d2200c7541708afcf8d661`, `e8796643c6125f46431fa9b348be33e8c2d3827ec56b586059bad12adf856385` | VDI structures and validation |
| QEMU `block/vdi.c` | tag `v11.1.1` | `844d7bf64dca9eaf57f7a639eca9d69ead978e23d304510b0c7ef576a0df1f62` | Free and zero block pointers |

## The guest disk child

- **One stored run.** When the guest's bytes lie in one contiguous run of
  the file (a fixed VHD always; a dynamic VHD, VHDX or VDI whose blocks
  happen to be stored in order), the child is a borrowed slice at that file
  offset, with no transform. A fixed VHD's slice is the whole guest disk
  however large it is; for other layouts it covers the analyzed range.
- **Assembled.** Otherwise the first `min(virtual size, 64 MiB)` guest bytes
  are assembled into an owned buffer: stored blocks are copied, compressed
  blocks decoded, zero and unallocated blocks left as zeros. The child's
  stored range is the whole file (offset 0) and its `decoded` range names
  the layout: `QCOW2 clusters`, `VMDK grains`, `VHD blocks`, `VHDX blocks`
  or `VDI blocks`. A note gives the bytes that were stored, decoded, zero or
  unallocated, and held by a parent.
- **Recognized formats only.** The child is listed when the guest disk is a
  recognized format (`Classify::IfRecognized`); otherwise a note says it is
  not classified. A guest disk is data, so it never goes to the code model
  on its own.
- **Parents and backing files.** A QCOW2 backing file, a VMDK delta link's
  parent, a differencing VHD's or VHDX's parent and a differencing VDI's
  parent hold the blocks this file leaves unallocated. Those bytes are not
  present: they read as zeros, and a note names the parent as the file
  stores it (QCOW2 backing file name and format; VMDK `parentFileNameHint`
  and `parentCID`; VHD parent Unicode name and unique ID; VHDX parent
  locator `parent_linkage` and paths; VDI linkage UUID).
- **Encrypted or elsewhere.** An encrypted QCOW2 (AES or LUKS) is opaque:
  no child, `opaque` set, and a note. A QCOW2 with an external data file has
  no child either; the note names the file.
- Metadata: `vdisk_virtual_size`, `vdisk_guest_size`, `vdisk_stored_size`,
  `vdisk_compressed_size`, `vdisk_parent_size`, plus `vdisk_qcow2_*`
  (version, cluster size, snapshots, backing file, data file),
  `vdisk_vmdk_*` (grain size, create type), `vdisk_vhd_*` (disk type,
  creator, block size), `vdisk_vhdx_*` (block size, creator, disk ID) and
  `vdisk_vdi_block_size`.

## Wire units and byte order

| Layout | Byte order | Units |
| --- | --- | --- |
| QCOW2 | Big-endian | Byte offsets; cluster size `1 << cluster_bits`; compressed descriptors count additional 512-byte sectors |
| VMDK | Little-endian | Every offset and size in 512-byte sectors (capacity, grain size, descriptor, grain directory, grain table entries); grain marker sizes in bytes |
| VHD | Big-endian | Footer and header offsets in bytes; BAT entries in 512-byte sectors; block size in bytes; parent name UTF-16BE |
| VHDX | Little-endian | BAT offsets in 1 MiB units (bits 20-63); metadata offsets relative to the region; sizes in bytes; strings UTF-16LE |
| VDI | Little-endian | Byte offsets and sizes; block pointers are block indices |

## Validation and resource bounds

- QCOW2: version 2 or 3; `cluster_bits` 9-21 (QEMU's 2 MiB limit); crypt
  method 0-2; unknown incompatible feature bits are unsupported (the
  specification requires refusing them); `refcount_order` at most 6;
  `header_length` at least 104, a multiple of 8 and within the first
  cluster; the compression type consistent with its feature bit (0 deflate,
  1 zstd); extended L2 entries need 16 KiB clusters; header extensions stay
  in the first cluster (at most 2 MiB, at least 8 bytes per step); the
  backing file name is at most 1023 B; the L1 and refcount tables lie in
  the file at cluster-aligned offsets and the L1 table covers the virtual
  size. Reserved L1 and L2 bits, unaligned host offsets, subclusters both
  allocated and zero, and allocated subclusters without a host cluster are
  errors. A compressed cluster's stored range is at most two clusters (the
  sector count field is `cluster_bits - 8` bits wide), clipped to the file.
- VMDK: version 1-3; the newline check bytes when flag bit 0 is set; grain
  size a power of two of 8 sectors (4 KiB) to 128 Ki sectors (64 MiB, the
  extraction limit); `numGTEsPerGT` 1-512; capacity times 512 within 64
  bits; compression algorithm 1 when flag bit 16 is set; the grain
  directory (`ceil(capacity / (GTEs x grain))` entries) and each grain
  table lie in the file; a grain marker names its grain's LBA, has a
  non-zero size of at most two grains; the stream-optimized footer marker,
  footer and end-of-stream marker are checked; at most 1 MiB of descriptor
  text is read.
- VHD: footer cookie, checksum, file format major version 1 and disk type
  2-4; dynamic header cookie, checksum, major version 1, block size a power
  of two of at least 512 B; the whole BAT lies in the file and its entries
  times the block size cover the current size.
- VHDX: the 320 KiB header section is present; a header counts when its
  signature, CRC-32C and version 1 are valid; region tables need their
  signature and CRC-32C, at most 2047 entries, the BAT and metadata regions
  exactly once, 1 MiB-aligned regions at or after 1 MiB inside the file,
  and no unknown region marked required; the metadata table needs its
  signature, at most 2047 entries, no duplicates, items of at most 1 MiB at
  or after 64 KiB inside the region, no unknown item marked required, and
  the file parameters, virtual disk size and logical sector size items;
  block size a power of two of 1-256 MiB; logical sector size 512 or 4096;
  virtual size a multiple of it of at most 64 TiB; the BAT region holds
  every entry the disk needs; block offsets lie after the header section;
  reserved payload state 4 and partially present blocks without a parent
  are errors.
- VDI: the checks of `vdiValidateHeader` (header size, block map and data
  offsets, image type, sizes and counts, non-null UUIDs) and a block map in
  the file; block pointers must be below the allocated count; blocks must
  be at least 512 B (a bound of this parser: VirtualBox accepts any power
  of two, QEMU only 1 MiB).
- Every table count is validated against the file before it is read, every
  offset computation is checked, and only the tables that map the analyzed
  range are read. At most 64 MiB of guest disk is assembled (one buffer);
  each compressed block decodes to at most its block size through
  `compressed::decode_prefix`, which stops at that size (QCOW2: a stream
  may run on into the next cluster's bytes in its last sector, and QEMU
  accepts a stream that fills the cluster before its end).
- Strong detection means a corrupt image is a parse error, not raw code.
  A truncated image either fails or assembles the same guest disk as the
  whole image (the property the truncation sweep checks).

## Detection order

`vdisk::detect` runs in `detect_format` before the archive, read-only and
flash filesystem, ext, EROFS, console disc, ISO 9660, partition table and
FAT checks. A fixed VHD starts with the guest disk's first sector (an MBR,
a GPT, a FAT or ISO 9660 volume), which those checks would otherwise claim;
only its footer at the end says it is a VHD. The checks before it are
executable and firmware formats whose headers a disk's first sector does
not carry. Within the family the VHD check runs first, so a fixed VHD whose
guest is itself an image is reported as the VHD.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| V1 | A fixed VHD's file is its current size plus the footer ("the size of the entire file is the size of the hard disk in the guest operating system plus the size of the footer"), so detection by the footer alone requires that; a file that merely ends with a VHD footer (a VHD as the last member of an ISO or archive) is not claimed. Parsed anyway, a fixed VHD's guest disk is every byte before the footer and a mismatch is noted (QEMU's `vpc.c` says the footer size of Virtual PC images is "too large usually" relative to their CHS geometry) | `a_footer_at_the_end_must_describe_the_file_to_be_detected`; a Virtual PC fixed image whose file size is not its current size plus 512 would not be detected (not verified on Virtual PC images) |
| V2 | The 511-byte footer of images older than Virtual PC 2004 is the 512-byte layout without its last reserved byte | `old_511_byte_vhd_footer_is_found_at_the_end` builds one by removing that byte; no real old image was available (not verified) |
| V3 | VHD sector bitmaps are read most significant bit first (VirtualBox `vhdBlockBitmapSectorContainsData`; the specification does not say) | `differencing_vhd_reads_present_sectors_and_leaves_the_rest_to_the_parent` uses that order; a differencing image written by Hyper-V or Virtual PC would confirm it (not verified) |
| V4 | VMDK grains are zlib streams (QEMU writes and reads them with `compress2`/`uncompress`; the technote names RFC 1951); raw DEFLATE is tried when zlib fails | `streamoptimized_vmdk_grains_are_zlib_streams_behind_markers`; a VMware-written stream-optimized OVA whose grains are raw DEFLATE would still decode (not verified on VMware-written files) |
| V5 | A VHDX log with a non-zero `LogGuid` may hold updates; reading the metadata and BAT as stored is acceptable for classification | `vhdx_second_region_table_and_non_empty_log` checks the note; an image whose replayed log changes the BAT would read differently (log replay is not implemented) |
| V6 | VHDX payload blocks that are not present, undefined or unmapped read as zeros in a disk without a parent, as the specification allows | `vhdx_unknown_required_metadata_and_reserved_block_states_are_errors` |
| V7 | GUIDs in VHDX and VDI are stored in binary GUID form (`Data1`-`Data3` little-endian), VHD unique IDs in RFC 4122 byte order | The QEMU fixtures' region GUIDs decode to the specification's text; VHD and VDI identifiers are only displayed |
| V8 | A guest disk that is not a recognized format is not code | Such a disk is not listed and the virtual disk reports no ISA (`qcow2_backing_overlay_leaves_unallocated_clusters_to_the_backing_file`) |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Parent and backing images | Not opened: a differencing disk's or overlay's missing blocks read as zeros, and a note names the parent |
| Encrypted QCOW2 (AES, LUKS) | Opaque; not decrypted |
| QCOW2 external data files, internal snapshots, bitmaps and refcounts | Data files are not opened; only the active L1 table is read; refcounts and bitmaps are not read (their bounds are checked) |
| QCOW version 1, QED, VMware `COWD` (ESXi) and SESparse extents, VMDK descriptor files and split (`twoGbMax...`) extents | Not recognized, or (split extents) each extent file parses on its own; a descriptor listing several extents is noted |
| VHDX log replay | Not implemented; a non-empty log is noted |
| VHDX with 4096-byte logical sectors | Parsed by the specification's arithmetic; QEMU supports only 512 (not verified on a real image) |
| VDI header version 0 (VirtualBox before 1.4) | Recognized, reported as unsupported |
| Split VHD files (`.v01`, ...) | Not joined |
| Guest disks larger than 64 MiB | Only the first 64 MiB are assembled and analyzed (a fixed VHD's stored slice is complete) |
| Images from VMware, Hyper-V, Virtual PC or VirtualBox | Not tested: every fixture was made by QEMU 11.1.1 or built in the tests |

## Verification

On 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly `f248f4038`
2026-09-05, QEMU 11.1.1, Node v25.8.1 with Playwright Chromium), `cargo
test --all-features --locked` passed: 1,888 tests, 6 ignored (the
repository's existing ignores), including the 35 tests of `tests/vdisk.rs`
and the 12 unit tests of `src/formats/vdisk*`. The sweeps cover, for every
fixture and the synthetic differencing VHD and VHDX disks, every prefix up
to 4 KiB and in the last 2 KiB plus at most 2048 strided prefixes between
(each must fail or assemble the same guest disk), and 0x00, 0xFF and
bit-flip mutations of every byte of the first 512, every second byte of the
last 512, up to 256 strided positions, and the VHDX headers, region tables,
metadata table and BAT; every 16th header byte is also mutated through the
full classification. With `IDA_INPUT_DIR` set to IDA Pro's test inputs
(7,315 files, none a virtual disk image), no input was detected as a
virtual disk. After `./build-web.sh`, `web/tests/vdisk.test.mjs` (4 tests)
passed through `/pkg/zrax.js`, `/dist/zrax.js`, `/web/index.html` and
`/dist/index.html`; the whole browser suite ran 216 tests, 212 passed and 4
skipped (the existing skips that need D10 and RX113 firmware not in the
repository). Behavior on images written by VMware, Microsoft or Oracle
products is not verified.

After integration on the same day, the native suite passed 1,990 tests
with 6 ignored; IDA's corpus (4,621 files) and a scan of 82,323 local
files (macOS system, Homebrew and toolchain files up to 8 MiB) classified
as before, so no existing input is claimed as a virtual disk. The
`tests/fixtures/iso9660/rockridge.iso.gz` image converted with
`qemu-img convert -O qcow2|vpc|vmdk|vdi|vhdx` (qemu-img 11.1.1) classified
as each virtual disk with the ISO 9660 guest and its x86-64 ELF member.
