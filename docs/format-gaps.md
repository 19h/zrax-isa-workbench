# Format coverage gaps

This register lists containers, encodings and transforms that Zrax does not
handle, plus defects in existing kernel-image support. It records missing
coverage, not committed work. Absence was checked against the source as of
2026-10-12 (`dcc295a`). Section 1 was also reproduced with the release CLI on
synthetic headers. Magic values and offsets in sections 2-8 come from public
specifications and have not been tested against fixtures in this repository.
Entries marked *layout not established here* need a sample or primary source
before any parser is written.

Impact reflects how much existing coverage a fix unlocks, not format popularity.

As of 2026-10-13 every entry with an established layout is implemented. Each
section's status line names what was built and links the family's document,
which records its sources, bounds and known boundaries.

## 1. Defects in existing kernel and boot-image support

**Resolved 2026-10-12.** All five defects are fixed: uImage byte order,
`XLF_KERNEL_64`, Arm zImage (little-endian, BE8 and BE32), FIT `/images`, and
decoded kernel payloads classified recursively. bFLT no longer defaults to
Arm. See [kernel and boot images](kernel-images.md). The table is kept as the
original record.

| Impact | Input | Current result | Location | Expected |
| --- | --- | --- | --- | --- |
| High | U-Boot uImage, any architecture | Reports `big` endianness for every image; an ARM/Linux uImage yields `arm 32 big 100%` | `src/formats/kernel.rs:427` | Header byte order (always big-endian) is kept separate from code byte order, as TI COFF already does; code order comes from the arch ID or the payload |
| High | x86-64 bzImage (`xloadflags` bit 0 `XLF_KERNEL_64` at `0x236`, protocol >= 2.12) | Always `x86 32 little 100%` | `src/formats/kernel.rs:327` | x86-64 when `XLF_KERNEL_64` is set |
| High | ARM32 zImage (`0x016F2818` at `0x24`, start/end at `0x28`/`0x2C`, endianness marker `0x04030201` at `0x30`) | No detector; falls through to raw heuristics, which a header-only probe left inconclusive | `src/formats/kernel.rs:155` | Recognized as a Linux ARM zImage with byte order from the marker |
| High | U-Boot FIT | FDT magic always returns `Dtb` with unknown ISA; `KernelFormat::Fit` is never constructed. The README lists FIT as covered | `src/formats/kernel.rs:173` | `/images` subnodes read for `arch`, `type`, `compression` and `data` or `data-offset`/`data-size`; each image becomes a slice |
| High | Compressed kernel payloads | uImage compression is a note only (`kernel.rs:414`); bFLT `GZIP` is a flag name only (`bflt.rs:86`); bzImage payloads are not inflated; kernel formats take the non-recursive `parse_detected` path | `src/lib.rs:468` | Payload decoded (section 2) and classified recursively, so extension detection, multi-ISA scans and header/code cross-checks run on kernel code |

Reproduction: `zrax --format short` on a 64-byte ARM uImage header, a 1 KiB
bzImage setup header with protocol 2.15 and `XLF_KERNEL_64`, and a 512-byte
buffer with the ARM zImage header fields. FIT behavior is from source inspection.

## 2. Decompression layer

**Implemented 2026-10-12** for gzip, zlib, raw DEFLATE, xz, LZMA-alone, LZ4
(frame and legacy), Zstandard, bzip2, lzop/LZO1X, LZFSE/LZVN and Apple LZSS,
plus Brotli for containers that name it; standalone streams are recognized as
formats. Raw LZ4 and LZO1X blocks, 3DS BLZ, the JFFS2 rtime and rubin coders,
EFI/Tiano compression and EDK2 LZMA F86 followed (2026-10-13) for the
containers that store them. See
[compressed streams](compressed-streams.md). The table below is
kept as the original register; containers still have to call the layer where
their header names a codec (sections 1, 3 and 4).

| Impact | Codec | Identification | Typical locations | Candidate pure-Rust crate (not evaluated) |
| --- | --- | --- | --- | --- |
| High | gzip / zlib / raw DEFLATE | `1F 8B`; zlib `78 01`/`78 9C`/`78 DA`; raw DEFLATE has no magic | uImage, bzImage, bFLT, initramfs, Android boot, Wii U RPX sections | `miniz_oxide`, already an optional dependency under the `wasm` feature only |
| High | xz / LZMA | `FD 37 7A 58 5A 00`; LZMA-alone properties byte (commonly `5D`) and 64-bit size | Router kernels, SquashFS, CBFS stages | `lzma-rs` |
| High | LZ4 | Frame `04 22 4D 18`; Linux legacy `02 21 4C 18` | Android kernels, initramfs, SquashFS | `lz4_flex` |
| Medium | Zstandard | `28 B5 2F FD` | Kernels, SquashFS, FIT images | `ruzstd` |
| Medium | bzip2 | `BZh` + block-size digit | uImage, older kernels | None selected |
| Medium | LZO (lzop) | `89 4C 5A 4F 00 0D 0A 1A 0A` | uImage, UBIFS, SquashFS | None selected |
| Medium | Apple LZFSE / LZVN / LZSS | `bvx2`, `bvx1`, `bvxn`, `bvx-`; LZSS `complzss` | IMG4 payloads, kernelcaches | `lzfse_rust` for LZFSE |

Constraints for any implementation:

- Apply the existing per-extraction limit (`MAX_PAYLOAD`, 64 MiB,
  `src/formats/ti.rs:17`) and the six-level nesting limit (`src/lib.rs:258`).
  Decoders must stop at the output cap rather than allocate the declared size.
- Keep stored and decoded coordinates separate, following D10: hex and entropy
  views refer to stored bytes, classification refers to decoded bytes, and
  metadata records the codec and stored offsets.
- Raw DEFLATE and LZMA-alone have weak or no magic. Try them only where a
  container field names the codec.

## 3. Filesystem and archive images

Embedded Linux firmware usually places executables inside one of these images.
The intended scope is the same as `ar` member handling (`src/lib.rs:331`):
enumerate members, classify recognized executables, and bound the member count.
This is not a general extractor. Most of these depend on section 2.

Status 2026-10-13: ZIP (ZIP64; stored, deflate, bzip2, LZMA, Zstandard and
xz members decoded with CRC-32 verified; Deflate64 and encrypted members
opaque; APK, JAR, IPA, Nordic DFU and PDX are labels), tar (ustar, pax and
GNU; header checksums verified) and CPIO (newc, crc, odc and old binary in
both byte orders; concatenated initramfs) are implemented; see
[archives](archives.md). SquashFS 4.0 (compressor IDs 1-6; regular files
listed by path), CramFS (both byte orders, CRC-32 verified) and romfs are
implemented; SquashFS 1.x-3.x, big-endian and streamed images are recognized
but not enumerated; see [read-only filesystems](rofs.md). UBI (PEB size
discovery, volume table, static and dynamic volumes), UBIFS (node scan; the
index is not walked) and JFFS2 in both byte orders (weak; every node CRC
verified) are implemented; see [flash filesystems](mtd.md). ext2/ext3/ext4
(strong detection with superblock geometry checks; block maps, extent trees
and htree directories; `metadata_csum` and `gdt_csum` verified; inline-data
and encrypted files not read) is implemented; see [ext](ext.md). EROFS
(compact and extended inodes; LZ4, MicroLZMA and DEFLATE clusters; Zstandard
extents not decoded) followed; see [EROFS](erofs.md). Partition tables (MBR
with EBR chains, GPT, Apple Partition Map) followed too; see
[partition tables](partitions.md). FAT12/16/32 (weak; FAT type by cluster
count) and exFAT (strong; boot, entry-set and up-case checksums verified)
followed; see [FAT](fat.md). ISO 9660 (Rock Ridge, Joliet; El Torito boot
images as children; UDF bridge and hybrid partition tables noted) followed;
see [ISO 9660](iso9660.md). Java runtime images followed: jimage (both
byte orders; perfect-hash index verified; `zip` and `compact-cp`
resources decoded) and JMOD (ZIP archive at offset 4 as a child); see
[Java runtime images](javaimage.md). Every row
of this section is now implemented.

| Impact | Format | Identification | Notes |
| --- | --- | --- | --- |
| High | SquashFS | `hsqs` (little-endian) / `sqsh` (big-endian); compressor ID at superblock offset 20 | Compressor IDs 1-6: gzip, LZMA, LZO, xz, LZ4, zstd |
| High | CPIO | ASCII `070701` (newc), `070702` (CRC), `070707` (odc) | initramfs; usually compressed |
| High | ZIP | `PK 03 04` local headers, central directory at end | Also unlocks APK, JAR, IPA, Nordic DFU packages and ODX PDX (sections 4 and 6) |
| Medium | tar | `ustar` at offset 257 | |
| Medium | UBI / UBIFS | UBI erase-counter `UBI#`, volume header `UBI!`; UBIFS node `0x06101831` | Raw NAND dumps also need OOB removal (section 7) |
| Medium | JFFS2 | Node magic `0x1985` | |
| Low | CramFS | `0x28CD3D45` | |
| Low | romfs | `-rom1fs-` | |
| Low | ext2/3/4 | `0xEF53` at `0x438` | |

## 4. Containers with ISA-bearing or slice-bearing headers

Status 2026-10-13: every row of this section is implemented: UF2 (family ID
mapped to ISA, reassembly by `targetAddr`, one child per family), STM32 DfuSe
(suffix CRC-32 verified), Silicon Labs GBL (CRC-32 verified; encryption opaque,
signatures not verified) and Cypress `.cyacd`/`.cyacd2` (weak); USB DFU 1.1
suffix files (CRC-32 verified, firmware child), Silicon Labs EBL (end CRC
verified; AAT platform field; encryption opaque, MAC not verified) and Nordic
nRF5 DFU init packets (weak, metadata only) followed; see [MCU update
images](mcu.md); Allwinner eGON/TOC0, Rockchip RKFW/RKAF/RKBOOT and idbloader,
MediaTek preloader headers and legacy Qualcomm MBN (SBL and 40-byte v3); see
[SoC loaders](socboot2.md). Apple IMG4/IM4P (payloads decoded; KBAG payloads
opaque) and dyld shared caches; see [Apple images](apple.md). Android boot and
`vendor_boot` images (kernel and ramdisk decoded and classified), sparse images
(expanded, CRC-32 verified), OTA `payload.bin` (full operations reassembled,
SHA-256 checked; delta operations opaque) and bootloader packs (`BOOTLDR!`,
Qualcomm meta image, FBPK v1/v2); see [Android images](android.md). Xilinx
Zynq-7000/ZynqMP `BOOT.BIN` (partition targets from the destination-CPU field;
bitstream partitions opaque), NXP i.MX IVT and AHAB images (no ISA inferred
from the SoC family) and NXP SB2.0/2.1/3.1 (metadata only; signatures not
verified); see [SoC boot images](socboot.md). UEFI firmware volumes (FFS files,
compression and GUID-defined sections, nested volumes, flash device images), TE
images and the Intel flash descriptor region map are implemented; ME/CSME and
AMD PSP regions are parsed for structure only (Intel ME `$FPT` and `$CPD`, AMD
EFS and PSP directories, Intel and AMD microcode; all opaque); see [UEFI and PC
flash images](uefi.md) and [PC firmware blobs](pcfw.md). Chromium FMAP (at
offset 0, or found by a bounded search) and coreboot CBFS (`LARCHIVE` regions
and master-header ROMs; LZMA/LZ4 stages, SELF segments, SHA-2 hash attributes
verified) are implemented; see [coreboot](coreboot.md). Router wrappers
(Broadcom TRX v1/v2, Netgear CHK, D-Link SEAMA, TP-Link mktplinkfw v1/v2/v3 and
SafeLoader; TRX CRC and CHK checksums verified, MD5 digests not verified; LZMA
kernels decoded by the OpenWrt convention) are implemented; see [router
firmware](router.md). Windows minidumps (`ProcessorArchitecture` as the
target; module memory as code, limited to executable sections when PE
headers are dumped, other memory opaque; checked against three
real dumps) and kernel crash dump headers (`PAGEDUMP`, `PAGEDU64`; bodies
not parsed) followed; see [Windows crash dumps](minidump.md). NetWare
Loadable Modules (the i386, SPARC, PowerPC and Alpha signatures as the
target field; packed NLMPACK modules opaque, not decoded) followed; see
[NetWare modules](nlm.md). PC/GEOS geodes (2.0 and 1.x headers; `HAF_CODE`
resources as 16-bit x86; relocations counted, not applied; GEOS VM and
data files recognized but not parsed) followed; see [PC/GEOS
geodes](geos.md). Psy-Q LNK objects (PROGRAMTYPE as the target; `.text` as
code; `LIB` archives and relocation application not implemented) followed;
see [Psy-Q objects](psyq.md). ARM Image Format files (executable,
non-executable and extended AIF; compressed payloads opaque, no documented
codec) followed; see [ARM AIF](aif.md). Symbian OS v9 SIS packages (UID
checksum, controller and data CRC-16s and per-file SHA-1 verified; files by
target path; signatures not verified; pre-v9 EPOC SIS not implemented)
followed; see [Symbian SIS packages](sis.md). LE/LX headers without an MZ
stub (weak; header, object table, page table and page extents validated;
the CPU type is the ISA evidence) and PE images whose DOS header starts
with `ZM` (only with the PE signature at `e_lfanew`) followed; see
[DOS-family headers](mz.md). UEFI capsules (FMP, nested FMP,
`EFI_CAPSULE_GUID`, JSON, Windows UX, Intel, Lenovo, Toshiba and AMI Aptio;
signatures not verified, Framework split capsules not supported) followed;
see [UEFI capsules](capsule.md).

| Impact | Format | Identification | Architecture evidence | Notes |
| --- | --- | --- | --- | --- |
| High | UF2 | 512-byte blocks: `0x0A324655` at 0, `0x9E5D5157` at 4, `0x0AB16F30` at 508; flag `0x2000` puts a family ID at offset 28 | Family ID maps to an MCU family (RP2040/RP2350, SAMD21/51, nRF52, ESP32-Sx, STM32 lines) | Payload is a sparse address map; reassemble by `targetAddr` before scoring |
| High | UEFI firmware volumes | `_FVH` at FV offset `0x28`; FFS files and sections inside | PE32 and TE sections carry machine fields | Sections can be compressed or GUID-defined (section 2) |
| High | UEFI TE images | `VZ` signature, machine `u16` at offset 2 | Direct machine field | Stripped PE header |
| Medium | Intel flash descriptor | `0x0FF0A55A` (offset `0x10` on current platforms) | None directly; region map locates BIOS and ME regions | ME/CSME and AMD PSP regions use separate layouts, not established here |
| Medium | Chromium FMAP | `__FMAP__` | None directly; named areas such as `EC_RO`/`EC_RW` | The Pixel EC research notes rule FMAP out for those files, but it is common in Chromebook AP and EC images |
| Medium | coreboot CBFS | Master header `ORBC`; file headers `LARCHIVE` | Stage and payload attributes | Stages are often LZMA or LZ4 |
| High | Android boot / vendor_boot | `ANDROID!` (header v0-v4); `VNDRBOOT` | uImage-style; kernel and ramdisk are slices | Kernel often gzip or LZ4 |
| Medium | Android sparse image | `0xED26FF3A` | None | Expands to a partition image; needs section 3 to be useful |
| Medium | Android OTA payload | `CrAU` | None | Protobuf manifest; operations may be bsdiff/puffdiff against a source image |
| Medium | Pixel bootloader packs | `BOOTLDR!` on earlier devices; `FBPK` reported for Tensor-era devices | Per-image names | *Layout not established here*; relevant to the Pixel EC investigation |
| High | Apple IMG4 / IM4P | DER sequence with IA5String `IM4P`, a 4CC type (`krnl`, `ibot`, ...) and an OCTET STRING payload | Type identifies the component; payload is usually Mach-O or raw Arm | Payloads often LZSS or LZFSE (section 2); encrypted payloads carry a `KBAG` and remain opaque |
| Medium | dyld shared cache | `dyld_v1` followed by a space-padded architecture name in a 16-byte field | Architecture string in the magic | Contains many Mach-O images |
| High | Xilinx Zynq / ZynqMP `BOOT.BIN` | Width word `0xAA995566` at `0x20`, `XNLX` at `0x24` | ZynqMP partition headers name the destination CPU: A53, R5 or PMU (MicroBlaze) | Natural multi-slice container like D10; bitstream partitions belong in section 8 |
| Medium | NXP i.MX IVT / HAB | IVT tag `0xD1`, length `0x0020` | Entry and load addresses only; SoC family implies Arm | |
| Medium | NXP SB2 / SB3 | *Layout not established here* | | LPC and i.MX RT secure binaries; often encrypted |
| Medium | Allwinner eGON | `eGON.BT0` at offset 4 after a branch instruction | Arm or RISC-V depending on SoC | Checksum and length fields follow the magic |
| Low | Rockchip images | `RKFW` update images containing `RKAF` | Per-partition names | idbloader headers are scrambled; *layout not established here* |
| Low | MediaTek preloader, legacy Qualcomm MBN | *Layout not established here* | | Modern Qualcomm images are ELF and already parsed |
| Medium | STM32 DfuSe `.dfu` | `DfuSe` prefix, `Target` records, 16-byte DFU suffix with `UFD` signature and CRC32 | Vendor/product IDs in the suffix | Element addresses and sizes per target |
| Medium | Silicon Labs GBL | Header tag `0x03A617EB` (per vendor documentation, not verified here) | EFR32 parts are Cortex-M | Tag-based; program data may be encrypted |
| Low | Cypress/Infineon `.cyacd` / `.cyacd2` | Text; header row with silicon ID and revision; `.cyacd2` has `@APPINFO` | Silicon ID maps to a device | |
| Medium | Router wrappers | Broadcom TRX `HDR0` with partition offsets; Netgear CHK, D-Link SEAMA and TP-Link headers | None; headers give partition offsets only | Payloads are usually an LZMA kernel and SquashFS, so sections 2 and 3 come first |

## 5. Console and retro ROMs

Status 2026-10-13: every row of this section is implemented. Mega
Drive/Genesis, PS-X EXE, Dreamcast IP.BIN, Wii U
RPX/RPL (zlib sections inflated), 3DS NCCH/ExeFS (BLZ `.code` decoded) and
3DSX, and PSP PBP are implemented; see [console images](retro.md). Nintendo
DS/DSi (ARM9 and ARM7 slices with their core variants; secure and modcrypt
areas opaque), Game Boy Advance, Game Boy/Color (`z80`, variant SM83),
iNES/NES 2.0 (PRG-ROM as 6502; CHR-ROM opaque), SNES (weak; LoROM, HiROM and
ExHiROM internal headers; `w65816` from the platform) and Nintendo 64 (all
three byte orders; CIC check code verified) are implemented; see
[Nintendo ROMs](nintendo-roms.md). Thumb is not distinguished on DS or GBA.
Beyond the table, Master System/Game Gear, Sega 32X, Saturn IP.BIN, Sega CD
system areas, MSX cartridges, Atari Lynx and 7800, C64 CRT, Atari ST GEMDOS
executables, ZX Spectrum .z80/.sna snapshots, WonderSwan and Neo Geo Pocket
followed; see [console and home-computer images](retro2.md). Console disc
images followed: GameCube (boot DOL, apploader, FST files), Wii (partition
table; AES partitions opaque) and Xbox XDVDFS (XISO, XGD1, XGD2, XGD3);
Wii decryption and the GCZ, WIA, RVZ, WBFS, CISO and NKit containers are
not implemented; see [console disc images](discs.md).

These follow the existing SPC, DOL, XBE, XEX, SELF and NSO support. The headers
also identify code slices for model classes Zrax already has, so they double as
labelled training data.

| Impact | Platform | Identification | CPU / model class | Notes |
| --- | --- | --- | --- | --- |
| High | Nintendo DS | ARM9 offset/entry/load/size at `0x20`-`0x2C`; ARM7 at `0x30`-`0x3C` | `arm`/`thumb` (ARMv5TE and ARMv4T) | Two slices, matching the D10 slice shape |
| Medium | Game Boy Advance | Logo at `0x04`, `0x96` at `0xB2`, complement check at `0xBD` | `arm`/`thumb` | |
| Medium | Game Boy / Color | Logo at `0x104`, header checksum at `0x14D` | `sm83` | |
| Medium | NES (iNES / NES 2.0) | `NES 1A` | `mos6502` (2A03 without decimal mode) | PRG and CHR banks; CHR is graphics, not code |
| Medium | Sega Genesis / Mega Drive | `SEGA` at `0x100` | `m68k`, plus a `z80` sound program | |
| High | Nintendo 64 | First word `0x80371240` (`.z64`), `0x37804012` (`.v64`), `0x40123780` (`.n64`) | `mips` (R4300i, big-endian) | Three byte orders of one image; exercises byte-order handling |
| Medium | PlayStation PS-X EXE | `PS-X EXE` at 0; `pc0` at `0x10`, `t_addr` at `0x18`, `t_size` at `0x1C`; 2048-byte header | `mipsel` | |
| Low | Dreamcast | `IP.BIN` begins `SEGA SEGAKATANA` | `sh` | `1ST_READ.BIN` is often scrambled |
| Low | Wii U RPX / RPL | ELF with `EI_OSABI` `0xCA`, `EI_ABIVERSION` `0xFE` | `ppc` from `e_machine` (already detected) | Sections flagged `0x08000000` are zlib-compressed (section 2) |
| Low | Nintendo 3DS NCCH / ExeFS | `NCCH` at `0x100` | `arm` | Usually encrypted; code may be compressed |
| Low | PSP PBP | `00 50 42 50` (`\0PBP`) | `mipsel` (Allegrex) | Embedded `~PSP` executables are usually encrypted |

The SNES CPU (65816) has no model class; `m7700` is the nearest. SNES ROMs
are reported as `w65816` from the platform, without a code-model check.

## 6. Automotive

These would extend the VBF, SGO, FRF, SOX, EPR, OLS and BCF support.

**Implemented 2026-10-12** for ODX-F, Honda RWD (`0x5A`, `0x31`), Toyota CUW and
Mercedes CFF; PDX packages followed on 2026-10-13 with the ZIP container,
which resolves `EXTERN-FLASHDATA` data files ([archives](archives.md)); SMR-F
has no public layout. See [automotive containers](automotive.md).

| Impact | Format | Identification | Notes |
| --- | --- | --- | --- |
| High | ASAM ODX-F / PDX | PDX is a ZIP with `index.xml`; ODX-F `FLASHDATA` elements declare `DATAFORMAT` (Intel HEX, Motorola S, binary or user-defined), inline or external data, and segments with start addresses | Vendor-neutral; needs ZIP (section 3). Inline hex data can go to the existing hex parsers |
| Medium | Honda RWD | Documented by the open-source `rwd-xray` tool | Often gzip-wrapped |
| Low | Toyota CUW | *Layout not established here* | Needs samples |
| Low | Mercedes SMR-F / CFF | *Layout not established here* | Needs samples |

## 7. Transforms on raw dumps

**Implemented 2026-10-12**: 16/32-bit byte swaps, 2- and 4-lane interleaves
(one file, either lane order, or separate files through
`detect_interleaved` / `zrax --interleave`) and NAND spare removal for five
page geometries, with the union-bound penalty described below. See
[raw-dump transforms](transforms.md) for when they are tried and the cases
the first-order model still misreads.

These are encodings, not containers. Each breaks the adjacent-byte pairs the
first-order model scores, so correctly dumped code reads as non-code.

| Impact | Transform | Origin |
| --- | --- | --- |
| High | Even/odd byte de-interleave (two files or one interleaved file) | Two 8-bit EPROMs on a 16-bit bus; four-way for 32-bit buses. Common in automotive and arcade dumps |
| Medium | 16-bit and 32-bit byte swaps | Programmer or reader byte-order conventions |
| Medium | NAND OOB/ECC removal | Raw NAND reads with spare area per page, e.g. 2048+64 or 4096+224 bytes |

A transform search would run only after raw classification is inconclusive,
record the chosen transform in metadata, and keep stored offsets for the hex
and entropy views. Trying `k` transforms adds `k` chances of a false accept;
a union bound suggests raising the 16-bit total-evidence threshold by at least
`log2(k)` bits.

## 8. Non-code recognizers

**Resolved 2026-10-12**: FPGA bitstreams are recognized and excluded from
ISA scoring. Xilinx `.bit` (strong) and headerless `.bin` in both word orders
(weak); Lattice iCE40 (strong with a comment block, weak and CRC-verified
without one) and ECP5/MachXO/Nexus; Intel Cyclone V `.rbf` (weak, option-frame
CRC) and `.pof` (strong). `.sof` and Arria 10 `.rbf` have no public layout.
See [FPGA bitstreams](bitstream.md).

FPGA bitstreams should be recognized and excluded from ISA scoring, as D10 does
for its FPGA component ([D10 support](d10-container.md)). They currently reach
the raw-code model.

| Impact | Format | Identification |
| --- | --- | --- |
| Medium | Xilinx `.bit` | Tag-length header (design name, part, date, time, length) followed by sync word `0xAA995566` |
| Low | Lattice iCE40 | Sync `7E AA 99 7E` |
| Low | Intel `.rbf` / `.sof` | `.rbf` has no magic, so recognition would be weak; `.sof` *layout not established here* |

## Suggested order

Done as of 2026-10-13, in this order:

1. Section 1 defects together with gzip, xz/LZMA, LZ4 and zstd from section 2.
   These make the existing uImage, zImage, FIT and bFLT support classify code.
2. UF2: small, fixed layout, and the family ID is direct evidence.
3. ZIP, CPIO and SquashFS member enumeration.
4. Remaining entries according to available samples.

What remains are the boundaries each family's document lists, and the
layouts marked as not established (Mercedes SMR-F, Intel `.sof`, Arria 10
`.rbf`).
