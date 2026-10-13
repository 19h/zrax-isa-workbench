# PC firmware blobs

`src/formats/pcfw.rs` and its submodules recognize the firmware blobs of PC
platforms that are not code for the host CPU: Intel microcode updates, AMD
microcode containers, Intel ME/CSME flash partition tables (`$FPT`) and code
partition directories (`$CPD`) with their `$MN2` manifests, and AMD flash
images (the Embedded Firmware Structure and the PSP, BIOS and combo
directories it leads to). They are built on the shared container model
([compressed streams and the container model](compressed-streams.md)).

None of these blobs is code for an ISA the classifier models. Microcode
updates are encrypted data for the processor's own update loader (Intel SDM
Vol. 3A 12.11.1: "No executable code resides within the update"). ME
partitions and PSP directory entries are firmware and data for separate
engines, and these structures do not say which processor runs them. Every
layout therefore reports an unknown ISA with confidence 0 and no candidates,
and every component is opaque: no byte reaches the code model or extension
detection. Firmware versions in manifests, processor signatures and PSP IDs
are reported as what they are, never as ISA evidence.

## Implemented layouts

| JSON format ID | Layout (variant) | Detection | Components | Primary source |
| --- | --- | --- | --- | --- |
| `intelmicrocode` | One or more microcode updates back to back, optionally followed by erased flash (`Intel microcode update`) | Weak: header version 1, loader revision 1, a valid BCD date, data size a multiple of 4 B, total size a multiple of 1024 B and at least header plus data, the header and data DWORD sum 0, and a consistent extended signature table (count, table sum 0, every entry checksum) for every update in the file | One opaque child per update | Intel SDM Vol. 3A, order 253668-093US (September 2026), section 12.11, Tables 12-7 to 12-10; Linux v6.12 `arch/x86/kernel/cpu/microcode/intel.c` (`intel_microcode_sanity_check`, `scan_microcode`) |
| `amdmicrocode` | One or more containers glued together (`AMD microcode container`) | Strong: magic `0x00414D44` (`DMA\0`) at 0 | One opaque child per patch section | Linux v6.12 `arch/x86/kernel/cpu/microcode/amd.c` (`verify_container`, `verify_equivalence_table`, `__verify_patch_section`, `parse_container`, `scan_containers`) |
| `intelme` | `$FPT` at 0x10 (after the ROM bypass vector) or 0, header versions 0x10, 0x20 and 0x21 (`Intel ME flash partition table`) | Strong: `$FPT` at 0x10 or 0 | One opaque child per valid partition; code partitions described from their `$CPD` (module names, checksum, manifest) or pre-ME 11 manifest | coreboot 25.09 (`07df08836eca`) `util/cbfstool/cse_fpt.c`, `fpt_formats/fpt_hdr_20.c`, `fpt_hdr_21.c`, the vendored `util/me_cleaner/me_cleaner.py`; `UEFITool` A75 (`19a4dab71f1f`) `common/me.h`, `meparser.cpp`; `MEAnalyzer` `MEA.py` (`d27ccdba0aad`) for the 2.1 CRC |
| `intelme` | A standalone code partition: `$CPD` header versions 1 and 2 at 0 (`Intel ME code partition directory`) | Strong: `$CPD` at 0 | One opaque child per module inside the file | coreboot 25.09 `util/cbfstool/ifwitool.c`, `bpdt_formats/subpart_hdr_1.c`, `subpart_hdr_2.c`, `subpart_entry_1.c`; `MEA.py` for the version 2 CRC |
| `amdpsp` | An AMD flash image with the EFS (signature `0x55AA55AA`) at 0xFA0000, 0xE20000, 0xC20000, 0x820000 or 0x20000 (`AMD flash image (Embedded Firmware Structure)`) | Weak: the EFS must lead to at least one directory, and every directory reached must validate (cookie, entry table inside the file, Fletcher-32) | One opaque child per directory entry with stored bytes | coreboot 25.09 `util/amdfwtool/amdfwtool.h`, `amdfwtool.c` (`fletcher32`, `fill_dir_header`, `integrate_psp_ab`, `RUN_BASE`), `amdfwread.c` (`fw_header_offsets`, `relative_offset`, `amdfw_psp_dir_walk`, `amdfw_bios_dir_walk`) |
| `amdpsp` | A standalone directory table: `$PSP`, `$PL2`, `$BHD`, `$BL2`, `2PSP` or `2BHD` at 0 (`AMD PSP/BIOS directory table`) | Strong: the cookie at 0 | Table-relative entries inside the file; others are noted | Same |

No Intel ME/CSME document and no AMD PSP document was read. The ME and PSP
layouts come from open tools; where coreboot leaves a field open,
`UEFITool` and `MEAnalyzer` (community reverse engineering) were consulted
and are named in the notes below.

### Detection order

The strong checks (`pcfw::detect`) run right before the magic-bearing
compressed streams, after every executable and firmware format. Intel flash
descriptor images are claimed earlier by the UEFI family's `FLVALSIG`
check, so an ME region inside one is reached only as a descriptor child
(see below).

The weak checks (`pcfw::detect_weak`) run right before zlib and LZMA-alone,
after the UEFI and coreboot weak checks. The EFS therefore never takes an
Intel flash descriptor image (claimed by its signature), an FMAP image (AMD
coreboot builds carry one, found at 0 or by search, that maps the EFS area
as well) or a UEFI firmware volume or flash device image: those describe the
whole flash, the EFS only its PSP part. `efs_detection_yields_to_descriptors_maps_and_volumes`
pins this: with an FMAP at 0x1000, both the coreboot search and the EFS
validate, and the image is not reported as `amdpsp`.

## Wire units and byte order

All structures are little-endian; offsets and sizes are bytes.

- Intel microcode: 48-byte header; data size 0 means 2000 B of data in a
  2048 B update. The extended signature table follows the data: count,
  checksum, 12 reserved bytes, then 12-byte entries.
- AMD microcode: a 12-byte container header (magic, type 0, table length),
  16-byte equivalence entries up to an all-zero entry, then sections of
  type 1 with an 8-byte header and a patch whose 64-byte header holds the
  data code (0x00), patch ID (0x04) and processor revision ID (0x18).
- `$FPT`: 32-byte header from the marker, 32-byte entries right after it;
  entry offsets count from the start of the region (the file), not from the
  marker (`cse_fpt.c` `write_partition_to_file`).
- `$CPD`: 16-byte (version 1) or 20-byte (version 2) header, 24-byte entries
  whose offset field holds the offset from the directory in bits 24:0 and a
  Huffman flag in bit 25.
- Manifests: the `$MN2` tag at 0x1C and the version (major, minor, hotfix,
  build as u16) at 0x24.
- EFS: 0x50 bytes; directory pointers carry no address mode. Directory
  headers are 16 bytes (combo: 32), PSP and combo entries 16 bytes, BIOS
  entries 24 bytes; entry addresses are 62 bits with the address mode in
  bits 63:62. The directory's own mode (bits 30:29 of `additional_info`, or
  25:24 when bit 31 selects the version 1 layout) applies to every entry
  when it is below 2 (`amdfwread.c`).
- Address modes: 1 is relative to the image, 2 to the directory, 0 is a
  physical address in the 16 MiB below 4 GiB, and 3 (relative to a slot) is
  not supported by `amdfwread` and is noted, not followed.

## Checksums

| Structure | Algorithm | On mismatch |
| --- | --- | --- |
| Intel update header and data | DWORD sum 0 (SDM Table 12-7) | Not recognized (weak) |
| Intel extended signature table | DWORD sum 0; each entry: primary signature, flags and checksum minus the entry's sum to 0 | Not recognized |
| AMD container | None defined; the patch header's checksum field is not checked by Linux and its algorithm is not documented in the sources | Reported as not verified |
| `$FPT` 0x10, 0x20 | 8-bit sum 0 over the header length: from the marker for 0x20, from the ROM bypass vector for 0x30 (`me_cleaner`, `MEA.py`) | Parse error, unless a 0x20 header matches the 2.1 CRC (below) |
| `$FPT` 0x21 | IEEE CRC-32 of the header with the field zeroed, then every entry (`MEA.py`) | Note: coreboot and `UEFITool` do not check it, and `MEAnalyzer` ignores mismatches in extracted CSME 12+ images, which carry placeholders |
| `$CPD` 1 | 8-bit sum 0 over header and entries (`ifwitool` `calc_checksum`) | Note: `ifwitool` only warns, and `MEAnalyzer` lists Intel images with known-bad values |
| `$CPD` 2 | IEEE CRC-32 of header and entries with the field zeroed (`MEA.py`) | Note |
| PSP, BIOS and combo directories | amdfwtool `fletcher32` over everything after the checksum field | Parse error (strong) or not recognized (weak) |
| ISH directory | `fletcher32` over the 28 bytes after the checksum (`integrate_psp_ab`) | Note: only coreboot's writer documents it |
| `$MN2` RSA signatures | Not checked | Reported as present, not verified |

A version 0x20 `$FPT` header whose 8-bit sum fails but whose 2.1 CRC-32
matches is accepted with a note, the way `MEAnalyzer` handles the 2.1 layout
with a 2.0 version byte.

## Intel flash descriptor integration

The flash descriptor parser (`src/formats/uefi/ifd.rs`) used to list the ME
region as one opaque child. It now checks the region with
`pcfw::is_me_partition_table`: when `detect_format` reports the region's
bytes as an `$FPT` table (the marker at 0x10 or 0), the region becomes a
classified child, so it is reported as an `intelme` container whose
partitions are each opaque. No ME byte reaches the code model either way: a
corrupt table is an `intelme` parse error noted on the region, and a region
without `$FPT` stays opaque with the previous note. The nested container's
notes stay with its own classification; the descriptor reports the region
as `ME region: unknown(0x0000) (contained Intel ME firmware)`.

## Validation and resource bounds

- Every read is bounds-checked; counts are checked against the bytes
  available before tables are read (`$FPT`: at most 255 entries,
  `UEFITool`'s bound; `$CPD` and PSP directories: entries must fit the
  file).
- Intel updates are at least 1 KiB each, so the walk over a file advances;
  AMD containers end at the next magic, at erased flash or at the end of
  the file. Trailing bytes may only be erased flash (`0x00`/`0xFF`), noted
  with their size.
- The PSP walk reads every directory once (a directory referenced again is
  noted), at most 64 directories and at most 6 levels below the EFS (own
  bounds; current images use four: combo, L1, L2, BIOS L2).
- Components are capped at `MAX_COMPONENTS` (4096) and detail notes at 64
  per container; what is left out is counted in a note. Lists in notes are
  cut at 32 names with a count of the rest.
- Partitions that overlap the `$FPT` table or lie outside the file, and
  directory entries outside the file, are noted, not listed (`UEFITool`
  skips them too). Entries with a zero or erased size, the soft fuse value
  (type 0x0B) and the BIOS entries with only a DRAM destination (APOB 0x61,
  PSP shared memory 0x6B) are noted without a component.
- Physical addresses must lie in 0xFF000000-0xFFFFFFFF. In a file smaller
  than 16 MiB, an address at or above `2^32 - file size` is taken relative
  to the top of the file (`amdfwtool` `RUN_BASE`); otherwise the low 24 bits
  are the offset (`amdfwread` `relative_offset`). Image-relative addresses
  must be below 16 MiB.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| P1 | Intel update total sizes are multiples of 1024 B (SDM Table 12-7), although Linux does not check it | A released update whose total size is not a multiple of 1 KiB would not be recognized |
| P2 | Header version 1 and loader revision 1 are the only values in released microcode files | An update with loader revision 2; Linux rejects it too |
| P3 | Every AMD container starts with an equivalence table section (type 0), although Linux skips the type check on Zen | A `linux-firmware` `amd-ucode` file whose second word is not 0 |
| P4 | `$FPT` entry offsets count from the region start, not from the marker | `cse_fpt.c` dump of a region with the marker at 0x10; `me_region_v20` places FTPR at 0x1000 of the region |
| P5 | A header length of 0x30 means the 8-bit checksum covers the ROM bypass vector, and 0x20 that it covers the header alone (`MEA.py` keys on the length, `me_cleaner` on the ME version) | An ME 6-10 image whose header length is 0x20 with the vector in the sum would fail with a checksum error |
| P6 | The 2.1 CRC-32 covers the header with its field zeroed and every entry (`MEA.py` only) | A CSME 12+ region table whose CRC matches only another coverage; it would be noted as not verified, not rejected |
| P7 | A `.man` entry of a `$CPD` is the partition manifest (`me_cleaner` looks up `FTPR.man`) | A partition with several `.man` entries; only the first is described |
| P8 | EFS pointer fields without an address mode are physical when at or above 0xFF000000 and image-relative below | An image whose EFS uses physical pointers for a ROM larger than 16 MiB |
| P9 | A recovery A/B entry (0x48, 0x4A) points to an ISH directory unless its target starts with `$PL2` (`integrate_psp_ab` writes either) | An image whose recovery entry points to another structure; its ISH checksum would be noted as mismatched and the `pl2_location` link would fail |
| P10 | The type names of `amdfwtool.h` identify entries; nothing in a directory names an ISA | Entries are labeled with the coreboot identifiers only, and all are opaque |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| IFWI 1.6/1.7 (BPDT) ME regions (Apollo Lake and later Atom platforms) | Not recognized: they start with a BPDT, not `$FPT`; a descriptor's ME region stays opaque |
| Pre-ME 11 module lists (`$MME` headers after the manifest) | Not parsed: `me_cleaner` locates them by a size heuristic; the manifest version is reported |
| `$FPT` backup tables (2.1 redundancy flag) | Noted, not read |
| Huffman and LZMA module compression, `LLUT` tables | Not decoded; modules are opaque anyway |
| `$MN2` RSA signatures, AMD PSP signatures, Intel microcode authentication | Not verified |
| AMD per-family patch size limits (`__verify_patch_size`) | Not applied: they depend on the running CPU |
| EFS blob pointers (IMC, GbE, xHCI, Promontory) | Noted; no size is recorded, so they are not listed |
| AMD address mode 3 (relative to a slot) | Noted, not followed, as in `amdfwread` |
| Duplicate PSP L2 links | Walked once each; `amdfwread` rejects them, this parser does not |
| ME firmware inside FMAP areas (`SI_ME`) | Unchanged: the coreboot family keeps such areas opaque |

## Verification

On 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly f248f4038, Node
v25.8.1 with Playwright Chromium), `cargo test --all-features --locked`
passed with 1179 tests and 6 ignored, including `tests/pcfw.rs` (26 tests)
and 17 unit tests in `src/formats/pcfw*`. The browser suite
(`node --test tests/*.test.mjs` after `./build-web.sh`) passed 140 of 144
tests with 4 skipped (they need D10/RX113 firmware that is not in the
repository); `web/tests/pcfw.test.mjs` (6 tests) passed through
`/pkg/zrax.js`, `/dist/zrax.js` and both workbench pages.

The sweeps cover every prefix and every single-byte mutation (`0x00`,
`0xFF`, bit flips) of the microcode, ME and directory fixtures; for the two
AMD flash images (mostly erased flash) every byte of the EFS and
directories, every 64th byte from the EFS on and every 4 KiB before it.
All fixtures are synthetic, built in the tests from the documented layouts
with patterned payload bytes; no microcode, ME or PSP image is
redistributed, and no real firmware was tested, so behavior on vendor
images is not verified.
