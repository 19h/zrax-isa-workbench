# UEFI and PC flash images

`src/formats/uefi.rs` and its submodules (`fv.rs`, `ffs.rs`, `section.rs`,
`te.rs`, `ifd.rs`) parse UEFI PI firmware volumes with their FFS files and
sections, standalone TE images and Intel flash descriptor images into the
shared container model ([compressed streams and the container
model](compressed-streams.md)). `src/formats/compressed/efi.rs` adds the
EFI 1.1 and Tiano decompressors to the codec layer.

Firmware volumes, FFS files and the flash descriptor name no ISA. The
explicit evidence is the `Machine` field of each PE32 and TE image, and every
image is a component classified from its own bytes, labeled with its FFS
file GUID and, when the file has one, its `USER_INTERFACE` name:
`PeiCore (52C05B14-0B98-496C-BC3B-04B50211D680): PE32 image`.

## Implemented layouts

| JSON format ID | Layout | Recognition | Architecture evidence | Primary source |
| --- | --- | --- | --- | --- |
| `uefifv` (PI firmware volume) | `EFI_FIRMWARE_VOLUME_HEADER` at offset 0: zero vector, file system GUID, `FvLength`, `_FVH` at 0x28, attributes, header length, 16-bit checksum, extended header offset, revision, block map; then FFS files, then any further volumes in the bytes that follow | Strong: `_FVH` at 0x28 | None at the volume level; PE32 and TE `Machine` fields | PI 1.8 Vol. 3, 3.2.1-3.2.5; EDK2 `edk2-stable202408` (`b158dad1`) `MdePkg/Include/Pi/PiFirmwareVolume.h`, `PiFirmwareFile.h` |
| `uefifv` (PI flash device image) | Leading data (a reset branch or boot code), then the first volume on a 4 KiB boundary within the first 1 MiB, then further volumes | Weak: the whole image must parse | As above | Same; layout observed in the Arm and AArch64 EDK2 images of QEMU 11.1.1 |
| `uefite` | `EFI_TE_IMAGE_HEADER` (40 B): `VZ`, machine, section count, subsystem, stripped size, entry point, base of code, image base, two data directories; the PE section headers kept after it | Strong when the machine is in the PE/COFF table, 1-96 sections are present and stripped size and base of code are consistent; otherwise weak, requiring every EDK2 loader check and the entry point in section data | `Machine`, through the PE machine table (`pe::machine_to_isa`) | PI 1.8 Vol. 1, chapter 15; EDK2 `PeImage.h`, `BasePeCoff.c`, `GenFw.c` |
| `intelifd` | `FLVALSIG` (`0x0FF0A55A`) at 0x10 (0x0 before the Ibex Peak B-step); `FLMAP0`/`FLMAP1` bases; up to 16 `FLREG` registers | Strong: the signature at 0x10 or 0x0 | None; BIOS-region volumes are children | coreboot 25.09 `util/ifdtool`, flashrom v1.8.0 `ich_descriptors.h`, UEFITool A75 `common/descriptor.h` (no Intel document was read) |

Codecs added to `compressed::Codec` (never recognized standalone, so their
`format` is `raw`):

| Codec | Name in slices | Wire format | Source |
| --- | --- | --- | --- |
| `Efi` | `EFI` | `CompSize`, `OrigSize` (u32 LE each), then the LZ77/Huffman bitstream with a 4-bit position set count (`mPBit` 4) | UEFI 2.10, chapter 19; EDK2 `MdePkg/Library/BaseUefiDecompressLib` |
| `Tiano` | `Tiano` | The same format with a 5-bit position set count (`mPBit` 5) | EDK2 `BaseUefiTianoCustomDecompressLib.c` |
| `LzmaX86` | `LZMA x86` | LZMA-alone, then the LZMA SDK x86 BCJ decoder over the output (start offset 0), as EDK2 LZMA F86 sections use it | EDK2 `F86GuidedSectionExtraction.c`, LZMA SDK `Bra86.c`; the filter is `lzma_rust2::filter::bcj` |

## Files and sections

| Item | Handling |
| --- | --- |
| File systems | `FFSv2` and `FFSv3` GUIDs, the six vendor GUIDs UEFITool walks as `FFSv2`, and the Framework `FFSv1` GUID are walked; the NVRAM variable store GUID and unknown GUIDs are listed but not walked |
| FFS headers | 24-byte header, or 32-byte `EFI_FFS_FILE_HEADER2` with `FFS_ATTRIB_LARGE_FILE` (only in `FFSv3` volumes); 8-byte file alignment from the volume start |
| File state | Most significant set bit after undoing the erase polarity (EDK2 `GetFileState`): data-valid and marked-for-update files are used, deleted files and incomplete headers skipped, any other state ends the walk as the PEI core does; erased bytes end it as the DXE core does |
| Checksums | Header checksum (8-bit sum with `State` and `Checksum.File` as zero) for used and deleted files; data checksum with `FFS_ATTRIB_CHECKSUM`, otherwise the fixed value 0xAA; a mismatch is a parse error. These are integrity checks, not authentication |
| Pad files (0xF0) | Checksummed and skipped |
| Sectioned files | Types 0x02 and 0x04-0x0F are section streams; SEC, OEM, debug and undefined types are walked as sections when they form a valid section stream, otherwise as raw data; RAW files are raw data |
| Section headers | 4-byte header, or 8-byte header when the 24-bit size is 0xFFFFFF; 4-byte alignment; zero or erased fill after the last section |
| PE32 (0x10), PIC (0x11) | Component classified by the PE parser |
| TE (0x12) | Component classified by the TE parser; the TE machine is also set as the component target, so it applies when the rest of the image does not validate |
| COMPATIBILITY16 (0x16) | Component classified as raw 16-bit x86 code: PI 1.8 Vol. 3 documents the content as "an IA-32 16-bit executable image" (a role, not a field) |
| FIRMWARE_VOLUME_IMAGE (0x17) | The nested volume is walked in the same container |
| RAW (0x19), FREEFORM_SUBTYPE_GUID (0x18) data, RAW files | A valid volume is walked in place; other data is listed only when it is a recognized format (`Classify::IfRecognized`) |
| USER_INTERFACE (0x15) | Names the file's images |
| COMPRESSION (0x01) | Type 0: the stored stream (`UncompressedLength` must fit). Type 1: EFI and Tiano decoders both run, as UEFITool does; the variant whose output is a section stream of exactly `UncompressedLength` bytes is used; if only Tiano succeeds, a note says the choice was inferred; two different valid outputs are reported as ambiguous and the section is opaque. Other types are opaque |
| GUID_DEFINED (0x02) | `DataOffset` must lie between the header and the section end. LZMA (`EE4E5898-...`), LZMA F86 (`D42AE6BD-...`), Tiano (`A31280AD-...`) and Brotli (`3D532050-...`, after the 16-byte decoded-size and scratch-size prefix) are decoded to the declared size; CRC32 (`FC1BCDB0-...`) is verified, then its stored stream is walked; signed sections (`0F9D89E8-...`) are walked with the signature not verified; other GUIDs are walked when `PROCESSING_REQUIRED` is clear and opaque otherwise |
| DEPEX, VERSION, DISPOSABLE, Insyde and Phoenix POST code sections | Not interpreted |

Decoded components keep the stored range of their outermost encapsulation
section as `offset`/`size`, and the slice's `decoded` range names the
codec. CRC32, uncompressed and unprocessed GUID-defined streams stay in file
coordinates.

## Flash descriptor regions

Regions are decoded with flashrom's 15-bit base and limit fields (4 KiB
units, inclusive limit). A register is unused when it is erased, when its
base is above its limit (flashrom), or when its limit field is 0 for any
region but the descriptor (UEFITool). The registers read are those between
`FRBA` and the next map structure (coreboot `max_regions_from_fdbar`), at
most 16; `FLMAP0` `NR` is reported but not used, because it is reserved
from the 100-series PCHs on. Regions must not overlap or start inside the
4 KiB descriptor, and a BIOS region must exist.

| Region | Handling |
| --- | --- |
| BIOS (1), secondary BIOS (6) | Scanned for volumes; each volume is a child classified on its own; other non-padding data is listed when recognized |
| ME (2) with a `$FPT` table at 0x10 or 0 | Classified as an `intelme` container whose partitions are each opaque ([PC firmware blobs](pcfw.md)) |
| ME (2) otherwise, IE (10) | Opaque, with a note: firmware of a separate engine whose layout is not established here |
| GbE (3), 10GbE (11, 12) | Opaque network controller configuration |
| Others (platform data, EC, device expansion, PTT, reserved) | Listed only when recognized |

A region beyond the end of the image is noted (a second flash chip or a
truncated dump); a BIOS region beyond it is an error.

## Wire units and byte order

All structures are packed and little-endian. Offsets and sizes are bytes:
FV and FFS offsets are relative to the volume, section offsets to the
section stream, IFD map bases are 16-byte units and region fields 4 KiB
units from the start of the image. TE offsets follow EDK2: TE file offset
`x` is original file offset `x + StrippedSize - 40`, and the section headers
are kept after the TE header. The TE container's sections carry the image
base plus the section RVA as their address. Header byte order says nothing
about code byte order; every listed image is classified from its own
header.

## Validation and resource bounds

- Volume header: revision 1 or 2; header length even and at least 0x48;
  `FvLength` between the header length and 4 GiB - 1 and within the input;
  16-bit header checksum; block-map terminator inside the header;
  extended header 4-byte aligned, inside the volume, entries at least 4 B.
- Volume scans examine at most 1024 `_FVH` candidates per region.
- Nesting of volumes and encapsulation sections inside one container is
  limited to 16 levels; deeper levels are noted and not walked.
- Decoded sections are capped at 64 MiB each and at 256 MiB per container
  (`MAX_EXTRACTED`); sections over the limit are counted in a note and not
  decoded. Declared sizes (LZMA, Tiano/EFI `OrigSize`, Brotli prefix) are
  checked against the limit before decoding, and the output must match them.
- At most 4096 components per container; detail notes are limited to 64.
- Raw data decoded from encapsulations is copied for listing only when the
  first 4 KiB are a recognized format.
- TE images: 1-96 sections; `StrippedSize > 40`; `BaseOfCode >
  StrippedSize`; headers and every section's raw data inside the image;
  sections must not overlap the headers.
- EFI/Tiano decoder: complete (not over- or under-subscribed) codes, length
  counts no larger than their alphabet, single-symbol codes inside it,
  back-references inside the output, a nonzero block size, and no bits read
  past `CompSize`. EDK2 is more lenient on each of these (it ignores a
  failed char-and-length table, wraps a zero block size to 65536 symbols,
  and reads zero bits past the end); the streams EDK2 `EfiRom` wrote for
  the option ROMs listed under Verification decode without reaching any of
  them.

## Assumption register

| ID | Assumption | Source | Falsification probe |
| --- | --- | --- | --- |
| U1 | The FFS header checksum covers the full 24- or 32-byte header with `State` and `Checksum.File` zeroed | EDK2 PEI and DXE cores | `UEFI_FIRMWARE_DIR` run over QEMU's EDK2 images: every header verified |
| U2 | Sections are 4-byte aligned relative to the file data | PI design 2.2.4; EDK2 `GET_OCCUPIED_SIZE` | Same run; a misaligned header would fail the walk |
| U3 | Compression type 1 can carry Tiano data in vendor images | UEFITool only | Find a type-1 section that decodes only with `mPBit` 5 (the note says "inferred") |
| U4 | TE section headers are kept after the TE header | EDK2 `GenFw` and `BasePeCoff.c`; contradicts the PI 1.8 wording | TE images from non-EDK2 toolchains |
| U5 | IFD region fields are 15 bits wide in every generation | flashrom; coreboot masks v1 to 12 bits | A v1 descriptor with bits 12-14 set |
| U6 | Framework (revision 1) files: bit 0 marks a 2-byte tail holding the inverted `IntegrityCheck`, the fixed data checksum is 0x5A, no large files | UEFITool only | Parse a Framework image; a file that breaks these rules ends that volume's walk with a note instead of an error |
| U7 | A flash device image places its first volume on a 4 KiB boundary within 1 MiB | QEMU 11.1.1 EDK2 Arm images (volume at 0x1000) | Flash images with the first volume elsewhere are not recognized (they fall back to raw analysis) |
| U8 | A zero block size never occurs in EFI/Tiano streams | EDK2 encoders emit the block's symbol count, at most a few thousand | A stream that EDK2 decodes but this decoder rejects with "block size 0" |
| U9 | The `LZMA F86` x86 filter is the xz/LZMA SDK BCJ x86 filter with start offset 0 | EDK2 `F86GuidedSectionExtraction.c` | `generate.py` checks its `x86_Convert` port against xz's encoder; the Rust decode equals the original stream |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| FMAP, coreboot CBFS | Not implemented here (the research notes cover them) |
| ME/CSME, AMD PSP, EC firmware layouts | Opaque or listed only when recognized; their processors are not inferred |
| Vendor GUID-defined sections (HP and MS LZMA, GZIP, AMD zlib) and compression types 0x02/0x86 | Opaque with a note (UEFITool-only layouts) |
| Lenovo 28-byte large-file headers in `FFSv2` volumes | A large file outside an `FFSv3` volume is a parse error |
| Gigabyte-style BIOS regions that overlap other regions | Parse error (overlap) |
| Apple `ZeroVector` CRC, signed volumes and signed sections | Not verified |
| IFD version, chipset and master permissions | Not decoded |
| Descriptor images that also hold a complete FMAP or a master-header CBFS ROM (coreboot on Intel) | Reported as `fmap` or `cbfs` ([coreboot](coreboot.md)), not `intelifd` |
| NVRAM variable stores | Listed, not interpreted |
| BIOS-region dumps whose first volume is not at offset 0 and not 4 KiB-aligned within 1 MiB | Not recognized |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly), `tests/uefi.rs`
(25 tests) and 19 unit tests in `src/formats/uefi*` and
`src/formats/compressed/efi.rs` passed; the full native suite passed with
544 tests and 6 ignored. The fixtures are synthetic (see
[`tests/fixtures/uefi/README.md`](../tests/fixtures/uefi/README.md)) and the
tests include every-prefix truncation sweeps for each layout and
0x00/0xFF/bit-flip mutation sweeps over every byte of the volume, TE and
flash fixtures. `web/tests/uefi.test.mjs` (4 tests) passed against `/pkg/`,
`/dist/` and both workbench pages.

Two tests read external data and skip without it:

- `UEFI_FIRMWARE_DIR=/opt/homebrew/share/qemu`: the twelve `edk2-*.fd`
  images of QEMU 11.1.1 (x86-64, i386 with and without Secure Boot,
  AArch64, Arm, RISC-V 64, LoongArch64 code images and their variable
  stores) classified as `uefifv`; in each code image every listed PE32 and
  TE image (82 to 141 per image, most inside LZMA-compressed nested
  volumes) had the build architecture as its ISA (x86-64, x86, AArch64,
  Arm, RISC-V 64 or LoongArch64), and the variable stores listed nothing.
  The Arm and AArch64 images are flash device images (volume at 0x1000).
- `EFI_ROM_DIR=/opt/homebrew/share/qemu`: the EFI images of the eight
  `efi-*.rom` iPXE option ROMs (EFI compression type 1, written by EDK2
  `EfiRom`) decoded with the EFI codec to x86-64 PE images of their declared
  size, consuming the bitstream up to its last data byte; the Tiano decoder
  rejected all of them.

Not verified: Tiano streams from an EDK2 encoder (`TianoCompress` was not
installed; the Tiano path is tested only with streams built in the tests),
Brotli sections from EDK2 `BrotliCompress`, Framework (revision 1) volumes,
`FFSv3` images with real large files, and flash descriptors from real
boards (all IFD tests use synthetic descriptors).
