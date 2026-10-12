# Chromium FMAP and coreboot CBFS

`src/formats/coreboot.rs` and its submodules `fmap.rs` and `cbfs.rs` parse
Chromium flash maps and coreboot file systems into the shared container
model ([compressed streams and the container model](compressed-streams.md)).
A flash map lists the areas of a whole flash image; a CBFS is a chain of
files inside one area or ROM. Neither format names the host CPU except the
CBFS master header's `architecture` field, so the ISA normally comes from
the contained images, each classified on its own.

## Implemented layouts

| JSON format ID | Layout (variant) | Recognition | Architecture evidence | Primary source |
| --- | --- | --- | --- | --- |
| `fmap` | `FMAP flash image`: `__FMAP__` header at offset 0, then the area table | Strong: 8-byte signature at offset 0 | None; areas are classified on their own | flashmap `lib/fmap.h` at `d56ae073fa2f`; coreboot 25.09 (`07df08836eca`) `src/commonlib/bsd/include/commonlib/bsd/fmap_serialized.h`, `util/cbfstool/fmap_from_fmd.c`; flashrom v1.8.0 (`90b6b4376c74`) `fmap.c` `is_valid_fmap` |
| `fmap` | `FMAP flash image (map found by search)`: the same map past offset 0, as in EC images and IFD-based x86 images | Weak: the whole map, every area and the trailing bytes validate; only for inputs no other format claims, except that it takes precedence over an Intel flash descriptor (`intelifd`), whose BIOS region holds CBFS rather than firmware volumes | As above | As above; flashmap `fmap_find` (linear search) |
| `cbfs` | `CBFS region`: `LARCHIVE` file header at offset 0 (an FMAP `COREBOOT` or `FW_MAIN_*` area, or a CBFS extracted from one) | Strong: 8-byte magic at offset 0 | Master header file (`CBFSHEADER`), when present | coreboot 25.09 `cbfs_serialized.h`, `src/commonlib/bsd/cbfs_private.c` (`cbfs_walk`, `cbfs_find_attr`) |
| `cbfs` | `CBFS ROM (master header pointer)`: a legacy ROM whose last four bytes point at the `ORBC` master header | Weak: valid pointer, master header, first file header and a clean walk of the region it names | Master header | coreboot 25.09 `util/cbfstool/cbfs_image.c` (`cbfs_find_header`, `fill_header_offset`) |

An FMAP `COREBOOT` area that holds a CBFS is not a separate layout: the area
is classified on its own bytes, which start with `LARCHIVE`, so the CBFS is
parsed as a nested container.

### Flash-map areas

Every area, up to the first 4096, is listed in the metadata
(`fmap_area_<n>`: offset, size, flags and role). Children are reported in
offset order:

| Role | Rule | Child |
| --- | --- | --- |
| Parent | Contains a code area; is a data area that contains any area; or is a code area whose bytes outside its nested data areas are all erased. Of two areas with the same range, the later one in the table is inside the earlier, since fmaptool lists parents first | None |
| Data | A name word is one of `FMAP`, `GBB`, `VPD`, `FRID`, `FWID`, `VBLOCK`, `KEY`, `SIG`, `NVRAM`, `ELOG`, `SMMSTORE`, `CACHE`, `CONSOLE`, `RBVER`, `ROLLBACK`, `PSTATE`, `GSCVD`, `SHARED`, `PRESERVE`, `UNUSED`, or the name is `SI_DESC`, `SI_GBE`, `SI_PDR`, `SI_10GBE0`, `SI_10GBE1` | Opaque |
| ME or IE firmware | Named `SI_ME` or `SI_IE` (ifdtool region names): firmware for another processor in a layout this parser does not read | Opaque, with a note |
| Erased | Contains no area and every byte is `0x00` or `0xFF` | None; counted in a note |
| Classified | Any other area with bytes of its own. A code area that contains only data areas is still classified (EC images nest `RO_FRID` and `FMAP` inside `EC_RO`) | `Classify::Always`: a nested format if recognized, else the code model |
| Overlapping | Would be classified but starts inside an area already classified | None; counted in a note |

An area flagged `FMAP_AREA_COMPRESSED` whose first 4 KiB are not a
recognized format is opaque: the map does not name the codec.

### CBFS files

| Type | Treatment |
| --- | --- |
| `DELETED` (0), `NULL` (0xFFFFFFFF) | Free space; counted, not listed |
| `CBFSHEADER` (0x02) | Master header; reported in notes and metadata |
| `STAGE` (0x11) | `StgH` attribute (load address, entry offset, memory size) in notes; data decoded per the `BCZL` compression attribute; flat program to the code model (`Classify::Code`). Without `StgH` the file is opaque |
| `LEGACY_STAGE` (0x10) | 28-byte little-endian `struct cbfs_stage` (coreboot 4.13): compression, entry, load address, data size (must equal the bytes present), memory size; data decoded, then to the code model |
| `SELF` (0x20) | Big-endian 28-byte segments up to `ENTR`: `CODE` segments decoded and sent to the code model, `DATA` segments opaque, `BSS ` and `PARA` skipped; an unknown segment type, missing `ENTR`, out-of-range or overlapping stored ranges leave the payload opaque |
| `BOOTBLOCK`, `OPTIONROM`, `VSA`, `MRC` | `Classify::Always` |
| `RAW`, `FIT_PAYLOAD`, `FSP`, `EFI`, `MBI`, `MMA`, `AMDFW`, unknown types | Listed only when the (decoded) bytes are a recognized format |
| `BOOTSPLASH`, `MICROCODE`, `INTEL_FIT`, `STRUCT`, `CMOS_DEFAULT`, `CMOS_LAYOUT`, `SPD`, `MRC_CACHE` | Opaque |

Attributes: `BCZL` compression (16 B: algorithm, decoded size), `StgH`
stage header (24 B), `hsaH` hash (12 B plus the digest size of its vboot
algorithm), and `BCSP`, `BCLA`, `2IBB`, `GNDP` (read past). An unused tag
(`0x00000000` or `0xFFFFFFFF`) ends the list; other tags are counted in a
note. Compression 1 is LZMA-alone (`compressed::Codec::Lzma`), 2 is an LZ4
frame (`Codec::Lz4`); any other value leaves the file opaque.

Hash attributes with SHA-256, SHA-512, SHA-224 or SHA-384 are verified over
the stored (still compressed) file data, which is what coreboot's
`cbfs_file_hash_mismatch` hashes; a mismatch is a note, not a rejection.
SHA-1 and unknown algorithms are reported as not verified.

### Master-header architectures

| Value | Name | Container target |
| --- | --- | --- |
| 0xFFFFFFFF | unknown (version-1 headers, and current cbfstool `add-master-header`) | None; never mapped to x86 |
| 0x00000001 | x86 | None: the field does not say 32- or 64-bit |
| 0x00000010 | ARM | `arm`, 32-bit, code byte order from the code |
| 0x0000AA64 | AArch64 | `a_arch64`, 64-bit, little-endian instructions |
| 0x00000100 | MIPS | None: width and byte order not encoded |
| 0xC001D0DE | RISC-V | None: XLEN not encoded |
| 0x407570FF | PPC64 | `ppc64`, 64-bit, code byte order from the code |

Values outside the table are reported in a note and set no target.

## Wire units and byte order

All offsets and sizes are bytes. FMAP fields are little-endian. CBFS file
headers, attributes, the master header and SELF segments are big-endian;
the legacy stage header and the legacy master-header pointer (a signed
offset from the end of the ROM) are little-endian. FMAP area offsets are
taken as file offsets (fmaptool writes absolute flash offsets); the FMAP
`base` address is reported only. CBFS file positions are 64-byte aligned
relative to the region start. Slices report stored file coordinates;
decoded stages and segments carry a decoded range naming the codec.
Stage load and entry addresses are target addresses, reported in notes.

## Validation and resource bounds

- FMAP (flashrom `is_valid_fmap`): `ver_major` 1; the map name is a
  NUL-terminated run of printable non-space ASCII; the image size is at
  least the map size; the area count fits the bytes after the header
  (`nareas <= (len - offset - 56) / 42`); the image size does not exceed
  the file; every area lies inside the image (checked addition); the map
  itself lies inside the image; when areas named `FMAP` exist, one holds
  the header's file offset; bytes after the image are `0x00`/`0xFF`. Area
  names must also be NUL-terminated printable words.
- The embedded-map search validates at most 64 `__FMAP__` candidates.
- Only the first 4096 areas take part in role assignment (containment is
  quadratic); further areas are validated and counted in a note.
- CBFS walk (`cbfs_walk`): from each 64-byte position with `LARCHIVE`, the
  file is taken and the walk continues at the next boundary after its data;
  other positions are skipped, and non-erased skipped bytes are counted in a
  note. Every step advances at least 64 bytes. A header must fit; data
  offset at most 256 B (`CBFS_METADATA_MAX_SIZE`); data inside the region;
  attributes and name before the data offset; the name NUL-terminated.
  Attribute lengths are at least 8 B and inside the metadata; compression
  and stage-header attributes have their exact sizes. A broken header or
  attribute is a parse error; a broken stage header, segment table or
  compressed stream leaves only that file opaque, with a note.
- Master header (`cbfs_header_valid`): `ORBC`, version `1111` or `1112`,
  first entry below the ROM size; for the pointer layout also ROM size
  within the file, alignment 64 and a file header at the first entry.
- SELF segment count is bounded by `data_len / 28`.
- Decoding: each stream is limited to its declared size (decoded size
  attribute, stage memory size or segment memory size), at most 64 MiB;
  with a compression attribute the decoded size must match exactly.
- Per container, at most 4096 children and 256 MiB of decoded or scanned
  bytes (`MAX_COMPONENTS`, `MAX_EXTRACTED`); what is left out is counted in
  a note. Nesting is capped at six levels by the classifier.

## Assumption register

| ID | Assumption | Source | Falsification probe |
| --- | --- | --- | --- |
| C1 | FMAP area offsets are absolute flash offsets, so the file is the whole flash | fmaptool `absolute_watermark` (spec A8) | An FMAP with `base != 0` whose areas only make sense relative to `base`; the `FMAP`-area check rejects such a map |
| C2 | The data-area name words above mark data, not code | Common Chrome OS and EC layouts (our reading; only `FMAP` is confirmed by coreboot `cbfs_sections.h`) | A real image whose code area name contains one of the words, e.g. a `*_CACHE` area that holds code |
| C3 | Area names are NUL-terminated printable words | fmaptool's `.fmd` identifiers | A map whose area names fill all 32 bytes or contain spaces is rejected; check vendor maps |
| C4 | Stage programs and SELF `CODE` segments are flat images without a header | `cbfs-mkstage.c`, `cbfs-mkpayload.c` | A stage whose decoded data starts with a container header the classifier would otherwise recognize |
| C5 | The legacy master-header pointer is little-endian on every architecture | cbfstool `write_le32` (spec A7) | A big-endian-target CBFS ROM with a master header |
| C6 | Hash attributes cover the stored file data | coreboot `cbfs_load_and_decompress` | A real signed CBFS whose SHA-256 attributes match only the decoded data |
| C7 | `SI_ME`/`SI_IE` areas are Intel ME/IE firmware | ifdtool region names | An FMAP that names a host-code area `SI_ME` |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Intel flash descriptor | Not parsed here; an IFD-based image with a complete FMAP or a master-header CBFS ROM is reported as `fmap` or `cbfs` rather than `intelifd` ([UEFI](uefi.md) parses descriptors without one) |
| A region extracted from a larger flash (FMAP offsets outside the file) | Parse error at offset 0; not recognized by the search |
| Legacy ROMs with a broken end pointer | Not recognized; cbfstool's byte-by-byte header scan is not implemented |
| `FIT_PAYLOAD`, `FSP`, `EFI` and other typed files | Listed only when another family recognizes their bytes |
| Option ROM sub-header (`struct cbfs_optionrom`, defined in `cbfs_serialized.h`) | Not interpreted; `OPTIONROM` data is classified as stored, so a ROM image is recognized only when the data starts with it |
| FMAP-level and CBFS metadata hashes (`CBFS_VERIFICATION`) | Not verified |
| Decode budgets | Counted per container; nested containers each have their own budget, bounded by the nesting cap |

## Verification

On 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly `f248f4038`),
`tests/coreboot.rs` (17 tests), the 14 unit tests in `src/formats/coreboot*`
and `web/tests/coreboot.test.mjs` (4 tests, Chromium through Playwright,
`/pkg/` and `/dist/` builds) passed, with no skips. The fixtures are
synthetic: maps, CBFS regions and ROMs are built in the tests from the
documented layouts, with the committed AArch64 and RISC-V code samples
(`tests/fixtures/transforms/`) as stage and area contents and one LZMA
stream generated with XZ Utils (`tests/fixtures/coreboot/README.md`). The
tests cover every layout, master-header architectures, LZMA, LZ4 and
legacy stages, SELF segments, hash verification and mismatch, corrupted
fields, an every-prefix sweep and a 0x00/0xFF/bit-flip mutation sweep of
three small images. No coreboot or Chrome OS firmware image was available,
so behavior on real images is not verified.
