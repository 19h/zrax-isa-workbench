# Nintendo 3DS and Switch containers

`src/formats/nintendo2.rs` and its submodules (`ncsd.rs`, `cia.rs`,
`partition_fs.rs`, `pfs0.rs`, `xci.rs`) parse the containers that carry
3DS and Switch titles into the shared container model
([compressed streams and the container model](compressed-streams.md)): 3DS
NCSD images (cart images and NAND images), 3DS CTR importable archives
(CIA), Switch `PartitionFs` archives (`PFS0`: NSP packages and `ExeFS`
images) and Switch gamecard images (XCI). A container's children are its
partitions, contents or files. None of these formats names a CPU: the
container target is always unknown, and the ISA comes from the members,
which are classified by the parsers that already exist for them (the NCCH
parser in `retro::n3ds`, the NSO and NRO parsers in `console.rs`).

## Implemented layouts

| JSON format ID | Container variant | Layout | Recognition | Children | Primary source |
| --- | --- | --- | --- | --- | --- |
| `ncsd` | `3DS CCI` (layout label `3DS NCSD`) | NCSD header (0x200 B): signature, `NCSD` at 0x100, image size in media units, media ID, FS and crypt types (all 0 for a cart), 8 partition offset/size pairs in media units, partition flags at 0x188 (platform, media type, media unit exponent), partition IDs at 0x190 | Strong: `NCSD` at 0x100 and the whole header | One child per used partition, `Partition <n> (<role>)`; an NCCH is classified by the NCCH parser, anything else is opaque | 3dbrew "NCSD" oldid 22570; makerom `ncsd.c`, `ncsd.h`; ctrtool `cci.h`, `CciFsSnapshotGenerator.cpp` |
| `ncsd` | `3DS NAND image` (layout label `3DS NCSD`) | The same header with nonzero FS or crypt types; media unit 0x200 B | Strong: as above | One opaque child per used partition, `Partition <n> (<FS type>; <crypt type>)` | 3dbrew "NCSD" oldid 22570, "Flash Filesystem" oldid 23624; ctrtool `cci.h` |
| `cia` | `3DS CIA` | Header (0x2020 B): header size, type, format version, certificate chain, ticket, TMD and meta sizes, content size, content index bitmap; sections aligned to 64 B; version 1 TMD with content info and chunk records; contents at 16-byte-aligned positions | Weak: header size 0x2020, type 0, version 0, nonzero section sizes, the file ending at the last section (or its 64-byte boundary with zero padding), documented signature types for the certificate chain, ticket and TMD, TMD version 1 with matching info-record and chunk-record SHA-256, and the present contents filling the content section | `Certificate chain`, `Ticket`, `TMD`, `Meta` (opaque); `Content <index> (ID 0x<id>)`, classified on its own, or `…, encrypted` (opaque) when TMD content type bit 0 is set | 3dbrew "CIA" oldid 22475, "Title metadata" oldid 21319, "Template:Signature Types" oldid 5790, "Certificates" oldid 21325, "Ticket" oldid 21072; makerom `cia.c`, `tmd.c`; ctrtool `cia.h`, `CiaFsSnapshotGenerator.cpp`, `CiaProcess.cpp`, libbroadon-es `es_tmd.h`, `es_sign.h` |
| `pfs0` | `Switch PFS0` | `PFS0`, entry count, string table size, reserved; 0x18-byte entries (data offset after the string table, size, name offset); NUL-terminated names; file data | Strong: `PFS0` at 0 with an entry table and string table that fit in the file | One child per file, labeled by its name: classified on its own when it is a recognized format (NSO, NRO, ...), opaque otherwise (NCAs, tickets, certificates, `main.npdm`) | switchbrew "NCA" oldid 14983 (PFS0 section); hactool `pfs0.c`, `pfs0.h`; nstool `README.md` (NSP is a `PartitionFs`) |
| `xci` | `Switch XCI` | Card header (0x200 B): signature, `HEAD` at 0x100, ROM size code, flags, package ID, valid data end page, root `HFS0` offset, header size and SHA-256; root `HFS0` of partitions `update`, `normal`, `secure`, `logo`, each an `HFS0` with 0x40-byte entries that add a hashed region size and SHA-256 | Strong: `HEAD` at 0x100 and an `HFS0` header, with its tables, at the root offset the card header names | One child per partition file, `<partition>/<name>`, classified on its own when it is a recognized format, opaque otherwise; `secure` first, then `normal`, `logo`, `update` | switchbrew "XCI" oldid 13628; hactool `xci.c`, `xci.h`, `hfs0.c`, `hfs0.h`, `utils.c`; nstool `GameCardProcess.cpp` |

Sources, fetched on 2026-10-13. 3dbrew answers plain HTTP clients with a
block page, so the wiki pages were read at their pinned revisions through a
fetch tool, table by table, and are not hashed:

| Source | Pin | Used for |
| --- | --- | --- |
| 3dbrew "NCSD" | oldid 22570 (2024-06-02) | NCSD header, partition flags, CCI partition roles, NAND header differences |
| 3dbrew "Flash Filesystem" | oldid 23624 (2025-07-27) | NAND partitions, FS and crypt types, AES-CTR encryption with keyslots and NAND CID counters |
| 3dbrew "CIA" | oldid 22475 (2023-12-31) | CIA header, section order and 64-byte alignment, meta layout, content encryption |
| 3dbrew "Title metadata" | oldid 21319 (2020-07-28) | TMD header, content info and chunk records, content type flags, byte order |
| 3dbrew "Template:Signature Types" | oldid 5790 (2013-04-27) | Signature types, sizes and padding |
| 3dbrew "Certificates", "Ticket" | oldid 21325 (2020-08-06), oldid 21072 (2019-10-14) | Certificate and ticket layout (only the signature type is read) |
| switchbrew "XCI" | oldid 13628 (2025-07-24) | Card header, ROM size codes, flags, HFS0 layout, root partition names and roles, the key area before the card header |
| switchbrew "NCA" | oldid 14983 (2026-09-10) | PFS0 layout; NCA header encryption (AES-XTS over 0xC00 B) and the `NCA3`/`NCA2`/`NCA1`/`NCA0` magic at 0x200 |
| Project_CTR (makerom, ctrtool) | commit `d52c2b0e788c2d085763d7c5dcc4b2edd9ffb7d8`; `makerom/src/cia.c` SHA-256 `5cfc510eab48fff3a9eb17fb487e8ac209724224b6ed00fb71a365d0a9aaa278`, `makerom/src/tmd.c` `bc41477a9c5e630eb68d028fd18f55831d695bfd3cf8d9738d9c400766272c67`, `makerom/src/ncsd.c` `dc7f32b10eee2450884dae855fa2b2f5273323145f8da2b891704624abea756d`, `ctrtool/deps/libnintendo-n3ds/include/ntd/n3ds/cia.h` `9edbc9a36b6b0482f565731936c8c50f5e31e52682fe97b574d7d469bdd7aa60`, `.../src/CiaFsSnapshotGenerator.cpp` `daf58e889de6245f8421a70a6ff4b1b8931fb9d8140da927ae40fe713159658e`, `ctrtool/src/CiaProcess.cpp` `ed3cebd925d7b58c101c694a5119e231aa23a798afbef99cde12a54c8930db20`, `.../include/ntd/n3ds/cci.h` `612f2570fd56eacadcd550191c277763a34f8757a8b0ad0fcaaf8f3dd97770e8`, `.../src/CciFsSnapshotGenerator.cpp` `0024567303ba8fff0e78ebb684cd9b00a2407ea444169e9e29f9412d6e6dbbcf`, `ctrtool/deps/libbroadon-es/include/brd/es/es_tmd.h` `7b493942c985261dae383fc0fe27cece97af2b5f8703a4059a21e4ab18505902`, `es_sign.h` `3ea713ec0858a0d30e13330c1485f1d30c6ba0ac985e62146a5aa3374126e4c2` | CIA header checks (`IsCia`), section and content alignment, bitmap bit order, content encryption IV, TMD writer and v1 layout, CCI checks, media unit, signature block sizes |
| hactool | commit `1d64a83450e025622f3468c28fc4164dad2c5ef6`; `xci.c` SHA-256 `6b0357bb158e8b2c6f3319ca6754e7616f22a2bfb223a97178f635eea62e5f61`, `hfs0.c` `7ed5c8f30004a9db4b20f705bd84656da470a1bb3e1b0af9340f2e8105ad6a92`, `pfs0.c` `0852a738db017dbeedff7ad3e1bd956cbb6930bdf2f5265eb463b7e099f57343`, `utils.c` `1f51d2b6cc8e66af6a9e7dafb737a089e0981f2fd3379d710d2f39c82fbae79f` | Card header struct, root partition rules, HFS0 entry order check, data offsets after the string table, the salted root hash, `main.npdm` `META` check |
| nstool | commit `cfb826ca6c165fbcd816fd7949df88ef3d72a948`; `README.md` SHA-256 `5214f6e80316dfaf89e93e95a5e241dd9858d3c6fab87f50d4cc069c8f979da5`, `src/GameCardProcess.cpp` `2d9d6af70aa757260cace68d31fb1cf1d593147edd90a7a4039676e6948a3d64` | NSP as a `PartitionFs`, card header at 0 or after the key area, valid data end, compatibility type salt |

## Children and classification

- **Cart partitions.** Each used partition is offered to the classifier
  on its own bytes. 3dbrew defines them as NCCH containers; the NCCH parser
  recognizes `NCCH` at 0x100 and decides the rest: an executable (CXI)
  names the ARM11, an encrypted one keeps its regions opaque, a CFA names
  no CPU. Partition 0 (the executable content) comes first, so it supplies
  the primary ISA. A partition that is not a recognized format is opaque.
- **NAND partitions.** Opaque: 3dbrew "Flash Filesystem" says the NAND file
  system is AES-CTR encrypted, with keyslots chosen by FS and crypt type
  and counters derived from the console's NAND CID.
- **CIA contents.** A content whose TMD type has bit 0 set is AES-128-CBC
  encrypted with the ticket's title key (3dbrew "CIA"; makerom
  `CryptContent`) and is opaque. Any other content is classified on its own
  bytes when it is a recognized format (an NCCH, a DS ROM) and is opaque
  otherwise. The certificate chain, ticket, TMD and meta section are data.
  The SHA-256 of every unencrypted content is checked against its chunk
  record and reported; the hash of an encrypted content covers its
  decrypted bytes and is not checked.
- **PFS0 and XCI files.** Each file is probed with its first 4 KiB and then
  checked in full; a recognized format is classified on its own (NSO and NRO
  through `console.rs`, which reports AArch64), anything else is opaque. NCAs
  are AES-XTS encrypted and never decrypted; a note counts opaque files
  named `.nca` and says why, and another counts files that carry a plaintext
  NCA magic at 0x200 (a decrypted header, whose sections are still not
  parsed). File names only select these notes; they never decide how a file
  is classified. A `main.npdm` with the `META` magic is noted as the mark of
  an `ExeFS`, as hactool takes it.
- **XCI partitions.** The partitions are listed in notes and metadata
  (`xci_partition_<name>`), and their files are the children, labeled
  `<partition>/<file>`. The game's `secure` partition comes first and the
  system `update` partition last, so update NCAs never decide the ISA.
- **Hashes.** The XCI root `HFS0` header SHA-256 is checked without a salt
  and with the China compatibility salt 0x01 (the compatibility type is in
  the encrypted card header data, which is not decrypted, so hactool tries
  both). Each root entry's hash of its partition header and each partition
  file's hashed region are checked and reported. TMD info-record and
  chunk-record hashes are checked during recognition. No RSA or ECDSA
  signature is verified, and the notes say so.
- Metadata: `<prefix>_image_size` and one `<prefix>_component_<n>` entry
  per child (from the container model), plus `ncsd_media_id`,
  `ncsd_image_size`, `ncsd_media_unit`, `ncsd_partitions`,
  `ncsd_partition_<n>_id` (carts); `cia_title_id`, `cia_title_version`,
  `cia_contents`; `pfs0_files`; `xci_rom_size`, `xci_package_id`,
  `xci_rom_area_start`, `xci_valid_data_end`, `xci_partition_<name>`.

## Wire units and byte order

| Layout | Byte order | Units |
| --- | --- | --- |
| NCSD | Little-endian | Image size and partition offsets and sizes in media units: `0x200 << flags[6]` bytes for a cart, 0x200 bytes for NAND |
| CIA header | Little-endian | Bytes; sections at 64-byte boundaries, contents at 16-byte boundaries of the content section |
| TMD, ticket, certificates | Big-endian (the TMD save data sizes are little-endian and not read) | Bytes |
| PFS0, HFS0 | Little-endian | Bytes; data offsets count from the end of the string table |
| XCI card header | Little-endian | Pages of 0x200 bytes for the ROM area start and the valid data end; bytes for the root `HFS0` offset and size |

Header byte order is never reported as code byte order; the members' own
parsers report theirs.

## Validation and resource bounds

- NCSD: the whole 0x200-byte header must be present. A cart must name the
  CTR platform (flags\[4\] bit 0) and media type Card1 or Card2, as makerom
  `IsCci` and ctrtool require; the media unit exponent must keep the unit at
  most 4 GiB. Every used partition must lie inside the image size and the
  file, and no two may overlap. After a cart's last partition only erased
  flash or zeros may follow (a full dump padded to the cart size, or a
  trimmed one; a trimmed dump is noted), except from a CARD2 cart's
  writable address on (card info header at 0x200, in media units; 3dbrew:
  on-chip save data, 0xFFFFFFFF on CARD1), which is noted and not parsed.
  Bytes after a NAND image's last partition are noted and not parsed.
- CIA: the checks listed under recognition; section placement uses
  checked 64-bit arithmetic; the TMD content count (at most 65,535) is
  checked against the TMD bytes before the records are read; contents may
  not run past the content section.
- PFS0 and HFS0: the entry count is checked against the bytes left after
  the header and the string table size against the bytes after the entry
  table before any entry is read; every name must be NUL-terminated inside
  the string table within 4096 bytes (a resource bound; the sources set no
  limit), so each entry scans a bounded part of the table; every file must lie inside the archive (for XCI
  partitions, inside the partition's root entry); in an `HFS0` an entry may
  not start before the previous entry ends (hactool rejects entries that
  start before the sum of the previous sizes). At most 4096 entries per
  table are kept; the rest are validated and counted in a note. After a
  PFS0's last file only zeros or 0xFF may follow.
- XCI: the file must hold the valid data (`(page + 1) * 0x200` bytes), and
  only erased flash or zeros may follow it; the root offset must lie after
  the card header and inside the valid data; the root may hold at most four
  partitions, each named once from `update`, `normal`, `secure`, `logo`.
- Members: at most 4096 children per container (`MAX_COMPONENTS`), the
  rest counted in a note; members are borrowed slices of the input, so
  nothing is extracted or copied; each is probed with 4 KiB before it is
  checked in full, and members are checked in full (and so classified) only
  while the bytes checked in full stay within the container size. Members
  that do not overlap always fit; PFS0 entries may overlap, and those past
  the budget are listed as opaque and counted in a note. Mismatch notes name
  at most 8 items and count the rest. Nesting is bounded by the six
  container levels of `lib.rs`.
- Strong detection means a damaged NCSD, PFS0 or XCI is a parse error, not
  raw code; a damaged CIA is not recognized.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| N1 | An NCSD whose FS and crypt types are all 0 is a cart image; one with any nonzero type is a NAND image (ctrtool rejects a cart with nonzero types; 3dbrew lists nonzero types for every NAND partition) | A real NAND dump with all types 0, or a cart with a nonzero type, would be misclassified; `nand_partitions_are_opaque` covers the documented NAND types (not verified on real dumps) |
| N2 | NCSD partitions never overlap each other (not stated by the sources) | A real image rejected with `they overlap` would falsify it (not verified on real dumps) |
| N3 | A cart's partitions are NCCH containers, so a partition that is no recognized format is data, not code | `cart_partitions_that_are_not_ncch_are_opaque`; a real cart partition the NCCH parser rejects would show as opaque |
| N4 | A CIA file ends at its last section or at that end aligned to 64 B with zeros (makerom writes nothing after the last section; ctrtool computes either end and only requires the file to be at least that long) | `cia_files_end_at_the_last_section_or_its_64_byte_boundary`; a real CIA with other trailing bytes would not be recognized (not verified on real CIAs) |
| N5 | The present CIA contents, at 16-byte-aligned positions, fill the content section exactly (makerom sums the 16-byte-aligned sizes) | `cia_recognition_requires_a_consistent_header_and_tmd`; a real CIA whose content section is larger would not be recognized (not verified on real CIAs) |
| N6 | 3DS CIAs carry version 1 TMDs whose info records hash all chunk records in order (3dbrew; makerom writes one record covering all; ctrtool requires version 1) | A real CIA with a version 0 TMD, or info records that skip chunk records, would not be recognized |
| N7 | The certificate chain, ticket and TMD each start with a documented signature type | A real CIA with another type (for example HMAC 0x10006, listed by libbroadon-es but not by 3dbrew) would not be recognized |
| N8 | An XCI file starts with the card header and its root `HFS0` offset is a file offset (hactool reads both from offset 0; switchbrew places the HFS0 at card offset 0x10000, 0xF000 after the card header) | `xci_partition_files_are_children_with_the_game_first` uses 0xF000; a dump that keeps the 0x1000-byte key area is not recognized (not verified on real dumps) |
| N9 | NCAs stored in NSPs and XCIs are encrypted, so they are opaque unless their bytes are a recognized format | `pfs0_files_are_children_labeled_by_name`; a plaintext NCA is still opaque and noted (`pfs0_exefs_and_plaintext_ncas_are_noted`) |
| N10 | No container here is ISA evidence: the 3DS application CPU is named only by the NCCH parser for executables, the Switch CPU only by the NSO and NRO parsers | Container results carry no target (`cart_partitions_are_classified_by_the_ncch_parser` checks `target` is `None`) |
| N11 | An NSP is a PFS0 (nstool and hactool read it as one; switchbrew has no NSP page) | A real NSP that does not start with `PFS0` would not be recognized (not verified on real NSPs) |
| N12 | A CARD2 cart dump may hold save data from the writable address on, so those bytes are kept unparsed rather than required to be padding (3dbrew documents the address, not what dumps contain there) | `card2_writable_regions_are_kept_but_not_parsed`; a real CARD2 dump with data between the last partition and the writable address would be a parse error (not verified on real dumps) |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Decryption (NCSD NAND partitions, CIA title keys, NCA AES-XTS, the XCI encrypted header data) | Not implemented: no keys are used, so encrypted members stay opaque |
| NCA parsing (FS headers, the `ExeFS` PFS0 and `RomFS` inside) | Not implemented; NCAs are opaque, so retail NSPs and XCIs report an unknown ISA |
| Simple CIAs (format version 0xFF, a content blob without a TMD) | Not recognized: the TMD is required for weak recognition |
| CIA meta section contents beyond the core version and dependency count; the SMDH icon | Not parsed |
| 3DS cart header fields past the NCSD header (card info, initial data, development card area) | Not parsed |
| XCI dumps that keep the 0x1000-byte key area before the card header | Not recognized |
| Standalone `HFS0` files | Not recognized as a format of their own; an `HFS0` is parsed only inside an XCI |
| Signatures (NCSD, XCI card header, certificates, tickets, TMDs) | Not verified |
| Compressed NSPs and XCIs (NSZ, XCZ) | Not recognized |
| Real dumps | Not tested: no redistributable dump exists, and none is committed |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`
2026-09-05, Node v25.8.1 with Playwright Chromium), `cargo test
--all-features --locked` passed: 1,890 tests, 6 ignored (the repository's
existing ignores), including the 26 tests of `tests/nintendo2.rs` and the
17 unit tests of `src/formats/nintendo2*`. After a last rename that does
not change behavior (the NCSD flags array length constant), those 43 tests
and `tests/registration.rs` were run again and passed. After
`./build-web.sh`, `web/tests/nintendo2.test.mjs` (4 tests) passed through
`/pkg/zrax.js`, `/dist/zrax.js`, `/web/index.html` and `/dist/index.html`;
the whole browser suite ran 216 tests, 212 passed and 4 skipped (the
existing skips that need D10 and RX113 firmware not in the repository).
The sweeps cover every 37th prefix of the cart and NAND fixtures, every
97th of the CIA, every 7th of the NSP and every 211th of the XCI, plus the
prefixes around each structure boundary, and 0x00, 0xFF and bit-flip
mutations of every header byte and of strided bytes of all five. All
fixtures are synthetic, built in the tests from the documented layouts with
hand-assembled ARM and AArch64 code, minimal NCCH and NSO headers and
pseudo-random bytes standing in for encrypted data; behavior on real cart,
NAND, CIA, NSP and XCI dumps is not verified.

After integration with the families added since on the same day, the
native suite passed 2,242 tests with 6 ignored, and IDA's corpus (4,621
files) classified as before.
