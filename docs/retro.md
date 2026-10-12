# Console executables and ROM images

`src/formats/retro.rs` and its submodules parse seven console layouts into the
shared container model ([compressed streams and the container
model](compressed-streams.md)): Sega Mega Drive / Genesis cartridge ROMs,
PlayStation `PS-X EXE`, Dreamcast `IP.BIN`, Wii U RPX/RPL, Nintendo 3DS NCCH
and `3DSX`, and PSP `EBOOT.PBP`. Each platform has one documented main CPU.
As for the formats in `src/formats/console.rs`, a platform format names that
CPU, so the container states it as its target; the Wii U layout takes it from
the ELF `e_machine` field instead, and a plain-ELF PSP `DATA.PSP` is classified
from its own header. The 3DS `.code` compression (BLZ) is a codec in
`src/formats/compressed/blz.rs`.

## Implemented layouts

| JSON format ID | Layout | Architecture evidence | Primary source |
| --- | --- | --- | --- |
| `genesisrom` | 68000 vector table and the header at 0x100; `SEGA` at 0x100 or ` SEGA` at 0x101; linear, byte-swapped and SMD (512-byte copier header, 16 KiB interleaved blocks) dumps; checksum at 0x18E computed and compared; ROM and RAM ranges, titles, serial, devices and region in notes; the initial PC must be an even address inside the ROM; `SEGA 32X` adds the SH-2 program named by the security program user header at 0x3C0 as a child | Platform CPU: 68000, big-endian. `SEGA TERA286` (Teradrive, boots from the x86 side) names no target, so the code model decides. The 32X child is SuperH, big-endian (the header names no SH-2 model) | [Plutiedev ROM header reference](https://plutiedev.com/rom-header); [Sega Retro "ROM header" oldid 1155876](https://segaretro.org/index.php?title=ROM_header&oldid=1155876); rom-properties `md_structs.h` at `b53204ff`; Genesis Plus GX `core/loadrom.c` at `49c58476`; PicoDrive `pico/32x/32x.c` at `26ecb2b6` |
| `psxexe` | 2048-byte header (`pc0`, `gp0`, `t_addr`, `t_size`, memfill, stack); the text at 0x800 is one load section at `t_addr`; region marker at 0x4C in notes | Platform CPU: MIPS R3000A (MIPS I), little-endian; the header names none | psx-spx "CDROM File Playstation EXE and SYSTEM.CNF" (fetched 2026-10-12, SHA-256 `78796681…f3ab69`); PSn00bSDK `psxapi.h` and `tools/util/elf2x.c` at `5d9aa2d3` |
| `dreamcastip` | `SEGA SEGAKATANA ` at 0; meta information (maker ID, device info, area symbols, peripherals, product, version, release date, boot file, maker, title); device info CRC-16/CCITT-FALSE over product number and version checked; area protection texts; license screen code (0x300-0x36FF) and bootstraps 1 and 2 (0x3800-0x7FFF) are load sections at 0x8C008000 + offset; entry 0x8C008300 | Platform CPU: Hitachi SH-4, little-endian | Marcus Comstedt, "IP0000.BIN" (2000-10-16) and "IP.BIN and 1ST_READ.BIN" (2000-11-16); KallistiOS `utils/makeip/src/field.c` and `crc.c` at `568c3404` |
| `wiiurpx` | ELF32 big-endian with `EI_OSABI` 0xCA and `EI_ABIVERSION` 0xFE, `e_type` 0xFE01; section headers; `SHF_DEFLATED` (0x08000000) sections inflated (big-endian size, then zlib) and their size checked; executable `SHT_PROGBITS` sections are load sections at `sh_addr`; text CRCs from `SHT_RPL_CRCS` checked; `SHT_RPL_FILEINFO` version and RPX/RPL flag, `SHT_RPL_IMPORTS` library names and export counts in notes | `e_machine` through the ELF machine table (`elf::e_machine_to_isa`), big-endian; variant "PowerPC" (the sources do not name the Wii U CPU model) | wut-tools `src/common/elf.h`, `src/elf2rpl/main.cpp`, `src/readrpl` at `b22de1a3`; decaf-emu `cafe_loader_rpl.h` at `e6c528a2` |
| `n3dsncch` | `NCCH` at 0x100; header fields, flags (crypto method, platform, form and content type, media unit size, `NoCrypto`); plain, logo, ExeFS and RomFS regions in media units; ExHeader system control info (title, `CompressExefsCode`, code sets); ExeFS header with up to ten files as children, `.code` decoded with BLZ when compressed; ExeFS superblock and file SHA-256 checked; encrypted content listed as opaque regions | Form type 2 or 3 (executable, CXI): ARM11 MPCore, ARM and Thumb, little-endian; `.code` carries the same target. A CFA names no CPU | 3dbrew "NCCH" oldid 23516, "ExeFS" oldid 16109, "NCCH/Extended Header" oldid 23704; ctrtool `ctrtool/src/lzss.c` at `d52c2b0e` |
| `n3ds3dsx` | `3DSX` header (32 or 44 bytes), three relocation headers, code, read-only data and data segments, relocation tables, SMDH and RomFS; the code segment is a child, the others are opaque | ARM11 MPCore, little-endian (platform; the header names no CPU) | 3dbrew "3DSX Format" oldid 14592; devkitPro 3dstools `src/3dsx.h`, `src/3dsxtool.cpp` at `718d6f23`; Luma3DS `sysmodules/loader/source/3dsx.c` at `aef31308` |
| `psppbp` | `\0PBP`, version, eight subfile offsets; `PARAM.SFO` title, category and disc ID in notes; `DATA.PSP` as a plain ELF child, or an encrypted `~PSP` module (optionally in a `~SCE` wrapper) that is opaque unless a plain ELF follows its 0x150-byte header; images, sound and `DATA.PSAR` opaque | Platform CPU: little-endian MIPS32 Allegrex; a plain-ELF `DATA.PSP` is classified from its own `e_machine` | PSPSDK `tools/pack-pbp.c` at `e2b2b313`; PPSSPP `Core/ELF/PBPReader.cpp`, `PrxDecrypter.h`, `ParamSFO.cpp` at `b419238f` |

The BLZ codec (`compressed::Codec::Blz`, name `BLZ`) decodes from the end of
the stream: the footer holds the footer-and-padding length (bits 31-24) and the
compressed region length (bits 23-0), then the decoded size minus the stored
size; control bytes select literals or 2-byte back-references (length 3-18,
distance 3-4098). It has no magic, so its standalone format is `raw` and it is
decoded only where an ExHeader names it.

## Detection

Every layout is strong (an identification string at a fixed offset), so a
corrupt image is a parse error rather than a confident raw ISA.

| Layout | Position in `detect_format` |
| --- | --- |
| Wii U RPX/RPL | Right after `ti::detect_strong`, before the generic ELF check: the files have ordinary ELF magic but Cafe OS `e_ident` bytes and compressed sections the ELF parser cannot read |
| Dreamcast, PS-X EXE, NCCH, 3DSX, PBP, Mega Drive (in this order) | One block right before the magic-bearing compressed streams |

## Wire units and byte order

All offsets and sizes are bytes unless stated. The Mega Drive header and
vectors and the 32X header are big-endian; the SMD block order is undone before
any field is read, and the stored offsets of the ROM section and of the 32X
child stay in file coordinates (for SMD dumps the child covers the whole
blocks that hold it). PS-X EXE, NCCH, ExeFS, ExHeader, BLZ footers, 3DSX, PBP,
PSF and `~PSP` fields are little-endian; RPX headers and the inflated size
field are big-endian. NCCH regions are in media units of `0x200 << flags[6]`
bytes; ExeFS file offsets are relative to the end of the 0x200-byte ExeFS
header. Destination addresses are reported as the header states them:
PS-X EXE `t_addr`, Dreamcast 0x8C008000 plus the offset, RPX `sh_addr`, Mega
Drive ROM address 0. 3DSX segments have no recorded base.

## Validation and resource bounds

- Mega Drive: a header needs 0x200 bytes; dumps above 64 MiB are refused
  (the ROM is one load section); SMD dumps must be 512 bytes plus whole
  16 KiB blocks. A checksum mismatch, a ROM start other than 0 or a ROM end
  beyond the image is a note, not an error (the console checks none of them).
- PS-X EXE: `t_size` must be non-zero and the text must lie in the file;
  bytes after it may only be `0x00`/`0xFF`. A `t_size` that is not a multiple
  of 2048 and a `pc0` outside the text are notes.
- Dreamcast: IP.BIN needs 0x8000 bytes; later bytes (a track image) are noted
  and not analyzed. A CRC mismatch is a note (the boot ROM accepts `0000`).
- RPX: `e_shentsize` must be 0x28 and `e_shnum` non-zero; the section header
  table (at most 65,535 entries) is checked against the file before it is
  read. A deflated section's inflated size is checked against 64 MiB before
  decoding, decoding stops at the declared size, and the result must match
  it; inflated sections stop at 256 MiB in total and text at 64 MiB, with the
  skipped count in a note. A CRC mismatch is a note. At most 16 import names
  are listed.
- NCCH: the media unit may not exceed the file; the content size must be at
  least 0x200 bytes and fit the file, with only `0x00`/`0xFF` after it; every
  region must lie in the content (checked arithmetic); the ExHeader needs
  0x40 bytes of system control info; every used ExeFS entry must lie in the
  ExeFS. Hash mismatches are notes. A `.code` that does not decode is opaque
  with a note.
- BLZ: the footer must fit, its header length must be at least 8 and inside
  the compressed region, which must be inside the stream; the decoded size is
  checked against the 64 MiB limit before allocation; every back-reference
  must stay in the output and above the region start; the decoder must end
  exactly at the region start.
- 3DSX: header size 32 or 44; relocation header size at least 8 and
  `3 * 4 * (size / 4) <= 0x1000`; BSS no larger than the data segment; every
  segment, the relocation tables (entry counts times 4, checked), the SMDH and
  the RomFS offset must lie in the file; without a RomFS, trailing bytes may
  only be `0x00`/`0xFF`.
- PBP: offsets must not decrease from 0x28 and must stay in the file. A PSF
  entry count is checked against the table size before entries are read.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| R1 | A Mega Drive ROM's code is 68000 code unless the system type is `SEGA TERA286` | A Teradrive or Pico ROM whose code model result disagrees with the target (warning note) |
| R2 | `ESAG` at 0x100 identifies a byte-swapped dump; Genesis Plus GX matches the two full swapped system types only | A byte-swapped 32X dump; a non-ROM file with `ESAG` at 0x100 |
| R3 | An SMD dump is 512 bytes plus whole 16 KiB blocks whose first block deinterleaves to a TMSS magic (stricter than Genesis Plus GX) | An SMD dump with a non-standard copier header length |
| R4 | The 32X SH-2 program is the ROM range at the masked source address and size from 0x3D4/0x3DC, big-endian SH-2 (the 32X header is PARTIAL in the sources) | A commercial 32X ROM with a known SH-2 program location |
| R5 | IP.BIN code areas are 0x300-0x36FF and 0x3800-0x7FFF; the area protection slots and the table of contents are not code | Code model results on a real IP.BIN |
| R6 | Data after IP.BIN is the rest of a data track | A track image classified by an ISO 9660 parser placed earlier would take precedence |
| R7 | RPX `e_type` is 0xFE01 (elf2rpl and decaf-emu), not wut's `ET_CAFE_RPL` 0xFF01 | An RPX with `e_type` 0xFF01 is rejected as unsupported |
| R8 | RPX code is the executable `SHT_PROGBITS` sections; executable import stub sections are not code | Code model results on `.fimport_*` sections of a real RPX |
| R9 | An NCCH is executable when its form type is 2 or 3 | A CXI with another form type would get no target |
| R10 | The ARM11 MPCore implements ARMv6K (ARM's processor documentation, not the 3DS sources) | None in the 3DS sources; the variant label carries the claim |
| R11 | ExeFS file hashes cover the stored file bytes, and the superblock hash covers the hash region from the ExeFS start | A real unencrypted CXI whose hashes mismatch |
| R12 | A BLZ stream decodes to exactly the bytes above its region start, and no back-reference token straddles the region start (stricter than ctrtool) | `.code` from makerom or a retail dump that ctrtool decodes and this decoder rejects |
| R13 | A `3DSX` RomFS offset before the end of the relocation tables (3dsxtool writes 0) means there is no RomFS | A 3DSX with an SMDH but no RomFS |
| R14 | PSF index entries are key offset (2), format (2), length (4), maximum length (4), data offset (4), as in PPSSPP `ParamSFO.cpp` (not in the collected notes) | A real `PARAM.SFO` whose title is not read |
| R15 | The PSP CPU is named Allegrex (the core revision is not confirmed) | None in the sources fetched |
| R16 | A `~PSP` module with `\x7FELF` at 0x150 stores a plain ELF there (PPSSPP fallback) | A retail module whose ciphertext happens to start with ELF magic |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Early Mega Drive header layout (titles at 0x120/0x140, checksum at 0x16E), `.mdx` dumps, Mega-CD discs | Not recognized; Mega-CD `SEGADISCSYSTEM`/`SEGADATADISC` images are excluded from Mega Drive detection |
| Mega Drive Z80 sound program | Not located: the 68000 copies it at run time and the header does not mark it (noted) |
| `PS-X EXR` relocatable executables | Not recognized |
| `1ST_READ.BIN` | Has no signature; its MIL-CD scrambling is not undone. IP.BIN notes name it |
| RPX relocations, exports beyond their count, FILEINFO sizes | Not parsed |
| NCCH and `~PSP` decryption, NCCH RSA signature, ExHeader, logo and RomFS hashes | Not attempted or not verified; encrypted content is opaque |
| NCSD cartridge and eMMC images (`NCSD` at 0x100) | Not recognized; their NCCH partitions are reached only when extracted |
| RomFS, SMDH, banner, `DATA.PSAR` (including PlayStation classics) | Listed as opaque data, not parsed |
| 3DSX relocations | Counted, not applied |
| SH-4 and the code model | The embedded model has an `sh` class but no SH-4 class; the classifier treats SH-4 as part of the SuperH family, so IP.BIN code classified as `sh` confirms the SH-4 target |

## Verification

On 2026-10-12 (macOS AArch64, rustc 1.100.0-nightly), `tests/retro.rs` (28
tests: a positive case per layout and dump order, target behavior, children
with stored offsets and decoded ranges, corrupted fields, checksums and
hashes, every-prefix truncation sweeps and byte mutation sweeps), the module
unit tests (13 in `retro`, 4 for BLZ) and `web/tests/retro.test.mjs` (4
tests, `/pkg/` and `/dist/` modules and the source and packaged workbench)
passed. All fixtures are synthetic and built in the tests from the documented
layouts; no game images are redistributed. Behavior on real ROMs, retail or
homebrew executables, and the outputs of makerom, elf2rpl, 3dsxtool,
pack-pbp or makeip is not verified: none of those tools or files was
available.
