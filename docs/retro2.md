# Console and home-computer images

`src/formats/retro2.rs` and its submodules parse twelve console and
home-computer layouts into the shared container model
([compressed streams and the container model](compressed-streams.md)):
Sega Master System / Game Gear ROMs, Sega 32X ROMs, Sega Saturn `IP.BIN`,
Sega CD / Mega-CD system areas, MSX cartridge ROMs, Atari Lynx `.lnx`, Atari
7800 `.a78`, Commodore 64 `.crt`, Atari ST GEMDOS executables, ZX Spectrum
`.z80` and `.sna` snapshots, Bandai WonderSwan ROMs and Neo Geo Pocket ROMs.
None of these headers has a CPU field. Each platform has one documented main
CPU, so the platform counts as the explicit target, as for the formats in
`retro.rs` and `nintendo.rs`: the container reports that ISA with confidence
1 and a CPU variant, and the code model only cross-checks it (a disagreement
is a warning note). Data that the CPU never executes (C64 RAM chips) is
listed as opaque.

## Implemented layouts

| JSON format ID | Layout (format variant) | Recognition | Target and components | Primary sources |
| --- | --- | --- | --- | --- |
| `smsrom` | Master System, Game Gear, or Master System / Game Gear ROM (from the region code) with the 16-byte header at 0x7FF0, 0x3FF0 or 0x1FF0 | Strong: `TMR SEGA` at the first of those offsets that holds it | `z80`, 8-bit, little-endian, variant `Z80`; entry 0x0000; the ROM is one code section at ROM offset 0 | [SMS Power! "ROM Header"](https://www.smspower.org/Development/ROMHeader) (fetched 2026-10-13); Charles MacDonald, "SMS/GG hardware notes" (`smstech-20021112.txt`); WLA-DX `wlalink/compute.c` at `7ae11df1657dafab1f5fa662889d005709fec15e`; PicoDrive `pico/media.c` at `26ecb2b6358fefba24e3d68b9eb2efba7f10d5ee` |
| `sega32xrom` | Sega 32X ROM: a linear Mega Drive ROM with the 32X user header at 0x3C0-0x3EF and the initial program `ICD_MARS.PRG` at 0x3F0 | Strong: TMSS `SEGA` at 0x100 or ` SEGA` at 0x101, and `MARS Initial & Security Program` at 0x512; not a Mega-CD disc identifier at 0 | `m68k`, 32-bit, big-endian, variant `68000`; entry is the 68000 initial PC. The ROM outside the SH-2 program is 68000 code sections; the SH-2 program is a raw-code child: `sh`, 32-bit, big-endian, variant `SH-2 (SH7095)` | Sega "32X Hardware Manual" (1994) §5.1-5.2 and Terminology (archive.org `32X_Hardware_Manual_1994_Sega`, OCR text SHA-256 `d0d3502c5b20af09034e85ceac125fe2161d22e4f2e000718fbcd0475c15d731`); rom-properties `md_structs.h`, `MegaDrive.cpp` at `b53204ff7479df44097d0567155ab361aed95be4`; PicoDrive `pico/32x/32x.c` at `26ecb2b6358fefba24e3d68b9eb2efba7f10d5ee` |
| `saturnip` | Saturn `IP.BIN`: system ID (0x100), security code (0xD00), area codes and application initial program, up to the IP size at 0xE0 | Strong: `SEGA SEGASATURN ` at 0 | `sh`, 32-bit, big-endian, variant `SH-2`; sections: security code at 0x06002100 and area codes plus initial program at 0x06002E00; entry 0x06002E00 | Sega ST-040-R4-051795 "Disc Format Standards Specification Sheet" §4 (SHA-256 `066dccf08feb72713f78d371dcaf749cf9aa9ed9264c51629c0fc85d5770f1d2`); ST-103-R1-040194 "Saturn Overview Manual"; Hitachi SH7604 Hardware Manual ADE-602-085C Rev. 4.0 §2.2.2; Yabause `yabause/src/yabause.c` at `7e38821dbac265490f115e163c523a939acda759` |
| `segacdip` | Sega CD / Mega-CD system area: system ID (0x000-0x0FF), disc ID (0x100-0x1FF), boot programs | Strong: `SEGADISCSYSTEM` at 0 | `m68k`, 32-bit, big-endian, variant `68000`; children (raw code): initial program (variant `MC68000 (main CPU)`) and system program (variant `MC68000 (sub-CPU)`) at their system ID offsets and sizes | Sega "Mega-CD Disc Format Specifications" Ver 2.00 (1992-02-24) Fig. 3-2 and Appendices 2-3, "Mega-CD BIOS Manual" Ver 2.00 §4, "Mega-CD Outline" §2 (archive.org `mega-cd-dev-manuals`); rom-properties `md_structs.h` (`MCD_SystemID`) at `b53204ff` |
| `msxrom` | MSX cartridge ROM with its header at 0x4000 or 0x8000 | Weak: `AB`, six zero reserved bytes, at least one non-zero address, and every address fits exactly one header position | `z80`, 8-bit, little-endian, variant `Z80`; the file is one code section at the header address; entry is INIT when set | ASCII "MSX2 Technical Handbook" chapter 5 §7.3.1 (Konamiman/MSX2-Technical-Handbook `md/Chapter5b.md` at `43959e9065ce05e8a74306f5315365e94b92f2c1`) |
| `lynxrom` | Atari Lynx `.lnx`: 64-byte header, then bank 0 and bank 1 | Strong: `LYNX` and version 1 | `mcs6502`, 8-bit, little-endian, variant `65C02`; one section per bank (cartridge offsets); no entry, because the boot ROM decrypts and runs a loader from the cartridge | Mednafen `lynx/cart.h`, `cart.cpp`, `c65c02.h` (libretro/beetle-lynx-libretro at `fcdefcfb3c11d6d2e71be076a5d3df2e88ab73ed`); cc65 `libsrc/lynx/exehdr.s`, `libsrc/lynx/bootldr.s`, `doc/lynx.sgml` at `e47ac5060b28a8be899871c814644aa04d21c221`; rom-properties `lnx_structs.h` at `b53204ff` |
| `atari7800rom` | Atari 7800 `.a78`: 128-byte header, then the ROM | Strong: `ATARI7800` at 1 | `mcs6502`, 8-bit, little-endian, variant `6502`; the ROM is one code section, at 0x10000 minus its size when unbanked (entry: the reset vector at 0xFFFC), at ROM offset 0 when banked (no entry) | [7800 8-bit dev wiki "A78 Header Specification"](https://7800.8bitdev.org/index.php?title=A78_Header_Specification&oldid=1120) (oldid 1120); cc65 `libsrc/atari7800/exehdr.s`, `cfg/atari7800.cfg` at `e47ac506`; MAME `src/devices/bus/a7800/a78_slot.cpp`, `src/mame/atari/a7800.cpp` at `17842be91dad10fab10e3ff657dc1e89ebc0ba27`; NESdev Wiki "CPU memory map" (oldid 21671) for the 6502 vectors |
| `c64crt` | Commodore 64 `.crt`: 0x40-byte header, then CHIP packets | Strong: `C64 CARTRIDGE   ` at 0 | `mcs6502`, 8-bit, little-endian, variant `6510`; one child per CHIP packet: ROM, Flash and EEPROM chips are raw 6510 code (variant `6510`), RAM chips opaque | [VICE manual §17.14](https://vice-emu.sourceforge.io/vice_17.html) (fetched 2026-10-13, SHA-256 `6f5ab9532b3ae39314dcd2dea229d147da396591460defd6cd237872882cbea1`); MAME `src/lib/formats/cbm_crt.cpp`, `src/mame/commodore/c64.cpp` at `17842be9` |
| `ataristprg` | Atari ST GEMDOS executable: 0x1C-byte header, TEXT, DATA, symbols, relocation table | Strong only with consistency: `0x601A`, a non-empty TEXT, sizes that fit the file, and (unless `ph_absflag` is set) a relocation table whose fixups are even TEXT/DATA offsets and that ends with a 0 byte in the file | `m68k`, 32-bit, big-endian, variant `68000`; the TEXT segment is one code section at offset 0 (relative to the TEXT start); entry 0 | [TOS.HYP §5.5 "The program format"](https://freemint.github.io/tos.hyp/en/gemdos_programs.html) (tos.hyp dated 2026-10-05); EmuTOS `bdos/pghdr.h`, `bdos/kpgmld.c`, `bdos/proc.c` at `02c2db75fc875265c1449efea014450466cf20b7` |
| `zxsnapshot` | ZX Spectrum `.z80` version 1, 2 or 3, or `.sna` 48K or 128K | Weak: `.z80` blocks that decode to exactly 48 KiB (v1, ending with `00 ED ED 00` at the end of the file) or exactly the pages the hardware mode saves (v2, v3); `.sna` at an exact size (49179, 131103, 147487 B) with interrupt mode 0-2, border 0-7, and SP in RAM (48K) or a paged bank and TR-DOS byte that match the size (128K) | `z80`, 8-bit, little-endian, variant `Z80`; RAM sections at their Z80 addresses (128K banks that are paged out are listed at 0xC000); decoded `.z80` blocks carry the transform `Z80 RLE`; entry is the PC | World of Spectrum ["Z80 File Format"](https://worldofspectrum.org/faq/reference/z80format.htm) (rev. 1.12), ["formats.htm"](https://worldofspectrum.org/faq/reference/formats.htm) (rev. 1.13, SNA), ["128kreference.htm"](https://worldofspectrum.org/faq/reference/128kreference.htm) (fetched 2026-10-13) |
| `wonderswanrom` | WonderSwan or WonderSwan Color ROM with the 10-byte footer at the end | Weak: a ROM size code of 2-9 equal to the file size, a zero byte before the footer, and a matching checksum | `x86`, 16-bit, little-endian, variant `NEC V30MZ`; the ROM is one code section at ROM offset 0; entry 0xFFFF0 (FFFF:0000) | trap15, ["WSMan" rev.7](http://daifukkat.su/docs/wsman/) (2016-08-17): Cartridge Metadata, CPU Overview; "WStech doc v2.4" §6 and Mednafen `wswan` (libretro/beetle-wswan-libretro at `4b01295838ea89e3f1355bbe4cb5cf98aa6108cd`); rom-properties `ws_structs.h` at `b53204ff` |
| `ngprom` | Neo Geo Pocket or Neo Geo Pocket Color ROM with the 64-byte header | Strong: `COPYRIGHT BY SNK CORPORATION` or ` LICENSED BY SNK CORPORATION` at 0 | `tlcs900`, 16-bit, little-endian, variant `TLCS-900/H`; sections: the first 2 MiB at 0x200000, the rest at 0x800000; entry is the startup address | NeeGee, "Everything You Always Wanted To Know About NeoGeo Pocket Color" (2000-04-16, SHA-256 `f9d71f7b1503d25479282512618ca9cd5454cdc9532b9698bd55e084dbf24443`); NeoPop `ngp/rom.h`, `mem.h`, `mem.c` (libretro/beetle-ngp-libretro at `a50d5ac288a81f2104ddf43195a4efdd15c72227`); rom-properties `ngpc_structs.h` at `b53204ff` |

## Detection

| Layouts | Position in `detect_format` |
| --- | --- |
| Sega 32X | Right before the `retro::detect` block: a 32X ROM is a Mega Drive ROM, and the Mega Drive check would claim it first |
| Saturn, Sega CD, Lynx, 7800, C64 CRT, Neo Geo Pocket, Master System / Game Gear, GEMDOS (in this order) | One block right before the magic-bearing compressed streams, after the Mega Drive check (PicoDrive also tests the Mega Drive header before `TMR SEGA`) |
| `.z80`, `.sna`, MSX, WonderSwan (in this order) | One block with the other structure-only layouts, right before zlib and LZMA-alone |

Weak layouts report a format confidence of 0.85. GEMDOS programs have only a
two-byte magic, a 68000 `BRA.S` over the header, so they are recognized only
when the whole relocation table validates; a broken table leaves the file
unrecognized rather than a parse error.

## CPU evidence

- Master System and Game Gear: the Z80 (MacDonald, "Z80 memory map"; the
  cartridge slot starts at 0x0000, where the Z80 starts).
- 32X: the manual names the two CPUs "SH2 (SH7095)". That they run
  big-endian code is derived: the SH-2 boot ROM reads the big-endian user
  header long words directly, and the SH7604 manual describes big-endian
  memory (little-endian only for area CS2). The 68000 side is the Mega Drive
  CPU.
- Saturn: two SH-2 CPUs (ST-103 "SH-2 X 2"); no part number appears in the
  Sega documents fetched, so the variant is `SH-2`.
- Sega CD: the main CPU is the Mega Drive MC68000 and the sub-CPU an
  MC68000 at 12.5 MHz (Mega-CD Outline); the IP runs on the main CPU and the
  SP on the sub-CPU (BIOS Manual §4).
- MSX and ZX Spectrum: the Z80 (MSX2 Technical Handbook; World of Spectrum).
- Lynx: a 65C02 (Mednafen `c65c02.h`), 7800: a 6502 (MAME `M6502`), C64: a
  6510 (MAME `m6510_device`). All three are `mcs6502`.
- Atari ST: the 68000 family (TOS.HYP refers to the MC-680x0 family).
- WonderSwan: the NEC V30MZ, "binary compatible with the Intel 80186"
  (WSMan), so the target is 16-bit x86.
- Neo Geo Pocket: the Toshiba TLCS-900/H (NeeGee); the Z80-compatible sound
  CPU runs a program the main CPU loads at run time, which the header does
  not locate.

## Wire units and byte order

All offsets and sizes are bytes. Master System, MSX, Lynx (after the
magic), `.z80`, `.sna`, WonderSwan and Neo Geo Pocket fields are
little-endian; the Mega Drive and 32X headers, the Saturn system ID, the Sega
CD system ID, A78 sizes and cart types, CRT headers and CHIP packets, and
GEMDOS headers and relocation offsets are big-endian. Header byte order is
never reported as code byte order; the targets above fix it.

Section addresses: CPU addresses for the Saturn (0x06002000 + offset), MSX
(header address), unbanked 7800 ROMs (0x10000 - size), `.z80`/`.sna` RAM and
the Neo Geo Pocket windows; ROM offsets for the Master System, 32X,
WonderSwan and banked 7800 ROMs (the cartridge maps banks); cartridge bank
offsets for the Lynx; TEXT-relative offsets for GEMDOS programs. Sega CD and
C64 components are children with stored file ranges. Decoded `.z80` blocks
keep their stored file offsets and sizes, and the metadata reads `N B stored;
M B decoded (Z80 RLE)`.

## Validation and resource bounds

| Layout | Errors | Reported, not enforced |
| --- | --- | --- |
| Master System | ROM above 64 MiB (`MAX_PAYLOAD`) | Checksum: verified over the declared size for codes 0xA, 0xB, 0xC, 0xE, 0xF, 0x0 and 0x1; codes 0xD and 0x2 (buggy in some BIOSes), unknown codes and declared sizes larger than the file leave it not verified. A mismatch is a note for every region; only region 4 (SMS Export) is checked by a BIOS |
| 32X | Truncated user header; source, destination, size, start addresses or VBRs not multiples of 4; SH-2 program outside the ROM; destination + size above the 256 KiB SDRAM; 68000 initial PC odd or outside the ROM; ROM above 64 MiB | Mega Drive checksum (verified or mismatch); start addresses outside the copied program; masked top address bits |
| Saturn | System ID truncated; IP size outside 0x1000-0x8000 or not a multiple of 4; IP longer than the file | Stack and 1st read addresses not long-word aligned; data after the IP (the rest of a disc image) |
| Sega CD | System area (0x200 B) truncated; a program outside the file or above 64 MiB | Entry offsets outside the program; an SP offset that is not on a 2048-byte sector; data after the programs |
| MSX | ROM above 64 MiB; reached only after weak recognition, which needs every check | ROM larger than the visible window (mapper banking is not modeled) |
| Lynx | Bank 0 page size other than 0x100, 0x200, 0x400, 0x800; bank 1 other than 0 or those; no data; data longer than both banks | Data shorter than the banks |
| 7800 | Header truncated; ROM size 0 or above 64 MiB; ROM data truncated; trailing bytes other than 0x00/0xFF; an unbanked ROM above 64 KiB | Missing end text; a ROM too small to reach 0xFFFC |
| C64 CRT | Header truncated or header length beyond the file; a CHIP packet that is truncated, lacks `CHIP`, is shorter than 16 B plus its data, or exceeds the 64 KiB address space; no packets | Header length below 0x40 (packets are read from 0x40); packet length other than size + 16; more than 4096 packets (`MAX_COMPONENTS`) are counted, not listed |
| GEMDOS | Program above 64 MiB; trailing bytes after the relocation table (or after the symbols of an absolute program) other than 0x00/0xFF; the header and table checks of recognition | `ph_res1` not 0; symbol table size not a multiple of 14 |
| `.z80` | A run that overshoots its block; a block that ends early; v1 data not followed by the end marker at the end of the file; uncompressed v1 not exactly 48 KiB; v2/v3 additional header length other than 23 (v2) or 54/55 (v3); unsupported hardware mode; a page the machine does not save, a duplicate page, or missing pages; a compressed page that decodes before its stored length ends | — |
| `.sna` | Size other than 49179, 131103 or 147487 B; interrupt mode above 2; border above 7; 48K SP outside 0x4000-0xFFFE; 128K TR-DOS byte above 1 or a paged bank that contradicts the size | — |
| WonderSwan | Footer missing, size code not 2-9 or not the file size, non-zero byte before the footer, checksum mismatch | — |
| Neo Geo Pocket | Header truncated; ROM above 4 MiB; startup address outside the mapped cartridge | System code other than 0x00/0x10; non-zero reserved bytes |

The `.z80` decoder writes into a buffer of exactly 16 KiB or 48 KiB and
consumes at least one input byte per step, so each block is bounded by its
stored size; a snapshot has at most eight pages. The WonderSwan checksum is
computed only after the size code matches the file length (at most 16 MiB).
The GEMDOS relocation walk reads each table byte once. Every other section
and child borrows the input.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| H1 | A platform's fixed CPU counts as an explicit target | A header for another CPU in one of these containers |
| H2 | A 32X ROM carries `MARS Initial & Security Program` at 0x512 (rom-properties; the manual requires `ICD_MARS.PRG` unchanged at 0x3F0 but does not list its bytes) | A commercial 32X ROM that rom-properties reports as 32X but this parser classifies as `genesisrom` |
| H3 | The 32X SH-2 CPUs run big-endian code (derived from the big-endian user header and the SH7604 memory format) | Code model results on a real 32X SH-2 program |
| H4 | The 32X SH-2 program is the masked source range copied to SDRAM; the manual names the part SH7095, not the SH7604 the task named | A 32X document that names another part |
| H5 | The Saturn IP's code begins at 0x100 (security code) and 0xE00 (area codes, then the initial program), loaded at 0x06002000; Yabause starts at 0x06002E00 | ST-040 sample linker script `STart SYSID (06002000)`; a real IP.BIN |
| H6 | A Sega CD system disc's IP and SP are 68000 code at the System ID offsets; their load addresses are not established | The BIOS manual memory map (sub-CPU user header at 0x6000) |
| H7 | An MSX cartridge at 0x8000 holds at most 16 KiB, and one at 0x4000 shows its first 32 KiB | A 32 KiB ROM with its header at 0x8000 would not be recognized |
| H8 | MSX reserved header bytes are 0 ("should be filled with 00H"); recognition depends on it | Commercial MSX ROMs with non-zero reserved bytes would not be recognized |
| H9 | The Lynx cartridge banks hold code and data behind an encrypted loader; they are listed as code sections, not opaque | Code model warnings on real `.lnx` images |
| H10 | A 7800 cart without banking bits (or with v4 mapper 0) ends at 0xFFFF; its reset vector is at 0xFFFC | cc65 `atari7800.cfg`; a banked ROM misread as linear would get a wrong entry |
| H11 | CHIP packets start at the header length (VICE: counted from offset 0), and at 0x40 when the field is smaller | A CRT with a header length above 0x40 |
| H12 | Every GEMDOS fixup, including the first, is even, and the table ends inside the file (stricter than EmuTOS, which accepts an odd first offset and a table cut by the end of the file) | A working program rejected by `gemdos_magic_without_a_valid_table_is_not_a_program`-style checks |
| H13 | Uncompressed `.z80` version 1 files are identified by size alone, so they are not recognized | A 49182-byte v1 snapshot is unrecognized |
| H14 | `.z80` pages are exactly the set the hardware mode saves (48K: 4, 5, 8; 16K: 8; SamRam: 4-8; 128K-class: 3-10) | Snapshots that also save ROM pages are not recognized |
| H15 | The WonderSwan checksum is the byte sum of all but the last two bytes (WStech; WSMan says "ROM words") | A real ROM whose checksum only matches a word sum |
| H16 | The Neo Geo Pocket recognition codes are the 28-byte rom-properties strings; NeeGee prints them with extra leading spaces | A real ROM with `  LICENSED BY SNK CORPORATION` (two spaces) |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Master System ROMs without `TMR SEGA` (Japanese SMS, SG-1000), SMD-interleaved SMS dumps, Codemasters and SDSC headers | Not recognized or not parsed |
| Byte-swapped and SMD-interleaved 32X dumps, and 32X ROMs without the security text | Classified by `retro.rs` as `genesisrom` with its 32X SH-2 child |
| Saturn and Sega CD 2352-byte raw sector images (identifier at 0x10), `SEGADATADISC`, the Saturn 1st read file | Not recognized; the 1st read file is named in a note |
| Sega CD IP and SP load addresses, region security code | Not reported (not established by the documents fetched) |
| MSX SUB-ROM (`CD`) cartridges, mapper banking | Not recognized; banking not modeled |
| Lynx loader decryption | Not attempted |
| 7800 cartridge signature (0xFF7A-0xFFF9), bank switching | Not verified; banked ROMs get no entry |
| C128, CBM2, VIC-20 and Plus/4 CRT signatures; C64 cartridge entry (`CBM80`); hardware type names | Not recognized or not reported |
| GEMDOS symbol tables, DATA segment, programs with appended data | Symbols counted, not parsed; DATA not analyzed; appended data is a parse error |
| `.z80` Didaktik-Kompakt, Scorpion and Timex hardware modes, ROM pages; uncompressed version 1 | Not recognized |
| WonderSwan size codes 0 and 1 (uncertain in WSMan), WonderWitch (checksum 0), ROMs with wrong metadata (WSMan list) | Not recognized |
| Neo Geo Pocket debug flag in the startup address | Not interpreted |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`
2026-09-05), `cargo test --all-features --locked` passed: 1077 tests, 6
ignored, including `tests/retro2.rs` (44 tests) and 29 unit tests in
`src/formats/retro2`. The integration tests cover a positive case per layout
(and per `.z80` version and `.sna` model), the target, variant and entry per
platform, children with stored offsets (32X, Sega CD, C64) and decoded
`.z80` blocks, corrupted fields and checksums, prefix truncation sweeps that
require no prefix shorter than the first complete structure to be claimed,
and no-panic sweeps over byte mutations (0x00, 0xFF, bit flip) of every
fixture. `./build-web.sh` and `web/tests/retro2.test.mjs` (4 tests:
classification through `/pkg/zrax.js` and `/dist/zrax.js`, and the workbench
in `/web/` and `/dist/`) passed with Node.js 25.8.1; the whole browser suite
passed 126 of 130 tests with 4 skipped (they need D10 and RX113 firmware that
is not in the repository).

All fixtures are synthetic, built in the tests from the documented layouts;
no game, firmware or homebrew image is redistributed, and no generator tool
for these formats was used. Behavior on real ROMs, discs, snapshots and
programs (including commercial 32X security programs, real Saturn and Sega CD
boot sectors, and WonderSwan checksums) is not verified.
