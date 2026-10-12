# Nintendo console ROMs

`src/formats/nintendo.rs` and its submodules (`nds.rs`, `gba.rs`, `gb.rs`,
`nes.rs`, `snes.rs`, `n64.rs`) parse Nintendo DS, Game Boy Advance, Game
Boy / Game Boy Color, iNES / NES 2.0, SNES and Nintendo 64 ROM images into the
shared container model
([compressed streams and the container model](compressed-streams.md)). None
of these headers has a CPU field. Each platform fixes its CPU, so the
platform counts as the explicit target, as an XBE names x86: the container
reports the platform's ISA with confidence 1 and a CPU variant, and the code
model only cross-checks it. Data the CPU never executes (NES CHR-ROM, the DS
secure area while it may be encrypted, DSi modcrypt areas, PlayChoice-10
INST-ROM and PROM, NES 2.0 miscellaneous ROMs) is listed as opaque and never
reaches the code model.

## Implemented layouts

| JSON format ID | Layout (format variant) | Recognition | Target and components | Primary sources |
| --- | --- | --- | --- | --- |
| `ndsrom` | Nintendo DS cartridge: header 0x000-0x17F, ARM9 area at 0x020, ARM7 area at 0x030; DSi extended header to 0x1000 when unit code bit 1 is set | Strong: logo CRC-16 field 0xCF56 at 0x15C, plus the 156-byte logo at 0x0C0 or a matching header CRC-16 | `arm`, 32-bit, little-endian, variant `ARMv5TE (ARM946E-S)`. Children (raw code): ARM9 binary (`ARMv5TE (ARM946E-S)`), ARM7 binary (`ARMv4T (ARM7TDMI)`), DSi ARM9i and ARM7i binaries | GBATEK "DS Cartridge Header", "DSi Cartridge Header", "DS Cartridge Secure Area", "DS Technical Data" (<https://problemkaputt.de/gbatek.htm>, fetched 2026-10-12, SHA-256 `919ca0deac2fe11ecc4eda95fd95157772dd72e2ad69fff61bdbaa9fb53121c8`); devkitPro ndstool `76e8b681bb225d945a48852821e03114e6c7ce1c` `source/header.cpp` |
| `gbarom` | Game Boy Advance cartridge or multiboot image: 192-byte header | Strong: 0x96 at 0x0B2 and the complement at 0x0BD, plus the 156-byte logo at 0x004 (with the two variable bit groups masked) or an ARM `B` at 0x000 into the file and zero reserved bytes | `arm`, 32-bit, little-endian, variant `ARMv4T (ARM7TDMI)`. The whole file is one code section at 0x08000000; the entry is the branch target | GBATEK "GBA Cartridge Header"; devkitPro gba-tools `054d507f90d32784274b6cf7e03f1c43d02d7a57` `src/gbafix.c` |
| `gbrom` | Game Boy cartridge, or Game Boy Color cartridge when the CGB flag at 0x143 is 0x80 or 0xC0 | Strong: the 48-byte logo at 0x104, or its first 0x18 bytes (what CGB boot ROMs check) with a valid header checksum | `z80`, 8-bit, little-endian, variant `SM83`. The declared ROM size is one code section; entry 0x0100 | Pan Docs "The Cartridge Header", gbdev/pandocs `4b31c4ba0bccc94080b80216287d14519d18e160` |
| `nesrom` | iNES (including archaic iNES and iNES 0.7) or NES 2.0 | Strong: `NES` 0x1A at 0; NES 2.0 when byte 7 bits 2-3 are 2 and the NES 2.0 sizes fit the file | `mcs6502`, 8-bit, little-endian. Children: trainer and PRG-ROM (raw 6502 code), CHR-ROM, PlayChoice-10 INST-ROM and PROM, NES 2.0 miscellaneous ROMs (opaque) | NESdev Wiki "iNES" (oldid 23194), "NES 2.0" (oldid 24342), "CPU" (oldid 24046), "CPU memory map" (oldid 21671) |
| `snesrom` | SNES LoROM (0x7FC0), HiROM (0xFFC0) or ExHiROM (0x40FFC0) internal header, each with or without a 512-byte copier header; or ambiguous | Weak: checksum and complement, a map mode valid for the location, a printable title, and an emulation-mode reset vector in the ROM half of bank 0x00, all at exactly one of the six candidate locations | `w65816`, 16-bit, little-endian, variant `65C816 (Ricoh 5A22)`. The ROM after any copier header is one code section; entry is the reset vector. Several valid locations: ISA unknown, nothing extracted | SNESdev Wiki "ROM header" (oldid 1456), "ROM file formats" (oldid 858), "CPU vectors" (oldid 535); bsnes `78474e5d39f58872dc21aca18cf9eb583b147fe7` `bsnes/heuristics/super-famicom.cpp` |
| `n64rom` | Nintendo 64 ROM in native (`.z64`), 16-bit byte-swapped (`.v64`) or 32-bit word-swapped (`.n64`) order | Strong: first word `80 37 12 40`, `37 80 40 12` or `40 12 37 80` with the clock-rate low nibble 0xF | `mips64`, 64-bit, big-endian, variant `VR4300 (MIPS III)`. Sections: IPL3 (0x040-0xFFF, at 0xA4000040) and game code and data (from 0x1000, at the entry); swapped dumps are normalized with transform `N64 byte swap` | N64brew Wiki "ROM Header" (oldid 5925), "Initial Program Load" (oldid 5596), "VR4300" (oldid 5928); mupen64plus-core `ba95bab92a76744753bfe61470823a4937850ab0` `src/main/rom.c`; pmret/papermario `adaf3e6e730025fb6f5ddf07cc5147426c2025d6` `tools/n64crc.c` |

Detection position: the five magic-bearing layouts are checked in one block
right before the magic-bearing compressed streams in `detect_format`; the
SNES header, which has no magic, is checked with the other structure-only
layouts right before zlib and LZMA-alone. A child's platform variant is
reported only while the child's ISA is the named target (`Child::variant`,
applied in `lib.rs` after `apply_target`).

## CPU evidence

- Nintendo DS: the ARM9 and ARM7 areas have fixed roles (GBATEK "DS
  Technical Data"): ARM946E-S (ARMv5TE) and ARM7TDMI (ARMv4T). Both are
  32-bit little-endian Arm, so the container names `arm` and each child
  carries its core as its variant. Entry points may be ARM or Thumb; the
  header does not say which, so Thumb is not reported separately. The DSi
  ARM9i and ARM7i areas run on the same two cores.
- Game Boy Advance: the ARM7TDMI (ARMv4T); the entry word is ARM code. A
  game code of `PASS` marks an NDS PassMe boot image, which keeps the Arm
  target but drops the core variant.
- Game Boy: Pan Docs calls the CPU "an 8-bit 8080-like Sharp CPU
  (speculated to be a SM83 core)". The code model's `sm83` class belongs to
  its Z80 family (`Isa::Z80` with variant `sm83`), so the target is `z80`
  with variant `SM83`, and a note says so.
- NES: the NESdev "CPU" page names a Ricoh 6502 core without decimal mode
  (RP2A03 NTSC, RP2A07 PAL). The variant is `Ricoh 2A03 (6502 without
  decimal mode)` for NES/Famicom and iNES headers, `Ricoh 2A07 (6502 without
  decimal mode)` for NES 2.0 PAL timing, and `6502 with decimal mode
  (famiclone)` for NES 2.0 extended console type 0x3. Vs. System,
  PlayChoice-10, Dendy timing, the V.R. Technology and UMC famiclone types
  and the Famicom Network System keep the 6502 target without a variant,
  because the cited sources do not describe their CPUs; the notes name the
  console type.
- SNES: the 65C816 in the Ricoh 5A22, which resets into 6502 emulation mode.
  The raw code model has no 65816 class (the nearest is `m7700`), so the ISA
  comes from the platform alone; when the code model classifies the ROM as
  another family, a warning says so. Coprocessors named by the chipset byte
  (SA-1, GSU, DSP, CX4, ST018, ...) are noted, not split out.
- Nintendo 64: the VR4300, NEC's implementation of the 64-bit MIPS III
  instruction set, running big-endian (N64brew "VR4300"). Zrax has no
  separate MIPS III ID, so the target is `mips64` with variant `VR4300 (MIPS
  III)`: the variant records that the code is limited to MIPS III, not a
  later MIPS64 release. RSP microcode inside the ROM is not marked and is
  analyzed with the rest of the game data.

## Wire units and byte order

All offsets and sizes are bytes. DS, GBA and SNES header fields are
little-endian; the Game Boy global checksum is big-endian; NES header fields
are single bytes and nibbles; N64 header fields are big-endian in native
order. Header byte order is never reported as code byte order; the targets
above fix the code order.

Addresses: DS load and entry addresses are ARM addresses; the GBA section
is at the cartridge address 0x08000000; N64 addresses are KSEG0/KSEG1
virtual addresses. Game Boy and SNES section addresses are ROM offsets,
because the cartridge maps banks into the CPU address space; NES children
are file ranges, and the NES entry is a CPU address. SNES entries are
bank-0x00 CPU addresses.

N64 sections keep the stored file offsets and sizes; for `.v64` and `.n64`
dumps the section bytes are the normalized copy, and the metadata reads
`N B stored; N B decoded (N64 byte swap)`.

## Validation and resource bounds

| Layout | Errors | Reported, not enforced |
| --- | --- | --- |
| DS | Logo CRC field other than 0xCF56; header CRC-16/MODBUS over 0x000-0x15D; ARM9/ARM7 size 0, offset inside the 0x180-byte header or beyond the file; ARM9 load range not inside main RAM 0x02000000-0x023BFE00; ARM7 load range not inside main RAM or ARM7 WRAM 0x037F8000-0x03807E00; an entry outside those ranges; DSi unit code with fewer than 0x1000 header bytes | Entry outside the loaded bytes; secure-area CRC-16 (it covers the KEY1-encrypted form); logo bytes; total used ROM size; RSA-SHA1 signatures and SHA1-HMACs (not verified); ARM9i/ARM7i areas outside the file |
| GBA | Fixed byte, complement, file larger than the 32 MiB cartridge window | Logo match; entry branch |
| Game Boy | Header checksum; unknown ROM size code; declared ROM larger than the file; trailing bytes other than 0x00/0xFF padding or a 64-byte `GBX!` footer | Global checksum (verified when it matches; the hardware does not check it) |
| NES | PRG-ROM size 0; trainer, PRG-ROM, CHR-ROM beyond the file; NES 2.0 sizes that overflow 64 bits; declared miscellaneous ROMs missing; trailing data other than 0x00/0xFF padding, a 127- or 128-byte title, or the PlayChoice-10 INST-ROM (8 KiB) and PROM (32 B) | Mapper, submapper, RAM sizes, timing, console type |
| SNES | Not recognized unless every check passes at exactly one location | Declared ROM size smaller than the file |
| N64 | `.v64`/`.n64` size not a multiple of 2/4 B; file larger than 64 MiB (`MAX_PAYLOAD`); header or IPL3 truncated; no game code after 0x1000 | Check code: verified when the IPL3 CRC-32 identifies a CIC and the ROM holds 0x1000-0x100FFF; a mismatch is a note, an unknown IPL3 or a shorter ROM leaves it not verified |

The SNES checksum is the 16-bit byte sum with the part after the largest
power of two zero-padded to a power of two and repeated (SNESdev); it is
computed only after the cheaper checks pass at a location, so detection sums
the file at most six times. Only swapped N64 dumps allocate (one copy per
section, at most 64 MiB in total); every other section and child borrows the
input. A DS image has at most five children (secure area, ARM9, ARM7, ARM9i,
ARM7i); an NES image at most five (trainer, PRG-ROM, CHR-ROM, INST-ROM and
PROM, or the miscellaneous ROM area). GBA and N64 headers declare no ROM
size, so a truncated image still parses as the bytes that remain.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| N1 | A platform's fixed CPU counts as an explicit target, like XBE's x86 | A header for another CPU in one of these containers; the GBA `PASS` game code is the only known case and drops the variant |
| N2 | DS code areas load only into the GBATEK ranges (main RAM, ARM7 WRAM), with their entries in the same ranges | A working ROM whose ARM7 loads elsewhere would be a parse error (`nds_code_areas_must_load_into_ram_and_lie_in_the_file`) |
| N3 | The DS secure area's first 2 KiB are encrypted unless the ID is `encryObj` or `E7FFDEFF E7FFDEFF` | Homebrew with plain code at 0x4000 loses 2 KiB of analysis (`nds_secure_area_is_opaque_unless_its_id_shows_it_decrypted`) |
| N4 | A GBA image is a cartridge image at 0x08000000; multiboot images share the header | A multiboot image is reported at the cartridge address (noted) |
| N5 | SNES titles may hold JIS X 0201 katakana (0xA1-0xDF); the SNESdev page says ASCII | A Japanese dump with a katakana title is recognized; other high bytes reject the location (`snes_needs_every_header_check_to_pass`) |
| N6 | Map mode nibbles 0x0, 0x2, 0x3 belong to the LoROM location, 0x1 and 0xA to HiROM, 0x5 to ExHiROM; SNESdev and rom-properties disagree on what 0x2 means | A dump with nibble 0x2 at the HiROM location is not recognized |
| N7 | The CIC 6103/6106 boot-address adjustment (N64brew: "before jumping") also applies to where IPL3 copies the game code | Disassemble a 6103 IPL3, or compare a 6103 game's linked address with its header (`n64_cic_6103_moves_the_entry_below_the_boot_address` pins the current reading) |
| N8 | IPL3 runs from RSP DMEM at 0xA4000040 (N64brew "Initial Program Load"; not in the collected header notes) | The IPL page and the PIF boot code |
| N9 | The check code is n64crc.c's reimplementation, with CICs identified by the CRC-32 of IPL3 | Real ROMs with known check codes; a disagreement is a note, never an error |
| N10 | Mapper 0 (NROM) maps the end of PRG-ROM at CPU 0xFFFF, so its last 6 bytes are the vectors (from the NROM board, not the header pages) | An NROM image whose reset vector does not point into its PRG-ROM |
| N11 | A header with NES 2.0 bits whose sizes exceed the file is iNES (NESdev recommendation) | `nes_sizes_trailers_and_unclean_headers` |
| N12 | An iNES header with bits 2-3 of byte 7 or bytes 12-15 nonzero carries text in bytes 7-15, so flags 7 and the upper mapper nibble are ignored | `DiskDude!` headers (`nes_sizes_trailers_and_unclean_headers`) |
| N13 | NES 2.0 PAL timing (RP2C07 PPU) implies the RP2A07 CPU that the NESdev "CPU" page names for PAL consoles | A PAL-timed NES 2.0 image for hardware with another CPU |
| N14 | A Game Boy file ends at the declared ROM size, except for padding or a GBX footer | Overdumped or trimmed files become parse errors (`gb_trailing_bytes_must_be_padding_or_a_gbx_footer`) |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| DS NitroROM file system, overlays, icon/title | Not parsed; noted |
| DS KEY1 secure area and DSi modcrypt (AES-CTR) | Not decrypted; the affected bytes are opaque |
| DS and DSi signatures and HMACs | Reported as not verified |
| Thumb entry points (DS, GBA) | Not distinguished from ARM |
| GBA multiboot load address 0x02000000 | Not distinguished from a cartridge image |
| Game Boy GBX footer fields, MBC banking | Footer recognized by size and magic only, not parsed; banking not modeled |
| Wii U VC `NES\0`, 3DS `TNES`, Famicom Disk System `FDS\x1A` | Not recognized |
| NES mapper bank switching | Not modeled; vectors are noted for mappers other than 0 |
| SNES ExLoROM (0x407FC0, bsnes only), interleaved dumps, NSRT headers | Not probed |
| SNES coprocessor code (SA-1, GSU, DSP, ST018) and SPC700 audio code | Not split from the ROM |
| N64 homebrew with other PI timing words, the `12 40 80 37` order, 64DD disk images | Not recognized |
| N64 CIC 7102 | Not identified (its IPL3 CRC-32 is not in the sources); its check code is not verified |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly `f248f4038`
2026-09-05), `cargo test --all-features --locked` passed: 539 tests, 6
ignored, including `tests/nintendo.rs` (26 tests) and 13 unit tests in
`src/formats/nintendo`. The integration tests cover a positive case per
layout and byte order, ISA and variant per platform, children with stored
offsets, corrupted fields and checksums, SNES ambiguity, N64 check codes for
CIC 6102, 6103, 6105 and 6106 (IPL3 bytes forged to the CRC-32 that
identifies the CIC, check codes computed by a separate test implementation
of the n64crc.c pseudo-code), a truncation sweep that requires an error for
every prefix of the DS, NES and Game Boy fixtures and no SNES recognition
for any LoROM prefix, and no-panic sweeps over byte mutations (0x00, 0xFF,
bit flip) of every fixture. `./build-web.sh` and
`web/tests/nintendo.test.mjs` (5 tests: classification through
`/pkg/zrax.js` and `/dist/zrax.js`, and the workbench in `/web/` and
`/dist/`) passed with Node.js 25.8.1; the whole browser suite passed 74 of
78 tests with 4 skipped (they need D10 and RX113 firmware that is not in the
repository).

All fixtures are synthetic, built in the tests from the documented
layouts; the Arm and MIPS payloads are compiled code from `testbins/`. No
commercial ROM was classified, so behavior on real dumps (including the
check code for real IPL3s and the SNES heuristics on commercial images) is
not verified.
