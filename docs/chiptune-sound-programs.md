# More chiptune and sound-program formats

`src/formats/chiptune.rs` and its submodules `psf`, `psf2`, `hes`, `kss`,
`sap`, `ay` and `sndh` add the PSF family, HES, KSS, SAP, AY and SNDH to the
chiptune family (NSF, SID and GBS are described in
[chiptune program files](chiptune.md)). All of them are built on the shared
container model ([compressed streams and the container model](compressed-streams.md)):
the music driver is machine code for the platform's CPU, and the platform
the format names is the explicit target, as for SNES SPC files.

## Implemented layouts

| JSON format ID | Layout | Target and architecture evidence | Primary source |
| --- | --- | --- | --- |
| `psf` (PSF1, 0x01) | `PSF` + version byte, reserved size, compressed size, CRC-32 (verified); zlib program decoded; `[TAG]` block parsed | `mips` 32-bit little-endian (R3000). The program is a `PS-X EXE` child classified by its own parser | Neill Corlett, "PSF specification v1.6" (16 March 2006), pinned: `web.archive.org/web/20060420042053/http://www.neillcorlett.com:80/psf/psf_format.txt` |
| `psf` (PSF2, 0x02) | Reserved area is a virtual filesystem: directories of 48-byte entries, files as zlib blocks with a size table | None from the format. Files whose first block starts a recognized format are children; `psf2.irx` and other IOP modules are ELF, so the ELF parser names the ISA from `e_machine` | PSF v1.6, "PSF2: Virtual filesystem format" |
| `psf` (SSF, 0x11) | Program = 4-byte LE load address + code, one load section | `m68k` big-endian ("raw 68000 program data"); entry = initial PC at address 4 when loaded at 0 | PSF v1.6, "Version 0x11" |
| `psf` (DSF, 0x12) | As SSF | `arm` 32-bit; the document names an ARM7 but not its byte order, so the order comes from the code | PSF v1.6, "Version 0x12" |
| `psf` (Genesis, 0x13) | Header and CRC only | None: "format to be announced" | PSF wiki live specification, pinned: `web.archive.org/web/20140125155137/http://wiki.neillcorlett.com:80/PSFFormat` |
| `psf` (USF, 0x21) | Reserved area: SR64 ROM segment and SR64 Project64 v1.4 save state (or four zero bytes each); ROM chunks are load sections, each 32-bit word swapped back to big-endian | `mips64` 64-bit big-endian (VR4300); the save state is noted, not analyzed | "USF specification v1.1", pinned: `web.archive.org/web/20050428023306/http://www.halleyscometsoftware.com:80/usf/usf.txt`; SR64 terminator as in lazyusf2 `usf/usf.c` (losnoco/Cog `fb2ed48d`) |
| `psf` (GSF, 0x22) | Program = entry point, ROM offset, ROM size, ROM data; one load section at the ROM offset (a GBA address) | `arm` 32-bit little-endian (ARM7TDMI); a whole ROM may be recognized by the GBA ROM parser | Caitsith2, "GSF Specifications version 0.02", pinned: `web.archive.org/web/20080530120338/http://gsf.caitsith2.net:80/gsf%20spec.txt` |
| `psf` (SNSF, 0x23) | Program = ROM offset, ROM size, ROM data | `w65816` 16-bit little-endian; ROM offsets, not CPU addresses | Caitsith2, "SNSF Specifications version 0.02", pinned: `web.archive.org/web/20081223230630/http://snsf.caitsith2.net:80/snsf%20spec.txt` |
| `psf` (2SF, 0x24) | Program = ROM offset, ROM size, DS ROM image data | `arm` 32-bit little-endian (ARM9 and ARM7) | "2sf specifications revision 7", pinned: `web.archive.org/web/20090706091626/http://unknown.hcs64.com:80/2sf/2sfspec.txt` |
| `psf` (NCSF, 0x25) | Reserved area empty or a 32-bit sequence number; program = zlib SDAT whose size (bytes 8-11) must match | None: SDAT sound data, an opaque child | Naram Qashat, "NCSF Specification v1.0", pinned: `web.archive.org/web/20131116015834/http://www.cyberbotx.com:80/NCSF/` |
| `psf` (QSF, 0x41) | Program = tagged blocks (`KEY`, `Z80`, `SMP`: tag, LSB-first offset and length, data) | `z80`. `Z80` blocks are load sections unless the Kabuki key has a nonzero swap key (then encrypted, not analyzed); `SMP` sample data is never analyzed | PSF v1.6, "Version 0x41" |
| `hes` | `HESM` header (version 0, start song, init address, MPR0-MPR7), then `DATA` blocks (size, physical load address, reserved) | `mcs6502` 8-bit; layout label names the `HuC6280` | Mamiya, "HES Music Format Spec V1.00", pinned: `web.archive.org/web/20030113021145/http://www.purose.net:80/befis/download/nezplug/hesspec.txt` |
| `kss` | `KSCC` or `KSSX` header (load, length, init, play, first bank, bank count and mapper, `KSSX` extra header), initial data, 16 KiB or 8 KiB banks | `z80` 8-bit; banks are listed at the 0x8000 window | Mamiya, "KSS Music Format Spec V1.03", pinned: `web.archive.org/web/20030113015803/http://www.purose.net:80/befis/download/nezplug/kssspec.txt`; libkss `kssxspec.md` at `2ed958823237d054da1ca7965620d8e62a0f9a1d` |
| `sap` | Text header (`SAP` + CR/LF; known tags validated), then Atari executable blocks (`FF FF`, first and last address) | `mcs6502` 8-bit; TYPE R register dumps have no ISA | ASAP "SAP file format specification", <https://asap.sourceforge.net/sap-format.html> (fetched 2026-10-13, SHA-256 `edbddc1a2636ce3128a7de8cadb0b007f44479d6fc12c1e2ad273ce3f3ccbde9`) |
| `aytune` | `ZXAYEMUL` header, song records, song data, pointers and data blocks, all through signed relative pointers | `z80` 8-bit | Sergey Bulba, AY-3-8910/12 Emulator help, "AY", pinned: `web.archive.org/web/20210812230617/https://documentation.help/AY-3-8910.12-ZX-Spectrum/ay_e04vt.htm`; block layout cross-checked with Game Music Emu 0.6.5 `gme/Ay_Emu.cpp` (`9e23d10f`) |
| `sndh` | `SNDH` at offset 12 after three entry branches; header tags up to `HDNS` | `m68k` big-endian; the whole file is one section, addresses are file offsets | "SNDH file structure, Revision 2.2" (January 2026), <https://sndh.atari.org/fileformat.php> (fetched 2026-10-13); same text in frno7/psgplay `doc/sndhv22.txt` at `6f1c39ffdacd4e568893c634033a571b2a34a01a` |
| `packice` | `ICE!`, packed size (including the 12-byte header) and unpacked size, big-endian | None: the packed data is an opaque child | frno7/psgplay `include/ice/ice.h` and `lib/ice/ice.c` at `6f1c39ff` |

The GSF, SNSF and 2SF documents do not give the byte order of their program
headers; little-endian is taken from the reference players, CyberBotX
`in_xsf` at `74fceae1f09f2e42afff4f71fb68b1952f494916`
(`src/in_gsf/XSFPlayer_GSF.cpp` `MapGSFSection`,
`src/in_snsf/XSFPlayer_SNSF.cpp` `MapSNSFSection`,
`src/in_2sf/XSFPlayer_2SF.cpp` `Map2SFSection`).

Tags of PSF files become notes: descriptive variables (`title`, `artist`,
`game`, `year`, `genre`, `copyright`, `comment`, `length`, `fade` and the
`*by` creator variables), library references (`_lib`, `_lib2`, ...), which
are noted as not resolved because they name other files, and other reserved
variables (`_refresh`, `_memory`, ...). Every variable is also metadata
`psf_tag_<name>`. PSF2 files are listed as `psf_file_<n>` metadata.

## Detection

All layouts are strong: they are recognized from their magic and then
parsed, so a damaged file is a parse error rather than raw code. The
checks run in `formats::chiptune::detect`, after NSF, NSFe, PSID/RSID and
GBS and in the position the chiptune family already had in
`detect_format` (ahead of the archive, filesystem and compressed-stream
checks). Three magics are short or printable, so recognition adds one
structural condition each:

- PSF: `PSF`, an assigned version byte, and a reserved area and program that
  fit in the file. Version bytes 0x21-0x25 and 0x41 are printable, so text
  starting `PSF!` or `PSFA` is not a PSF file. A PSF file truncated inside
  its reserved area or program is therefore not recognized.
- SAP: `SAP` and CR/LF, then a line that starts with a tag the
  specification defines.
- SNDH: `SNDH` at offset 12, then a header tag this parser reads or `HDNS`.
  This keeps, for example, a tar archive whose first member path has `SNDH`
  at offset 12 (`Music/Atari/SNDH/...`) from being taken for SNDH.

`HESM`, `KSCC`, `KSSX`, `ZXAYEMUL` and `ICE!` are recognized from the magic
alone.

## Wire units and byte order

All offsets and sizes are bytes. PSF headers, PSF2 directories, SR64
chunks, QSF block headers and the GSF, SNSF and 2SF program headers are
little-endian; QSF Kabuki keys are big-endian. USF ROM chunks are stored as
little-endian 32-bit words of the big-endian ROM and are swapped back before
analysis (transform `32-bit byte swap`); section addresses are ROM offsets.
HES load addresses are `HuC6280` physical addresses (21 bits) while the init
address is a logical 16-bit address. KSS, SAP and AY addresses are 16-bit
CPU addresses; KSS banks are listed at the 0x8000 bank window. AY and SNDH
headers are big-endian. Header byte order is never reported as code byte
order.

## Validation and resource bounds

- PSF: the reserved area and the program must lie in the file; the CRC-32
  (zlib, IEEE 802.3) of a non-empty program must match; the program must be
  a complete zlib stream. Decoded size limits: PSF1 2,033,664 B, SSF
  524,292 B, DSF 2,097,156 B (the specification's limits), otherwise 64 MiB.
  Bytes after the program that are not `[TAG]` are noted and ignored. At
  most 64 tag variables are kept, 256 characters each.
- PSF2: entry counts are checked against the reserved area before reading;
  every file or subdirectory offset must lie after its own entry, so the
  walk cannot loop; names must be 1-36 bytes of ASCII 32-126 without
  `/ \ :`, paths at most 255 bytes; at most 4096 entries are visited; a
  size table must fit the area before it is read; every block of a decoded
  file must decode to exactly the block size (the last to the remainder).
  Files are decoded only when their first block starts a recognized format,
  each at most 64 MiB and 256 MiB in total.
- USF: each segment must be `SR64` or four zero bytes; chunks must lie in
  the reserved area; ROM chunks that are not whole 32-bit words, beyond 4096
  sections or beyond 64 MiB are noted and not analyzed.
- GSF, SNSF, 2SF: the decoded program must hold its header and the declared
  ROM size; an undocumented GSF entry point or a ROM offset whose high byte
  differs from the entry point's is noted.
- NCSF: the reserved area must be 0 or 4 bytes; the SDAT size field must
  equal the decoded size.
- QSF: every block must lie in the decoded program; unknown block tags are
  errors; `KEY` data must fit 11 bytes; at most 4096 `Z80` sections.
- HES: version must be 0 and the first block must be `DATA`. A data size
  beyond the file is clipped to the bytes present and noted, because Game
  Music Emu 0.6.5 (`gme/Hes_Emu.cpp`) reports that "many files have bad
  sizes"; further `DATA` blocks are read when they follow directly.
- KSS: reserved bits, an unexpected `KSSX` extra header size, initial data
  beyond the file or the 64 KiB address space and missing banks are noted,
  not rejected, as Game Music Emu 0.6.5 (`gme/Kss_Emu.cpp`) tolerates them;
  a last bank cut short by the end of the file is kept.
- SAP: the header must consist of printable tag lines; the known tags'
  arguments are validated (quoted strings, decimal `SONGS`, `DEFSONG` and
  `FASTPLAY` up to 32767, one to four hex digits for addresses, the `TIME`
  shape, `STEREO` and `NTSC` without an argument, `TYPE` one of B, C, D, S,
  R); `TYPE` and the tags each type requires must be present. A block cut
  short by the end of the file is kept and noted ("malformed, but some SAP
  players accept them"). At most 4096 blocks.
- AY: every pointer must land inside the file; a block reaching past 65536
  or the end of the file is shortened, following the documentation's
  loading rules; at most 4096 block records are read over all songs, and
  blocks shared by several songs are listed once.
- SNDH: recognized by `SNDH` at offset 12; header tags are read until
  `HDNS` or the first tag this parser does not know.
- Pack-Ice: the packed size must be at least 12 bytes and fit the file, the
  unpacked size nonzero.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| C1 | The PSF CRC-32 is zlib's `crc32` (IEEE 802.3) | `psf_crc_sizes_and_program_stream_are_checked`; a real PSF whose stored CRC differs from `checksum::crc32` of its program would falsify it |
| C2 | GSF, SNSF and 2SF program headers are little-endian | A real GSF whose decoded program starts `00 00 00 08` would read as entry 0x08000000 only little-endian |
| C3 | USF ROM chunks are the native big-endian ROM with every 32-bit word reversed | A full-ROM USF whose chunk at offset 0 starts `40 12 37 80` swaps to the N64 header word `80 37 12 40` |
| C4 | The DSF document does not fix the ARM7 byte order | Reported from the code model (`ssf_and_dsf_load_their_programs_at_the_given_address`); a big-endian DSF would show a byte-order note |
| C5 | PSF2 IOP modules are ELF files that name their own machine | `psf2_lists_its_filesystem_and_the_elf_parser_names_the_irx_isa`; a module that is not ELF is listed only in the metadata |
| C6 | A QSF key with both swap keys zero means the Z80 program is plain | `qsf_z80_blocks_are_code_unless_the_key_encrypts_them` |
| C7 | HES `DATA` blocks may be followed by further `DATA` blocks | Not established by HES V1.00; files with one block are unaffected |
| C8 | The `HuC6280` runs 6502-family code | MAME `h6280.cpp` (`mame0289`) says only that its emulator is based on a 6502 emulator; the 65C02 lineage is not verified, so the variant says `HuC6280` without `(65C02)` |
| C9 | A real SNDH file has a header tag right after `SNDH` | `text_and_archive_paths_with_the_magics_are_not_taken_for_tunes`; an SNDH file that starts its header with another tag would not be recognized |
| C10 | A real SAP file's second line is a defined tag | GStreamer's identification even requires `AUTHOR` there (ASAP specification); a file starting with an undefined tag would not be recognized |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| MiniPSF libraries (`_lib`, `_lib2`, ...) | Noted as not resolved: they name other files |
| Pack-Ice decoding | Not implemented: the only depacker source found (psgplay `lib/ice/ice.c`) is GPL-2.0, this crate is MIT OR Apache-2.0, and no independent test vectors were available. The packed data is opaque and its content format is not determined |
| PSF version 0x13 (Sega Genesis) | Recognized; reserved area and program not interpreted |
| GSF and SNSF save-state reserved areas | Noted, not analyzed (the format is undefined) |
| USF save states | Noted with the Project64 identifier check; emulator state, not analyzed |
| AY files of type `AMAD` | Not recognized (FXM music data, not Z80 code) |
| SNDH subtune names (`#!SN`) and unknown tags | Header reading stops there; the program is still one section |
| KSS 8 KiB banks | Listed at 0x8000; which window (0x8000 or 0xA000) a bank occupies is chosen at run time |
| SAP TYPE R | The data is a POKEY register dump; no ISA is reported |
| SNDH entry branch targets | Informational notes from the `bra.w` encoding (opcode 0x6000, 16-bit displacement from the opcode + 2); the 68000 encoding source is not pinned here |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly),
`tests/chiptune_sound_programs.rs` (22 tests) passed, with every-prefix and
every-byte mutation sweeps (0x00, 0xFF, bit flip) over one fixture per
layout, together with the 8 unit tests in the new submodules and the
whole native suite (`cargo test --all-features --locked`: 1034 passed, 6
ignored, the same 6 as on the base commit). The browser test
`web/tests/chiptune-sound-programs.test.mjs` passed through `/pkg/zrax.js`
and `/dist/zrax.js` after `./build-web.sh`; the whole browser suite ran 128
tests, 124 passed and 4 skipped (they need D10/RX113 firmware that is not in
the repository). All fixtures are synthetic, built in the tests from
the documented layouts with short hand-assembled drivers and the
repository's compiled testbins as code; no rips are redistributed. No real
PSF, HES, KSS, SAP, AY or SNDH file was available, so behavior on real
files is not verified.
