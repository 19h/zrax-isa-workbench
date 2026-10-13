# Chiptune program files

Some music formats store the playback driver as machine code for the
original platform's CPU. `src/formats/chiptune.rs` recognizes three of them.
The format names the platform, so the target is explicit, as for SNES SPC.

| JSON format ID | Layout | Target | Primary source |
| --- | --- | --- | --- |
| `nsf` | NSF (`NESM\x1A`, 128-byte header; NSF2 program length) and NSFe (`NSFE` chunk stream: `INFO`, `DATA`, `NEND`; unknown uppercase chunks rejected) | `mcs6502`, 8-bit: Ricoh 2A03 (6502 without decimal mode) | NESdev wiki, "NSF" and "NSFe" |
| `sid` | PSID versions 1-4 and RSID versions 2-4: big-endian header, program at the data offset, load address from the header or the first two data bytes | `mcs6502`, 8-bit: MOS 6510. RSID BASIC and PSID MUS programs are opaque | HVSC `SID_file_format.txt` |
| `gbs` | GBS version 1, 0x70-byte header, code loaded at `$0400`-`$7FFF` | `z80`, 8-bit: Sharp SM83, which the code model treats as a Z80-family variant | `gbsformat.txt` (Scott Worley, 2001) |

Recognition requires the magic and a consistent header: song numbers in
range, load, init and play addresses in the platform's program space, and a
non-empty program. The program is one load section at the load address and
goes straight to the code model; it is never treated as a nested container.

Known boundaries: bank-switched NSF programs are analyzed as stored, without
reconstructing the bank mapping. The PSF family, HES, KSS, SAP, AY, SNDH and
Pack-Ice files are described in
[more chiptune and sound-program formats](chiptune-sound-programs.md).

Verification: on 2026-10-12 (macOS AArch64), `tests/chiptune.rs` (6 tests,
synthetic headers with short hand-assembled drivers, truncation and mutation
sweeps) passed.
