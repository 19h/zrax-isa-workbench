# ZX Spectrum tape images

`src/formats/zxtape.rs` reads ZX Spectrum tape images. The platform's CPU
is the Z80, so the target is explicit.

| JSON format ID | Layout | Recognition | Primary source |
| --- | --- | --- | --- |
| `zxtape` (TZX) | `ZXTape!\x1A`, version, then blocks by ID with the specification's length rules; standard (0x10), turbo (0x11) and pure-data (0x14) blocks carry ROM tape blocks | Strong: signature. Unknown block IDs are parse errors | World of Spectrum, "TZX format" revision 1.20 |
| `zxtape` (TAP) | Little-endian length, then a ROM tape block, to the end of the file | Weak: at least two blocks covering the file exactly, the first a ROM header, every XOR checksum valid | World of Spectrum, TAP description |

A ROM header block (flag 0x00, 17 data bytes) names the file type, name,
data length and parameters. A `Bytes` header (type 3) followed by a data
block (flag 0xFF) becomes a load section at the header's start address and
goes to the code model. BASIC programs are noted, not analyzed. Headerless
or custom-loader blocks have no load address and are counted, not analyzed.
Checksum failures in TZX files are counted in a note.

Known boundaries: snapshots (`.z80`, `.sna`) have no signature and are not
recognized; custom-loader data inside headerless blocks is not located.

Verification: on 2026-10-12 (macOS AArch64), `tests/zxtape.rs` (3 tests,
synthetic tapes with a hand-assembled Z80 routine, truncation and mutation
sweeps) passed.
