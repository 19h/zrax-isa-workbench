# Automotive flash containers

`src/formats/automotive.rs` recognizes four automotive containers. None of
them names the ECU's CPU, so the ISA always comes from extracted flash data.

| JSON format ID | Layout | Recognition | Primary source |
| --- | --- | --- | --- |
| `odx` | ASAM ODX document; for the FLASH category, every `FLASHDATA`: `INTEL-HEX`/`MOTOROLA-S` text decoded by the hex parsers, `BINARY` hex text decoded; `USER-DEFINED` or `ENCRYPT-COMPRESS-METHOD` data opaque; `EXTERN-FLASHDATA` noted | Strong: `ODX` root element after the XML declaration | odxtools 11.7.0 (the ASAM schemas are not public) |
| `hondarwd` | Formats `0x5A` (six length-prefixed headers, one firmware block) and `0x31` (delimited headers, 130-byte records merged into blocks) | Strong: format byte and CR LF plus the trailing 32-bit sum | rwd-xray `83b990e3` (community reverse engineering) |
| `toyotacuw` | `\0CALIBRATION\0`, format type, CRC-32 over the declared range, members with CRC-32; formats `0x04`/`0x67` member lists | Strong: 13-byte magic | `kaikozlov/ghidra_rh850` `7b31684d` (community reverse engineering) |
| `mercedescff` | Caesar flash file: stub, header size, bit-flag flash header, data blocks and segments | Weak: un-inverted CRC-32 over the file and a consistent header | `CaesarSuite` `f8e8463f` (community reverse engineering) |

Behavior and bounds: RWD firmware is enciphered with a key-selected byte
substitution whose decoder rwd-xray chooses from the file name, so it stays
opaque. CUW `attach.att` is opaque INI text; other members are listed only
when recognized (plain S-records). CFF segments in encrypted data blocks are
opaque; signatures and checksums inside ODX and CFF are reported as not
verified. The XML reader never expands DTD entities, limits nesting to 256
levels, and requires balanced elements. Components are capped at 4096.

Known boundaries: Mercedes SMR-F has no public layout and is not recognized.
RWD formats `0x58`, `0x59` and `0x30` have no established layout. PDX
packages need the ZIP container, which is being added separately; ODX
`EXTERN-FLASHDATA` files are therefore not resolved yet.

Verification: on 2026-10-12 (macOS AArch64), `tests/automotive.rs` (9 tests,
synthetic fixtures built from the documented layouts, with truncation and
mutation sweeps) passed.
