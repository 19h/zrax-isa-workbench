# Blackfin LDR boot streams

An LDR file is the block stream the Blackfin boot ROM loads.
`src/formats/blackfin_ldr.rs` parses it; the format is the boot ROM's own,
so the target is Blackfin (32-bit, little-endian).

| JSON format ID | Layout | Recognition | Primary source |
| --- | --- | --- | --- |
| `blackfinldr` | BF51x/BF52x/BF54x/BF59x: 16-byte headers (block code with signature `0xAD` and XOR check byte, target address, byte count, argument); `FILL` and `IGNORE` blocks; several boot streams back to back | Strong: signature and XOR checksum of the first header, then a complete walk | ldr-utils `2253efd1` `lfd_bf548.c`; U-Boot v2016.01 `bootrom.h` |
| `blackfinldr` | BF53x: 10-byte headers (target address, byte count, flags); `ZEROFILL`, `IGNORE`, `INIT`, `FINAL` | Weak: first block in L1 memory (U-Boot's `address & 0xFF0FFF0F == 0xFF000000`), a complete walk to the final block, padding only after it | ldr-utils `lfd_bf537.c`; U-Boot `cmd_bootldr.c` |
| `blackfinldr` | BF56x: 4-byte global header with signature nibble `0xA`, then BF53x blocks | Weak, as BF53x | ldr-utils `lfd_bf561.c`; U-Boot `bootrom.h` |

Loaded blocks (not fill, zero-fill or ignore blocks) become load sections at
their target addresses and go straight to the code model for cross-checks
and extensions. Initialization blocks are counted in the notes. Block counts
are bounded by the input size and by 4096 sections; data after the final
block must be padding.

Known boundaries: compressed BF53x blocks (`BFLAG_53X_COMPRESSED`) and
callback-processed blocks are listed as stored, not decoded. SHARC LDR files
are not recognized.

Verification: on 2026-10-12 (macOS AArch64), 3 unit tests and
`tests/blackfin_ldr.rs` (4 tests, synthetic streams with truncation and
mutation sweeps) passed. No ADI-generated LDR file was available.
