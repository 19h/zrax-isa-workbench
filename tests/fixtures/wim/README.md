# WIM fixture provenance

These fixtures hold only files made for this repository: no Windows
component, setup image or other third-party data. `tests/wim.rs` and
`web/tests/wim.test.mjs` use them. Generated on 2026-10-13 on macOS
(AArch64) with `tests/fixtures/wim/generate.sh`.

| Fixture | Size (B) | SHA-256 | Written by |
| --- | --- | --- | --- |
| `7zip-stored.wim` | 2601 | `23bc5a56d0b5566a613a6791b017c5392e4bf230ef8c669ef724e64f665264a1` | 7-Zip 26.03 |
| `xpress.wim` | 7212 | `6438806bac3ac79c86c09b63bb490a4ed45048b6d69ca305b3784b612cf3f01c` | test builder |
| `lzx.wim` | 6379 | `a856f0652bcf89d16f95aa16ff6041fc7f484476b723a68c4bac12cdf74ad889` | test builder |
| `solid-lzx.wim` | 7036 | `51f79de8e2b9e2ffbc5f6280e1af2ab202aeacad7395772c349960f701cd496d` | test builder |
| `solid-lzms.wim` | 2628 | `29130f350b444270b17aeb2341a6322709da02ca9e2cf6a9de7d4970edaf76de` | test builder |

## Contents

Every fixture holds one image with these files:

| Path | Size (B) | Source |
| --- | --- | --- |
| `Windows/System32/driver.efi` | 428 | Bytes 4 to `0x1B0` of `tests/fixtures/uefi/pe32-sections.bin`, an x86-64 PE32+ image |
| `payload.elf` | 256 | `tests/fixtures/archives/payload.elf`, an AArch64 ELF |
| `readme.txt` | 37 | The text `Release notes: nothing to see here.` and CRLF |
| `tools.elf` | 20000 | Synthetic fixtures only: `payload.elf`, then a repeated English phrase with an `E8` call opcode and a 32-bit operand every 211 bytes, which exercises the LZX call translation |
| `table.bin` | 4000 | Synthetic fixtures only: 2,000 little-endian 16-bit counters stepping by 3, which LZMS codes with delta matches |

The synthetic fixtures name their image `Fixture`. They differ in layout:

| Fixture | Version | Compression | Chunk size |
| --- | --- | --- | --- |
| `xpress.wim` | `0x10D00` | XPRESS Huffman, one resource per file | 32 KiB |
| `lzx.wim` | `0x10D00` | LZX, one resource per file | 32 KiB |
| `solid-lzx.wim` | `0xE00` | One solid LZX resource for the files | 32 KiB |
| `solid-lzms.wim` | `0xE00` | One solid LZMS resource for the files | 64 KiB |

In the two solid fixtures the chunk size is the solid resource's own; the
header names the codec, its chunk size field is 0, and the image metadata
resources are stored uncompressed. In every synthetic fixture, a chunk
that coding does not make smaller is stored as is.

## Generators

- `7zip-stored.wim`: 7-Zip `7-Zip (z) 26.03 (arm64) : Copyright (c)
  1999-2026 Igor Pavlov : 2026-09-03` (Homebrew `7zz`), which writes only
  uncompressed WIMs. The archive holds the capture time and a random GUID,
  so a new run writes different bytes; the hash above identifies the
  committed file.
- The other four: the test builder `tests/support/wim_image.rs` with the
  test encoders `tests/support/xpress.rs`, `tests/support/wim_lzx.rs` and
  `tests/support/lzms.rs`, at the commit that adds this file. The test
  `committed_synthetic_fixtures_match_the_builder` fails when the
  committed bytes differ from what the builder writes. Their GUID,
  timestamps and security data are fixed values.

Command, from the repository root (needs `7zz`, `cargo` and `python3`):

```sh
tests/fixtures/wim/generate.sh
```

The script prints each fixture's size and SHA-256.

## Independent check

On 2026-10-13, 7-Zip 26.03 (`7zz t`) reported `Everything is Ok` for all
five fixtures, which includes its SHA-1 check of every file, and
`7zz x` extracted the four synthetic fixtures to exactly the files listed
above. `7zz l -slt` reported the methods `XPress:15`, `LZX:15` (both LZX
fixtures) and `LZMS:15`/`LZMS:16`. This is the only check by a decoder
other than this repository's; no Microsoft tool (DISM, `wimgapi.dll`) was
run.
