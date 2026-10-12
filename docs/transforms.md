# Raw-dump transforms

Some dumps hold correct code in the wrong byte order: two 8-bit EPROMs on a
16-bit bus dumped one after the other, a programmer that swapped bytes, or a
NAND read that kept each page's spare area. These break the adjacent-byte
pairs the code model scores, so correctly dumped code reads as non-code.
`src/transform.rs` defines the readings that undo them. Nothing in the bytes
declares a transform, so transforms are not containers.

## Readings tried

| Transform | Applies when | Effect |
| --- | --- | --- |
| 16-bit byte swap | length is a multiple of 2 | Swap the bytes of every 16-bit word |
| 32-bit byte swap | length is a multiple of 4 | Reverse the bytes of every 32-bit word |
| 2-lane interleave, in file order or reversed | two equal halves of at least 256 B | Interleave the halves (even/odd EPROMs dumped one after the other) |
| 4-lane interleave, in file order or reversed | four equal quarters of at least 256 B | Interleave four lanes (32-bit bus) |
| NAND spare removal | length is a multiple of the page plus spare size, at least 4 pages | Drop the spare bytes of every page: 512+16, 2048+64, 4096+128, 4096+224 or 8192+448 B |

Separately dumped lanes are interleaved directly with
`zrax::detect_interleaved(&[even, odd], options)` or
`zrax --interleave even.bin odd.bin`; the payload's offsets then refer to the
interleaved image.

## When transforms are tried

- A top-level raw input whose code-model result is inconclusive. Every
  applicable reading is classified, and the most confident result is kept.
- A top-level container that is recognized but does not parse: each NAND
  spare geometry is removed and the input is parsed again when the same
  layout is detected. Slice offsets are mapped back to the stored dump, and
  `decoded` gives the range in the spare-free image.
- Never in fast mode (`ClassifierOptions::fast`, `try_transforms: false`), and
  never for nested components, so the cost stays bounded at one input.

The applied reading is recorded in the `transform_applied` metadata entry,
along with the number of readings tried (`transform_trials`) and a note that
the stored bytes are not in execution order. Extensions are detected on the
transformed bytes.

## False accepts

Trying `k` readings gives `k` chances of a false accept. Each attempt pays a
union-bound penalty (`heuristics::analyze_detailed_with_trials`):

- a window needs `ceil(log2(k))` more bits of total margin (16 bits
  normally);
- the weak-window false-alarm allowance is multiplied by `k`, so weak hits
  must outweigh `k` times as many chance windows.

With all eleven readings applicable, `k = 12`: 4 more bits per window and a
twelvefold allowance. Strong windows (a margin of at least 1 bit per byte)
still count in full.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| T1 | A transform is applied only when the stored order is inconclusive | Code in execution order never gets a `transform_applied` entry (`fixtures_classify_in_execution_order`) |
| T2 | The union-bound penalty keeps noise inconclusive | Deterministic noise of several sizes, including NAND-shaped lengths, stays inconclusive (`noise_stays_inconclusive_after_every_transform`) |
| T3 | A spare-area geometry that lets a recognized container parse is the dump's geometry | uImage inside a 2048+64 B NAND read parses after removal (`a_nand_dump_of_a_container_parses_after_spare_removal`) |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| A swap that yields another valid byte order of the same ISA | Classified in that byte order before any transform is tried. On the 2026-10-12 fixtures, a 16-bit swap of 32-bit Arm code read as big-endian Arm, and a 16-bit swap of big-endian MIPS read as little-endian MIPS. A 32-bit swap of a bi-endian ISA is indistinguishable from the other byte order. |
| An even/odd split of 32-bit Arm code | Read as big-endian Arm by the first-order model, so no transform is tried |
| Interleaves with more than four lanes, word-wide lanes, or lanes of unequal size within one file | Not tried |
| NAND layouts with spare bytes interleaved inside the page (per 512-byte ECC chunk) | Not tried |
| Bad-block remapping and ECC correction | Not performed; spare areas are only removed |

## Verification

On 2026-10-12 (macOS AArch64, rustc 1.100.0-nightly), `tests/transforms.rs`
(9 tests) passed. Its fixtures are AArch64 and RISC-V machine code compiled
from a synthetic C file ([provenance](../tests/fixtures/transforms/README.md)).
Manual checks with the same C file compiled for other targets:

- 16-bit swaps of AArch64 and RISC-V code were recovered;
- even/odd splits of AArch64, RISC-V, MIPS and PowerPC code were recovered;
- spare-laden x86-64, RISC-V, MIPS, AArch64 and PowerPC code classified
  without a transform, since 3% spare bytes do not make the code
  inconclusive.
