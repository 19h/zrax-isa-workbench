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
| 16-bit byte swap | at least 2 B | Swap the bytes of every 16-bit word; a trailing odd byte stays as it is |
| 32-bit byte swap | at least 4 B | Reverse the bytes of every 32-bit word; trailing bytes short of a word stay as they are |
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

The `k`-fold allowance is not loose. Over 7,244 negative samples of the
training corpora (data segments, MAME data ROMs, tables, media), the most
weak-window weight any single family gathers in any applicable reading, per
informative window, is 0.35 at the 99th percentile, 0.67 at the 99.9th and
0.76 at most; samples of 50 informative windows or more still reach 0.61
(fw1 audit, 2026-11-04). The allowance is 0.05 per window and reading. A
byte-swapped Neo-Geo system ROM (`vs-bios.rom`) whose 68000 windows were all
weak (0.12 per informative window) therefore stayed inconclusive. The fix was
better 68000 evidence (hand-written 68000 training code), not a smaller
allowance: with it the swapped reading has 26 68000 windows, one of them
strong (20, none strong, before), and reads as 68000 at 0.85.

The penalty keeps noise inconclusive, but structured input that the model
cannot place raw (code of an unmodelled ISA extension, file headers) can
still resemble some class after a rearrangement. A transformed reading is
therefore accepted only when:

- its confidence is at least 0.8 (`MIN_TRANSFORM_CONFIDENCE`): 99.4% of the
  fw1 golden code files, scored with the trial penalty, decide at 0.8 or
  above (2026-11-03), while the readings that won on IDA's test corpus
  without a bar were at 0.6 or bytecode;
- the decided family explains at least 14% of the non-padding bytes scanned
  as code (`MIN_TRANSFORM_CODE_SHARE`): reordered code is code throughout
  (the 1st percentile of fw1 golden code files is 0.44), while
  lane-interleaved calibration maps, Wi-Fi board data and Qualcomm data
  segments reached the confidence bar on a few strong windows at a share of
  0.01 to 0.12. A program ROM can hold much data besides its code: the
  byte-swapped program ROMs of a Yamaha MU100 (H8S) and VL70-m (H8 with
  Hitachi's HI8 kernel), which carry voice tables, read as H8/300 at 0.99
  and 0.97 with shares of 0.21 and 0.15, and among the fw1 files whose stored
  reading is inconclusive no other transformed reading at 0.8 or more has a
  share from 0.12 to 0.25 (2026-11-04), so the bar is 0.14, down from 0.25;
- an interleave never names a CPU that runs only from on-chip program
  memory (PIC, AVR): no ROM of theirs is one byte lane of a wider bus, and
  an 8-bit PCM ROM read as PIC14 at 0.99 after a 2-lane interleave (fw1,
  2026-11-04);
- it names an ISA that a memory dump can hold: JVM, Dalvik, WebAssembly,
  CLR, EBC and BPF bytecode live in files, and their weak byte statistics
  matched rearranged structured data;
- for a byte swap or lane interleave, it names a CPU that fetches from a
  16- or 32-bit memory bus (`BYTE_BUS_ISAS` lists the exceptions: Z80,
  8080/8085, 8051, 6502/65816, 6800/6809, 68HC05/08/11, MELPS 740, C39, Z8,
  ST7, STM8, SPC700). Those transforms undo how a wide bus stores words, and
  a byte-wide program memory is never stored that way; ECU calibration maps
  read as Z80 or 8080 code at 0.99 after a 2-lane interleave without this
  check (fw1 audit, 2026-11-04). NAND spare removal applies to any ISA.

A lane interleave is not even tried unless its lanes agree
(`Transform::lanes_agree`): every lane of a split memory holds one byte of
each bus word, so all lanes carry content in the same places. In 512-byte
lane windows (content: no byte value covers nine tenths), every lane must
hold content in at least half of the windows where any lane does. Four 25 KiB
Qualcomm data segments whose first half is zero fill read as ARM at 0.99
after a 2-lane interleave before this check (fw1 audit, 2026-11-04).

A byte swap applies to any input of at least one word and keeps a trailing
partial word as it is: a dump can carry a byte past its last word. A
byte-swapped BMW 68000 ECU dump with one appended byte had no swap reading
before; it reads as 68000 at 0.99 (fw1 audit, 2026-11-04,
`byte_swaps_keep_a_trailing_partial_word`).

`examples/reading_share.rs` prints every reading of a file with its
confidence and code share, so a rejected reading can be traced to the bar
it missed.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| T1 | A transform is applied only when the stored order is inconclusive | Code in execution order never gets a `transform_applied` entry (`fixtures_classify_in_execution_order`) |
| T2 | The union-bound penalty keeps noise inconclusive | Deterministic noise of several sizes, including NAND-shaped lengths, stays inconclusive (`noise_stays_inconclusive_after_every_transform`) |
| T3 | A genuine transformed reading is decisive (confidence at least 0.8), explains at least 14% of the input as code, and is native code | On 2026-10-13, IDA's test corpus (`tests/input`, 7,327 files) had two files decided only by a transform, both wrong (`mipsb_mips3d.bin` as ST20 at 0.60 after a 16-bit swap, `pc_bad_nimports.lx` as JVM at 0.98 after a 4-lane interleave); with the rule both are inconclusive again, and the transform tests still recover every scrambled fixture. In the fw1 audit (2026-11-03), lane-interleaved readings of calibration maps, board data and Qualcomm data segments reached 0.9 or more at a code share of 0.01 to 0.12; the code-share rule rejects them (`a_transformed_reading_must_explain_most_of_the_input`) |
| T5 | Byte swaps and lane interleaves only restore code of CPUs with a 16- or 32-bit program bus | Calibration maps whose interleaved reading looks like Z80 or 8080 code stay inconclusive (fw1 full run, 2026-11-04: 138 of 138) |
| T4 | The lanes of a genuine split hold content in the same places | A file whose first half is fill and second half data is not interleaved (`lanes_agree_only_when_every_lane_holds_content_where_the_others_do`); split AArch64 and RISC-V fixtures still are (`split_lane_dumps_are_interleaved`) |
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

On 2026-11-04 (macOS AArch64), `tests/transforms.rs` (13 tests) passed,
including the code-share rule, the single-window rule for large inputs
(`one_code_window_does_not_classify_a_large_input`), sparse code with strong
evidence (`sparse_code_with_strong_evidence_classifies_a_large_image`) and
recovered code (`recovered_code_is_code_throughout`), and the lane-agreement
unit test in `src/transform.rs` passed. IDA's test corpus was not re-run
after the bar moved from 0.9 to 0.8. On 2026-10-12 (macOS AArch64, rustc
1.100.0-nightly), the 9 tests of that date passed. Its fixtures are AArch64 and RISC-V machine code compiled
from a synthetic C file ([provenance](../tests/fixtures/transforms/README.md)).
Manual checks with the same C file compiled for other targets:

- 16-bit swaps of AArch64 and RISC-V code were recovered;
- even/odd splits of AArch64, RISC-V, MIPS and PowerPC code were recovered;
- spare-laden x86-64, RISC-V, MIPS, AArch64 and PowerPC code classified
  without a transform, since 3% spare bytes do not make the code
  inconclusive.
