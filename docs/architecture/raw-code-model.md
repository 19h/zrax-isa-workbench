# Raw-code ISA identification

How `zrax` recognises the instruction set of data that has no
container header (raw firmware, memory dumps, extracted sections), how the
model is built, and how it is measured.

Code: `src/heuristics/mod.rs` (engine), `src/heuristics/model.rs` (model),
`scripts/build_corpus.py` (ground truth), `examples/train_model.rs`,
`examples/eval.rs`, `examples/calibrate.rs`, `examples/scan_debug.rs`.

## Why not hand-written scorers

The previous engine had ~45 hand-written scorers (`src/architectures/*.rs`,
~40k lines) that each summed ad-hoc points for byte patterns and subtracted
points for other ISAs' patterns; the ISA with the largest raw sum won and
"confidence" was its share of all positive points. Measured on held-out data
this could not work:

* **Scores measured length, not evidence.** 64 KB of random bytes scored
  48k (MIPS64), 40k (ARM, RISC-V), 34k (MSP430). Whoever had the highest noise
  slope won on non-code data: 71% of non-code inputs (text, media, tables,
  real `.rodata`) were confidently labelled as some ISA.
* **Weights pointed the wrong way.** Many of the heaviest-weighted patterns are
  *more* frequent in random bytes than in the ISA's own code (e.g. AVR `CPI`,
  `RCALL`; MSP430 SP/CG operands; SH `BRA`/`BSR`).
* **Encodings were wrong.** V850 decoded every field from the wrong bits,
  Alpha penalised its own loads/stores (22% of real instructions), IA-64 had
  the NOP encodings wrong, the i860 opcode map was invented, ARC read 32-bit
  instructions in the wrong halfword order, …
* **Cross-ISA penalties hit their own ISA.** Every scorer carried copies of
  other ISAs' "signatures" with 2–7-bit masks; on real code they multiplied
  TriCore, SH, V850, RL78, C166, HCS12 and Xtensa scores by 1e-2…1e-5.
  TriCore, ARC, C-SKY, PA-RISC, m68k, SH, Xtensa, V850, C166, HCS12 and C6000
  were 0% on real code; the testbins suite only passed because those files
  were ELF objects classified by their header.
* **Two scorers had infinite loops** (PPC VLE, FR30) that hung the CLI on
  ~1.6% of random 64 KB chunks and on 436 of the 800 synthetic firmware images
  in `--multi-isa` mode.
* **Calibration by special case.** A RISC-V→C6000 override for one file, fixed
  damping factors for four "confuser" ISAs, a CFF-container special case, a
  "variant family boost" to undo the damage the SPARC/SPARC64 score tie did to
  the margin, etc.

## Model

A **class** is one ISA encoding variant (e.g. `mips64el`, `thumb`, `sheb`) or
one kind of non-code data (`neg_rodata`, `neg_text`, `neg_media`,
`neg_table`). Each class is a first-order Markov model over bytes,
`P(b[t] | b[t-1])`, stored as a 256×256 table of costs in half-bits:

```
P(b | a) = (n(a,b) + α·P(b)) / (n(a) + α),   α = 16
cost(a,b) = round(2 · min(-log2 P(b|a), 10))
```

* Rare contexts back off to the class's own byte distribution.
* The 10-bit cap keeps one unseen byte pair from outweighing a window of
  evidence (measured: caps of 8/10/12/16 bits give 98.1/99.2/98.6/98.2% of
  held-out files correct).
* Half-bit resolution is indistinguishable from 1/16 bit on held-out data and
  compresses to ~1.7 MB with gzip for 94 classes (relevant for the WASM build).

The uniform distribution (8 bits/byte) is an implicit extra data class, so
compressed/encrypted data is never code.

## Scanning

1. The input is tiled into 1 KB windows (inputs ≤ 2 KB are one window).
   Windows dominated (≥ 90%) by one byte value are **padding**; windows that
   are ≥ 90% printable ASCII are **text** (real code: p99 < 0.8 for every ISA).
   With a scan budget (`max_scan_bytes`, 1 MB by default), the budget is spread
   evenly over the *non-padding* windows, so an 8 MB image with a few KB of code
   in it is not sampled into nothing but erased flash.
2. Every other window is scored against every class (sum of pair costs).
3. If a data class (or uniform) is cheapest, the window is **data**.
   Otherwise the cheapest code class wins the window if its margin over the
   cheapest class of *any other family* (data included) is at least
   0.4 bits/byte; if not, the window is **ambiguous**. Families group variants
   of one ISA (MIPS32/64, both endiannesses, microMIPS) so sibling variants never
   erode confidence in the ISA itself.

## Decision and confidence

* **Primary family** = the family with the most calibrated evidence.
* **Variant** = within that family, the class with the lowest total cost over
  the family's windows (this is where 32/64-bit, endianness and A32/Thumb are
  decided).
* **Confidence** = family share × strength:
  * each code window has a weight `w = sqrt(min(1, len/1KB)) · σ((m − 0.6)/0.15)`
    in its margin `m`;
  * windows with `m ≥ 1.0` are *strong*: across 6,724 held-out non-code windows,
    false alarms never exceeded a margin of 0.72;
  * weak windows are discounted by 0.05 per non-padding window scanned, so a
    few weak hits in a large data blob cancel out, while a small function on
    its own still passes;
  * evidence `E` maps to `1 − exp(−E / 0.5)`; one clean 1 KB window gives ≈ 0.86.

Results below `min_confidence` (0.3 by default) are `HeuristicInconclusive`.

**Multi-ISA** (`--multi-isa`) uses the same windows and the same evidence,
tiling the whole input: every family with net evidence ≥ 0.35 that owns ≥ 2%
of the code bytes is reported.

## Ground truth

`scripts/build_corpus.py` assembles labelled code from:

| source | what | truth from |
|---|---|---|
| ISAdetect (`../data/new_new_dataset/ds2`) | ~400 real Debian binaries per arch, 23 arches | Debian arch |
| armgen `objects/`, `objects-fresh/` | compiler output of the armgen programs | oracle family / `e_machine` |
| LLVM matrix (`--gen`) | `armgen/programs{,2}` × 39 target configs × O0–O3/Os (`scripts/compile_llvm_matrix.sh`) | target config |
| GCC matrix (`--gen`) | same programs, 22 GCC 16 cross compilers for embedded ISAs (`scripts/gcc_matrix/`) | target config, checked against the object's `e_machine`/byte order |
| idaref, radare2 testbins | ELF/PE code sections; a few curated raw dumps | `e_machine` / PE machine / provenance |
| SDCC/cc65 matrix (`--gen corpus_extra/sdcc-objects`) | the armgen programs linked with SDCC 4.6 / cc65 2.19, plus every module of their runtime libraries: 8051/DS390, HC08/S08, Z80/Z180/eZ80 (Z80 mode)/R800, SM83, STM8, 6502/65C02, PIC14, PIC18 (`scripts/sdcc_matrix/`) | target config |
| GCC PDP-11 and CR16 | GCC 16 `pdp11-aout` (`.text` as raw `.bin`) and GCC 11.5 `cr16-elf` (the port is gone from GCC 12) | target config |
| IDA kernel test inputs (`corpus_extra/raw-ida`) | instruction bytes of raw dumps in `ida/tests/input`, cut out with IDA's reference listings (`scripts/ida_listing_code.py`, `scripts/ida_test_corpus.py`): MCS-96, R32C, ST20, OakDSP, PIC24, eZ80, TLCS-900, MN10200, C3x, cLEMENCy, ... | IDA processor module |
| independent real code (`corpus_extra/raw-ext`) | ~80 programs for 22 rare ISAs from open sources (monitors, BASIC/Forth, homebrew, vendor examples, revived GCC ports), one row per file in `raw-ext/PROVENANCE.md` | provenance |

Samples are *code sections only* (ELF `SHF_EXECINSTR`, PE code sections),
with linker stubs (`.plt`, `.got`, `.init`, …) dropped, runs of ≥ 64 identical
bytes removed, 256-byte blocks that are > 85% printable removed (string
tables), and text-listing / fill-dominated raw dumps rejected. Exact duplicates
are dropped. Negatives are real `.rodata`/`.data` from Debian binaries, source
text (and UTF-16), fonts, images, sounds, and synthetic numeric tables.

Some classes are derived rather than compiled. Big-endian RX (`rxeb`)
fetches code as big-endian 32-bit words but decodes instructions in
little-endian byte order. Linked big-endian images and ROM dumps therefore
store code with every 32-bit word byte-reversed (binutils
`bfd/elf32-rx.c`, `rx_get_section_contents`); relocatable objects are not
swapped. `WORD_SWAPPED` in `build_corpus.py` adds every `rx` sample to
`rxeb` with its words reversed, in the same group. Word-addressed DSPs are
handled the same way: DSP56000 (24-bit), DSP56100 (16-bit) and TMS320C3x
(32-bit) words appear in either byte order depending on the ROM interface or
converter, so those samples are stored little-endian and the big-endian
classes (`dsp56keb`, `dsp56100eb`, `tic3xeb`) are derived. The swap happens
before padding/text removal, which would otherwise shift the word phase.

The train/test split is by **program** (or by file where there is no program
identity), so no program is on both sides.

`examples/train_model.rs` caps each (class, source) at 1 MB so no single
toolchain dominates a class. Without the cap, LLVM-built MIPS32 fits the
LLVM-heavy MIPS64 model better than the GCC-heavy MIPS32 one.

## Measuring

The compiled corpora and the extra raw samples are kept in `corpus_extra/`
(see its README for the exact command).

```sh
python3 scripts/build_corpus.py --out $CORPUS --gen $LLVM_OUT --gen $GCC_OUT [--raw CLASS=GLOB ...]
cargo run --release --example train_model -- --corpus $CORPUS --split train --out /tmp/m.bin
cargo run --release --example eval -- --corpus $CORPUS --model /tmp/m.bin      # held-out
cargo run --release --example eval -- --firmware /path/to/armgen/firmware --model /tmp/m.bin
cargo run --release --example train_model -- --corpus $CORPUS                  # ship: all data
```

`examples/eval.rs` reports, per class and overall, what a user gets at the
default threshold: correct / wrong / rejected for code, false accepts for
non-code, for whole samples and for 128 B / 512 B / 2 KB snippets.
`examples/scan_debug.rs FILE` shows the per-window verdicts and best classes.

### Results (held-out test split, model trained on the train split)

94 classes (90 ISA variants of 63 ISA families, plus 4 data classes); 14.2k held-out code samples, 395 non-code samples.

| input | correct | wrong | rejected | non-code false accept |
|---|---|---|---|---|
| whole sample | 99.5% | 0.0% | 0.5% | 0.5% |
| 2 KB snippet | 98.9% | 0.0% | 1.1% | 0.0% |
| 512 B snippet | 98.7% | 0.0% | 1.3% | 0.3% |
| 128 B snippet | 94.1% | 0.0% | 5.8% | 0.0% |

Macro average over classes (whole samples): 97.7%. Exact variant (bitwidth and
endianness right as well): 99.0%. The macro average is lower than before the
8/16-bit classes were added because several of them have only one to three
held-out samples (pieces of a single image), e.g. MCS-96 and ST20 at 1/2.

A class that attracts non-code is worse than a missing class: TI PRU (GCC
output only) took 14 of 19 false-alarm windows on real `.rodata`, with margins
up to 1.5 bits/byte, so `train_model` leaves it out by default. TriMedia
(one program, the tmlinux kernel) accepted a real `.rodata` file with a
0.87 bits/byte window margin and is left out as well; TriMedia objects are
identified from their TMObj header. Without them the largest false-alarm
margin on held-out non-code is 0.73 (9 of 6,951 windows, 5 of them Z80
family), below the 1.0 strong-window threshold. Re-check this
(`examples/calibrate.rs`) whenever a class is added.

Old engine on the same held-out samples (it covers fewer ISAs): 79.0% correct
/ 11.1% wrong / 9.8% rejected for whole samples, 54.6% / 29.4% / 16.0% for
512 B snippets, and 71% false accepts on non-code.

Synthetic multi-ISA firmware (`armgen/firmware`, 800 images): exact ISA set
96.6%, per-family precision 99.9%, recall 97.1%. The old engine: 21.8% / 74.5%
/ 35.8%, and 436 of the 800 images hung.

IDA reference corpus (`tests/idaref.rs`, mostly containers): 90.5% correct,
0.3% wrong (precision 99.7%), the rest inconclusive (compressed kernelcaches,
text listings, tiny snippets, formats we do not parse). On IDA's full
`tests/input` (`IDAREF_DIR`, 4,587 files, every processor in it now has an
`Isa` variant): 87.6% correct, 0.3% wrong. For the rare ISAs these numbers
are fit, not generalisation: their raw test dumps are part of the training
data (`raw-ida`); see the cross-source results below for how well unseen code
is recognised.

### Rare 8/16-bit ISAs and DSPs

For most of these there is no compiler, only a handful of real programs, and
some of them are also the evaluation files. Two cross-source runs show what to
expect on code from a source the model has not seen (whole samples):

| trained without | tested on | samples | correct | wrong | rejected |
|---|---|---|---|---|---|
| `raw-ext` (independent code) | `raw-ext` | 30 | 76.7% | 3.3% | 20.0% |
| `raw-ida` (IDA test dumps) | `raw-ida` | 41 | 53.7% | 0.0% | 46.3% |

Wrong answers stay rare (one 8051 program read as C3x); the failure mode is
rejection. Byte bigrams of dense 8-bit opcode maps depend on coding style:
the SDCC-trained Z80 class costs about 8 bits/byte on the hand-written Pac-Man
ROM, as much as random data, and a class trained on iC-96-compiled MCS-96
code does not recognise Ford EEC code. The shipped model is trained on
compiler output and on every real source, which covers more styles, but for
classes backed by one or two programs (MCS-96, ST20, OakDSP, PIC24, R32C,
TLCS-900, MN10200, C3x, eZ80, cLEMENCy) expect rejections on code written
differently.

Left out of the model for lack of ground truth (< 48 KB of code), identified
from containers only: Philips XA (47 KB), 68HC05 (34 KB; the 68HC08 class
accepts 68HC05 code), DSP56100 (23 KB), MELPS 7700/7900 (20 KB; reported as
the 6502 family, which it derives from), ST7, unSP, KR1878, H8/500, DSP96000,
SPC700 (`.spc` files are identified by header). MELPS 740 and Rockwell C39
are 6502 supersets and are reported as 6502.

Known confusion: 12-bit baseline PIC code (PIC10/12/16C5x) has no class and
reads as cLEMENCy (`pic12Cxx.hex`).

Caveat: for ISAs whose ground truth comes only from the GCC matrix (V850,
RL78, RX, FR30, C6000, M32R, M16C, NDS32, PRU, FR-V, H8/300, Blackfin,
MicroBlaze, OpenRISC, big-endian Xtensa), the held-out samples are other
programs from the same compiler; vendor toolchains (Green Hills, TASKING,
IAR, CC-RL, ...) generate somewhat different code. Real-world samples of
those ISAs are the most valuable thing to add to the corpus. For example, the
1 KB windows of a 2 MB big-endian CC-RX firmware image (not in the corpus)
cost a median 7.2 bits/byte under `rxeb`, against 6.0 for held-out GCC code.
It is still detected (0.99, big-endian), but only 65% of its windows are
called code.

## Adding an ISA

1. Add a class to `CLASSES` in `src/heuristics/model.rs` (ISA, endianness,
   bitwidth, family, optional variant).
2. Get ground-truth code: compile the armgen programs with a cross compiler
   into `<gen>/<class>/<config>/<set>__<program>.o` (or `.bin` with the code
   already extracted, for toolchains without ELF output), or map its
   `e_machine` in `scripts/build_corpus.py`, or add raw dumps with
   `--raw class=glob`. Raw dumps must be code only: when IDA has a listing of
   the dump, `scripts/ida_listing_code.py` extracts its instruction bytes.
   ≥ 48 KB of clean code is the minimum the trainer accepts; a few hundred KB
   from more than one program is what makes a class reliable.
3. Rebuild the corpus, train on the train split, run `eval` and check the new
   class *and* the false-accept column, then train on all data.

ISAs without enough ground truth are left out of the model rather than
guessed at. Container formats still identify them from their headers.
