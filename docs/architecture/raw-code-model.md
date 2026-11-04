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
`neg_table`, `neg_pixels`). Two byte distributions that one table cannot hold
get two classes of the same family and variant: hand-written mid-range PIC
code (`pic14asm`) next to the SDCC-trained `pic14` (a PIC12C671 program costs
7.31 bits/byte under one table of both, 5.94 under hand-written code alone),
and uncompressed pixels and tile graphics (`neg_pixels`) next to `neg_media`
(as part of `neg_media`, 6 of 11 held-out synthetic images were still read as
code at 0.95 or more). Each class is a first-order Markov model over bytes,
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
  compresses to ~1.9 MB with gzip for 102 classes (relevant for the WASM build).

The uniform distribution (8 bits/byte) is an implicit extra data class, so
compressed/encrypted data is never code.

## Scanning

1. The input is tiled into 1 KB windows (inputs ≤ 2 KB are one window).
   A window is **padding** when one byte value covers ≥ 90% of it, when one
   aligned 16- or 32-bit word covers ≥ 70% of its words (erased 14-bit PIC
   words `0x3FFF`, tables of one pointer, 16-bit bitmaps that are mostly
   background colour), or when it has fewer than 16 distinct adjacent byte
   pairs (flat image areas; 0.08% of the corpus's 827,023 non-fill code
   windows, while the median uncompressed-image window has 6). The 70% word
   bar: sprite windows of an SPG2xx game ROM measure 0.77 to 0.83 and were
   read as x86 at 0.99, while 4 of 44,472 code windows of the shipped corpus
   (30 samples per class) reach 0.7 (2026-11-04). Windows that are ≥ 90% printable ASCII are **text** (real code:
   p99 < 0.8 for every ISA).
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

* **Primary family** = the family with the most window weight (strong and
  weak windows, see below), before the false-alarm allowance. The allowance
  is the same for every family, so it decides whether the evidence is above
  chance (the confidence), not whose evidence is largest; ranking after it,
  where it clamps weak evidence to zero, let one strong window of another
  family outrank many weak windows of one family. On the fw1 raw files
  (2026-11-04) the change moved four answers: two Sega SH-4 boot ROMs from
  ARM to SH, and two Thumb firmware images read as PowerPC to Arm and to
  inconclusive; an interleaved 68000 program read as MIPS64 at 0.85 became
  inconclusive.
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

Results below `min_confidence` (0.3 by default) are `HeuristicInconclusive`;
rejections by the window-count rules below are `HeuristicSparseCode`, whose
message gives the decided family's code windows and the informative windows
(earlier the same rejections reported a false "confidence below threshold").

Three rules bound what the evidence may claim:

* **One window is not an image.** In an input with at least 8 informative
  (non-padding) windows, the decided family needs at least two code windows
  (`MIN_CODE_WINDOWS`, `LARGE_INPUT_WINDOWS`); otherwise the result is
  inconclusive. One strong 1 KiB window reaches 0.86 on its own. In the fw1
  set (2026-11-04), 66 raw files of at least 32 windows were decided by one
  window, 34 of them ECU calibration maps; golden code files decided by one
  window have at most 6 informative windows, Qualcomm data segments accepted
  on one pointer-table window 8 to 11. Smaller inputs, where one window is
  most of the input, are unaffected.
* **Sparse code needs strong evidence.** With fewer than one code window per
  64 informative windows, the decision needs 0.9 confidence
  (`SPARSE_CODE_RATIO`, `SPARSE_MIN_CONFIDENCE`): chance strong windows grow
  with the input. Of 40 such fw1 answers (2026-11-04), the wrong ones (camera,
  toy and Qualcomm images as MN10300, PIC, C-SKY or FR30) were at 0.84 to
  0.86, while firmware updates with a small uncompressed code part (SH,
  Alpha, x86-64, MIPS) were at 0.98 to 0.99. The ratio was 128
  until a byte lane of Namco System 21 DSP data read as µ'nSP at 0.86 from 2
  of 240 windows; at 64 it also catches five byte-swapped 68000 ECU dumps
  read as 68000 at 0.85 from 2 or 3 windows, four of which the byte-swap
  reading then recovers at 0.99 (the fifth has an odd length, which no swap
  applies to).
* **Superset variants need clearly more evidence.** Z80 code is also valid
  eZ80 code, so a Z80 image fits both classes. The eZ80 variant is reported
  only when its evidence over the family's windows is at least 1.75 times the
  Z80 class's (`SUPERSET_VARIANTS`, `SUPERSET_EVIDENCE_RATIO`); TI-84 CE eZ80
  code measures 2.0 to 2.6, Z80 ROMs that had chosen eZ80 1.0 to 1.5. Before
  the rule, 408 fw1 Z80 ROMs were reported as eZ80.
* **Z80 needs Z80 instructions.** 8080 code is also Z80 code, so the Z80
  family holds an `i8085` class, and the superset chain eZ80 > Z80 > 8080/8085
  reduces a Z80 answer to 8080/8085 unless the Z80 evidence is at least 1.75
  times the 8080/8085 evidence. An 8080/8085 answer becomes Z80 when a linear
  Z80 decode of the family's code windows (`heuristics/z80.rs`, from the Z80
  User Manual's opcode tables) finds more than 0.2% prefix-group instructions
  (`CB`, `ED`, `DD`/`FD` with a second byte that continues a defined Z80
  instruction). Relative jumps, `DJNZ` and `EXX` are not evidence: the 8085
  executes instructions at every one of those opcodes (`RIM`, `SIM` and the
  undocumented `DSUB`, `ARHL`, `RDEL`, `LDHI`, `LDSI`, `SHLX`), and 8085 ROMs
  use them (the Toshiba T200 boot ROM holds 47 `RDEL`s). On the fw1 program
  ROMs whose MAME driver names the CPU (2026-11-04), the 21 8080/8085 ROMs
  hold 0 to 0.06% prefix-group instructions, the Z80 ROMs the model read as
  8080/8085 0.4% to 30%; Z80 to 8080/8085 evidence is 0.41 to 1.0 for the
  8080/8085 ROMs and 0.75 to 8.8 for the Z80 ROMs.
* **65816 needs native-mode instructions.** The model has no 65816 class:
  65816 code reads as 6502 code, which its emulation mode runs. A 6502 answer
  becomes WDC 65816 when a linear decode of the family's code windows
  (`heuristics/w65816.rs`, 8-bit register lengths) finds at least 8 `REP`/`SEP`
  of the register-width flags or `XCE` after `CLC`/`SEC`, and at least one per
  thousand instructions. On the NMOS 6502 these opcodes are undocumented
  NOPs or `ISC`, on the 65C02 NOPs. On fw1 (whole files, 2026-11-04), 6502
  ROMs whose MAME driver names the CPU and the 6502 training samples hold 0
  to 3 (at most 0.36 per thousand); the two W65C816 ROMs of MAME's `we816`,
  the CMD SuperCPU ROM, three SNES copier BIOS ROMs and an Apple II SCSI card
  ROM that enters native mode hold 42 to 168 (2.7 to 35.7 per thousand).

A transformed reading (byte swap, lane interleave, NAND spare removal) must
also reach 0.8 confidence and explain at least 14% of the input as code; a
lane interleave is tried only when its lanes hold content in the same places;
a byte swap or interleave never names a CPU with a byte-wide program bus
(Z80, 8080/8085, 8051, 6502, 6800, ...), and an interleave never names a CPU
that runs only from on-chip program memory (PIC, AVR)
([raw-dump transforms](../transforms.md#false-accepts)).

Two structural rules use the code model's evidence without being part of
it:

* **A boot marker names the boot core.** A raw image that carries the
  architecture's own description of the core that starts it, and holds code
  of that core's family, is reported as that ISA, from those code windows,
  also when another core's code dominates the image; a note records the
  code model's own reading. Two markers are implemented: a Cortex-M vector
  table at offset 0 (ARMv7-M ARM, DDI 0403E, B1.5.3: initial stack pointer
  in the code or SRAM region, Thumb-bit reset vector, at least three set
  exception vectors, all Thumb-bit and within 16 MiB of the reset handler)
  names Arm; an x86 reset vector (a power-of-two image of at least 64 KiB
  whose last 16 bytes start with a far jump into segment `F000`, where the
  real-mode reset at `0xFFFF0` lands) names x86. In the fw1 set
  (2026-11-04), 1,042 raw files start with such a vector table, 1,039 of
  which already read as Arm, and 15 end with such a reset vector, 13 of which
  already read as x86. The rule changes the three `faceauth` images (RISC-V
  and Thumb code; Arm boot core) and two Asus laptop BIOS images that also
  hold 8051 embedded-controller firmware (x86 boot core).
* **An ELF header contradicted by its code names no ISA.** When the code
  model reads an ELF's instructions (sections with `SHF_EXECINSTR`, else
  executable `PT_LOAD` segments, else all loadable segments) as another ISA
  family at 0.9 or more, with at least half of the bytes as code, and the
  header's ISA has a model class, the ISA is not identified and a note names
  both readings, as for a layout with two valid interpretations. On 1,380
  ISAdetect Debian ELFs (60 per architecture) the rule changes nothing; in
  fw1 it changes 43 files: 8 Qualcomm Cortex-M images (7 `m3.bin`,
  `wpss.b06`) declaring `EM_386`, 8 modem images declaring `EM_ARM` around
  Hexagon code, and 27 NFC firmware libraries declaring `EM_AARCH64` whose
  only content is 32-bit Arm firmware in `.data`.

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
| GCC matrix (`--gen`) | same programs, 23 GCC 16 cross compilers for embedded ISAs (`scripts/gcc_matrix/`; MN10300 added 2026-11-04 with `-mam33`, `-mam33-2`, `-mam34`) | target config, checked against the object's `e_machine`/byte order |
| idaref, radare2 testbins | ELF/PE code sections; a few curated raw dumps | `e_machine` / PE machine / provenance |
| SDCC/cc65 matrix (`--gen corpus_extra/sdcc-objects`) | the armgen programs linked with SDCC 4.6 / cc65 2.19, plus every module of their runtime libraries: 8051/DS390, HC08/S08, Z80/Z180/eZ80 (Z80 mode)/R800, SM83, STM8, 6502/65C02, PIC14, PIC18 (`scripts/sdcc_matrix/`) | target config |
| GCC PDP-11 and CR16 | GCC 16 `pdp11-aout` (`.text` as raw `.bin`) and GCC 11.5 `cr16-elf` (the port is gone from GCC 12) | target config |
| IDA kernel test inputs (`corpus_extra/raw-ida`) | instruction bytes of raw dumps in `ida/tests/input`, cut out with IDA's reference listings (`scripts/ida_listing_code.py`, `scripts/ida_test_corpus.py`): MCS-96, R32C, ST20, OakDSP, PIC24, eZ80, TLCS-900, MN10200, C3x, cLEMENCy, ... | IDA processor module |
| independent real code (`corpus_extra/raw-ext`) | ~80 programs for 22 rare ISAs from open sources (monitors, BASIC/Forth, homebrew, vendor examples, revived GCC ports), one row per file in `raw-ext/PROVENANCE.md` | provenance |
| Qualcomm Hexagon DSP binaries (`--elf GLOB`, `../data/hexagon-dsp-binaries`) | `.so` libraries and `fastrpc_shell` images: executable sections as code, non-executable `PROGBITS` sections as `neg_rodata` | `e_machine` |
| DOS load modules | the load module of plain MZ executables (no NE/LE/LX/PE header) in idaref and the radare2 testbins | `x86_16` (MZ header) |
| hand-written mid-range PIC (`corpus_extra/raw-ext/pic14asm`) | 195 public GitHub repositories of PIC12F/PIC16F assembly at pinned commits, assembled with gpasm/gplink 1.5.2, program-memory words only (`scripts/pic14_asm_corpus.py`); 39 licensed, 156 without a license file (weak) | `pic14asm` by assembly |
| Intel 8080/8085 code (`corpus_extra/raw-ext/i8085`) | 107 public GitHub repositories of 8080/8085 assembly (monitors, CP/M BIOSes, Kermit, Altair and course programs) at pinned commits, assembled with AS 1.42 in 8085 mode, instruction lines only (`scripts/asl_asm_corpus.py --profile 8085`) | `i8085` by assembly |
| Motorola 68HC11 code (`corpus_extra/raw-ext/hc11`) | 12 public GitHub repositories of 68HC11 assembly (the Buffalo monitor, Flex11, Holden VY ECU patches, course programs) at pinned commits, assembled with AS 1.42 as `6811` after rewriting full-line `*` comments, instruction lines only (`--profile 68hc11`); 27 KB, with the 23 KB IDA-test ECU dump 50 KB | `hc11` by assembly |
| Motorola 68000 code (`corpus_extra/raw-asm/m68k`, corpus `corpus-m68kx`) | 77 of 938 public GitHub repositories of 68000 assembly (Atari ST and Amiga programs, Mega Drive games and disassemblies of commercial games, monitors, course programs) at pinned commits, assembled with AS 1.42 for the 68000 after renaming asm68k/Devpac local labels, 68000 instruction lines only (`CPU Z80` stretches dropped; `--profile 68000`); 359 KB after run and text-block removal, under its own corpus source (`asl-68000`) so it does not share the 1 MB cap of `raw`. The other 68000 samples are compiled (Debian, GCC); before this the hand-written Neo-Geo system ROM read at 0.5 to 0.8 bits/byte margins | `m68k` by assembly |
| µ'nSP code (`fw1-mame-unsp` in `scripts/fw1/fw1_corpus.py`) | the instruction words of 9 fw1 ROMs that MAME maps flat into a µ'nSP SoC's program space (V.Smile and V.Smile Baby system ROMs, SPG2xx and GPL162xx game ROMs; 6 ROM families), found by recursive descent from the interrupt vectors, through `call` targets, and from untraced `push` words (`scripts/fw1/unsp_trace.py`, decoding after MAME's µ'nSP disassembler); 64 KiB blocks of the same ROMs without one traced instruction as `neg_media` (as `neg_rodata` they shifted that class: an ARM relocation table read as PIC24) | MAME's CPU for the ROM region; the trace |
| byte lanes (`scripts/fw1/lane_negatives.py`) | the 2 and 4 byte lanes of 68000 code samples, 2.3 MB: one file per lane of a wide bus holds no whole instruction | `neg_lanes` by construction |
| synthetic 8-bit PCM (`synthetic-pcm8`) | signed 8-bit decaying tone bursts at six amplitudes, near-silent to full scale, separated by silence, as haptic and ringtone files store them | `neg_media` by construction |
| synthetic tiles and pixels (`synthetic-tiles`, `synthetic-pixels`) | canvases of sprites, glyph cells and dithered backgrounds as 8x8 tiles (one bit plane, 2bpp, 4bpp planar and packed, 8bpp) and as RGB565 (both byte orders) and ARGB8888 frame buffers | `neg_pixels` by construction |
| synthetic weight tables (`synthetic-weights`) | normally distributed float32/float16 values at four scales, both byte orders | `neg_table` by construction |
| fw1 golden set (`scripts/fw1/fw1_corpus.py`) | 18,014 third-party firmware files, labelled only where the bytes prove it: ELF `e_machine`, Qualcomm PIL segment flags from the matching `.mdt`, PCM smoothness, 8051 and Cortex-M vector tables, ROM-family provenance, return-instruction density, code regions of other cores inside data segments, MAME's ROM region for dumps it lists by SHA-1 (see `scripts/fw1/README.md`) | evidence per file |
| transform-augmented negatives (`scripts/fw1/aug_neg.py`) | train-split calibration maps, 16-bit tables, GPU microcode and Qualcomm data segments under every reading the transform search tries | the source's data class |
| mined hard negatives (`examples/mine_hard.rs`) | windows that a held-out model calls code in train-split Qualcomm data segments and MAME data ROMs | the source's data class |

Samples are *code sections only* (ELF `SHF_EXECINSTR`, PE code sections),
with linker stubs (`.plt`, `.got`, `.init`, …) dropped, runs of ≥ 64 identical
bytes removed, 256-byte blocks that are > 85% printable removed (string
tables), and text-listing / fill-dominated raw dumps rejected. Exact duplicates
are dropped. Negatives are real `.rodata`/`.data` from Debian binaries, source
text (and UTF-16), fonts, images, sounds, and synthetic numeric tables.

ARM ELF code is labelled by the byte order of its instructions, not of the
file (`arm_class` in `build_corpus.py`): a BE-8 executable (`EF_ARM_BE8`)
stores big-endian data but little-endian instructions, so its code is `arm`
or `thumb`; big-endian relocatable objects and BE-32 executables store
big-endian instructions (`armeb`, `thumbeb`). A32 and T32 are told apart by
the condition nibble of each word, read in that byte order. Until
2026-11-04 the builder took the file's byte order and read the condition
from the little-endian position: seven BE-8 executables from idaref and the
radare2 testbins (846 KB of little-endian code) were in `armeb`/`thumbeb`,
and eleven big-endian A32 files in `thumbeb`. Little-endian Thumb-2 sections
of Debian `armhf` binaries then read as big-endian Arm (2 of 50 held-out
files, `elf_check.py`).

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
classes (`dsp56keb`, `dsp56100eb`, `tic3xeb`) are derived. µ'nSP dumps come
in both word orders too (MAME's `pokermor` dump traces as big-endian words,
the others as little-endian), so `unspeb` is derived from `unsp`. The swap
happens before padding/text removal, which would otherwise shift the word
phase.

The train/test split is by **program** (or by file where there is no program
identity), so no program is on both sides. fw1 samples are grouped by
firmware family, so versions of one image are on one side. Two sets are held
out of training entirely: ISAdetect files 400 to 549 of each architecture
(`--isadetect-skip 400 --isadetect-per-arch 150`, files already in the base
corpus dropped), and the PCI option ROMs and XT-IDE BIOS ROMs of fw1, which
test the `x86_16` class. As training data, the fonts and tables in option
ROMs taught that class to accept data (fw1 non-code false accepts 2.3% with
them, 0.8% without).

`examples/train_model.rs` caps each (class, source) at 1 MB so no single
toolchain dominates a class. Without the cap, LLVM-built MIPS32 fits the
LLVM-heavy MIPS64 model better than the GCC-heavy MIPS32 one.

## Measuring

The compiled corpora and the extra raw samples are kept in `corpus_extra/`
(see its README for the exact command). The shipped model is trained on that
base corpus plus the Hexagon ELF collection and the fw1 golden set; the
commands that rebuild it are in `scripts/fw1/README.md` ("Rebuild the
shipped model").

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

Measured on 2026-11-04 (macOS AArch64) with `ship21-train`, the shipped recipe
trained on the train split only: 97 classes (91 ISA variants of 61 families,
plus 6 data classes); the shipped all-splits model `ship21-all` has 102 (96
variants of 64 families), since five small classes reach the 48 KiB minimum
only with their test samples.

Base corpus (`corpus-base7`: the compiled and raw corpora, the Hexagon
collection, MN10300, hand-written PIC14, 8080/8085 and the synthetic
negatives): 14,526 held-out code samples, 464 non-code samples.

| input | correct | wrong | rejected | non-code false accept |
|---|---|---|---|---|
| whole sample | 99.3% | 0.0% | 0.7% | 0.2% |
| 2 KB snippet | 98.6% | 0.0% | 1.4% | 0.0% |
| 512 B snippet | 98.5% | 0.0% | 1.5% | 0.0% |
| 128 B snippet | 93.8% | 0.0% | 6.2% | 0.0% |

Macro average over classes (whole samples): 97.2%. Exact variant (bitwidth and
endianness right as well): 99.0% (98.9% with `ship19-train` on `corpus-base6`;
the corrected ARM labels make big-endian Arm and Thumb exact on all 179 and
106 held-out samples). Several 8/16-bit classes have only one to
three held-out samples (pieces of a single image), which keeps the macro
average below the overall rate. The one false accept is a synthetic
uncompressed image (1 of 25 held-out `neg_pixels` samples, read as IA-64).
On their held-out samples: `i8085` 13 of 14 (one rejected), `mn10300` 300 of
300, `pic14asm` 27 of 27, `z80` 252 of 252, `m68k` 297 of 300 (three
rejected; 298 without the hand-written 68000 samples) and the 18 held-out
hand-written 68000 samples of `corpus-m68kx` 15 (three rejected; 14 without
the class's hand-written training samples).

| held-out set | code samples | correct | exact | wrong | rejected | non-code | false accept |
|---|---|---|---|---|---|---|---|
| fw1 golden set, test split (`corpus-fw1v20`) | 975 | 99.0% | 98.9% | 0.0% | 1.0% | 536 | 0.9% |
| ISAdetect files 400-549 (`corpus-ds2h`) | 3,438 | 100.0% | 100.0% | 0.0% | 0.0% | 0 | - |

The fw1 false accepts are 5 of 300 held-out `.rodata`/`.data` samples (3
little-endian and 1 big-endian ARM, 1 CR16; iteration 12: 4). The two fw1 µ'nSP test samples (the
2.8 KiB traced from the asset ROM `29dl640e.u3`, in both word orders) are
rejected.

Through the CLI, file by file, on the 935 fw1 golden test files: 934 correct,
0 wrong, 1 rejected (`29dl640e.u3`). With `ship21-all`, on 1,150 ISAdetect files
no corpus uses (files 550-599 of each of the 23 architectures), the largest executable
section alone, as raw bytes, gives 1,149 right answers, 0 wrong and 1
rejection (a 556-byte section; `scripts/fw1/elf_check.py`); with the ARM
labels before the fix, two `armhf` Thumb-2 sections read as big-endian Arm. The iteration-12 model got 99.0% of the
924 test files of that time (8 wrong: Qualcomm data segments and two of the
held-out 8085 ROMs), a model of the base corpus alone 71.6%. The MAME
cross-validations are in `scripts/fw1/README.md`, with the per-label table,
the MAME CPU check and the full-corpus results.

A class that attracts non-code is worse than a missing class: TI PRU (GCC
output only) took 14 of 19 false-alarm windows on real `.rodata`, with margins
up to 1.5 bits/byte, so `train_model` leaves it out by default. TriMedia
(one program, the tmlinux kernel) accepted a real `.rodata` file with a
0.87 bits/byte window margin and is left out as well; TriMedia objects are
identified from their TMObj header. cLEMENCy (the DEF CON CTF architecture
with 9-bit bytes, no real firmware) is left out since 2026-11-04: its
near-uniform model won the data windows of 28 fw1 files (Sega NAOMI SH-4 BIOS
images, NIC and UEFI updates), all wrong; without it they classify as SH-4 or
stay inconclusive. Without them the largest false-alarm
margin on held-out non-code is 0.73 (9 of 6,951 windows, 5 of them Z80
family), below the 1.0 strong-window threshold. Re-check this
(`examples/calibrate.rs`) whenever a class is added.

Old engine on the held-out samples of the earlier base corpus (it covers fewer ISAs): 79.0% correct
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
TLCS-900, MN10200, C3x, eZ80) expect rejections on code written
differently.

Left out of the model for lack of ground truth (< 48 KB of code), identified
from containers only: Philips XA (47 KB), 68HC05 (34 KB; the 68HC08 class
accepts 68HC05 code), DSP56100 (23 KB), MELPS 7700/7900 (20 KB; reported as
the 6502 family, which it derives from), ST7, KR1878, H8/500, DSP96000,
SPC700 (`.spc` files are identified by header). MELPS 740 and Rockwell C39
are 6502 supersets and are reported as 6502; WDC 65816 code is reported as
65816 by the native-mode check, without a class of its own.

µ'nSP had no class until 2026-11-04: the open V.Smile homebrew sources hold
2,074 B of instructions, and a return-instruction test cannot separate code
from data in the commercial dumps. The class now comes from recursive
descent over MAME-listed dumps (`scripts/fw1/unsp_trace.py`): decoding
after MAME's µ'nSP disassembler, from the interrupt vectors through `call`
targets, plus functions that start with a `push`, stay in ROM and return,
found after traced code and at untraced `push` words. That rule keeps 8 of
6,097 worst-case seeds in non-µ'nSP data (58 words). The 68HC11 class
(50 KB) comes from AS-assembled open code and one IDA test dump; it is a
variant of the 6800 family, which it extends through the 6801, so the two
classes do not take each other's windows (as a family of its own it left
AMD GPU SMC and DMCU firmware, read as 6800 at 0.98 to 0.99 before, with
ambiguous windows only). The fw1 68HC11 ECU dumps `Punto75.mod`,
`MX5-3441.ORI` and `TI14CKYD.CAP` and the DMCU images read as 68HC11 at 0.99;
`500IEK.ORI` too, but it shares 6.1% of its bytes with the IDA test dump.

Known confusions:

- 12-bit baseline PIC code (PIC10/12/16C5x) has no class. Mid-range (14-bit)
  hand-written code is now recognized: `hop_leds_pic12c671.bin` (a PIC12C671,
  which has the 14-bit core) reads as PIC at 0.83, with no sample of it in
  training.
- The MN10300 class is trained on GCC output only (`-mam33`, `-mam33-2`,
  `-mam34`); the two decrypted Panasonic GH2 firmware images (14.9 MiB, not
  in training) read as MN10300 at 0.99.
- µ'nSP code that is a small part of an asset ROM is inconclusive: MAME's
  `pokermor` dump holds 2.8 KiB of traced code in 8 MiB of 16-bit sprites
  and audio.
- SH-4 code is reported as SuperH (`sh`); the model has no SH-4 class.
- MCS-96 ECU code from a Bosch M5.2.2 (`POSBOX.ORI`) is inconclusive: the
  class holds 106 KB, and the open 80C196 assembly found is in Intel ASM96
  syntax, which AS does not assemble.
- A code-share floor alone does not separate data from code: real code in fw1
  (NAOMI SH-4 BIOS images, an 8051 update image, firmware updates with a
  small uncompressed part) explains 6% or less of some inputs. The sparse-code
  rule therefore asks for strong evidence, not for a share.

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
