# nanoMIPS

zrax reports nanoMIPS code as the ISA `nanomips` (`nanoMIPS`, 32-bit,
little-endian code). Two paths name it:

- **ELF header.** `e_machine` 0xF9 (249, `EM_NANOMIPS`) maps to `nanomips`.
  Before 2026-11-06 it mapped to `mips`, and the MIPS `e_flags` layout then
  gave a `MIPS-I` variant that does not apply to nanoMIPS.
- **Code model.** The class `nanomips` holds function bytes of one MediaTek
  modem image. It classifies raw images, and checks that an ELF's loaded code
  agrees with its header like every other class.

zrax decodes no nanoMIPS instruction: there is no extension detection and no
instruction-level check.

## Identification

The samples are the user-submitted folder
`~/Downloads/firmwares-kenan/nanoMIPS` (third-party firmware, not in the
repository).

| Evidence | Where | What it shows |
| --- | --- | --- |
| `e_machine` 0xF9, ELF32 little-endian, `e_flags` 0x00001000, 475 program headers, 546 sections | `nanoMIPS-mt6833/TK_MD_PCB01_MT6833_S00.elf` | One machine number, read from the header |
| `elf32-littlenanomips` | The image's `.sym` file | The toolchain's name for the target |
| The ELF's largest load segment (`ROM`, 32,640,000 B) stored whole at offset 0x4000; 2 of the next 7 largest also whole, the 5 others (overlays at one address) not found | The image's `.bin` beside the ELF | The raw image holds the ELF's main code, not all of its segments |
| `#define EM_NANOMIPS 249 /* Wave Computing nanoMIPS */` | QEMU `include/elf.h` | The machine number |
| `decode_nanomips_32_48_opc`, `NM_P48I`, the `P16.RI` and `POOL16C` pools | QEMU `target/mips/tcg/nanomips_translate.c.inc` | Instructions of 16, 32 and 48 bits, in opcode pools of their own |

Whether the System V gABI registry lists the machine number was not checked.
QEMU's decoder is separate from its MIPS32 decoder; the claim that nanoMIPS
code differs from MIPS32 code at the byte level is measured only as far as
the results below go.

## Training data

`ROM`, the image's main executable section, is 32,640,000 B of code and
read-only data linked together, so taking the whole section, as
`build_corpus.py --elf` does, would teach the class the data as well.
`scripts/fw1/elf_symbol_corpus.py` takes only the bytes that sized `STT_FUNC`
symbols name inside `SHF_EXECINSTR` sections, in address order, each address
once.

One image is one program, so a split by file cannot hold anything out. The
functions are grouped into blocks of 1 MiB of address space and every fifth
block is the test split, so neighbouring functions stay on one side.

| Split | Samples | Bytes |
| --- | --- | --- |
| train | 322 | 20,439,434 |
| test | 82 | 5,244,326 |

The output is `corpus-nanomipsx`, 64 KiB per sample, under `corpus_extra/`
(git-ignored). `scripts/build_corpus.py` also labels little-endian ELF machine
249 as `nanomips`. The class has no big-endian form: both images available are
little-endian.

## Results

Held-out model `ship24-train` (2026-11-06, macOS AArch64):

| Input | Result |
| --- | --- |
| The 82 held-out function samples (`corpus-nanomipsx` test split) | 82 of 82 `nanomips`; 512 B and 2 KiB snippets 100%, 128 B snippets 97.6% (2 of 82 rejected) |
| Every other held-out set (`corpus-base7`, `corpus-fw1v23`, `corpus-ds2h`, `corpus-m68kx`, `corpus-z8x`, `corpus-mcs251x`, `corpus-ippx`) | Summary lines identical to `ship23-train`, except `corpus-base7` at 128 B: correct 93.8% to 93.7%, exact 92.4% to 92.3%, rejected 6.2% to 6.3% |
| fw1 golden test split (940 files, CLI) | 940 of 940, as with `ship23-train` |
| The 19,680 held-out non-padding, non-code windows of `corpus-base7` (`examples/calibrate.rs`) | 24 code verdicts and a largest margin of 0.96, as with `ship23-train`; none is `nanomips` |

The shipped model `ship24-all` on files of the submitted folder:

| File | Size | Result |
| --- | --- | --- |
| `nanoMIPS/md1rom` (Xiaomi MT6853, `MOLY.NR15.R3.TC8.PR1.SP.V1.1.P70`), never trained on | 29,401,504 B | `nanomips` 0.99 |
| `nanoMIPS-mt6833/TK_MD_PCB01_MT6833_S00.bin` (holds the training image's `ROM`: fit, not evidence) | 33,949,856 B | `nanomips` 0.99 |
| `nanoMIPS-mt6833/TK_MD_PCB01_MT6833_S00.elf` | 57,469,408 B | `nanomips` 1.00, from the header |
| `mips16e2/0000_md1rom.bin` (a `MOLY.LR12A` modem image, in a folder named for MIPS16e2) | 16,936,100 B | `mips` 0.99, unchanged |

`md1rom` and the training image come from one modem codebase (`MOLY.NR15`
builds), so its result and the held-out split are upper bounds for unrelated
nanoMIPS code. fw1 holds no ELF with machine 0xF9.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| N1 | ELF machine 0xF9 means nanoMIPS | A 0xF9 ELF whose toolchain strings name another architecture; the code-model check reports a header contradicted by its code |
| N2 | One modem codebase represents nanoMIPS code | Code from another nanoMIPS toolchain or project that reads as another class or as no ISA; none was available to test |
| N3 | Sized function symbols hold code, not data | Literal pools or tables inside functions that shift the class; measure the same image with blocks that hold return instructions only |
| N4 | Code is little-endian | A big-endian nanoMIPS image; `e_machine` still names the ISA, the code model has no class for it |

## Known boundaries

- No nanoMIPS instruction is decoded.
- `e_flags` of a nanoMIPS ELF is not decoded.
- Big-endian nanoMIPS has no class: raw images of it are not recognized as
  nanoMIPS.
- The training code comes from one vendor's builds; how the class does on
  other nanoMIPS code is not measured.
- The samples are third-party firmware and stay out of the repository; the
  tests use a synthetic ELF header.

## Verification

On 2026-11-06 (macOS AArch64, rustc 1.99.1), with `ship24-all` and the external
fixtures `D10_FIXTURE` and `TI_C55X_FIXTURE` set:

- `cargo test --all-features --locked --no-fail-fast`: 3,012 passed, 0 failed,
  7 ignored (five diagnostic tools, one D10 reference test and one test that
  needs a `UARP_FIXTURE`), including `nanomips_machine_is_not_reported_as_mips`
  in `tests/elf_headers.rs`.
- `npm test` after `./build-web.sh`: 406 tests, 406 passed, 0 skipped, 0 failed,
  including the display name in `web/tests/isa-names.test.mjs`.

Not verified: the leave-one-group-out folds of `scripts/fw1/README.md` were not
repeated for `ship24-train`, and no nanoMIPS code from outside the MediaTek
modem builds was available.

## Sources

- QEMU `include/elf.h` (master, read 2026-11-06):
  <https://github.com/qemu/qemu/blob/master/include/elf.h>
- QEMU `target/mips/tcg/nanomips_translate.c.inc` (master, read 2026-11-06):
  <https://github.com/qemu/qemu/blob/master/target/mips/tcg/nanomips_translate.c.inc>
