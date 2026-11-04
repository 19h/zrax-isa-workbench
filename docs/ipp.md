# Panasonic UniPhier IPP

zrax reports code for the processor that Panasonic's UniPhier system LSIs
call the IPP ("Instruction Parallel Processor") as the ISA `ipp`
(`Panasonic UniPhier IPP`, 32-bit, big-endian code). Two paths name it:

- **ELF header.** `e_machine` 0x1040 maps to `ipp`. It is not in the System
  V gABI registry or in binutils. The toolchain that writes it names the
  architecture `ipp` in the files themselves (see
  [Identification](#identification)).
- **Code model.** The class `ipp` holds the code of 212 FreeBSD ELF files
  with that machine number. It classifies raw images, and checks that an
  ELF's loaded code agrees with its header like every other class.

No instruction-set manual, compiler or disassembler for the IPP is public
(searches on 2026-11-03 and 2026-11-04). zrax therefore decodes no IPP
instruction: there is no extension detection and no instruction-level check
like the SH-4 or 65816 checks.

## Identification

The samples are the user-assembled folder `~/Downloads/ipp-samples`
(2026-11-04; third-party firmware, not in the repository). Its README
records the evidence; the parts zrax relies on:

| Evidence | Where | What it shows |
| --- | --- | --- |
| `e_machine` 0x1040, ELF32 big-endian, `EI_OSABI` 9 (FreeBSD), `e_flags` 0x00034000 | all 212 ELFs | One machine number for one userland |
| `.../libexec/rtld-elf/ipp/reloc.c` (assert) and `Unexpected R_IPP_COPY relocation` | `ld-elf.so.1` | FreeBSD's per-architecture linker directory and relocation names call it `ipp` |
| `ipp-unknown-freebsd`, `ipp-freebsd-clang -mtarget=Pro5` | `freetimed`, `libcurl.so.7`, `libcrypto.so.6` and others | GNU target triple and compiler name |
| `UniPhier-ReCS`; `Do you believe in UniPhier ?` | 3 files; 14 files | The product family |

Tanaka and Yoshioka, "UniPhier System LSIs and Their Core Technologies"
(Panasonic Technical Journal 58(1), April 2012), describe the UniPhier
processor as the IPP and the DPP, with the IPP3 taking on host-processor
functions; a FreeBSD userland with a dynamic linker and a JavaScript JIT
fits that. The mapping of 0x1040 to the IPP rests on these strings, not on
a registry: another vendor could use the same unregistered number.

## Training data and wire units

`scripts/build_corpus.py` labels ELF machine 0x1040 as `ipp` (big-endian
only) and takes the executable sections, one group per file. The corpus
`corpus-ippx` has 212 samples, 23.1 MB: 179 files in the train split and 33
in the test split. Code is a stream of big-endian 16-bit parcels; whether
some instructions take two parcels is not established. The class is
trained like every other class (`ship23`, see `scripts/fw1/README.md`).

The 143 static executables link the same C library, so a held-out file
shares functions with training files: held-out results on these files are
an upper bound for unrelated IPP code.

## Results

Held-out model `ship23-train` (2026-11-04, macOS AArch64):

| Input | Result |
| --- | --- |
| The 33 held-out ELF code samples (`corpus-ippx` test split) | 33 of 33 `ipp`; 512 B and 2 KiB snippets 100%, 128 B snippets 97.0% (1 of 33 rejected) |
| Every other held-out set (`corpus-base7`, `corpus-fw1v23`, `corpus-ds2h`, `corpus-m68kx`, `corpus-z8x`, `corpus-mcs251x`) | Summary lines identical to `ship22-train`: the class took no other class's samples and accepted no non-code sample |
| fw1 golden test split (940 files, CLI) | 940 of 940, as with `ship22-train` |

Raw images of `ipp-samples` (none of them in training), with the same
model:

| File | Size | Result |
| --- | --- | --- |
| `ipp-code-raw/ippboot.rom` (= `user-submissions/new/ippboot.rom`) | 21,256 B | `ipp` 0.99 after a byte swap; code share 0.81 |
| `user-submissions/new/pprk.rom` | 3,263,824 B | `ipp` 0.99 after a byte swap; code share 0.67 |
| `user-submissions/new/kernel.crash` | 5,750,784 B | `ipp` 0.99 as stored (the file starts with the kernel command line ` root=/dev/emmc8`; what else it holds was not examined) |
| `user-submissions/old/ippboot.bin`, `vio.bin`, `ipp_ext.bin` | 61,440 B, 786,432 B, 2,031,616 B | `ipp` 0.99 after a byte swap |
| `peaks-pro2-ucode/uniphier.bin` (PEAKS Pro2 microcode, 2010) | 2,022,576 B | `ipp` 0.85 after a 32-bit byte swap, from 19.7% of the image |
| `peaks-pro2-ucode/uniphier1.bin` | 2,097,184 B | No ISA |
| `coef.bin`, `dccoef.bin`, `ver.bin`, `version.bin` (tables and version text) | 296 B to 1,760 B | No ISA |
| `encrypted/ipp_enc.bin`, `encrypted/uniphier_enc.bin`, `user-submissions/old/ipp_enc.bin` | 131,072 B each | No ISA (entropy at the noise level) |

The boot images store each 32-bit word little-endian. A 16-bit and a 32-bit
byte swap both put the parcels into big-endian order, and read as `ipp` at
the same confidence with the same code share: they differ only in the order
of the two parcels of a word, which the byte-pair model does not resolve.
The note names both swaps and says which one restores the execution order
is not established. The samples' own parcel-bigram measure favors the 32-bit
swap for `ippboot.rom` (`analysis/parcel-profile.tsv`: 0.463 against 0.033);
zrax does not use that measure.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| I1 | ELF machine 0x1040 is the toolchain's `ipp` | A 0x1040 ELF whose toolchain strings name another architecture, or a registry entry assigning 0x1040 elsewhere; the code-model check reports a header contradicted by its code |
| I2 | The toolchain's `ipp` is Panasonic UniPhier's IPP | A Panasonic or Socionext document that names the processor otherwise |
| I3 | The FreeBSD userland is representative IPP code | Real IPP code from another toolchain (the PEAKS Pro2 microcode, 2010) reads only partly as `ipp`: either an earlier IPP generation with another encoding or mostly data, which was not tested |
| I4 | The raw images that read as `ipp` hold IPP code | Decode them once an encoding is known; check that `ippboot.rom`'s leading table of `0x6000xxxx` words points into its code |

## Known boundaries

- No IPP instruction is decoded; there is no disassembly, extension
  detection or instruction-level variant check.
- `e_flags` 0x00034000 is not decoded.
- The parcel order inside the 32-bit words of byte-swapped images is not
  established (see Results).
- The PEAKS Pro2 microcode is not shown to use the 0x1040 encoding.
- The samples are third-party firmware and stay out of the repository; the
  tests use synthetic ELF headers.

## Sources

- Tanaka, Yoshioka, "UniPhier System LSIs and Their Core Technologies",
  Panasonic Technical Journal 58(1), April 2012:
  <https://tech.panasonic.com/jp/phd/pdf/technology-journal/v5801/p0109.pdf>
- System V gABI, ELF header (`e_machine` registry):
  <https://www.sco.com/developers/gabi/latest/ch4.eheader.html>
- The sample folder's README (`~/Downloads/ipp-samples/README.md`,
  2026-11-04), which lists the string evidence per file.
