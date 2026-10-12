# MCU image fixtures

Machine code for the UF2, DfuSe, GBL and `.cyacd` tests in `tests/mcu.rs`
and `web/tests/mcu.test.mjs`. The containers themselves are built by the
tests from the documented layouts; only the code inside them is committed.

`generate.sh` compiles the synthetic, freestanding
`tests/fixtures/transforms/sample.c` at `-O0` and `-O2` and concatenates the
two `.text` sections per target, as `tests/fixtures/transforms/generate.sh`
does. The result is unlinked machine code with unresolved relocations, for
testing only. The LZMA file is the Thumb code in the LZMA-alone format (the
layout GBL "program LZMA" tags carry).

Generated on 2026-10-12, macOS AArch64, with clang 23.0.0git (llvm-project
`b51054818b78dc395cd4d33f17cfb6e98a36a76d`), the matching llvm-objcopy, and
xz (XZ Utils) 5.8.2:

```sh
clang --target=thumbv7em-none-eabi -mcpu=cortex-m4 -O0|-O2 -ffreestanding -fno-builtin -c sample.c
clang --target=riscv32-none-elf -march=rv32imac -O0|-O2 -ffreestanding -fno-builtin -c sample.c
llvm-objcopy -O binary --only-section=.text sample.o text.bin
xz --format=lzma -9 -c thumbv7em.text.bin > thumbv7em.text.bin.lzma
```

| File | Content | Size (B) | SHA-256 |
| --- | --- | --- | --- |
| `thumbv7em.text.bin` | Cortex-M4 Thumb-2 | 5484 | `0577c5f798d7f6b30f4b91e4a43f31b604dda5f434e4fb80f7b7cc1ba8606aa1` |
| `riscv32.text.bin` | RV32IMAC | 3816 | `7cbd43c15b62d72782d17aa1ae253abfbf9c93421c05288619846a38bcbc1a79` |
| `thumbv7em.text.bin.lzma` | LZMA-alone, unknown size | 3556 | `0957146558bc4b5b8c0cf9a9c627742b2dc5f8dacbc5d21ff7e97cc187a255bd` |
