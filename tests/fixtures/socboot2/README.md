# SoC boot image fixtures

`arm.text.bin` is A32 machine code for the SoC boot image tests
(`tests/socboot2.rs`, `web/tests/socboot2.test.mjs`). `generate.sh` compiles
the synthetic, freestanding `../transforms/sample.c` for ARMv7-A in ARM state
with `-O0` and `-O2` and concatenates the two `.text` sections. The code is
not linked and its relocations are unresolved; it is test input for the code
model, not a working program.

Every boot image container in the tests (eGON, TOC0, RKBOOT, RKAF, RKFW,
idbloader, MediaTek GFH, Qualcomm MBN) is built by the test code from the
documented wire layout around this file and the AArch64 and RV64 code in
`../transforms/`. No vendor firmware is included.

Generated on 2026-10-12, macOS AArch64, with clang 23.0.0git (llvm-project
`b51054818b78dc395cd4d33f17cfb6e98a36a76d`) and the matching llvm-objcopy:

```sh
clang --target=armv7a-none-eabi -marm -O0|-O2 -ffreestanding -fno-builtin -c ../transforms/sample.c
llvm-objcopy -O binary --only-section=.text sample.o text.bin
```

| File | Target | Size (B) | SHA-256 |
| --- | --- | --- | --- |
| `arm.text.bin` | armv7a, ARM state | 5976 | `002b25c1a48d61f34a0aaab3115d03b4baa94fd346b3c8661fdd44fa20e18df0` |
