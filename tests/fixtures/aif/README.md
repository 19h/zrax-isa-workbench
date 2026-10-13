# ARM Image Format fixtures

`arm-le.text.bin` and `arm-be.text.bin` are A32 machine code for the ARM
Image Format tests (`tests/aif.rs`, `web/tests/aif.test.mjs`).
`generate.sh` compiles the synthetic, freestanding `../transforms/sample.c`
for ARMv4T in ARM state, little-endian and big-endian, with `-O0` and `-O2`,
and concatenates the two `.text` sections. The code is not linked and its
relocations are unresolved; it is test input for the code model, not a
working program.

Every AIF image in the tests (executable, non-executable and extended AIF,
compressed and self-relocating images, both byte orders) is built by the
test code from the documented header layout (ARM DUI 0041C, Table 13-1)
around these files. No AIF image produced by ARM's tools and no RISC OS
software is included.

Generated on 2026-10-13, macOS AArch64, with clang 23.0.0git (llvm-project
`b51054818b78dc395cd4d33f17cfb6e98a36a76d`) and the matching llvm-objcopy:

```sh
clang --target=armv4t-none-eabi|armebv4t-none-eabi -marm -O0|-O2 -ffreestanding -fno-builtin -c ../transforms/sample.c
llvm-objcopy -O binary --only-section=.text sample.o text.bin
```

| File | Target | Size (B) | SHA-256 |
| --- | --- | --- | --- |
| `arm-le.text.bin` | armv4t, ARM state, little-endian | 5764 | `a6cc44dbadd7c111c05ae75bf55e16ab96eb2b5ec99011f1fc89b19a5c24c9e5` |
| `arm-be.text.bin` | armebv4t, ARM state, big-endian (BE32 instruction words) | 5764 | `0fb8275bde5b9f8c73ed56d965a12510593e4a6a2044b296766ba2399e5ae55c` |
