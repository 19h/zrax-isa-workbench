# Transform fixtures

`sample.c` is a synthetic, freestanding C file (CRC, sorting, string,
base64, matrix, a stack VM, a hash map). `generate.sh` compiles it with
`-O0` and `-O2` and concatenates the two `.text` sections per target. The
result is machine code for testing only: it is not linked, and its
relocations are unresolved.

Generated on 2026-10-12, macOS AArch64, with clang 23.0.0git (llvm-project
`b51054818b78dc395cd4d33f17cfb6e98a36a76d`) and the matching llvm-objcopy:

```sh
clang --target=<target>-none-elf -O0|-O2 -ffreestanding -fno-builtin -c sample.c
llvm-objcopy -O binary --only-section=.text sample.o text.bin
```

| File | Target | Size (B) | SHA-256 |
| --- | --- | --- | --- |
| `aarch64.text.bin` | aarch64 | 6384 | `813ee8804e2c0f2aa98e447082bdab719977bc3a1c263fda8392e4d9d044979b` |
| `riscv64.text.bin` | riscv64 | 4026 | `37df5c045512f3708c6850e39d692216d2c2e8f4a069175e464d639246822d85` |
| `sample.c` | source | 4393 | `39e26fed1722a7821d6ebda5548507b3e9d41babcaf0a5ccc01a3bf4fb1211fc` |
