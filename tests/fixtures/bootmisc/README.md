# Miscellaneous boot image fixtures

Inputs for the miscellaneous boot image tests (`tests/bootmisc.rs`,
`web/tests/bootmisc.test.mjs`). Every payload is synthetic; no vendor
firmware is included. OP-TEE headers, Amlogic burning images and the
version 0x0300 IMAGEWTY images are built by the test code from the
documented wire layouts.

## barebox heads

`barebox-*.S` transcribe the barebox v2024.10.0 heads
(`arch/arm/include/asm/barebox-arm-head.h` `__barebox_arm_head` with and
without `CONFIG_THUMB2_BAREBOX`, `arch/arm/include/asm/barebox-arm64.h`
`ENTRY_PROC`, `arch/arm/cpu/head_64.S` `__barebox_arm64_head`) with a text
base of 0 (ARM32) or `0xFFFFFFFF` (AArch64) and an image size of 0x200. They
are assembled with clang and the `.text` section is extracted; the tests
take the first 0x50 bytes (the head), append code from `../socboot2/` or
`../transforms/` and patch the image size.

## IMAGEWTY images

`imagewty-plain.img` and `imagewty-encrypted.img` are packed by awutils'
`awimage` (`Ithamar/awutils` commit
`3f1cbb2c67752b392a88b252c51158d13d8809b5`) from `imagewty.cfg` and three
synthetic 512-byte files: `payload.fex` (the x86-64 ELF header
`../compressed/payload.elf`, zero-padded), `sys_config.fex` (two lines of
text, zero-padded) and `tool.bin` (bytes `(i * 7 + 1) & 0xFF`). awimage
writes header version 0x0100. `imagewty-encrypted.img` uses awimage's
default RC6 encryption of the header, item table and file data;
`imagewty-plain.img` is packed with `-n` (no encryption). `awimage -d` on
the encrypted image reproduces the plain image byte for byte.

## Generation

Generated on 2026-10-13, macOS AArch64, with clang 23.0.0git (llvm-project
`b51054818b78dc395cd4d33f17cfb6e98a36a76d`), the matching llvm-objcopy, and
awimage built with the system C compiler:

```sh
AWUTILS_DIR=/path/to/awutils tests/fixtures/bootmisc/generate.sh
```

The script runs, per head:

```sh
clang --target=armv7a-none-eabi|aarch64-none-elf -c barebox-<head>.S -o barebox-<head>.o
llvm-objcopy -O binary --only-section=.text barebox-<head>.o barebox-<head>.bin
```

and, in a temporary directory holding `input/` (the files above):

```sh
cc -w -O0 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -o awimage awimage.c parsecfg.c twofish.c rc6.c
./awimage input encrypted.img
./awimage -n input plain.img
```

awimage copies an eight-character main type into its eight-byte field with
`strcpy`, overrunning into the next field on purpose; fortified builds trap
on it, so fortification is off.

| File | Content | Size (B) | SHA-256 |
| --- | --- | --- | --- |
| `barebox-a32.bin` | ARM32 head, A32 `b 2f` | 88 | `eec8d5e24d135a602fe5154282dd93335d366d90ebb719f72200cec9c0ee0b50` |
| `barebox-thumb2.bin` | ARM32 head, `adr r9`/`bx r9` into Thumb-2 | 84 | `86afa0f2a2dc3e33dfd0d1c8c4d8b4c0d0720572b8b40621029178aab08dcfa2` |
| `barebox-a64-branch.bin` | AArch64 `ENTRY_PROC` head, A64 `b 2f` | 84 | `664e2f163737af469c2618de41b5a069c2fdd0d62837dabdada4adc1a537f3c0` |
| `barebox-a64-nop.bin` | AArch64 `__barebox_arm64_head`, A64 `nop` | 92 | `93456b7e3cf4cdfd0cfefea02ebc5233970b8121dcf7fe519061cfa334403876` |
| `imagewty-plain.img` | awimage `-n`, header version 0x0100 | 5632 | `81322cf923f4ca7ca6d7c4a97d35e0cc85f914028d0b7a501e5a2c1348ffade4` |
| `imagewty-encrypted.img` | awimage, RC6-encrypted | 5632 | `fe216565c68963ea9034ba895b74e6c7fa34d977048d14b12a5a516a9d55b3b3` |
