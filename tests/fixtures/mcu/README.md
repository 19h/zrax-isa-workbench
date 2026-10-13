# MCU image fixtures

Machine code for the UF2, DfuSe, GBL and `.cyacd` tests in `tests/mcu.rs`
and `web/tests/mcu.test.mjs`, and for the DFU suffix and EBL tests in
`tests/mcu_wrappers.rs` and `web/tests/mcu-wrappers.test.mjs`. The
containers themselves are built by the tests from the documented layouts;
only the code inside them is committed, plus the Nordic init packets
described at the end.

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

## Nordic DFU init packets

`nordic-init-signed.dat` and `nordic-init-unsigned.dat` are synthetic nRF5
DFU init packets for `tests/mcu_wrappers.rs` and
`web/tests/mcu-wrappers.test.mjs`. `generate-init-packets.sh` encodes the
committed protobuf text inputs (`*.txtpb`) with `protoc --encode=dfu.Packet`
against pc-nrfutil v6.1.7 `nordicsemi/dfu/dfu-cc.proto` (commit
`804bc0ffa9929d4c74238eb7abdfb62ad660e122`, SHA-256
`d2b08647acc64a008452b5c78dd38f519fc0f9c960c19f65f5d68c40e18adb69`), which
the script downloads and checks; the `.proto` file is not committed.

Generated on 2026-10-13, macOS AArch64, with protoc (libprotoc) 36.2:

```sh
tests/fixtures/mcu/generate-init-packets.sh
```

| File | Content | Size (B) | SHA-256 |
| --- | --- | --- | --- |
| `nordic-init-signed.dat` | `signed_command` for an application of 5484 B: fields as pc-nrfutil writes them, SHA-256 of `thumbv7em.text.bin` in reverse byte order, `sd_req` 0x0100 and 0x0101, one CRC boot validation | 142 | `ea88feead449fb971347266edfbfa83d10c81380acff09c1eb4ff0942e2992cd` |
| `nordic-init-unsigned.dat` | `command` for a SoftDevice and bootloader update (152864 B and 24576 B), `sd_req` 0xFFFE, debug flag set, two boot validations | 83 | `dba729993e15af6bade12bf343f7999da2a2d1cd77c4c15dfa3a006d7546f72a` |

What is synthetic: the signature is 64 bytes of `0x5A`, not an ECDSA
signature; the unsigned packet's hash is 32 bytes of `0x11` and its sizes
describe no real image; `hw_version` 52 and the `sd_req` IDs were chosen,
not taken from a release. No nrfutil-generated package was available, so
the packets were not compared with nrfutil output.

The USB DFU and Silicon Labs EBL files in `tests/mcu_wrappers.rs` are built
by the tests from the documented layouts around `thumbv7em.text.bin` and
`riscv32.text.bin`; dfu-util (`dfu-suffix`) and Simplicity Commander were not
installed, so no tool-generated DFU or EBL file is committed.
