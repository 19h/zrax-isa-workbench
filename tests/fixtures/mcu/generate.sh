#!/usr/bin/env bash
set -euo pipefail

# Regenerate the MCU image test fixtures: Cortex-M4 Thumb-2 and RV32IMAC
# machine code compiled from tests/fixtures/transforms/sample.c, and an
# LZMA-alone copy of the Thumb code for GBL "program LZMA" tags. The UF2,
# DfuSe, GBL and .cyacd containers themselves are built by tests/mcu.rs.
# Usage: tests/fixtures/mcu/generate.sh
# Requires clang and llvm-objcopy with the ARM and RISC-V targets, and xz
# (XZ Utils). See README.md for the versions used.

cd "$(dirname "$0")"
source_file=../transforms/sample.c

compile() {
    local name="$1"
    shift
    for level in O0 O2; do
        clang "$@" "-$level" -ffreestanding -fno-builtin -c "$source_file" -o "$name.$level.o"
        llvm-objcopy -O binary --only-section=.text "$name.$level.o" "$name.$level.bin"
        rm "$name.$level.o"
    done
    cat "$name.O0.bin" "$name.O2.bin" > "$name.text.bin"
    rm "$name.O0.bin" "$name.O2.bin"
}

compile thumbv7em --target=thumbv7em-none-eabi -mcpu=cortex-m4
compile riscv32 --target=riscv32-none-elf -march=rv32imac
xz --format=lzma -9 -c thumbv7em.text.bin > thumbv7em.text.bin.lzma
