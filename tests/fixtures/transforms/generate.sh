#!/usr/bin/env bash
set -euo pipefail

# Regenerate the transform-test code fixtures from sample.c.
# Usage: tests/fixtures/transforms/generate.sh
# Requires clang and llvm-objcopy with the AArch64 and RISC-V targets (see
# README.md).

cd "$(dirname "$0")"
for target in aarch64 riscv64; do
    for level in O0 O2; do
        clang "--target=$target-none-elf" "-$level" -ffreestanding -fno-builtin -c sample.c \
            -o "sample.$target.$level.o"
        llvm-objcopy -O binary --only-section=.text "sample.$target.$level.o" "text.$level.bin"
        rm "sample.$target.$level.o"
    done
    cat text.O0.bin text.O2.bin > "$target.text.bin"
    rm text.O0.bin text.O2.bin
done
