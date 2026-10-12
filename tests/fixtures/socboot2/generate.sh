#!/usr/bin/env bash
set -euo pipefail

# Regenerate the A32 code fixture for the SoC boot image tests from the
# transform fixtures' sample.c.
# Usage: tests/fixtures/socboot2/generate.sh
# Requires clang and llvm-objcopy with the ARM target (see README.md).

cd "$(dirname "$0")"
for level in O0 O2; do
    clang --target=armv7a-none-eabi -marm "-$level" -ffreestanding -fno-builtin \
        -c ../transforms/sample.c -o "sample.arm.$level.o"
    llvm-objcopy -O binary --only-section=.text "sample.arm.$level.o" "text.$level.bin"
    rm "sample.arm.$level.o"
done
cat text.O0.bin text.O2.bin > arm.text.bin
rm text.O0.bin text.O2.bin
