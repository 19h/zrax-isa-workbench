#!/usr/bin/env bash
set -euo pipefail

# Regenerate the ARM code used by the ARM Image Format tests from
# ../transforms/sample.c: ARMv4T in ARM state, little- and big-endian, -O0
# and -O2 concatenated. The AIF images themselves are built by the tests
# from the documented header layout.
#
# Usage: tests/fixtures/aif/generate.sh
# Requires clang and llvm-objcopy with the ARM target (see README.md).

cd "$(dirname "$0")"
for order in le be; do
    case "${order}" in
        le) target=armv4t-none-eabi ;;
        be) target=armebv4t-none-eabi ;;
    esac
    for level in O0 O2; do
        clang "--target=${target}" -marm "-${level}" -ffreestanding -fno-builtin \
            -c ../transforms/sample.c -o "sample.${order}.${level}.o"
        llvm-objcopy -O binary --only-section=.text "sample.${order}.${level}.o" \
            "text.${level}.bin"
        rm "sample.${order}.${level}.o"
    done
    cat text.O0.bin text.O2.bin > "arm-${order}.text.bin"
    rm text.O0.bin text.O2.bin
done
