#!/usr/bin/env bash
set -euo pipefail

# Regenerate the router firmware fixtures in this directory.
# Usage: tests/fixtures/router/generate.sh
# Requires python3 and xz (XZ Utils). See README.md for the versions used.

cd "$(dirname "$0")"

python3 build_images.py payloads .

# A raw LZMA-alone kernel with the properties OpenWrt passes to `lzma e`
# for router kernels (lc=1 lp=2 pb=2, properties byte 0x6D).
xz --format=lzma --lzma1=preset=6,lc=1,lp=2,pb=2 -c kernel.elf > kernel.elf.lzma

python3 build_images.py wrappers .
