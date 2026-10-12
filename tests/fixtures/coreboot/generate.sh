#!/usr/bin/env bash
set -euo pipefail

# Regenerate romstage.lzma in this directory: the committed AArch64 code
# sample tests/fixtures/transforms/aarch64.text.bin encoded as LZMA-alone
# with the decoded size in the header, which is how cbfstool stores an
# LZMA-compressed stage body.
# Usage: tests/fixtures/coreboot/generate.sh
# Requires xz (XZ Utils) and python3. See README.md for the versions used.

cd "$(dirname "$0")"
input=../transforms/aarch64.text.bin

# xz writes LZMA-alone with an unknown decoded size (all ones) and an end
# marker. cbfstool's encoder records the decoded size instead, so the size
# field (bytes 5-12, little-endian) is patched to the input length.
xz --format=lzma --lzma1=preset=9,dict=64KiB -c "$input" > romstage.lzma
python3 - "$input" <<'PY'
import os
import struct
import sys

size = os.path.getsize(sys.argv[1])
stream = bytearray(open("romstage.lzma", "rb").read())
struct.pack_into("<Q", stream, 5, size)
open("romstage.lzma", "wb").write(bytes(stream))
PY
