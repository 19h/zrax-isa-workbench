#!/usr/bin/env bash
set -euo pipefail

# Regenerate the Apple Image4 fixtures in this directory.
# Usage: IMG4TOOL=/path/to/img4tool tests/fixtures/apple/generate.sh
# Requires python3 and tihmstar's img4tool built with bvx2 support (see
# README.md for the revision used). IMG4TOOL defaults to `img4tool` on PATH.

cd "$(dirname "$0")"
img4tool="${IMG4TOOL:-img4tool}"
description="zrax synthetic kernelcache"

python3 synthetic.py kernel kernel.macho
python3 synthetic.py im4m synthetic.im4m

"$img4tool" -c krnl.im4p -t krnl -d "$description" kernel.macho
"$img4tool" -c krnl.bvx2.im4p -t krnl -d "$description" --compression bvx2 kernel.macho
"$img4tool" -c krnl.complzss.im4p -t krnl -d "$description" --compression complzss kernel.macho
# The generator becomes the IM4R boot nonce (BNCN), stored little-endian.
"$img4tool" -c krnl.img4 -p krnl.bvx2.im4p -m synthetic.im4m -g 0x1122334455667788
