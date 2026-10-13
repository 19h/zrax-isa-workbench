#!/usr/bin/env bash
set -euo pipefail
# Regenerate the synthetic 16-bit x86 code used by the PC/GEOS geode tests.
# The geodes themselves are built in the tests from the documented layout.
#
# Usage: tests/fixtures/geos/generate.sh
# Requires nasm (3.02 was used for the committed file).

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
nasm -f bin -o "${here}/code.bin" "${here}/code.asm"
