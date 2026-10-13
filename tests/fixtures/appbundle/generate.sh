#!/usr/bin/env bash
set -euo pipefail
# Rebuild the ASAR fixture for tests/appbundle.rs and
# web/tests/appbundle.test.mjs with the asar CLI (@electron/asar).
#
# Usage: tests/fixtures/appbundle/generate.sh [OUT_DIR]
# OUT_DIR defaults to this script's directory. Needs `asar` on PATH.

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="$(cd "$here/.." && pwd)"
out="${1:-$here}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

src="$work/app"
mkdir -p "$src/native" "$src/lib" "$src/assets" "$src/bin"
printf 'module.exports = require("./native/x86_64.node");\n' > "$src/index.js"
cp "$fixtures/compressed/payload.elf" "$src/native/x86_64.node"
cp "$fixtures/archives/payload.elf" "$src/native/aarch64.node"
printf 'zrax asar fixture\n' > "$src/assets/readme.txt"
printf '#!/bin/sh\nexit 0\n' > "$src/bin/run.sh"
chmod 755 "$src/bin/run.sh"
chmod 644 "$src/index.js" "$src/native/x86_64.node" "$src/native/aarch64.node" \
  "$src/assets/readme.txt"
ln -s ../index.js "$src/lib/main.js"

(cd "$work" && asar pack app sample.asar --unpack '*.txt')
cp "$work/sample.asar" "$out/sample.asar"
