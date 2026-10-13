#!/usr/bin/env bash
set -euo pipefail
# Regenerate the WIM fixtures of tests/wim.rs and web/tests/wim.test.mjs.
#
# - 7zip-stored.wim: 7-Zip (7zz) captures a directory of the repository's
#   own fixtures: Windows/System32/driver.efi (the x86-64 PE32+ image of
#   tests/fixtures/uefi/pe32-sections.bin, bytes 4 to 0x1B0), payload.elf
#   (tests/fixtures/archives/payload.elf) and a text file. 7-Zip writes
#   only uncompressed WIMs. Its output holds timestamps and a random GUID,
#   so a new run gives different bytes; the README records the committed
#   file.
# - xpress.wim, lzx.wim, solid-lzx.wim, solid-lzms.wim: written by the test
#   builder (tests/support/wim_image.rs with the XPRESS, LZX and LZMS test
#   encoders). The test `committed_synthetic_fixtures_match_the_builder`
#   checks that the committed files are what the builder writes.
#
# Usage: tests/fixtures/wim/generate.sh   (from the repository root; needs
# 7zz, cargo and python3)

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${here}/../../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

mkdir -p "${work}/tree/Windows/System32"
python3 -I -c '
import sys
data = open(sys.argv[1], "rb").read()[4:0x1B0]
open(sys.argv[2], "wb").write(data)
' "${root}/tests/fixtures/uefi/pe32-sections.bin" "${work}/tree/Windows/System32/driver.efi"
cp "${root}/tests/fixtures/archives/payload.elf" "${work}/tree/payload.elf"
printf 'Release notes: nothing to see here.\r\n' > "${work}/tree/readme.txt"
(cd "${work}/tree" && 7zz a -twim "${work}/7zip-stored.wim" . > /dev/null)
cp "${work}/7zip-stored.wim" "${here}/7zip-stored.wim"

log="${work}/cargo.log"
if ! (cd "${root}" && WIM_WRITE_FIXTURES="${here}" cargo test --all-features --test wim \
    committed_synthetic_fixtures_match_the_builder > "${log}" 2>&1); then
    cat "${log}" >&2
    exit 1
fi

for name in 7zip-stored.wim xpress.wim lzx.wim solid-lzx.wim solid-lzms.wim; do
    size="$(wc -c < "${here}/${name}" | tr -d ' ')"
    digest="$(shasum -a 256 "${here}/${name}" | cut -d ' ' -f 1)"
    echo "${name} ${size} ${digest}"
done
