#!/usr/bin/env bash
set -euo pipefail

# Regenerate the compressed-stream fixtures in this directory.
# Usage: tests/fixtures/compressed/generate.sh
# Requires gzip, xz (XZ Utils), lz4, zstd, bzip2, lzop and, for LZFSE, the
# macOS compression_tool. See README.md for the versions used.

cd "$(dirname "$0")"

# Synthetic payload: an ELF64 little-endian x86-64 header (e_machine 0x3E)
# followed by 192 bytes of repeating ASCII, so every codec emits matches.
python3 - <<'PY'
import struct
header = bytearray(64)
header[0:4] = b"\x7fELF"
header[4] = 2  # ELFCLASS64
header[5] = 1  # ELFDATA2LSB
header[6] = 1  # EV_CURRENT
struct.pack_into("<HHI", header, 16, 2, 0x3E, 1)  # ET_EXEC, EM_X86_64, version
struct.pack_into("<HHH", header, 52, 64, 56, 64)  # e_ehsize, e_phentsize, e_shentsize
body = (b"zrax compressed fixture " * 8)[:192]
open("payload.elf", "wb").write(bytes(header) + body)
PY

gzip -n -9 -c payload.elf > payload.elf.gz
xz -9 -c --check=crc64 payload.elf > payload.elf.xz
xz -c --check=sha256 --x86 --lzma2=preset=6 payload.elf > payload.elf.bcj.xz
cat payload.elf.xz payload.elf.xz > payload.elf.concat.xz
lzma -9 -c payload.elf > payload.elf.lzma
lz4 -q -9 -c --content-size payload.elf > payload.elf.lz4
lz4 -q -l -9 -c payload.elf > payload.elf.legacy.lz4
zstd -q -19 -c --check payload.elf > payload.elf.zst
bzip2 -9 -c payload.elf > payload.elf.bz2
lzop -9 -c payload.elf > payload.elf.lzo
compression_tool -encode -a lzfse -i payload.elf -o payload.elf.lzfse
