#!/usr/bin/env bash
set -euo pipefail

# Regenerate the archive fixtures in this directory.
# Usage: tests/fixtures/archives/generate.sh
# Requires Info-ZIP zip, 7-Zip (7zz), Python 3.14 (zipfile with Zstandard
# and tarfile), bsdtar, bsdcpio and gzip. See README.md for the versions
# used. Every archive holds the same two synthetic members.

cd "$(dirname "$0")"
fixtures="$(pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Synthetic members: an ELF64 little-endian AArch64 header (e_machine 0xB7)
# followed by 192 bytes of repeating ASCII, and a short text file. The long
# path exceeds the 100-byte tar name field.
long_dir="long/$(printf 'd%.0s' {1..50})/$(printf 'e%.0s' {1..50})"
python3 - "$fixtures" "$work" "$long_dir" <<'PY'
import os
import struct
import sys

fixtures, work, long_dir = sys.argv[1:4]
header = bytearray(64)
header[0:4] = b"\x7fELF"
header[4] = 2  # ELFCLASS64
header[5] = 1  # ELFDATA2LSB
header[6] = 1  # EV_CURRENT
struct.pack_into("<HHI", header, 16, 2, 0xB7, 1)  # ET_EXEC, EM_AARCH64, version
struct.pack_into("<HHH", header, 52, 64, 56, 64)  # e_ehsize, e_phentsize, e_shentsize
body = (b"zrax archive fixture " * 10)[:192]
payload = bytes(header) + body
notes = b"Synthetic archive member; not a recognized format.\n"
open(f"{fixtures}/payload.elf", "wb").write(payload)
for directory in (f"{work}/tree/bin", f"{work}/tree/{long_dir}"):
    os.makedirs(directory, exist_ok=True)
open(f"{work}/tree/bin/payload.elf", "wb").write(payload)
open(f"{work}/tree/{long_dir}/payload.elf", "wb").write(payload)
open(f"{work}/tree/notes.txt", "wb").write(notes)
PY

cd "$work/tree"
find . -exec env TZ=UTC touch -t 202610120000 {} +
members=(bin/payload.elf notes.txt)

# ZIP: Info-ZIP for stored, deflate, data descriptors, ZIP64 and
# traditional encryption; 7-Zip for bzip2, LZMA, xz, Deflate64 and AES;
# Python for Zstandard.
rm -f "$fixtures"/*.zip
zip -X -q -0 "$fixtures/stored.zip" "${members[@]}"
zip -X -q -9 "$fixtures/deflate.zip" "${members[@]}"
zip -X -q -9 -fd "$fixtures/descriptor.zip" "${members[@]}"
zip -X -q -9 -fz "$fixtures/zip64.zip" "${members[@]}"
zip -X -q -9 -P zrax "$fixtures/encrypted.zip" "${members[@]}"
7zz a -bso0 -bsp0 -tzip -mtc=off -mm=BZip2 "$fixtures/bzip2.zip" "${members[@]}"
7zz a -bso0 -bsp0 -tzip -mtc=off -mm=LZMA "$fixtures/lzma.zip" "${members[@]}"
7zz a -bso0 -bsp0 -tzip -mtc=off -mm=XZ "$fixtures/xz.zip" "${members[@]}"
7zz a -bso0 -bsp0 -tzip -mtc=off -mm=Deflate64 "$fixtures/deflate64.zip" "${members[@]}"
7zz a -bso0 -bsp0 -tzip -mtc=off -pzrax -mem=AES256 "$fixtures/aes.zip" "${members[@]}"
python3 - "$fixtures/zstd.zip" "${members[@]}" <<'PY'
import sys
import zipfile

target, *members = sys.argv[1:]
with zipfile.ZipFile(target, "w") as archive:
    for name in members:
        info = zipfile.ZipInfo(name, date_time=(2026, 10, 12, 0, 0, 0))
        info.compress_type = zipfile.ZIP_ZSTANDARD
        archive.writestr(info, open(name, "rb").read())
PY

# tar: bsdtar ustar (the long path is split into prefix and name); Python
# pax (`path` record) and GNU (`././@LongLink` long name) formats.
COPYFILE_DISABLE=1 tar --format ustar --no-xattrs --no-acls --no-mac-metadata \
    --uid 0 --gid 0 --uname root --gname root \
    -cf "$fixtures/ustar.tar" bin notes.txt "$long_dir/payload.elf"
python3 - "$fixtures" "$long_dir/payload.elf" <<'PY'
import sys
import tarfile

fixtures, long_path = sys.argv[1:3]
for name, form in (("pax.tar", tarfile.PAX_FORMAT), ("gnu.tar", tarfile.GNU_FORMAT)):
    with tarfile.open(f"{fixtures}/{name}", "w", format=form) as archive:
        for path in ("bin/payload.elf", "notes.txt", long_path):
            info = archive.gettarinfo(path)
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = 1_791_763_200  # 2026-10-12T00:00:00Z
            archive.addfile(info, open(path, "rb"))
PY

# CPIO: bsdcpio newc, odc and old binary (written in the host byte order,
# little-endian on AArch64), and a gzip-compressed newc archive as Linux
# initramfs images ship.
printf '%s\n' bin bin/payload.elf notes.txt | cpio -o --quiet -R 0:0 -H newc > "$fixtures/newc.cpio"
printf '%s\n' bin bin/payload.elf notes.txt | cpio -o --quiet -R 0:0 -H odc > "$fixtures/odc.cpio"
printf '%s\n' bin bin/payload.elf notes.txt | cpio -o --quiet -R 0:0 -H bin > "$fixtures/binary.cpio"
gzip -n -9 -c "$fixtures/newc.cpio" > "$fixtures/initramfs.cpio.gz"
