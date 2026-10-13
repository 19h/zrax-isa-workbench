#!/usr/bin/env bash
set -euo pipefail
# Regenerate the RPM and Debian package payload fixtures: a newc cpio
# archive of ../compressed/payload.elf (as ./usr/bin/hello) and a short text
# file, compressed copies of it, and an xz-compressed ustar archive of the
# same two files. tests/rpm.rs and web/tests/rpm.test.mjs build the package
# headers around them.
# Usage: tests/fixtures/rpm/generate.sh (from any directory).

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/usr/bin" "$work/usr/share/doc/hello"
cp "$here/../compressed/payload.elf" "$work/usr/bin/hello"
printf 'zrax synthetic package payload\n' > "$work/usr/share/doc/hello/README"
chmod 0755 "$work/usr" "$work/usr/bin" "$work/usr/bin/hello" "$work/usr/share" \
  "$work/usr/share/doc" "$work/usr/share/doc/hello"
chmod 0644 "$work/usr/share/doc/hello/README"
find "$work/usr" -exec touch -h -t 202610120000.00 {} +

(cd "$work" && find ./usr | LC_ALL=C sort | cpio -o -H newc -R 0:0 --quiet) \
  > "$here/payload.cpio"
gzip -9 -n -c "$here/payload.cpio" > "$here/payload.cpio.gz"
bzip2 -9 -c "$here/payload.cpio" > "$here/payload.cpio.bz2"
xz -9 -c --check=crc64 "$here/payload.cpio" > "$here/payload.cpio.xz"
lzma -9 -c "$here/payload.cpio" > "$here/payload.cpio.lzma"
zstd -q -19 -c --check "$here/payload.cpio" > "$here/payload.cpio.zst"

(cd "$work" && tar -c --format ustar --uid 0 --gid 0 --uname root --gname root \
  -f - ./usr/bin/hello ./usr/share/doc/hello/README) > "$work/data.tar"
xz -9 -c --check=crc64 "$work/data.tar" > "$here/data.tar.xz"
