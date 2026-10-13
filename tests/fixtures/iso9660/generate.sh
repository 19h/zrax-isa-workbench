#!/usr/bin/env bash
set -euo pipefail

# Regenerate the ISO 9660 fixtures: three images of the same synthetic tree,
# written by libarchive's ISO 9660 writer (bsdtar) with Rock Ridge and
# Joliet, by bsdtar with Joliet only, and by macOS hdiutil makehybrid with a
# UDF bridge. Every image is gzip-compressed (`gzip -9 -n`); the tests
# decompress them.
# Usage: tests/fixtures/iso9660/generate.sh
# Requires nasm, bsdtar (libarchive 3.7) and, for hdiutil.iso.gz, macOS
# hdiutil. BSDTAR and NASM name other binaries. See README.md.

cd "$(dirname "$0")"
fixtures="$(pwd)"
bsdtar="${BSDTAR:-bsdtar}"
nasm="${NASM:-nasm}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tree="$work/tree"

# The tree: a boot image, a recognized member with a long lowercase name,
# a text file, and a member nine directory levels down, deeper than the
# eight levels ISO 9660 allows, so the Rock Ridge writer relocates it.
mkdir -p "$tree/boot" "$tree/bin" "$tree/docs" "$tree/deep/l1/l2/l3/l4/l5/l6/l7/l8"
"$nasm" -f bin -o "$tree/boot/boot.bin" boot.asm
cp ../compressed/payload.elf "$tree/bin/payload-with-a-long-name.elf"
cp ../compressed/payload.elf "$tree/deep/l1/l2/l3/l4/l5/l6/l7/l8/deep.elf"
printf 'Plain text that no format recognizes.\n' > "$tree/docs/readme.txt"
find "$tree" -exec touch -h -t 202610130000 {} +

boot_options='boot=boot/boot.bin,boot-type=no-emulation,boot-load-size=4,!pad'
"$bsdtar" -c -f "$work/rockridge.iso" --format iso9660 \
    --options "iso9660:$boot_options,volume-id=ZRAX_RR" -C "$tree" .
# Without Rock Ridge there is no relocation and libarchive refuses the deep
# directory, so the Joliet image leaves it out.
"$bsdtar" -c -f "$work/joliet.iso" --format iso9660 \
    --options "iso9660:$boot_options,!rockridge,volume-id=ZRAX_JOLIET" \
    --exclude ./deep -C "$tree" .
images=(rockridge joliet)

if command -v hdiutil > /dev/null; then
    hdiutil makehybrid -quiet -o "$work/hdiutil.iso" -iso -joliet -udf \
        -eltorito-boot "$tree/boot/boot.bin" -no-emul-boot \
        -iso-volume-name ZRAX_HD -joliet-volume-name ZRAX_HD "$tree"
    images+=(hdiutil)
fi

for image in "${images[@]}"; do
    gzip -9 -n -c "$work/$image.iso" > "$fixtures/$image.iso.gz"
done
