#!/usr/bin/env bash
set -euo pipefail

# Regenerate the miscellaneous boot image fixtures: the barebox heads,
# assembled from barebox-*.S, and two IMAGEWTY images packed by awutils'
# awimage from synthetic files.
# Usage: AWUTILS_DIR=/path/to/awutils tests/fixtures/bootmisc/generate.sh
# Requires clang and llvm-objcopy with the ARM and AArch64 targets, a C
# compiler, python3, and an awutils checkout at
# 3f1cbb2c67752b392a88b252c51158d13d8809b5 (see README.md).

cd "$(dirname "$0")"
fixtures="$(pwd)"

for head in a32 thumb2 a64-branch a64-nop; do
    case "$head" in
        a64-*) target=aarch64-none-elf ;;
        *) target=armv7a-none-eabi ;;
    esac
    clang --target="$target" -c "barebox-$head.S" -o "barebox-$head.o"
    llvm-objcopy -O binary --only-section=.text "barebox-$head.o" "barebox-$head.bin"
    rm "barebox-$head.o"
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# awimage's strcpy of an 8-character main type into its 8-byte field
# overruns into the next field on purpose; fortified builds trap on it.
cc -w -O0 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -o "$work/awimage" \
    "$AWUTILS_DIR/awimage.c" "$AWUTILS_DIR/parsecfg.c" \
    "$AWUTILS_DIR/twofish.c" "$AWUTILS_DIR/rc6.c"

# Whole 512-byte files, so awimage's 512-byte write buffer carries no
# uninitialized bytes into the images.
mkdir "$work/input"
cp imagewty.cfg "$work/input/image.cfg"
cp ../compressed/payload.elf "$work/input/payload.fex"
truncate -s 512 "$work/input/payload.fex"
printf '[platform]\r\ndebug_mode = 1\r\n' > "$work/input/sys_config.fex"
truncate -s 512 "$work/input/sys_config.fex"
python3 -I -c 'import sys; open(sys.argv[1], "wb").write(bytes((i * 7 + 1) & 0xFF for i in range(512)))' \
    "$work/input/tool.bin"

# awimage prefixes the input directory with "./", so it runs from $work.
(cd "$work" && ./awimage input encrypted.img && ./awimage -n input plain.img)
cp "$work/encrypted.img" "$fixtures/imagewty-encrypted.img"
cp "$work/plain.img" "$fixtures/imagewty-plain.img"
