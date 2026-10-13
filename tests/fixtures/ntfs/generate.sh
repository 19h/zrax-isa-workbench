#!/usr/bin/env bash
set -euo pipefail

# Regenerate the NTFS volume fixtures in this directory with ntfs-3g
# (mkntfs and the FUSE driver).
# Usage, as root on Linux with FUSE: tests/fixtures/ntfs/generate.sh
# Environment: MKNTFS (default: mkntfs), NTFS3G (default: ntfs-3g) and
# NTFSINFO (default: ntfsinfo) name the ntfs-3g tools. The script also
# needs GNU coreutils, attr (setfattr), util-linux (umount) and gzip. See
# README.md for the versions used and for running it in a container on
# macOS.

cd "$(dirname "$0")"

MKNTFS="${MKNTFS:-mkntfs}"
NTFS3G="${NTFS3G:-ntfs-3g}"
NTFSINFO="${NTFSINFO:-ntfsinfo}"

work="$(mktemp -d)"
mnt="$work/mnt"
mkdir "$mnt"
cleanup() {
    umount "$mnt" 2> /dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

# text <size> <text>: the text repeated without newlines, cut to size bytes.
text() {
    head -c "$1" < <(yes "$2" | tr -d '\n')
}

# pad <input> <size> <text> <output>: the input followed by the repeated
# text, cut to size bytes.
pad() {
    local input="$1" size="$2" filler="$3" output="$4"
    cp "$input" "$output"
    local have
    have="$(stat -c %s "$output")"
    text "$((size - have))" "$filler" >> "$output"
}

# Source files, all synthetic:
# - payload.elf: the 256 B x86-64 ELF header of the compressed-stream
#   fixtures (resident in a 1 KiB or 4 KiB MFT record);
# - app.exe: the 428 B x86-64 PE32+ image of the UEFI fixtures (bytes 4 to
#   432 of pe32-sections.bin, after the section header), padded to 12 KiB;
# - zrax.macho: the 8 KiB arm64 Mach-O header of the Apple fixtures, padded
#   to 100 KiB with text, so that LZNT1 compresses it;
# - stream.macho: the same Mach-O header alone (8 KiB);
# - fragmented.elf: payload.elf padded to 40 KiB.
cp ../compressed/payload.elf "$work/payload.elf"
dd if=../uefi/pe32-sections.bin of="$work/pe.bin" bs=1 skip=4 count=428 status=none
pad "$work/pe.bin" 12288 'zrax synthetic PE overlay ' "$work/app.exe"
pad ../apple/kernel.macho 102400 'zrax synthetic compressed member ' "$work/zrax.macho"
cp ../apple/kernel.macho "$work/stream.macho"
pad "$work/payload.elf" 40960 'zrax synthetic fragmented member ' "$work/fragmented.elf"

# mount_volume <image>: mount with compression enabled and named streams
# reachable as `file:stream` paths.
mount_volume() {
    "$NTFS3G" -o compression,streams_interface=windows "$1" "$mnt"
}

# compressed_directory <path>: mark a directory compressed (bit 0x800 of its
# Windows attributes), so that ntfs-3g compresses new files in it.
compressed_directory() {
    mkdir -p "$1"
    setfattr -n system.ntfs_attrib_be -v 0x00000810 "$1"
}

# make_volume <image> <size> <label> <mkntfs options...>: a zeroed image of
# size bytes formatted with the volume times at the epoch (-T).
make_volume() {
    local image="$1" size="$2" label="$3"
    shift 3
    rm -f "$image"
    truncate -s "$size" "$image"
    "$MKNTFS" -F -q -T -L "$label" "$@" "$image" > /dev/null 2>&1
}

# fragmented_copy <input> <output> <cluster size>: write the input one
# cluster at a time, creating a 2 KiB spacer file (too large to be resident
# in a 1 KiB MFT record) after each cluster, then delete the spacers.
# ntfs-3g allocates in order, so the output is stored in one-cluster runs
# with the spacers' clusters between them.
fragmented_copy() {
    local input="$1" output="$2" cluster="$3"
    local spacers="$mnt/spacers"
    local count=$(( $(stat -c %s "$input") / cluster ))
    mkdir "$spacers"
    : > "$output"
    for i in $(seq 0 "$((count - 1))"); do
        dd if="$input" of="$output" bs="$cluster" skip="$i" count=1 oflag=append conv=notrunc \
            status=none
        text 2048 "zrax spacer $i " > "$spacers/$i"
    done
    rm -r "$spacers"
    cmp "$input" "$output"
}

# zero_upcase <image> <cluster size>: zero the 128 KiB $UpCase table (the
# data of MFT record 10), which the classifier never reads, so that the
# gzip file stays small: gzip cannot compress its ascending 16-bit values.
zero_upcase() {
    local image="$1" cluster="$2"
    local run
    run="$("$NTFSINFO" -v -i 10 "$image" 2> /dev/null | awk '/Runlist:/ { getline; print $2, $3; exit }')"
    local lcn="${run% *}" length="${run#* }"
    if [ "$((length * cluster))" -ne 131072 ]; then
        echo "unexpected \$UpCase run: $run" >&2
        exit 1
    fi
    dd if=/dev/zero of="$image" bs="$cluster" seek="$((lcn))" count="$((length))" conv=notrunc \
        status=none
}

# ntfs.img: 4 MiB, 512 B sectors, 4 KiB clusters, 1 KiB MFT records.
make_volume "$work/ntfs.img" 4M ZRAX
mount_volume "$work/ntfs.img"
cp "$work/payload.elf" "$mnt/payload.elf"
mkdir -p "$mnt/Program Files/Zrax"
cp "$work/app.exe" "$mnt/Program Files/Zrax/app.exe"
printf 'zrax NTFS fixture: not a recognized format\n' > "$mnt/notes.txt"
cat "$work/stream.macho" > "$mnt/notes.txt:payload.macho"
compressed_directory "$mnt/compressed"
cp "$work/zrax.macho" "$mnt/compressed/zrax.macho"
# A sparse file: the ELF header, a hole to 128 KiB, then 4 KiB of text.
cp "$work/payload.elf" "$mnt/sparse.elf"
truncate -s 131072 "$mnt/sparse.elf"
text 4096 'zrax synthetic sparse tail ' >> "$mnt/sparse.elf"
mkdir "$mnt/links"
ln "$mnt/payload.elf" "$mnt/links/hardlink.elf"
ln -s ../payload.elf "$mnt/links/symlink.elf"
# A Windows symbolic link: an empty file given a reparse point with tag
# IO_REPARSE_TAG_SYMLINK (0xA000000C) and the relative target
# `..\payload.elf` as substitute and print name (flags 1, relative).
target=2e002e005c007000610079006c006f00610064002e0065006c006600
: > "$mnt/links/winlink.elf"
setfattr -n system.ntfs_reparse_data \
    -v "0x0c0000a04400000000001c001c001c0001000000$target$target" "$mnt/links/winlink.elf"
mkdir "$mnt/many"
for i in $(seq -w 0 199); do
    printf 'zrax synthetic small file %s\n' "$i" > "$mnt/many/file$i.txt"
done
cp "$work/payload.elf" "$mnt/deleted.elf"
rm "$mnt/deleted.elf"
mkdir "$mnt/bin"
fragmented_copy "$work/fragmented.elf" "$mnt/bin/fragmented.elf" 4096
# Three hard links with 200-character names and three named streams do not
# fit one MFT record: ntfs-3g adds an attribute list and moves file names
# and streams to extension records. The stream `payload.elf` holds the ELF.
cp "$work/app.exe" "$mnt/bin/linked.exe"
long="$(text 200 L)"
for i in 1 2 3; do
    ln "$mnt/bin/linked.exe" "$mnt/bin/$long$i"
done
printf 'zrax synthetic stream one\n' > "$mnt/bin/linked.exe:one"
cat "$work/payload.elf" > "$mnt/bin/linked.exe:payload.elf"
printf 'zrax synthetic stream three\n' > "$mnt/bin/linked.exe:three"
umount "$mnt"

# ntfs-4k.img: 2 MiB, 4096 B sectors and clusters, so 4 KiB MFT records
# with eight update sequence strides.
make_volume "$work/ntfs-4k.img" 2M ZRAX4K -s 4096
mount_volume "$work/ntfs-4k.img"
cp "$work/payload.elf" "$mnt/payload.elf"
mkdir -p "$mnt/Program Files/Zrax"
cp "$work/app.exe" "$mnt/Program Files/Zrax/app.exe"
compressed_directory "$mnt/compressed"
cp "$work/zrax.macho" "$mnt/compressed/zrax.macho"
umount "$mnt"

# ntfs-512.img: 2 MiB, 512 B clusters, so each 1 KiB MFT record spans two
# clusters and a compression unit is 8 KiB.
make_volume "$work/ntfs-512.img" 2M ZRAX512 -c 512
mount_volume "$work/ntfs-512.img"
cp "$work/payload.elf" "$mnt/payload.elf"
compressed_directory "$mnt/compressed"
cp "$work/zrax.macho" "$mnt/compressed/zrax.macho"
mkdir "$mnt/bin"
head -c 10240 "$work/fragmented.elf" > "$work/fragmented-10k.elf"
fragmented_copy "$work/fragmented-10k.elf" "$mnt/bin/fragmented.elf" 512
umount "$mnt"

for image in ntfs.img ntfs-4k.img ntfs-512.img; do
    for path in /payload.elf "/Program Files/Zrax/app.exe" /compressed/zrax.macho \
        /bin/fragmented.elf /bin/linked.exe /sparse.elf /links/winlink.elf /notes.txt; do
        echo "== $image $path"
        "$NTFSINFO" -v -F "$path" "$work/$image" 2> /dev/null \
            | grep -E 'Dumping|Attribute flags|Attribute name|Compression unit|Data size|Total runs' \
            || true
    done
done

zero_upcase "$work/ntfs.img" 4096
zero_upcase "$work/ntfs-4k.img" 4096
zero_upcase "$work/ntfs-512.img" 512

for image in ntfs.img ntfs-4k.img ntfs-512.img; do
    gzip -9 -n -c "$work/$image" > "$image.gz"
    sha256sum "$work/$image" "$image.gz"
    stat -c '%n %s' "$work/$image" "$image.gz"
done
