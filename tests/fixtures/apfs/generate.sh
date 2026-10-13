#!/usr/bin/env bash
set -euo pipefail

# Regenerate the APFS container fixtures in this directory.
# Usage: tests/fixtures/apfs/generate.sh
# Requires macOS: hdiutil creates and attaches the raw (UDRW) 8 MiB images,
# whose APFS container starts at offset 0 (-layout NONE), ditto
# --hfsCompression writes decmpfs (AppleFSCompression) files on the mounted
# volume, and diskutil replaces the volume of encrypted.img with an
# encrypted one. See README.md for the versions used. The images are not
# reproducible byte for byte: UUIDs, timestamps, transaction identifiers
# and (for encrypted.img) the keys differ on each run.

cd "$(dirname "$0")"

work="$(mktemp -d)"
mnt="$work/mnt"
mkdir "$mnt" "$work/src"
cleanup() {
    hdiutil detach -quiet -force "$mnt" 2>/dev/null || true
    if [[ -n "${device:-}" ]]; then
        hdiutil detach -quiet -force "$device" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

# Members, built from the committed synthetic inputs:
# - payload.elf: the 256 B x86-64 ELF header from the compressed fixtures;
# - zrax.macho: the 8 KiB synthetic arm64 Mach-O from the Apple fixtures,
#   padded with ASCII text to 24 KiB, so that ditto compresses it into the
#   com.apple.decmpfs attribute;
# - large.macho: the same Mach-O padded to 200 KiB, so that ditto stores it
#   as 64 KiB chunks in the com.apple.ResourceFork attribute;
# - huge.macho: the same Mach-O followed by pseudo-random words to 70 KiB,
#   which LZVN compresses to two chunks of several blocks;
# - fragmented.elf: payload.elf padded with ASCII text to 40 KiB, written a
#   block at a time between spacer files so that it needs several extents;
# - notes.txt and 160 small text files, which are not a recognized format
#   and give the file-system tree index nodes.
python3 -I - "$work" <<'PY'
import sys
work = sys.argv[1]
elf = open("../compressed/payload.elf", "rb").read()
macho = open("../apple/kernel.macho", "rb").read()

def padded(head, size, text):
    body = bytearray(head)
    while len(body) < size:
        body += text
    return bytes(body[:size])

def words(head, size):
    # Words picked by a linear congruential generator: text that LZVN
    # compresses to tens of KiB rather than a few hundred bytes.
    vocabulary = [b"zrax", b"synthetic", b"apfs", b"resource", b"fork", b"chunk",
                  b"member", b"stream", b"extent", b"block", b"node", b"tree"]
    body = bytearray(head)
    state = 1
    while len(body) < size:
        state = (state * 1103515245 + 12345) % (1 << 31)
        body += vocabulary[(state >> 16) % len(vocabulary)] + b" "
    return bytes(body[:size])

files = {
    "payload.elf": elf,
    "zrax.macho": padded(macho, 24 << 10, b"zrax synthetic inline member "),
    "large.macho": padded(macho, 200 << 10, b"zrax synthetic resource fork member "),
    "huge.macho": words(macho, 70 << 10),
    "fragmented.elf": padded(elf, 40 << 10, b"zrax synthetic fragmented member "),
    "notes.txt": b"zrax APFS fixture: not a recognized format\n",
}
for name, data in files.items():
    open(f"{work}/{name}", "wb").write(data)
PY
cp "$work/payload.elf" "$work/notes.txt" "$work/src/"

attach() {
    hdiutil attach -quiet -nobrowse -noverify -noautoopen -mountpoint "$mnt" "$1"
}

# create <image> <file system> <volume name>: an 8 MiB raw image whose
# container starts at offset 0, with payload.elf and notes.txt copied in.
create() {
    hdiutil create -quiet -size 8m -fs "$2" -volname "$3" -layout NONE \
        -srcfolder "$work/src" -format UDRW "$work/$1"
}

# apfs.img: case-insensitive APFS volume ZRAX.
create apfs.dmg APFS ZRAX
attach "$work/apfs.dmg"
mkdir -p "$mnt/Applications/Zrax.app/Contents/MacOS" "$mnt/Library" "$mnt/bin" \
    "$mnt/links" "$mnt/many"
ditto --hfsCompression "$work/zrax.macho" "$mnt/Applications/Zrax.app/Contents/MacOS/Zrax"
ditto --hfsCompression "$work/large.macho" "$mnt/Library/large.macho"
ditto --hfsCompression "$work/huge.macho" "$mnt/Library/huge.macho"
ln "$mnt/payload.elf" "$mnt/links/hardlink.elf"
ln -s ../payload.elf "$mnt/links/symlink.elf"
for i in $(seq -w 0 159); do
    printf 'zrax APFS fixture note %s\n' "$i" > "$mnt/many/note-$i.txt"
done
# Write fragmented.elf a block at a time, each block synced and followed by
# a synced one-block spacer file, so that its blocks are not adjacent and
# it needs one extent per block. The spacers are deleted afterwards.
python3 -I - "$work/fragmented.elf" "$mnt/bin/fragmented.elf" "$mnt/spacers" <<'PY'
import os
import sys
source, target, spacers = sys.argv[1:]
data = open(source, "rb").read()
os.mkdir(spacers)
with open(target, "wb") as out:
    for i in range(0, len(data), 4096):
        out.write(data[i:i + 4096])
        out.flush()
        os.fsync(out.fileno())
        with open(f"{spacers}/{i // 4096}", "wb") as spacer:
            spacer.write(bytes(4096))
            spacer.flush()
            os.fsync(spacer.fileno())
PY
rm -rf "$mnt/spacers"
sync
hdiutil detach -quiet "$mnt"
cp "$work/apfs.dmg" apfs.img

# apfs-cs.img: case-sensitive APFS volume ZRAXCS; /CASE and /case differ
# only in case.
create apfs-cs.dmg "Case-sensitive APFS" ZRAXCS
attach "$work/apfs-cs.dmg"
mkdir -p "$mnt/CASE" "$mnt/case"
cp "$work/payload.elf" "$mnt/CASE/payload.elf"
cp "$work/zrax.macho" "$mnt/case/payload.elf"
sync
hdiutil detach -quiet "$mnt"
cp "$work/apfs-cs.dmg" apfs-cs.img

# encrypted.img: the volume replaced by an encrypted volume ZRAXENC (the
# synthetic passphrase "zrax-synthetic-passphrase"), which is never
# mounted, so nothing is copied into it. The
# container of 8 MiB allows one volume, so the first (which held
# payload.elf and notes.txt) is deleted first; its freed blocks keep their
# bytes.
create encrypted.dmg APFS ZRAXTMP
hdiutil attach -nomount -noverify -noautoopen -plist "$work/encrypted.dmg" > "$work/attach.plist"
read -r device container volume < <(python3 -I - "$work/attach.plist" <<'PY'
import plistlib
import sys
entities = plistlib.load(open(sys.argv[1], "rb"))["system-entities"]
hints = {e.get("content-hint"): e["dev-entry"] for e in entities}
container = hints["EF57347C-0000-11AA-AA11-00306543ECAC"]
volume = hints["41504653-0000-11AA-AA11-00306543ECAC"]
# The image's own device is the entity that is neither.
device = [e["dev-entry"] for e in entities if e["dev-entry"] not in (container, volume)]
print(device[0], container, volume)
PY
)
diskutil apfs deleteVolume "$volume" > /dev/null
diskutil apfs addVolume "$container" APFS ZRAXENC -passphrase zrax-synthetic-passphrase \
    -nomount > /dev/null
hdiutil detach -quiet "$device"
device=""
cp "$work/encrypted.dmg" encrypted.img

# The containers are mostly free space; they are committed compressed.
gzip -9 -n -f apfs.img apfs-cs.img encrypted.img
shasum -a 256 apfs.img.gz apfs-cs.img.gz encrypted.img.gz
