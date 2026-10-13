# APFS container fixtures

Small raw container images for `tests/apfs.rs` and
`web/tests/apfs.test.mjs`, created by macOS from synthetic inputs.
`generate.sh` rebuilds all three.

## Contents

Every member is synthetic and built by `generate.sh` from committed
fixtures:

| Input | Built from |
| --- | --- |
| `payload.elf` | `tests/fixtures/compressed/payload.elf`: a 256 B ELF64 header for x86-64 with no code |
| `zrax.macho` | `tests/fixtures/apple/kernel.macho` (an 8 KiB arm64 Mach-O header with no code), padded with the repeated ASCII text `zrax synthetic inline member ` to 24 KiB |
| `large.macho` | the same Mach-O, padded with `zrax synthetic resource fork member ` to 200 KiB |
| `huge.macho` | the same Mach-O followed by words picked by a linear congruential generator (`state = state * 1103515245 + 12345 mod 2^31`, word `(state >> 16) mod 12` of `zrax synthetic apfs resource fork chunk member stream extent block node tree`, each followed by a space) to 70 KiB |
| `fragmented.elf` | `payload.elf`, padded with `zrax synthetic fragmented member ` to 40 KiB |
| `notes.txt` | 43 B of ASCII text, not a recognized format |
| `many/note-000.txt` … `note-159.txt` | `zrax APFS fixture note NNN` and a newline, not a recognized format |

All three images are 8 MiB (2048 blocks of 4 KiB) with the container at
offset 0 (`-layout NONE`) and one volume, formatted by
`newfs_apfs (3288.40.17)` and last modified by `apfs_kext (3288.40.17)`.

`apfs.img` holds the case-insensitive volume `ZRAX`
(`APFS_INCOMPAT_CASE_INSENSITIVE`); its file-system tree has 704 records
in 16 nodes (an index root over 15 leaves), resolved through the volume
object map.

| Path | What macOS stored |
| --- | --- |
| `/payload.elf` | `payload.elf` in one extent; a second hard link `/links/hardlink.elf` (sibling records) |
| `/links/symlink.elf` | a symbolic link to `../payload.elf` |
| `/notes.txt`, `/many/note-*.txt` | the text files |
| `/Applications/Zrax.app/Contents/MacOS/Zrax` | `zrax.macho`, decmpfs type 7 (LZVN after the header): the `com.apple.decmpfs` attribute is a 300 B data stream, next to an empty `com.apple.ResourceFork` stream |
| `/Library/large.macho` | `large.macho`, decmpfs type 8: an embedded 16 B decmpfs header and four LZVN chunks in a 1,799 B resource fork stream |
| `/Library/huge.macho` | `huge.macho`, decmpfs type 8: two LZVN chunks in a 17,032 B resource fork stream of five blocks |
| `/bin/fragmented.elf` | `fragmented.elf` in ten one-block extents |

`apfs-cs.img` holds the case-sensitive volume `ZRAXCS`
(`APFS_INCOMPAT_NORMALIZATION_INSENSITIVE` only): `/payload.elf` and
`/notes.txt`, `/CASE/payload.elf` (`payload.elf`) and `/case/payload.elf`
(`zrax.macho`, uncompressed).

`encrypted.img` holds the encrypted volume `ZRAXENC` (`APFS_FS_ONEKEY`,
`APFS_FS_UNENCRYPTED` clear) with the synthetic passphrase
`zrax-synthetic-passphrase`; the container has `NX_CRYPTO_SW` and a
one-block keybag. The volume was never mounted; its superblock counts no
files or directories. It replaced the volume `ZRAXTMP` that `hdiutil`
created with `payload.elf` and `notes.txt`; that volume's freed blocks keep
their bytes and are not reachable from any superblock.

The recognized members, in walk order, are `/ZRAX/payload.elf`,
`/ZRAX/Applications/Zrax.app/Contents/MacOS/Zrax`,
`/ZRAX/Library/huge.macho`, `/ZRAX/Library/large.macho` and
`/ZRAX/bin/fragmented.elf` in `apfs.img`; `/ZRAXCS/payload.elf`,
`/ZRAXCS/CASE/payload.elf` and `/ZRAXCS/case/payload.elf` in
`apfs-cs.img`; and the opaque volume `/ZRAXENC` in `encrypted.img`.

## Generator and commands

Generated on 2026-10-13 on macOS 27.2 (build 26B5101f), AArch64, with the
system `hdiutil` (DiskImages framework 710), `newfs_apfs` and the APFS
kernel extension 3288.40.17 (as the volume superblocks record), `ditto`,
`diskutil` and Python 3.14.7. From the repository root:

```sh
tests/fixtures/apfs/generate.sh
```

The script:

1. builds the inputs above in a temporary directory with Python;
2. creates each 8 MiB raw read/write image (`UDRW`, which `hdiutil`
   stores as a raw disk image) with
   `hdiutil create -size 8m -fs <APFS | "Case-sensitive APFS"> -volname <name>
   -layout NONE -srcfolder <payload.elf and notes.txt> -format UDRW`;
3. for `apfs.img`, attaches it with `hdiutil attach -nobrowse -noverify
   -noautoopen -mountpoint`, writes the Mach-O files with
   `ditto --hfsCompression`, makes the links with `ln` and `ln -s`, writes
   the 160 notes with `printf`, writes `fragmented.elf` a block at a time
   (each block and a one-block spacer file synced with `fsync`), deletes
   the spacers, and detaches the image;
4. for `apfs-cs.img`, copies the two files with `cp` and detaches it;
5. for `encrypted.img`, attaches it without mounting, deletes its volume
   with `diskutil apfs deleteVolume`, adds the encrypted volume with
   `diskutil apfs addVolume <container> APFS ZRAXENC -passphrase
   zrax-synthetic-passphrase -nomount`, and detaches it.

The images are not reproducible byte for byte: UUIDs, timestamps,
transaction identifiers, the allocation of blocks and the encryption keys
differ from run to run. The tests check structure and member contents, not
these bytes.

## Sizes and SHA-256

The containers are committed as `gzip -9 -n` files, which `generate.sh`
writes; the tests decompress them.

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `apfs.img` (inside `apfs.img.gz`) | 8388608 | `9d3351bb22882ba0e117c60a5bc4148297fd75a5f774d2c5cbdc491e1817568f` |
| `apfs-cs.img` (inside `apfs-cs.img.gz`) | 8388608 | `c35971eda556aea9df55895ea520d810e87e221d95982a5f3f71a5b99db3baf2` |
| `encrypted.img` (inside `encrypted.img.gz`) | 8388608 | `5786ec852e6a0dd9aac5551d392a660592888dcb612fcab872a46cfeaa77480c` |
| `apfs.img.gz` | 42906 | `5a30e7a631db8d3b25906d1e4c70542bfd5adcc6e6167f30d36384912022cb5c` |
| `apfs-cs.img.gz` | 13255 | `df12336700bc8f640fb7fcd334af4ee5995244db2d3df9c45ac86892609afd27` |
| `encrypted.img.gz` | 37748 | `7113d33cf949baa0b2227056091434a4e29750628e3d2bd2998114ab70e422b8` |
