# NTFS volume fixtures

Three small NTFS volumes for `tests/ntfs.rs` and `web/tests/ntfs.test.mjs`,
formatted by `mkntfs` and filled through the `ntfs-3g` FUSE driver from
synthetic inputs. `generate.sh` rebuilds all three.

## Contents

Every member is synthetic and built by `generate.sh` from committed
fixtures:

| Input | Built from |
| --- | --- |
| `payload.elf` | `tests/fixtures/compressed/payload.elf`: a 256 B ELF64 header for x86-64 with no code |
| `app.exe` | the 428 B x86-64 PE32+ image in `tests/fixtures/uefi/pe32-sections.bin` (bytes 4 to 432, after the FFS section header), padded with the repeated text `zrax synthetic PE overlay ` to 12 KiB |
| `zrax.macho` | `tests/fixtures/apple/kernel.macho` (an 8 KiB arm64 Mach-O header with no code), padded with `zrax synthetic compressed member ` to 100 KiB |
| `stream.macho` | `kernel.macho` as it is |
| `fragmented.elf` | `payload.elf`, padded with `zrax synthetic fragmented member ` to 40 KiB (the first 10 KiB in `ntfs-512.img`) |
| `notes.txt` | 43 B of ASCII text, not a recognized format |

`ntfs.img`: 4 MiB, label `ZRAX`, 512 B sectors (8,191 of them and the
backup boot sector), 4 KiB clusters, 1 KiB MFT records, `$MFT` of 299
records in one run at cluster 4, `$MFTMirr` at cluster 0x1FF.

| Path | What ntfs-3g stored |
| --- | --- |
| `/payload.elf` | `payload.elf`, resident in MFT record 64; its value crosses the end of the record's first 512 B stride |
| `/links/hardlink.elf` | a second `$FILE_NAME` in record 64 (`ln`) |
| `/Program Files/Zrax/app.exe` | `app.exe`, non-resident in one run |
| `/notes.txt` | `notes.txt`, resident, and the named stream `payload.macho` holding `stream.macho` in one run |
| `/compressed/zrax.macho` | `zrax.macho` in a directory marked compressed: LZNT1, compression unit 4 (16 clusters), two units in four runs (stored, sparse, stored, sparse) |
| `/sparse.elf` | `payload.elf`, extended to 128 KiB with `truncate`, then 4 KiB of `zrax synthetic sparse tail `: `ATTR_IS_SPARSE`, runs stored, sparse (31 clusters), stored |
| `/links/symlink.elf` | `ln -s ../payload.elf`: ntfs-3g writes an Interix symbolic link, a system file whose data is `IntxLNK\1` and the UTF-16 target |
| `/links/winlink.elf` | an empty file given a reparse point through `system.ntfs_reparse_data`: tag `IO_REPARSE_TAG_SYMLINK` (0xA000000C), relative target `..\payload.elf` |
| `/many/file000.txt` to `/many/file199.txt` | 30 B of text each, resident |
| `/deleted.elf` | `payload.elf`, deleted again: its record is not in use |
| `/bin/fragmented.elf` | `fragmented.elf`, written one cluster at a time with a 2 KiB spacer file after each cluster (the spacers deleted afterwards): five runs |
| `/bin/linked.exe` | `app.exe` with three further hard links named 200 `L`s and a digit, and the named streams `one`, `payload.elf` (holding `payload.elf`) and `three`: the names and streams do not fit record 296, so ntfs-3g adds a non-resident `$ATTRIBUTE_LIST` and moves two names and two streams, `payload.elf` among them, to extension records 297 and 298 |

`ntfs-4k.img`: 2 MiB, label `ZRAX4K`, 4096 B sectors (`mkntfs -s 4096`), so
4 KiB clusters and 4 KiB MFT records with eight update sequence strides;
`$MFT` of 70 records in two runs (clusters 4 and 0x143).

| Path | What ntfs-3g stored |
| --- | --- |
| `/payload.elf` | `payload.elf`, resident |
| `/Program Files/Zrax/app.exe` | `app.exe`, one run |
| `/compressed/zrax.macho` | `zrax.macho`, LZNT1 |

`ntfs-512.img`: 2 MiB, label `ZRAX512`, 512 B clusters (`mkntfs -c 512`),
so each 1 KiB MFT record spans two clusters and a compression unit is
8 KiB; `$MFT` of 90 records at cluster 0x20.

| Path | What ntfs-3g stored |
| --- | --- |
| `/payload.elf` | `payload.elf`, resident |
| `/compressed/zrax.macho` | `zrax.macho`, LZNT1 in 13 units of 8 KiB |
| `/bin/fragmented.elf` | the first 10 KiB of `fragmented.elf`, written one 512 B cluster at a time with 2 KiB spacers: 19 runs |

The recognized members, in MFT record order, are listed in
`tests/ntfs.rs` (`ntfs_members`) and `web/tests/ntfs.test.mjs`.

What is synthetic beyond the inputs: after ntfs-3g wrote each volume,
`generate.sh` overwrites the 128 KiB `$UpCase` table (the data of MFT
record 10, located with `ntfsinfo -i 10`) with zeros. gzip cannot compress
the table's ascending 16-bit values, which made each file about 120 KiB
larger; the classifier never reads it. The committed volumes are otherwise
as ntfs-3g left them. Because of the zeroed table, ntfs-3g refuses to open
them (`ntfsinfo -m`: "Corrupted file $UpCase"); 7-Zip 26.03 (`7zz l`) lists
`ntfs.img` and `ntfs-512.img` (it does not open volumes with 4096 B
sectors).

## Generator and commands

Generated on 2026-10-13 in the Docker image `arm64v8/ubuntu:24.04`
(`sha256:b44ffd8afd8ddbe91a08120a3aba4d4d105c17ccfadd835beb5097da5d196d65`)
on macOS AArch64 (OrbStack), with the Ubuntu packages ntfs-3g
`1:2022.10.3-1.2ubuntu3.2` (mkntfs, ntfs-3g and ntfsinfo v2022.10.3), attr
`1:2.5.2-1ubuntu0.1`, coreutils `9.4-3ubuntu6.3`, util-linux
`2.39.3-9ubuntu6.6` and gzip `1.12-1ubuntu3.2`. The FUSE mount needs a
privileged container. From the repository root:

```sh
docker run --rm --privileged -v "$PWD/tests/fixtures:/fixtures" arm64v8/ubuntu:24.04 bash -c \
    'apt-get update && apt-get install -y ntfs-3g=1:2022.10.3-1.2ubuntu3.2 attr=1:2.5.2-1ubuntu0.1 \
     && bash /fixtures/ntfs/generate.sh'
```

On a Linux host with ntfs-3g and FUSE, `generate.sh` runs directly as root
(`MKNTFS`, `NTFS3G` and `NTFSINFO` name other tool binaries).

The script:

1. builds the inputs above in a temporary directory;
2. formats each image with `mkntfs -F -q -T -L <label>` (`-T` sets the
   volume's own times to the epoch), plus `-s 4096` or `-c 512` for the
   variants;
3. mounts it with `ntfs-3g -o compression,streams_interface=windows`, so
   that files in a directory whose attributes include 0x800 are compressed
   and named streams are written as `file:stream` paths, and writes the
   files with `cp`, `cat`, `truncate`, `ln`, `ln -s`, `setfattr` and `dd`;
4. prints the attributes of the interesting files with `ntfsinfo -v -F`;
5. zeroes each `$UpCase` table and writes the images with `gzip -9 -n`.

The images are not reproducible byte for byte: the volume serial numbers,
the times of the files written and the security descriptors differ from run
to run. The tests check structure and member contents, not these bytes.

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `ntfs.img` (inside `ntfs.img.gz`) | 4194304 | `7b8aaadc53d92b9008d2530c76b1810d70214943bf84a602557c5c119e201580` |
| `ntfs-4k.img` (inside `ntfs-4k.img.gz`) | 2097152 | `166461f9546ef5e69977d0ef17ebfa931cb549790fdafaacb1680822c988bdaa` |
| `ntfs-512.img` (inside `ntfs-512.img.gz`) | 2097152 | `34d77d8591f3a9934db74ba353eec6dbc222be5de00775f02b1449042506920c` |
| `ntfs.img.gz` | 23779 | `eaf8a1b0304e4963c35f7a115a8282fcd84e49fdab05af8cdd9d40bdc9750480` |
| `ntfs-4k.img.gz` | 8206 | `5e78780515d476f0eb0fe5c84ac1e687e4d89b4f036ae8804b37911bdc9b4540` |
| `ntfs-512.img.gz` | 8521 | `e64e0960e31b9614ae199c06cb093d2a76cbcce47567290c19d4c7aae0850b20` |
