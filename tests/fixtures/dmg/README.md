# Apple disk image fixtures

UDIF disk images made by `hdiutil` for `tests/dmg.rs` and
`web/tests/dmg.test.mjs`. Every image is a 1 MiB disk (2048 sectors of
512 B) whose one volume, named `ZRAX`, holds a copy of
`tests/fixtures/compressed/payload.elf` (a 256 B ELF64 header for x86-64
with no code; see `tests/fixtures/compressed/README.md`). Everything is
committed gzip-compressed (`gzip -9 -n`). `generate.sh` rebuilds them.
Images with a data fork CRC-32, a binary resource fork, an Encrypted
Encoding version 1 footer, other segments, oversized partitions and every
corrupted variant are built in the test file from the documented layouts.

Nothing in the images is third-party data: the volume holds the synthetic
ELF header, and the rest is what `hdiutil` writes (partition maps, HFS+ or
FAT metadata, the property list and the trailer).

## Images

| File | Command (from `generate.sh`) | Layout |
| --- | --- | --- |
| `hfs-udzo.dmg.gz` | `hdiutil create -size 1m -fs HFS+ -volname ZRAX -srcfolder src -format UDZO` | GPT disk (8 block tables: protective MBR, primary GPT header and table, free space, `disk image (Apple_HFS : 4)`, free space, backup GPT table and header); zlib chunks |
| `hfs-udbz.dmg.gz` | `... -format UDBZ` | the same disk; bzip2 chunks |
| `hfs-ulfo.dmg.gz` | `... -format ULFO` | the same disk; LZFSE chunks (`bvx2` and `bvxn` blocks) |
| `hfs-ulmo.dmg.gz` | `... -format ULMO` | the same disk; chunk type `0x80000008`, each an xz stream |
| `hfs-udco.dmg.gz` | `... -format UDCO` | the same disk; ADC chunks |
| `hfs-udro.dmg.gz` | `... -format UDRO` | the same disk; raw and zero-fill chunks (the HFS+ volume in 16 chunks, `payload.elf` in the raw chunk at sector 912 of the volume) |
| `fat-udzo.dmg.gz` | `hdiutil create -size 1m -fs MS-DOS -volname ZRAX -srcfolder src -format UDZO` | MBR disk (2 block tables: `Master Boot Record (MBR : 0)` and ` (DOS_FAT_32 : 1)`, a FAT12 volume by its cluster count); zlib chunks; the volume's chunk is the 460 B at file offset 0x1E |
| `segmented.dmg.gz`, `segmented.002.dmgpart.gz` | `hdiutil segment -segmentSize 32k -o segmented hfs-udro.dmg` | `hfs-udro.dmg` in two segments. The first holds the 8 block tables, the first 32 KiB of the data fork and a trailer for segment 1 of 2; the second the rest of the data fork (running data fork offset 32768), a property list whose `resource-fork` dictionary is empty, and a trailer for segment 2 of 2 that repeats the master checksum |
| `encrypted.dmg.gz` | `printf zrax \| hdiutil create -size 1m -fs HFS+ -volname ZRAX -srcfolder src -format UDZO -encryption AES-128 -stdinpass` | Encrypted Encoding version 2 (`encrcdsa`), AES-128, 512 B blocks, one key protector, 14449 B of data encrypted in 29 blocks at 0x1DE00 (the file ends with the last block); the passphrase is `zrax` |

In every unencrypted image the data fork starts at offset 0, the XML
property list follows it, and the trailer ends the file. `hdiutil` stores
no data fork checksum (type 0) and a CRC-32 master checksum; every block
table carries a CRC-32 of its decoded partition, free-space chunks left
out. `hdiutil` (macOS 27.2) writes `-format UDRW` images as raw disks
without a UDIF trailer (`hdiutil imageinfo`: `CRawDiskImage`), so there is
no UDRW fixture.

`generate.sh` checks every unencrypted image (the segmented one through
its first segment) with `hdiutil verify`.

## Generator and commands

Generated on 2026-10-13 on macOS 27.2 (build 26B5101f), AArch64, with the
system `hdiutil` (DiskImages framework 710, as `hdiutil info` reports it)
and Apple gzip 487.40.2. From the repository root:

```sh
tests/fixtures/dmg/generate.sh
```

`hdiutil` prints a deprecation warning for `create` on macOS 27.2 and
still writes the images. It writes random identifiers, the current time,
and for the encrypted image a random salt and keys, so the images differ
on every run.

## Sizes and SHA-256

| File | Size (B) | SHA-256 | Uncompressed (B) | Uncompressed SHA-256 |
| --- | --- | --- | --- | --- |
| `encrypted.dmg.gz` | 15547 | `39eb2584fca371d33013a5ea16ed3d65f55b0c36ddd20d682034a2d398dc7176` | 137216 | `ca956362a06c5d24401d2213660f39dace727fb91d55723b3197faebcca77521` |
| `fat-udzo.dmg.gz` | 1011 | `0e95b01da84192a4ad63c86645d3060460c9456ea3330e043a6fe4280d4ac1ab` | 4536 | `121ad92e2160f94dd51e19c2df3bcac15cdb52ddf40d1fc15587361a490882d7` |
| `hfs-udbz.dmg.gz` | 2299 | `28d6904051988aaaf9989bb0d4a3205545133629cb88b9d1fd3a5c26c22babcd` | 10137 | `db6e5ce12b7de0bfaade571e6a31a720b5ff748f9426286220a28f4a4a5f25ef` |
| `hfs-udco.dmg.gz` | 2164 | `97ee47145d97c4abe03b2f4818f6a5814b8df9de013c0a999ff9267447ca5185` | 56565 | `849e5775ff90136bfc65b6c25d3c4cb60e540ccb57e0c6ebd8182c7c2fabe40e` |
| `hfs-udro.dmg.gz` | 1830 | `702ee6524071603cf2217e56142f67dd3240b0612428eb1b59e641fa71029fb0` | 69670 | `5ec1f6a76e5c1894f7973f91adafbf0398336caaaa114846bd5bef640b37cfea` |
| `hfs-udzo.dmg.gz` | 2440 | `27492cab4727d763acf7f8927cce649ba0e0f8532011c67d2c31127d727d7c1b` | 14458 | `e401d61d807f36e9808ff8f5deb4d1e55e498eac6adff4ac26c82f2900a303d8` |
| `hfs-ulfo.dmg.gz` | 2623 | `939be232a935c1d4ff5d37e5585464521b1d5d4dbf33bc55a8daf49a2257c046` | 11383 | `b9b299436e33060ac658935c1bf6f4fb23edb9d00229e0ccfb7c9bede4d09b23` |
| `hfs-ulmo.dmg.gz` | 2329 | `9f0cee227cd12949ff332231ad39bff1e2b120f5e545fea0b4a039076b08168d` | 10421 | `6a993a5ee32884faf10f1ca2d484b2655d94c0f07301456b2af34dd2832c1724` |
| `segmented.002.dmgpart.gz` | 889 | `73215a5b566734154c5c61dbdd9af9f5f82feb9af8924b05dca0796adbcee3ae` | 28383 | `c14c53ccd0ac16a91faf7e0c84769de74748c5884c82f12d54d937aedb698f40` |
| `segmented.dmg.gz` | 1475 | `8c0ab3d7cf9337aee7bc8506e225dab753e6fb2a18fbbd0d3a3f7e8432df94d5` | 42022 | `dff37d8d763b8b29526f0db9d5a58022b9e79911de536b36e5d6b92f2c10f53c` |
