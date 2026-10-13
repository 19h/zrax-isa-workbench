# Virtual disk fixtures

Disk images made by `qemu-img` and `qemu-io` for `tests/vdisk.rs` and
`web/tests/vdisk.test.mjs`. Every image holds the same 170 KiB raw disk
(`disk.img`), so each parser's guest disk can be compared byte for byte
with it. Everything is committed gzip-compressed (`gzip -9 -n`), because
the images are mostly zeros. `generate.sh` rebuilds them. Differencing VHD
and VHDX disks, an oversized QCOW2 and every corrupted variant are built in
the test files from the documented layouts.

## The raw disk

`disk.img` is 340 sectors of 512 B (174080 B; 5 cylinders, 4 heads and 17
sectors, the geometry the VHD specification's CHS algorithm gives for that
size, so `qemu-img` keeps the VHD images at exactly this size):

| Sectors | Contents |
| --- | --- |
| 0 | MBR (UEFI 2.10 Table 5.1): bootstrap code area all zeros, disk signature `0x5A524158`, one inactive record of OS type `0x01` (FAT12) for sectors 64-319, boot signature `55 AA` |
| 1-63 | zeros |
| 64-319 | `tests/fixtures/fat/fat12.img` (see `tests/fixtures/fat/README.md`): a FAT12 volume whose files include the synthetic x86-64 ELF header `payload.elf` |
| 320-339 | zeros |

Nothing in the images is third-party data: the FAT volume and its files
are the synthetic fixtures of the FAT tests, and the rest is what QEMU
writes.

## Images

| File | Command (from `generate.sh`) | Layout |
| --- | --- | --- |
| `qcow2-v3.qcow2.gz` | `qemu-img convert -f raw -O qcow2 -o compat=1.1,cluster_size=4096` | QCOW2 version 3, 4 KiB clusters, 4 data clusters |
| `qcow2-v2.qcow2.gz` | `... -O qcow2 -o compat=0.10,cluster_size=512` | QCOW2 version 2, 512 B clusters, 6 L1 entries |
| `qcow2-deflate.qcow2.gz` | `... -c -O qcow2 -o cluster_size=4096` | QCOW2 version 3, deflate-compressed clusters |
| `qcow2-zstd.qcow2.gz` | `... -c -O qcow2 -o cluster_size=4096,compression_type=zstd` | QCOW2 version 3, zstd-compressed clusters |
| `qcow2-extl2.qcow2.gz` | `... -O qcow2 -o cluster_size=16384,extended_l2=on` | QCOW2 version 3, extended L2 entries (32 subclusters of 512 B) |
| `qcow2-overlay.qcow2.gz` | `qemu-img create -f qcow2 -o cluster_size=4096 -b qcow2-v3.qcow2 -F qcow2`, then `qemu-io -c 'write -q -P 0x5a 4096 512'` | QCOW2 overlay with backing file `qcow2-v3.qcow2`; one cluster allocated, holding sector 8 = `0x5A` |
| `vmdk-sparse.vmdk.gz` | `... -O vmdk -o subformat=monolithicSparse` | VMDK sparse extent version 1, 64 KiB grains, embedded descriptor |
| `vmdk-stream.vmdk.gz` | `... -O vmdk -o subformat=streamOptimized` | VMDK sparse extent version 3, zlib-compressed grains with markers (QEMU writes the grain directory in place, not `GD_AT_END`) |
| `vhd-dynamic.vhd.gz` | `... -O vpc -o subformat=dynamic` | VHD dynamic, creator `qemu` 5.3, 2 MiB blocks, one BAT entry |
| `vhd-fixed.vhd.gz` | `... -O vpc -o subformat=fixed` | VHD fixed: the raw disk and a 512 B footer |
| `vhdx-dynamic.vhdx.gz` | `... -O vhdx -o subformat=dynamic,block_size=1M,log_size=1M` | VHDX dynamic, 1 MiB blocks, BAT at 2 MiB, metadata at 3 MiB, block 0 at 8 MiB |
| `vhdx-fixed.vhdx.gz` | `... -O vhdx -o subformat=fixed,block_size=1M,log_size=1M` | VHDX fixed (`LeaveBlockAllocated`), block 0 at 9 MiB |
| `vdi-dynamic.vdi.gz` | `... -O vdi` | VDI header 1.1, dynamic, one 1 MiB block at 0x400 |
| `vdi-static.vdi.gz` | `... -O vdi -o static=on` | VDI header 1.1, fixed |

`generate.sh` checks every image with `qemu-img compare` against the raw
disk (naming the format, since `qemu-img` probes a fixed VHD as raw) and
every QCOW2 image with `qemu-img check`.

## Generator and commands

Generated on 2026-10-13 on macOS 27.2 (build 26B5101f), AArch64, with QEMU
11.1.1 (`qemu-img` and `qemu-io` of the Homebrew `qemu` 11.1.1 formula)
and Apple gzip 487.40.2. From the repository root:

```sh
QEMU_IMG=/opt/homebrew/bin/qemu-img QEMU_IO=/opt/homebrew/bin/qemu-io \
    tests/fixtures/vdisk/generate.sh
```

QEMU writes random identifiers (VHD unique IDs, VHDX GUIDs, VDI UUIDs,
VMDK content IDs) and the current time into most of these formats, so the
images differ on every run; only `disk.img` reproduces byte for byte.

## Sizes and SHA-256

| File | Size (B) | SHA-256 | Uncompressed (B) | Uncompressed SHA-256 |
| --- | --- | --- | --- | --- |
| `disk.img.gz` | 1118 | `f5a9102ae4cbb4abcd2f4b5c2443bc9ef994ab084ea9e5b7e00949281c5ed498` | 174080 | `181a1a04eaff5c36a7f3fb6d2a6fae639bfd9a1274bfd3099a55cb409e725e51` |
| `qcow2-v3.qcow2.gz` | 1012 | `bbfa3c7f0290e806cc7aab117ef40e729fcfb07ed74f6ed3e5dae5f7c94cf1db` | 36864 | `32ba6aa196edf16c51a8515f01d3f3632e41bb38494b454eb7f13c1ae6b4e6d9` |
| `qcow2-v2.qcow2.gz` | 1037 | `d8159f7dd4b3cd6916ccc920e4616961974e4e88505e793a4ba89d0acdde2298` | 19456 | `5e7261a9a1bd06d753d2ccd374ab6c420c32c3eb40b53bf2b649efdd2bc623de` |
| `qcow2-deflate.qcow2.gz` | 1245 | `26bdeeffb122a83be8e02ed7d8ef82c98a4c99db09b4594aa08ed55026a71b7b` | 22016 | `c1663481938b0a3756dc37f2bec1da3c9413662dc4a9427c016b9af6ff24c29b` |
| `qcow2-zstd.qcow2.gz` | 1251 | `ee5bea87051d74aed3cd0c73db31465e515aff56d0658fbe30184fcfd4d3e379` | 22016 | `8b2f68c2d45280f64e057bfdab88d9864f566688969586f034c2d367f0bc54d7` |
| `qcow2-extl2.qcow2.gz` | 1267 | `2cb3b32cea963d0e88f6d896f3353f1639285a5ecc4beb0ecaf2242493db88bf` | 122880 | `8e96cf8792b47b3f08f478e8d0e580c87a50129dcaa8a06a5107c176412c53cc` |
| `qcow2-overlay.qcow2.gz` | 170 | `365dd5bad8140b2e1bc1e7c8942df1a28afafa6273dbe453039d99ee9dcfd4a8` | 24576 | `14a5507e0a570b2c7858f1ff61728f281932af7382c4d6680c364ef1be3091cf` |
| `vmdk-sparse.vmdk.gz` | 1373 | `b51e4af90cf50425c5531672643defe7e0f82ae5d21d9c6af38ba3262af30cdd` | 131072 | `ad570de7dda1de66dd491ad17d83cf790d004844a16c402753c1cd7419a54a34` |
| `vmdk-stream.vmdk.gz` | 1501 | `f63dab246f42f7d3293804d224c31d09a0179eeaaa49d7d5159f8916324d8731` | 131072 | `68be976ab848e7398e0842b9aa291e747ad48e2f282e808627579fbff0af7b4a` |
| `vhd-dynamic.vhd.gz` | 3166 | `ba310b3a76e672696f8040955f9cb125fb1d67cfdc5adfe9d9b421401e3087ed` | 2100224 | `7444d841ad6df403cbbf61dec5f3585332a8869e565a72ce826fc034b78e8ff4` |
| `vhd-fixed.vhd.gz` | 1196 | `3fee3d53832fba3286ae0466c0e31b4c215d15c92c468455299f27177e87e144` | 174592 | `c71c771cfbba9f622d63fbeb5fd5f4ccc8b194ea9da86a5896975c4253351b5c` |
| `vhdx-dynamic.vhdx.gz` | 10687 | `87570685bc4b5f4d43a1b00adbabfe921f946026c045daca0eaf76758f8794c5` | 9437184 | `edad940fb88c442599637dcb117d4b565f813733d429019be12a13ebcb78cb1a` |
| `vhdx-fixed.vhdx.gz` | 11705 | `9dd5aa4f464887e4bbf4e0b222058996c33b7631bba31aa52308c758ff8a2cc3` | 10485760 | `2d01e35e947f0b98324c6e53a9050e0ea93ca00095eb4ab2d13abef93fe17d78` |
| `vdi-dynamic.vdi.gz` | 2082 | `aae44b3a56c493fa8260c145e211cfebd0ae045a906e7113b20037b0f9cc6b78` | 1049600 | `ed32af43b6dbc328e87562271d21e323651615ce3886299981ff64e9afcff5a8` |
| `vdi-static.vdi.gz` | 2076 | `40dd0df9fa6bc217cbfb8e32aaabdfd3445dddbc55de0df93a1c118316eea5cb` | 1049600 | `3f4a9d7350f7deabdc84a07c66497f9103895a8bc129ba5ed8881e1f4477cffa` |
