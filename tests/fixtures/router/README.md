# Router firmware fixtures

Synthetic fixtures for `tests/router.rs` and `web/tests/router.test.mjs`.
`generate.sh` rebuilds them all and is deterministic: a run in a scratch
directory on 2026-10-13 reproduced every file below byte for byte.

## Payloads

| File | Contents |
| --- | --- |
| `kernel.elf` | 256 B: a 52-byte ELF32 big-endian header with `e_machine = 8` (MIPS), then the repeated ASCII text `zrax router kernel fixture ` |
| `loader.elf` | 128 B: the same header kind, then `zrax router loader fixture ` |
| `rootfs.bin` | 512 B of the repeated ASCII line `zrax router rootfs fixture`; not a filesystem |
| `kernel.elf.lzma` | `kernel.elf` as a raw LZMA-alone stream with OpenWrt's kernel properties `lc=1 lp=2 pb=2` (properties byte `0x6D`, 8 MiB dictionary, unknown size, end marker) |
| `loader.gz` | `loader.elf` gzip-compressed (level 9, mtime 0) plus one NUL byte, as the OpenWrt bcm47xx recipe appends to `loader.gz` |

No payload contains runnable code; the ELF headers only give the kernel an
explicit architecture field.

## Wrappers

`build_images.py` writes every wrapper field by field, following the
OpenWrt firmware-utils writers at
`a1d9589f1ea1b96529ac10fef5d164ff3aa03dc7`. It is an independent Python
re-implementation, cross-checked against the upstream tools (below). MD5
digests are real (Python `hashlib`) but the classifier does not verify
them. Board IDs, hardware IDs, vendor and support-list strings are
synthetic and name no real device.

| File | Writer followed | Layout |
| --- | --- | --- |
| `image.trx` | `trx.c` | TRX v1: `loader.gz`, `kernel.elf.lzma`, `rootfs.bin`, each zero-padded to 4 B, image padded to 4 KiB; CRC-32/JAMCRC from offset 12 |
| `image-v2.trx` | `trx.c -2` | TRX v2: the same parts plus a 32-byte Cybertan code header (`W54G`, `U2ND`) as the fourth partition; CRC with the 8 bytes at `offsets[3] + 22` counted as `0xFF` |
| `image.chk` | `mkchkimg.c` | Netgear CHK around `image.trx`, board ID `U12H072T00_NETGEAR` (the tool default), region 1, version digits 99, no root filesystem |
| `image.seama` | `seama.c -s` | SEAMA seal (`signature=zrax_router_fixture`) holding one entity (`dev=/dev/mtdblock/1`, `type=firmware`) whose image is `kernel.elf.lzma` |
| `tplink-v1.bin` | `mktplinkfw.c -s` | v1 header (vendor `TP-LINK Technologies`, `ver. 1.0`, hardware ID `0x5A520001`, load/entry `0x80060000`, firmware length `0x3C0000`), kernel at 0x200, `rootfs.bin` at 0x1000, salted MD5 |
| `tplink-v2.bin` | `mktplinkfw2.c -s` | v2 header (`0xFF`-filled, version word 2, `0x55AA`/`0xA5` constants), kernel at 0x200, `rootfs.bin` at 0x1000, salted MD5 |
| `safeloader.bin` | `tplink-safeloader.c` | Factory image with vendor information `vendor:ZRAX\r\n` and partitions `partition-table`, `soft-version` (numeric 1.0.0, 2026-10-12, revision 1), `support-list`, `os-image` (a combined `mktplinkfw -c -O` header plus `kernel.elf.lzma`) and `file-system` (`rootfs.bin`); salted MD5 |

## Generator and commands

Generated on 2026-10-12, macOS AArch64, with Python 3.14.7 and XZ Utils
5.8.2:

```sh
python3 build_images.py payloads .
xz --format=lzma --lzma1=preset=6,lc=1,lp=2,pb=2 -c kernel.elf > kernel.elf.lzma
python3 build_images.py wrappers .
```

## Cross-check against the upstream tools

On 2026-10-13 the firmware-utils sources at
`a1d9589f1ea1b96529ac10fef5d164ff3aa03dc7` (`trx.c`, `otrx.c`,
`mkchkimg.c`, `seama.c`, `mktplinkfw.c`, `mktplinkfw2.c`,
`mktplinkfw-lib.c`, `tplink-safeloader.c`, `md5.c`) were built with Apple
clang on macOS AArch64 (`cc -fgnu89-inline`, with two local shim headers
standing in for glibc's `<byteswap.h>` and `<endian.h>`). The tools were
not committed. Results:

| Fixture | Upstream command | Result |
| --- | --- | --- |
| `image.trx` | `trx -o out -f loader.gz -f kernel.elf.lzma -f rootfs.bin` | Byte-identical; `otrx check` reports a valid TRX version 1 |
| `image-v2.trx` | `trx -2 -o out -f loader.gz -f kernel.elf.lzma -f rootfs.bin -f <the 32-byte Cybertan header>` | Byte-identical |
| `image.chk` | `mkchkimg -o out -k image.trx` | Byte-identical |
| `image.seama` | `seama -i <kernel.elf.lzma> -m dev=/dev/mtdblock/1 -m type=firmware`, then `seama -s out -m signature=zrax_router_fixture -i <that>.seama` | Byte-identical; `seama -d` matches the entity MD5 |
| `tplink-v1.bin` | `mktplinkfw -i tplink-v1.bin` | Header fields as listed above; `MD5Sum1 (ok)` |
| `tplink-v2.bin` | `mktplinkfw2 -i tplink-v2.bin` | Header fields as listed above; `MD5Sum1 (ok)` |
| `safeloader.bin` | `tplink-safeloader -x safeloader.bin -d out` | Extracts the five partitions; the salted MD5 was checked separately with Python `hashlib` |

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `kernel.elf` | 256 | `63341814a6787e4b1f77802b10a3c496b0887172141c48f5b4caeddd692faf71` |
| `loader.elf` | 128 | `4acf6b0849379da641bd25b32ed6b0cc885fdd8464b16ab64ff437a50034cde1` |
| `rootfs.bin` | 512 | `1db304c2fd9cee500abaf6b653866df64b356368a13877f14601f980e13a1996` |
| `kernel.elf.lzma` | 79 | `51b81dd56add295e25f5c89903a2a635c24282d0183d3776862c6923c4e8b957` |
| `loader.gz` | 73 | `b70780fbe82e83c5aff8df3820fa285f7de459eaec4ca65fe9fb660a12bb38b4` |
| `image.trx` | 4096 | `b81fca93973cb532c6a6f2739d60af8e267c63aca636f52f972ec7d91a63e5eb` |
| `image-v2.trx` | 4096 | `7bbdee8191e31c902038a0441d4ca12fc048738aef625b04fd2ba7cdc72cce07` |
| `image.chk` | 4154 | `2f33e83a7df2a7a4a4b5dc061d8335799cb6aeec093d42e2542892accaaf71e0` |
| `image.seama` | 187 | `205f4d561b805e82ddf660ea9cfc65345d39c35643667e456e7ea9615fe6c36f` |
| `tplink-v1.bin` | 4608 | `4bab241b77a1cbbad700b42292aedbc147f902765bc6d0a06dc3d0a3b5b9ca53` |
| `tplink-v2.bin` | 4608 | `2fa86790c9aeb32e381c1b8047f4865e7b1188a82f843d526739de376b6284ab` |
| `safeloader.bin` | 9389 | `67d55c9a73890683a472b5011dfde7557391250d977aa46c6773c5ab51f354dc` |
