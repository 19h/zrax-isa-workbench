# EROFS fixtures

Small EROFS images for `tests/erofs.rs` and `web/tests/erofs.test.mjs`,
built with erofs-utils `mkfs.erofs` from a synthetic directory tree.
`generate.sh` rebuilds all six images.

## Contents

Every image holds the same tree. Every file is synthetic:

| Path | Contents |
| --- | --- |
| `/payload.elf` | `tests/fixtures/compressed/payload.elf`: a 256 B ELF64 header for x86-64 with no code |
| `/boot/payload.elf.gz` | `tests/fixtures/compressed/payload.elf.gz`, its gzip stream |
| `/notes.txt` | 44 B of ASCII text, not a recognized format |
| `/bin/link` | a symlink to `../payload.elf` |
| `/lib/big.elf` | `payload.elf`, then the 1000 lines `zrax erofs filler line 000` ... `999`: 27256 B |
| `/lib/mixed.elf` | `payload.elf`, 8192 B of LCG noise (seed 1), the 600 lines `mixed text line 000` ... `599`, 4096 B of LCG noise (seed 7): 24544 B |

The noise is `x(n+1) = (x(n) * 1103515245 + 12345) mod 2^31`, one byte per
step (bits 16-23 of `x(n+1)`); it does not compress, so the compressed
images store it in plain (uncompressed) pclusters. The recognized members,
in walk order, are `/payload.elf`, `/boot/payload.elf.gz`, `/lib/big.elf`
and `/lib/mixed.elf`.

| Image | `mkfs.erofs` options (besides the common ones) | Layouts exercised |
| --- | --- | --- |
| `plain.img` | none | Flat-plain and flat-inline (tail-packed) files, compact inodes, inline directories |
| `chunk.img` | `--chunksize=4096 -Eforce-chunk-indexes -Eforce-inode-extended` | Chunk-based files with 8-byte chunk indexes, extended inodes |
| `lz4.img` | `-zlz4hc,level=12 -C16384 -Eztailpacking` | LZ4 with 16 KiB big pclusters, compact indexes, tail-packed pclusters, plain pclusters |
| `lz4-full.img` | `-zlz4 -Elegacy-compress` | LZ4 with full (8-byte, non-compact) lcluster indexes |
| `deflate.img` | `-zdeflate,level=9` | Raw DEFLATE pclusters, compressed-algorithm configuration records |
| `lzma-fragments.img` | `-zlzma -Eall-fragments` | MicroLZMA pclusters; every file is a fragment of the packed inode |

Common options: `--quiet -b4096 -T0 -U 5a524158-6572-6f66-8000-000000000000
--all-root`: 4 KiB blocks, build time and every file time 0, a fixed UUID
and root ownership, so the images are reproducible byte for byte.

## Generator and commands

Generated on 2026-10-13 with erofs-utils 1.9.4 (`mkfs.erofs 1.9.4`,
Homebrew build, available compressors lz4, lz4hc, lzma and deflate) on
macOS AArch64, with Perl 5 from macOS for the noise. From the repository
root:

```sh
tests/fixtures/erofs/generate.sh
```

`MKFS_EROFS` names another `mkfs.erofs` binary. The script builds the tree
in a temporary directory and runs `mkfs.erofs` once per image, as listed
above. Running it twice on 2026-10-13 produced identical files.

`fsck.erofs` 1.9.4 checks every image without errors, and
`fsck.erofs --extract` reproduces the tree.

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `plain.img` | 57344 | `2530384932596d19b96073aa3cd5a2365c1794048959a0bcba1ba11f3ae5ac41` |
| `chunk.img` | 69632 | `8ae89bb718baee5120249fdd00afc8e2745f81b775ef603f59297dbe277db0ad` |
| `lz4.img` | 28672 | `fc58ae2373c8670a63948542d610d96c4ff8ca2eafcb34d7b0ded772d7c65e88` |
| `lz4-full.img` | 28672 | `a741b4e919cd744d4420eb1aec4e206fd71269b712dbe17dfdf5ce9ffe502eb8` |
| `deflate.img` | 24576 | `ccd7d3e1c6804a5d20cac8c2c7558105e0f1886fe187de3bdeef2f404f7f0bcc` |
| `lzma-fragments.img` | 20480 | `de9640901570fec3dd408f23722e3396522befbba97d3b39a046cf853139a5a9` |
