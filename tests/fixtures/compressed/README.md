# Compressed-stream fixtures

Synthetic fixtures for `tests/compressed.rs` and
`web/tests/compressed.test.mjs`. `generate.sh` rebuilds them all.

## Payload

`payload.elf` is 256 B: a 64-byte ELF64 little-endian header with
`e_machine = 0x3E` (x86-64), followed by 192 B of the repeated ASCII text
`zrax compressed fixture `. It has no program headers or code; it is not a
runnable program.

## Generators and commands

Generated on 2026-10-12, macOS AArch64:

| File | Command | Tool version |
| --- | --- | --- |
| `payload.elf.gz` | `gzip -n -9 -c payload.elf` | Apple gzip 487.40.2 |
| `payload.elf.xz` | `xz -9 -c --check=crc64 payload.elf` | XZ Utils 5.8.2 |
| `payload.elf.bcj.xz` | `xz -c --check=sha256 --x86 --lzma2=preset=6 payload.elf` | XZ Utils 5.8.2 |
| `payload.elf.concat.xz` | `cat payload.elf.xz payload.elf.xz` | — |
| `payload.elf.lzma` | `lzma -9 -c payload.elf` | XZ Utils 5.8.2 |
| `payload.elf.lz4` | `lz4 -q -9 -c --content-size payload.elf` | lz4 1.10.0 |
| `payload.elf.legacy.lz4` | `lz4 -q -l -9 -c payload.elf` | lz4 1.10.0 |
| `payload.elf.zst` | `zstd -q -19 -c --check payload.elf` | Zstandard 1.5.7 |
| `payload.elf.bz2` | `bzip2 -9 -c payload.elf` | bzip2 1.0.8 |
| `payload.elf.lzo` | `lzop -9 -c payload.elf` | lzop 1.04, LZO 2.10 |
| `payload.elf.lzfse` | `compression_tool -encode -a lzfse -i payload.elf -o payload.elf.lzfse` | macOS (Darwin 27.2) `compression_tool`, which emits an LZVN `bvxn` block for this input size |

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `payload.elf` | 256 | `cf8da6f7bf290dc9d4ff29eda38b156a91feb830bfb79f7ad9a1aaf009cd9ab8` |
| `payload.elf.gz` | 69 | `eb48146ac61b46113c8cb96419c89bbea89a6c80d42b9d92dd8a94b53d9bdd33` |
| `payload.elf.xz` | 128 | `d65e681e5bd6682e2d246afa3e987496c030b75aba80b316389446355622b5f1` |
| `payload.elf.bcj.xz` | 152 | `e7d9053770290a34360ca18f47a671cc1e05b5c1f9d4de3bbd24ded0493f58bf` |
| `payload.elf.concat.xz` | 256 | `5d93dba36881477218af316df2c606f05a0ac3f4e3e6eec1b0bea15fef864ad7` |
| `payload.elf.lzma` | 73 | `08f8f0992cf139af6e945478116e7a880a4f5f8b06833a77ab89d379591ea599` |
| `payload.elf.lz4` | 91 | `12100a6e9d9f405dff6c7df35082006596ba54fab33273732fcd8dd9e0e6e490` |
| `payload.elf.legacy.lz4` | 72 | `3b3bb09b7156b425bbf69c5aa332c9cfffd1111d6e7c4dc6369e843c1b395fac` |
| `payload.elf.zst` | 73 | `294f570ac88336fa60e377aea217b7445523b8b16892f1da46e66484e459c0ab` |
| `payload.elf.bz2` | 105 | `f7dbf00332304b67f1e1ceaf9e11ff0dc1a3095d8ae38dcd30eb02cf6fac1df7` |
| `payload.elf.lzo` | 126 | `c996327fb51f0c627e5c65f6e0495ba6f2bd136e472ec836b561242aa26861ed` |
| `payload.elf.lzfse` | 88 | `87829390d43f00e93de580c65115b9b38c85c69d05b6a070ae10eea2a01bf729` |
