# RPM and Debian package payload fixtures

Synthetic payloads for `tests/rpm.rs` and `web/tests/rpm.test.mjs`, which
build the RPM lead and headers and the Debian ar archive around them from
the documented layouts. `generate.sh` rebuilds them all. No package is
committed: there is no RPM or dpkg tool on the generating machine, and the
headers are built by the tests.

## Contents

Both archives hold the same two files:

- `./usr/bin/hello`: a copy of `../compressed/payload.elf` (256 B: a
  64-byte ELF64 little-endian header with `e_machine = 0x3E`, x86-64, and
  192 B of repeated text; not a runnable program).
- `./usr/share/doc/hello/README`: the text `zrax synthetic package payload`
  and a newline.

`payload.cpio` also has the directory entries `./usr`, `./usr/bin`,
`./usr/share`, `./usr/share/doc` and `./usr/share/doc/hello`, in sorted
order, and is padded to 512 bytes after `TRAILER!!!` as bsdcpio writes it.
Owner and group are 0; every time stamp is 2026-10-12 00:00 local time.
Inode and device numbers are those of the generating machine's temporary
directory, so regenerating changes them (and the hashes below).

## Generators and commands

Generated on 2026-10-13, macOS AArch64 (Darwin 27.2), with `generate.sh`:

| File | Command | Tool version |
| --- | --- | --- |
| `payload.cpio` | `find ./usr \| LC_ALL=C sort \| cpio -o -H newc -R 0:0 --quiet` | bsdcpio 3.5.3 (libarchive 3.7.4) |
| `payload.cpio.gz` | `gzip -9 -n -c payload.cpio` | Apple gzip 487.40.2 |
| `payload.cpio.bz2` | `bzip2 -9 -c payload.cpio` | bzip2 1.0.8 |
| `payload.cpio.xz` | `xz -9 -c --check=crc64 payload.cpio` | XZ Utils 5.8.2 |
| `payload.cpio.lzma` | `lzma -9 -c payload.cpio` | XZ Utils 5.8.2 |
| `payload.cpio.zst` | `zstd -q -19 -c --check payload.cpio` | Zstandard 1.5.7 |
| `data.tar.xz` | `tar -c --format ustar --uid 0 --gid 0 --uname root --gname root -f - ./usr/bin/hello ./usr/share/doc/hello/README`, then `xz -9 -c --check=crc64` | bsdtar 3.5.3 (libarchive 3.7.4), XZ Utils 5.8.2 |

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `payload.cpio` | 1536 | `d85c2f446d06ca4a05d350f412b63813385fa764a8e813172e312908831b15bc` |
| `payload.cpio.gz` | 278 | `e43034f37a94110aaad2b7ee2b31b7ad0ce1b45b438eade5594b4a5ceb36c522` |
| `payload.cpio.bz2` | 326 | `d37f1907e05fa7081435600679fc8512928fc35212d5906a5b72ce761c53302a` |
| `payload.cpio.xz` | 316 | `b3cd40dea7cd6d4eacf1abb1896a5e92857d494a0a8ecf5732b8852ed9d5bd8f` |
| `payload.cpio.lzma` | 260 | `e9e2a11840d5a05248a4a03e3c374f98d5afb537ce1ca1f3a7a7db9ceb508e8f` |
| `payload.cpio.zst` | 256 | `98fbcb0837d2b89d9acbd6db74b21096fe6b58fbcafa109fed100044892391db` |
| `data.tar.xz` | 296 | `4733262d2d418b9adca8326eb353c0acf0d4eec56858d85c4b6e4eab61161386` |

## What is synthetic

Everything: the files are made up, the ELF has no code, and the package
headers (lead, signature and main header, digests) and the ar archive are
built by the tests, not by rpm or dpkg.
