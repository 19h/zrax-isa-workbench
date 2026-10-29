# Apple Image4 fixtures

Synthetic fixtures for `tests/apple.rs` and `web/tests/apple.test.mjs`.
`generate.sh` rebuilds them all. dyld shared caches, encrypted (keybag)
payloads and malformed DER are built in the tests themselves from the
documented layouts; no fixture file is needed for them.

## Inputs

Both inputs come from `synthetic.py`:

- `kernel.macho` (8,192 B) stands in for a kernelcache. It is a 64-bit
  little-endian Mach-O header (`MH_MAGIC_64`, `CPU_TYPE_ARM64`,
  `CPU_SUBTYPE_ARM64_ALL`, `MH_FILESET`, one 24-byte `LC_UUID` command with
  UUID bytes `00..0F`) followed by the repeated ASCII text
  `zrax synthetic kernelcache `. It has no code and is not runnable.
- `synthetic.im4m` (443 B) is an IM4M manifest in the layout img4lib,
  PyIMG4 and img4tool share: version 0; a `MANB` body holding `MANP`
  (`CHIP` 0x8030, `BORD` 0x0C) and a `krnl` group with an all-zero 48 B
  `DGST`; a 256 B all-zero "signature"; and a certificate chain holding one
  placeholder `SEQUENCE { OCTET STRING "cert" }`. Nothing in it is signed
  or corresponds to a real device.

## Generator and commands

Generated on 2026-10-12, macOS AArch64 (Darwin 27.2), with Python 3 and
tihmstar img4tool 0.202, commit `e1c37d6ce8c629ca9669efc9cb5b5f7d6810ed30`
(built with bvx2 support, which uses the system `libcompression`). Rerunning
`generate.sh` on that system reproduced every hash below.

| File | Command |
| --- | --- |
| `kernel.macho` | `python3 synthetic.py kernel kernel.macho` |
| `synthetic.im4m` | `python3 synthetic.py im4m synthetic.im4m` |
| `krnl.im4p` | `img4tool -c krnl.im4p -t krnl -d "zrax synthetic kernelcache" kernel.macho` |
| `krnl.bvx2.im4p` | `img4tool -c krnl.bvx2.im4p -t krnl -d "zrax synthetic kernelcache" --compression bvx2 kernel.macho` |
| `krnl.complzss.im4p` | `img4tool -c krnl.complzss.im4p -t krnl -d "zrax synthetic kernelcache" --compression complzss kernel.macho` |
| `krnl.img4` | `img4tool -c krnl.img4 -p krnl.bvx2.im4p -m synthetic.im4m -g 0x1122334455667788` |

What img4tool wrote:

- `krnl.im4p`: the payload stored as-is in the `OCTET STRING`.
- `krnl.bvx2.im4p`: an LZFSE stream starting with a `bvx2` block (237 B),
  followed by the compression info `SEQUENCE { INTEGER 1, INTEGER 8192 }`.
- `krnl.complzss.im4p`: a `complzss` header (Adler-32 `0x953F548A`,
  decoded size 8,192 B, stored size 1,031 B, `prelinkVersion` 1) and the
  LZSS stream; no compression info.
- `krnl.img4`: `krnl.bvx2.im4p`, the manifest as `[0]`, and an `[1]` IM4R
  whose `BNCN` nonce is the generator stored little-endian
  (`88 77 66 55 44 33 22 11`).

## Headerless Brotli fixture

`kernel.macho.br` was generated on 2026-10-29 on macOS AArch64 using Node
25.8.1 and its bundled Brotli 1.2.0 encoder, quality 4. Its input is the same
synthetic `kernel.macho` listed below; it contains no third-party firmware.
The fixture exercises a headerless codec trial followed by structural
recognition. Regenerate it separately from img4tool's files:

```sh
cd tests/fixtures/apple
node --input-type=module - kernel.macho kernel.macho.br <<'JS'
import { readFileSync, writeFileSync } from 'node:fs';
import { brotliCompressSync, constants } from 'node:zlib';
const data = readFileSync(process.argv[2]);
writeFileSync(process.argv[3], brotliCompressSync(data, {
  params: { [constants.BROTLI_PARAM_QUALITY]: 4 },
}));
JS
```

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `kernel.macho` | 8192 | `68e38b250dd441c1dd96b4baa7efad4bcbf928f19b9615c51d8744b834fdc6ea` |
| `synthetic.im4m` | 443 | `c4c4d74cfe0fba0f62cd176c72de26343a81621b93db40cf83432f7247a5f664` |
| `krnl.im4p` | 8240 | `058cdb8f531ce9ce5bf10ac9ae511a4b68f27f272b00e47c0baa0c902a897582` |
| `krnl.bvx2.im4p` | 293 | `ddbe536f0c7b7ea2f24eda30cb7fc49437055e63c051839f12349cdb2be09e18` |
| `krnl.complzss.im4p` | 1463 | `01ffa229ed87e86856a54ef9f21499e5af487b5380f1c4f9d7bfb09905cdba30` |
| `krnl.img4` | 787 | `e4f3b6f3505e6e4c6aa774401b665a4b83af3c96f1ee68366e46752dfea2f066` |
| `kernel.macho.br` | 80 | `edd78a0f41465771286e35095f960cc3455755d7c6f8283bc6eebbafa9aa4908` |
