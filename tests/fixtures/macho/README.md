# Mach-O fixtures

Clang-built Mach-O files for `tests/macho.rs` and `web/tests/macho.test.mjs`.
Everything else those tests use (segments, thread states, encryption
records, filesets, fat headers, damaged commands) is built in the tests
from the `loader.h` layouts.

## Source

`hello.c` is a synthetic program written for these fixtures: a checksum
loop, a vectorizable multiply-add and a dot product. Nothing in it comes
from third-party code. The executables are not meant to be run.

## Generator and commands

Generated on 2026-10-13 on macOS 27.2 (build 26B5101f), AArch64, with
Apple clang 21.0.0 (`clang-2100.3.34.2`), `ld-27105`, and the MacOSX 27.2
SDK of Xcode. `generate.sh` runs, in a temporary directory:

```sh
xcrun clang -target arm64-apple-macos12.0 -O2 -o hello-arm64 hello.c
xcrun clang -target x86_64-apple-macos10.15 -O2 -mavx2 -mfma -o hello-x86_64 hello.c
xcrun clang -target arm64-apple-macos12.0 -O2 -c -o hello-arm64.o hello.c
gzip -9 -n -c hello-arm64 > hello-arm64.gz      # and the same for the others
```

ld ad-hoc signs the arm64 executable, and the signature records the output
file name, so the names above are part of the recipe. Rerunning
`generate.sh` on that system reproduced every hash below.

## What the files hold (`otool -l`)

| File | Contents |
| --- | --- |
| `hello-arm64` | `MH_EXECUTE`, `CPU_TYPE_ARM64`, 16 load commands (744 B): `__PAGEZERO`, `__TEXT` (`__text` at 0x328, 616 B; `__unwind_info`), `__LINKEDIT`; `LC_DYLD_CHAINED_FIXUPS` (0x4000, 56 B); `LC_BUILD_VERSION` macOS 12.0, SDK 27.2; `LC_MAIN` `entryoff` 0x554; `LC_UUID` `DCB4CF0B-F814-38AE-AE23-A8C9FF0C7F49`; `LC_CODE_SIGNATURE` (0x4120, 280 B, ad hoc) |
| `hello-x86_64` | `MH_EXECUTE`, `CPU_TYPE_X86_64`, 14 load commands (744 B): `__PAGEZERO`, `__TEXT` (`__text` at 0x340, 1054 B of AVX2/FMA code; `__unwind_info`), `__LINKEDIT`; `LC_DYLD_INFO_ONLY`; `LC_BUILD_VERSION` macOS 10.15, SDK 27.2; `LC_MAIN` `entryoff` 0x6A0; `LC_UUID` `AF8030DB-A967-39E2-B3ED-CB22EAC1D7A6`; no code signature |
| `hello-arm64.o` | `MH_OBJECT`, `CPU_TYPE_ARM64`, 4 load commands (360 B): one unnamed `LC_SEGMENT_64` (file 0x188, 744 B) with `__TEXT,__text` (616 B) and `__LD,__compact_unwind`; `LC_BUILD_VERSION` macOS 12.0 |

## Sizes and SHA-256

| File | Size (B) | SHA-256 |
| --- | --- | --- |
| `hello-arm64` (decompressed) | 16952 | `3b449d78e99e4b6703a60a39ad798e0c330c8c00903ef370fc98fcd788baf54a` |
| `hello-x86_64` (decompressed) | 4336 | `4993857af3e3106ae6c73f0b574f7d1d92f4d36db1dfd7fa4cd13a7d05a888b1` |
| `hello-arm64.o` (decompressed) | 1312 | `db6f751b8d8ea39c3ad592ce45d4b0c33661802d62e100182ac19f9735c23578` |
| `hello-arm64.gz` | 1199 | `20fd41c15df9b9d9dc415141a446354a4b77930f429884283f32e9f444f93e69` |
| `hello-x86_64.gz` | 1237 | `82a13c8c2ce1075aca08dc1655fae19332e4de3f05a8be8f6dc3512d48ecbbbf` |
| `hello-arm64.o.gz` | 742 | `26d0885ecb841b8a3268e3d1c73ba053c10c034309876047d46dca7fbb060c93` |
| `hello.c` | 847 | `d674366bbbf113664c47f40d634175108836612e18f7bc6d8dfb945ba9357e1b` |
