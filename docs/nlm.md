# NetWare Loadable Modules

`src/formats/nlm.rs` and its submodules (`nlm/header.rs`, `nlm/tables.rs`)
parse NetWare Loadable Modules (NLMs) into the shared container model
([compressed streams and the container model](compressed-streams.md)). The
module's code image is the single load section and goes to the code model;
the data image, the tables and the auxiliary data are described in notes and
metadata and never analyzed as code.

## Implemented layouts

All four layouts report the JSON format ID `netwarenlm` (display name
"NetWare NLM"); the layout is the format variant.

| Variant | Layout | Architecture evidence | Primary source |
| --- | --- | --- | --- |
| `NetWare NLM (i386)` | Signature `NetWare Loadable Module` + `0x1A` at 0; 130-byte little-endian fixed header (no padding after the module name); 4-byte relocation records; imports as name, count, relocations | The signature selects binutils' `nlm32-i386` backend (`bfd_arch_i386`): x86, 32-bit, little-endian | binutils 2.24 `bfd/nlm32-i386.c`, `include/nlm/i386-ext.h` |
| `NetWare NLM (SPARC)` | Signature `NetWare SPARC Module   ` + `0x1A`; 132-byte big-endian fixed header (`pad1[2]`); 12-byte relocation records; imports as count, name, relocations | `nlm32-sparc` (`bfd_arch_sparc`, `TARGET_BIG_SYM`): SPARC, 32-bit, big-endian | `bfd/nlm32-sparc.c`, `include/nlm/sparc32-ext.h` |
| `NetWare NLM (PowerPC)` | Signature `NetWare PowerPC Module ` + `0x1A`; 132-byte big-endian fixed header; 4-byte relocation records | `nlm32-powerpc` (`bfd_arch_powerpc`, `TARGET_BIG_SYM`): PowerPC, 32-bit, big-endian | `bfd/nlm32-ppc.c` (default build, not `OLDFORMAT`), `include/nlm/ppc-ext.h` |
| `NetWare NLM (Alpha)` | 16-byte prefix header (magic `0x83561840`, format, size, padding), then signature `NetWare Alpha Module   ` + `0x1A` at the offset the prefix's `size` word gives; 132-byte little-endian fixed header; 16-byte ECOFF relocation records | `nlm32-alpha` (`bfd_arch_alpha`): Alpha, 64-bit registers, little-endian | `bfd/nlm32-alpha.c`, `include/nlm/alpha-ext.h`, `include/nlm/common.h` |

Common to every layout (binutils `include/nlm/internal.h`, `external.h`,
`bfd/nlmcode.h`, `binutils/nlmconv.c`, `binutils/nlmheader.y`):

- Fixed header: version, module name (length byte, DOS 8.3 name, NUL), code
  and data image offset and size, uninitialized data size, custom data,
  module dependency, fixup, import, export and debug tables (offset and
  count each), start, exit and check-unload procedure offsets, module type
  and flags.
- Variable header: description (at most 127 bytes), stack size, reserved
  word, the unused `" LONG"`, screen name and thread name (at most 71 bytes
  each), each text counted and NUL-terminated.
- Auxiliary headers in any order up to the first unknown stamp:
  `VeRsIoN#` (version, revision and date), `CoPyRiGhT=`, `MeSsAgEs`
  (language, message file, help file, RPC data, shared code and data images,
  product ID) and `CuStHeAd`, read field by field as far as its `length`
  word covers them. A `CuStHeAd` with the data stamp `CyGnUsEx` locates the
  section table of the original object file, whose entries are counted.
- Tables: module dependencies (length-prefixed names), relocation fixups
  (fixed-size records of the target), imports (name, relocation count and
  relocations), exports (name and offset word) and debug records (type,
  value word, name) are walked record by record.

The `flags` bits that `nlmheader.y` sets (`REENTRANT` 0x1, `MULTIPLE` 0x2,
`SYNCHRONIZE` 0x4, `PSEUDOPREEMPTION` 0x8, `OS_DOMAIN` 0x10) are named in a
note; other bits are shown in hex.

Sources are GNU binutils tag `binutils-2_24` (commit
`237df3fa4a1d939e6fd1af0c3e5029a25a137310`), fetched from
`sourceware.org/git/?p=binutils-gdb.git;a=blob_plain;hb=binutils-2_24;f=<path>`
on 2026-10-13. NLM support was later removed from binutils, so the pinned
tag is the reference.

| Path | SHA-256 |
| --- | --- |
| `include/nlm/common.h` | `ba06b93173ccea3ad2c73981eae210f2e0e7f7e380058f0e08f30d75ae652913` |
| `include/nlm/internal.h` | `62fd25f5d0153c56670f1b5302bc614d133cb15e305a09b9f18afc4be9f5e778` |
| `include/nlm/external.h` | `d34634d6c7c78890d3003e0d542ec526814dc983408cece8cad29dda58f57843` |
| `include/nlm/i386-ext.h` | `acf61b4d2d1fe814e064c926c1faa5c09b3daa9deb22d3af3a59e8cbfc01ecb9` |
| `include/nlm/sparc32-ext.h` | `fd373bf326febab37a3383f10ddee37131e57f73594dfed476e8c78df0a9f7df` |
| `include/nlm/ppc-ext.h` | `d74333a4805d0b6b67c017695938e47ff9f6d32a87b1671123d1e966310caba6` |
| `include/nlm/alpha-ext.h` | `4daed674eca869e23f3c560b70332b87bcd9d0c1527bfef524970e85032455ce` |
| `bfd/nlmcode.h` | `78131ee91ec80785f2fc8f69d9a84adb1130b05c5d9efb8452360088ba16ede2` |
| `bfd/nlmswap.h` | `64e7be4861a77639a941684ddd48d4e766a5c1dc6e2bbff3ea7c0d6953b01058` |
| `bfd/nlm-target.h` | `ef34128a44a63533ca5131ce02985238b4ee87556257d5a3b8bbfeb95b009582` |
| `bfd/nlm32-i386.c` | `28ee578b25f8b30e0cd47f0ebd88af01edce4ce86a9186dd82c89e5c7e6f57c9` |
| `bfd/nlm32-sparc.c` | `9bef769f52cbf3d5094574f344f6777e889f217d953032653889dfe5559185bb` |
| `bfd/nlm32-ppc.c` | `3f4d1ad8d4d7b43becdfb63a5a22e786e1f9969b14b5b7b35d568639f9b70fad` |
| `bfd/nlm32-alpha.c` | `1694f4b112887196ee773ab681bec94a2f4bc956f2b94d34074e241b5fd3054c` |
| `binutils/nlmconv.c` | `bd0e3ad853adc308d13acc4077842bc44a34f1eaebd6e6802f34134107309341` |
| `binutils/nlmheader.y` | `d21273fa2ae6173da6b042d3065dde3f59272ba34ed9840de70be8b6d4c96480` |

## Processor identification

`nlm_object_p` compares the 24-byte signature with each backend's signature
string ("It must contain the signature string, which depends upon the NLM
target", `internal.h`) and then sets the backend's architecture. The
signature, and for Alpha the prefix header, is therefore the format's target
field, and the container names that processor (`Container::target`). The
code image still goes to the code model: when it classifies as another ISA
family, a warning says so ("Container names x86; the loaded code classifies
as ...") and the signature's ISA stays. The `NetWare Loadable Module`
signature is mapped to x86 only because binutils assigns it to its i386
backend and nothing else; the other three targets carry their own
signatures.

## Wire units and byte order

Every header and table word is 32 bits in the target's byte order
(`nlm-target.h`: header and data byte order are the same): little-endian for
i386 and Alpha, big-endian for SPARC and PowerPC. The header byte order is
reported in a note; it is also the code byte order of these targets.

All offsets are file offsets in bytes. The code and data images are
relocatable: binutils gives both sections address 0, so the code image is
the load section at destination 0. The start, exit and check-unload
procedure offsets are code image offsets (`nlm_write_object_contents`
subtracts the text base), and the start offset is the container entry point.
The uninitialized data size is a load-time allocation and is reported, never
allocated.

## Validation and resource bounds

Detection is strong (the 24-byte signature; for Alpha the prefix magic and
the signature at the prefix's `size` offset), so a damaged module is a parse
error, not raw code. The parser checks, in this order (the order is
observable in error messages):

1. The signature and, for Alpha, the prefix header (size at least 16 B).
2. The fixed header fits the file (130 B for i386, 132 B otherwise).
3. The header version: 1 to 4 (`NLM_HEADER_VERSION`) is documented; a
   documented version with bit 7 set is accepted without its images (see
   A3); anything else is `Unsupported header version`.
4. The module name length is 1 to 12 (`NLM_MODULE_NAME_SIZE - 2`).
5. The variable header: each text within its documented maximum (127, 71,
   71 B) and inside the file.
6. Auxiliary headers: each stamp's fields inside the file; at most one
   `VeRsIoN#`, `CoPyRiGhT=` and `MeSsAgEs` (`Duplicate ...`); at most 64
   auxiliary headers in all (our bound).
7. The code image, data image and custom data lie in the file when their
   size is not 0. Empty ranges are not located, because writers point them
   at the end of the file.
8. Each non-empty table: its count is at most the bytes after its offset
   divided by the smallest record (1 B for dependencies, the target's
   relocation size for fixups, 5 B for imports and exports, 6 B for debug
   records), then every record is read; import relocation counts are
   multiplied with checked arithmetic.
9. Nonzero start, exit and check-unload offsets lie inside the code image.
10. The message file, help file, RPC data and shared images of `MeSsAgEs`,
    and the data of every `CuStHeAd`, lie in the file; a `CyGnUsEx` table
    must consist of whole entries.

Every loop is bounded by a count checked against the file size; nothing is
allocated from a header value. At most 16 module dependency names are
listed; the rest are counted. The code image is subject to the 64 MiB
payload limit of the container model.

Bytes after the last structure the headers describe are not an error: NLMs
define no trailer, and a linker may append data such as debug information.
A note gives their size when they are not `0x00`/`0xFF` padding, and they
are never analyzed. This deviates from the erased-flash rule of `AGENTS.md`
section 2.8, which is written for firmware images.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| A1 | The signature identifies the processor, as binutils' backend selection does | A module with the i386 signature whose code is another ISA: reported as x86 with a "Container names x86" warning (`code_that_contradicts_the_signature_is_reported_not_adopted`); a non-x86 NetWare module with the i386 signature would falsify the mapping. Not seen in the samples |
| A2 | Header and data byte order are the same per target (`nlm-target.h`) | SPARC and PowerPC fixtures with big-endian compiled code classify big-endian; a little-endian reading of the same words fails (`big_endian_targets_pad_the_module_name_and_swap_every_word`) |
| A3 | A header version with bit 7 set over a documented version means the images are not stored as the header describes (UNCONFIRMED) | IDA's `pc_old.nlm` (VREPAIR.NLM 3.12, version `0x84`): its code, data and table offsets lie beyond the 44,854 B file while every header parses; reported with its headers, opaque, without range checks. Novell documents NLMPACK compression (NDK "5.3 NLM Compression Tools") but not its layout or marker |
| A4 | A zero procedure offset means "none" for the check-unload procedure and is never checked | `nlmconv` zeroes the header and sets the field only for `CHECK`; a module whose start procedure is at a nonzero offset outside the code image is an error |
| A5 | Every range a header names with a nonzero size lies in the file | IDA's `pc_huge_bss.nlm` and the other samples cut to 16,896 B fail on the first range past the cut |
| A6 | Module type values have no meaning in binutils | Reported as a number only |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Packed (NLMPACK) modules | Not decoded: the compression format is undocumented. A bit-7 version is reported as opaque (A3) |
| PowerPC `OLDFORMAT` modules (`AppleNLM` prefix) | Not recognized; binutils builds it only with `OLDFORMAT` defined |
| Relocation, import and export semantics | Records are walked and counted, not applied; no symbols are listed |
| `MeSsAgEs` shared library tables (shared fixups, imports, exports, debug records) | Not walked; only the shared code and data images are range-checked |
| Message, help and RPC data contents | Located and range-checked, not parsed |
| NLM64 | binutils defines no 64-bit NLM target; not recognized |
| Signatures or checksums | The format defines none; nothing is verified |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly):

- `tests/nlm.rs` (12 tests) passed, and the 18 unit tests in
  `src/formats/nlm.rs`, `nlm/header.rs` and `nlm/tables.rs` passed. The
  fixtures are synthetic, built from the documented layouts with code from
  the repository's i686, SPARC and PowerPC testbins; every prefix of each
  layout's fixture is an error, and every byte mutated to `0x00`, `0xFF` and
  two bit flips parses or fails without panicking.
- With `IDA_INPUT_DIR` set to IDA's `tests/input`,
  `ida_nlm_samples_parse_or_fail_with_bounded_errors` passed on the seven
  IDA samples: `pc_netw6.nlm` (IPTRACE.NLM, 18,811 B) reports x86 with 339
  fixups, 54 imports and its message file; `pc_old.nlm` reports x86 with an
  undocumented header version `0x84` and no analyzed image; `pc_bad_codeoff`,
  `pc_bad_impoff`, `pc_bad_import_count`, `pc_huge_bss` and
  `pc_truncated_nlm` fail with `NetWare module parse error` messages naming
  the code image, the header version, the import count, the message file and
  the code image respectively. Without the variable the test skips.
- `web/tests/nlm.test.mjs` (4 tests) passed after `./build-web.sh`, through
  `/pkg/zrax.js`, `/dist/zrax.js` and both workbench pages.
- The whole native suite (`cargo test --all-features --locked`: 1,508
  passed, 6 ignored) and the browser suite (`npm test`: 176 tests, 172
  passed, 4 skipped because they need D10 and RX113 firmware that is not in
  the repository) passed. `tests/idaref.rs` with `IDAREF_DIR` set to IDA's
  `tests/input` passed its thresholds; the five malformed NLM samples, which
  the code model alone had classified as x86 or left inconclusive, now count
  as parse errors there.
- After integration with the partition table, FAT, ISO 9660, console disc,
  Java image, MCU wrapper and minidump families on the same day, the native
  suite passed 1,801 tests with 6 ignored. On IDA's corpus (4,621 files),
  `pc_old.nlm` went from inconclusive to x86, and the five malformed
  samples became parse errors (four had been classified x86 by the code
  model alone, `pc_bad_impoff.nlm` was inconclusive); `pc_huge_bss.nlm` is
  `pc_netw6.nlm` cut to 16,896 B with a 2 GiB uninitialized data size, so
  its message file lies past the end of the file. No other file changed.

SPARC, PowerPC and Alpha modules were verified only with synthetic fixtures;
no real module of those targets was available, so their layouts are as
binutils defines them and not verified against Novell-built files.
