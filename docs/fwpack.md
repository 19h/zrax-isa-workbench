# Firmware package wrappers

`src/formats/fwpack.rs` and its submodules parse three firmware update
wrappers into the shared container model
([compressed streams and the container model](compressed-streams.md)):
MikroTik RouterOS packages (NPK), Ubiquiti firmware images, and ChromeOS
verified-boot kernel partitions. None of them names a CPU, so every
container leaves its target open; the ISA comes from the components, each
classified from its own bytes.

## Implemented layouts

| JSON format ID | Layout | Components | Primary source |
| --- | --- | --- | --- |
| `mikrotiknpk` | Magic `0xBAD0F11E`, the size of everything after the size field, then parts (type, size, payload) that tile it; package information (name, version, build time), description, architecture, bundle parts (`PKG_INFO`, `PKG_FEATURES`); the SHA-1 digest of each signature part checked | Regular files of each zlib file container that are a recognized format (`if_recognized`, decoded with `compressed::decode_limited`); each SquashFS part (opaque when it does not start with `hsqs` or `sqsh`) | tenable/routeros [`c5d42403`](https://github.com/tenable/routeros/tree/c5d42403135e7d826fbddd85b788401b0f40d90d) `ls_npk/src/main.cpp`, `modify_npk/src/main.cpp`; elseif/MikroTikPatch [`45e9c0a6`](https://github.com/elseif/MikroTikPatch/tree/45e9c0a66ad1c30034d8259f59c00d6edfdfae5f) `npk.py`; kost/mikrotik-npk [`d54e97ca`](https://github.com/kost/mikrotik-npk/tree/d54e97caac9ea447e29939ca4176d17eeff856a9) `unpacknpk.py`; botlabsDev/npkpy [`cbfc8373`](https://github.com/botlabsDev/npkpy/tree/cbfc8373317c74770f818a6b3811c9b73c8d208a) `npkpy/npk/` |
| `ubiquitifw` | 268-byte header (`OPEN`, `UBNT` or `GEOS`, version string, CRC-32, zero pad), `PART` and `EXEC` records (56-byte header, data, CRC-32, pad), then `END.` (CRC-32 of the image) or `ENDS` (RSA signature) | Each `PART` record's data (kernel, rootfs, ...); `EXEC` data opaque | `OpenWrt` firmware-utils [`a1d9589f`](https://github.com/openwrt/firmware-utils/tree/a1d9589f1ea1b96529ac10fef5d164ff3aa03dc7) `src/fw.h`, `src/mkfwimage.c`, `src/mkfwimage2.c`; `OpenWrt` v24.10.0 `target/linux/ath79/image/common-ubnt.mk`; binwalk [v2.3.4](https://github.com/ReFirmLabs/binwalk/blob/v2.3.4/src/binwalk/magic/firmware) `src/binwalk/magic/firmware` |
| `chromeoskernel` | `vb2_keyblock` (`CHROMEOS`, version 2.x, signature, SHA-512 hash, flags, data key), `vb2_kernel_preamble` 2.0, 2.1 or 2.2 (kernel version, body load address, bootloader, body signature, vmlinuz header, kernel type flags), then the kernel blob at `keyblock_size + preamble_size` | The kernel (a `vmlinuz` rebuilt from the vmlinuz header and the blob when the preamble names a vmlinuz header, otherwise the kernel slot before the command line page), then the bootloader | vboot (`vboot_reference`, coreboot/vboot mirror) [`8273cc58`](https://github.com/coreboot/vboot/tree/8273cc58132e616a3405fb1de364b5be87a39000) `firmware/2lib/include/2struct.h`, `firmware/2lib/2struct.c`, `firmware/2lib/2common.c`, `firmware/2lib/include/2constants.h`, `firmware/2lib/2load_kernel.c`, `host/lib/host_keyblock.c`, `host/lib/host_common.c`, `futility/vb1_helper.c`, `futility/cmd_vbutil_kernel.c`, `futility/kernel_blob.h` |

Children are pushed in the order that describes the input best: NPK files
and SquashFS images in part order, Ubiquiti records in file order, and the
ChromeOS kernel before its bootloader, so a boot stub never decides the
partition's ISA.

### MikroTik NPK

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | Magic `0xBAD0F11E` (bytes `1E F1 D0 BA`) |
| 4 | 4 | Size of everything after this field |
| 8 | 2 + 4 + n | Parts: type, payload size, payload |

Part types follow MikroTikPatch `NpkPartID` (0x01-0x19) and tenable
`ls_npk` (which also names 0x05 and 0x06 and calls 0x0A-0x0F unused). The
parser reads:

| Type | Payload |
| --- | --- |
| 0x01 `NAME_INFO` | Name (16, NUL-padded), version bytes revision, build code, minor, major (4), build time (4, Unix seconds), unknown bytes |
| 0x02 `DESCRIPTION` | Text, reported as metadata |
| 0x04 `FILE_CONTAINER` | zlib stream of 30-byte entry headers (`st_mode` low and high byte, user and group (6), modification time, version bytes, creation time, unknown (4), data size, name size (2)), each followed by its name and data |
| 0x09 `SIGNATURE` | SHA-1 digest (20), KCDSA signature (48), optional EdDSA signature (64) |
| 0x10 `ARCHITECTURE` | Text such as `x86`, reported as metadata only |
| 0x12 `PKG_INFO`, 0x14 `PKG_FEATURES` | Bundle information; after `PKG_FEATURES`, each `NAME_INFO` starts a member package whose member labels are prefixed with its name |
| 0x15 `SQUASHFS` | A SquashFS image |

The SHA-1 digest covers every part header and payload of the package, from
its first part (in a bundle, from the member's `NAME_INFO`), skipping
`HEADER` (0x19) parts, followed by the signature part's own header
(MikroTikPatch `get_digest`; tenable `ls_npk` hashes the same way).

### Ubiquiti firmware image

| Record | Layout (big-endian) |
| --- | --- |
| Header (268 B) | Magic (4), version (256, NUL-padded), CRC-32 of bytes 0-259 (4), zero pad (4) |
| `PART` / `EXEC` | Magic (4), name (16), pad (12), memory address, index, flash base address, entry address, data size, partition size (4 each), data, CRC-32 of header and data (4), pad (4) |
| `END.` (12 B) | Magic, CRC-32 of every byte before the record, zero pad |
| `ENDS` (264 B) | Magic, RSA signature (256), zero pad |

All CRCs are zlib `crc32` (CRC-32/ISO-HDLC).

### ChromeOS kernel partition

| Structure | Fields (little-endian) |
| --- | --- |
| `vb2_keyblock` (112 B) | `CHROMEOS` (8), header version major 2 and minor (4 each), keyblock size (4), reserved, keyblock signature (24), keyblock hash (24), flags (4), reserved, data key (32) |
| `vb2_kernel_preamble` (96, 112 or 116 B) | Preamble size (4), reserved, preamble signature (24), version 2.minor (4 each), kernel version (4), reserved, body load address (8), bootloader address (8), bootloader size (4), reserved, body signature (24); 2.1+: vmlinuz header address (8), size (4), reserved; 2.2+: flags (4, bits 1-0 kernel type: ChromeOS, Android boot image, multiboot) |
| `vb2_signature` (24 B) | Data offset from the structure, data size, signed size (4 each, each followed by a reserved word) |
| `vb2_packed_key` (32 B) | Key offset from the structure, key size, algorithm (`vb2_crypto_algorithm` 0-17), key version (4 each, each followed by a reserved word) |
| Kernel blob (`futility`) | Kernel (rounded to 4 KiB), command line page (4 KiB), x86 boot parameter page (4 KiB), bootloader (rounded to 4 KiB), vmlinuz header |

The bootloader and vmlinuz header are located by their target addresses
relative to the body load address. The command line page lies 8 KiB before
the bootloader by `futility`'s convention (`kernel_cmd_line_offset`), not
by a header field; the notes say so. On x86, `futility` keeps only the
protected-mode part of the `bzImage` in the kernel slot and stores the
setup code as the vmlinuz header; the parser rebuilds the `vmlinuz` as
`vbutil_kernel --get-vmlinuz` does (the vmlinuz header, then the whole
blob) and classifies it as a `bzImage` with the kernel family. The
rebuilt kernel is a child with transform `vmlinuz reassembly` whose stored
range is the blob.

## Wire units and byte order

All offsets and sizes are bytes. NPK and ChromeOS structures are
little-endian; Ubiquiti headers and records are big-endian. ChromeOS
addresses are target addresses; blob offsets are computed from them and
the body load address. Header byte order is never reported as code byte
order.

## Validation and resource bounds

- NPK: the declared size must fit the file; parts must tile it exactly;
  at most 4096 parts; only `0x00`/`0xFF` padding may follow. A file
  container that does not decode is listed as an opaque component with a
  note. File containers decode to at most 64 MiB each and 256 MiB per
  package; past the limit the entries in the decoded prefix are listed and
  a note says the rest was not. At most 4096 components are listed; regular
  files are copied only when their first 4 KiB and then their whole
  contents are a recognized format.
- Ubiquiti: the header CRC, every record CRC and the `END.` CRC must match;
  header and end-record pads must be zero; at most 4096 records; a record
  magic other than `PART`, `EXEC`, `END.` or `ENDS` is an error; only
  padding may follow the end record. Data larger than its partition size is
  noted; empty records are noted and not listed.
- ChromeOS: the keyblock and preamble checks of `vb2_check_keyblock` and
  `vb2_verify_kernel_preamble` (signature, hash and data key inside their
  structures and signed ranges; signed sizes at least 112 B for the
  keyblock and 108 B for the preamble; preamble size at least the version's
  structure size); the keyblock SHA-512 hash must match; the body must be
  non-empty and fit the file; the bootloader and vmlinuz header must lie in
  the signed body. A body that starts beyond the 64 KiB vboot reads is
  noted. Bytes after the body are noted as unused partition space, padding
  or not, and are not analyzed: a dumped kernel partition is larger than
  the kernel it holds and may hold stale data. A rebuilt `vmlinuz` larger
  than 64 MiB is not built; the kernel slot is classified instead.
- Container nesting is capped at six levels and every extraction at 64 MiB
  (see [compressed streams](compressed-streams.md)).

## Evidence and verification

| Check | Status |
| --- | --- |
| NPK SHA-1 digests | Verified; a mismatch is a note, not an error (coverage from one tool, see F2) |
| NPK KCDSA and EdDSA signatures | Present, not verified (need MikroTik's keys) |
| NPK file container | Adler-32 verified by the zlib decoder |
| Ubiquiti header, record and image CRC-32s | Verified; a mismatch is an error |
| Ubiquiti `ENDS` RSA signature | Present, not verified |
| ChromeOS keyblock SHA-512 hash | Verified; a mismatch is an error |
| ChromeOS keyblock, preamble and body RSA signatures | Present, not verified |

No wrapper sets a target. The NPK architecture part, Ubiquiti board names
and version strings, flash and load addresses and the ChromeOS body load
address are reported in notes and metadata only.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| F1 | NPK integers are little-endian and parts tile the declared size exactly | Every prefix of the test package fails to parse (`npk_prefixes_and_mutations_do_not_claim_the_package`); a real package whose parts leave a remainder would fail with "Truncated NPK part header" |
| F2 | The NPK digest starts at the package's first part (a bundle member's `NAME_INFO`) and skips `HEADER` (0x19) parts, as MikroTikPatch `get_digest` computes it | A real RouterOS 7 package or bundle that reports "does not match"; tenable `ls_npk` predates part 0x19 |
| F3 | The NPK file container's second entry byte is the file type (0x81 regular file) | Real packages list their executables; a package whose files are all counted "of another type" would falsify it |
| F4 | The NPK architecture string names no ISA by a documented mapping | Not used; metadata `npk_architecture` reports it |
| F5 | Ubiquiti `UBNT` and `GEOS` headers share the `OPEN` layout, and `EXEC` records the `PART` layout | binwalk v2.3.4 magic offsets agree; a real `UBNT` image whose header CRC fails would falsify it |
| F6 | The ChromeOS command line lies 8 KiB before the bootloader | `futility` `kernel_cmd_line_offset`; another producer's blob reports a non-text command line page or none |
| F7 | A preamble with a vmlinuz header holds an x86 kernel whose setup code is that header | `chromeos_x86_kernels_are_rebuilt_into_vmlinuz_as_futility_does`; on a real Arm partition the header size is 0 |
| F8 | Bytes after a ChromeOS body are unused partition space | Noted, never analyzed; `chromeos_unused_partition_space_is_noted` |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| ChromeOS firmware vblocks (keyblock followed by `vb2_fw_preamble`, the FMAP `VBLOCK_A`/`VBLOCK_B` areas) | Recognized by the keyblock magic and rejected by the kernel preamble or body checks; `futility` tells them apart by verifying the preamble signature, which needs the key |
| ChromeOS keyblock header versions other than 2.x | Not recognized (`vb2_check_keyblock` rejects them) |
| ChromeOS command line and x86 boot parameter pages | Command line reported as text; the boot parameter page is not parsed |
| NPK install and uninstall scripts, dependencies, conflicts, features, channel, Git commit parts | Counted with the parts, not listed |
| NPK parts of undocumented types (0x0A-0x0F, above 0x19) | Listed in a note; a first part of such a type is not recognized |
| NPK packages before RouterOS 5 | Not examined; no primary source |
| Ubiquiti `ENDS` images | No overall CRC; the RSA signature is not verified |
| Other Ubiquiti formats (UniFi `.bin` with other headers, EdgeOS `.tar`) | Not recognized by this family |
| Real samples | No MikroTik, Ubiquiti or ChromeOS samples were available (none in `IDA_INPUT_DIR`); every fixture is synthetic |

## Verification

On 2026-10-13 (macOS AArch64), `tests/fwpack.rs` (19 tests) passed,
including every-prefix parse sweeps and single-byte mutation sweeps of an
NPK package, a Ubiquiti image and a ChromeOS kernel partition, as did the
11 module unit tests; `cargo test --all-features --locked` passed 2,272
tests with 6 ignored. After `./build-web.sh`, `web/tests/fwpack.test.mjs`
(4 tests) passed through `/pkg/`, `/dist/`, `/web/index.html` and
`/dist/index.html`. All
fixtures are synthetic, built in the tests from the documented layouts
around `tests/fixtures/compressed/payload.elf`; no firmware is
redistributed. Behaviour on real MikroTik, Ubiquiti and ChromeOS files is
not verified.

After integration on the same day, the native suite passed 2,415 tests
with 6 ignored, and IDA's corpus (4,621 files, none starting with these
magics) classified as before.
