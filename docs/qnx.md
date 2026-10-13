# QNX image filesystems

`src/formats/qnx.rs` and its submodules parse QNX Neutrino image
filesystems (IFS) into the shared container model
([compressed streams and the container model](compressed-streams.md)): the
bootable images that `mkifs` writes (a startup header, the startup program
and an image filesystem, optionally compressed) and bare image filesystems.
The startup header's `machine` field names the startup program's
architecture; the files in the image filesystem are listed when they are a
recognized format and classified on their own bytes, so an ELF executable
reports its own `e_machine`.

## Implemented layouts

| JSON format ID | Layout | Architecture evidence | Primary source |
| --- | --- | --- | --- |
| `qnxifs` (variant "QNX bootable image") | Startup header (`0x00FF7EEB` in target order) at offset 0, or after a boot prefix whose size `preboot_size` states; startup program; image filesystem stored, gzip-compressed (`ZLIB`), LZO-compressed or UCL-compressed; startup and image trailer checksums verified | `machine` is an ELF `e_machine` value, mapped by the ELF table (`elf::e_machine_to_isa`); machines whose ISA depends on the ELF class (MIPS, RISC-V, S/390) and `EM_NONE` name no target | QNX `sys/startup.h` (`$Rev: 169802`, Apache-2.0 release, copy at [askac/dumpifs `b7bac90e`](https://github.com/askac/dumpifs/blob/b7bac90e8312eca2796f2003a52791899eb8dcd9/sys/startup.h)); mkifs `mk_image_fsys.c` `$Rev: 203655` ([vocho/openqnx `cc95df35`](https://github.com/vocho/openqnx/blob/cc95df3543a1c481d4f8ad387e29f0d1ff0c87fe/trunk/utils/m/mkxfs/mkxfs/mk_image_fsys.c)); [QNX SDP 8.0 "The startup header"](https://qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/ipl/ipl_startup_header.html) |
| `qnxifs` (variant "QNX image filesystem") | `imagefs` header at offset 0, directory, files, image trailer checksum verified | None: the image filesystem names no architecture; the primary ISA comes from the first recognized member | QNX `sys/image.h` `$Rev: 153052` ([vocho/openqnx `cc95df35`](https://github.com/vocho/openqnx/blob/cc95df3543a1c481d4f8ad387e29f0d1ff0c87fe/trunk/services/system/public/sys/image.h)); dumpifs `dumpifs.c`, same commit, `trunk/utils/m/mkxfs/dumpifs/` |

The image layout and the `compress` attribute values (1 ZLIB, 2 LZO, 3 UCL8,
the `+compress` default) follow the QNX SDP 8.0 Utilities Reference,
[`mkifs`](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkifs.html)
("Output image format"); the boot script encoding follows `union
script_cmd` in `sys/image.h` and `parse_script_cmd` in mkxfs `mkxfs.c`
(same commit).

## Components

| Component | Kind | Classification |
| --- | --- | --- |
| Startup program (`header + header_size` to the startup trailer) | Load section at `ram_paddr + header_size` | Code model under the machine's target; `startup_vaddr` is the entry (a virtual byte address) |
| Boot prefix (bytes before the header) | Child, raw code | Code model under the machine's target (the prefix runs on the same processor before startup; on x86 BIOS boots it is 16-bit real-mode code); a zero-filled prefix is only noted |
| Regular files | Children, listed only when recognized | Their own format and header (`Classify::IfRecognized`) |
| Boot script (`script_ino`) | Opaque child | Never analyzed as code; its commands are counted by type and up to 8 program names are quoted in a note |
| Compressed image filesystem that is not decoded (UCL, or a stream that fails) | Opaque child | Not analyzed |

Directories, symbolic links and devices are counted in a note; their
targets are not followed.

## Wire units and byte order

All sizes and offsets are bytes. Every multi-byte field of the startup
header, the image header, the directory entries and the trailers is stored
in the target byte order: the startup signature's byte order must agree
with the `flags1` big-endian bit, and the image header's big-endian flag
with both. The boot script's command sizes are an explicit little-endian
byte pair, and the LZO and UCL block lengths are big-endian 16-bit values,
in every byte order. Header byte order is not reported as code byte order
where the ISA fixes its own: `AArch64` code is little-endian in either
order, and a big-endian 32-bit Arm image leaves the instruction order open
(BE8 or BE32).

File offsets in the directory are relative to the image header. Members of
a stored image filesystem are reported at their file offsets; members of a
decoded one carry the stored range of the compressed stream and their
decoded size.

## Validation and resource bounds

- Startup header: `header_size` at least 0x34 (the fields read);
  `startup_size` a multiple of 4 that holds the header and the startup
  trailer; `stored_size` a multiple of 4 that holds an image trailer after
  it; both inside the file. A prefixed header's `preboot_size` must equal
  its offset; prefixes are searched at four-byte aligned offsets up to
  0xFFFC.
- Checksums: the 32-bit word sum (target order) of the startup region and of
  the stored image region must be zero, as mkifs writes the trailers (the
  negated sum) and the IPL checks them. A mismatch is a parse error. The
  image filesystem's own trailer is checked the same way, including inside a
  decoded image filesystem.
- Image header: `image_size` a multiple of 4 that holds the directory and
  the trailer; `dir_offset` after the fixed header and not past
  `hdr_dir_size`; NUL-terminated mountpoint. For a stored image filesystem,
  `image_size`, `imagefs_size` and `stored_size - startup_size` must agree.
- Directory: entries of at least 24 bytes inside `hdr_dir_size`, ended by a
  zero-size entry; inode 0 entries are skipped (and counted); every file's
  data must lie before the image trailer. The walk is bounded by the
  directory size.
- Compression: `imagefs_size` above 64 MiB is not decoded. gzip goes
  through `compressed::decode_limited` with `imagefs_size` as the limit;
  LZO1X blocks through `Codec::Lzo1x`, each at most 64 KiB decoded and
  consumed exactly; the decoded total must equal `imagefs_size`; only zero
  padding to four bytes may follow the stream. A stream that does not
  decode, or decodes to an invalid image filesystem, is kept as an opaque
  component with a note, and the startup header still reports. UCL block
  framing is walked but not decoded.
- Members: recognized from their first 4 KiB, then their whole contents;
  at most 4096 members (`MAX_COMPONENTS`); decoded members are copied up to
  256 MiB per image (`MAX_EXTRACTED`) and 64 MiB per member; notes record
  what was left out. The boot script is listed once.
- Bytes after `stored_size` (or `image_size` for a bare image filesystem)
  are noted, not rejected: mkifs documents a boot postfix that other
  programs append.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| Q1 | The trailer checksums are 32-bit word sums that make each region sum to zero (mkifs 6.x `iwrite`), also in QNX 7 and 8 images | A mkifs 7.x or 8.x image whose startup or stored region does not sum to zero; it would be rejected with `Invalid startup trailer checksum` or `Invalid image trailer checksum` |
| Q2 | `machine` is the ELF `e_machine` of the startup program, without the ELF class | An image whose startup code disagrees with its machine (the container notes the code model's family); class-dependent machines name no target (`a_machine_whose_width_depends_on_the_elf_class_names_no_target`) |
| Q3 | The `ZLIB` compression is a gzip stream (mkifs `gzopen`, dumpifs `gzdopen`) | A ZLIB image whose stream starts with a zlib header (`78 xx`) instead of `1F 8B`: it would be kept opaque with a note |
| Q4 | LZO and UCL blocks are framed by big-endian 16-bit lengths and end with a zero length, and each LZO block is one complete LZO1X stream | An LZO image whose blocks do not consume exactly their stored length; it would be kept opaque with a note |
| Q5 | Directory entries keep 32-bit fields on 64-bit targets | Secondary evidence only (lclevy/dumpifs reads a QNX 7 AArch64 image with the same layout); a QNX 7 or 8 image whose directory fails to parse |
| Q6 | The boot prefix runs on the processor that the machine names | An image whose boot prefix is code for another processor; the prefix slice would report the machine's ISA |
| Q7 | A prefixed startup header has `preboot_size` equal to its file offset (mkifs `bsize`, with no `notloaded=` bytes) | A prefixed image built with `notloaded=`; it would not be recognized |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| UCL (NRV2B) compression, the `+compress` default | Not decoded (no decoder in the crate); the compressed image filesystem is opaque, block framing checked, members not listed |
| QNX 8.0 `addr_off` (64-bit address offset) | Not read: the 8.0 documentation lists it but does not fix its offset (0x38 per a secondary reader); addresses are reported without it |
| `chain_paddr` (chained image filesystems) | Noted, not followed |
| `extattr_offset` | Ignored; its meaning is not documented |
| `IMAGE_SIGNATURE_REV` (`sfegami`) | Not recognized; its use is not documented |
| Images wrapped by mkifs filters (ELF, S-record) | Classified as the wrapper format |
| Undefined `flags1` bits (0xE0) and image flags (0xF8) | Reported in notes, not interpreted |
| Symbolic link targets and devices | Counted, not resolved |

## Verification

On 2026-10-13 (macOS 27.2 AArch64, rustc 1.100.0-nightly 2026-09-05,
Node 25.8.1), `tests/qnx.rs` (16 tests) and the `formats::qnx` unit tests
(13 tests) passed, with every-prefix truncation sweeps and 0x00/0xFF/bit-flip
mutation sweeps over a stored image with a boot prefix and gzip-, LZO- and
UCL-compressed images, and mutation sweeps with recomputed checksums over a
bare image filesystem and the decoded image filesystem of an LZO image.
`web/tests/qnx.test.mjs` (4 tests) passed through `/pkg/zrax.js`,
`/dist/zrax.js`, `/web/index.html` and `/dist/index.html`. All committed
fixtures are synthetic, built in the tests from the documented layouts
with ELF headers as members; no QNX images are redistributed and no
fixture comes from mkifs, which was not available. The UCL-compressed x86
image `qnx.ifs` from vocho/openqnx `cc95df35` was classified locally
through `QNX_IFS_FIXTURE` (header at 0x3F8 after a 1016 B boot prefix,
both checksums verified, x86 target); without the variable that test skips.
gzip and LZO decoding of images written by mkifs is not verified.
