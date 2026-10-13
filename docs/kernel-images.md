# Kernel and boot images

`src/formats/kernel.rs` and its submodules parse Linux kernel images, U-Boot
uImages and FIT images, and flattened device trees into the shared container
model ([compressed streams and the container model](compressed-streams.md)).
Compressed kernel payloads are decoded and classified from their own bytes,
so extension detection, header/code cross-checks and nested containers run on
kernel code instead of compressed data.

## Implemented layouts

| JSON format ID | Layout | Architecture evidence | Primary source |
| --- | --- | --- | --- |
| `uimage` | 64-byte big-endian header; header CRC-32 (field zeroed) and data CRC-32 verified; single images and multi-file images (size table, 4-byte padding); compression IDs 0-6 decoded; data after the image listed when it is a recognized format | Architecture ID names the ISA. The code byte order comes from the ID where it fixes one (x86, AArch64, RISC-V, SPARC, M68K, ...), otherwise from the decoded payload; undetermined orders are reported as `bi_endian`. Architecture ID 19 (sandbox) names no ISA | [U-Boot v2024.10 `include/image.h`](https://source.denx.de/u-boot/u-boot/-/blob/v2024.10/include/image.h) |
| `fit` | Device tree with `/images`; inline `data`, external `data-offset` (from the 4-byte-aligned end of the tree) or `data-position`; `compression` decoded; default configuration's kernel names the primary target | Each image's `arch` names its ISA for executable types (kernel, firmware, standalone, loadable, TEE); `fpga` and `script` images are opaque | [U-Boot `source_file_format.rst`](https://docs.u-boot.org/en/latest/usage/fit/source_file_format.html) |
| `dtb` | Flattened devicetree v17: header, structure tokens, string table; root `model` and `compatible` in notes | None: a device tree is data and never reaches the code model | [Devicetree Specification v0.4, chapter 5](https://github.com/devicetree-org/devicetree-specification/releases/tag/v0.4) |
| `zimage` (x86) | Setup header; `xloadflags` (2.12+); `payload_offset`/`payload_length` (2.08+) relative to the protected-mode code at `(setup_sects + 1) * 512`; image CRC-32 (2.08+) checked and reported | `XLF_KERNEL_64` gives x86-64; protocol 2.12+ without it gives x86. From 2.08 to 2.11 the decoded ELF `vmlinux` supplies the ISA; before 2.08 the boot code is x86 and the kernel width is not recorded | [Linux `boot.rst`](https://docs.kernel.org/arch/x86/boot.html) |
| `zimage` (Arm) | Magic `0x016F2818` at 0x24, start/end at 0x28/0x2C, endianness flag at 0x30; little-endian, BE8 and BE32 storage; optional extension table (`0x45454545`, `KLSZ` tag) | Arm. Data byte order from the flag and magic storage; BE8 instructions are little-endian, BE32 instructions big-endian | Linux v6.12 `arch/arm/boot/compressed/head.S`, `vmlinux.lds.S` |
| `zimage` (EFI zboot) | `MZ\0\0` + `zimg` DOS header with payload offset/size and compression name (`gzip`, `lz4`, `lzma`, `lzo`, `xzkern`, `zstd22`), `LINUX_PE_MAGIC`; recognized before the generic PE check | PE `Machine` of the stub names the kernel architecture; the decoded `Image` is classified as a child | Linux v6.12 `drivers/firmware/efi/libstub/zboot-header.S`, `Makefile.zboot` |
| `zimage` (AArch64) | 64-byte `Image` header, magic `ARM\x64` at 0x38; flags bit 0 (big-endian data) noted | AArch64, little-endian instructions | [Linux `arm64/booting.rst`](https://docs.kernel.org/arch/arm64/booting.html) |
| `zimage` (RISC-V) | 64-byte `Image` header, `RISCV` at 0x30 or `RSC\x05` at 0x38 | RISC-V; the header does not encode XLEN, so 64-bit is assumed and noted | [Linux `riscv/boot-image-header.rst`](https://docs.kernel.org/arch/riscv/boot-image-header.html) |
| `bflt` | 64-byte big-endian header; text from 0x40 to `data_start`; `FLAT_FLAG_GZIP` text decoded | None, except `FLAT_FLAG_L1STK`, which exists only on Blackfin. The ISA otherwise comes from the text | Linux v6.6 `include/uapi/linux/flat.h`, `fs/binfmt_flat.c` |

Kernels with an EFI stub (x86 `bzImage`, arm64 and RISC-V `Image`, Arm
`zImage` built with `CONFIG_EFI_STUB`) start with `MZ` and are also valid
PE files (Linux `Documentation/admin-guide/efi-stub.rst`). Like zboot
images, they are recognized before the generic PE check, because the boot
header locates the kernel and its payload, and a note says the image is also
a PE/COFF executable. An x86 file too short for the setup code and payload
its header names (headers only) is left to the PE parser.

## Payload identification

A compressed Linux payload is identified the way `lib/decompress.c` does it,
by its leading magic, with the header checks of `compressed::sniff` so a
two-byte match is not enough. LZMA-alone has only a properties byte and is
accepted as `5D` with a power-of-two dictionary. The Arm zImage header does
not record where the compressed kernel starts: the parser takes the first
offset after the header where a codec decodes, bounded by the `KLSZ` size
word when the extension table is present (at most 64 failed candidates), and
says so in a note. When the size word is present, the decoded size is
compared with it.

## Wire units and byte order

All offsets and sizes are bytes. uImage and FDT headers are big-endian; x86,
Arm (little-endian and BE8), AArch64 and RISC-V headers are little-endian;
BE32 Arm headers are big-endian. Header byte order is never reported as code
byte order. A container that states a component's code order separately (Arm
BE8 kernels) is not cross-checked against it.

## Validation and resource bounds

- uImage header and data CRCs must match; a mismatch is a parse error.
- A payload that does not decode with the named codec is kept as an opaque
  component with a note, so the header's architecture still reports.
- FDT nesting is limited to 64 levels; every node and property must lie in
  the structure block, and names in the string table.
- Decoded payloads are capped at 64 MiB and container nesting at six levels
  (see [compressed streams](compressed-streams.md)).
- The x86 image CRC is reported, not enforced, because signing tools append
  data after it.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| K1 | An architecture ID names the ISA but not always the code byte order | uImage with little- and big-endian ARM ELF payloads (`uimage_code_byte_order_comes_from_the_payload_not_the_header`) |
| K2 | A RAM disk, script or filesystem image is not code for the named architecture | uImage RAM disk with raw bytes produces no slices or candidates |
| K3 | A device tree is data | DTB classification yields no candidates |
| K4 | The first decodable codec header after the zImage header is the kernel | Bounded by the `KLSZ` size word when present; decoded size compared with it |
| K5 | The RISC-V `Image` header does not distinguish RV32 from RV64 | Reported with a note; an RV32 `Image` would be misreported as 64-bit |
| K6 | A file that starts with `MZ` and carries a Linux boot header is a kernel with an EFI stub, best described by the boot header | `efi_stub_kernels_are_kernel_images_unless_only_headers_are_present`; on 2026-10-13 Alpine's `vmlinuz-virt` (12,575,744 B, boot protocol 2.15) reported a bzImage whose gzip payload decoded to a 39,274,268 B x86-64 ELF, where it was reported as PE/COFF before |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| FIT signatures and hashes | Reported as present and not verified |
| uImage signature schemes outside the legacy header | Not recognized |
| x86 kernels before boot protocol 2.08 | ISA x86 from the boot code; kernel width not determined |
| Arm zImages without a decodable payload | Classified from the header and decompressor code only |
| Old gzip magic `1F 9E` | Not decoded |
| Raw PowerPC U-Boot binaries, which start with the uImage magic followed by `U-Boot ` (U-Boot `arch/powerpc/cpu/ppc4xx/start.S`) | Not taken for a uImage; classified as raw code (QEMU's `u-boot-sam460.bin` reports PowerPC on 2026-10-13) |

## Verification

On 2026-10-12 (macOS AArch64, rustc 1.100.0-nightly), `tests/kernel_images.rs`
(17 tests) passed, with every-prefix and every-byte mutation sweeps over a
uImage, a bzImage, an Arm zImage and a FIT. All fixtures are synthetic,
built in the tests from the documented layouts with ELF headers as payloads;
no kernel images are redistributed.
