# SoC boot images

`src/formats/socboot.rs` and its submodules `zynq`, `imx` and `nxp_sb` parse
Xilinx Zynq-7000 and Zynq UltraScale+ MPSoC (ZynqMP) `BOOT.BIN` images, NXP
i.MX HAB images and i.MX 8/9 AHAB containers, and NXP Secure Binary files
into the shared container model
([compressed streams and the container model](compressed-streams.md)). Each
boot partition, boot-ROM image or container image is a child classified on
its own bytes. Bitstreams, encrypted images, configuration data,
certificates and signatures are opaque children and never reach the code
model.

## Implemented layouts

| JSON format ID | Layout | Recognition | Architecture evidence | Primary source |
| --- | --- | --- | --- | --- |
| `xilinxbootbin` | ZynqMP: boot header (checksum verified), PMU firmware and FSBL located by the boot header, image header table (checksum verified), image header chain, partition header `next` chain (checksums verified) | Strong: `0xAA995566` at 0x20 and `XNLX` at 0x24 | Boot header attribute bits 11:10 name the FSBL CPU (container target). Partition attribute bits 11:8 name the destination CPU: A53-0..3 with bit 3 clear is AArch64, set is 32-bit Arm; R5-0, R5-1 and R5 lockstep are 32-bit Arm (little-endian unless attribute bit 18 says big-endian, then the code decides); PMU is little-endian MicroBlaze. Destination device PL is an opaque bitstream | Bootgen `d93c3fa6e6ef8aa1d4fb4532c58ed4a5efa8804e` (`zynqmp/include/bootheader-zynqmp.h`, `zynqmp/src/bootheader-zynqmp.cpp`, partition header table sources); AMD UG1283 "Zynq UltraScale+ MPSoC Boot Header", "Boot Header Attribute Bits", "Image Header Table", "Partition Attribute Bits"; U-Boot `5e3b01c8466dbe45cd6a06299f8f4c7e8c1c2363` `tools/zynqmpimage.[ch]` |
| `xilinxbootbin` | Zynq-7000: boot header (checksum verified), FSBL, image header table, image header chain, contiguous partition header array ending in the null header (checksums verified) | Strong: same signature | The boot header names no CPU. Partition destination device PS is the Cortex-A9 processing system (32-bit Arm, little-endian instructions); PL is an opaque bitstream; other devices name nothing | Bootgen `zynq/include/bootheader-zynq.h`, `partitionheadertable-zynq.h`; UG1283 "Zynq-7000 SoC Boot Header", "Image Header Table", "Partition Header", "Partition Attribute Bits"; U-Boot `tools/zynqimage.c` |
| `imximage` | HAB image: IVT (tag `0xD1`, length `0x0020`, version `0x4X`) at file offset 0, 0x400 or 0x1000; boot data; DCD (length only); CSF (presence only) | Strong position, but only when the IVT is consistent: reserved words zero, boot data after the IVT and in the file, the IVT and boot data inside the declared image, the entry point in the application bytes after the headers, DCD and CSF pointers valid | None: no IVT field names a CPU. The application bytes are a raw-code child for the code model | U-Boot `include/imximage.h`, `tools/imximage.c`, `arch/arm/include/asm/mach-imx/hab.h`, `arch/arm/mach-imx/hab.c`; SPSDK `fb0f666d2c4c0260face05d5ccc8238154465eea` `spsdk/image/hab/segments/seg_ivt.py`, `hab_header.py` |
| `imximage` | AHAB container (version 0 or 2, tag `0x87`) at file offset 0, and a second container at 0x400 (version 0) or 0x4000 (version 2) when one validates there; image array entries; signature block (tag `0x90`) | Weak: the whole header, every image range and the signature block must validate, and at least one image must be non-empty | None: the image flags' core ID is SoC-specific and the container does not name its SoC. Executable images (type 3) are children for the code model; every other type and every encrypted image is opaque | U-Boot `include/imx8image.h`, `tools/imx8image.c`; SPSDK `spsdk/image/ahab/ahab_container.py`, `ahab_iae.py`, device databases |
| `nxpsb` | SB2.0: 0x60-byte header in 16-byte blocks, header HMAC, key blob, encrypted certificate section (signed), encrypted boot sections, signature after the counted image (signed). SB2.1: header, boot section HMAC, key blob, certificate block V1 at 0xD0, optional SHA-256 of the boot sections, signature, encrypted boot sections | Strong: `STMP` at 0x14, `sgtl` at 0x34, major version 2 | None; metadata only | SPSDK `spsdk/sbfile/sb2/headers.py`, `sb2/images.py` (`BootImageV20`, `BootImageV21`), `spsdk/image/cert_block/cert_block_v1.py`, `rkht.py` |
| `nxpsb` | SB3.1: 0x3C-byte header, block 0 (hash of block 1, certificate block V2.1 `chdr`, ECDSA signature), data blocks of 292 (SHA-256) or 308 (SHA-384) bytes; the block hash chain is verified | Strong: `sbv3` and major version 3 | None; metadata only | SPSDK `spsdk/sbfile/sb31/images.py`, `spsdk/image/cert_block/cert_block_v21.py` |

SPSDK files other than those listed in the spec notes (`sb2/images.py`
method bodies, `cert_block_v1.py`, `rkht.py`, `cert_block_v21.py`,
`ahab_container.py`) were read at the pinned revision on 2026-10-13. The
PMU core type comes from Xilinx `embeddedsw` (master branch, read on
2026-10-13, not pinned): `lib/sw_apps/zynqmp_pmufw/data/zynqmp_pmufw.tcl`
accepts only the "PMU Microblaze processor (psu_pmu)", and
`lib/sw_apps/zynqmp_pmufw/src/Makefile` builds with
`-mlittle-endian -mcpu=v9.2`. UG585 and UG1085 were not read.

## Wire units and byte order

- `BOOT.BIN`: every field is a 32-bit little-endian word. The boot header's
  table offsets (0x98, 0x9C) and FSBL source offset are bytes; offsets in
  the image header table, image headers and partition headers are 32-bit
  word offsets from the start of the file, and partition lengths are in
  words. Both are converted to bytes with checked arithmetic. Image names
  are stored four characters per word, each word big-endian. ZynqMP
  partition load and execution addresses are 64-bit, Zynq-7000 ones 32-bit.
- i.MX HAB: the header word is tag, big-endian length, version; IVT
  pointers and boot data are little-endian absolute addresses, mapped to
  file offsets as `pointer - self + IVT file offset`. Sizes are bytes. DCD
  command payloads are big-endian and are not interpreted.
- AHAB: version, little-endian length, tag (in that order), then
  little-endian fields; image offsets are bytes relative to the container
  header.
- SB2 sizes and offsets in the header are 16-byte cipher blocks, except
  the certificate block offset, which is bytes. SB3.1 fields are
  little-endian bytes.
- Header byte order is never reported as code byte order. ZynqMP partition
  bit 18 (big-endian) leaves the Cortex-R5 instruction order to the code;
  A53 code is little-endian in both execution states; the PMU is
  little-endian whatever bit 18 says (the classifier warns when the code
  model disagrees). The ZynqMP boot header has no endianness field, so an
  R5 FSBL's byte order comes from its code.

## Family decision for `BOOT.BIN`

Zynq-7000 and ZynqMP share the signature and the checksummed words, so the
image is validated completely under both layouts. Bootgen's Zynq-7000 QSPI
configuration word (1 at 0x44) sets a bit the ZynqMP attribute word never
uses (bits 31:18 and 1:0 are neither defined by UG1283 nor written by
Bootgen); the Zynq-7000 image header table is 0xFF-filled where ZynqMP
stores a checksum; and partition headers link to their image header at 0x24
(Zynq-7000) or 0x30 (ZynqMP), with data offsets at 0x14 or 0x20. An image
that validates as both, typically a header-only U-Boot `mkimage` image
without PMU firmware, is reported as `Ambiguous Zynq-7000/ZynqMP boot
header`, opaque, with an unknown ISA and no children.

The boot ROM's own images are listed from the boot header: on ZynqMP the
PMU firmware at the source offset and the FSBL after its stored size, on
Zynq-7000 the FSBL. A partition whose data overlaps them (Bootgen's
"FSBL + PMU" partition) is described in a note and not listed a second
time, so MicroBlaze and Arm code are never one child. The ZynqMP FSBL takes
the boot header's CPU select; the Zynq-7000 FSBL takes the destination of
the partition that holds it, and no target when no partition does. A
partition whose bytes start a recognized format (an ELF, a device tree)
keeps that format's own evidence instead of the destination target.

## Secure Binary placement

- SB2.1 certificate block V1 (SPSDK `CertBlockV1.export`, `raw_size`): the
  32-byte header (header size field 32), the certificate table
  (`certificate count` entries of a 32-bit length and the certificate
  bytes, `certificate table length` bytes in all), the 128-byte root key
  hash table (`RKHTv1`: four SHA-256 values), padded to 16 bytes.
- SB2.1 with flag 0x8000: SPSDK `BootImageV21.export` writes the SHA-256
  of the boot sections between the certificate block and the signature,
  but `update` and `raw_size` leave it out of the header's first boot tag
  block and image block count. The parser therefore places the boot
  sections and the image end 32 bytes after the header's counts.
- Signed SB2.0 (flag 0x08): `BootImageV20.export` appends the signature
  after the `image_blocks` the header counts, and `parse` verifies it over
  `data[image_size:]`. The bytes between the key blob and the first boot
  tag block are the encrypted certificate section.
- SB3.1 block 0 (`SecureBinary31Header`, `export`): header, hash of data
  block 1, certificate block V2.1 (its size field covers the whole block),
  then a 64-byte (SHA-256) or 96-byte (SHA-384) ECDSA signature; the
  header's image total length ends block 0.

## Validation and resource bounds

- `BOOT.BIN`: boot header checksum always; image header table checksum
  (ZynqMP); every partition header checksum, the null header included.
  Table structures must lie after the boot header (0x8A0 bytes on
  Zynq-7000, 0x8B8 on ZynqMP plus 1544 bytes of PUF helper data when
  attribute bits 7:6 are 3). At most 254 partition headers and 254 image
  headers (Bootgen's reader limit, below 0xFF), with loop detection on both
  chains; image names at most 256 bytes; PMU firmware at most 128 KiB;
  every partition's total length inside the file and its encrypted and
  unencrypted lengths within the total; each partition must name a listed
  image header and each image header a listed partition; a non-zero
  partition header table offset at 0x9C must match the image header table.
- i.MX HAB: three probe offsets (0, 0x400, 0x1000); the DCD length must be
  at least 4 bytes and inside the file; the CSF pointer must lie in the
  declared image after the headers. A declared image that extends past the
  end of the file (U-Boot reserves the CSF area before signing and rounds
  the image to 4 KiB) is noted with the missing byte count.
- AHAB: at least one image entry; legacy hash types 0-2 only; images at or
  after the header and inside the file; the signature block directly after
  the image array with tag `0x90`, a length of at least 16 bytes and inside
  the file; the container length must end after the signature block header
  (U-Boot) or after the whole signature block (SPSDK). Recognition also
  needs a non-empty image in the first container. At most two containers
  are parsed; empty images do not extend the container size.
- SB2: header block count 6; minor version 0 or 1; the declared image
  inside the file; key blob after the header and HMAC; first boot tag
  block after the key blob and inside the image. SB2.1: certificate block
  offset 0xD0, `cert` magic, header size 32, at least one certificate and
  no more than the table's length allows, every certificate inside the
  table, and the certificate block, section hash and a non-empty signature
  before the boot sections. Signed SB2.0: a non-empty signature after the
  image.
- SB3.1: minor version 1; block size 292 or 308; certificate block offset
  `0x3C + hash length` with `chdr` magic inside block 0; signature size
  64 or 96 bytes to match the hash; block 0 inside the file; the declared
  block count no more than the bytes present allow; every block number
  sequential; every block's SHA-256/SHA-384 equal to the hash stored in the
  previous block, and the last block's next-hash zero.
- Trailing bytes after the described image are ignored when they are
  0x00/0xFF, otherwise noted and listed when they start a recognized format.
  Children are capped at 4096 and container nesting at six levels by the
  shared model.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| S1 | The ZynqMP PMU is a little-endian MicroBlaze core (Xilinx `embeddedsw` `zynqmp_pmufw` build files; UG1085 not read) | A Bootgen PMU firmware partition whose ELF has `e_machine` MicroBlaze (189) and `EI_DATA` little-endian; `zynqmp_pmu_partition_is_microblaze_and_aarch32_boot_cpu_is_arm` pins the mapping |
| S2 | Every Zynq-7000 PS partition is Cortex-A9 code (a device fact; UG585 not read) | A Zynq-7000 BOOT.BIN whose PS partition is raw data: the code model's family is then overridden; recognized formats keep their own evidence |
| S3 | A Zynq-7000 partition is encrypted when the boot header names a key and its stored length differs from its original length | A Bootgen Zynq-7000 image with `[encryption=aes]` on one partition only: the unencrypted partitions must keep equal lengths |
| S4 | The ZynqMP FSBL follows the PMU firmware at `source + total PMU length` | Bootgen output with `[pmufw_image]`; U-Boot `zynqmpimage_pmufw` places the FSBL right after the PMU firmware |
| S5 | No Bootgen Zynq-7000 image validates as ZynqMP, and no ZynqMP image with tables validates as Zynq-7000 | `zynq7000_without_qspi_word_is_identified_by_its_table`, `zynqmp_partitions_take_their_destination_cpu_as_target` |
| S6 | HAB 4 IVTs carry version `0x4X` (U-Boot `hab.c`; SPSDK accepts `0x40..=0x4E`), not only `0x40..=0x43` | An i.MX image with IVT version `0x44` or later from a current NXP tool |
| S7 | Boot data lies after the IVT and the entry point lies in the application bytes after the IVT, boot data and DCD | MCUXpresso i.MX RT XIP images and U-Boot `u-boot.imx`, `flash.bin` for i.MX 8M |
| S8 | Every AHAB container has a signature block right after the image array (SPSDK `parse` reads one unconditionally; U-Boot always writes its header) | An unsigned SPSDK i.MX 93 container: it must still carry the `0x90` header |
| S9 | The SB3.1 block hash covers the whole next block (number, next hash, payload) and the last block's next hash is zero | An SPSDK `nxpimage sb31 export` file; the hash chain check fails otherwise |
| S10 | SB2.1 writers leave the boot section SHA-256 out of the header's block counts, as SPSDK does | An SB2.1 file with flag 0x8000 from SPSDK or the older `elftosb`: its size must be `image_blocks × 16 + 32` |
| S11 | The SB2.0 signature is everything after the counted image | A signed SPSDK SB2.0 file: the trailer length must equal the RSA modulus size of the last certificate |
| S12 | The SB3.1 signature is 64 bytes with SHA-256 blocks and 96 bytes with SHA-384 blocks | An SPSDK SB3.1 file signed with a P-384 key but SHA-256 blocks, if any tool allows it |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Header-only `BOOT.BIN` valid as both families | Reported as ambiguous; no ISA, no children |
| ZynqMP partition headers that do not link to an image header (U-Boot `zynqmpbif` output was not checked) | Parse error under both families |
| Versal PDI (signature at 0x10/0x14) | Not recognized |
| `BOOT.BIN` authentication certificates, partition checksums (MD5, SHA-2, SHA-3) and FSBL SHA-3 integrity | Reported as present, not verified |
| i.MX IVTs at other offsets (OneNAND 0x100, SD images at 32/33 KiB) and second IVTs (plugins, i.MX 8M FIT) | Not probed; only the first consistent IVT is parsed |
| Legacy v1 flash header (`0x000000B1` barker) | Not recognized |
| DCD commands, CSF commands, certificates and signatures | Not interpreted, not verified |
| AHAB core IDs | Reported as numbers; never mapped to an ISA, because the SPSDK device databases and U-Boot assign different cores to the same ID and the container does not name its SoC |
| AHAB containers beyond the second, SPSDK placements at 0x8000 or 0x1000, tag `0x82` headers | Not probed |
| AHAB image hashes and signature blocks | Not verified |
| SB1 (`STMP`/`sgtl`, major version 1), SB4, SBx, SBc | Not recognized |
| SB2.1 files whose header counts include the boot section SHA-256 | Parse error or misplaced boundaries (see S10) |
| SB2 header and boot section HMACs, key blob, certificates, signatures; SB3.1 ECDSA signature and certificate block | Not verified; encrypted contents are not decrypted |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly f248f4038, Node
v25.8.1 with Playwright Chromium), the module unit tests (18) and
`tests/socboot.rs` (28 tests) passed, including every-prefix truncation
sweeps over ZynqMP and Zynq-7000 images, an AHAB `flash.bin` and all
Secure Binary variants (the signed SB2.0 sweep up to the end of the
counted image, since its signature has no length field), a truncation
sweep over a `u-boot.imx` image, and a 0x00/0xFF/bit-flip mutation sweep
over every byte of eleven fixtures (every seventh mutation through the
whole classifier). `cargo test --all-features --locked` passed with 546
tests and 6 ignored. The browser test `web/tests/socboot.test.mjs` (4
tests: classification through `/pkg/zrax.js` and `/dist/zrax.js`, and the
workbench in `/web/` and `/dist/`) passed, and the whole browser suite
passed 73 of 77 tests with 4 skipped (they need D10/RX113 firmware that is
not in the repository). All fixtures are synthetic, built in the tests
from the documented layouts with committed code fixtures
(`tests/fixtures/transforms/aarch64.text.bin`,
`testbins/arm32_arm-unknown-linux-gnueabi_O0_int_crc32.bin`) as payloads.
No Bootgen, U-Boot `mkimage` or SPSDK output was available, so
compatibility with tool-generated images is not verified.
