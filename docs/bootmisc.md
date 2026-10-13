# Miscellaneous boot images

`src/formats/bootmisc.rs` and its submodules parse four boot image families
into the shared container model
([compressed streams and the container model](compressed-streams.md)):
OP-TEE OS images with the `OPTE` header, Amlogic USB burning images,
Allwinner PhoenixSuit/LiveSuit `IMAGEWTY` images (including the
RC6-encrypted variant) and barebox ARM images. Two of them name an
instruction set: the OP-TEE `arch` byte and the first instruction of the
barebox head. Amlogic and Allwinner images name none; their components are
classified on their own bytes.

## Implemented layouts

| JSON format ID | Layout (variant) | Architecture evidence | Primary source |
| --- | --- | --- | --- |
| `opteeimage` | Header version 1 (`tee.bin`, 28 B): magic `OPTE`, version, arch, flags, init size, init load address (high, low), init memory usage, paged size; the init part and the paged part follow and must end the file (erased-flash padding allowed). Both parts become children | `arch` 0 = AArch32, 1 = AArch64 is an explicit target field. AArch64 instructions are little-endian; the header does not state the A32 code byte order, so it comes from the code | optee_os tag `4.3.0` `scripts/gen_tee_bin.py` (`output_header_v1`); U-Boot `5e3b01c8` `include/tee/optee.h`, `lib/optee/optee.c` (`optee_verify_image`) |
| `opteeimage` | Header version 2 (`tee-header_v2.bin`): magic, version, arch, flags, image count (1 or 2), 16-byte records (load address high and low, image ID 0 pager or 1 paged, size); `0xFFFFFFFF`/`0xFFFFFFFF` means the loader chooses the address. The images are separate files, so there are no children; data after the table is listed only when it is a recognized format | As version 1; the entry point is the pager load address | optee_os `output_header_v2`; TF-A tag `v2.11.0` `include/lib/optee_utils.h`, `lib/optee/optee_utils.c` (`tee_validate_header`, `parse_optee_header`) |
| `amlogicupgrade` | 64-byte header (CRC-32, version 1 or 2, magic `0x27B51956` at 8, 64-bit image size, item alignment, item count), item table at 0x40 (128-byte version 1 or 576-byte version 2 records with 32- or 256-byte main and sub type names), item data; CRC-32 verified; `VERIFY` SHA-1 records checked | None | Vendor U-Boot `422c6635` `drivers/usb/gadget/v2_burning/v2_common/amlImage_if.h`, `optimus_img_decoder.c`, `v2_sdc_burn/optimus_sdc_burn.c`; Amlogic packer (yyftxws/aml_image_packer `6c954162`) `src/amlImage.cpp`, `src/crc32.cpp`, `src/sha1.c`; ampack `46066067` `src/image.rs` |
| `allwinnerimage` (`IMAGEWTY image`) | 1024-byte header (`IMAGEWTY`, header version 0x0300 or 0x0100), 1024-byte item records from offset 1024 (main type, sub type, file name, stored and file length, data offset, encryption plug-in ID), file data | None | Allwinner `imagefile_new.h`, `imgdecode.c` (copies in YuzukiTsuru/OpenixCard `b5a6ffcc` `docs/img_decode/firmware/`) for 0x0300; awutils `3f1cbb2c` `imagewty.h` for 0x0100 |
| `allwinnerimage` (`IMAGEWTY image (RC6-encrypted header)`) | As above, with header, item table and file data RC6-32/20/32-encrypted per 16-byte block with the three fixed keys awutils publishes; `.fex` files are decrypted (`RC6` decoded range); other files stay opaque | None | awutils `awimage.c` (`crypto_init`, `decrypt_image`), `rc6.c`; "The RC6 Block Cipher" v1.1 |
| `bareboximage` | Head at offset 0: eight instruction words, `barebox\0` at 0x20, text base (0x28), image size (0x2C), eight spare words (0x30), code from 0x50. The image `[0, size)` is one code section; data after it is listed only when recognized | First instruction, as the head defines it: A32 `B` past the head, A32 `adr r9`/`bx r9` (Thumb-2 head), A64 `B` past the head (`ENTRY_PROC`), or A64 `NOP` with text base `0xFFFFFFFF` (`__barebox_arm64_head`). Anything else: code model | barebox tag `v2024.10.0` `arch/arm/include/asm/barebox-arm-head.h`, `arch/arm/include/asm/barebox-arm64.h`, `arch/arm/cpu/head_64.S`, `arch/arm/lib/pbl.lds.S` |

The A32 `B` decoding and the sign extension are the eGON parser's
(`socboot2::decode_jump`, U-Boot `tools/sunxi_egon.c`); the other head
encodings were confirmed by assembling the barebox heads with clang (see
`tests/fixtures/bootmisc/README.md`).

### Amlogic item roles

| Item | Child |
| --- | --- |
| `USB`/`DDR`, `USB`/`UBOOT`, `PARTITION`/`bootloader` | Boot loader stage: always classified, by the code model when the bytes are not a recognized format |
| `USB`/`*_ENC` | Opaque: named as the encrypted stage (ampack) |
| `VERIFY`, `ini`, `conf` | Opaque configuration or verification data |
| Anything else (`PARTITION`/`boot`, `PARTITION`/`system`, `dtb`/`meson1`, `UBOOT`/`aml_sdc_burn`, ...) | Classified when its first 64 KiB start a recognized format (Android sparse, ext4, Android boot image, ELF, ...); otherwise opaque, and named in a note |

Backup items (`isBackUpItem`) share the data of an earlier item and are
listed with the same stored range. Item file types other than normal (0)
and sparse (`0xFE`) are noted.

### IMAGEWTY files

A file is classified only when it is a recognized format. Files with an
encryption plug-in ID (version 0x0300 `encryptID` not all NUL) are opaque.
In encrypted images, `.fex` files are decrypted; awutils marks an
additional Twofish layer on other files as not working
(`TF_DECRYPT_WORKING 0`), so they are opaque. Labels are
`name (main type/sub type)`.

## Wire units and byte order

All offsets and sizes are bytes; every header is little-endian. OP-TEE and
barebox addresses are target addresses; Amlogic and IMAGEWTY offsets are
file offsets from the image start. Child and slice offsets are always the
stored file range; decrypted IMAGEWTY files carry a `decoded` range with the
transform `RC6`. Header byte order is never reported as code byte order:
the barebox head instruction decides it (little-endian for every
documented head), and the OP-TEE AArch32 order comes from the code.

## Validation and resource bounds

- OP-TEE: the magic and a version byte of 1 or 2 are required for
  detection, so text starting with `OPTE` is not claimed. Version 1 parts
  must lie in the file and only erased flash may follow; the init part must
  not be empty. Version 2 needs 1 or 2 records, IDs 0 or 1, no duplicates
  (TF-A rejects the rest). An architecture byte other than 0 or 1 is an
  error.
- Amlogic: version 1 or 2; the image size covers the header; the CRC-32
  (reflected `0xEDB88320`, initial `0xFFFFFFFF`, no final XOR, over
  `[4, image size)`) must match; only erased flash may follow; the item
  table must fit the image; each item ID must equal its index and its data
  must lie in the image. A `VERIFY` record whose digest does not match is
  noted, not rejected (the CRC already holds; the burning tool would reject
  that partition). SHA-1 hashing is capped at twice the image size, so
  overlapping items cannot multiply the work; records beyond the cap are
  noted as not checked. At most 4096 items are listed.
- IMAGEWTY: header version 0x0300 or 0x0100; the item table must fit the
  file; each file's stored range must lie in the file and its file length
  must not exceed its stored length; the declared image length must not
  exceed the file; only erased flash may follow the image. Decryption is
  bounded per file by 64 MiB and in total by 256 MiB of decrypted bytes
  (`MAX_PAYLOAD`, `MAX_EXTRACTED`); files beyond either bound stay opaque.
  Per-file checksums are not verified.
- barebox: the head (0x50 bytes) must be present; the image size must
  cover it and lie in the file. A branch counts as evidence only when it
  lands in `[0x50, image size)`.
- Recognition of Amlogic and plaintext IMAGEWTY components looks at their
  first 64 KiB only.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| B1 | The OP-TEE `arch` byte names AArch32 or AArch64 and nothing else | A header with another value is a parse error (`optee_v1_sizes_must_cover_the_file_exactly`) |
| B2 | An OP-TEE version 2 header file holds no image data | gen_tee_bin.py writes the images to separate files; data after the table is listed only when recognized (`optee_v2_tables_are_checked_like_tf_a`) |
| B3 | The Amlogic CRC-32 starts at offset 4 for every item alignment | The Amlogic packer passes `itemAlginSize` (4) as the start; ampack starts at 4 and reproduces version 2 images with alignment 8. An image with alignment 8 that fails the CRC would falsify it |
| B4 | A `VERIFY` item checks the item with the same sub type just before it | Amlogic packer `image_pack` and ampack `try_read_file`; records elsewhere are counted as not checked (`amlogic_verify_records_not_in_the_packer_form_are_counted`) |
| B5 | `USB` items are boot loader stages; `_ENC` marks an encrypted one | From ampack's names only; a `USB` item that is data would reach the code model |
| B6 | IMAGEWTY header version 0x0100 follows awutils' layout | Only reverse-engineered; awimage-packed fixtures parse, real version 0x0100 images are not verified |
| B7 | Encrypted IMAGEWTY `.fex` files are RC6 only | awutils decrypts them with the data key; the decrypted fixture payload is the committed ELF (`awimage_encrypted_image_is_decrypted_with_the_published_keys`) |
| B8 | The barebox head is at offset 0 and its instruction words are little-endian | Big-endian builds and images with a prepended SoC header are not recognized as barebox |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| OP-TEE `tee-raw.bin` and `tee-pager_v2.bin` | No header; not recognized (raw code) |
| Amlogic secure-boot (`@AML`) boot loaders | Classified by the code model like any boot loader stage; the encryption is not detected |
| IMAGEWTY Twofish layer on non-`.fex` files | Not decrypted (awutils does not either); opaque |
| IMAGEWTY per-file checksums, Amlogic and Allwinner signatures | Not verified |
| barebox images wrapped in i.MX, Rockchip or eGON headers | The wrapper format is reported (the barebox head is not at offset 0) |
| Weak formats inside Amlogic or plaintext IMAGEWTY items | Not recognized beyond the first 64 KiB |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly), `tests/bootmisc.rs`
(25 tests) and the module unit tests (16) passed, with every-prefix and
byte-mutation sweeps over an OP-TEE v1 and v2 header, Amlogic version 1 and
2 images, the plaintext awimage fixture, an encrypted version 0x0300
IMAGEWTY image and A32 and A64 barebox images. `web/tests/bootmisc.test.mjs`
(4 tests, Node 25.8.1, Playwright Chromium) passed through `/pkg/`,
`/dist/`, `/web/index.html` and `/dist/index.html`. The whole native suite
(1058 tests, 6 ignored) and the whole browser suite (130 tests: 126 passed,
4 skipped because they need D10/RX113 firmware that is not in the
repository) passed on the same date. The RC6 implementation
matches the 256-bit test vectors of "The RC6 Block Cipher" v1.1 and decrypts
the awimage-encrypted fixture. Real vendor images (OP-TEE builds, Amlogic
and Allwinner firmware, barebox builds) were not tested: not verified.
