# Espressif firmware

`src/formats/esp.rs` and its submodules parse Espressif application and
bootloader images and whole flash dumps into the shared container model
([compressed streams and the container model](compressed-streams.md)).
Images become load sections (instruction-range segments) and opaque
children (data segments); flash dumps become children: the bootloader, the
partition table and each partition by label, every image classified from
its own bytes.

## Implemented layouts

| JSON format ID | Layout | Architecture evidence | Primary source |
| --- | --- | --- | --- |
| `espfirmware` (variant `ESP32-family image`) | 24-byte `esp_image_header_t` (magic `0xE9`, segment count, SPI mode, flash size and frequency, entry, WP pin, pin drive, chip ID, chip revisions, `hash_appended`); up to 16 segments; XOR checksum; SHA-256 digest when `hash_appended` is 1; `esp_app_desc_t` or `esp_bootloader_desc_t` at the start of segment 0 | `chip_id` is an explicit target field. ESP-IDF `Kconfig` names the architecture: ESP32, ESP32-S2 and ESP32-S3 are Xtensa (cores LX6, LX7, LX7 from `core-isa.h`); ESP32-C2, -C3, -C5, -C6, -C61, -H2, -H21, -H4, -P4 and -S31 are 32-bit RISC-V. An undocumented chip ID (and ESP32-E22, which only esptool lists) names no target; the code model decides | esptool v5.4.0 (`5ac7935ee036`) `esptool/bin_image.py`, `esptool/targets/*.py`; ESP-IDF v5.5.1 (`fcae32885b02`) `components/bootloader_support/include/esp_app_format.h`, `components/bootloader_support/src/esp_image_format.c`, `components/esp_app_format/include/esp_app_desc.h`, `components/esp_bootloader_format/include/esp_bootloader_desc.h`, `Kconfig`; ESP-IDF v6.1 (`fff9895c82d7`) `Kconfig` and `esp_app_format.h` for ESP32-S31 |
| `espfirmware` (variant `ESP8266 image (version 1)`) | 8-byte common header (`0xE9`), segments, checksum; an appended SHA-256 digest (esptool's version 3 writer) is accepted when it matches | The layout is specific to the ESP8266 (esptool `ESP8266ROMFirmwareImage`): Xtensa, core lx106 (`LX3.0.1`) | esptool `bin_image.py`; `ESP8266_RTOS_SDK` v3.4 (`89a3f254b638`) `components/esp8266/include/xtensa/config/core-isa.h` |
| `espfirmware` (variant `ESP8266 image (version 2)`) | `0xEA` header, IROM segment (not in the checksum), second `0xE9` header, RAM segments, checksum, `esp8266_crc32` of the whole image | As version 1 | esptool `bin_image.py` (`ESP8266V2FirmwareImage`, `esp8266_crc32`) |
| `espfirmware` (variant `Ambiguous ESP image`) | An `0xE9` image that validates both with the 24-byte header and as a version 1 image | None: the layout is not determined, nothing is analyzed | As above |
| `espflash` | Partition table at 0x8000 (32-byte records, magic `0x50AA`, at most one MD5 record `0xEBEB` over the records before it, terminator `0xFFFF`/`0xFF`/`0xFF`, at most 0xC00 bytes); bootloader at 0x0, 0x1000 or 0x2000 | None at the dump level: the bootloader and application images name their own chips | ESP-IDF v5.5.1 `components/bootloader_support/include/esp_flash_partitions.h`, `components/bootloader_support/src/flash_partitions.c` (`esp_partition_table_verify`), `components/partition_table/gen_esp32part.py`, `components/partition_table/Kconfig.projbuild`, `components/bootloader/Kconfig.projbuild`, `components/esp_partition/include/esp_partition.h`; esptool `BOOTLOADER_FLASH_OFFSET` |

### Segments and memory roles

Each segment is placed by its load address in the chip's esptool
`MEMORY_MAP`, as esptool `get_memory_type` does:

| Role | Regions | Result |
| --- | --- | --- |
| Instruction | IROM, IRAM, `DIRAM_IRAM`, `RTC_IRAM` | Load section at the load address; analyzed as code |
| Data | DROM, DRAM, `DIRAM_DRAM`, `RTC_DRAM`, `RTC_DATA`, `EXTRAM_DATA` | Opaque child, never analyzed |
| Padding | `PADDING` (0x0-0xFFFF, every ESP32-family chip) | Counted, not listed (ESP-IDF `should_load` never loads it) |
| Unmapped | No listed region | Opaque child |
| Unknown | Undocumented chip | Load section; analyzed as code |

On the ESP32-C5, -C6, -C61, -H2, -H21, -H4, -P4, -S31 and -E22, and in the
RTC memory of the ESP32-C3 and -S3, an instruction region and a data region
coincide. Segments there are analyzed as code and a note says that they may
hold data. The ESP8266 version 2 IROM segment stores load address 0; its
mapped address depends on where the image is written, so it is a load
section at its stored address with a note.

### Flash dumps

| Component | Child |
| --- | --- |
| Bootloader | The first of 0x0, 0x1000, 0x2000 where an image validates, sliced to the image; a note compares the offset with the chip's documented one; data before it that is not erased is an opaque child. No image: noted when the region is erased, otherwise an opaque `Bootloader region` |
| Partition table | Opaque, 0x8000 to the end of the terminator record |
| `app` and `bootloader` partitions | The image, sliced to its length, classified on its own; data after it that is not erased is an opaque child; a partition that is not a valid image is opaque (it may be encrypted) |
| `data` and custom-type partitions | Listed as their own format when the classifier recognizes the bytes (4 KiB prefix first), otherwise opaque |
| `partition_table` partitions | Opaque |
| Encrypted (`PART_FLAG_ENCRYPTED`) | Opaque |
| Erased (all 0xFF), empty, outside or past the end of the dump | Noted; a truncated partition keeps its available bytes |

## Wire units and byte order

All fields are little-endian; offsets and sizes are bytes; load addresses
and the entry point are target byte addresses. The checksum offset is
counted from the image start (the file start for a standalone image). The
chip ID determines the code byte order: Xtensa cores have
`XCHAL_HAVE_BE` 0, and RISC-V instruction parcels are little-endian.

## Validation and resource bounds

- The image magic is one byte (`0xE9` also starts x86 `JMP rel32` code), so
  images are recognized in the weak position of `detect_format` and only
  when everything validates: 1 to 16 segments, each length a multiple of 4
  below 16 MiB with its data in the file, the XOR checksum (seed 0xEF) at
  the end of its 16-byte block, `hash_appended` 0 or 1, the SHA-256 digest
  when flagged, the version 2 CRC-32, the entry point inside a segment with
  a non-zero load address, and only erased flash (0x00/0xFF) after the
  image. Data after a verified digest or CRC is listed as an opaque child
  (ESP-IDF appends secure boot signatures there; they are not parsed).
- Flash dumps are recognized in the strong position from the partition
  table: every record up to the terminator carries a record magic, at most
  96 records. An MD5 record that does not match is a parse error.
- Segment counts are bounded (16) before allocation; the partition table
  is bounded to 96 records; nothing is decoded or copied, so
  `MAX_EXTRACTED` is not reached. Container nesting is capped by `lib.rs`.
- The MD5 is a small RFC 1321 implementation in `src/formats/checksum.rs`,
  unit-tested against the RFC 1321 appendix A.5 suite; SHA-256 uses the
  `sha2` crate already in the dependency tree.

## Assumption register

| ID | Assumption | Falsification probe |
| --- | --- | --- |
| E1 | The entry point of every real image lies in one of its segments | `entry_must_be_inside_a_loaded_segment`; a RAM-loaded image whose entry is in ROM would not be recognized |
| E2 | esptool's version 2 writer appends the CRC-32 to every version 2 image, so it is required | `esp8266_version_1_and_2_images_are_xtensa_lx106`; a version 2 image from another writer without the CRC would not be recognized |
| E3 | Images end after the checksum and digest; only a verified digest or CRC allows other data after them | `erased_flash_after_an_image_is_noted_and_other_data_needs_a_digest`; esptool `--ram-only-header` images, whose flash segments follow the checksum uncounted, are not recognized |
| E4 | Load addresses separate code from data where the chip's instruction and data regions are distinct | `only_instruction_range_segments_are_load_sections`, `data_segments_never_reach_the_code_model`; unified-memory chips are noted (`unified_memory_segments_are_code_with_a_note`) |
| E5 | The application descriptor starts segment 0 and is recognized by its 4-byte magic; the bootloader descriptor (one-byte magic) only with printable NUL-terminated strings | `esp32_application_names_xtensa_lx6_and_reads_the_descriptor`, `esp32_bootloader_reads_the_bootloader_descriptor`, and the ESP-IDF v5.2 image in `testbins/` |
| E6 | The partition table is at the default offset 0x8000 | A dump built with another `CONFIG_PARTITION_TABLE_OFFSET` is not recognized as `espflash` |
| E7 | A random file does not carry valid record magics up to a terminator at 0x8000 | `flash_dump_md5_and_records_are_verified` (a broken record magic is not recognized) |

## Known boundaries

| Boundary | Behavior |
| --- | --- |
| Secure boot signature blocks, flash encryption | Signature blocks after a verified digest are listed as opaque, not parsed or verified; encrypted images do not validate and are listed as opaque |
| esptool `--ram-only-header` images | Not recognized (see E3) |
| A moved partition table | Not found (see E6) |
| Standalone partition table files (`partition-table.bin`) | Not recognized |
| OTA data (`otadata`), NVS, PHY and filesystem partitions (SPIFFS, FAT, LittleFS) | Opaque unless the classifier recognizes the bytes; the active OTA slot is not determined |
| ESP32-E22 | Named from esptool; no ESP-IDF release names its architecture, so no target |
| ESP8266 version 2 IROM address | Not encoded; reported as 0 |
| Extensions of the code sections | When opaque data segments are listed, `lib.rs` (`classify_container`) does not scan the load sections for extensions; images without data segments are scanned |

## Verification

On 2026-10-13 (macOS AArch64, rustc 1.100.0-nightly):

- `tests/esp.rs`: 24 tests passed, covering ESP32 (Xtensa) applications and
  bootloaders, ESP32-C3 and ESP32-C6 (RISC-V) images, an undocumented chip
  ID, ESP8266 version 1 (with and without a digest) and version 2 images,
  an ambiguous image, flash dumps (bootloader at 0x0 and 0x1000 and the
  documented-offset check, flags, truncated and outside partitions, an
  invalid application, a data partition holding an ELF, MD5 and record
  checks),
  every-prefix sweeps of each image layout and a sampled prefix sweep of a
  flash dump, and 0x00/0xFF/bit-flip mutation sweeps (every byte of the
  images; the partition table and every 251st byte of the dump). All
  fixtures are built in the tests from the documented layouts; the RISC-V
  and Thumb code inside them is `tests/fixtures/mcu` (clang output).
- One real image: the ESP32-C3 application built by ESP-IDF v5.2 that is
  tracked in `testbins/fw1-riscv64.bin` parses with checksum and digest
  verified (`real_esp_idf_image_parses_with_checksum_and_digest_verified`).
- Unit tests in `src/formats/esp*` (11) and the MD5 test in
  `src/formats/checksum.rs` (RFC 1321 suite, every split point) passed.
- `web/tests/esp.test.mjs`: 4 tests passed through `/pkg/zrax.js`,
  `/dist/zrax.js`, `/web/index.html` and `/dist/index.html`.
- The full native suite (`cargo test --all-features --locked`: 1037 passed,
  6 ignored) and the full browser suite (130 tests: 126 passed, 4 skipped
  because the D10 and RX113 firmware is not in the repository) passed.

Not verified: images written by esptool or ESP-IDF other than the one in
`testbins/` (esptool is not installed here), ESP8266 images from real SDK
builds, Xtensa code-model agreement (no Xtensa compiler is installed; the
Xtensa fixtures take their ISA from the chip ID), and flash dumps read from
real devices.
