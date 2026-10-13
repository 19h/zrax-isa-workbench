//! Espressif firmware: ESP32-family images take their ISA from the chip ID
//! and send only instruction-range segments to the code model, ESP8266
//! version 1 and 2 images are Xtensa, flash dumps list the bootloader, the
//! partition table and each partition, and the segment walk, checksum,
//! SHA-256 digest, CRC-32 and partition table MD5 reject corruption.

use sha2::{Digest, Sha256};
use zrax::formats::checksum::Md5;
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{
    detect_payload, ClassificationSource, ClassifierOptions, DetectionPayload, FileFormat, Isa,
    MetadataKey,
};

/// `ESP_IMAGE_MAGIC`.
const IMAGE_MAGIC: u8 = 0xE9;
/// `IMAGE_V2_MAGIC`.
const IMAGE_V2_MAGIC: u8 = 0xEA;
/// `ESP_CHECKSUM_MAGIC`.
const CHECKSUM_SEED: u8 = 0xEF;
/// `ESP_APP_DESC_MAGIC_WORD`.
const APP_DESC_MAGIC: u32 = 0xABCD_5432;
/// Chip IDs (`esp_chip_id_t`).
const ESP32: u16 = 0x0000;
const ESP32_C3: u16 = 0x0005;
const ESP32_C6: u16 = 0x000D;
/// A chip ID no source documents.
const UNDOCUMENTED_CHIP: u16 = 0x0042;
/// ESP32 memory map (esptool `ESP32ROM.MEMORY_MAP`).
const ESP32_DROM: u32 = 0x3F40_0020;
const ESP32_IRAM: u32 = 0x4008_0000;
const ESP32_IROM: u32 = 0x400D_0020;
const ESP32_DRAM: u32 = 0x3FFB_0000;
/// ESP32-C3 memory map (esptool `ESP32C3ROM.MEMORY_MAP`).
const C3_DROM: u32 = 0x3C0A_0020;
const C3_IRAM: u32 = 0x4038_0000;
const C3_IROM: u32 = 0x4200_0020;
/// ESP32-C6 unified SRAM, both IRAM and DRAM (`ESP32C6ROM.MEMORY_MAP`).
const C6_SRAM: u32 = 0x4080_0000;
/// ESP8266 memory map (`ESP8266ROM.MEMORY_MAP`).
const ESP8266_IRAM: u32 = 0x4010_0000;
const ESP8266_DRAM: u32 = 0x3FFE_8000;
/// Partition table offset and record magics (`esp_flash_partitions.h`).
const TABLE_OFFSET: usize = 0x8000;
const PARTITION_MAGIC: [u8; 2] = [0xAA, 0x50];
const MD5_MAGIC: [u8; 2] = [0xEB, 0xEB];

const MCU_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mcu");

/// RV32IMAC code compiled by clang (`tests/fixtures/mcu/README.md`).
fn riscv32() -> Vec<u8> {
    std::fs::read(format!("{MCU_FIXTURES}/riscv32.text.bin")).expect("fixture is committed")
}

/// Cortex-M4 Thumb-2 code compiled by clang (`tests/fixtures/mcu/README.md`).
fn thumb() -> Vec<u8> {
    std::fs::read(format!("{MCU_FIXTURES}/thumbv7em.text.bin")).expect("fixture is committed")
}

/// Bytes for Xtensa segments. They are not checked as Xtensa code: these
/// tests take the ISA from the chip ID or the layout.
fn xtensa_bytes(len: usize) -> Vec<u8> {
    // `entry a1, 32`, `movi.n a2, 1`, `s32i.n a2, a1, 4`, `retw.n`.
    let pattern = [0x36, 0x41, 0x00, 0x0c, 0x12, 0x29, 0x11, 0x1d, 0xf0];
    pattern.iter().copied().cycle().take(len).collect()
}

/// Data that is plainly not code: printable strings.
fn strings(len: usize) -> Vec<u8> {
    b"ESP-IDF log message %s: %d\n\0"
        .iter()
        .copied()
        .cycle()
        .take(len)
        .collect()
}

/// A segment as the header lists it.
struct Segment {
    /// Load address.
    address: u32,
    /// Data; its length must be a multiple of 4.
    data: Vec<u8>,
}

fn seg(address: u32, data: Vec<u8>) -> Segment {
    Segment { address, data }
}

/// Segment header (load address, length, both u32 LE) and data.
fn push_segments(image: &mut Vec<u8>, segments: &[Segment]) {
    for segment in segments {
        image.extend_from_slice(&segment.address.to_le_bytes());
        image.extend_from_slice(&(segment.data.len() as u32).to_le_bytes());
        image.extend_from_slice(&segment.data);
    }
}

/// XOR of every segment data byte, seeded with 0xEF.
fn checksum(segments: &[Segment]) -> u8 {
    segments
        .iter()
        .flat_map(|s| s.data.iter())
        .fold(CHECKSUM_SEED, |sum, b| sum ^ b)
}

/// Zero padding so that the checksum is the last byte of a 16-byte block
/// (counted from the image start), then the checksum.
fn push_checksum(image: &mut Vec<u8>, value: u8) {
    while image.len() % 16 != 15 {
        image.push(0);
    }
    image.push(value);
}

/// The 8-byte common header: magic, segment count, SPI mode (2 = DIO),
/// flash size and frequency (0x20 = 4 MiB / 40 MHz on the ESP32 family),
/// entry point.
fn common_header(magic: u8, count: usize, flash: u8, entry: u32) -> Vec<u8> {
    let mut header = vec![magic, count as u8, 2, flash];
    header.extend_from_slice(&entry.to_le_bytes());
    header
}

/// An ESP32-family image: common header, extended header (WP pin 0xEE
/// disabled, pin drive 0, chip ID, legacy minimum revision 0, minimum
/// revision v0.0, maximum v0.99, four reserved bytes, `hash_appended`),
/// segments, checksum and the SHA-256 of everything before it when
/// `hash_appended` is set.
fn esp32_image(chip_id: u16, entry: u32, segments: &[Segment], hash_appended: bool) -> Vec<u8> {
    let mut image = common_header(IMAGE_MAGIC, segments.len(), 0x20, entry);
    image.extend_from_slice(&[0xEE, 0, 0, 0]);
    image.extend_from_slice(&chip_id.to_le_bytes());
    image.push(0);
    image.extend_from_slice(&0u16.to_le_bytes());
    image.extend_from_slice(&99u16.to_le_bytes());
    image.extend_from_slice(&[0; 4]);
    image.push(u8::from(hash_appended));
    push_segments(&mut image, segments);
    push_checksum(&mut image, checksum(segments));
    if hash_appended {
        let digest = Sha256::digest(&image);
        image.extend_from_slice(&digest);
    }
    image
}

/// `esp_app_desc_t` (256 bytes): magic, secure version 3, reserved,
/// version, project name, time, date, ESP-IDF version, ELF SHA-256 (0xAB),
/// eFuse block revisions, MMU page size log2 16 (64 KiB), reserved.
fn app_descriptor() -> Vec<u8> {
    let mut desc = vec![0u8; 256];
    desc[0..4].copy_from_slice(&APP_DESC_MAGIC.to_le_bytes());
    desc[4..8].copy_from_slice(&3u32.to_le_bytes());
    let mut text =
        |at: usize, value: &str| desc[at..at + value.len()].copy_from_slice(value.as_bytes());
    text(0x10, "1.2.3");
    text(0x30, "blink");
    text(0x50, "12:34:56");
    text(0x60, "Oct 13 2026");
    text(0x70, "v5.5.1");
    desc[0x90..0xB0].fill(0xAB);
    desc[0xB4] = 16;
    desc
}

/// `esp_bootloader_desc_t` (80 bytes): magic byte 80, reserved, secure
/// version 1, version 7, ESP-IDF version, date and time, reserved.
fn bootloader_descriptor() -> Vec<u8> {
    let mut desc = vec![0u8; 80];
    desc[0] = 0x50;
    desc[3] = 1;
    desc[4..8].copy_from_slice(&7u32.to_le_bytes());
    desc[8..14].copy_from_slice(b"v5.5.1");
    desc[0x28..0x3C].copy_from_slice(b"Oct 13 2026 12:34:56");
    desc
}

/// An ESP32 application: DROM starting with the application descriptor,
/// IRAM code with the entry point, IROM code, DRAM data; SHA-256 appended.
fn esp32_app() -> Vec<u8> {
    let mut drom = app_descriptor();
    drom.extend(strings(64));
    esp32_image(
        ESP32,
        ESP32_IRAM + 8,
        &[
            seg(ESP32_DROM, drom),
            seg(ESP32_IRAM, xtensa_bytes(96)),
            seg(ESP32_IROM, xtensa_bytes(128)),
            seg(ESP32_DRAM, strings(32)),
        ],
        true,
    )
}

/// An ESP32 bootloader: DRAM starting with the bootloader descriptor, then
/// IRAM code with the entry point; no digest.
fn esp32_bootloader() -> Vec<u8> {
    esp32_image(
        ESP32,
        ESP32_IRAM,
        &[
            seg(0x3FFF_0000, bootloader_descriptor()),
            seg(ESP32_IRAM, xtensa_bytes(64)),
        ],
        false,
    )
}

/// An ESP32-C3 application with RV32IMAC code in IRAM and IROM and strings
/// in DROM.
fn c3_app(chip_id: u16) -> Vec<u8> {
    let code = riscv32();
    let (iram, irom) = code.split_at(1024);
    esp32_image(
        chip_id,
        C3_IRAM,
        &[
            seg(C3_DROM, strings(256)),
            seg(C3_IRAM, iram.to_vec()),
            seg(C3_IROM, irom.to_vec()),
        ],
        true,
    )
}

/// An ESP8266 version 1 image: common header (flash code 0x20 = 1 MiB /
/// 40 MHz on the ESP8266), IRAM code with the entry point, DRAM data,
/// checksum.
fn esp8266_v1() -> Vec<u8> {
    let segments = [
        seg(ESP8266_IRAM, xtensa_bytes(64)),
        seg(ESP8266_DRAM, strings(48)),
    ];
    let mut image = common_header(IMAGE_MAGIC, segments.len(), 0x20, ESP8266_IRAM + 4);
    push_segments(&mut image, &segments);
    push_checksum(&mut image, checksum(&segments));
    image
}

/// IEEE CRC-32 (reflected polynomial 0xEDB88320), bit by bit.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xEDB8_8320
            };
        }
    }
    !crc
}

/// An ESP8266 version 2 image: `0xEA` header (count 4), the IROM segment
/// (load address 0, length a multiple of 16, not in the checksum), the
/// `0xE9` header, IRAM and DRAM segments, checksum (16-byte boundary from
/// the file start) and `esp8266_crc32` of everything before it (CRC-32,
/// inverted when bit 31 is set, else plus 1).
fn esp8266_v2() -> Vec<u8> {
    let mut image = common_header(IMAGE_V2_MAGIC, 4, 0x20, ESP8266_IRAM + 4);
    push_segments(&mut image, &[seg(0, xtensa_bytes(160))]);
    let segments = [
        seg(ESP8266_IRAM, xtensa_bytes(64)),
        seg(ESP8266_DRAM, strings(48)),
    ];
    image.extend(common_header(
        IMAGE_MAGIC,
        segments.len(),
        0x20,
        ESP8266_IRAM + 4,
    ));
    push_segments(&mut image, &segments);
    push_checksum(&mut image, checksum(&segments));
    let crc = crc32(&image);
    let crc = if crc & 0x8000_0000 != 0 {
        crc ^ 0xFFFF_FFFF
    } else {
        crc + 1
    };
    image.extend_from_slice(&crc.to_le_bytes());
    image
}

/// A partition record: magic `AA 50`, type, subtype, offset, size, label
/// (16 bytes, NUL padded), flags.
fn partition(kind: u8, subtype: u8, offset: u32, size: u32, label: &str, flags: u32) -> Vec<u8> {
    let mut record = PARTITION_MAGIC.to_vec();
    record.extend_from_slice(&[kind, subtype]);
    record.extend_from_slice(&offset.to_le_bytes());
    record.extend_from_slice(&size.to_le_bytes());
    let mut name = [0u8; 16];
    name[..label.len()].copy_from_slice(label.as_bytes());
    record.extend_from_slice(&name);
    record.extend_from_slice(&flags.to_le_bytes());
    record
}

/// A partition table as `gen_esp32part.py` writes it: the records, the MD5
/// record (`EB EB`, 14 bytes 0xFF, MD5 of the records) when `md5` is set,
/// then 0xFF up to 0xC00 bytes (the first 0xFF record terminates).
fn partition_table(records: &[Vec<u8>], md5: bool) -> Vec<u8> {
    let mut table: Vec<u8> = records.concat();
    if md5 {
        let mut hasher = Md5::new();
        hasher.update(&table);
        let digest = hasher.finish();
        table.extend_from_slice(&MD5_MAGIC);
        table.extend_from_slice(&[0xFF; 14]);
        table.extend_from_slice(&digest);
    }
    table.resize(0xC00, 0xFF);
    table
}

/// Partition offsets of the flash dump fixture.
const NVS: u32 = 0x9000;
const PHY: u32 = 0xA000;
const FACTORY: u32 = 0x10000;
const PARTITION_SIZE: u32 = 0x1000;

/// An ESP32 flash dump: erased flash, the bootloader at 0x1000, the
/// partition table at 0x8000 (nvs with data, an erased phy_init, a factory
/// application), each partition 4 KiB, erased flash elsewhere.
fn esp32_flash() -> Vec<u8> {
    let mut flash = vec![0xFF; (FACTORY + PARTITION_SIZE) as usize];
    let bootloader = esp32_bootloader();
    flash[0x1000..0x1000 + bootloader.len()].copy_from_slice(&bootloader);
    let table = partition_table(
        &[
            partition(1, 0x02, NVS, PARTITION_SIZE, "nvs", 0),
            partition(1, 0x01, PHY, PARTITION_SIZE, "phy_init", 0),
            partition(0, 0x00, FACTORY, PARTITION_SIZE, "factory", 0),
        ],
        true,
    );
    flash[TABLE_OFFSET..TABLE_OFFSET + table.len()].copy_from_slice(&table);
    let nvs = strings(256);
    flash[NVS as usize..NVS as usize + nvs.len()].copy_from_slice(&nvs);
    let app = esp32_app();
    flash[FACTORY as usize..FACTORY as usize + app.len()].copy_from_slice(&app);
    flash
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn has_note(payload: &DetectionPayload, text: &str) -> bool {
    payload.notes.iter().any(|n| n.message.contains(text))
}

fn metadata(payload: &DetectionPayload, key: &str) -> String {
    payload
        .metadata
        .iter()
        .find(|m| matches!(&m.key, MetadataKey::Custom(k) if k == key))
        .unwrap_or_else(|| panic!("metadata {key}"))
        .value
        .to_string()
}

fn slice<'a>(payload: &'a DetectionPayload, label: &str) -> &'a zrax::ContainedArch {
    payload
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some(label))
        .unwrap_or_else(|| panic!("slice {label}"))
}

fn is_esp(data: &[u8]) -> bool {
    matches!(
        detect_format(data),
        DetectedFormat::Container {
            kind: zrax::formats::container::Kind::Esp(_)
        }
    )
}

fn parse_error(data: &[u8]) -> String {
    let DetectedFormat::Container { kind } = detect_format(data) else {
        panic!("not a container");
    };
    zrax::formats::container::parse(data, kind)
        .expect_err("parse error")
        .to_string()
}

#[test]
fn esp32_application_names_xtensa_lx6_and_reads_the_descriptor() {
    let p = classify(&esp32_app());
    assert_eq!(p.format.format, FileFormat::EspFirmware);
    assert_eq!(p.format.variant_name.as_deref(), Some("ESP32-family image"));
    assert_eq!(p.primary.isa, Isa::Xtensa);
    assert_eq!(p.primary.bitwidth, 32);
    assert_eq!(p.primary.endianness, zrax::Endianness::Little);
    assert_eq!(p.primary.source, ClassificationSource::FileFormat);
    assert_eq!(
        p.primary.variant.as_ref().map(|v| v.name.as_str()),
        Some("Xtensa LX6")
    );
    assert!(has_note(&p, "ESP32 image (chip ID 0x0000); Xtensa LX6"));
    assert!(has_note(
        &p,
        "ESP-IDF application descriptor; project blink; version 1.2.3; ESP-IDF v5.5.1; \
         compiled Oct 13 2026 12:34:56"
    ));
    assert!(has_note(&p, "SPI flash: DIO mode, 4 MiB, 40 MHz"));
    assert!(has_note(&p, "Chip revision v0.0 to v0.99"));
    assert!(has_note(&p, "SHA-256 digest verified"));
    assert_eq!(metadata(&p, "esp_app_project_name"), "blink");
    assert_eq!(metadata(&p, "esp_app_secure_version"), "3");
    assert_eq!(metadata(&p, "esp_app_mmu_page_size"), "64 KiB");
    assert_eq!(metadata(&p, "esp_chip"), "ESP32");
    assert_eq!(metadata(&p, "esp_wp_pin"), "0xEE (disabled)");
}

#[test]
fn only_instruction_range_segments_are_load_sections() {
    let p = classify(&esp32_app());
    assert!(has_note(
        &p,
        "Segments: 2 analyzed as code (IRAM, IROM); 2 listed as opaque (DROM, DRAM)"
    ));
    // Data segments are opaque slices at their stored data offsets.
    let drom = slice(&p, "Segment 0 (DROM)");
    assert_eq!(drom.offset, 24 + 8);
    assert_eq!(drom.size, 256 + 64);
    assert_eq!(drom.isa, Isa::Unknown(0));
    assert_eq!(slice(&p, "Segment 3 (DRAM)").isa, Isa::Unknown(0));
    assert_eq!(p.slices.len(), 2);
    let iram = 24 + 8 + 320 + 8;
    assert_eq!(
        metadata(&p, "esp_section_0"),
        format!("file 0x{iram:X}; destination 0x{ESP32_IRAM:X}; 96 B")
    );
    assert_eq!(
        metadata(&p, "esp_segment_2"),
        format!(
            "file 0x{:X}; load 0x{ESP32_IROM:08X}; 128 B; code",
            iram + 96 + 8
        )
    );
}

#[test]
fn data_segments_never_reach_the_code_model() {
    // Thumb code in DROM must not be analyzed: only four bytes of IRAM are.
    let image = esp32_image(
        ESP32_C3,
        C3_IRAM,
        &[seg(C3_DROM, thumb()), seg(C3_IRAM, vec![0x13, 0, 0, 0])],
        true,
    );
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::RiscV32);
    assert!(!has_note(&p, "classifies as"));
    assert!(p.candidates.iter().all(|c| c.isa != Isa::Arm));
}

#[test]
fn esp32_c3_application_is_risc_v_and_the_code_agrees() {
    let p = classify(&c3_app(ESP32_C3));
    assert_eq!(p.format.format, FileFormat::EspFirmware);
    assert_eq!(p.primary.isa, Isa::RiscV32);
    assert_eq!(p.primary.bitwidth, 32);
    assert!(has_note(
        &p,
        "ESP32-C3 image (chip ID 0x0005); 32-bit RISC-V"
    ));
    assert!(!has_note(&p, "classifies as"));
    assert_eq!(slice(&p, "Segment 0 (DROM)").isa, Isa::Unknown(0));
}

#[test]
fn undocumented_chip_ids_leave_the_isa_to_the_code() {
    let p = classify(&c3_app(UNDOCUMENTED_CHIP));
    assert_eq!(p.format.format, FileFormat::EspFirmware);
    assert!(has_note(&p, "Chip ID 0x0042 is not a documented chip"));
    // Every segment goes to the code model, which finds RISC-V.
    assert_eq!(p.primary.isa, Isa::RiscV32);
    assert_ne!(p.primary.source, ClassificationSource::FileFormat);
    assert!(p.slices.is_empty());
}

#[test]
fn unified_memory_segments_are_code_with_a_note() {
    let code = riscv32();
    let image = esp32_image(
        ESP32_C6,
        C6_SRAM,
        &[seg(C6_SRAM, code[..512].to_vec())],
        false,
    );
    let p = classify(&image);
    assert_eq!(p.primary.isa, Isa::RiscV32);
    assert!(has_note(&p, "Segments: 1 analyzed as code (IRAM/DRAM)"));
    assert!(has_note(
        &p,
        "On the ESP32-C6 instruction and data addresses coincide"
    ));
    assert!(has_note(&p, "no SHA-256 digest appended"));
}

#[test]
fn esp32_bootloader_reads_the_bootloader_descriptor() {
    let p = classify(&esp32_bootloader());
    assert_eq!(p.primary.isa, Isa::Xtensa);
    assert!(has_note(
        &p,
        "ESP-IDF bootloader descriptor; version 7; ESP-IDF v5.5.1; compiled Oct 13 2026 12:34:56"
    ));
    assert_eq!(metadata(&p, "esp_bootloader_secure_version"), "1");
}

#[test]
fn esp8266_version_1_and_2_images_are_xtensa_lx106() {
    for (image, label) in [
        (esp8266_v1(), "ESP8266 image (version 1)"),
        (esp8266_v2(), "ESP8266 image (version 2)"),
    ] {
        let p = classify(&image);
        assert_eq!(p.format.format, FileFormat::EspFirmware, "{label}");
        assert_eq!(p.format.variant_name.as_deref(), Some(label));
        assert_eq!(p.primary.isa, Isa::Xtensa, "{label}");
        assert_eq!(
            p.primary.variant.as_ref().map(|v| v.name.as_str()),
            Some("Xtensa lx106 (LX3.0.1)")
        );
        assert!(
            has_note(&p, "SPI flash: DIO mode, 1 MiB, 40 MHz"),
            "{label}"
        );
        assert!(has_note(&p, "1 listed as opaque (DRAM)"), "{label}");
    }
    let p = classify(&esp8266_v2());
    assert!(has_note(&p, "IROM segment excluded"));
    assert!(has_note(&p, "CRC-32 0x"));
    assert!(has_note(&p, "Segments: 2 analyzed as code (IROM, IRAM)"));
}

#[test]
fn esp8266_version_1_accepts_an_appended_sha256() {
    let mut image = esp8266_v1();
    let digest = Sha256::digest(&image);
    image.extend_from_slice(&digest);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::EspFirmware);
    assert!(has_note(&p, "SHA-256 digest verified"));
}

#[test]
fn erased_flash_after_an_image_is_noted_and_other_data_needs_a_digest() {
    let mut image = esp8266_v1();
    image.extend_from_slice(&[0xFF; 100]);
    assert!(has_note(
        &classify(&image),
        "100 B of erased flash after the image"
    ));
    let mut image = esp8266_v1();
    image.extend_from_slice(b"trailing data");
    assert!(!is_esp(&image));
    let mut app = esp32_app();
    let end = app.len();
    app.extend_from_slice(&[0x5A; 64]);
    let p = classify(&app);
    assert_eq!(p.format.format, FileFormat::EspFirmware);
    assert_eq!(slice(&p, "Data after the image").offset, end as u64);
    assert!(has_note(&p, "64 B after the image"));
}

#[test]
fn x86_code_starting_with_jmp_rel32_is_not_an_esp_image() {
    // `jmp rel32` (E9), then real-mode-style code: the old detection took
    // any E9 with a segment count of 1 to 16 and a plausible entry point.
    let mut code = vec![0xE9, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    for _ in 0..64 {
        code.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3]);
    }
    assert!(!is_esp(&code));
    if let Ok(p) = detect_payload(&code, &ClassifierOptions::new()) {
        assert_ne!(p.format.format, FileFormat::EspFirmware);
    }
}

#[test]
fn corrupted_fields_are_rejected() {
    let app = esp32_app();
    let mut checksum = app.clone();
    let checksum_at = app.len() - 33;
    checksum[checksum_at] ^= 1;
    assert!(!is_esp(&checksum));
    let mut digest = app.clone();
    *digest.last_mut().expect("digest") ^= 1;
    assert!(!is_esp(&digest));
    let mut hash_flag = app.clone();
    hash_flag[23] = 2;
    assert!(!is_esp(&hash_flag));
    let mut count = app.clone();
    count[1] = 17;
    assert!(!is_esp(&count));
    let mut entry = app.clone();
    entry[4..8].copy_from_slice(&0x5000_0000u32.to_le_bytes());
    assert!(!is_esp(&entry));
    let mut length = esp8266_v1();
    length[12] = 0x41;
    assert!(!is_esp(&length));
    let mut crc = esp8266_v2();
    *crc.last_mut().expect("crc") ^= 1;
    assert!(!is_esp(&crc));
}

#[test]
fn parse_errors_name_the_failing_field_and_offset() {
    let app = esp32_app();
    let DetectedFormat::Container { kind } = detect_format(&app) else {
        panic!("container");
    };
    let mut checksum = app.clone();
    let checksum_at = app.len() - 33;
    checksum[checksum_at] ^= 1;
    let message = zrax::formats::container::parse(&checksum, kind)
        .expect_err("checksum")
        .to_string();
    assert!(
        message.starts_with(&format!(
            "Espressif image parse error: Invalid image checksum 0x{:02X} at 0x{checksum_at:X}",
            checksum[checksum_at]
        )),
        "{message}"
    );
    let message = zrax::formats::container::parse(&app[..100], kind)
        .expect_err("truncated")
        .to_string();
    assert!(message.contains("Truncated segment 0 at 0x20"), "{message}");
}

/// An `0xE9` file that is valid both ways. As an ESP8266 version 1 image,
/// bytes 8-15 are a segment header (load 0x40080000, 32 B) covering
/// 0x10-0x2F. As an ESP32-family image the same bytes are the extended
/// header (chip ID 0x0020), and its one segment header at 0x18 (load
/// 0x40080000, 16 B) covers 0x20-0x2F. The reserved bytes make the XOR of
/// 0x10-0x1F zero, so both checksums (at 0x3F) agree.
fn ambiguous_image() -> Vec<u8> {
    let mut image = common_header(IMAGE_MAGIC, 1, 0x20, 0x4008_0000);
    image.extend_from_slice(&0x4008_0000u32.to_le_bytes());
    image.extend_from_slice(&32u32.to_le_bytes());
    image.extend_from_slice(&[0, 0, 0, 0x58, 0, 0, 0, 0]);
    let segments = [seg(0x4008_0000, vec![0x11; 16])];
    push_segments(&mut image, &segments);
    push_checksum(&mut image, checksum(&segments));
    image
}

#[test]
fn ambiguous_layouts_are_reported_without_an_isa() {
    let p = classify(&ambiguous_image());
    assert_eq!(p.format.format, FileFormat::EspFirmware);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("Ambiguous ESP image")
    );
    assert_eq!(p.primary.isa, Isa::Unknown(0));
    assert!(has_note(
        &p,
        "Validates as an ESP32-family image (1 segments, chip ID 0x0020) and as an ESP8266 \
         version 1 image (1 segments)"
    ));
    assert!(p.slices.is_empty());
}

#[test]
fn flash_dump_lists_bootloader_table_and_partitions() {
    let flash = esp32_flash();
    let p = classify(&flash);
    assert_eq!(p.format.format, FileFormat::EspFlash);
    assert_eq!(p.format.variant_name.as_deref(), Some("ESP flash dump"));
    assert_eq!(p.format.confidence, 1.0);
    assert_eq!(p.primary.isa, Isa::Xtensa);
    assert!(has_note(
        &p,
        "Partition table at 0x8000: 3 partitions; MD5 verified"
    ));
    assert!(has_note(
        &p,
        "Bootloader at 0x1000: ESP32 image (ESP32-family image)"
    ));
    assert!(has_note(&p, "phy_init: erased"));
    let bootloader = slice(&p, "Bootloader");
    assert_eq!(bootloader.offset, 0x1000);
    assert_eq!(bootloader.size, esp32_bootloader().len() as u64);
    assert_eq!(bootloader.isa, Isa::Xtensa);
    let table = slice(&p, "Partition table");
    assert_eq!((table.offset, table.size), (0x8000, 5 * 32));
    assert_eq!(table.isa, Isa::Unknown(0));
    assert_eq!(slice(&p, "nvs").isa, Isa::Unknown(0));
    let factory = slice(&p, "factory");
    assert_eq!(factory.offset, u64::from(FACTORY));
    assert_eq!(factory.size, esp32_app().len() as u64);
    assert_eq!(factory.isa, Isa::Xtensa);
    assert_eq!(
        metadata(&p, "esp_partition_2"),
        "app factory at 0x10000, 4 KiB"
    );
    assert!(p
        .slices
        .iter()
        .all(|s| s.label.as_deref() != Some("phy_init")));
}

#[test]
fn flash_dump_bootloader_offset_is_checked_against_the_chip() {
    let mut flash = esp32_flash();
    // An ESP32-C3 bootloader belongs at 0x0, not 0x1000.
    flash[..0x8000].fill(0xFF);
    let c3 = esp32_image(
        ESP32_C3,
        C3_IRAM,
        &[seg(C3_IRAM, riscv32()[..256].to_vec())],
        false,
    );
    flash[0x1000..0x1000 + c3.len()].copy_from_slice(&c3);
    let p = classify(&flash);
    assert!(has_note(
        &p,
        "Bootloader at 0x1000: ESP32-C3 image; the documented bootloader offset of the \
         ESP32-C3 is 0x0"
    ));
    assert_eq!(slice(&p, "Bootloader").isa, Isa::RiscV32);
    flash[..0x8000].fill(0xFF);
    assert!(has_note(
        &classify(&flash),
        "No bootloader: 0x0-0x7FFF is erased flash"
    ));
}

#[test]
fn flash_dump_partition_flags_and_bounds() {
    let mut flash = esp32_flash();
    let table = partition_table(
        &[
            partition(1, 0x02, NVS, PARTITION_SIZE, "nvs", 1),
            partition(0, 0x10, FACTORY, 0x10_0000, "ota_0", 0),
            partition(1, 0x81, 0x20_0000, PARTITION_SIZE, "storage", 0),
        ],
        false,
    );
    flash[TABLE_OFFSET..TABLE_OFFSET + table.len()].copy_from_slice(&table);
    let p = classify(&flash);
    assert!(has_note(&p, "3 partitions; no MD5 record"));
    assert!(has_note(&p, "nvs: encrypted partition; listed as opaque"));
    assert!(has_note(&p, "ota_0: truncated"));
    assert!(has_note(&p, "storage: 0x200000 lies outside the dump"));
    assert_eq!(slice(&p, "ota_0").isa, Isa::Xtensa);
    assert_eq!(
        metadata(&p, "esp_partition_0"),
        "data nvs at 0x9000, 4 KiB, encrypted"
    );
}

#[test]
fn flash_dump_invalid_app_partitions_are_opaque() {
    let mut flash = esp32_flash();
    let app = FACTORY as usize;
    // A corrupt image (possibly encrypted): checksum wrong.
    let checksum_at = app + esp32_app().len() - 33;
    flash[checksum_at] ^= 1;
    let p = classify(&flash);
    assert!(has_note(&p, "factory: not a valid ESP image"));
    assert_eq!(slice(&p, "factory").isa, Isa::Unknown(0));
}

/// A minimal x86-64 ELF header: magic, 64-bit, little-endian, version 1,
/// `ET_REL`, `EM_X86_64`, header and table entry sizes.
fn elf_x86_64() -> Vec<u8> {
    let mut elf = vec![0u8; 64];
    elf[..7].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1]);
    elf[16..18].copy_from_slice(&1u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[58..60].copy_from_slice(&64u16.to_le_bytes());
    elf
}

#[test]
fn flash_dump_with_a_bootloader_at_zero_is_a_flash_dump_first() {
    // An ESP32-C3 dump starts with its bootloader image; with a verified
    // digest that image would also validate on its own, so the partition
    // table check must come first.
    let mut flash = esp32_flash();
    flash[..0x8000].fill(0xFF);
    let bootloader = esp32_image(
        ESP32_C3,
        C3_IRAM,
        &[seg(C3_IRAM, riscv32()[..256].to_vec())],
        true,
    );
    flash[..bootloader.len()].copy_from_slice(&bootloader);
    let p = classify(&flash);
    assert_eq!(p.format.format, FileFormat::EspFlash);
    assert!(has_note(
        &p,
        "Bootloader at 0x0: ESP32-C3 image (ESP32-family image)"
    ));
    assert_eq!(slice(&p, "Bootloader").offset, 0);
    assert_eq!(p.primary.isa, Isa::RiscV32);
}

#[test]
fn flash_dump_data_partitions_in_a_recognized_format_are_classified() {
    let mut flash = esp32_flash();
    let elf = elf_x86_64();
    flash[PHY as usize..PHY as usize + elf.len()].copy_from_slice(&elf);
    let p = classify(&flash);
    let phy = slice(&p, "phy_init");
    assert_eq!((phy.isa, phy.offset), (Isa::X86_64, u64::from(PHY)));
    assert_eq!(slice(&p, "nvs").isa, Isa::Unknown(0));
}

#[test]
fn flash_dump_md5_and_records_are_verified() {
    let mut flash = esp32_flash();
    flash[TABLE_OFFSET + 4] ^= 1;
    assert_eq!(
        parse_error(&flash),
        format!(
            "Espressif image parse error: Invalid partition table MD5 at 0x{:X}: stored {}, \
             computed {}",
            TABLE_OFFSET + 96,
            hex(&flash[TABLE_OFFSET + 96 + 16..TABLE_OFFSET + 128]),
            {
                let mut hasher = Md5::new();
                hasher.update(&flash[TABLE_OFFSET..TABLE_OFFSET + 96]);
                hex(&hasher.finish())
            }
        )
    );
    assert!(detect_payload(&flash, &ClassifierOptions::new()).is_err());
    let mut flash = esp32_flash();
    flash[TABLE_OFFSET + 32] = 0x00;
    assert!(!matches!(
        detect_format(&flash),
        DetectedFormat::Container {
            kind: zrax::formats::container::Kind::Esp(zrax::formats::esp::Layout::Flash)
        }
    ));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

#[test]
fn real_esp_idf_image_parses_with_checksum_and_digest_verified() {
    // An ESP32-C3 application built by ESP-IDF v5.2, tracked in testbins/.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testbins/fw1-riscv64.bin");
    let Ok(image) = std::fs::read(path) else {
        eprintln!("skipped: {path} is not present");
        return;
    };
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::EspFirmware);
    assert_eq!(p.primary.isa, Isa::RiscV32);
    assert!(has_note(
        &p,
        "Checksum 0xBB verified; SHA-256 digest verified"
    ));
    assert!(has_note(&p, "ESP-IDF v5.2"));
    assert!(!has_note(&p, "classifies as"));
    assert_eq!(metadata(&p, "esp_chip"), "ESP32-C3");
}

#[test]
fn every_prefix_errors_or_does_not_claim_the_image() {
    for image in [esp32_app(), esp32_bootloader(), esp8266_v1(), esp8266_v2()] {
        for end in 0..image.len() {
            assert!(!is_esp(&image[..end]), "prefix {end} of {} B", image.len());
        }
    }
    let flash = esp32_flash();
    for end in (0..flash.len()).step_by(97) {
        let prefix = &flash[..end];
        if let Ok(p) = detect_payload(prefix, &ClassifierOptions::new()) {
            if p.format.format == FileFormat::EspFlash {
                assert!(end >= TABLE_OFFSET + 5 * 32, "prefix {end}");
            }
        }
    }
}

#[test]
fn byte_mutations_never_panic() {
    let fixtures = [
        esp32_app(),
        esp32_bootloader(),
        esp8266_v1(),
        esp8266_v2(),
        ambiguous_image(),
    ];
    for image in &fixtures {
        for i in 0..image.len() {
            for mutation in [0x00, 0xFF, image[i] ^ 0x01] {
                let mut mutated = image.clone();
                mutated[i] = mutation;
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
    let flash = esp32_flash();
    let table = TABLE_OFFSET..TABLE_OFFSET + 6 * 32;
    let sampled = (0..flash.len()).step_by(251);
    for i in table.chain(sampled) {
        for mutation in [0x00, 0xFF, flash[i] ^ 0x01] {
            let mut mutated = flash.clone();
            mutated[i] = mutation;
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}
