//! Chromium FMAP flash images and coreboot CBFS: area roles and the leaves
//! that are classified, the embedded-map search, stages (LZMA, LZ4, legacy),
//! SELF payload segments, master-header architectures, hash attributes,
//! legacy ROMs found through the end pointer, corrupted fields, and
//! truncation and mutation sweeps.

use sha2::{Digest, Sha256};
use std::io::Write;
use zrax::{
    detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa, MetadataKey,
};

const AARCH64_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/transforms/aarch64.text.bin"
);
const RISCV64_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/transforms/riscv64.text.bin"
);
/// `AARCH64_CODE` as LZMA-alone with the decoded size in the header
/// (`tests/fixtures/coreboot/generate.sh`).
const ROMSTAGE_LZMA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/coreboot/romstage.lzma"
);

/// CBFS file types, compression values and architectures used below
/// (coreboot `cbfs_serialized.h`).
const TYPE_CBFSHEADER: u32 = 0x02;
const TYPE_LEGACY_STAGE: u32 = 0x10;
const TYPE_STAGE: u32 = 0x11;
const TYPE_SELF: u32 = 0x20;
const TYPE_RAW: u32 = 0x50;
const TYPE_MICROCODE: u32 = 0x53;
const TYPE_BOOTBLOCK: u32 = 0x01;
const TYPE_NULL: u32 = 0xffff_ffff;
const COMPRESS_NONE: u32 = 0;
const COMPRESS_LZMA: u32 = 1;
const COMPRESS_LZ4: u32 = 2;
const ARCHITECTURE_AARCH64: u32 = 0x0000_aa64;
const ARCHITECTURE_RISCV: u32 = 0xc001_d0de;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).expect("fixture is committed")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn parse_error(data: &[u8]) -> String {
    match detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => panic!("expected a parse error, got {:?}", p.format),
        Err(e) => e.to_string(),
    }
}

fn labels(p: &DetectionPayload) -> Vec<&str> {
    p.slices
        .iter()
        .map(|s| s.label.as_deref().unwrap_or(""))
        .collect()
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn metadata(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| m.key == MetadataKey::Custom(key.to_string()))
        .map(|m| m.value.to_string())
}

fn lz4_frame(data: &[u8]) -> Vec<u8> {
    let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
    encoder.write_all(data).expect("in-memory write");
    encoder.finish().expect("in-memory frame")
}

/// `n` rounded up to a multiple of `align`.
fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) / align * align
}

fn place(image: &mut [u8], offset: usize, bytes: &[u8]) {
    image[offset..offset + bytes.len()].copy_from_slice(bytes);
}

/// One FMAP area.
struct Area {
    offset: u32,
    size: u32,
    name: &'static str,
    flags: u16,
}

const fn area(offset: u32, size: u32, name: &'static str) -> Area {
    Area {
        offset,
        size,
        name,
        flags: 0,
    }
}

/// `struct fmap`, little-endian: signature `__FMAP__`, `ver_major` 1,
/// `ver_minor` 1, `base` (u64, flash base address), `size` (u32, image
/// size), `name` (32 B, NUL-padded), `nareas` (u16); then one 42-byte
/// `struct fmap_area` per area: `offset` (u32), `size` (u32), `name` (32 B),
/// `flags` (u16).
fn fmap(base: u64, image_size: u32, name: &str, areas: &[Area]) -> Vec<u8> {
    let mut out = b"__FMAP__".to_vec();
    out.extend_from_slice(&[1, 1]);
    out.extend_from_slice(&base.to_le_bytes());
    out.extend_from_slice(&image_size.to_le_bytes());
    let mut field = [0u8; 32];
    field[..name.len()].copy_from_slice(name.as_bytes());
    out.extend_from_slice(&field);
    out.extend_from_slice(&(areas.len() as u16).to_le_bytes());
    for a in areas {
        out.extend_from_slice(&a.offset.to_le_bytes());
        out.extend_from_slice(&a.size.to_le_bytes());
        let mut field = [0u8; 32];
        field[..a.name.len()].copy_from_slice(a.name.as_bytes());
        out.extend_from_slice(&field);
        out.extend_from_slice(&a.flags.to_le_bytes());
    }
    out
}

/// `struct cbfs_file`, big-endian: `LARCHIVE`, data length, type,
/// attributes offset (from the header; 0 for none), data offset (from the
/// header), then the name NUL-padded to a multiple of 4 bytes, the
/// attributes and the data.
fn cbfs_file(file_type: u32, name: &str, attributes: &[u8], data: &[u8]) -> Vec<u8> {
    let name_size = align_up(name.len() + 1, 4);
    let attributes_offset = if attributes.is_empty() {
        0
    } else {
        24 + name_size
    };
    let data_offset = 24 + name_size + attributes.len();
    let mut out = b"LARCHIVE".to_vec();
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&file_type.to_be_bytes());
    out.extend_from_slice(&(attributes_offset as u32).to_be_bytes());
    out.extend_from_slice(&(data_offset as u32).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.resize(24 + name_size, 0);
    out.extend_from_slice(attributes);
    out.extend_from_slice(data);
    out
}

/// Compression attribute: tag `BCZL` (0x42435A4C), length 16, algorithm,
/// decoded size; all big-endian.
fn compression_attribute(algorithm: u32, decoded_size: usize) -> Vec<u8> {
    let mut out = 0x4243_5a4c_u32.to_be_bytes().to_vec();
    out.extend_from_slice(&16u32.to_be_bytes());
    out.extend_from_slice(&algorithm.to_be_bytes());
    out.extend_from_slice(&(decoded_size as u32).to_be_bytes());
    out
}

/// Stage-header attribute: tag `StgH` (0x53746748), length 24, load
/// address (u64), entry offset from it, memory size; all big-endian.
fn stage_attribute(load_address: u64, entry_offset: u32, memory_size: u32) -> Vec<u8> {
    let mut out = 0x5374_6748_u32.to_be_bytes().to_vec();
    out.extend_from_slice(&24u32.to_be_bytes());
    out.extend_from_slice(&load_address.to_be_bytes());
    out.extend_from_slice(&entry_offset.to_be_bytes());
    out.extend_from_slice(&memory_size.to_be_bytes());
    out
}

/// Hash attribute: tag `hsaH` (0x68736148), length 12 + 32, three reserved
/// bytes, vboot algorithm 2 (SHA-256), then the digest of `data`.
fn sha256_attribute(data: &[u8]) -> Vec<u8> {
    let mut out = 0x6873_6148_u32.to_be_bytes().to_vec();
    out.extend_from_slice(&44u32.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 2]);
    out.extend_from_slice(&Sha256::digest(data));
    out
}

/// `struct cbfs_header`, big-endian: magic `ORBC`, version `1112`, ROM
/// size, bootblock size 4, alignment 64, first-entry offset,
/// architecture, 4 bytes of padding.
fn master_header(rom_size: u32, first_entry: u32, architecture: u32) -> Vec<u8> {
    let mut out = b"ORBC1112".to_vec();
    for field in [rom_size, 4, 64, first_entry, architecture, 0] {
        out.extend_from_slice(&field.to_be_bytes());
    }
    out
}

/// Legacy `struct cbfs_stage`, little-endian: compression, entry (u64),
/// load address (u64), data size, memory size; then the data.
fn legacy_stage(compression: u32, entry: u64, load: u64, memory_size: u32, data: &[u8]) -> Vec<u8> {
    let mut out = compression.to_le_bytes().to_vec();
    out.extend_from_slice(&entry.to_le_bytes());
    out.extend_from_slice(&load.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&memory_size.to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// One SELF payload segment: type (`CODE`, `DATA`, `BSS `, `ENTR`),
/// compression, load address, stored bytes and memory size.
struct Segment {
    kind: &'static [u8; 4],
    compression: u32,
    load: u64,
    data: Vec<u8>,
    memory_size: u32,
}

/// SELF payload: 28-byte big-endian `struct cbfs_payload_segment` records
/// (type, compression, offset from the payload start, load address u64,
/// stored size, memory size), then the stored bytes in record order.
fn self_payload(segments: &[Segment]) -> Vec<u8> {
    let mut records = Vec::new();
    let mut contents = Vec::new();
    let mut offset = segments.len() * 28;
    for s in segments {
        records.extend_from_slice(s.kind);
        records.extend_from_slice(&s.compression.to_be_bytes());
        records.extend_from_slice(&(offset as u32).to_be_bytes());
        records.extend_from_slice(&s.load.to_be_bytes());
        records.extend_from_slice(&(s.data.len() as u32).to_be_bytes());
        records.extend_from_slice(&s.memory_size.to_be_bytes());
        contents.extend_from_slice(&s.data);
        offset += s.data.len();
    }
    records.extend_from_slice(&contents);
    records
}

/// Append `file` at the next 64-byte boundary of `region`.
fn push_file(region: &mut Vec<u8>, file: &[u8]) {
    region.resize(align_up(region.len(), 64), 0xff);
    region.extend_from_slice(file);
}

/// A CBFS region of `size` bytes: the files on 64-byte boundaries, then a
/// `NULL` entry with an empty name and `0xFF` data up to the end, as
/// cbfstool fills free space.
fn cbfs_region(files: &[Vec<u8>], size: usize) -> Vec<u8> {
    let mut region = Vec::new();
    for file in files {
        push_file(&mut region, file);
    }
    region.resize(align_up(region.len(), 64), 0xff);
    let free = size - region.len() - 28;
    region.extend(cbfs_file(TYPE_NULL, "", &[], &vec![0xff; free]));
    assert_eq!(region.len(), size);
    region
}

/// The CBFS of the AP image: an `AArch64` master header, an LZMA stage
/// with a SHA-256 hash, a SELF payload with an LZ4 CODE segment, a DATA
/// and a BSS segment, a raw text file and a microcode blob.
fn ap_cbfs(size: usize) -> Vec<u8> {
    let code = read(AARCH64_CODE);
    let romstage = read(ROMSTAGE_LZMA);
    let mut attributes = compression_attribute(COMPRESS_LZMA, code.len());
    attributes.extend(stage_attribute(0x4000_0000, 0, 0x2000));
    attributes.extend(sha256_attribute(&romstage));
    let payload = self_payload(&[
        Segment {
            kind: b"CODE",
            compression: COMPRESS_LZ4,
            load: 0x8000_0000,
            data: lz4_frame(&code),
            memory_size: 0x2000,
        },
        Segment {
            kind: b"DATA",
            compression: COMPRESS_NONE,
            load: 0x8000_2000,
            data: vec![0x5a; 64],
            memory_size: 64,
        },
        Segment {
            kind: b"BSS ",
            compression: COMPRESS_NONE,
            load: 0x8000_3000,
            data: Vec::new(),
            memory_size: 0x1000,
        },
        Segment {
            kind: b"ENTR",
            compression: COMPRESS_NONE,
            load: 0x8000_0000,
            data: Vec::new(),
            memory_size: 0,
        },
    ]);
    cbfs_region(
        &[
            cbfs_file(
                TYPE_CBFSHEADER,
                "cbfs master header",
                &[],
                &master_header(size as u32, 0, ARCHITECTURE_AARCH64),
            ),
            cbfs_file(TYPE_STAGE, "fallback/romstage", &attributes, &romstage),
            cbfs_file(TYPE_SELF, "fallback/payload", &[], &payload),
            cbfs_file(TYPE_RAW, "config", &[], b"CONFIG_ARCH_ARM64=y\n"),
            cbfs_file(TYPE_MICROCODE, "cpu_microcode_blob.bin", &[], &[0xa5; 64]),
        ],
        size,
    )
}

/// File offsets in `ap_cbfs`: the 76-byte master-header file is followed,
/// at the next 64-byte boundary, by the romstage, whose data follows its
/// 24-byte header, 20-byte name and 16 + 24 + 44 bytes of attributes.
const ROMSTAGE_FILE: usize = 0x80;
const ROMSTAGE_DATA: usize = ROMSTAGE_FILE + 24 + 20 + 84;

/// The AP image's areas, parents before children as fmaptool lists them.
const AP_AREAS: [Area; 10] = [
    area(0x00000, 0x18000, "RO_SECTION"),
    area(0x00000, 0x1000, "FMAP"),
    area(0x01000, 0x40, "RO_FRID"),
    area(0x01100, 0x100, "GBB"),
    area(0x02000, 0x16000, "COREBOOT"),
    area(0x18000, 0x6000, "RW_SECTION_A"),
    area(0x18000, 0x1000, "VBLOCK_A"),
    area(0x19000, 0x4f00, "FW_MAIN_A"),
    area(0x1df00, 0x100, "RW_FWID_A"),
    area(0x1e000, 0x2000, "RW_UNUSED"),
];

/// A 128 KiB AP firmware image: the FMAP at 0, version strings, a GBB, the
/// COREBOOT CBFS, a verified-boot block, and two erased areas.
fn ap_image() -> Vec<u8> {
    let mut image = vec![0xffu8; 0x20000];
    place(
        &mut image,
        0,
        &fmap(0xff00_0000, 0x20000, "FLASH", &AP_AREAS),
    );
    place(&mut image, 0x1000, b"Google_Test.1.0.0\0");
    place(&mut image, 0x1100, b"$GBB\x01\x00\x01\x00");
    place(&mut image, 0x2000, &ap_cbfs(0x16000));
    place(&mut image, 0x18000, b"CHROMEOS\x02\x00\x00\x00");
    place(&mut image, 0x1df00, b"Google_Test.1.0.0\0");
    image
}

/// A 16 KiB EC image: RISC-V code in `EC_RO` and `EC_RW`, the version
/// strings and the FMAP nested in the code areas, the map at 0x1040.
fn ec_image() -> Vec<u8> {
    let code = read(RISCV64_CODE);
    let areas = [
        area(0x0000, 0x2000, "EC_RO"),
        area(0x1000, 0x20, "RO_FRID"),
        area(0x1040, 0x200, "FMAP"),
        area(0x2000, 0x2000, "EC_RW"),
        area(0x3fe0, 0x20, "RW_FWID"),
    ];
    let mut image = vec![0xffu8; 0x4000];
    place(&mut image, 0, &code);
    place(&mut image, 0x1000, b"ec_test_v1.0.0\0");
    place(&mut image, 0x1040, &fmap(0, 0x4000, "EC_FMAP", &areas));
    place(&mut image, 0x2000, &code);
    place(&mut image, 0x3fe0, b"ec_test_v1.0.0\0");
    image
}

/// A CBFS region at offset 0 with an LZ4 legacy stage of RISC-V code and no
/// master header.
fn legacy_stage_cbfs() -> Vec<u8> {
    let code = read(RISCV64_CODE);
    let stage = legacy_stage(
        COMPRESS_LZ4,
        0x1000_0000,
        0x1000_0000,
        0x2000,
        &lz4_frame(&code),
    );
    cbfs_region(
        &[cbfs_file(
            TYPE_LEGACY_STAGE,
            "fallback/ramstage",
            &[],
            &stage,
        )],
        0x2000,
    )
}

/// A 16 KiB legacy ROM: erased flash up to 0x400, then a CBFS whose last
/// file, the bootblock, ends at the end of the ROM with the little-endian
/// master-header pointer in its last four bytes.
fn legacy_rom() -> Vec<u8> {
    let code = read(RISCV64_CODE);
    let rom_size = 0x4000usize;
    let first_entry = 0x400usize;
    let bootblock_at = 0x3f00usize;
    let mut region = Vec::new();
    push_file(
        &mut region,
        &cbfs_file(
            TYPE_CBFSHEADER,
            "cbfs master header",
            &[],
            &master_header(rom_size as u32, first_entry as u32, ARCHITECTURE_RISCV),
        ),
    );
    // "cbfs master header" plus its terminator pads to 20 bytes.
    let master_header_at = first_entry + 24 + 20;
    push_file(
        &mut region,
        &cbfs_file(
            TYPE_LEGACY_STAGE,
            "fallback/romstage",
            &[],
            &legacy_stage(COMPRESS_NONE, 0x8000_0000, 0x8000_0000, 0x2000, &code),
        ),
    );
    region.resize(align_up(region.len(), 64), 0xff);
    let free = bootblock_at - first_entry - region.len() - 28;
    region.extend(cbfs_file(TYPE_NULL, "", &[], &vec![0xff; free]));
    // "bootblock" plus its terminator pads to 12 bytes.
    let mut bootblock = vec![0u8; rom_size - bootblock_at - 24 - 12];
    let pointer = master_header_at as i64 - rom_size as i64;
    let pointer_at = bootblock.len() - 4;
    bootblock[pointer_at..].copy_from_slice(&(pointer as i32).to_le_bytes());
    region.extend(cbfs_file(TYPE_BOOTBLOCK, "bootblock", &[], &bootblock));
    let mut rom = vec![0xffu8; first_entry];
    rom.extend(region);
    assert_eq!(rom.len(), rom_size);
    rom
}

#[test]
fn fmap_image_lists_leaf_areas_and_classifies_the_coreboot_cbfs() {
    let image = ap_image();
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Fmap);
    assert_eq!(p.format.variant_name.as_deref(), Some("FMAP flash image"));
    assert_eq!(p.format.confidence, 1.0);
    assert_eq!(
        labels(&p),
        [
            "FMAP",
            "RO_FRID",
            "GBB",
            "COREBOOT",
            "VBLOCK_A",
            "RW_FWID_A"
        ]
    );
    let offsets: Vec<u64> = p.slices.iter().map(|s| s.offset).collect();
    assert_eq!(offsets, [0, 0x1000, 0x1100, 0x2000, 0x18000, 0x1df00]);
    assert_eq!(p.slices[3].size, 0x16000);
    assert_eq!(p.slices[3].isa, Isa::AArch64);
    for data_area in [0, 1, 2, 4, 5] {
        assert!(matches!(p.slices[data_area].isa, Isa::Unknown(_)));
    }
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert!(has_note(&p, "Primary ISA selected from COREBOOT"));
    assert!(has_note(&p, "VBLOCK_A: opaque"));
    assert!(has_note(&p, "2 erased areas were not classified"));
    assert!(has_note(
        &p,
        "FMAP 1.1 \"FLASH\" at 0x0: 10 areas over a 128 KiB image"
    ));
    assert_eq!(
        metadata(&p, "fmap_area_0").as_deref(),
        Some("0x0 + 98304 B; flags none; contains other areas")
    );
    assert_eq!(
        metadata(&p, "fmap_area_7").as_deref(),
        Some("0x19000 + 20224 B; flags none; erased")
    );
    assert_eq!(
        metadata(&p, "fmap_base_address").as_deref(),
        Some("0xFF000000")
    );
}

#[test]
fn cbfs_stages_payload_segments_and_master_header_are_classified() {
    let region = ap_cbfs(0x16000);
    let code = read(AARCH64_CODE);
    let romstage = read(ROMSTAGE_LZMA);
    let p = classify(&region);
    assert_eq!(p.format.format, FileFormat::Cbfs);
    assert_eq!(p.format.variant_name.as_deref(), Some("CBFS region"));
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert_eq!(p.primary.bitwidth, 64);
    assert_eq!(p.primary.endianness, Endianness::Little);
    assert_eq!(
        labels(&p),
        [
            "fallback/romstage",
            "fallback/payload CODE at 0x80000000",
            "fallback/payload DATA at 0x80002000",
            "cpu_microcode_blob.bin"
        ]
    );
    let romstage_slice = &p.slices[0];
    assert_eq!(romstage_slice.offset, ROMSTAGE_DATA as u64);
    assert_eq!(romstage_slice.size, romstage.len() as u64);
    let decoded = romstage_slice.decoded.as_ref().expect("decoded range");
    assert_eq!(decoded.transform, "LZMA");
    assert_eq!(decoded.size, code.len() as u64);
    assert_eq!(romstage_slice.isa, Isa::AArch64);
    let payload_code = &p.slices[1];
    assert_eq!(payload_code.decoded.as_ref().unwrap().transform, "LZ4");
    assert_eq!(
        payload_code.decoded.as_ref().unwrap().size,
        code.len() as u64
    );
    assert_eq!(payload_code.isa, Isa::AArch64);
    assert!(matches!(p.slices[2].isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "Architecture AArch64 (0x0000AA64) from the master header"
    ));
    assert!(has_note(
        &p,
        "fallback/romstage: stage; load address 0x40000000; entry 0x40000000; memory size 8192 B"
    ));
    assert!(has_note(
        &p,
        "fallback/payload: SELF payload; 2 stored segments, 1 BSS; entry 0x80000000"
    ));
    assert!(has_note(
        &p,
        "1 file hash attributes verified over the stored file data"
    ));
    assert!(has_note(
        &p,
        "CBFS region at 0x0, 88 KiB: 5 files, 1 empty entries"
    ));
    assert_eq!(
        metadata(&p, "cbfs_file_1").as_deref(),
        Some(
            format!(
                "STAGE; file 0x{ROMSTAGE_DATA:X}; {} B; LZMA, 6384 B decoded size declared",
                romstage.len()
            )
            .as_str()
        )
    );
    assert_eq!(
        metadata(&p, "cbfs_architecture").as_deref(),
        Some("AArch64")
    );
    assert!(metadata(&p, "cbfs_file_3").unwrap().starts_with("RAW;"));
}

#[test]
fn a_hash_that_does_not_match_is_reported_not_rejected() {
    let mut region = ap_cbfs(0x16000);
    // The digest ends the romstage attributes, just before the data.
    let digest_at = ROMSTAGE_DATA - 1;
    region[digest_at] ^= 0x01;
    let p = classify(&region);
    assert_eq!(p.format.format, FileFormat::Cbfs);
    assert!(has_note(
        &p,
        "fallback/romstage: SHA-256 hash attribute does not match the stored file data"
    ));
    assert!(!has_note(&p, "verified over the stored file data"));
}

#[test]
fn embedded_fmap_is_found_by_search_and_ec_code_areas_are_classified() {
    let image = ec_image();
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Fmap);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("FMAP flash image (map found by search)")
    );
    assert!(p.format.confidence < 1.0);
    assert_eq!(labels(&p), ["EC_RO", "RO_FRID", "FMAP", "EC_RW", "RW_FWID"]);
    assert_eq!(p.slices[0].isa, Isa::RiscV64);
    assert_eq!(p.slices[3].isa, Isa::RiscV64);
    assert_eq!(p.primary.isa, Isa::RiscV64);
    assert!(has_note(&p, "Primary ISA selected from EC_RO"));
    assert_eq!(metadata(&p, "fmap_offset").as_deref(), Some("4160"));
}

#[test]
fn an_fmap_signature_without_a_valid_map_is_not_a_flash_image() {
    let mut data = read(RISCV64_CODE);
    data.extend_from_slice(b"__FMAP__\x01\x01");
    data.extend_from_slice(&[0x13; 64]);
    let p = classify(&data);
    assert_ne!(p.format.format, FileFormat::Fmap);

    // A map whose FMAP area does not hold the header is a different
    // coordinate system (a region extracted from a larger flash).
    let mut image = ec_image();
    image[0x1040 + 56 + 2 * 42..][..4].copy_from_slice(&0x1100u32.to_le_bytes());
    assert_ne!(classify(&image).format.format, FileFormat::Fmap);
}

#[test]
fn legacy_stages_decode_without_a_master_header() {
    let region = legacy_stage_cbfs();
    let p = classify(&region);
    assert_eq!(p.format.format, FileFormat::Cbfs);
    assert_eq!(labels(&p), ["fallback/ramstage"]);
    let slice = &p.slices[0];
    // Legacy stage data follows the 24-byte header, the 20-byte name and
    // the 28-byte stage header.
    assert_eq!(slice.offset, 24 + 20 + 28);
    assert_eq!(slice.decoded.as_ref().unwrap().transform, "LZ4");
    assert_eq!(p.primary.isa, Isa::RiscV64);
    assert!(has_note(
        &p,
        "fallback/ramstage: legacy stage; load address 0x10000000; entry 0x10000000; memory size 8192 B"
    ));
}

#[test]
fn legacy_rom_is_found_through_the_master_header_pointer() {
    let rom = legacy_rom();
    let p = classify(&rom);
    assert_eq!(p.format.format, FileFormat::Cbfs);
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("CBFS ROM (master header pointer)")
    );
    assert!(p.format.confidence < 1.0);
    assert_eq!(labels(&p), ["fallback/romstage", "bootblock"]);
    // The romstage file follows the 76-byte master-header file at the
    // next boundary; its data follows the header, name and stage header.
    assert_eq!(p.slices[0].offset, 0x480 + 24 + 20 + 28);
    assert_eq!(p.primary.isa, Isa::RiscV64);
    assert!(has_note(
        &p,
        "Master header architecture RISC-V (0xC001D0DE) does not encode the register width"
    ));
    assert!(has_note(
        &p,
        "CBFS region at 0x400, 15 KiB: 3 files, 1 empty entries"
    ));

    let mut broken = rom.clone();
    let pointer_at = broken.len() - 4;
    broken[pointer_at] ^= 0x04;
    assert_ne!(classify(&broken).format.format, FileFormat::Cbfs);
}

#[test]
fn master_header_architectures_set_a_target_only_with_a_register_width() {
    let cases: [(u32, Isa, u8); 6] = [
        (0x0000_0010, Isa::Arm, 32),
        (0x0000_aa64, Isa::AArch64, 64),
        (0x4075_70ff, Isa::Ppc64, 64),
        (0x0000_0001, Isa::Unknown(0), 0),
        (0xc001_d0de, Isa::Unknown(0), 0),
        (0xffff_ffff, Isa::Unknown(0), 0),
    ];
    for (architecture, isa, bits) in cases {
        let region = cbfs_region(
            &[
                cbfs_file(
                    TYPE_CBFSHEADER,
                    "cbfs master header",
                    &[],
                    &master_header(0x400, 0, architecture),
                ),
                cbfs_file(TYPE_RAW, "config", &[], b"CONFIG_X=y\n"),
            ],
            0x400,
        );
        let p = classify(&region);
        assert_eq!(p.format.format, FileFormat::Cbfs, "0x{architecture:X}");
        assert_eq!(p.primary.isa, isa, "0x{architecture:X}");
        assert_eq!(p.primary.bitwidth, bits, "0x{architecture:X}");
    }
}

#[test]
fn corrupt_maps_and_file_headers_are_parse_errors() {
    let image = ap_image();
    let mut version = image.clone();
    version[8] = 2;
    assert!(parse_error(&version).contains("Unsupported FMAP version 2.1 at 0x0"));

    let mut outside = image.clone();
    // COREBOOT (area 4) grows past the 128 KiB image.
    outside[56 + 4 * 42 + 4..][..4].copy_from_slice(&0x1f000u32.to_le_bytes());
    let message = parse_error(&outside);
    assert!(
        message
            .contains("Invalid FMAP area COREBOOT: 0x2000 + 126976 B is outside the 128 KiB image"),
        "{message}"
    );

    let mut name = image.clone();
    name[22] = b' ';
    assert!(parse_error(&name).contains("Invalid FMAP name at 0x16"));

    let mut trailing = image.clone();
    trailing.extend_from_slice(b"junk");
    assert!(parse_error(&trailing).contains("4 B after the FMAP image at 0x20000"));

    assert!(parse_error(b"LARCHIVE\0\0\0\0").contains("Truncated CBFS file header at 0x0"));

    let region = ap_cbfs(0x16000);
    let mut metadata_size = region.clone();
    metadata_size[20..24].copy_from_slice(&300u32.to_be_bytes());
    assert!(parse_error(&metadata_size).contains("exceeds the 256 B metadata limit"));

    let mut too_long = region.clone();
    too_long[8..12].copy_from_slice(&0x20000u32.to_be_bytes());
    assert!(parse_error(&too_long).contains("Truncated CBFS file at 0x0"));

    // The romstage's first attribute, after its header and name, claims
    // 4 bytes.
    let mut attribute = region.clone();
    attribute[ROMSTAGE_FILE + 44 + 4..][..4].copy_from_slice(&4u32.to_be_bytes());
    assert!(parse_error(&attribute).contains("Invalid CBFS attribute 0x42435A4C at 0xAC"));
}

#[test]
fn overlapping_payload_segments_leave_the_payload_opaque() {
    let code = read(AARCH64_CODE);
    let segment = |load: u64| Segment {
        kind: b"CODE",
        compression: COMPRESS_NONE,
        load,
        data: code[..256].to_vec(),
        memory_size: 256,
    };
    let entry = Segment {
        kind: b"ENTR",
        compression: COMPRESS_NONE,
        load: 0x1000,
        data: Vec::new(),
        memory_size: 0,
    };
    let mut payload = self_payload(&[segment(0x1000), segment(0x2000), entry]);
    // Point the second record's offset (bytes 8-11) at the first segment's
    // bytes, which follow the three 28-byte records.
    payload[28 + 8..28 + 12].copy_from_slice(&(3u32 * 28).to_be_bytes());
    let region = cbfs_region(&[cbfs_file(TYPE_SELF, "payload", &[], &payload)], 0x400);
    let p = classify(&region);
    assert_eq!(p.format.format, FileFormat::Cbfs);
    assert_eq!(labels(&p), ["payload"]);
    assert!(matches!(p.slices[0].isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "payload: Invalid payload segments: stored ranges overlap at 0x"
    ));
}

#[test]
fn undecodable_stage_contents_stay_opaque() {
    let mut region = ap_cbfs(0x16000);
    // Corrupt the LZMA stream past its 13-byte header.
    let stream_at = ROMSTAGE_DATA + 13;
    for byte in &mut region[stream_at..stream_at + 64] {
        *byte = !*byte;
    }
    let p = classify(&region);
    assert_eq!(p.format.format, FileFormat::Cbfs);
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.starts_with("fallback/romstage: ")
            && n.message.ends_with("; not analyzed")));
    assert!(matches!(p.slices[0].isa, Isa::Unknown(_)));
}

/// A 64-byte ELF64 header and nothing else: `\x7fELF`, class 2 (64-bit),
/// data 1 (little-endian), version 1, `e_type` 2 (executable), `e_machine`
/// 62 (x86-64), `e_version` 1, `e_ehsize` 64, `e_phentsize` 56,
/// `e_shentsize` 64, no program or section headers.
fn x86_64_elf_header() -> Vec<u8> {
    let mut header = vec![0u8; 64];
    header[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    header[16..18].copy_from_slice(&2u16.to_le_bytes());
    header[18..20].copy_from_slice(&62u16.to_le_bytes());
    header[20..24].copy_from_slice(&1u32.to_le_bytes());
    header[52..54].copy_from_slice(&64u16.to_le_bytes());
    header[54..56].copy_from_slice(&56u16.to_le_bytes());
    header[58..60].copy_from_slice(&64u16.to_le_bytes());
    header
}

#[test]
fn stage_programs_go_to_the_code_model_and_raw_files_only_when_recognized() {
    // The same bytes, an x86-64 ELF header followed by AArch64 code, as an
    // uncompressed stage and as a RAW file; a second RAW file holds bytes
    // of no recognized format.
    let mut program = x86_64_elf_header();
    program.extend(read(AARCH64_CODE));
    let mut attributes = stage_attribute(0x1000, 0, 0x4000);
    attributes.extend(compression_attribute(COMPRESS_NONE, program.len()));
    let region = cbfs_region(
        &[
            cbfs_file(TYPE_STAGE, "fallback/ramstage", &attributes, &program),
            cbfs_file(TYPE_RAW, "image.elf", &[], &program),
            cbfs_file(TYPE_RAW, "notes.txt", &[], b"plain text, not a format"),
        ],
        0x4000,
    );
    let p = classify(&region);
    assert_eq!(p.format.format, FileFormat::Cbfs);
    assert_eq!(labels(&p), ["fallback/ramstage", "image.elf"]);
    // A stage is a flat program image: its bytes are never parsed as ELF.
    assert_eq!(p.slices[0].isa, Isa::AArch64);
    assert_eq!(p.slices[1].isa, Isa::X86_64);
    assert_eq!(
        metadata(&p, "cbfs_file_2")
            .as_deref()
            .map(|v| v.starts_with("RAW;")),
        Some(true)
    );
}

/// An x86-style flash image: the descriptor, an Intel ME region holding
/// code bytes, and the BIOS region with the FMAP at 0x4000 and an LZ4
/// stage of `AArch64` code in the COREBOOT CBFS.
fn ifd_style_image() -> Vec<u8> {
    let code = read(AARCH64_CODE);
    let mut attributes = compression_attribute(COMPRESS_LZ4, code.len());
    attributes.extend(stage_attribute(0x10_0000, 0, 0x4000));
    let cbfs = cbfs_region(
        &[cbfs_file(
            TYPE_STAGE,
            "fallback/romstage",
            &attributes,
            &lz4_frame(&code),
        )],
        0xb000,
    );
    let areas = [
        area(0x0000, 0x10000, "SI_ALL"),
        area(0x0000, 0x1000, "SI_DESC"),
        area(0x1000, 0x3000, "SI_ME"),
        area(0x4000, 0xc000, "SI_BIOS"),
        area(0x4000, 0x800, "FMAP"),
        area(0x5000, 0xb000, "COREBOOT"),
    ];
    let mut image = vec![0xffu8; 0x10000];
    place(&mut image, 0x20, b"descriptor placeholder");
    place(&mut image, 0x1000, &read(RISCV64_CODE));
    place(&mut image, 0x4000, &fmap(0, 0x10000, "FLASH", &areas));
    place(&mut image, 0x5000, &cbfs);
    image
}

/// `FLVALSIG`, the Intel flash descriptor signature, at descriptor offset
/// 0x10.
const FLVALSIG: u32 = 0x0ff0_a55a;

#[test]
fn fmap_takes_precedence_over_the_intel_flash_descriptor_it_maps() {
    let mut image = ifd_style_image();
    place(&mut image, 0x10, &FLVALSIG.to_le_bytes());
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Fmap);
    assert_eq!(labels(&p), ["SI_DESC", "SI_ME", "FMAP", "COREBOOT"]);
    assert_eq!(p.primary.isa, Isa::AArch64);
}

#[test]
fn intel_me_regions_are_listed_but_not_analyzed() {
    let p = classify(&ifd_style_image());
    assert_eq!(p.format.format, FileFormat::Fmap);
    assert_eq!(labels(&p), ["SI_DESC", "SI_ME", "FMAP", "COREBOOT"]);
    let me = &p.slices[1];
    assert_eq!((me.offset, me.size), (0x1000, 0x3000));
    assert!(matches!(me.isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "SI_ME: Intel ME or IE region by its ifdtool name; its layout is not parsed"
    ));
    assert!(has_note(&p, "SI_ME: opaque"));
    assert_eq!(
        metadata(&p, "fmap_area_2").as_deref(),
        Some("0x1000 + 12288 B; flags none; ME or IE firmware, not parsed")
    );
    assert_eq!(p.slices[3].isa, Isa::AArch64);
    assert_eq!(p.primary.isa, Isa::AArch64);
    assert!(has_note(&p, "Primary ISA selected from COREBOOT"));
}

#[test]
fn areas_flagged_compressed_without_a_recognized_codec_stay_opaque() {
    let mut image = ec_image();
    // EC_RW (area 3): flags `FMAP_AREA_COMPRESSED` (0x2), after the
    // area's offset, size and 32-byte name.
    let flags_at = 0x1040 + 56 + 3 * 42 + 40;
    image[flags_at..flags_at + 2].copy_from_slice(&0x0002u16.to_le_bytes());
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::Fmap);
    let ec_rw = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("EC_RW"))
        .expect("EC_RW is listed");
    assert!(matches!(ec_rw.isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "EC_RW: flagged compressed and the codec is not named; not analyzed"
    ));
    assert_eq!(
        metadata(&p, "fmap_area_3").as_deref(),
        Some("0x2000 + 8192 B; flags compressed; classified")
    );
    assert_eq!(p.primary.isa, Isa::RiscV64);
}

/// A 1 KiB EC image: RISC-V code in `EC_RO` and `EC_RW`, the map at 0x100
/// inside `EC_RO`.
fn small_ec_image() -> Vec<u8> {
    let code = read(RISCV64_CODE);
    let areas = [
        area(0x000, 0x200, "EC_RO"),
        area(0x100, 0x100, "FMAP"),
        area(0x200, 0x200, "EC_RW"),
    ];
    let mut image = vec![0xffu8; 0x400];
    place(&mut image, 0, &code[..0x100]);
    place(&mut image, 0x100, &fmap(0, 0x400, "EC_FMAP", &areas));
    place(&mut image, 0x200, &code[..0x200]);
    image
}

/// Small fixtures for the sweeps: a 1.5 KiB FMAP image with a CBFS holding
/// an LZ4 stage with a hash and a SELF payload, a 1 KiB legacy ROM, and a
/// 1 KiB EC image whose map is found by search.
fn sweep_fixtures() -> Vec<Vec<u8>> {
    let code = read(AARCH64_CODE);
    let stage_code = lz4_frame(&code[..256]);
    let mut attributes = compression_attribute(COMPRESS_LZ4, 256);
    attributes.extend(stage_attribute(0x1000, 0, 0x200));
    attributes.extend(sha256_attribute(&stage_code));
    let cbfs = cbfs_region(
        &[
            cbfs_file(
                TYPE_CBFSHEADER,
                "cbfs master header",
                &[],
                &master_header(0x500, 0, ARCHITECTURE_AARCH64),
            ),
            cbfs_file(TYPE_STAGE, "stage", &attributes, &stage_code),
            cbfs_file(
                TYPE_SELF,
                "payload",
                &[],
                &self_payload(&[
                    Segment {
                        kind: b"CODE",
                        compression: COMPRESS_NONE,
                        load: 0x2000,
                        data: code[..64].to_vec(),
                        memory_size: 64,
                    },
                    Segment {
                        kind: b"ENTR",
                        compression: COMPRESS_NONE,
                        load: 0x2000,
                        data: Vec::new(),
                        memory_size: 0,
                    },
                ]),
            ),
        ],
        0x500,
    );
    let mut image = vec![0xffu8; 0x600];
    let areas = [area(0, 0x100, "FMAP"), area(0x100, 0x500, "COREBOOT")];
    place(&mut image, 0, &fmap(0, 0x600, "SMALL", &areas));
    place(&mut image, 0x100, &cbfs);

    let mut rom = vec![0xffu8; 0x40];
    let mut region = Vec::new();
    push_file(
        &mut region,
        &cbfs_file(
            TYPE_CBFSHEADER,
            "cbfs master header",
            &[],
            &master_header(0x400, 0x40, ARCHITECTURE_AARCH64),
        ),
    );
    push_file(
        &mut region,
        &cbfs_file(
            TYPE_LEGACY_STAGE,
            "romstage",
            &[],
            &legacy_stage(COMPRESS_LZ4, 0, 0, 0x200, &stage_code),
        ),
    );
    region.resize(align_up(region.len(), 64), 0xff);
    let mut bootblock = vec![0u8; 0x400 - 0x40 - region.len() - 24 - 12];
    let pointer: i32 = 0x40 + 24 + 20 - 0x400;
    let pointer_at = bootblock.len() - 4;
    bootblock[pointer_at..].copy_from_slice(&pointer.to_le_bytes());
    region.extend(cbfs_file(TYPE_BOOTBLOCK, "bootblock", &[], &bootblock));
    rom.extend(region);
    assert_eq!(rom.len(), 0x400);

    vec![image, rom, small_ec_image()]
}

#[test]
fn sweep_fixtures_are_recognized() {
    let fixtures = sweep_fixtures();
    assert_eq!(classify(&fixtures[0]).format.format, FileFormat::Fmap);
    assert_eq!(classify(&fixtures[0]).primary.isa, Isa::AArch64);
    assert_eq!(classify(&fixtures[1]).format.format, FileFormat::Cbfs);
    assert_eq!(classify(&fixtures[2]).format.format, FileFormat::Fmap);
}

#[test]
fn every_prefix_errors_or_claims_no_more_than_the_whole() {
    let fixtures = sweep_fixtures();
    // The map declares the image size, so every proper prefix that keeps
    // the signature is a parse error.
    let image = &fixtures[0];
    for end in 8..image.len() {
        let parsed = detect_payload(&image[..end], &ClassifierOptions::new());
        assert!(parsed.is_err(), "prefix {end} of the FMAP image parsed");
    }
    // A region whose first header is cut short is truncated, not empty.
    let region = &image[0x100..];
    for end in 8..=24 {
        let parsed = detect_payload(&region[..end], &ClassifierOptions::new());
        assert!(parsed.is_err(), "prefix {end} of the CBFS region parsed");
    }
    for file in fixtures {
        let whole = detect_payload(&file, &ClassifierOptions::new())
            .map(|p| p.slices.len())
            .unwrap_or(0);
        for end in 0..file.len() {
            let Ok(p) = detect_payload(&file[..end], &ClassifierOptions::new()) else {
                continue;
            };
            if p.format.format == FileFormat::Fmap {
                panic!("prefix {end} of an FMAP image still parses as one");
            }
            if p.format.format == FileFormat::Cbfs {
                assert!(p.slices.len() <= whole, "prefix {end}");
            }
        }
    }
}

#[test]
fn byte_mutations_do_not_panic() {
    for file in sweep_fixtures() {
        for i in 0..file.len() {
            for value in [0x00, 0xff, file[i] ^ 0x01] {
                let mut mutated = file.clone();
                mutated[i] = value;
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}
