//! Nintendo console ROMs: DS cartridges with ARM9/ARM7 children, secure
//! area and DSi areas; GBA and Game Boy headers with their checksums; iNES
//! and NES 2.0 images with PRG/CHR children; SNES internal headers
//! (LoROM, HiROM, ExHiROM, copier header, ambiguity); Nintendo 64 ROMs in
//! all three byte orders with CIC identification and the check code; with
//! corruption, truncation and mutation sweeps. All fixtures are synthetic
//! and built here from the documented header layouts.

use zrax::formats::container;
use zrax::formats::nintendo::{Layout, N64ByteOrder, SnesMapping};
use zrax::formats::{detect_format, DetectedFormat};
use zrax::{detect_payload, ClassifierOptions, DetectionPayload, Endianness, FileFormat, Isa};

/// Compiled 32-bit Arm code (little-endian), from the repository's testbins.
const ARM_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/arm32_arm-unknown-linux-gnueabi_O0_min_float_add.bin"
);

/// Compiled 64-bit MIPS code (big-endian), from the repository's testbins.
const MIPS_CODE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testbins/mips64_be_mips64-unknown-linux-gnuabi64_O0_int_crc32.bin"
);

fn arm_code() -> Vec<u8> {
    std::fs::read(ARM_CODE).expect("testbin is committed")
}

fn mips_code() -> Vec<u8> {
    std::fs::read(MIPS_CODE).expect("testbin is committed")
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn has_note(p: &DetectionPayload, text: &str) -> bool {
    p.notes.iter().any(|n| n.message.contains(text))
}

fn metadata(p: &DetectionPayload, key: &str) -> Option<String> {
    p.metadata
        .iter()
        .find(|m| matches!(&m.key, zrax::MetadataKey::Custom(k) if k == key))
        .map(|m| m.value.to_string())
}

fn layout(data: &[u8]) -> Option<Layout> {
    match detect_format(data) {
        DetectedFormat::Container {
            kind: container::Kind::Nintendo(layout),
        } => Some(layout),
        _ => None,
    }
}

fn parse(data: &[u8]) -> zrax::Result<container::Container<'_>> {
    let layout = layout(data).expect("a Nintendo layout");
    container::parse(data, container::Kind::Nintendo(layout))
}

fn error_text(data: &[u8]) -> String {
    match parse(data) {
        Ok(_) => panic!("expected a parse error"),
        Err(e) => e.to_string(),
    }
}

fn put_le16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_le32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_be32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

/// CRC-16/MODBUS (reflected 0xA001, initial 0xFFFF), bit by bit as in the
/// GBATEK description.
fn crc16_modbus(bytes: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &b in bytes {
        crc ^= u16::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// The 156-byte Nintendo logo (gbafix.c `good_header.logo`).
#[rustfmt::skip]
const NINTENDO_LOGO: [u8; 156] = [
    0x24, 0xFF, 0xAE, 0x51, 0x69, 0x9A, 0xA2, 0x21, 0x3D, 0x84, 0x82, 0x0A, 0x84, 0xE4, 0x09, 0xAD,
    0x11, 0x24, 0x8B, 0x98, 0xC0, 0x81, 0x7F, 0x21, 0xA3, 0x52, 0xBE, 0x19, 0x93, 0x09, 0xCE, 0x20,
    0x10, 0x46, 0x4A, 0x4A, 0xF8, 0x27, 0x31, 0xEC, 0x58, 0xC7, 0xE8, 0x33, 0x82, 0xE3, 0xCE, 0xBF,
    0x85, 0xF4, 0xDF, 0x94, 0xCE, 0x4B, 0x09, 0xC1, 0x94, 0x56, 0x8A, 0xC0, 0x13, 0x72, 0xA7, 0xFC,
    0x9F, 0x84, 0x4D, 0x73, 0xA3, 0xCA, 0x9A, 0x61, 0x58, 0x97, 0xA3, 0x27, 0xFC, 0x03, 0x98, 0x76,
    0x23, 0x1D, 0xC7, 0x61, 0x03, 0x04, 0xAE, 0x56, 0xBF, 0x38, 0x84, 0x00, 0x40, 0xA7, 0x0E, 0xFD,
    0xFF, 0x52, 0xFE, 0x03, 0x6F, 0x95, 0x30, 0xF1, 0x97, 0xFB, 0xC0, 0x85, 0x60, 0xD6, 0x80, 0x25,
    0xA9, 0x63, 0xBE, 0x03, 0x01, 0x4E, 0x38, 0xE2, 0xF9, 0xA2, 0x34, 0xFF, 0xBB, 0x3E, 0x03, 0x44,
    0x78, 0x00, 0x90, 0xCB, 0x88, 0x11, 0x3A, 0x94, 0x65, 0xC0, 0x7C, 0x63, 0x87, 0xF0, 0x3C, 0xAF,
    0xD6, 0x25, 0xE4, 0x8B, 0x38, 0x0A, 0xAC, 0x72, 0x21, 0xD4, 0xF8, 0x07,
];

/// The 48-byte Game Boy logo (Pan Docs).
#[rustfmt::skip]
const GB_LOGO: [u8; 48] = [
    0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B, 0x03, 0x73, 0x00, 0x83, 0x00, 0x0C, 0x00, 0x0D,
    0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E, 0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99,
    0xBB, 0xBB, 0x67, 0x63, 0x6E, 0x0E, 0xEC, 0xCC, 0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E,
];

// --- Nintendo DS -------------------------------------------------------

/// One DS code area: ROM offset, entry, RAM address; the size comes from
/// the bytes.
struct NdsBinary<'a> {
    offset: usize,
    entry: u32,
    ram_address: u32,
    bytes: &'a [u8],
}

/// Set the logo CRC (0x15C) and the header CRC (0x15E over 0x000-0x15D).
fn seal_nds(image: &mut [u8]) {
    let logo_crc = crc16_modbus(&image[0xC0..0x15C]);
    put_le16(image, 0x15C, logo_crc);
    let header_crc = crc16_modbus(&image[..0x15E]);
    put_le16(image, 0x15E, header_crc);
}

/// A DS image of `size` bytes: title, game code, maker code, unit code,
/// the ARM9 (0x020) and ARM7 (0x030) areas (offset, entry, RAM address,
/// size), total used ROM size (0x080), header size (0x084), the logo at
/// 0x0C0 and both CRCs. Code areas are copied to their offsets.
fn nds(size: usize, unit_code: u8, arm9: &NdsBinary<'_>, arm7: &NdsBinary<'_>) -> Vec<u8> {
    let mut image = vec![0u8; size];
    image[..8].copy_from_slice(b"ZRAXTEST");
    image[0x0C..0x10].copy_from_slice(b"AZRE");
    image[0x10..0x12].copy_from_slice(b"01");
    image[0x12] = unit_code;
    for (at, binary) in [(0x20, arm9), (0x30, arm7)] {
        put_le32(&mut image, at, binary.offset as u32);
        put_le32(&mut image, at + 4, binary.entry);
        put_le32(&mut image, at + 8, binary.ram_address);
        put_le32(&mut image, at + 12, binary.bytes.len() as u32);
        image[binary.offset..binary.offset + binary.bytes.len()].copy_from_slice(binary.bytes);
    }
    put_le32(&mut image, 0x80, size as u32);
    put_le32(&mut image, 0x84, 0x4000);
    image[0xC0..0x15C].copy_from_slice(&NINTENDO_LOGO);
    seal_nds(&mut image);
    image
}

/// A homebrew-style DS image: ARM9 at 0x200 in main RAM, ARM7 after it in
/// ARM7 WRAM.
fn homebrew_nds() -> Vec<u8> {
    let code = arm_code();
    let arm9_offset = 0x200;
    let arm7_offset = arm9_offset + code.len();
    nds(
        arm7_offset + code.len(),
        0x00,
        &NdsBinary {
            offset: arm9_offset,
            entry: 0x0200_0000,
            ram_address: 0x0200_0000,
            bytes: &code,
        },
        &NdsBinary {
            offset: arm7_offset,
            entry: 0x037F_8000,
            ram_address: 0x037F_8000,
            bytes: &code,
        },
    )
}

#[test]
fn checksum_helpers_match_their_reference_values() {
    assert_eq!(crc16_modbus(b"123456789"), 0x4B37);
    assert_eq!(crc16_modbus(&NINTENDO_LOGO), 0xCF56);
}

#[test]
fn nds_arm9_and_arm7_are_children_with_their_cores() {
    let image = homebrew_nds();
    let code_size = arm_code().len() as u64;
    assert_eq!(layout(&image), Some(Layout::Nds));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::NdsRom);
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Arm, 32, Endianness::Little)
    );
    assert_eq!(
        p.primary.variant.as_ref().map(|v| v.name.as_str()),
        Some("ARMv5TE (ARM946E-S)")
    );
    let slice = |label: &str| {
        p.slices
            .iter()
            .find(|s| s.label.as_deref() == Some(label))
            .unwrap_or_else(|| panic!("{label} slice"))
    };
    let arm9 = slice("ARM9 binary");
    assert_eq!(
        (arm9.offset, arm9.size, arm9.isa),
        (0x200, code_size, Isa::Arm)
    );
    assert_eq!(
        arm9.variant.as_ref().map(|v| v.name.as_str()),
        Some("ARMv5TE (ARM946E-S)")
    );
    let arm7 = slice("ARM7 binary");
    assert_eq!(arm7.offset, 0x200 + code_size);
    assert_eq!(
        arm7.variant.as_ref().map(|v| v.name.as_str()),
        Some("ARMv4T (ARM7TDMI)")
    );
    let header_crc = u16::from_le_bytes([image[0x15E], image[0x15F]]);
    assert!(has_note(
        &p,
        &format!("Header CRC-16 0x{header_crc:04X} verified")
    ));
    assert!(has_note(&p, "No secure area"));
    assert_eq!(metadata(&p, "nds_title").as_deref(), Some("ZRAXTEST"));
    assert_eq!(metadata(&p, "nds_game_code").as_deref(), Some("AZRE"));
    assert_eq!(
        p.metadata
            .iter()
            .filter(|m| m.label.ends_with("binary"))
            .count(),
        2
    );
}

#[test]
fn nds_header_and_logo_crcs_are_checked() {
    let image = homebrew_nds();
    let mut bad_crc = image.clone();
    bad_crc[0x15E] ^= 0x01;
    assert!(error_text(&bad_crc).contains("Invalid header CRC-16"));
    // A changed title breaks the header CRC; the logo still identifies the
    // image, so the corruption is a parse error.
    let mut bad_title = image.clone();
    bad_title[0] = b'Y';
    assert!(error_text(&bad_title).contains("Invalid header CRC-16"));
    let mut bad_logo_crc = image.clone();
    put_le16(&mut bad_logo_crc, 0x15C, 0x1234);
    assert_eq!(layout(&bad_logo_crc), None);
}

#[test]
fn nds_code_areas_must_load_into_ram_and_lie_in_the_file() {
    let code = arm_code();
    let at = |offset, entry, ram_address| NdsBinary {
        offset,
        entry,
        ram_address,
        bytes: &code,
    };
    let size = 0x200 + 2 * code.len();
    let arm7 = at(0x200 + code.len(), 0x037F_8000, 0x037F_8000);
    let outside_ram = nds(size, 0, &at(0x200, 0x0100_0000, 0x0100_0000), &arm7);
    assert!(error_text(&outside_ram).contains("Invalid ARM9 binary RAM address 0x01000000"));
    let bad_entry = nds(size, 0, &at(0x200, 0x0100_0000, 0x0200_0000), &arm7);
    assert!(
        error_text(&bad_entry).contains("Invalid ARM9 binary entry 0x01000000: not in main RAM")
    );
    // An entry in main RAM but past the loaded bytes is allowed by the
    // header ranges and only noted.
    let far_entry = nds(size, 0, &at(0x200, 0x0230_0000, 0x0200_0000), &arm7);
    assert!(has_note(
        &classify(&far_entry),
        "entry 0x02300000 (outside the loaded bytes)"
    ));
    let in_header = nds(size, 0, &at(0x100, 0x0200_0000, 0x0200_0000), &arm7);
    assert!(error_text(&in_header).contains("Invalid ARM9 binary ROM offset 0x100"));
    let mut beyond = homebrew_nds();
    put_le32(&mut beyond, 0x3C, 0x0001_0000);
    seal_nds(&mut beyond);
    assert!(error_text(&beyond).contains("Truncated ARM7 binary"));
}

/// A cartridge-style DS image with the ARM9 binary in the secure area at
/// 0x4000 and `id` as its first 8 bytes, and the ARM7 binary at 0x8000.
fn secure_area_nds(id: &[u8; 8]) -> Vec<u8> {
    let mut arm9 = vec![0u8; 0x1000];
    arm9[..8].copy_from_slice(id);
    arm9[0x800..0x800 + arm_code().len()].copy_from_slice(&arm_code());
    let arm7 = arm_code();
    nds(
        0x8000 + arm7.len(),
        0,
        &NdsBinary {
            offset: 0x4000,
            entry: 0x0200_0800,
            ram_address: 0x0200_0000,
            bytes: &arm9,
        },
        &NdsBinary {
            offset: 0x8000,
            entry: 0x0238_0000,
            ram_address: 0x0238_0000,
            bytes: &arm7,
        },
    )
}

#[test]
fn nds_secure_area_is_opaque_unless_its_id_shows_it_decrypted() {
    let encrypted = classify(&secure_area_nds(&[0x5A; 8]));
    let secure = encrypted
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("ARM9 secure area (encrypted or unidentified)"))
        .expect("opaque secure area");
    assert_eq!((secure.offset, secure.size), (0x4000, 0x800));
    assert!(matches!(secure.isa, Isa::Unknown(_)));
    let arm9 = encrypted
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("ARM9 binary"))
        .expect("ARM9 after the encrypted part");
    assert_eq!((arm9.offset, arm9.size), (0x4800, 0x800));
    assert!(has_note(
        &encrypted,
        "Secure area CRC-16 0x0000 does not match"
    ));

    let decrypted = classify(&secure_area_nds(b"encryObj"));
    assert!(has_note(
        &decrypted,
        "Secure area is decrypted (ID encryObj)"
    ));
    let arm9 = decrypted
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("ARM9 binary"))
        .expect("whole ARM9");
    assert_eq!((arm9.offset, arm9.size), (0x4000, 0x1000));
}

#[test]
fn nds_dsi_areas_are_children_unless_modcrypted() {
    let image = dsi_nds();
    let p = classify(&image);
    assert!(has_note(&p, "DSi extended header: unit code 0x02"));
    assert!(has_note(&p, "Modcrypt (AES-CTR) areas"));
    let arm7 = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("ARM7 binary (modcrypted)"))
        .expect("opaque ARM7");
    assert!(matches!(arm7.isa, Isa::Unknown(_)));
    let arm9 = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("ARM9 binary"))
        .expect("ARM9 outside the modcrypt areas");
    assert_eq!(arm9.isa, Isa::Arm);
    let arm9i = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("ARM9i binary"))
        .expect("ARM9i child");
    assert_eq!(
        (arm9i.offset, arm9i.isa),
        (DSI_ARM9I_OFFSET as u64, Isa::Arm)
    );
    assert_eq!(
        arm9i.variant.as_ref().map(|v| v.name.as_str()),
        Some("ARMv5TE (ARM946E-S)")
    );
    let arm7i = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("ARM7i binary (modcrypted)"))
        .expect("opaque ARM7i");
    assert!(matches!(arm7i.isa, Isa::Unknown(_)));
    // A DSi unit code needs the extended header up to 0x1000.
    let code = arm_code();
    let small = |offset| NdsBinary {
        offset,
        entry: 0x0200_0000,
        ram_address: 0x0200_0000,
        bytes: &code[..0x100],
    };
    let short = nds(0x400, 0x02, &small(0x200), &small(0x300));
    assert!(error_text(&short).contains("Truncated DSi extended header"));
}

/// File offset of the ARM9i binary in [`dsi_nds`].
const DSI_ARM9I_OFFSET: usize = 0x3000;

/// A DSi-enhanced image (unit code 0x02): ARM9 at 0x1000 and ARM7 at
/// 0x2000 in main RAM, then the ARM9i and ARM7i areas (header 0x1C0 and
/// 0x1D0: ROM offset, RAM address at +8, size at +12) from
/// [`DSI_ARM9I_OFFSET`]. DSi flags (0x01C) bit 1 marks it modcrypted: area 1
/// (0x220 offset, 0x224 size) covers the ARM7i binary, area 2 (0x228,
/// 0x22C) the first 16 bytes of the ARM7 binary.
fn dsi_nds() -> Vec<u8> {
    let code = arm_code();
    let arm9i_offset = DSI_ARM9I_OFFSET;
    let arm7i_offset = arm9i_offset + code.len();
    let size = arm7i_offset + code.len();
    let mut image = nds(
        size,
        0x02,
        &NdsBinary {
            offset: 0x1000,
            entry: 0x0200_4000,
            ram_address: 0x0200_4000,
            bytes: &code,
        },
        &NdsBinary {
            offset: 0x2000,
            entry: 0x0238_0000,
            ram_address: 0x0238_0000,
            bytes: &code,
        },
    );
    // ARM9i and ARM7i areas: ROM offset, RAM address (+8), size (+12).
    for (at, offset, ram) in [
        (0x1C0, arm9i_offset, 0x0240_0000u32),
        (0x1D0, arm7i_offset, 0x02E8_0000),
    ] {
        put_le32(&mut image, at, offset as u32);
        put_le32(&mut image, at + 8, ram);
        put_le32(&mut image, at + 12, code.len() as u32);
        image[offset..offset + code.len()].copy_from_slice(&code);
    }
    // DSi flags bit 1: modcrypted; area 1 covers the ARM7i binary, area 2
    // the first 16 bytes of the ARM7 binary.
    image[0x1C] = 0x02;
    put_le32(&mut image, 0x220, arm7i_offset as u32);
    put_le32(&mut image, 0x224, code.len() as u32);
    put_le32(&mut image, 0x228, 0x2000);
    put_le32(&mut image, 0x22C, 0x10);
    seal_nds(&mut image);
    image
}

// --- Game Boy Advance --------------------------------------------------

/// The GBA complement over 0x0A0-0x0BC (GBATEK).
fn gba_complement(header: &[u8]) -> u8 {
    let sum = header[0xA0..0xBD]
        .iter()
        .fold(0u8, |sum, &b| sum.wrapping_add(b));
    0u8.wrapping_sub(sum.wrapping_add(0x19))
}

/// A GBA image: entry branch `B 0x0C0` (0xEA00002E), logo, title, game
/// code, maker code, fixed 0x96 at 0x0B2, complement at 0x0BD, then `code`
/// from 0x0C0.
fn gba(code: &[u8], with_logo: bool) -> Vec<u8> {
    let mut image = vec![0u8; 0xC0];
    put_le32(&mut image, 0, 0xEA00_002E);
    if with_logo {
        image[0x04..0xA0].copy_from_slice(&NINTENDO_LOGO);
    }
    image[0xA0..0xA8].copy_from_slice(b"ZRAXTEST");
    image[0xAC..0xB0].copy_from_slice(b"AZRE");
    image[0xB0..0xB2].copy_from_slice(b"01");
    image[0xB2] = 0x96;
    image[0xBD] = gba_complement(&image);
    image.extend_from_slice(code);
    image
}

#[test]
fn gba_rom_is_one_arm7tdmi_code_section() {
    let image = gba(&arm_code(), true);
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::GbaRom);
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Arm, 32, Endianness::Little)
    );
    assert_eq!(
        p.primary.variant.as_ref().map(|v| v.name.as_str()),
        Some("ARMv4T (ARM7TDMI)")
    );
    assert!(has_note(&p, "Entry branch at 0x000 to 0x080000C0"));
    assert!(has_note(&p, "Nintendo logo at 0x004 matches"));
    assert_eq!(
        metadata(&p, "gba_section_0").as_deref(),
        Some(format!("file 0x0; destination 0x8000000; {} B", image.len()).as_str())
    );
    assert_eq!(metadata(&p, "gba_title").as_deref(), Some("ZRAXTEST"));
}

#[test]
fn gba_needs_fixed_byte_complement_and_logo_or_entry_branch() {
    let code = arm_code();
    let no_logo = gba(&code, false);
    assert_eq!(layout(&no_logo), Some(Layout::Gba));
    assert!(has_note(
        &classify(&no_logo),
        "recognized from the entry branch"
    ));
    let mut bad_complement = gba(&code, true);
    bad_complement[0xBD] ^= 0x01;
    assert_eq!(layout(&bad_complement), None);
    let mut bad_fixed = gba(&code, true);
    bad_fixed[0xB2] = 0x00;
    bad_fixed[0xBD] = gba_complement(&bad_fixed);
    assert_eq!(layout(&bad_fixed), None);
    let mut no_branch = gba(&code, false);
    put_le32(&mut no_branch, 0, 0);
    assert_eq!(layout(&no_branch), None);
}

// --- Game Boy ----------------------------------------------------------

/// The header checksum over 0x134-0x14C (Pan Docs).
fn gb_header_checksum(rom: &[u8]) -> u8 {
    rom[0x134..0x14D]
        .iter()
        .fold(0u8, |sum, &b| sum.wrapping_sub(b).wrapping_sub(1))
}

/// Set the header checksum (0x14D) and the big-endian global checksum
/// (0x14E, sum of every other byte).
fn seal_gb(rom: &mut [u8]) {
    rom[0x14D] = gb_header_checksum(rom);
    let sum = rom
        .iter()
        .enumerate()
        .filter(|(i, _)| !(0x14E..0x150).contains(i))
        .fold(0u16, |sum, (_, &b)| sum.wrapping_add(u16::from(b)));
    rom[0x14E..0x150].copy_from_slice(&sum.to_be_bytes());
}

/// A 32 KiB Game Boy ROM: `nop; jp $0150` at 0x100, logo, title, CGB flag,
/// cartridge type MBC1 (0x147), ROM size code 0 (0x148), RAM size code 2
/// (0x149), checksums; synthetic SM83 bytes from 0x150.
fn gb(cgb_flag: u8) -> Vec<u8> {
    let mut rom = vec![0u8; 0x8000];
    rom[0x100..0x104].copy_from_slice(&[0x00, 0xC3, 0x50, 0x01]);
    rom[0x104..0x134].copy_from_slice(&GB_LOGO);
    rom[0x134..0x13C].copy_from_slice(b"ZRAXTEST");
    rom[0x143] = cgb_flag;
    rom[0x147] = 0x01;
    rom[0x149] = 0x02;
    // ld a, $01; ld ($2000), a; jr -2 ... repeated.
    for (i, b) in rom[0x150..0x4000].iter_mut().enumerate() {
        *b = [0x3E, 0x01, 0xEA, 0x00, 0x20, 0x18, 0xFE, 0xC9][i % 8];
    }
    seal_gb(&mut rom);
    rom
}

#[test]
fn gb_rom_reports_sm83_and_verifies_both_checksums() {
    let rom = gb(0x80);
    assert_eq!(layout(&rom), Some(Layout::Gbc));
    assert_eq!(layout(&gb(0x00)), Some(Layout::Gb));
    let p = classify(&rom);
    assert_eq!(p.format.format, FileFormat::GbRom);
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Z80, 8, Endianness::Little)
    );
    assert_eq!(
        p.primary.variant.as_ref().map(|v| v.name.as_str()),
        Some("SM83")
    );
    assert!(has_note(&p, "reported as the Z80 family"));
    assert!(has_note(&p, "Global checksum"));
    assert!(has_note(&p, "verified"));
    assert!(has_note(&p, "CGB flag 0x80"));
    assert_eq!(metadata(&p, "gb_cartridge_type").as_deref(), Some("MBC1"));
    assert_eq!(metadata(&p, "gb_rom_size").as_deref(), Some("32 KiB"));
    assert_eq!(metadata(&p, "gb_ram_size").as_deref(), Some("8 KiB"));
    assert_eq!(metadata(&p, "gb_title").as_deref(), Some("ZRAXTEST"));
}

#[test]
fn gb_checksums_and_declared_size_are_checked() {
    let mut bad_header = gb(0);
    bad_header[0x14D] ^= 0x01;
    assert!(error_text(&bad_header).contains("Invalid header checksum"));
    let mut bad_global = gb(0);
    bad_global[0x7FFF] = 0x55;
    let p = classify(&bad_global);
    assert!(has_note(&p, "does not match the computed"));
    let mut too_large = gb(0);
    too_large[0x148] = 0x01;
    too_large[0x14D] = gb_header_checksum(&too_large);
    assert!(error_text(&too_large).contains("Truncated ROM: the header declares 64 KiB"));
    // The CGB boot ROM checks only the first 0x18 logo bytes; with a valid
    // header checksum that prefix is enough.
    let mut cgb_logo = gb(0xC0);
    cgb_logo[0x104 + 0x20] ^= 0xFF;
    assert_eq!(layout(&cgb_logo), Some(Layout::Gbc));
    cgb_logo[0x14D] ^= 0x01;
    assert_eq!(layout(&cgb_logo), None);
}

/// A GBX footer: mapper ID, flags, sizes and mapper variables (60 bytes,
/// zero here), ending in `GBX!` (64 bytes in all).
fn gbx_footer() -> Vec<u8> {
    let mut footer = vec![0u8; 60];
    footer[..4].copy_from_slice(b"MBC1");
    footer.extend_from_slice(b"GBX!");
    footer
}

#[test]
fn gb_trailing_bytes_must_be_padding_or_a_gbx_footer() {
    let mut padded = gb(0);
    padded.extend_from_slice(&[0xFF; 100]);
    let p = classify(&padded);
    assert!(has_note(&p, "100 B of padding after the declared ROM"));
    assert_eq!(metadata(&p, "gb_image_size").as_deref(), Some("32868"));
    // The section is the declared ROM; the padding is not analyzed.
    assert_eq!(
        metadata(&p, "gb_section_0").as_deref(),
        Some("file 0x0; destination 0x0; 32768 B")
    );
    let mut gbx = gb(0);
    gbx.extend_from_slice(&gbx_footer());
    assert!(has_note(&classify(&gbx), "64 B GBX footer at 0x8000"));
    let mut overdump = gb(0);
    overdump.extend_from_slice(&[0x12; 40]);
    assert!(error_text(&overdump).contains("Invalid trailing data: 40 B at 0x8000"));
}

// --- NES ---------------------------------------------------------------

/// A 16-byte iNES or NES 2.0 header: magic, size LSBs (4, 5), flags 6 and
/// 7, then bytes 8-15 as given.
fn nes_header(prg: u8, chr: u8, flags6: u8, flags7: u8, rest: [u8; 8]) -> Vec<u8> {
    let mut header = b"NES\x1A".to_vec();
    header.extend_from_slice(&[prg, chr, flags6, flags7]);
    header.extend_from_slice(&rest);
    header
}

/// PRG-ROM of `size` bytes filled with 6502 code, ending with the NMI,
/// RESET (0xC000) and IRQ vectors.
fn prg_rom(size: usize) -> Vec<u8> {
    // sei; cld; ldx #$FF; txs; lda #$00; sta $2000; jmp $C00B
    let code = [
        0x78, 0xD8, 0xA2, 0xFF, 0x9A, 0xA9, 0x00, 0x8D, 0x00, 0x20, 0x4C, 0x0B, 0xC0,
    ];
    let mut prg: Vec<u8> = code.iter().copied().cycle().take(size).collect();
    let vectors = size - 6;
    prg[vectors..].copy_from_slice(&[0x00, 0xC0, 0x00, 0xC0, 0x00, 0xC0]);
    prg
}

/// An iNES NROM image: 16 KiB PRG-ROM and 8 KiB CHR-ROM (0x33 filler).
fn ines_nrom() -> Vec<u8> {
    let mut image = nes_header(1, 1, 0x01, 0x00, [0; 8]);
    image.extend_from_slice(&prg_rom(16 << 10));
    image.extend(std::iter::repeat(0x33).take(8 << 10));
    image
}

#[test]
fn ines_prg_rom_is_6502_code_and_chr_rom_is_opaque() {
    let image = ines_nrom();
    assert_eq!(layout(&image), Some(Layout::Ines));
    let p = classify(&image);
    assert_eq!(p.format.format, FileFormat::NesRom);
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::Mcs6502, 8, Endianness::Little)
    );
    let variant = Some("Ricoh 2A03 (6502 without decimal mode)");
    assert_eq!(p.primary.variant.as_ref().map(|v| v.name.as_str()), variant);
    let prg = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("PRG-ROM"))
        .expect("PRG-ROM child");
    assert_eq!(
        (prg.offset, prg.size, prg.isa),
        (16, 16 << 10, Isa::Mcs6502)
    );
    assert_eq!(prg.variant.as_ref().map(|v| v.name.as_str()), variant);
    let chr = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("CHR-ROM"))
        .expect("CHR-ROM child");
    assert_eq!((chr.offset, chr.size), (16 + (16 << 10), 8 << 10));
    assert!(matches!(chr.isa, Isa::Unknown(_)));
    assert!(has_note(
        &p,
        "CHR-ROM: opaque; payload ISA analysis skipped"
    ));
    assert!(has_note(&p, "Entry is the reset vector 0xC000"));
    assert_eq!(metadata(&p, "nes_mapper").as_deref(), Some("0"));
}

#[test]
fn nes20_exponent_sizes_trainer_mapper_and_console_types() {
    // PRG 2^8 * 1 = 256 B and CHR 2^8 * 3 = 768 B in exponent form (MSB
    // nibbles 0xF); flags 6: trainer, mapper low nibble 3; flags 7: NES
    // 2.0, mapper bits 4-7 = 2, console type 3; byte 8: mapper bits 8-11
    // = 1, submapper 5; byte 13: extended console type 0x3.
    let header = nes_header(0x20, 0x21, 0x34, 0x2B, [0x51, 0xFF, 0, 0, 0, 0x03, 0, 0]);
    let mut image = header.clone();
    image.extend(std::iter::repeat(0xEA).take(512));
    image.extend_from_slice(&prg_rom(256));
    image.extend(std::iter::repeat(0x55).take(768));
    assert_eq!(layout(&image), Some(Layout::Nes20));
    let p = classify(&image);
    assert_eq!(
        p.primary.variant.as_ref().map(|v| v.name.as_str()),
        Some("6502 with decimal mode (famiclone)")
    );
    assert_eq!(metadata(&p, "nes_mapper").as_deref(), Some("291"));
    assert_eq!(metadata(&p, "nes_submapper").as_deref(), Some("5"));
    assert_eq!(metadata(&p, "nes_prg_rom_size").as_deref(), Some("256"));
    assert_eq!(metadata(&p, "nes_chr_rom_size").as_deref(), Some("768"));
    let trainer = p
        .slices
        .iter()
        .find(|s| s.label.as_deref() == Some("Trainer"))
        .expect("trainer child");
    assert_eq!(
        (trainer.offset, trainer.size, trainer.isa),
        (16, 512, Isa::Mcs6502)
    );
    assert!(has_note(&p, "loaded at CPU 0x7000"));

    // Console type 1 (Vs. System): 6502 family, no CPU variant claimed.
    let mut vs = image.clone();
    vs[7] = 0x29;
    vs[13] = 0x50;
    let p = classify(&vs);
    assert_eq!(p.primary.isa, Isa::Mcs6502);
    assert_eq!(p.primary.variant, None);
    assert!(has_note(&p, "Console type Vs. System; Vs. Dual System"));
    // Extended console type 0x7 (VT03): famiclone, no CPU variant.
    let mut vt03 = image.clone();
    vt03[13] = 0x07;
    let p = classify(&vt03);
    assert_eq!(p.primary.variant, None);
    assert!(has_note(&p, "V.R. Technology VT03"));
    // PAL timing on a standard console: the RP2A07.
    let mut pal = image.clone();
    pal[7] = 0x28;
    pal[12] = 0x01;
    assert_eq!(
        classify(&pal)
            .primary
            .variant
            .as_ref()
            .map(|v| v.name.as_str()),
        Some("Ricoh 2A07 (6502 without decimal mode)")
    );
}

#[test]
fn nes_sizes_trailers_and_unclean_headers() {
    let image = ines_nrom();
    assert!(error_text(&image[..16 + 100]).contains("Truncated PRG-ROM"));
    assert!(error_text(&image[..image.len() - 1]).contains("Truncated CHR-ROM"));
    let mut padded = image.clone();
    padded.extend(std::iter::repeat(0xFF).take(1000));
    assert!(parse(&padded).is_ok());
    let mut titled = image.clone();
    titled.extend(
        b"ZRAX TITLE"
            .iter()
            .copied()
            .chain(std::iter::repeat(0))
            .take(128),
    );
    let p = classify(&titled);
    assert_eq!(
        metadata(&p, "nes_trailer_title").as_deref(),
        Some("ZRAX TITLE")
    );
    let mut junk = image.clone();
    junk.extend_from_slice(&[0x12; 40]);
    assert!(error_text(&junk).contains("Invalid trailing data: 40 B"));
    let mut no_prg = image.clone();
    no_prg[4] = 0;
    assert!(error_text(&no_prg).contains("Missing PRG-ROM"));
    // Text from an old tool in bytes 7-15 (`DiskDude!`): the upper mapper
    // nibble and flags 7 are ignored.
    let mut disk_dude = image.clone();
    disk_dude[6] = 0x11;
    disk_dude[7..16].copy_from_slice(b"DiskDude!");
    let p = classify(&disk_dude);
    assert_eq!(metadata(&p, "nes_mapper").as_deref(), Some("1"));
    assert!(has_note(&p, "Archaic iNES or iNES 0.7 header"));
    // NES 2.0 sizes that exceed the file fall back to iNES, as NESdev
    // recommends; the iNES sizes are then checked.
    let mut oversized = image.clone();
    oversized[7] = 0x08;
    oversized[9] = 0x01;
    assert_eq!(layout(&oversized), Some(Layout::Ines));
}

#[test]
fn ines_playchoice_rom_lists_inst_rom_and_prom_as_data() {
    let mut image = ines_nrom();
    image[7] = 0x02;
    image.extend(std::iter::repeat(0x20).take(8 << 10));
    image.extend_from_slice(&[0x01; 32]);
    let p = classify(&image);
    assert!(has_note(&p, "Console type PlayChoice-10"));
    assert_eq!(p.primary.variant, None);
    for label in ["PlayChoice-10 INST-ROM", "PlayChoice-10 PROM"] {
        let slice = p
            .slices
            .iter()
            .find(|s| s.label.as_deref() == Some(label))
            .unwrap_or_else(|| panic!("{label}"));
        assert!(matches!(slice.isa, Isa::Unknown(_)));
    }
}

// --- SNES --------------------------------------------------------------

/// The SNES checksum: 16-bit byte sum with the part after the largest power
/// of two zero-padded to a power of two and repeated (SNESdev).
fn snes_checksum(rom: &[u8]) -> u16 {
    let sum = |bytes: &[u8]| bytes.iter().map(|&b| u64::from(b)).sum::<u64>();
    let mut base = 1usize;
    while base * 2 <= rom.len() {
        base *= 2;
    }
    let mut total = sum(&rom[..base]);
    let rest = &rom[base..];
    if !rest.is_empty() {
        let mut padded = 1usize;
        while padded < rest.len() {
            padded *= 2;
        }
        total += sum(rest) * (base / padded) as u64;
    }
    (total & 0xFFFF) as u16
}

/// Write an internal header at ROM offset `at`: title, map mode, chipset
/// ROM+RAM, ROM size byte, RAM size 32 KiB, region North America,
/// developer 0x01, version 0, checksum 0 and complement 0xFFFF, and the
/// emulation-mode reset vector.
fn snes_header(rom: &mut [u8], at: usize, map_mode: u8, reset: u16) {
    let mut title = [b' '; 21];
    title[..9].copy_from_slice(b"ZRAX TEST");
    rom[at..at + 21].copy_from_slice(&title);
    rom[at + 0x15] = map_mode;
    rom[at + 0x16] = 0x01;
    rom[at + 0x17] = 0x08;
    rom[at + 0x18] = 0x05;
    rom[at + 0x19] = 0x01;
    rom[at + 0x1A] = 0x01;
    rom[at + 0x1B] = 0x00;
    put_le16(rom, at + 0x1C, 0xFFFF);
    put_le16(rom, at + 0x1E, 0x0000);
    put_le16(rom, at + 0x3C, reset);
}

/// Store the ROM checksum and complement in every header at `headers`;
/// each pair sums to the same byte total, so one sum serves all of them.
fn seal_snes(rom: &mut [u8], headers: &[usize]) {
    let checksum = snes_checksum(rom);
    for &at in headers {
        put_le16(rom, at + 0x1C, !checksum);
        put_le16(rom, at + 0x1E, checksum);
    }
}

/// A ROM of `size` bytes with 65816 code at `code_offset` (where the reset
/// vector points) and one header.
fn snes(size: usize, header: usize, map_mode: u8, reset: u16, code_offset: usize) -> Vec<u8> {
    let mut rom = vec![0u8; size];
    // sei; clc; xce; rep #$30; lda #$1234; sta $2100; bra -
    let code = [
        0x78, 0x18, 0xFB, 0xC2, 0x30, 0xA9, 0x34, 0x12, 0x8D, 0x00, 0x21, 0x80, 0xFE,
    ];
    for (i, b) in rom[code_offset..code_offset + 0x1000]
        .iter_mut()
        .enumerate()
    {
        *b = code[i % code.len()];
    }
    snes_header(&mut rom, header, map_mode, reset);
    seal_snes(&mut rom, &[header]);
    rom
}

fn lorom() -> Vec<u8> {
    snes(0x8000, 0x7FC0, 0x20, 0x8000, 0x0000)
}

#[test]
fn snes_lorom_hirom_and_copier_header_layouts() {
    let rom = lorom();
    assert_eq!(
        layout(&rom),
        Some(Layout::Snes {
            mapping: SnesMapping::LoRom,
            copier_header: false
        })
    );
    let p = classify(&rom);
    assert_eq!(p.format.format, FileFormat::SnesRom);
    assert_eq!(p.format.variant_name.as_deref(), Some("SNES LoROM"));
    assert_eq!(
        (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
        (Isa::W65816, 16, Endianness::Little)
    );
    assert_eq!(
        p.primary.variant.as_ref().map(|v| v.name.as_str()),
        Some("65C816 (Ricoh 5A22)")
    );
    assert!(has_note(&p, "no 65816 class"));
    assert!(has_note(&p, "reset vector 0x8000"));
    assert_eq!(metadata(&p, "snes_title").as_deref(), Some("ZRAX TEST"));
    assert_eq!(
        metadata(&p, "snes_region").as_deref(),
        Some("North America")
    );

    let hirom = snes(0x1_0000, 0xFFC0, 0x31, 0x8000, 0x8000);
    assert_eq!(
        layout(&hirom),
        Some(Layout::Snes {
            mapping: SnesMapping::HiRom,
            copier_header: false
        })
    );
    let mut copier = vec![0u8; 0x200];
    copier.extend_from_slice(&rom);
    assert_eq!(
        layout(&copier),
        Some(Layout::Snes {
            mapping: SnesMapping::LoRom,
            copier_header: true
        })
    );
    let c = parse(&copier).expect("headered LoROM");
    assert_eq!(
        (c.sections[0].offset, c.sections[0].data.len()),
        (0x200, 0x8000)
    );
}

#[test]
fn snes_exhirom_header_and_mirrored_checksum() {
    // 4 MiB + 64 KiB: the last 64 KiB count 64 times in the checksum.
    let rom = snes(0x41_0000, 0x40_FFC0, 0x35, 0x8000, 0x40_8000);
    assert_eq!(
        layout(&rom),
        Some(Layout::Snes {
            mapping: SnesMapping::ExHiRom,
            copier_header: false
        })
    );
    let c = parse(&rom).expect("ExHiROM");
    assert_eq!(c.entry, Some(0x8000));
}

#[test]
fn snes_needs_every_header_check_to_pass() {
    let rom = lorom();
    let header = 0x7FC0;
    let corruptions: [(&str, usize, u8); 5] = [
        ("checksum", header + 0x1E, 0x01),
        ("complement", header + 0x1C, 0x01),
        (
            "map mode (HiROM at the LoROM location)",
            header + 0x15,
            0x01,
        ),
        ("title", header + 3, 0x80),
        ("ROM byte", 0x100, 0x01),
    ];
    for (what, at, flip) in corruptions {
        let mut bad = rom.clone();
        bad[at] ^= flip;
        assert_eq!(layout(&bad), None, "{what}");
    }
    // A reset vector below 0x8000 is not in the ROM of bank 0x00.
    let low_reset = snes(0x8000, header, 0x20, 0x7000, 0);
    assert_eq!(layout(&low_reset), None);
    // Too short for the LoROM header.
    assert_eq!(layout(&rom[..0x7FF0]), None);
}

#[test]
fn snes_headers_valid_at_two_locations_are_ambiguous() {
    let mut rom = vec![0u8; 0x1_0000];
    snes_header(&mut rom, 0x7FC0, 0x20, 0x8000);
    snes_header(&mut rom, 0xFFC0, 0x21, 0x8000);
    seal_snes(&mut rom, &[0x7FC0, 0xFFC0]);
    assert_eq!(layout(&rom), Some(Layout::SnesAmbiguous));
    let p = classify(&rom);
    assert_eq!(p.format.format, FileFormat::SnesRom);
    assert!(matches!(p.primary.isa, Isa::Unknown(_)));
    assert_eq!(p.primary.confidence, 0.0);
    assert!(p.slices.is_empty() && p.candidates.is_empty());
    assert!(has_note(&p, "Ambiguous internal header"));
}

// --- Nintendo 64 -------------------------------------------------------

fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (i, entry) in table.iter_mut().enumerate() {
        let mut crc = i as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
        *entry = crc;
    }
    table
}

/// Fill the last 4 bytes of `block` so that its IEEE CRC-32 is `target`:
/// walk the table back from the final register to find the four table
/// indices, then choose the bytes that produce them from the register
/// after the prefix.
fn forge_crc32(block: &mut [u8], target: u32) {
    let table = crc32_table();
    let prefix = block.len() - 4;
    let mut register = !target;
    let mut indices = [0u8; 4];
    for k in (0..4).rev() {
        let index = (0..256)
            .find(|&i| table[i] >> 24 == register >> 24)
            .expect("CRC-32 table top bytes are unique");
        indices[k] = index as u8;
        register = (register ^ table[index]) << 8;
    }
    let mut register = zrax::formats::checksum::crc32_update(!0, &block[..prefix]);
    for (k, &index) in indices.iter().enumerate() {
        block[prefix + k] = (register as u8) ^ index;
        register = (register >> 8) ^ table[usize::from(index)];
    }
    assert_eq!(zrax::formats::checksum::crc32(block), target);
}

/// How a CIC's check code combines the accumulators (n64crc.c).
#[derive(Clone, Copy)]
enum Mix {
    /// `crc1 = t6 ^ t4 ^ t3; crc2 = t5 ^ t2 ^ t1`.
    Xor,
    /// 6103: `crc1 = (t6 ^ t4) + t3; crc2 = (t5 ^ t2) + t1`.
    Add,
    /// 6106: `crc1 = t6 * t4 + t3; crc2 = t5 * t2 + t1`.
    Multiply,
}

/// A CIC as n64crc.c identifies it: the CRC-32 of IPL3 (ROM 0x40-0xFFF),
/// its name in the notes, the seed, the final mix, and whether `t1` mixes
/// in IPL3 words instead of `t5` (6105).
struct TestCic {
    ipl3_crc32: u32,
    name: &'static str,
    seed: u32,
    mix: Mix,
    ipl3_table: bool,
}

const CIC_6102: TestCic = TestCic {
    ipl3_crc32: 0x90BB_6CB5,
    name: "6102/7101",
    seed: 0xF8CA_4DDC,
    mix: Mix::Xor,
    ipl3_table: false,
};

const CIC_6103: TestCic = TestCic {
    ipl3_crc32: 0x0B05_0EE0,
    name: "6103/7103",
    seed: 0xA388_6759,
    mix: Mix::Add,
    ipl3_table: false,
};

const CIC_6105: TestCic = TestCic {
    ipl3_crc32: 0x98BC_2C86,
    name: "6105/7105",
    seed: 0xDF26_F436,
    mix: Mix::Xor,
    ipl3_table: true,
};

const CIC_6106: TestCic = TestCic {
    ipl3_crc32: 0xACC8_580A,
    name: "6106/7106",
    seed: 0x1FEA_617A,
    mix: Mix::Multiply,
    ipl3_table: false,
};

/// The N64 check code over native ROM 0x1000-0x100FFF, following the
/// n64crc.c pseudo-code in the spec notes word by word.
fn n64_check_code(rom: &[u8], cic: &TestCic) -> (u32, u32) {
    let be32 = |at: usize| u32::from_be_bytes([rom[at], rom[at + 1], rom[at + 2], rom[at + 3]]);
    let [mut t1, mut t2, mut t3, mut t4, mut t5, mut t6] = [cic.seed; 6];
    for i in (0x1000..0x10_1000).step_by(4) {
        let d = be32(i);
        if t6.wrapping_add(d) < t6 {
            t4 = t4.wrapping_add(1);
        }
        t6 = t6.wrapping_add(d);
        t3 ^= d;
        let r = d.rotate_left(d & 0x1F);
        t5 = t5.wrapping_add(r);
        if t2 > d {
            t2 ^= r;
        } else {
            t2 ^= t6 ^ d;
        }
        if cic.ipl3_table {
            t1 = t1.wrapping_add(be32(0x40 + 0x0710 + (i & 0xFF)) ^ d);
        } else {
            t1 = t1.wrapping_add(t5 ^ d);
        }
    }
    match cic.mix {
        Mix::Xor => (t6 ^ t4 ^ t3, t5 ^ t2 ^ t1),
        Mix::Add => ((t6 ^ t4).wrapping_add(t3), (t5 ^ t2).wrapping_add(t1)),
        Mix::Multiply => (
            t6.wrapping_mul(t4).wrapping_add(t3),
            t5.wrapping_mul(t2).wrapping_add(t1),
        ),
    }
}

/// A native (.z64) ROM of `size` bytes: first word `80 37 12 40`, clock
/// rate 0x0000000F, boot address, libultra 2.0L, title, game code `NZRE`,
/// version 0; IPL3 filler (0x40-0xFFF) with CRC-32 `ipl3_crc32` when
/// given; MIPS code repeated from 0x1000.
fn z64(size: usize, boot_address: u32, ipl3_crc32: Option<u32>) -> Vec<u8> {
    let mut rom = vec![0u8; size];
    rom[..4].copy_from_slice(&[0x80, 0x37, 0x12, 0x40]);
    put_be32(&mut rom, 0x04, 0x0000_000F);
    put_be32(&mut rom, 0x08, boot_address);
    rom[0x0C..0x10].copy_from_slice(&[0, 0, 0x14, b'L']);
    let mut title = [b' '; 20];
    title[..9].copy_from_slice(b"ZRAX TEST");
    rom[0x20..0x34].copy_from_slice(&title);
    rom[0x3B..0x3F].copy_from_slice(b"NZRE");
    for (i, b) in rom[0x40..0x1000].iter_mut().enumerate() {
        *b = (i * 7) as u8;
    }
    if let Some(target) = ipl3_crc32 {
        forge_crc32(&mut rom[0x40..0x1000], target);
    }
    let code = mips_code();
    for (i, b) in rom[0x1000..].iter_mut().enumerate() {
        *b = code[i % code.len()];
    }
    rom
}

/// Store the check code (CRC1 at 0x10, CRC2 at 0x14).
fn seal_n64(rom: &mut [u8], cic: &TestCic) {
    let (crc1, crc2) = n64_check_code(rom, cic);
    put_be32(rom, 0x10, crc1);
    put_be32(rom, 0x14, crc2);
}

/// `.v64`: bytes swapped within each 16-bit halfword.
fn v64(native: &[u8]) -> Vec<u8> {
    native.chunks_exact(2).flat_map(|h| [h[1], h[0]]).collect()
}

/// `.n64`: bytes reversed within each 32-bit word.
fn n64(native: &[u8]) -> Vec<u8> {
    native
        .chunks_exact(4)
        .flat_map(|w| [w[3], w[2], w[1], w[0]])
        .collect()
}

#[test]
fn n64_byte_orders_normalize_to_the_same_code_sections() {
    let native = z64(0x3000, 0x8000_0400, None);
    let orders = [
        (
            native.clone(),
            N64ByteOrder::Native,
            "N64 native byte order (.z64)",
        ),
        (
            v64(&native),
            N64ByteOrder::ByteSwapped,
            "N64 byte-swapped (.v64)",
        ),
        (
            n64(&native),
            N64ByteOrder::WordSwapped,
            "N64 word-swapped (.n64)",
        ),
    ];
    for (image, order, label) in &orders {
        assert_eq!(layout(image), Some(Layout::N64(*order)));
        let c = parse(image).expect("N64 ROM");
        assert_eq!(c.sections.len(), 2);
        assert_eq!(&*c.sections[0].data, &native[0x40..0x1000], "{label} IPL3");
        assert_eq!(&*c.sections[1].data, &native[0x1000..], "{label} game code");
        assert_eq!(c.sections[1].offset, 0x1000);
        assert_eq!(c.sections[1].address, 0x8000_0400);
        let swapped = *order != N64ByteOrder::Native;
        assert_eq!(c.sections[1].transform.is_some(), swapped);
        let p = classify(image);
        assert_eq!(p.format.format, FileFormat::N64Rom);
        assert_eq!(p.format.variant_name.as_deref(), Some(*label));
        assert_eq!(
            (p.primary.isa, p.primary.bitwidth, p.primary.endianness),
            (Isa::Mips64, 64, Endianness::Big)
        );
        assert_eq!(
            p.primary.variant.as_ref().map(|v| v.name.as_str()),
            Some("VR4300 (MIPS III)")
        );
        assert_eq!(metadata(&p, "n64_title").as_deref(), Some("ZRAX TEST"));
        assert_eq!(metadata(&p, "n64_game_code").as_deref(), Some("NZRE"));
        assert_eq!(
            metadata(&p, "n64_libultra_version").as_deref(),
            Some("2.0L")
        );
        assert!(has_note(&p, "matches no known CIC"));
        if swapped {
            assert_eq!(
                metadata(&p, "n64_section_1").as_deref(),
                Some("file 0x1000; destination 0x80000400; 8192 B stored; 8192 B decoded (N64 byte swap)")
            );
        }
    }
}

#[test]
fn n64_check_code_is_verified_for_an_identified_cic() {
    let mut rom = z64(0x10_1000, 0x8000_0400, Some(CIC_6102.ipl3_crc32));
    seal_n64(&mut rom, &CIC_6102);
    let p = classify(&rom);
    assert!(has_note(&p, "CIC 6102/7101 IPL3; check code"));
    assert!(has_note(&p, "verified over 0x1000-0x100FFF"));
    assert_eq!(metadata(&p, "n64_cic").as_deref(), Some("6102/7101"));
    let swapped = classify(&v64(&rom));
    assert!(has_note(&swapped, "verified over 0x1000-0x100FFF"));
    let mut corrupt = rom.clone();
    corrupt[0x2000] ^= 0x01;
    assert!(has_note(&classify(&corrupt), "does not match the computed"));
    // A short ROM cannot be checked.
    let short = z64(0x2000, 0x8000_0400, Some(CIC_6102.ipl3_crc32));
    assert!(has_note(&classify(&short), "is not verified"));
}

#[test]
fn n64_check_code_follows_each_cic_seed_and_mix() {
    // 6105 mixes IPL3 words into `t1`, and 6106 multiplies; the entry is
    // the boot address less the IPL3 adjustment (6106: 0x200000).
    let cases = [
        (&CIC_6105, 0x8000_0400, 0x8000_0400),
        (&CIC_6106, 0x8020_0400, 0x8000_0400),
    ];
    for (cic, boot_address, entry) in cases {
        let mut rom = z64(0x10_1000, boot_address, Some(cic.ipl3_crc32));
        seal_n64(&mut rom, cic);
        let p = classify(&rom);
        let name = cic.name;
        assert!(
            has_note(&p, &format!("CIC {name} IPL3; check code")),
            "{name}"
        );
        assert!(has_note(&p, "verified over 0x1000-0x100FFF"), "{name}");
        assert_eq!(p.primary.isa, Isa::Mips64);
        let c = parse(&rom).expect("N64 ROM");
        assert_eq!(c.entry, Some(entry), "{name}");
        if cic.ipl3_table {
            // A changed IPL3 word in the 6105 table changes the check code.
            let mut table = rom.clone();
            table[0x40 + 0x710] ^= 0x01;
            forge_crc32(&mut table[0x40..0x1000], cic.ipl3_crc32);
            assert!(has_note(&classify(&table), "does not match the computed"));
        }
    }
}

#[test]
fn n64_cic_6103_moves_the_entry_below_the_boot_address() {
    let mut rom = z64(0x10_1000, 0x8010_0400, Some(CIC_6103.ipl3_crc32));
    seal_n64(&mut rom, &CIC_6103);
    let p = classify(&rom);
    assert!(has_note(&p, "CIC 6103/7103 IPL3; check code"));
    assert!(has_note(&p, "verified"));
    assert!(has_note(
        &p,
        "Entry 0x80000400: the CIC 6103/7103 IPL3 subtracts 0x100000"
    ));
    let c = parse(&rom).expect("N64 ROM");
    assert_eq!(c.entry, Some(0x8000_0400));
}

#[test]
fn n64_sizes_and_signatures_are_checked() {
    let native = z64(0x2000, 0x8000_0400, None);
    let mut odd = v64(&native);
    odd.push(0);
    assert!(error_text(&odd).contains("Invalid ROM size 8193 B"));
    assert!(error_text(&native[..0x1000]).contains("Missing game code"));
    assert!(error_text(&native[..0x800]).contains("Truncated IPL3"));
    let mut no_clock_nibble = native.clone();
    no_clock_nibble[7] = 0x00;
    assert_eq!(layout(&no_clock_nibble), None);
}

// --- Sweeps ------------------------------------------------------------

/// Small fixtures of every layout, with their header sizes.
fn sweep_fixtures() -> Vec<(Vec<u8>, usize)> {
    let code = arm_code();
    let small = |offset, address| NdsBinary {
        offset,
        entry: address,
        ram_address: address,
        bytes: &code[..0x100],
    };
    let small_nds = nds(
        0x400,
        0,
        &small(0x200, 0x0200_0000),
        &small(0x300, 0x037F_8000),
    );
    // NES 2.0 with 256-byte PRG-ROM and CHR-ROM in exponent form.
    let mut tiny_nes = nes_header(0x20, 0x20, 0x00, 0x08, [0, 0xFF, 0, 0, 0, 0, 0, 0]);
    tiny_nes.extend_from_slice(&prg_rom(256));
    tiny_nes.extend_from_slice(&[0x11; 256]);
    let native = z64(0x1040, 0x8000_0400, None);
    vec![
        (small_nds, 0x200),
        (dsi_nds(), 0x300),
        (gba(&code[..256], true), 0xC0),
        (tiny_nes, 0x10),
        (v64(&native), 0x40),
        (n64(&native), 0x40),
        (native, 0x40),
    ]
}

#[test]
fn every_prefix_of_a_sized_image_is_an_error() {
    for image in [homebrew_nds(), ines_nrom(), gb(0x80)] {
        for end in 0..image.len() {
            let prefix = &image[..end];
            if let Some(found) = layout(prefix) {
                let kind = container::Kind::Nintendo(found);
                assert!(container::parse(prefix, kind).is_err(), "prefix {end}");
            }
        }
    }
    let rom = lorom();
    for end in 0..rom.len() {
        assert_eq!(layout(&rom[..end]), None, "SNES prefix {end}");
    }
}

#[test]
fn nintendo_roms_survive_truncation_and_mutation() {
    for (image, header_size) in sweep_fixtures() {
        for end in 0..image.len() {
            let _ = detect_payload(&image[..end], &ClassifierOptions::new());
        }
        for i in 0..image.len() {
            for value in [0x00, 0xFF, image[i] ^ 0x01] {
                let mut mutated = image.clone();
                mutated[i] = value;
                if let Some(found) = layout(&mutated) {
                    let _ = container::parse(&mutated, container::Kind::Nintendo(found));
                }
                // The whole classifier on the header, the last 64 bytes and
                // every 64th byte between them.
                if i < header_size || i % 64 == 0 || i + 64 >= image.len() {
                    let _ = detect_payload(&mutated, &ClassifierOptions::new());
                }
            }
        }
    }
    // Large images: the header bytes and a stride of the rest through the
    // parser, the header bytes once through the whole classifier. A SNES
    // mutation outside the header usually fails the checksum and then runs
    // every other detector, so its stride is wider.
    for (image, header, stride) in [(gb(0x80), 0x100..0x150, 7), (lorom(), 0x7FC0..0x8000, 257)] {
        for i in (0..image.len()).filter(|i| header.contains(i) || i % stride == 0) {
            for value in [0x00, 0xFF, image[i] ^ 0x01] {
                let mut mutated = image.clone();
                mutated[i] = value;
                if let Some(found) = layout(&mutated) {
                    let _ = container::parse(&mutated, container::Kind::Nintendo(found));
                }
            }
        }
        for i in header {
            let mut mutated = image.clone();
            mutated[i] ^= 0xFF;
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}
