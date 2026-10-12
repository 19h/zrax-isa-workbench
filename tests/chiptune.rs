//! Chiptune program files: NSF and NSFe (NES 6502), PSID/RSID (C64 6510)
//! and GBS (Game Boy SM83) name their platform's CPU, place the driver at
//! its load address, and reject inconsistent headers.

use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

/// A short 6502 driver: LDA #$00, STA $4015, LDX #$0F, loop DEX/BNE, RTS.
const DRIVER_6502: &[u8] = &[
    0xa9, 0x00, 0x8d, 0x15, 0x40, 0xa2, 0x0f, 0xca, 0xd0, 0xfd, 0x60,
];

/// A short SM83 driver: LD A,$80; LDH ($26),A; RET.
const DRIVER_SM83: &[u8] = &[0x3e, 0x80, 0xe0, 0x26, 0xc9];

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

fn text_field(text: &str) -> [u8; 32] {
    let mut field = [0u8; 32];
    field[..text.len()].copy_from_slice(text.as_bytes());
    field
}

/// NSF: `NESM\x1A`, version, songs, start song, load/init/play (LE), title,
/// artist and copyright fields, speeds, bank values, region, chips, NSF2
/// fields; program data at 0x80.
fn nsf(version: u8, load: u16, program: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 0x80];
    data[..5].copy_from_slice(b"NESM\x1a");
    data[5] = version;
    data[6] = 3;
    data[7] = 1;
    data[8..10].copy_from_slice(&load.to_le_bytes());
    data[10..12].copy_from_slice(&load.to_le_bytes());
    data[12..14].copy_from_slice(&(load + 5).to_le_bytes());
    data[0x0e..0x2e].copy_from_slice(&text_field("Test Tune"));
    data[0x2e..0x4e].copy_from_slice(&text_field("Composer"));
    data.extend_from_slice(program);
    data
}

/// NSFe: `NSFE`, then `INFO` (load, init, play, region, chips, songs,
/// start), `DATA` and `NEND` chunks, each a little-endian length and an ID.
fn nsfe(load: u16, program: &[u8]) -> Vec<u8> {
    let chunk = |data: &mut Vec<u8>, id: &[u8; 4], body: &[u8]| {
        data.extend_from_slice(&(body.len() as u32).to_le_bytes());
        data.extend_from_slice(id);
        data.extend_from_slice(body);
    };
    let mut info = Vec::new();
    info.extend_from_slice(&load.to_le_bytes());
    info.extend_from_slice(&load.to_le_bytes());
    info.extend_from_slice(&(load + 5).to_le_bytes());
    info.extend_from_slice(&[0, 0, 2, 0]);
    let mut data = b"NSFE".to_vec();
    chunk(&mut data, b"INFO", &info);
    chunk(&mut data, b"auth", b"Tune\0Composer\0\0\0");
    chunk(&mut data, b"DATA", program);
    chunk(&mut data, b"NEND", &[]);
    data
}

/// PSID/RSID v2: magic, version, data offset 0x7C, load address (0: in the
/// data), init, play, songs, start song, speed, name/author/released,
/// flags; the program follows, prefixed by its load address when the header
/// leaves it 0.
fn sid(magic: &[u8; 4], header_load: u16, flags: u16, program: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 0x7c];
    data[..4].copy_from_slice(magic);
    data[4..6].copy_from_slice(&2u16.to_be_bytes());
    data[6..8].copy_from_slice(&0x7cu16.to_be_bytes());
    data[8..10].copy_from_slice(&header_load.to_be_bytes());
    data[10..12].copy_from_slice(&0x1000u16.to_be_bytes());
    data[12..14].copy_from_slice(&0x1003u16.to_be_bytes());
    data[14..16].copy_from_slice(&1u16.to_be_bytes());
    data[16..18].copy_from_slice(&1u16.to_be_bytes());
    data[0x16..0x36].copy_from_slice(&text_field("Commando"));
    data[0x36..0x56].copy_from_slice(&text_field("Hubbard"));
    data[0x76..0x78].copy_from_slice(&flags.to_be_bytes());
    if header_load == 0 {
        data.extend_from_slice(&0x1000u16.to_le_bytes());
    }
    data.extend_from_slice(program);
    data
}

/// GBS: `GBS`, version 1, songs, first song, load/init/play/stack (LE),
/// timer, title/author/copyright; code at 0x70.
fn gbs(load: u16, program: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 0x70];
    data[..4].copy_from_slice(b"GBS\x01");
    data[4] = 2;
    data[5] = 1;
    data[6..8].copy_from_slice(&load.to_le_bytes());
    data[8..10].copy_from_slice(&load.to_le_bytes());
    data[10..12].copy_from_slice(&(load + 2).to_le_bytes());
    data[12..14].copy_from_slice(&0xfffeu16.to_le_bytes());
    data[0x10..0x30].copy_from_slice(&text_field("Overworld"));
    data.extend_from_slice(program);
    data
}

#[test]
fn nsf_names_the_nes_cpu_and_places_its_driver() {
    for file in [nsf(1, 0x8000, DRIVER_6502), nsfe(0x8000, DRIVER_6502)] {
        let p = classify(&file);
        assert_eq!(p.format.format, FileFormat::Nsf);
        assert_eq!((p.primary.isa, p.primary.bitwidth), (Isa::Mcs6502, 8));
        assert!(p.notes.iter().any(|n| n.message.contains("Ricoh 2A03")));
        assert!(p
            .metadata
            .iter()
            .any(|m| m.label == "Program" && m.value.to_string().contains("destination 0x8000")));
    }
    let p = classify(&nsfe(0x8000, DRIVER_6502));
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.starts_with("Credits: Tune")));
}

#[test]
fn nsf_headers_with_bad_songs_or_addresses_are_errors() {
    let mut bad_song = nsf(1, 0x8000, DRIVER_6502);
    bad_song[7] = 9;
    assert!(detect_payload(&bad_song, &ClassifierOptions::new())
        .map_or(true, |p| p.format.format != FileFormat::Nsf));
    let low_load = nsf(1, 0x0200, DRIVER_6502);
    assert!(detect_payload(&low_load, &ClassifierOptions::new())
        .map_or(true, |p| p.format.format != FileFormat::Nsf));
}

#[test]
fn sid_tunes_take_the_load_address_from_header_or_data() {
    let in_data = classify(&sid(b"PSID", 0, 0, DRIVER_6502));
    assert_eq!(in_data.format.format, FileFormat::Sid);
    assert_eq!(in_data.primary.isa, Isa::Mcs6502);
    assert!(in_data
        .notes
        .iter()
        .any(|n| n.message.contains("MOS 6510 driver loaded at 0x1000")));
    let in_header = classify(&sid(b"PSID", 0x1000, 0, DRIVER_6502));
    assert_eq!(in_header.primary.isa, Isa::Mcs6502);
    // RSID requires the load address in the data.
    let rsid_header_load = sid(b"RSID", 0x1000, 0, DRIVER_6502);
    assert!(detect_payload(&rsid_header_load, &ClassifierOptions::new())
        .map_or(true, |p| p.format.format != FileFormat::Sid));
}

#[test]
fn basic_and_mus_sid_programs_are_not_code() {
    for file in [
        sid(b"RSID", 0, 0x0002, b"10 PRINT"),
        sid(b"PSID", 0, 0x0001, &[0; 32]),
    ] {
        let p = classify(&file);
        assert_eq!(p.format.format, FileFormat::Sid);
        assert!(p.candidates.is_empty());
        assert!(p
            .notes
            .iter()
            .any(|n| n.message.contains("not machine code")));
    }
}

#[test]
fn gbs_names_the_game_boy_cpu() {
    let p = classify(&gbs(0x0400, DRIVER_SM83));
    assert_eq!(p.format.format, FileFormat::Gbs);
    assert_eq!(p.primary.isa, Isa::Z80);
    assert!(p.notes.iter().any(|n| n.message.contains("Sharp SM83")));
    let outside_rom = gbs(0x8000, DRIVER_SM83);
    assert!(detect_payload(&outside_rom, &ClassifierOptions::new())
        .map_or(true, |p| p.format.format != FileFormat::Gbs));
}

#[test]
fn chiptune_files_survive_truncation_and_mutation() {
    let fixtures = [
        nsf(2, 0x8000, DRIVER_6502),
        nsfe(0x8000, DRIVER_6502),
        sid(b"PSID", 0, 0, DRIVER_6502),
        gbs(0x0400, DRIVER_SM83),
    ];
    for file in &fixtures {
        for end in 0..file.len() {
            let _ = detect_payload(&file[..end], &ClassifierOptions::new());
        }
        for i in 0..file.len() {
            for value in [0x00, 0xff, file[i] ^ 0x01] {
                let mut mutated = file.clone();
                mutated[i] = value;
                let _ = detect_payload(&mutated, &ClassifierOptions::new());
            }
        }
    }
}
