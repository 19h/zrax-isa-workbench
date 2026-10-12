//! ZX Spectrum tapes: TZX blocks and TAP files carry ROM tape blocks;
//! `Bytes` data become Z80 load sections at their load address, BASIC
//! programs are not machine code, and TAP needs every checksum to count.

use zrax::{detect_payload, ClassifierOptions, DetectionPayload, FileFormat, Isa};

/// A short Z80 routine: LD HL,$4000; LD (HL),$FF; INC HL; LD A,H; CP $58;
/// JR NZ,-7; RET.
const CODE: &[u8] = &[
    0x21, 0x00, 0x40, 0x36, 0xff, 0x23, 0x7c, 0xfe, 0x58, 0x20, 0xf8, 0xc9,
];

/// A ROM tape block: flag, data, XOR checksum.
fn rom_block(flag: u8, data: &[u8]) -> Vec<u8> {
    let mut block = vec![flag];
    block.extend_from_slice(data);
    block.push(block.iter().fold(0u8, |x, b| x ^ b));
    block
}

/// A ROM header block: type, 10-byte name, data length, two parameters.
fn header(kind: u8, name: &str, length: u16, start: u16) -> Vec<u8> {
    let mut data = vec![kind];
    let mut padded = [b' '; 10];
    padded[..name.len()].copy_from_slice(name.as_bytes());
    data.extend_from_slice(&padded);
    data.extend_from_slice(&length.to_le_bytes());
    data.extend_from_slice(&start.to_le_bytes());
    data.extend_from_slice(&32768u16.to_le_bytes());
    rom_block(0x00, &data)
}

/// TAP: each block preceded by its little-endian length.
fn tap(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for block in blocks {
        out.extend_from_slice(&(block.len() as u16).to_le_bytes());
        out.extend_from_slice(block);
    }
    out
}

/// TZX version 1.20: standard-speed blocks (ID 0x10: pause, length,
/// block), with a text description block (ID 0x30) first.
fn tzx(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"ZXTape!\x1a\x01\x14".to_vec();
    out.extend_from_slice(&[0x30, 4]);
    out.extend_from_slice(b"demo");
    for block in blocks {
        out.push(0x10);
        out.extend_from_slice(&1000u16.to_le_bytes());
        out.extend_from_slice(&(block.len() as u16).to_le_bytes());
        out.extend_from_slice(block);
    }
    out
}

fn code_tape() -> Vec<Vec<u8>> {
    vec![
        header(0, "loader", 10, 10),
        rom_block(0xff, b"10 RANDOMIZE USR 32768"),
        header(3, "screen", CODE.len() as u16, 0x8000),
        rom_block(0xff, CODE),
    ]
}

fn classify(data: &[u8]) -> DetectionPayload {
    detect_payload(data, &ClassifierOptions::new()).expect("classifies")
}

#[test]
fn tzx_code_blocks_load_at_their_address() {
    let p = classify(&tzx(&code_tape()));
    assert_eq!(p.format.format, FileFormat::ZxTape);
    assert_eq!(p.primary.isa, Isa::Z80);
    assert!(p
        .metadata
        .iter()
        .any(|m| m.label == "Bytes \"screen\" at 0x8000"));
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("BASIC program \"loader\"")));
}

#[test]
fn tap_files_need_valid_checksums() {
    let file = tap(&code_tape());
    let p = classify(&file);
    assert_eq!(p.format.format, FileFormat::ZxTape);
    assert!(p.format.confidence < 1.0);
    let mut bad = file.clone();
    let last = bad.len() - 2;
    bad[last] ^= 1;
    if let Ok(p) = detect_payload(&bad, &ClassifierOptions::new()) {
        assert_ne!(p.format.format, FileFormat::ZxTape);
    }
}

#[test]
fn unknown_tzx_blocks_and_truncation_are_errors() {
    let mut file = tzx(&code_tape());
    file.push(0x77);
    assert!(detect_payload(&file, &ClassifierOptions::new()).is_err());
    let file = tzx(&code_tape());
    for end in 10..file.len() {
        let _ = detect_payload(&file[..end], &ClassifierOptions::new());
    }
    for i in 0..file.len() {
        let mut mutated = file.clone();
        mutated[i] ^= 0xff;
        let _ = detect_payload(&mutated, &ClassifierOptions::new());
    }
}
