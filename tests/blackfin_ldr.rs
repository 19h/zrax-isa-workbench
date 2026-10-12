//! Blackfin LDR boot streams: signed BF54x-style headers are recognized
//! from their checksum, BF53x/BF56x streams from a complete block walk, and
//! loaded blocks become sections for the Blackfin target.

use zrax::{detect_payload, ClassifierOptions, FileFormat, Isa};

const IGNORE_FIRST: u32 = 0x1000 | 0x4000;
const FILL: u32 = 0x0100;
const FINAL: u32 = 0x8000;

/// A BF54x-style block: block code (signature 0xAD, XOR check byte),
/// target address, byte count, argument; then the block's data.
fn block(code: u32, address: u32, count: u32, body: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&(code | 0xad00_0000).to_le_bytes());
    header.extend_from_slice(&address.to_le_bytes());
    header.extend_from_slice(&count.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header[2] = header.iter().fold(0u8, |x, b| x ^ b);
    header.extend_from_slice(body);
    header
}

/// One boot stream: an ignored first block, a code block, a fill block and
/// a final code block.
fn bf54x_stream() -> Vec<u8> {
    let mut data = block(IGNORE_FIRST, 0xff80_0000, 0, &[]);
    data.extend(block(
        0x1,
        0xffa0_0000,
        8,
        &[0x01, 0xe8, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00],
    ));
    data.extend(block(FILL, 0xff80_0000, 0x100, &[]));
    data.extend(block(
        FINAL | 0x1,
        0xffa0_0008,
        4,
        &[0x10, 0x00, 0x00, 0x00],
    ));
    data
}

/// A BF53x block: address, count, flags (0x8000 final), data.
fn bf53x_block(address: u32, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut out = address.to_le_bytes().to_vec();
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(body);
    out
}

#[test]
fn bf54x_streams_name_blackfin_and_list_loaded_blocks() {
    let p = detect_payload(&bf54x_stream(), &ClassifierOptions::new()).unwrap();
    assert_eq!(p.format.format, FileFormat::BlackfinLdr);
    assert_eq!(p.format.confidence, 1.0);
    assert_eq!(p.primary.isa, Isa::Blackfin);
    let sections: Vec<_> = p
        .metadata
        .iter()
        .filter(|m| m.label.starts_with("Load section"))
        .map(|m| m.value.to_string())
        .collect();
    assert_eq!(sections.len(), 2);
    assert!(sections[0].contains("destination 0xFFA00000"));
}

#[test]
fn concatenated_streams_and_padding_are_accepted() {
    let mut data = bf54x_stream();
    data.extend(bf54x_stream());
    data.extend_from_slice(&[0xff; 64]);
    let p = detect_payload(&data, &ClassifierOptions::new()).unwrap();
    assert!(p
        .notes
        .iter()
        .any(|n| n.message.contains("2 boot stream(s)")));
}

#[test]
fn bf53x_and_bf56x_streams_are_weak_detections() {
    let mut bf53x = bf53x_block(0xffa0_0000, 0, &[1, 2, 3, 4]);
    bf53x.extend(bf53x_block(0xffa0_0004, 0x8000, &[5, 6, 7, 8]));
    let p = detect_payload(&bf53x, &ClassifierOptions::new()).unwrap();
    assert_eq!(p.format.format, FileFormat::BlackfinLdr);
    assert!(p.format.confidence < 1.0);
    let mut bf56x = vec![0x00, 0x00, 0x00, 0xa0];
    bf56x.extend_from_slice(&bf53x);
    let p = detect_payload(&bf56x, &ClassifierOptions::new()).unwrap();
    assert_eq!(
        p.format.variant_name.as_deref(),
        Some("Blackfin LDR (BF56x)")
    );
}

#[test]
fn corrupt_or_truncated_streams_are_not_ldr() {
    let data = bf54x_stream();
    let mut bad_check = data.clone();
    bad_check[18] ^= 1;
    for (name, bytes) in [
        ("bad checksum", &bad_check[..]),
        ("truncated", &data[..data.len() - 1]),
    ] {
        if let Ok(p) = detect_payload(bytes, &ClassifierOptions::new()) {
            assert_ne!(p.format.format, FileFormat::BlackfinLdr, "{name}");
        }
    }
    for end in 0..data.len() {
        let _ = detect_payload(&data[..end], &ClassifierOptions::new());
    }
    for i in 0..data.len() {
        for value in [0x00, 0xff, data[i] ^ 0x01] {
            let mut mutated = data.clone();
            mutated[i] = value;
            let _ = detect_payload(&mutated, &ClassifierOptions::new());
        }
    }
}
