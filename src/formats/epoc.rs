//! Symbian E32 image (EPOC) parser.
//!
//! Symbian binaries typically carry UID fields and the ASCII marker "EPOC"
//! in the image header.

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// Marker value at offset 0x10 (little-endian u32 of "EPOC").
pub const EPOC_MARKER_LE: u32 = 0x434F_5045;

/// Known Symbian UID1 values commonly seen in executable images.
const KNOWN_UID1: &[u32] = &[
    0x1000_0079,
    0x1000_007A,
    0x1000_8C6A,
    0x1020_1A7A,
    0x1000_1351,
];

/// Known Symbian UID2 values that appear in SIS/E32 images.
const KNOWN_UID2: &[u32] = &[0x1000_3A12];

/// Detect EPOC format.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < 0x20 {
        return false;
    }

    let uid1 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let uid2 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let uid3 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let marker = u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]);

    if marker == EPOC_MARKER_LE {
        return true;
    }

    // Fallback for partially-corrupted headers that still preserve UID layout.
    KNOWN_UID1.contains(&uid1)
        || ((uid1 & 0xFFF0_0000) == 0x1000_0000 && uid2 != 0)
        || (KNOWN_UID2.contains(&uid2) && (uid3 & 0xFFF0_0000) == 0x1000_0000)
}

/// Parse EPOC file.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < 0x20 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 0x20,
            actual: data.len(),
        });
    }

    let uid1 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let uid2 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let uid3 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let header_crc = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let marker = u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]);

    let mut notes = vec!["Symbian E32 image (EPOC)".to_string()];
    notes.push(format!("UID1: 0x{uid1:08X}"));
    notes.push(format!("UID2: 0x{uid2:08X}"));
    notes.push(format!("UID3: 0x{uid3:08X}"));
    notes.push(format!("Header CRC: 0x{header_crc:08X}"));
    if marker == EPOC_MARKER_LE {
        notes.push("Header marker: EPOC".to_string());
    }

    let metadata = ClassificationMetadata {
        notes,
        ..Default::default()
    };

    // Symbian corpus in this project is ARM-focused.
    let mut result =
        ClassificationResult::from_format(Isa::Arm, 32, Endianness::Little, FileFormat::Epoc);
    result.variant = Variant::new("Symbian E32");
    result.metadata = metadata;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_epoc_with_marker() {
        let mut data = vec![0u8; 0x40];
        data[0..4].copy_from_slice(&0x1000_0079u32.to_le_bytes());
        data[0x10..0x14].copy_from_slice(&EPOC_MARKER_LE.to_le_bytes());
        assert!(detect(&data));
    }

    #[test]
    fn test_parse_epoc() {
        let mut data = vec![0u8; 0x40];
        data[0..4].copy_from_slice(&0x1000_0079u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x1000_008Du32.to_le_bytes());
        data[8..12].copy_from_slice(&0x1000_0419u32.to_le_bytes());
        data[0x10..0x14].copy_from_slice(&EPOC_MARKER_LE.to_le_bytes());
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::Arm);
        assert_eq!(result.format, FileFormat::Epoc);
    }

    #[test]
    fn test_detect_epoc_with_uid2_uid3_fallback() {
        let mut data = vec![0u8; 0x40];
        data[0..4].copy_from_slice(&0x2000_4B2Eu32.to_le_bytes());
        data[4..8].copy_from_slice(&0x1000_3A12u32.to_le_bytes());
        data[8..12].copy_from_slice(&0x1000_0419u32.to_le_bytes());
        assert!(detect(&data));
    }
}
