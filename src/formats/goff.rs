//! GOFF (Generalized Object File Format) parser.
//!
//! GOFF is used by IBM z/Architecture (s390x) systems.
//! It uses EBCDIC encoding and big-endian byte order.

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// GOFF record marker byte.
pub const GOFF_MARKER: u8 = 0x03;

/// GOFF record types (in PTV byte 1, bits 0-3).
pub mod record_type {
    pub const HDR: u8 = 0xF0;  // Header record (masked)
    pub const ESD: u8 = 0x00;  // External Symbol Dictionary
    pub const TXT: u8 = 0x10;  // Text record
    pub const RLD: u8 = 0x20;  // Relocation Dictionary
    pub const LEN: u8 = 0x30;  // Length record
    pub const END: u8 = 0x40;  // End record
}

/// GOFF ESD symbol types.
pub mod esd_type {
    pub const SD: u8 = 0x00;   // Section Definition
    pub const ED: u8 = 0x01;   // Element Definition
    pub const LD: u8 = 0x02;   // Label Definition
    pub const PR: u8 = 0x03;   // Part Reference
    pub const ER: u8 = 0x04;   // External Reference
}

/// GOFF record size (fixed length records).
pub const GOFF_RECORD_SIZE: usize = 80;

/// Detect GOFF format.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < 3 {
        return false;
    }

    // GOFF records start with 0x03 marker
    // Byte 0: 0x03 (GOFF marker)
    // Byte 1: Record type | continuation flags
    // Byte 2: Version (usually 0x00)
    data[0] == GOFF_MARKER && data[2] == 0x00
}

/// Parse GOFF file.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < GOFF_RECORD_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: GOFF_RECORD_SIZE,
            actual: data.len(),
        });
    }

    // Count records by type
    let mut record_count = 0u32;
    let mut esd_count = 0u32;
    let mut txt_count = 0u32;
    let mut rld_count = 0u32;
    let mut has_hdr = false;
    let mut has_end = false;

    let mut offset = 0;
    while offset + 3 <= data.len() {
        if data[offset] != GOFF_MARKER {
            // Not a GOFF record, might be padding
            offset += 1;
            continue;
        }

        let rec_type = data[offset + 1] & 0xF0;
        record_count += 1;

        match rec_type {
            0xF0 => {
                // Could be HDR if version byte indicates
                if data[offset + 2] == 0x00 {
                    has_hdr = true;
                }
            }
            record_type::ESD => esd_count += 1,
            record_type::TXT => txt_count += 1,
            record_type::RLD => rld_count += 1,
            record_type::END => has_end = true,
            _ => {}
        }

        // GOFF records are typically 80 bytes (card image)
        // But can vary with continuation
        offset += GOFF_RECORD_SIZE;
        if offset > data.len() {
            break;
        }
    }

    let mut notes = vec!["GOFF (z/Architecture)".to_string()];
    notes.push(format!("Records: {}", record_count));
    notes.push(format!("ESD entries: {}", esd_count));
    notes.push(format!("Text records: {}", txt_count));
    notes.push(format!("RLD entries: {}", rld_count));

    if !has_hdr {
        notes.push("Warning: No header record".to_string());
    }
    if !has_end {
        notes.push("Warning: No end record".to_string());
    }

    let metadata = ClassificationMetadata {
        section_count: Some(esd_count as usize),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::S390x, 64, Endianness::Big, FileFormat::Goff);
    result.variant = Variant::new("z/Architecture");
    result.metadata = metadata;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_goff_file() -> Vec<u8> {
        let mut data = vec![0u8; GOFF_RECORD_SIZE * 3];

        // HDR record
        data[0] = GOFF_MARKER;
        data[1] = 0xF0;
        data[2] = 0x00;

        // ESD record
        let off = GOFF_RECORD_SIZE;
        data[off] = GOFF_MARKER;
        data[off + 1] = record_type::ESD;
        data[off + 2] = 0x00;

        // END record
        let off = GOFF_RECORD_SIZE * 2;
        data[off] = GOFF_MARKER;
        data[off + 1] = record_type::END;
        data[off + 2] = 0x00;

        data
    }

    #[test]
    fn test_detect_goff() {
        let data = make_goff_file();
        assert!(detect(&data));
    }

    #[test]
    fn test_detect_not_goff() {
        let data = vec![0x7F, b'E', b'L', b'F'];
        assert!(!detect(&data));
    }

    #[test]
    fn test_parse_goff() {
        let data = make_goff_file();
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::S390x);
        assert_eq!(result.format, FileFormat::Goff);
    }
}
