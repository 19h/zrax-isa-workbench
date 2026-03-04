//! Amiga Hunk format parser.
//!
//! Classic Amiga executables/objects commonly begin with HUNK_HEADER (0x3F3).

use crate::error::{ClassifierError, Result};
use crate::formats::read_u32;
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// HUNK_HEADER marker (big-endian).
pub const HUNK_HEADER: u32 = 0x0000_03F3;

/// Detect Amiga Hunk format.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == HUNK_HEADER
}

/// Parse Amiga Hunk format.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < 8 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 8,
            actual: data.len(),
        });
    }

    let mut notes = vec!["Amiga Hunk container".to_string()];

    // Try to parse basic hunk table metadata when available.
    let mut off = 4usize;
    let mut resident_names = 0usize;
    while off + 4 <= data.len() {
        let words = read_u32(data, off, false)? as usize;
        off += 4;
        if words == 0 {
            break;
        }
        let bytes = words.saturating_mul(4);
        if off + bytes > data.len() {
            break;
        }
        resident_names += 1;
        off += bytes;
        if resident_names > 64 {
            break;
        }
    }

    let mut section_count = None;
    if off + 12 <= data.len() {
        let table_size = read_u32(data, off, false)? as usize;
        section_count = Some(table_size);
        notes.push(format!("Hunk table size: {table_size}"));
    }
    if resident_names > 0 {
        notes.push(format!("Resident library names: {resident_names}"));
    }

    let metadata = ClassificationMetadata {
        section_count,
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::M68k, 32, Endianness::Big, FileFormat::AmigaHunk);
    result.variant = Variant::new("Amiga Hunk");
    result.metadata = metadata;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_hunk() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&HUNK_HEADER.to_be_bytes());
        assert!(detect(&data));
    }

    #[test]
    fn test_parse_hunk() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&HUNK_HEADER.to_be_bytes());
        // No resident names (terminator)
        data[4..8].copy_from_slice(&0u32.to_be_bytes());
        // table size
        data[8..12].copy_from_slice(&2u32.to_be_bytes());
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::M68k);
        assert_eq!(result.format, FileFormat::AmigaHunk);
    }
}
