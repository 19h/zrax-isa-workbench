//! ARM Object Format (AOF/AXF) parser.
//!
//! AOF is used by legacy ARM toolchains (including RVCT/ARMCC output variants).

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// Common AOF file signature.
pub const AOF_MAGIC: [u8; 4] = [0xC5, 0xC6, 0xCB, 0xC3];

/// Detect AOF format.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }

    if data[0..4] != AOF_MAGIC {
        return false;
    }

    // Most valid samples carry chunk tags like "OBJ_" / "HEAD"
    &data[12..16] == b"OBJ_" || &data[16..20] == b"OBJ_"
}

/// Parse AOF file.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < 20 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 20,
            actual: data.len(),
        });
    }

    let chunk_count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let mut notes = vec!["ARM Object Format (AOF/AXF)".to_string()];
    if chunk_count > 0 {
        notes.push(format!("Declared chunks: {chunk_count}"));
    }
    if &data[12..16] == b"OBJ_" {
        notes.push("Found OBJ_ chunk table".to_string());
    }

    let metadata = ClassificationMetadata {
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::Arm, 32, Endianness::Little, FileFormat::Aof);
    result.variant = Variant::new("AOF");
    result.metadata = metadata;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_aof() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&AOF_MAGIC);
        data[4..8].copy_from_slice(&5u32.to_le_bytes());
        data[12..16].copy_from_slice(b"OBJ_");
        assert!(detect(&data));
    }

    #[test]
    fn test_parse_aof() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&AOF_MAGIC);
        data[4..8].copy_from_slice(&3u32.to_le_bytes());
        data[12..16].copy_from_slice(b"OBJ_");
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::Arm);
        assert_eq!(result.format, FileFormat::Aof);
    }
}
