//! Turbo Debugger Symbols (TDS) parser.
//!
//! TDS files are Borland/Delphi debug symbol containers associated with x86 binaries.

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// TDS signature.
pub const TDS_MAGIC: [u8; 4] = *b"FB0A";

/// Detect TDS container.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    if data[..4] != TDS_MAGIC {
        return false;
    }

    // Many corpus samples have 0x00000008 immediately after the signature.
    let header_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    header_size > 0 && header_size < 0x100000
}

/// Parse TDS container.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < 12 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 12,
            actual: data.len(),
        });
    }

    let header_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let mut notes = vec!["Turbo Debugger Symbols (TDS)".to_string()];
    notes.push(format!("Header size: {header_size}"));

    let metadata = ClassificationMetadata {
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::X86, 32, Endianness::Little, FileFormat::Tds);
    result.variant = Variant::new("Borland TDS");
    result.metadata = metadata;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_tds() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&TDS_MAGIC);
        data[4..8].copy_from_slice(&8u32.to_le_bytes());
        assert!(detect(&data));
    }

    #[test]
    fn test_parse_tds() {
        let mut data = vec![0u8; 32];
        data[0..4].copy_from_slice(&TDS_MAGIC);
        data[4..8].copy_from_slice(&8u32.to_le_bytes());
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::X86);
        assert_eq!(result.format, FileFormat::Tds);
    }
}
