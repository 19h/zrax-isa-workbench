//! OS-9 module parser.
//!
//! OS-9 modules commonly start with sync bytes 0x87CD and include a
//! big-endian module size field.

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// OS-9 sync marker.
pub const OS9_SYNC: u16 = 0x87CD;

/// Detect OS-9 module format.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }

    let sync = u16::from_be_bytes([data[0], data[1]]);
    if sync != OS9_SYNC {
        return false;
    }

    let module_size = u16::from_be_bytes([data[2], data[3]]) as usize;
    module_size >= 8 && module_size <= data.len()
}

/// Parse OS-9 module format.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < 8 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 8,
            actual: data.len(),
        });
    }

    let module_size = u16::from_be_bytes([data[2], data[3]]) as usize;
    let module_type = data.get(6).copied().unwrap_or(0);

    let mut notes = vec!["OS-9 module".to_string()];
    notes.push(format!("Declared size: {module_size} bytes"));
    notes.push(format!("Type byte: 0x{module_type:02X}"));

    let metadata = ClassificationMetadata {
        notes,
        ..Default::default()
    };

    // 6809 is not currently modeled as a dedicated ISA enum variant.
    // Use M68k family as the closest legacy bucket for now.
    let mut result =
        ClassificationResult::from_format(Isa::M68k, 32, Endianness::Big, FileFormat::Os9);
    result.variant = Variant::new("OS-9 module");
    result.metadata = metadata;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_os9() {
        let mut data = vec![0u8; 64];
        data[0..2].copy_from_slice(&OS9_SYNC.to_be_bytes());
        data[2..4].copy_from_slice(&64u16.to_be_bytes());
        assert!(detect(&data));
    }

    #[test]
    fn test_parse_os9() {
        let mut data = vec![0u8; 32];
        data[0..2].copy_from_slice(&OS9_SYNC.to_be_bytes());
        data[2..4].copy_from_slice(&32u16.to_be_bytes());
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::M68k);
        assert_eq!(result.format, FileFormat::Os9);
    }
}
