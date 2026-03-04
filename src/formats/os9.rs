//! OS-9 module parser.
//!
//! OS-9 modules commonly start with sync bytes 0x87CD and include a
//! big-endian module size field. Some 6809 ecosystems also ship loadable
//! FLEX/OS-9 binary record streams.

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// OS-9 sync marker.
pub const OS9_SYNC: u16 = 0x87CD;

/// FLEX data record type.
const FLEX_DATA_RECORD: u8 = 0x02;

/// FLEX transfer-address record type.
const FLEX_TRANSFER_RECORD: u8 = 0x16;

#[derive(Debug, Clone, Copy)]
struct FlexSummary {
    record_count: usize,
    payload_bytes: usize,
    transfer_addr: u16,
}

fn detect_flex_binary(data: &[u8]) -> Option<FlexSummary> {
    if data.len() < 7 || data[0] != FLEX_DATA_RECORD {
        return None;
    }

    let mut pos = 0usize;
    let mut record_count = 0usize;
    let mut payload_bytes = 0usize;

    while pos < data.len() {
        match data[pos] {
            FLEX_DATA_RECORD => {
                if pos + 4 > data.len() {
                    return None;
                }
                let data_len = data[pos + 3] as usize;
                let end = pos + 4 + data_len;
                if end > data.len() {
                    return None;
                }
                payload_bytes += data_len;
                record_count += 1;
                pos = end;
            }
            FLEX_TRANSFER_RECORD => {
                if pos + 3 > data.len() || record_count == 0 {
                    return None;
                }
                let transfer_addr = u16::from_be_bytes([data[pos + 1], data[pos + 2]]);
                pos += 3;

                // Allow only benign padding after transfer record.
                let tail = &data[pos..];
                if !tail.iter().all(|b| matches!(*b, 0x00 | 0x0A | 0x0D | 0xFF)) {
                    return None;
                }

                return Some(FlexSummary {
                    record_count,
                    payload_bytes,
                    transfer_addr,
                });
            }
            _ => return None,
        }
    }

    None
}

/// Detect OS-9 module format.
pub fn detect(data: &[u8]) -> bool {
    if data.len() >= 8 {
        let sync = u16::from_be_bytes([data[0], data[1]]);
        if sync == OS9_SYNC {
            let module_size = u16::from_be_bytes([data[2], data[3]]) as usize;
            if module_size >= 8 && module_size <= data.len() {
                return true;
            }
        }
    }

    detect_flex_binary(data).is_some()
}

/// Parse OS-9 module format.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    let notes = if data.len() >= 8 && u16::from_be_bytes([data[0], data[1]]) == OS9_SYNC {
        let module_size = u16::from_be_bytes([data[2], data[3]]) as usize;
        let module_type = data.get(6).copied().unwrap_or(0);

        vec![
            "OS-9 module".to_string(),
            format!("Declared size: {module_size} bytes"),
            format!("Type byte: 0x{module_type:02X}"),
        ]
    } else if let Some(flex) = detect_flex_binary(data) {
        vec![
            "FLEX/OS-9 6809 binary stream".to_string(),
            format!("Data records: {}", flex.record_count),
            format!("Payload bytes: {}", flex.payload_bytes),
            format!("Transfer address: 0x{:04X}", flex.transfer_addr),
        ]
    } else if data.len() < 8 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 8,
            actual: data.len(),
        });
    } else {
        return Err(ClassifierError::UnknownFormat {
            magic: data[..4].to_vec(),
        });
    };

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

    #[test]
    fn test_detect_flex_os9_binary() {
        let mut data = Vec::new();
        data.extend_from_slice(&[FLEX_DATA_RECORD, 0x10, 0x00, 0x03, 0xDE, 0xAD, 0xBE]);
        data.extend_from_slice(&[FLEX_DATA_RECORD, 0x10, 0x03, 0x02, 0xEF, 0x01]);
        data.extend_from_slice(&[FLEX_TRANSFER_RECORD, 0x10, 0x00]);
        assert!(detect(&data));
    }

    #[test]
    fn test_parse_flex_os9_binary() {
        let mut data = Vec::new();
        data.extend_from_slice(&[FLEX_DATA_RECORD, 0x20, 0x00, 0x02, 0x12, 0x34]);
        data.extend_from_slice(&[FLEX_TRANSFER_RECORD, 0x20, 0x00]);
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::M68k);
        assert_eq!(result.format, FileFormat::Os9);
        assert!(result
            .metadata
            .notes
            .iter()
            .any(|n| n.contains("FLEX/OS-9")));
    }

    #[test]
    fn test_reject_invalid_flex_tail() {
        let mut data = Vec::new();
        data.extend_from_slice(&[FLEX_DATA_RECORD, 0x10, 0x00, 0x01, 0xAA]);
        data.extend_from_slice(&[FLEX_TRANSFER_RECORD, 0x10, 0x00, 0x02]);
        assert!(!detect(&data));
    }
}
