//! VW/Audi FRF encrypted flash container detector.
//!
//! FRF files are the proprietary encrypted flash container format used by
//! Volkswagen Group's **ODIS** (Offboard Diagnostic Information System)
//! and **VAS** diagnostic tools for distributing ECU firmware updates.
//!
//! # Container Structure
//!
//! The entire file is encrypted (AES or similar), tied to VW's SVM/FAZIT
//! licensing system. Only an 8-byte magic signature is recognizable:
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//! 0x00     8    Magic: 0A 9C 92 7C 51 A5 E1 B5
//! 0x08     *    Encrypted payload (to EOF)
//! ```
//!
//! Since the payload is fully encrypted, ISA classification is not possible
//! from the binary content. However, FRF filenames typically encode VW Group
//! part numbers that can be mapped to ECU platforms using the same scheme
//! as SGO files.
//!
//! # Filename Convention
//!
//! FRF files are typically named with VW Group part numbers:
//! - `03L906022QF_0002.frf` → EDC17 (TriCore)
//! - `03C906014A.frf` → Simos 7 (C166)
//! - `06J906027FC.frf` → MED17.5 (TriCore)

use crate::error::{ClassifierError, Result};
use crate::types::{ClassificationResult, Endianness, FileFormat, Isa};

/// Magic bytes: first 8 bytes of every FRF file.
pub const MAGIC: [u8; 8] = [0x0A, 0x9C, 0x92, 0x7C, 0x51, 0xA5, 0xE1, 0xB5];

/// Minimum file size for a valid FRF file.
const MIN_FRF_SIZE: usize = 16;

/// Detect whether the given data is an FRF container.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < MIN_FRF_SIZE {
        return false;
    }
    data[..8] == MAGIC
}

/// Parse the FRF container.
///
/// Since the payload is fully encrypted, this only confirms the format
/// and reports file size. ISA classification is not possible without
/// decryption keys.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < MIN_FRF_SIZE {
        return Err(ClassifierError::FileTooSmall {
            expected: MIN_FRF_SIZE,
            actual: data.len(),
        });
    }

    if data[..8] != MAGIC {
        return Err(ClassifierError::InvalidMagic {
            expected: "FRF magic (0A 9C 92 7C 51 A5 E1 B5)".into(),
            actual: format!("{:02X?}", &data[..8]),
        });
    }

    let mut result =
        ClassificationResult::from_format(Isa::Unknown(0), 0, Endianness::Little, FileFormat::Frf);
    result.confidence = 0.0;

    result
        .metadata
        .notes
        .push("VW/Audi ODIS encrypted flash container (FRF)".into());
    result.metadata.notes.push(format!(
        "Encrypted payload: {} bytes (AES, VW SVM/FAZIT key required)",
        data.len() - 8
    ));
    result
        .metadata
        .notes
        .push("ISA classification not possible without decryption".into());

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_frf(size: usize) -> Vec<u8> {
        let mut data = vec![0u8; size];
        data[..8].copy_from_slice(&MAGIC);
        // Fill rest with pseudo-random encrypted-looking data
        for i in 8..data.len() {
            data[i] = ((i * 137 + 59) & 0xFF) as u8;
        }
        data
    }

    #[test]
    fn test_detect_valid_frf() {
        let data = make_test_frf(1024);
        assert!(detect(&data));
    }

    #[test]
    fn test_detect_rejects_non_frf() {
        assert!(!detect(&[0u8; 64]));
        assert!(!detect(b"SGML Object File"));
    }

    #[test]
    fn test_detect_too_small() {
        assert!(!detect(&MAGIC[..4]));
    }

    #[test]
    fn test_parse_frf() {
        let data = make_test_frf(4096);
        let result = parse(&data).unwrap();
        assert_eq!(result.format, FileFormat::Frf);
        assert_eq!(result.isa, Isa::Unknown(0));
        assert_eq!(result.confidence, 0.0);
        assert!(result
            .metadata
            .notes
            .iter()
            .any(|n| n.contains("encrypted")));
    }
}
