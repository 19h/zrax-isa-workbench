//! SMS-Soft CombiLoader container format detector (BCF).
//!
//! BCF files are a proprietary encrypted container format created by
//! **SMS-Software** (Russian ECU chip-tuning company). They are used by
//! **CombiLoader** (flash reading/writing tool) and **ChipTuningPRO**
//! (calibration editing software) to store ECU flash memory dumps,
//! EEPROM data, and metadata in a single encrypted container.
//!
//! # Container Structure
//!
//! ```text
//! Offset  Size  Type      Field
//! ------  ----  --------  -----
//! 0x00    16    char[16]  Magic: "SMS-SoftContFile" (ASCII)
//! 0x10     4    u32 LE    Encryption nonce / IV (changes per save)
//! 0x14     4    u32 LE    Encrypted payload size (== file_size - 26)
//! 0x18     2    u16 LE    Section count (memory regions in container)
//! 0x1A     *    u8[]      Encrypted payload (to EOF)
//! ```
//!
//! # Encryption
//!
//! The entire payload after offset 0x1A is encrypted with a password-based
//! scheme. The nonce at offset 0x10 serves as an IV combined with the
//! user-supplied password. Entropy is 7.999+ bits/byte — effectively
//! indistinguishable from random data. Without the password, the firmware
//! content cannot be recovered.
//!
//! # Section Count Semantics
//!
//! The section count field reveals the ECU's memory architecture:
//! - 1 section: Single flash (e.g., Ford SIM28/SIM210)
//! - 2 sections: Flash + EEPROM (e.g., Bosch ME17.9.7, M86)
//! - 3 sections: Dual flash + EEPROM (e.g., Ford PCM)
//! - 7 sections: Multi-segment TriCore (e.g., Bosch MEDC17 on TC1724)
//! - 9 sections: Delphi MT86 multi-calibration
//! - 10 sections: GM/Delphi large multi-calibration sets

use crate::error::{ClassifierError, Result};
use crate::types::{ClassificationResult, Endianness, FileFormat, Isa};

/// Magic bytes: "SMS-SoftContFile" (16 bytes ASCII).
pub const MAGIC: &[u8; 16] = b"SMS-SoftContFile";

/// Header size (magic + nonce + payload_size + section_count).
const HEADER_SIZE: usize = 0x1A;

/// Detect whether the given data is a BCF container.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < HEADER_SIZE {
        return false;
    }
    &data[..16] == MAGIC
}

/// Parse the BCF container header.
///
/// Since the payload is password-encrypted, this only extracts the
/// cleartext header fields: nonce, payload size, and section count.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < HEADER_SIZE {
        return Err(ClassifierError::FileTooSmall {
            expected: HEADER_SIZE,
            actual: data.len(),
        });
    }

    if &data[..16] != MAGIC {
        return Err(ClassifierError::InvalidMagic {
            expected: "SMS-SoftContFile".into(),
            actual: format!("{:?}", &data[..16]),
        });
    }

    // Parse header fields
    let nonce = u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]);
    let payload_size = u32::from_le_bytes([data[0x14], data[0x15], data[0x16], data[0x17]]);
    let section_count = u16::from_le_bytes([data[0x18], data[0x19]]);

    // Validate payload size
    let expected_payload = data.len().saturating_sub(HEADER_SIZE) as u32;
    let size_valid = payload_size == expected_payload;

    let mut result =
        ClassificationResult::from_format(Isa::Unknown(0), 0, Endianness::Little, FileFormat::Bcf);
    result.confidence = 0.0;

    result
        .metadata
        .notes
        .push("SMS-Soft CombiLoader/ChipTuningPRO container (BCF)".into());
    result.metadata.notes.push(format!(
        "{} memory section(s), {} bytes encrypted payload",
        section_count, payload_size
    ));
    result
        .metadata
        .notes
        .push(format!("Encryption nonce: 0x{:08X}", nonce));

    if !size_valid {
        result.metadata.notes.push(format!(
            "Warning: declared payload size {} != actual {} (file may be truncated)",
            payload_size, expected_payload
        ));
    }

    // Infer ECU type from section count (heuristic)
    let ecu_hint = match section_count {
        1 => Some("Single flash ECU (e.g., Ford SIM28/SIM210)"),
        2 => Some("Flash + EEPROM ECU (e.g., Bosch ME17.9.7, M86)"),
        3 => Some("Dual flash + EEPROM ECU (e.g., Ford PCM)"),
        7 => Some("Multi-segment TriCore ECU (e.g., Bosch MEDC17 on TC1724)"),
        9 => Some("Delphi MT86 multi-calibration ECU"),
        10 => Some("GM/Delphi large multi-calibration set"),
        _ => None,
    };
    if let Some(hint) = ecu_hint {
        result
            .metadata
            .notes
            .push(format!("ECU type hint: {}", hint));
    }

    result
        .metadata
        .notes
        .push("Password-encrypted payload (ISA classification not possible)".into());

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_bcf(section_count: u16, payload_size: usize) -> Vec<u8> {
        let total = HEADER_SIZE + payload_size;
        let mut data = vec![0u8; total];
        data[..16].copy_from_slice(MAGIC);
        // Nonce
        data[0x10..0x14].copy_from_slice(&0x12345678u32.to_le_bytes());
        // Payload size
        data[0x14..0x18].copy_from_slice(&(payload_size as u32).to_le_bytes());
        // Section count
        data[0x18..0x1A].copy_from_slice(&section_count.to_le_bytes());
        data
    }

    #[test]
    fn test_detect_valid_bcf() {
        let data = make_test_bcf(2, 1024);
        assert!(detect(&data));
    }

    #[test]
    fn test_detect_rejects_non_bcf() {
        assert!(!detect(&[0u8; 64]));
        assert!(!detect(b"SGML Object File0000"));
    }

    #[test]
    fn test_detect_too_small() {
        assert!(!detect(b"SMS-SoftCont"));
    }

    #[test]
    fn test_parse_bcf() {
        let data = make_test_bcf(7, 4096);
        let result = parse(&data).unwrap();
        assert_eq!(result.format, FileFormat::Bcf);
        assert_eq!(result.isa, Isa::Unknown(0));
        assert!(result
            .metadata
            .notes
            .iter()
            .any(|n| n.contains("7 memory section")));
        assert!(result.metadata.notes.iter().any(|n| n.contains("TC1724")));
    }

    #[test]
    fn test_parse_bcf_single_section() {
        let data = make_test_bcf(1, 512);
        let result = parse(&data).unwrap();
        assert!(result
            .metadata
            .notes
            .iter()
            .any(|n| n.contains("Single flash")));
    }

    #[test]
    fn test_parse_bcf_payload_size_validation() {
        let data = make_test_bcf(2, 1024);
        let result = parse(&data).unwrap();
        // Should not have truncation warning since sizes match
        assert!(!result
            .metadata
            .notes
            .iter()
            .any(|n| n.contains("truncated")));
    }

    #[test]
    fn test_parse_bcf_nonce() {
        let data = make_test_bcf(2, 256);
        let result = parse(&data).unwrap();
        assert!(result
            .metadata
            .notes
            .iter()
            .any(|n| n.contains("0x12345678")));
    }
}
