//! VAG/Simos SOX encrypted container format detector.
//!
//! SOX files are a proprietary encrypted container format used by
//! Volkswagen Group for distributing Simos ECU firmware updates.
//! They contain a structured 132-byte (0x84) cleartext header followed
//! by encrypted firmware data organized in 128-byte blocks.
//!
//! # Container Structure
//!
//! ```text
//! Offset  Size  Type     Field
//! ------  ----  -------  -----
//! 0x00     4    u32 LE   Header size (always 0x84 = 132)
//! 0x04     4    u32 LE   Constant (0x100 = 256)
//! 0x08     4    u32 LE   Version (0x01)
//! 0x0C     4    u32 LE   Block size (0x80 = 128)
//! 0x10     4    u32 LE   Data block count (N)
//! 0x14     4    u32 LE   Total capacity blocks (>= N)
//! 0x18     4    u32 LE   Unused block count (capacity - data)
//! 0x1C     4    u32 LE   Segment-related count
//! 0x20     4    u32 LE   Data blocks used
//! 0x24     4    u32 LE   Constant (0x20 = 32)
//! 0x28     4    u32 LE   Constant (0x00)
//! 0x2C     4    u32 LE   Key/version field (often 0x2D4 = 724)
//! 0x30    76    u8[76]   Reserved / additional header fields
//! 0x7C     4    u8[4]    Trailer magic (0x13149562 — fixed byte pattern)
//! 0x80     4    u8[4]    Padding to 0x84
//! 0x84     *    u8[]     Encrypted 128-byte blocks (N * 128 bytes)
//! ```
//!
//! # Size Invariant
//!
//! `file_size == 0x84 + block_count * 128` (verified across all known files).
//!
//! # Encryption
//!
//! The payload blocks are encrypted with a proprietary scheme.
//! Entropy is 7.999+ bits/byte — ISA classification is not possible
//! without the decryption key.

use crate::error::{ClassifierError, Result};
use crate::types::{ClassificationResult, Endianness, FileFormat, Isa};

/// Magic: first 4 bytes are the header size 0x84 in little-endian.
const HEADER_SIZE_MARKER: [u8; 4] = [0x84, 0x00, 0x00, 0x00];

/// Expected constant at offset 0x04 (0x100 LE).
const EXPECTED_04: [u8; 4] = [0x00, 0x01, 0x00, 0x00];

/// Expected constant at offset 0x08 (0x01 LE).
const EXPECTED_08: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// Expected block size at offset 0x0C (0x80 LE).
const EXPECTED_BLOCK_SIZE: [u8; 4] = [0x80, 0x00, 0x00, 0x00];

/// Trailer magic at offset 0x7C.
const TRAILER_MAGIC: [u8; 4] = [0x13, 0x14, 0x95, 0x62];

/// Full header size in bytes.
const HEADER_SIZE: usize = 0x84;

/// Detect whether the given data is a SOX container.
///
/// Detection uses multiple structural invariants:
/// 1. First 4 bytes = 0x00000084 (header size)
/// 2. Bytes 4-7 = 0x00000100
/// 3. Bytes 8-11 = 0x00000001
/// 4. Bytes 12-15 = 0x00000080 (block size = 128)
/// 5. Trailer magic at offset 0x7C = 0x13149562
pub fn detect(data: &[u8]) -> bool {
    if data.len() < HEADER_SIZE {
        return false;
    }
    data[0x00..0x04] == HEADER_SIZE_MARKER
        && data[0x04..0x08] == EXPECTED_04
        && data[0x08..0x0C] == EXPECTED_08
        && data[0x0C..0x10] == EXPECTED_BLOCK_SIZE
        && data[0x7C..0x80] == TRAILER_MAGIC
}

/// Parse the SOX container header.
///
/// Extracts the cleartext header fields: block count, capacity, and
/// validates the file size against the declared block count.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < HEADER_SIZE {
        return Err(ClassifierError::FileTooSmall {
            expected: HEADER_SIZE,
            actual: data.len(),
        });
    }

    if !detect(data) {
        return Err(ClassifierError::InvalidMagic {
            expected: "SOX header (0x84 + structural constants)".into(),
            actual: format!("{:02X?}", &data[..16]),
        });
    }

    // Parse header fields (all little-endian u32)
    let block_count = u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]);
    let capacity = u32::from_le_bytes([data[0x14], data[0x15], data[0x16], data[0x17]]);
    let unused_blocks = u32::from_le_bytes([data[0x18], data[0x19], data[0x1A], data[0x1B]]);
    let key_version = u32::from_le_bytes([data[0x2C], data[0x2D], data[0x2E], data[0x2F]]);

    // Validate file size: header + block_count * 128
    let expected_size = HEADER_SIZE + (block_count as usize) * 128;
    let size_valid = data.len() == expected_size;

    let mut result =
        ClassificationResult::from_format(Isa::Unknown(0), 0, Endianness::Little, FileFormat::Sox);
    result.confidence = 0.0;

    result
        .metadata
        .notes
        .push("VAG/Simos encrypted firmware container (SOX)".into());
    result.metadata.notes.push(format!(
        "{} data block(s) of 128 bytes ({} bytes payload)",
        block_count,
        block_count as u64 * 128
    ));
    result.metadata.notes.push(format!(
        "Capacity: {} blocks, {} unused",
        capacity, unused_blocks
    ));
    result.metadata.notes.push(format!(
        "Key/version field: 0x{:08X} ({})",
        key_version, key_version
    ));

    if !size_valid {
        result.metadata.notes.push(format!(
            "Warning: expected file size {} (0x84 + {} * 128), actual {}",
            expected_size,
            block_count,
            data.len()
        ));
    }

    result
        .metadata
        .notes
        .push("Encrypted 128-byte blocks (ISA classification not possible)".into());

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_sox(block_count: u32) -> Vec<u8> {
        let total = HEADER_SIZE + (block_count as usize) * 128;
        let mut data = vec![0u8; total];

        // Header size marker
        data[0x00..0x04].copy_from_slice(&HEADER_SIZE_MARKER);
        // Constant 0x100
        data[0x04..0x08].copy_from_slice(&EXPECTED_04);
        // Version 1
        data[0x08..0x0C].copy_from_slice(&EXPECTED_08);
        // Block size 128
        data[0x0C..0x10].copy_from_slice(&EXPECTED_BLOCK_SIZE);
        // Block count
        data[0x10..0x14].copy_from_slice(&block_count.to_le_bytes());
        // Capacity = block_count + 2
        data[0x14..0x18].copy_from_slice(&(block_count + 2).to_le_bytes());
        // Unused = 2
        data[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());
        // Constant at 0x24
        data[0x24..0x28].copy_from_slice(&0x20u32.to_le_bytes());
        // Key/version at 0x2C
        data[0x2C..0x30].copy_from_slice(&0x2D4u32.to_le_bytes());
        // Trailer magic
        data[0x7C..0x80].copy_from_slice(&TRAILER_MAGIC);

        data
    }

    #[test]
    fn test_detect_valid_sox() {
        let data = make_test_sox(100);
        assert!(detect(&data));
    }

    #[test]
    fn test_detect_rejects_non_sox() {
        assert!(!detect(&[0u8; 256]));
        assert!(!detect(b"SMS-SoftContFile00000000000000000"));
    }

    #[test]
    fn test_detect_too_small() {
        assert!(!detect(&[0u8; 64]));
    }

    #[test]
    fn test_detect_wrong_trailer() {
        let mut data = make_test_sox(10);
        data[0x7C..0x80].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        assert!(!detect(&data));
    }

    #[test]
    fn test_parse_sox() {
        let data = make_test_sox(100);
        let result = parse(&data).unwrap();
        assert_eq!(result.format, FileFormat::Sox);
        assert_eq!(result.isa, Isa::Unknown(0));
        assert!(result
            .metadata
            .notes
            .iter()
            .any(|n| n.contains("100 data block")));
        assert!(result
            .metadata
            .notes
            .iter()
            .any(|n| n.contains("12800 bytes payload")));
    }

    #[test]
    fn test_parse_sox_size_validation() {
        let data = make_test_sox(50);
        let result = parse(&data).unwrap();
        // Size should be valid (we constructed it correctly)
        assert!(!result.metadata.notes.iter().any(|n| n.contains("Warning")));
    }

    #[test]
    fn test_parse_sox_key_version() {
        let data = make_test_sox(10);
        let result = parse(&data).unwrap();
        assert!(result
            .metadata
            .notes
            .iter()
            .any(|n| n.contains("0x000002D4")));
    }
}
