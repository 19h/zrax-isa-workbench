//! OMF (Object Module Format) parser.
//!
//! OMF is a record-based object format used by DOS/Windows toolchains
//! (Intel/Microsoft/Borland). Most corpus samples are x86-oriented.

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// OMF record types we treat as valid for detection.
const VALID_RECORD_TYPES: &[u8] = &[
    0x80, // THEADR
    0x82, // LHEADR
    0x88, // COMENT
    0x8A, // MODEND (16)
    0x8B, // MODEND (32)
    0x8C, // EXTDEF
    0x90, // PUBDEF (16)
    0x91, // PUBDEF (32)
    0x94, // LINNUM (16)
    0x95, // LINNUM (32)
    0x96, // LNAMES
    0x98, // SEGDEF (16)
    0x99, // SEGDEF (32)
    0x9A, // GRPDEF
    0x9C, // FIXUPP (16)
    0x9D, // FIXUPP (32)
    0xA0, // LEDATA (16)
    0xA1, // LEDATA (32)
    0xB0, // COMDEF
    0xB2, // BAKPAT (16)
    0xB3, // BAKPAT (32)
    0xC2, // COMDAT (16)
    0xC3, // COMDAT (32)
];

#[inline]
fn is_valid_record_type(t: u8) -> bool {
    VALID_RECORD_TYPES.contains(&t)
}

/// Detect OMF format.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    let mut pos = 0usize;
    let mut checked = 0usize;
    let mut checksum_ok = 0usize;

    while checked < 4 && pos + 3 <= data.len() {
        let rec_type = data[pos];
        if !is_valid_record_type(rec_type) {
            return false;
        }

        let rec_len = u16::from_le_bytes([data[pos + 1], data[pos + 2]]) as usize;
        if rec_len == 0 {
            return false;
        }

        let end = pos + 3 + rec_len;
        if end > data.len() {
            return false;
        }

        let rec = &data[pos..end];
        if rec.iter().fold(0u8, |acc, b| acc.wrapping_add(*b)) == 0 {
            checksum_ok += 1;
        }

        checked += 1;
        pos = end;

        if rec_type == 0x8A || rec_type == 0x8B {
            break;
        }
    }

    checked > 0 && checksum_ok * 2 >= checked
}

/// Parse OMF file.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < 4 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 4,
            actual: data.len(),
        });
    }

    let mut pos = 0usize;
    let mut record_count = 0usize;
    let mut has_modend = false;
    let mut uses_32bit_records = false;
    let mut checksum_mismatch = 0usize;

    while pos + 3 <= data.len() {
        let rec_type = data[pos];
        if !is_valid_record_type(rec_type) {
            break;
        }

        let rec_len = u16::from_le_bytes([data[pos + 1], data[pos + 2]]) as usize;
        if rec_len == 0 {
            break;
        }

        let end = pos + 3 + rec_len;
        if end > data.len() {
            break;
        }

        let rec = &data[pos..end];
        if rec.iter().fold(0u8, |acc, b| acc.wrapping_add(*b)) != 0 {
            checksum_mismatch += 1;
        }

        record_count += 1;
        if rec_type & 1 == 1 {
            uses_32bit_records = true;
        }
        if rec_type == 0x8A || rec_type == 0x8B {
            has_modend = true;
            break;
        }

        pos = end;
    }

    if record_count == 0 {
        return Err(ClassifierError::UnknownFormat {
            magic: data[..data.len().min(4)].to_vec(),
        });
    }

    let bitwidth = if uses_32bit_records { 32 } else { 16 };
    let mut notes = vec!["OMF object module".to_string()];
    notes.push(format!("Records: {}", record_count));
    if uses_32bit_records {
        notes.push("Contains 32-bit record variants".to_string());
    }
    if !has_modend {
        notes.push("No MODEND record found (possibly malformed/truncated)".to_string());
    }
    if checksum_mismatch > 0 {
        notes.push(format!(
            "{} record(s) with checksum mismatch",
            checksum_mismatch
        ));
    }

    let metadata = ClassificationMetadata {
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::X86, bitwidth, Endianness::Little, FileFormat::Omf);
    result.variant = Variant::new(if uses_32bit_records {
        "32-bit OMF"
    } else {
        "16-bit OMF"
    });
    result.metadata = metadata;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(rec_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut rec = Vec::with_capacity(3 + payload.len() + 1);
        rec.push(rec_type);
        let rec_len = (payload.len() + 1) as u16;
        rec.extend_from_slice(&rec_len.to_le_bytes());
        rec.extend_from_slice(payload);
        let sum = rec.iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
        rec.push(0u8.wrapping_sub(sum));
        rec
    }

    #[test]
    fn test_detect_omf() {
        let mut data = make_record(0x80, b"test");
        data.extend(make_record(0x8A, &[]));
        assert!(detect(&data));
    }

    #[test]
    fn test_parse_omf_32bit() {
        let mut data = make_record(0x80, b"mod");
        data.extend(make_record(0xA1, &[1, 2, 3, 4]));
        data.extend(make_record(0x8B, &[]));
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::X86);
        assert_eq!(result.bitwidth, 32);
        assert_eq!(result.format, FileFormat::Omf);
    }

    #[test]
    fn test_reject_non_omf() {
        let data = b"\x7FELF\x02\x01\x01\x00";
        assert!(!detect(data));
    }
}
