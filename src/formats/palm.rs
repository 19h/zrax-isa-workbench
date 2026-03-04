//! Palm PDB/PRC container parser.
//!
//! Palm resource databases are used by classic PalmOS applications.
//! They can carry classic 68k `code` resources and ARM `ARMC` resources.

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// Fixed Palm database header length.
pub const PDB_HEADER_SIZE: usize = 78;

#[inline]
fn read_be_u16(data: &[u8], off: usize) -> Option<u16> {
    (off + 2 <= data.len()).then(|| u16::from_be_bytes([data[off], data[off + 1]]))
}

#[inline]
fn read_be_u32(data: &[u8], off: usize) -> Option<u32> {
    (off + 4 <= data.len())
        .then(|| u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]))
}

#[inline]
fn is_ascii_fourcc(bytes: &[u8]) -> bool {
    bytes.len() == 4
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b' ')
}

/// Detect Palm PDB/PRC container.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < PDB_HEADER_SIZE {
        return false;
    }

    let db_type = &data[60..64];
    let creator = &data[64..68];
    if !is_ascii_fourcc(db_type) || !is_ascii_fourcc(creator) {
        return false;
    }

    let Some(num_records) = read_be_u16(data, 76) else {
        return false;
    };
    if num_records == 0 || num_records > 4096 {
        return false;
    }

    // Resource DB path: 10-byte entries (type[4], id[2], offset[4])
    let table10 = PDB_HEADER_SIZE + num_records as usize * 10;
    if table10 <= data.len() {
        let first_type = &data[PDB_HEADER_SIZE..PDB_HEADER_SIZE + 4];
        if is_ascii_fourcc(first_type) {
            if let Some(first_off) = read_be_u32(data, PDB_HEADER_SIZE + 6) {
                if (first_off as usize) < data.len() && (first_off as usize) >= table10 {
                    return true;
                }
            }
        }
    }

    // Record DB path: 8-byte entries (offset[4], attrs+uid[4])
    let table8 = PDB_HEADER_SIZE + num_records as usize * 8;
    if table8 <= data.len() {
        if let Some(first_off) = read_be_u32(data, PDB_HEADER_SIZE) {
            if (first_off as usize) < data.len() && (first_off as usize) >= table8 {
                return true;
            }
        }
    }

    false
}

/// Parse Palm PDB/PRC container.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < PDB_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: PDB_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let num_records = read_be_u16(data, 76).unwrap_or(0) as usize;
    let db_type = String::from_utf8_lossy(&data[60..64]).to_string();
    let creator = String::from_utf8_lossy(&data[64..68]).to_string();

    let table10 = PDB_HEADER_SIZE + num_records.saturating_mul(10);
    let is_resource_db =
        table10 <= data.len() && is_ascii_fourcc(&data[PDB_HEADER_SIZE..PDB_HEADER_SIZE + 4]);

    let mut has_armc = false;
    let mut has_code = false;
    let mut parsed_entries = 0usize;

    if is_resource_db {
        for i in 0..num_records {
            let off = PDB_HEADER_SIZE + i * 10;
            if off + 10 > data.len() {
                break;
            }
            let rtype = &data[off..off + 4];
            if rtype == b"ARMC" || rtype == b"armc" {
                has_armc = true;
            }
            if rtype == b"code" || rtype == b"CODE" {
                has_code = true;
            }
            parsed_entries += 1;
        }
    }

    let (isa, endianness, variant_name) = if has_armc {
        (Isa::Arm, Endianness::Little, "Palm ARM resource DB")
    } else if has_code {
        (Isa::M68k, Endianness::Big, "Palm 68k resource DB")
    } else {
        (Isa::M68k, Endianness::Big, "Palm database")
    };

    let mut notes = vec!["Palm PDB/PRC container".to_string()];
    notes.push(format!("Type: {db_type}"));
    notes.push(format!("Creator: {creator}"));
    notes.push(format!("Records: {num_records}"));
    if is_resource_db {
        notes.push(format!("Parsed resource entries: {parsed_entries}"));
    }
    if has_armc {
        notes.push("Contains ARMC resources".to_string());
    }
    if has_code {
        notes.push("Contains code resources".to_string());
    }

    let metadata = ClassificationMetadata {
        section_count: if parsed_entries > 0 {
            Some(parsed_entries)
        } else {
            Some(num_records)
        },
        notes,
        ..Default::default()
    };

    let mut result = ClassificationResult::from_format(isa, 32, endianness, FileFormat::PalmPdb);
    result.variant = Variant::new(variant_name);
    result.metadata = metadata;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_palm_resource_db() {
        let mut data = vec![0u8; 128];
        data[60..64].copy_from_slice(b"appl");
        data[64..68].copy_from_slice(b"TEST");
        data[76..78].copy_from_slice(&1u16.to_be_bytes());
        data[78..82].copy_from_slice(b"code");
        data[82..84].copy_from_slice(&1u16.to_be_bytes());
        data[84..88].copy_from_slice(&100u32.to_be_bytes());
        assert!(detect(&data));
    }

    #[test]
    fn test_parse_arm_resource() {
        let mut data = vec![0u8; 256];
        data[60..64].copy_from_slice(b"appl");
        data[64..68].copy_from_slice(b"MSTH");
        data[76..78].copy_from_slice(&2u16.to_be_bytes());
        // Entry 0: ARMC
        data[78..82].copy_from_slice(b"ARMC");
        data[82..84].copy_from_slice(&1u16.to_be_bytes());
        data[84..88].copy_from_slice(&120u32.to_be_bytes());
        // Entry 1: code
        data[88..92].copy_from_slice(b"code");
        data[92..94].copy_from_slice(&2u16.to_be_bytes());
        data[94..98].copy_from_slice(&160u32.to_be_bytes());

        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::Arm);
        assert_eq!(result.format, FileFormat::PalmPdb);
    }
}
