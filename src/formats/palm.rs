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

/// Size of the NUL-terminated database name at the start of the header.
const NAME_SIZE: usize = 32;

/// Sizes of a resource entry (type, ID, offset) and of a record entry
/// (offset, attributes and unique ID).
const RESOURCE_ENTRY_SIZE: usize = 10;
const RECORD_ENTRY_SIZE: usize = 8;

/// Offset of the data offset within each entry kind.
const RESOURCE_OFFSET_FIELD: usize = 6;
const RECORD_OFFSET_FIELD: usize = 0;

/// Detect Palm PDB/PRC container.
///
/// Header (Palm File Format Specification, "Database Header"): name (32 B,
/// NUL-terminated), attributes, version, three dates, modification number,
/// app info and sort info offsets, type (60), creator (64), unique ID seed,
/// next record list ID, record count (76). The name must end with a NUL
/// and hold no control characters, and every entry's data offset must lie
/// after the entry table, inside the file and in ascending order (entries
/// store no sizes; a record's size is the distance to the next offset).
/// Type and creator codes alone matched text-heavy files such as compiled
/// terminfo entries.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < PDB_HEADER_SIZE || !has_database_name(data) {
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
    let count = usize::from(num_records);

    // Resource DB path: 10-byte entries (type[4], id[2], offset[4])
    let first_type = &data[PDB_HEADER_SIZE..PDB_HEADER_SIZE + 4];
    if is_ascii_fourcc(first_type)
        && has_ordered_offsets(data, count, RESOURCE_ENTRY_SIZE, RESOURCE_OFFSET_FIELD)
    {
        return true;
    }

    // Record DB path: 8-byte entries (offset[4], attrs+uid[4])
    has_ordered_offsets(data, count, RECORD_ENTRY_SIZE, RECORD_OFFSET_FIELD)
}

/// Does the header start with a NUL-terminated name free of control
/// characters?
fn has_database_name(data: &[u8]) -> bool {
    let Some(end) = data[..NAME_SIZE].iter().position(|&b| b == 0) else {
        return false;
    };
    data[..end].iter().all(|&b| b >= 0x20 && b != 0x7f)
}

/// Do the `count` entries of `entry_size` bytes after the header give data
/// offsets, at `offset_field` in each entry, that lie after the table,
/// inside the file and in ascending order?
fn has_ordered_offsets(data: &[u8], count: usize, entry_size: usize, offset_field: usize) -> bool {
    let table_end = PDB_HEADER_SIZE + count * entry_size;
    if table_end > data.len() {
        return false;
    }
    let mut previous = table_end;
    for i in 0..count {
        let Some(offset) = read_be_u32(data, PDB_HEADER_SIZE + i * entry_size + offset_field)
        else {
            return false;
        };
        let offset = offset as usize;
        if offset < previous || offset >= data.len() {
            return false;
        }
        previous = offset;
    }
    true
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
    fn names_with_control_characters_and_unordered_offsets_are_rejected() {
        let mut data = vec![0u8; 128];
        data[60..64].copy_from_slice(b"appl");
        data[64..68].copy_from_slice(b"TEST");
        data[76..78].copy_from_slice(&2u16.to_be_bytes());
        // Record entries: offsets 100 and 90 (descending).
        data[78..82].copy_from_slice(&100u32.to_be_bytes());
        data[86..90].copy_from_slice(&90u32.to_be_bytes());
        assert!(!detect(&data));
        data[86..90].copy_from_slice(&110u32.to_be_bytes());
        assert!(detect(&data));
        // A compiled terminfo entry starts with its magic, not a name.
        data[..4].copy_from_slice(&[0x1a, 0x01, 0x40, 0x00]);
        assert!(!detect(&data));
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
