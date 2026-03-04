//! HP-UX SOM (System Object Model) parser.
//!
//! SOM is the native executable/object format for PA-RISC HP-UX systems.

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u16, read_u32};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// Minimum SOM header size we rely on.
pub const SOM_HEADER_MIN_SIZE: usize = 0x60;

/// Common SOM magic values (big-endian).
pub mod magic {
    pub const EXEC_MAGIC: u16 = 0x0107;
    pub const SHARE_MAGIC: u16 = 0x0108;
    pub const DEMAND_MAGIC: u16 = 0x010B;
    pub const DL_MAGIC: u16 = 0x010D;
}

/// Known HP-UX system IDs for PA-RISC.
pub mod system_id {
    pub const HP9000S700: u16 = 0x020B;
    pub const HP9000S800: u16 = 0x0210;
}

#[inline]
fn is_valid_magic(m: u16) -> bool {
    matches!(
        m,
        magic::EXEC_MAGIC | magic::SHARE_MAGIC | magic::DEMAND_MAGIC | magic::DL_MAGIC
    )
}

/// Detect SOM format.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < SOM_HEADER_MIN_SIZE {
        return false;
    }

    let sid = u16::from_be_bytes([data[0], data[1]]);
    let mag = u16::from_be_bytes([data[2], data[3]]);

    if sid != system_id::HP9000S700 && sid != system_id::HP9000S800 {
        return false;
    }
    if !is_valid_magic(mag) {
        return false;
    }

    let som_len = u32::from_be_bytes([data[0x20], data[0x21], data[0x22], data[0x23]]) as usize;
    if som_len == 0 {
        return false;
    }

    true
}

/// Parse SOM file.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < SOM_HEADER_MIN_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: SOM_HEADER_MIN_SIZE,
            actual: data.len(),
        });
    }

    let sid = read_u16(data, 0, false)?;
    let mag = read_u16(data, 2, false)?;
    let version_id = read_u32(data, 4, false)?;
    let entry_offset = read_u32(data, 0x14, false)?;
    let som_length = read_u32(data, 0x20, false)?;
    let symbol_total = read_u32(data, 0x5C, false).unwrap_or(0);

    let variant_name = match mag {
        magic::EXEC_MAGIC => "Executable",
        magic::SHARE_MAGIC => "Shared library",
        magic::DEMAND_MAGIC => "Demand-load executable",
        magic::DL_MAGIC => "Dynamic-load library",
        _ => "Unknown",
    };

    let mut notes = vec!["HP-UX SOM container".to_string()];
    notes.push(format!("System ID: 0x{sid:04X}"));
    notes.push(format!("Magic: 0x{mag:04X} ({variant_name})"));
    notes.push(format!("Version ID: 0x{version_id:08X}"));
    if entry_offset != 0 {
        notes.push(format!("Entry offset: 0x{entry_offset:08X}"));
    }
    if som_length != 0 {
        notes.push(format!("Declared length: {som_length} bytes"));
    }

    let metadata = ClassificationMetadata {
        symbol_count: if symbol_total > 0 {
            Some(symbol_total as usize)
        } else {
            None
        },
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::Parisc, 32, Endianness::Big, FileFormat::Som);
    result.variant = Variant::new(variant_name);
    result.metadata = metadata;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_som_header(magic_value: u16) -> Vec<u8> {
        let mut data = vec![0u8; SOM_HEADER_MIN_SIZE];
        data[0..2].copy_from_slice(&system_id::HP9000S800.to_be_bytes());
        data[2..4].copy_from_slice(&magic_value.to_be_bytes());
        data[4..8].copy_from_slice(&0x0512_4000u32.to_be_bytes());
        data[0x20..0x24].copy_from_slice(&(SOM_HEADER_MIN_SIZE as u32).to_be_bytes());
        data[0x5C..0x60].copy_from_slice(&7u32.to_be_bytes());
        data
    }

    #[test]
    fn test_detect_som() {
        let data = make_som_header(magic::SHARE_MAGIC);
        assert!(detect(&data));
    }

    #[test]
    fn test_parse_som() {
        let data = make_som_header(magic::EXEC_MAGIC);
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::Parisc);
        assert_eq!(result.format, FileFormat::Som);
    }

    #[test]
    fn test_reject_non_som() {
        let data = b"\x7FELF\x02\x01\x01\x00";
        assert!(!detect(data));
    }
}
