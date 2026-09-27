//! Philips/NXP TriMedia object module (TMObj, `.o`/`.out`/`.tmobj`).
//!
//! The module header starts with type and endianness bytes, then 32-bit
//! fields in the stored byte order: start symbol, format version (219 for
//! v2.19), machine, checksum and the magic `0x3C46F37A` at offset 20.

use crate::error::{ClassifierError, Result};
use crate::types::{ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa};

/// Module magic number (offset 20).
pub const MAGIC: u32 = 0x3C46_F37A;
/// TMObj format version 2.19 (offset 8).
pub const VERSION: u32 = 219;

/// Header byte order: `Some(true)` for big-endian, `None` if not a TMObj module.
fn header_order(data: &[u8]) -> Option<bool> {
    let field = |off: usize, big: bool| {
        let b: [u8; 4] = data.get(off..off + 4)?.try_into().ok()?;
        Some(if big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    };
    [true, false]
        .into_iter()
        .find(|&big| field(20, big) == Some(MAGIC) && field(8, big) == Some(VERSION))
}

/// Detect a TriMedia object module.
pub fn detect(data: &[u8]) -> bool {
    header_order(data).is_some()
}

/// Parse a TriMedia object module.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    let Some(big) = header_order(data) else {
        return Err(ClassifierError::UnknownFormat {
            magic: data.iter().take(4).copied().collect(),
        });
    };
    // Byte 2 is the byte order of the contained code (TMObj_Endian: 0 = big).
    let code_order = if data[2] == 0 { Endianness::Big } else { Endianness::Little };
    let mut result = ClassificationResult::from_format(Isa::TriMedia, 32, code_order, FileFormat::TmObj);
    result.metadata = ClassificationMetadata {
        notes: vec![format!(
            "TriMedia object module (header {}-endian)",
            if big { "big" } else { "little" }
        )],
        ..Default::default()
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_both_byte_orders() {
        let mut be = vec![0u8; 64];
        be[0] = 1;
        be[8..12].copy_from_slice(&VERSION.to_be_bytes());
        be[20..24].copy_from_slice(&MAGIC.to_be_bytes());
        let r = parse(&be).unwrap();
        assert_eq!((r.isa, r.format, r.endianness), (Isa::TriMedia, FileFormat::TmObj, Endianness::Big));

        let mut le = vec![0u8; 64];
        le[2] = 1;
        le[8..12].copy_from_slice(&VERSION.to_le_bytes());
        le[20..24].copy_from_slice(&MAGIC.to_le_bytes());
        assert_eq!(parse(&le).unwrap().endianness, Endianness::Little);

        le[8] = 0;
        assert!(!detect(&le));
    }
}
