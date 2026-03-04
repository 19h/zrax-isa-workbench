//! Espressif firmware image parser.
//!
//! ESP images (ESP8266/ESP32 family) commonly start with 0xE9 and carry
//! chip metadata that can distinguish Xtensa and RISC-V variants.

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// ESP image magic byte.
pub const ESP_MAGIC: u8 = 0xE9;

/// RISC-V-based ESP chip IDs (as seen in image headers).
const RISCV_CHIP_IDS: &[u16] = &[0x0005, 0x000C, 0x000D]; // C3, C2, C6

/// Xtensa-based ESP chip IDs.
const XTENSA_CHIP_IDS: &[u16] = &[0x0000, 0x0002, 0x0004, 0x0009]; // ESP32/S2/S3 family

/// Detect ESP firmware image.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < 16 || data[0] != ESP_MAGIC {
        return false;
    }

    let segment_count = data[1];
    if !(1..=16).contains(&segment_count) {
        return false;
    }

    let entry = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let top_byte = entry & 0xFF00_0000;
    let plausible_entry =
        entry == 0xDEAD_BEEF || entry == 0 || top_byte == 0x4000_0000 || top_byte == 0x3F00_0000;
    plausible_entry
}

/// Parse ESP firmware image.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < 16 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 16,
            actual: data.len(),
        });
    }

    let segment_count = data[1] as usize;
    let entry = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let chip_id = if data.len() >= 14 {
        u16::from_le_bytes([data[12], data[13]])
    } else {
        u16::MAX
    };

    let (isa, variant_name) = if RISCV_CHIP_IDS.contains(&chip_id) {
        (Isa::RiscV32, "ESP RISC-V")
    } else if XTENSA_CHIP_IDS.contains(&chip_id) {
        (Isa::Xtensa, "ESP Xtensa")
    } else {
        // Legacy ESP8266 images often do not carry the modern chip-id field.
        (Isa::Xtensa, "ESP (legacy/unknown chip)")
    };

    let mut notes = vec!["Espressif firmware image".to_string()];
    notes.push(format!("Segments: {segment_count}"));
    notes.push(format!("Entry: 0x{entry:08X}"));
    if chip_id != u16::MAX {
        notes.push(format!("Chip ID: 0x{chip_id:04X}"));
    }

    let metadata = ClassificationMetadata {
        section_count: Some(segment_count),
        entry_point: if entry != 0 { Some(entry as u64) } else { None },
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(isa, 32, Endianness::Little, FileFormat::EspFirmware);
    result.variant = Variant::new(variant_name);
    result.metadata = metadata;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_esp() {
        let mut data = vec![0u8; 32];
        data[0] = ESP_MAGIC;
        data[1] = 3;
        data[4..8].copy_from_slice(&0x4000_1000u32.to_le_bytes());
        assert!(detect(&data));
    }

    #[test]
    fn test_parse_esp_riscv() {
        let mut data = vec![0u8; 32];
        data[0] = ESP_MAGIC;
        data[1] = 2;
        data[4..8].copy_from_slice(&0x403A_E000u32.to_le_bytes());
        data[12..14].copy_from_slice(&0x0005u16.to_le_bytes());
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::RiscV32);
        assert_eq!(result.format, FileFormat::EspFirmware);
    }
}
