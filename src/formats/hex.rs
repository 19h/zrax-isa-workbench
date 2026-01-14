//! Text-based hex format parsers.
//!
//! This module handles:
//! - Intel HEX (.hex, .ihex)
//! - Motorola S-record (.srec, .s19, .s28, .s37)
//! - TI-TXT (.txt)

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// Intel HEX record types.
pub mod intel_hex {
    pub const DATA: u8 = 0x00;
    pub const EOF: u8 = 0x01;
    pub const EXT_SEGMENT: u8 = 0x02;
    pub const START_SEGMENT: u8 = 0x03;
    pub const EXT_LINEAR: u8 = 0x04;
    pub const START_LINEAR: u8 = 0x05;
}

/// Detected hex format variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexVariant {
    /// Intel HEX format
    IntelHex {
        /// Has 32-bit addressing (type 04/05 records)
        is_32bit: bool,
    },
    /// Motorola S-record format
    Srec {
        /// Address size (2, 3, or 4 bytes)
        addr_size: u8,
    },
    /// TI-TXT format
    TiTxt,
}

/// Detect hex format.
pub fn detect(data: &[u8]) -> Option<HexVariant> {
    if data.is_empty() {
        return None;
    }

    // Try to interpret as text
    // Intel HEX starts with ':'
    if data[0] == b':' {
        // Scan for record types to determine address mode
        let mut is_32bit = false;
        let text = String::from_utf8_lossy(data);
        for line in text.lines().take(100) {
            let line = line.trim();
            if line.starts_with(':') && line.len() >= 9 {
                if let Ok(rec_type) = u8::from_str_radix(&line[7..9], 16) {
                    if rec_type == intel_hex::EXT_LINEAR || rec_type == intel_hex::START_LINEAR {
                        is_32bit = true;
                        break;
                    }
                }
            }
        }
        return Some(HexVariant::IntelHex { is_32bit });
    }

    // S-record starts with 'S'
    if data[0] == b'S' && data.len() >= 2 && data[1].is_ascii_digit() {
        let text = String::from_utf8_lossy(data);
        let mut max_addr_size = 2u8;
        for line in text.lines().take(100) {
            let line = line.trim();
            if line.len() >= 2 && line.starts_with('S') {
                match line.as_bytes()[1] {
                    b'0' | b'1' | b'5' | b'9' => max_addr_size = max_addr_size.max(2),
                    b'2' | b'8' => max_addr_size = max_addr_size.max(3),
                    b'3' | b'7' => max_addr_size = max_addr_size.max(4),
                    _ => {}
                }
            }
        }
        return Some(HexVariant::Srec {
            addr_size: max_addr_size,
        });
    }

    // TI-TXT starts with '@'
    if data[0] == b'@' {
        let text = String::from_utf8_lossy(data);
        // Check if first line is @XXXX (address)
        if let Some(first_line) = text.lines().next() {
            let line = first_line.trim();
            if line.starts_with('@') && line.len() > 1 {
                // Verify it looks like an address
                if line[1..].chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(HexVariant::TiTxt);
                }
            }
        }
    }

    None
}

/// Parse Intel HEX format.
fn parse_intel_hex(data: &[u8], is_32bit: bool) -> Result<ClassificationResult> {
    let text = String::from_utf8_lossy(data);

    let mut min_addr: u64 = u64::MAX;
    let mut max_addr: u64 = 0;
    let mut data_bytes = 0u64;
    let mut record_count = 0u32;
    let mut base_addr: u64 = 0;
    let mut entry_point: Option<u64> = None;
    let mut has_eof = false;

    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with(':') || line.len() < 11 {
            continue;
        }

        record_count += 1;

        // Parse record
        let byte_count = u8::from_str_radix(&line[1..3], 16).unwrap_or(0) as u64;
        let address = u16::from_str_radix(&line[3..7], 16).unwrap_or(0) as u64;
        let rec_type = u8::from_str_radix(&line[7..9], 16).unwrap_or(0);

        match rec_type {
            intel_hex::DATA => {
                let full_addr = base_addr + address;
                min_addr = min_addr.min(full_addr);
                max_addr = max_addr.max(full_addr + byte_count);
                data_bytes += byte_count;
            }
            intel_hex::EOF => {
                has_eof = true;
            }
            intel_hex::EXT_SEGMENT => {
                // Extended segment address (20-bit)
                if line.len() >= 13 {
                    let seg = u16::from_str_radix(&line[9..13], 16).unwrap_or(0) as u64;
                    base_addr = seg << 4;
                }
            }
            intel_hex::START_SEGMENT => {
                // Start segment address (CS:IP)
                if line.len() >= 17 {
                    let cs = u16::from_str_radix(&line[9..13], 16).unwrap_or(0) as u64;
                    let ip = u16::from_str_radix(&line[13..17], 16).unwrap_or(0) as u64;
                    entry_point = Some((cs << 4) + ip);
                }
            }
            intel_hex::EXT_LINEAR => {
                // Extended linear address (32-bit)
                if line.len() >= 13 {
                    let upper = u16::from_str_radix(&line[9..13], 16).unwrap_or(0) as u64;
                    base_addr = upper << 16;
                }
            }
            intel_hex::START_LINEAR => {
                // Start linear address (EIP)
                if line.len() >= 17 {
                    let eip = u32::from_str_radix(&line[9..17], 16).unwrap_or(0) as u64;
                    entry_point = Some(eip);
                }
            }
            _ => {}
        }
    }

    let address_mode = if is_32bit { "32-bit" } else { "16/20-bit" };

    let mut notes = vec!["Intel HEX format".to_string()];
    notes.push(format!("Address mode: {}", address_mode));
    notes.push(format!("Records: {}", record_count));
    notes.push(format!("Data bytes: {}", data_bytes));

    if min_addr != u64::MAX {
        notes.push(format!("Address range: 0x{:X} - 0x{:X}", min_addr, max_addr));
    }
    if !has_eof {
        notes.push("Warning: No EOF record".to_string());
    }

    let metadata = ClassificationMetadata {
        entry_point,
        code_size: Some(data_bytes),
        notes,
        ..Default::default()
    };

    // Intel HEX is ISA-independent
    let mut result = ClassificationResult::from_format(
        Isa::Unknown(0),
        if is_32bit { 32 } else { 16 },
        Endianness::Little,
        FileFormat::IntelHex,
    );
    result.variant = Variant::new(address_mode);
    result.metadata = metadata;

    Ok(result)
}

/// Parse Motorola S-record format.
fn parse_srec(data: &[u8], addr_size: u8) -> Result<ClassificationResult> {
    let text = String::from_utf8_lossy(data);

    let mut min_addr: u64 = u64::MAX;
    let mut max_addr: u64 = 0;
    let mut data_bytes = 0u64;
    let mut record_count = 0u32;
    let mut entry_point: Option<u64> = None;
    let mut has_header = false;

    for line in text.lines() {
        let line = line.trim();
        if line.len() < 4 || !line.starts_with('S') {
            continue;
        }

        let rec_type = line.as_bytes()[1];
        record_count += 1;

        match rec_type {
            b'0' => {
                has_header = true;
            }
            b'1' => {
                // 16-bit address, data
                if line.len() >= 10 {
                    let addr = u16::from_str_radix(&line[4..8], 16).unwrap_or(0) as u64;
                    let byte_count = u8::from_str_radix(&line[2..4], 16).unwrap_or(0) as u64;
                    let data_len = byte_count.saturating_sub(3);
                    min_addr = min_addr.min(addr);
                    max_addr = max_addr.max(addr + data_len);
                    data_bytes += data_len;
                }
            }
            b'2' => {
                // 24-bit address, data
                if line.len() >= 12 {
                    let addr = u32::from_str_radix(&line[4..10], 16).unwrap_or(0) as u64;
                    let byte_count = u8::from_str_radix(&line[2..4], 16).unwrap_or(0) as u64;
                    let data_len = byte_count.saturating_sub(4);
                    min_addr = min_addr.min(addr);
                    max_addr = max_addr.max(addr + data_len);
                    data_bytes += data_len;
                }
            }
            b'3' => {
                // 32-bit address, data
                if line.len() >= 14 {
                    let addr = u32::from_str_radix(&line[4..12], 16).unwrap_or(0) as u64;
                    let byte_count = u8::from_str_radix(&line[2..4], 16).unwrap_or(0) as u64;
                    let data_len = byte_count.saturating_sub(5);
                    min_addr = min_addr.min(addr);
                    max_addr = max_addr.max(addr + data_len);
                    data_bytes += data_len;
                }
            }
            b'7' => {
                // 32-bit start address
                if line.len() >= 14 {
                    entry_point = Some(u32::from_str_radix(&line[4..12], 16).unwrap_or(0) as u64);
                }
            }
            b'8' => {
                // 24-bit start address
                if line.len() >= 12 {
                    entry_point = Some(u32::from_str_radix(&line[4..10], 16).unwrap_or(0) as u64);
                }
            }
            b'9' => {
                // 16-bit start address
                if line.len() >= 10 {
                    entry_point = Some(u16::from_str_radix(&line[4..8], 16).unwrap_or(0) as u64);
                }
            }
            _ => {}
        }
    }

    let addr_bits = match addr_size {
        2 => 16,
        3 => 24,
        4 => 32,
        _ => 16,
    };

    let mut notes = vec!["Motorola S-record format".to_string()];
    notes.push(format!("Address size: {}-bit", addr_bits));
    notes.push(format!("Records: {}", record_count));
    notes.push(format!("Data bytes: {}", data_bytes));

    if min_addr != u64::MAX {
        notes.push(format!("Address range: 0x{:X} - 0x{:X}", min_addr, max_addr));
    }
    if has_header {
        notes.push("Has header record".to_string());
    }

    let metadata = ClassificationMetadata {
        entry_point,
        code_size: Some(data_bytes),
        notes,
        ..Default::default()
    };

    // S-record is ISA-independent
    let mut result = ClassificationResult::from_format(
        Isa::Unknown(0),
        addr_bits as u8,
        Endianness::Big,
        FileFormat::Srec,
    );
    result.variant = Variant::new(format!("S{}", match addr_size {
        4 => "3",
        3 => "2",
        _ => "1",
    }));
    result.metadata = metadata;

    Ok(result)
}

/// Parse TI-TXT format.
fn parse_ti_txt(data: &[u8]) -> Result<ClassificationResult> {
    let text = String::from_utf8_lossy(data);

    let mut min_addr: u64 = u64::MAX;
    let mut max_addr: u64 = 0;
    let mut data_bytes = 0u64;
    let mut section_count = 0u32;
    let mut current_addr: u64 = 0;

    for line in text.lines() {
        let line = line.trim();

        if line.starts_with('@') {
            // Address line
            if let Ok(addr) = u64::from_str_radix(&line[1..], 16) {
                current_addr = addr;
                section_count += 1;
                min_addr = min_addr.min(addr);
            }
        } else if line == "q" || line == "Q" {
            // End of file
            break;
        } else if !line.is_empty() {
            // Data line - count bytes
            let bytes: Vec<&str> = line.split_whitespace().collect();
            let count = bytes.len() as u64;
            data_bytes += count;
            max_addr = max_addr.max(current_addr + count);
            current_addr += count;
        }
    }

    let mut notes = vec!["TI-TXT format".to_string()];
    notes.push(format!("Sections: {}", section_count));
    notes.push(format!("Data bytes: {}", data_bytes));

    if min_addr != u64::MAX {
        notes.push(format!("Address range: 0x{:X} - 0x{:X}", min_addr, max_addr));
    }

    let metadata = ClassificationMetadata {
        code_size: Some(data_bytes),
        section_count: Some(section_count as usize),
        notes,
        ..Default::default()
    };

    // TI-TXT is commonly used for MSP430
    let mut result = ClassificationResult::from_format(
        Isa::Msp430,
        16,
        Endianness::Little,
        FileFormat::TiTxt,
    );
    result.variant = Variant::new("TI-TXT");
    result.metadata = metadata;

    Ok(result)
}

/// Parse hex format file.
pub fn parse(data: &[u8], variant: HexVariant) -> Result<ClassificationResult> {
    match variant {
        HexVariant::IntelHex { is_32bit } => parse_intel_hex(data, is_32bit),
        HexVariant::Srec { addr_size } => parse_srec(data, addr_size),
        HexVariant::TiTxt => parse_ti_txt(data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_intel_hex() {
        let data = b":10010000214601360121470136007EFE09D2190140\n:00000001FF\n";
        let variant = detect(data);
        assert!(matches!(variant, Some(HexVariant::IntelHex { is_32bit: false })));
    }

    #[test]
    fn test_detect_srec() {
        let data = b"S00600004844521B\nS1130000285F245F2212226A000424290008237C2A\nS5030001FB\nS9030000FC\n";
        let variant = detect(data);
        assert!(matches!(variant, Some(HexVariant::Srec { addr_size: 2 })));
    }

    #[test]
    fn test_detect_ti_txt() {
        let data = b"@1000\n01 02 03 04 05 06 07 08\n@2000\n11 12 13 14\nq\n";
        let variant = detect(data);
        assert!(matches!(variant, Some(HexVariant::TiTxt)));
    }

    #[test]
    fn test_parse_intel_hex() {
        let data = b":10010000214601360121470136007EFE09D2190140\n:00000001FF\n";
        let variant = detect(data).unwrap();
        let result = parse(data, variant).unwrap();
        assert_eq!(result.format, FileFormat::IntelHex);
    }

    #[test]
    fn test_parse_srec() {
        let data = b"S00600004844521B\nS1130000285F245F2212226A000424290008237C2A\nS5030001FB\nS9030000FC\n";
        let variant = detect(data).unwrap();
        let result = parse(data, variant).unwrap();
        assert_eq!(result.format, FileFormat::Srec);
    }
}
