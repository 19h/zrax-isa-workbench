//! PEF (Preferred Executable Format) parser.
//!
//! PEF was used by Classic Mac OS for PowerPC and 68K executables.
//! It was the native executable format before Mac OS X adopted Mach-O.

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u16, read_u32};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// PEF magic values.
pub mod magic {
    /// Tag1: "Joy!" (big-endian)
    pub const TAG1: u32 = 0x4A6F7921;
    /// Tag2: "peff" (big-endian)
    pub const TAG2: u32 = 0x70656666;
    /// PowerPC architecture: "pwpc"
    pub const ARCH_PPC: u32 = 0x70777063;
    /// 68K architecture: "m68k"
    pub const ARCH_M68K: u32 = 0x6D36386B;
}

/// PEF container header size.
pub const PEF_HEADER_SIZE: usize = 40;

/// PEF section header size.
pub const PEF_SECTION_HEADER_SIZE: usize = 28;

/// PEF section types.
pub mod section_type {
    pub const CODE: u8 = 0;
    pub const UNPACKED_DATA: u8 = 1;
    pub const PATTERN_DATA: u8 = 2;
    pub const CONSTANT: u8 = 3;
    pub const LOADER: u8 = 4;
    pub const DEBUG: u8 = 5;
    pub const EXEC_DATA: u8 = 6;
    pub const EXCEPTION: u8 = 7;
    pub const TRACEBACK: u8 = 8;
}

/// Detect PEF format.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }

    let tag1 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let tag2 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    tag1 == magic::TAG1 && tag2 == magic::TAG2
}

/// Parse PEF file.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < PEF_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: PEF_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // PEF is always big-endian
    let _tag1 = read_u32(data, 0, false)?;
    let _tag2 = read_u32(data, 4, false)?;
    let architecture = read_u32(data, 8, false)?;
    let format_version = read_u32(data, 12, false)?;
    let timestamp = read_u32(data, 16, false)?;
    let old_def_version = read_u32(data, 20, false)?;
    let old_imp_version = read_u32(data, 24, false)?;
    let current_version = read_u32(data, 28, false)?;
    let section_count = read_u16(data, 32, false)?;
    let inst_section_count = read_u16(data, 34, false)?;
    let _reserved = read_u32(data, 36, false)?;

    // Determine ISA from architecture tag
    let (isa, bitwidth, arch_name) = match architecture {
        magic::ARCH_PPC => (Isa::Ppc, 32, "PowerPC"),
        magic::ARCH_M68K => (Isa::M68k, 32, "Motorola 68K"),
        _ => {
            let arch_str = String::from_utf8_lossy(&architecture.to_be_bytes());
            (Isa::Unknown(architecture), 32, "Unknown")
        }
    };

    let mut notes = vec!["PEF (Preferred Executable Format)".to_string()];
    notes.push(format!("Architecture: {}", arch_name));
    notes.push(format!("Format version: {}", format_version));
    notes.push(format!("Sections: {} ({} instantiated)", section_count, inst_section_count));

    // Version info
    if current_version > 0 {
        let major = (current_version >> 16) & 0xFF;
        let minor = (current_version >> 8) & 0xFF;
        let patch = current_version & 0xFF;
        notes.push(format!("Version: {}.{}.{}", major, minor, patch));
    }

    // Parse sections if available
    let mut code_size = 0u64;
    let sections_off = PEF_HEADER_SIZE;
    if sections_off + (section_count as usize * PEF_SECTION_HEADER_SIZE) <= data.len() {
        for i in 0..section_count as usize {
            let sec_off = sections_off + i * PEF_SECTION_HEADER_SIZE;
            let _name_offset = read_u32(data, sec_off, false)?;
            let _default_addr = read_u32(data, sec_off + 4, false)?;
            let total_size = read_u32(data, sec_off + 8, false)?;
            let _unpacked_size = read_u32(data, sec_off + 12, false)?;
            let _packed_size = read_u32(data, sec_off + 16, false)?;
            let _container_off = read_u32(data, sec_off + 20, false)?;
            let section_kind = data[sec_off + 24];

            if section_kind == section_type::CODE {
                code_size += total_size as u64;
            }
        }
    }

    if code_size > 0 {
        notes.push(format!("Code size: {} bytes", code_size));
    }

    let metadata = ClassificationMetadata {
        code_size: if code_size > 0 { Some(code_size) } else { None },
        section_count: Some(section_count as usize),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(isa, bitwidth, Endianness::Big, FileFormat::Pef);
    result.variant = Variant::new(arch_name);
    result.metadata = metadata;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pef_header(architecture: u32) -> Vec<u8> {
        let mut data = vec![0u8; 64];

        // Tag1: "Joy!"
        data[0..4].copy_from_slice(&magic::TAG1.to_be_bytes());
        // Tag2: "peff"
        data[4..8].copy_from_slice(&magic::TAG2.to_be_bytes());
        // Architecture
        data[8..12].copy_from_slice(&architecture.to_be_bytes());
        // Format version
        data[12..16].copy_from_slice(&1u32.to_be_bytes());
        // Section count
        data[32..34].copy_from_slice(&2u16.to_be_bytes());
        // Instantiated section count
        data[34..36].copy_from_slice(&1u16.to_be_bytes());

        data
    }

    #[test]
    fn test_detect_pef() {
        let data = make_pef_header(magic::ARCH_PPC);
        assert!(detect(&data));
    }

    #[test]
    fn test_detect_not_pef() {
        let data = vec![0x7F, b'E', b'L', b'F'];
        assert!(!detect(&data));
    }

    #[test]
    fn test_parse_ppc() {
        let data = make_pef_header(magic::ARCH_PPC);
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::Ppc);
        assert_eq!(result.bitwidth, 32);
        assert_eq!(result.format, FileFormat::Pef);
        assert_eq!(result.endianness, Endianness::Big);
    }

    #[test]
    fn test_parse_m68k() {
        let data = make_pef_header(magic::ARCH_M68K);
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::M68k);
        assert_eq!(result.bitwidth, 32);
        assert_eq!(result.format, FileFormat::Pef);
    }
}
