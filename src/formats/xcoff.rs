//! XCOFF (eXtended Common Object File Format) parser.
//!
//! XCOFF is used by AIX on PowerPC systems. It extends the original COFF
//! format with support for 64-bit addresses, TOC (Table of Contents), and
//! other AIX-specific features.
//!
//! There are two variants:
//! - XCOFF32: 32-bit addresses, magic 0x01DF
//! - XCOFF64: 64-bit addresses, magic 0x01F7

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u16, read_u32, read_u64};
use crate::types::{ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa};

/// XCOFF magic numbers.
pub mod magic {
    /// XCOFF 32-bit magic number
    pub const XCOFF32: u16 = 0x01DF;
    /// XCOFF 64-bit magic number
    pub const XCOFF64: u16 = 0x01F7;
}

/// XCOFF file header flags.
pub mod flags {
    /// Relocation information stripped
    pub const F_RELFLG: u16 = 0x0001;
    /// File is executable (no unresolved external references)
    pub const F_EXEC: u16 = 0x0002;
    /// Line numbers stripped
    pub const F_LNNO: u16 = 0x0004;
    /// Local symbols stripped
    pub const F_LSYMS: u16 = 0x0008;
    /// File was profiled with fdpr
    pub const F_FDPR_PROF: u16 = 0x0010;
    /// File was reordered with fdpr
    pub const F_FDPR_OPTI: u16 = 0x0020;
    /// File uses Very Large Program Support
    pub const F_DSA: u16 = 0x0040;
    /// Reserved
    pub const F_DEP_1: u16 = 0x0080;
    /// AIX version 1
    pub const F_VARPG: u16 = 0x0100;
    /// Reserved
    pub const F_DEP_2: u16 = 0x0200;
    /// Reserved
    pub const F_DEP_3: u16 = 0x0400;
    /// Reserved
    pub const F_DEP_4: u16 = 0x0800;
    /// File is dynamically loadable
    pub const F_DYNLOAD: u16 = 0x1000;
    /// File is a shared object
    pub const F_SHROBJ: u16 = 0x2000;
    /// File is a loadable module  
    pub const F_LOADONLY: u16 = 0x4000;
}

/// XCOFF32 file header size in bytes.
pub const XCOFF32_HEADER_SIZE: usize = 20;

/// XCOFF64 file header size in bytes.
pub const XCOFF64_HEADER_SIZE: usize = 24;

/// XCOFF32 auxiliary header size (for executables).
pub const XCOFF32_AOUT_HEADER_SIZE: usize = 72;

/// XCOFF64 auxiliary header size (for executables).
pub const XCOFF64_AOUT_HEADER_SIZE: usize = 120;

/// XCOFF32 section header size.
pub const XCOFF32_SECTION_HEADER_SIZE: usize = 40;

/// XCOFF64 section header size.
pub const XCOFF64_SECTION_HEADER_SIZE: usize = 72;

/// Auxiliary header magic for executables.
pub mod aout_magic {
    /// Writable text sections
    pub const U802WRMAGIC: u16 = 0x0107;
    /// Read-only text sections  
    pub const U802ROMAGIC: u16 = 0x0108;
    /// TOC overflow protected
    pub const U802TOCMAGIC: u16 = 0x010B;
    /// 64-bit executable
    pub const U64_TOCMAGIC: u16 = 0x0117;
}

/// XCOFF section types.
pub mod section_type {
    /// Regular section
    pub const STYP_REG: u32 = 0x0000;
    /// Pad section
    pub const STYP_PAD: u32 = 0x0008;
    /// Text (code) section
    pub const STYP_TEXT: u32 = 0x0020;
    /// Data section
    pub const STYP_DATA: u32 = 0x0040;
    /// BSS section
    pub const STYP_BSS: u32 = 0x0080;
    /// Exception section
    pub const STYP_EXCEPT: u32 = 0x0100;
    /// Comment section
    pub const STYP_INFO: u32 = 0x0200;
    /// Type check section
    pub const STYP_TDATA: u32 = 0x0400;
    /// Type check bss section
    pub const STYP_TBSS: u32 = 0x0800;
    /// Loader section
    pub const STYP_LOADER: u32 = 0x1000;
    /// Debug section
    pub const STYP_DEBUG: u32 = 0x2000;
    /// Type check section
    pub const STYP_TYPCHK: u32 = 0x4000;
    /// Overflow section
    pub const STYP_OVRFLO: u32 = 0x8000;
}

/// Check if data looks like XCOFF and return the bitwidth.
pub fn detect(data: &[u8]) -> Option<u8> {
    if data.len() < 2 {
        return None;
    }

    // XCOFF is big-endian
    let magic = u16::from_be_bytes([data[0], data[1]]);

    match magic {
        magic::XCOFF32 => Some(32),
        magic::XCOFF64 => Some(64),
        _ => None,
    }
}

/// Parse an XCOFF32 file.
fn parse_xcoff32(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < XCOFF32_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: XCOFF32_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // XCOFF is big-endian
    let _magic = read_u16(data, 0, false)?;
    let num_sections = read_u16(data, 2, false)?;
    let _timestamp = read_u32(data, 4, false)?;
    let _sym_offset = read_u32(data, 8, false)?;
    let num_symbols = read_u32(data, 12, false)?;
    let opt_header_size = read_u16(data, 16, false)?;
    let flags = read_u16(data, 18, false)?;

    // Check for auxiliary header (executables have one)
    let mut entry_point = None;
    #[allow(unused_assignments)]
    let mut _text_start = None;
    #[allow(unused_assignments)]
    let mut _data_start = None;
    #[allow(unused_assignments)]
    let mut _is_executable = false;

    if opt_header_size >= 28 {
        let opt_off = XCOFF32_HEADER_SIZE;
        if opt_off + opt_header_size as usize <= data.len() {
            let aout_magic = read_u16(data, opt_off, false)?;
            _is_executable = matches!(
                aout_magic,
                aout_magic::U802WRMAGIC | aout_magic::U802ROMAGIC | aout_magic::U802TOCMAGIC
            );

            if opt_header_size >= 28 {
                entry_point = Some(read_u32(data, opt_off + 16, false)? as u64);
                _text_start = Some(read_u32(data, opt_off + 20, false)? as u64);
                _data_start = Some(read_u32(data, opt_off + 24, false)? as u64);
            }
        }
    }

    // Build notes
    let mut notes = Vec::new();
    notes.push("XCOFF32 (AIX 32-bit)".to_string());

    if flags & flags::F_EXEC != 0 {
        notes.push("Executable".to_string());
    }
    if flags & flags::F_SHROBJ != 0 {
        notes.push("Shared object".to_string());
    }
    if flags & flags::F_DYNLOAD != 0 {
        notes.push("Dynamically loadable".to_string());
    }
    if flags & flags::F_DSA != 0 {
        notes.push("Very Large Program Support".to_string());
    }

    let metadata = ClassificationMetadata {
        entry_point,
        section_count: Some(num_sections as usize),
        symbol_count: if num_symbols > 0 {
            Some(num_symbols as usize)
        } else {
            None
        },
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::Ppc, 32, Endianness::Big, FileFormat::Xcoff);
    result.metadata = metadata;

    Ok(result)
}

/// Parse an XCOFF64 file.
fn parse_xcoff64(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < XCOFF64_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: XCOFF64_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // XCOFF is big-endian
    let _magic = read_u16(data, 0, false)?;
    let num_sections = read_u16(data, 2, false)?;
    let _timestamp = read_u32(data, 4, false)?;
    let _sym_offset = read_u64(data, 8, false)?;
    let opt_header_size = read_u16(data, 16, false)?;
    let flags = read_u16(data, 18, false)?;
    let num_symbols = read_u32(data, 20, false)?;

    // Check for auxiliary header (executables have one)
    let mut entry_point = None;
    #[allow(unused_assignments)]
    let mut _is_executable = false;

    if opt_header_size >= 72 {
        let opt_off = XCOFF64_HEADER_SIZE;
        if opt_off + opt_header_size as usize <= data.len() {
            let aout_magic = read_u16(data, opt_off, false)?;
            _is_executable = aout_magic == aout_magic::U64_TOCMAGIC;

            if opt_header_size >= 32 {
                entry_point = Some(read_u64(data, opt_off + 16, false)?);
            }
        }
    }

    // Build notes
    let mut notes = Vec::new();
    notes.push("XCOFF64 (AIX 64-bit)".to_string());

    if flags & flags::F_EXEC != 0 {
        notes.push("Executable".to_string());
    }
    if flags & flags::F_SHROBJ != 0 {
        notes.push("Shared object".to_string());
    }
    if flags & flags::F_DYNLOAD != 0 {
        notes.push("Dynamically loadable".to_string());
    }
    if flags & flags::F_DSA != 0 {
        notes.push("Very Large Program Support".to_string());
    }

    let metadata = ClassificationMetadata {
        entry_point,
        section_count: Some(num_sections as usize),
        symbol_count: if num_symbols > 0 {
            Some(num_symbols as usize)
        } else {
            None
        },
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::Ppc64, 64, Endianness::Big, FileFormat::Xcoff);
    result.metadata = metadata;

    Ok(result)
}

/// Parse an XCOFF file (32-bit or 64-bit).
pub fn parse(data: &[u8], bits: u8) -> Result<ClassificationResult> {
    match bits {
        32 => parse_xcoff32(data),
        64 => parse_xcoff64(data),
        _ => Err(ClassifierError::InvalidMagic {
            expected: "XCOFF32 or XCOFF64".to_string(),
            actual: format!("{}-bit", bits),
        }),
    }
}

/// Get section type description.
pub fn section_type_name(stype: u32) -> &'static str {
    match stype {
        section_type::STYP_TEXT => ".text",
        section_type::STYP_DATA => ".data",
        section_type::STYP_BSS => ".bss",
        section_type::STYP_LOADER => ".loader",
        section_type::STYP_DEBUG => ".debug",
        section_type::STYP_TYPCHK => ".typchk",
        section_type::STYP_EXCEPT => ".except",
        section_type::STYP_INFO => ".info",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_xcoff32_header(num_sections: u16, opt_size: u16, flags: u16) -> Vec<u8> {
        let mut data = vec![0u8; 256];

        // Magic (big-endian)
        data[0] = (magic::XCOFF32 >> 8) as u8;
        data[1] = (magic::XCOFF32 & 0xFF) as u8;

        // Number of sections (big-endian)
        data[2] = (num_sections >> 8) as u8;
        data[3] = (num_sections & 0xFF) as u8;

        // Timestamp
        data[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());

        // Symbol table offset
        data[8..12].copy_from_slice(&0x00001000u32.to_be_bytes());

        // Number of symbols
        data[12..16].copy_from_slice(&100u32.to_be_bytes());

        // Optional header size
        data[16] = (opt_size >> 8) as u8;
        data[17] = (opt_size & 0xFF) as u8;

        // Flags
        data[18] = (flags >> 8) as u8;
        data[19] = (flags & 0xFF) as u8;

        data
    }

    fn make_xcoff64_header(num_sections: u16, opt_size: u16, flags: u16) -> Vec<u8> {
        let mut data = vec![0u8; 256];

        // Magic (big-endian)
        data[0] = (magic::XCOFF64 >> 8) as u8;
        data[1] = (magic::XCOFF64 & 0xFF) as u8;

        // Number of sections (big-endian)
        data[2] = (num_sections >> 8) as u8;
        data[3] = (num_sections & 0xFF) as u8;

        // Timestamp
        data[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());

        // Symbol table offset (8 bytes)
        data[8..16].copy_from_slice(&0x0000000000002000u64.to_be_bytes());

        // Optional header size
        data[16] = (opt_size >> 8) as u8;
        data[17] = (opt_size & 0xFF) as u8;

        // Flags
        data[18] = (flags >> 8) as u8;
        data[19] = (flags & 0xFF) as u8;

        // Number of symbols
        data[20..24].copy_from_slice(&200u32.to_be_bytes());

        data
    }

    #[test]
    fn test_detect_xcoff32() {
        let data = make_xcoff32_header(3, 0, 0);
        assert_eq!(detect(&data), Some(32));
    }

    #[test]
    fn test_detect_xcoff64() {
        let data = make_xcoff64_header(5, 0, 0);
        assert_eq!(detect(&data), Some(64));
    }

    #[test]
    fn test_detect_invalid() {
        let data = vec![0x7F, b'E', b'L', b'F'];
        assert_eq!(detect(&data), None);
    }

    #[test]
    fn test_parse_xcoff32() {
        let data = make_xcoff32_header(3, 0, flags::F_EXEC);
        let result = parse(&data, 32).unwrap();
        assert_eq!(result.isa, Isa::Ppc);
        assert_eq!(result.bitwidth, 32);
        assert_eq!(result.endianness, Endianness::Big);
        assert_eq!(result.format, FileFormat::Xcoff);
        assert_eq!(result.metadata.section_count, Some(3));
    }

    #[test]
    fn test_parse_xcoff64() {
        let data = make_xcoff64_header(5, 0, flags::F_SHROBJ);
        let result = parse(&data, 64).unwrap();
        assert_eq!(result.isa, Isa::Ppc64);
        assert_eq!(result.bitwidth, 64);
        assert_eq!(result.endianness, Endianness::Big);
        assert_eq!(result.format, FileFormat::Xcoff);
        assert_eq!(result.metadata.section_count, Some(5));
    }

    #[test]
    fn test_parse_xcoff32_with_opt_header() {
        let mut data = make_xcoff32_header(2, 72, flags::F_EXEC);
        // Add auxiliary header magic
        let opt_off = XCOFF32_HEADER_SIZE;
        data[opt_off] = (aout_magic::U802WRMAGIC >> 8) as u8;
        data[opt_off + 1] = (aout_magic::U802WRMAGIC & 0xFF) as u8;
        // Entry point at offset 16
        data[opt_off + 16..opt_off + 20].copy_from_slice(&0x10000100u32.to_be_bytes());

        let result = parse(&data, 32).unwrap();
        assert_eq!(result.metadata.entry_point, Some(0x10000100));
    }
}
