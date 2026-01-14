//! ECOFF (Extended Common Object File Format) parser.
//!
//! ECOFF was used by older UNIX systems, primarily:
//! - MIPS systems: Ultrix, early IRIX, some embedded
//! - Alpha systems: Digital UNIX (Tru64), OpenVMS
//!
//! ECOFF is largely obsolete, replaced by ELF on these platforms,
//! but legacy binaries still exist.

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u16, read_u32, read_u64};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// ECOFF magic numbers.
pub mod magic {
    /// MIPS little-endian (MIPSELMAGIC)
    pub const MIPS_LE: u16 = 0x0160;
    /// MIPS big-endian (MIPSEBMAGIC) - stored as big-endian
    pub const MIPS_BE: u16 = 0x0160;
    /// MIPS big-endian magic as it appears in file
    pub const MIPS_BE_RAW: [u8; 2] = [0x01, 0x60];
    /// MIPS little-endian magic as it appears in file
    pub const MIPS_LE_RAW: [u8; 2] = [0x60, 0x01];
    /// Alpha (ALPHAMAGIC)
    pub const ALPHA: u16 = 0x0183;
}

/// ECOFF file header flags.
pub mod flags {
    /// Relocation info stripped
    pub const F_RELFLG: u16 = 0x0001;
    /// File is executable
    pub const F_EXEC: u16 = 0x0002;
    /// Line numbers stripped
    pub const F_LNNO: u16 = 0x0004;
    /// Local symbols stripped
    pub const F_LSYMS: u16 = 0x0008;
    /// Minimal header
    pub const F_MINMAL: u16 = 0x0010;
    /// Fully stripped
    pub const F_UPDATE: u16 = 0x0020;
    /// Shared object
    pub const F_SWABD: u16 = 0x0040;
    /// Patch header
    pub const F_AR16WR: u16 = 0x0080;
    /// Archive member
    pub const F_AR32WR: u16 = 0x0100;
    /// Archive member
    pub const F_AR32W: u16 = 0x0200;
    /// Patch header
    pub const F_PATCH: u16 = 0x0400;
    /// File is a shared object
    pub const F_CALL_SHARED: u16 = 0x2000;
    /// No undefined symbols
    pub const F_NO_UNRESOLVED: u16 = 0x4000;
}

/// ECOFF optional header (a.out) magic values.
pub mod aout_magic {
    /// Standard OMAGIC
    pub const OMAGIC: u16 = 0x0107;
    /// Standard NMAGIC
    pub const NMAGIC: u16 = 0x0108;
    /// Standard ZMAGIC
    pub const ZMAGIC: u16 = 0x010B;
    /// Shared library
    pub const LIBMAGIC: u16 = 0x010D;
}

/// ECOFF file header size (same for MIPS and Alpha).
pub const ECOFF_HEADER_SIZE: usize = 20;

/// ECOFF section header size for MIPS.
pub const ECOFF_MIPS_SECTION_SIZE: usize = 40;

/// ECOFF section header size for Alpha.
pub const ECOFF_ALPHA_SECTION_SIZE: usize = 64;

/// ECOFF MIPS optional header size.
pub const ECOFF_MIPS_AOUT_SIZE: usize = 56;

/// ECOFF Alpha optional header size.
pub const ECOFF_ALPHA_AOUT_SIZE: usize = 80;

/// ECOFF variant types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcoffVariant {
    /// MIPS little-endian
    MipsLe,
    /// MIPS big-endian
    MipsBe,
    /// Alpha (DEC Alpha)
    Alpha,
}

impl EcoffVariant {
    /// Get the ISA for this variant.
    pub fn isa(&self) -> Isa {
        match self {
            EcoffVariant::MipsLe | EcoffVariant::MipsBe => Isa::Mips,
            EcoffVariant::Alpha => Isa::Alpha,
        }
    }

    /// Get the endianness for this variant.
    pub fn endianness(&self) -> Endianness {
        match self {
            EcoffVariant::MipsLe => Endianness::Little,
            EcoffVariant::MipsBe => Endianness::Big,
            EcoffVariant::Alpha => Endianness::Little,
        }
    }

    /// Get the bitwidth for this variant.
    pub fn bitwidth(&self) -> u8 {
        match self {
            EcoffVariant::MipsLe | EcoffVariant::MipsBe => 32,
            EcoffVariant::Alpha => 64,
        }
    }

    /// Check if this variant uses little-endian.
    pub fn is_little_endian(&self) -> bool {
        matches!(self, EcoffVariant::MipsLe | EcoffVariant::Alpha)
    }

    /// Get the optional header size for this variant.
    pub fn aout_header_size(&self) -> usize {
        match self {
            EcoffVariant::MipsLe | EcoffVariant::MipsBe => ECOFF_MIPS_AOUT_SIZE,
            EcoffVariant::Alpha => ECOFF_ALPHA_AOUT_SIZE,
        }
    }

    /// Get the section header size for this variant.
    pub fn section_header_size(&self) -> usize {
        match self {
            EcoffVariant::MipsLe | EcoffVariant::MipsBe => ECOFF_MIPS_SECTION_SIZE,
            EcoffVariant::Alpha => ECOFF_ALPHA_SECTION_SIZE,
        }
    }

    /// Get a human-readable name for this variant.
    pub fn name(&self) -> &'static str {
        match self {
            EcoffVariant::MipsLe => "MIPS little-endian",
            EcoffVariant::MipsBe => "MIPS big-endian",
            EcoffVariant::Alpha => "Alpha",
        }
    }
}

/// Detect ECOFF variant from raw bytes.
pub fn detect(data: &[u8]) -> Option<EcoffVariant> {
    if data.len() < 2 {
        return None;
    }

    // Check magic bytes
    if data[0] == 0x60 && data[1] == 0x01 {
        // Little-endian MIPS: 0x0160 stored as [0x60, 0x01]
        return Some(EcoffVariant::MipsLe);
    }

    if data[0] == 0x01 && data[1] == 0x60 {
        // Big-endian MIPS: 0x0160 stored as [0x01, 0x60]
        return Some(EcoffVariant::MipsBe);
    }

    if data[0] == 0x83 && data[1] == 0x01 {
        // Alpha: 0x0183 stored as [0x83, 0x01] (little-endian)
        return Some(EcoffVariant::Alpha);
    }

    None
}

/// Parse an ECOFF file.
pub fn parse(data: &[u8], variant: EcoffVariant) -> Result<ClassificationResult> {
    if data.len() < ECOFF_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: ECOFF_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let le = variant.is_little_endian();

    // Parse file header
    let _magic = read_u16(data, 0, le)?;
    let num_sections = read_u16(data, 2, le)?;
    let _timestamp = read_u32(data, 4, le)?;
    let _sym_offset = read_u32(data, 8, le)?;
    let num_symbols = read_u32(data, 12, le)?;
    let opt_header_size = read_u16(data, 16, le)?;
    let flags = read_u16(data, 18, le)?;

    // Parse optional (a.out) header if present
    let mut entry_point = None;
    #[allow(unused_assignments)]
    let mut _text_start = None;
    #[allow(unused_assignments)]
    let mut _data_start = None;
    #[allow(unused_assignments)]
    let mut _bss_start = None;

    if opt_header_size > 0 {
        let opt_off = ECOFF_HEADER_SIZE;
        let expected_size = variant.aout_header_size();

        if opt_off + (opt_header_size as usize).min(expected_size) <= data.len() {
            let _aout_magic = read_u16(data, opt_off, le)?;
            let _vstamp = read_u16(data, opt_off + 2, le)?;

            match variant {
                EcoffVariant::Alpha => {
                    // Alpha has 64-bit addresses
                    if opt_header_size >= 48 {
                        // tsize, dsize, bsize, entry, text_start, data_start
                        entry_point = Some(read_u64(data, opt_off + 16, le)?);
                        _text_start = Some(read_u64(data, opt_off + 24, le)?);
                        _data_start = Some(read_u64(data, opt_off + 32, le)?);
                        _bss_start = Some(read_u64(data, opt_off + 40, le)?);
                    }
                }
                _ => {
                    // MIPS has 32-bit addresses
                    if opt_header_size >= 28 {
                        entry_point = Some(read_u32(data, opt_off + 16, le)? as u64);
                        _text_start = Some(read_u32(data, opt_off + 20, le)? as u64);
                        _data_start = Some(read_u32(data, opt_off + 24, le)? as u64);
                    }
                    if opt_header_size >= 32 {
                        _bss_start = Some(read_u32(data, opt_off + 28, le)? as u64);
                    }
                }
            }
        }
    }

    // Build notes
    let mut notes = Vec::new();
    notes.push(format!("ECOFF {}", variant.name()));

    if flags & flags::F_EXEC != 0 {
        notes.push("Executable".to_string());
    }
    if flags & flags::F_CALL_SHARED != 0 {
        notes.push("Shared object".to_string());
    }
    if flags & flags::F_NO_UNRESOLVED != 0 {
        notes.push("No unresolved symbols".to_string());
    }

    // Build variant info
    let var = match variant {
        EcoffVariant::MipsLe => Variant::new("MIPS-LE"),
        EcoffVariant::MipsBe => Variant::new("MIPS-BE"),
        EcoffVariant::Alpha => Variant::default(),
    };

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

    let mut result = ClassificationResult::from_format(
        variant.isa(),
        variant.bitwidth(),
        variant.endianness(),
        FileFormat::Ecoff,
    );
    result.variant = var;
    result.metadata = metadata;

    Ok(result)
}

/// Get a human-readable description of ECOFF flags.
pub fn flags_description(flags: u16) -> Vec<&'static str> {
    let mut desc = Vec::new();

    if flags & flags::F_RELFLG != 0 {
        desc.push("relocs stripped");
    }
    if flags & flags::F_EXEC != 0 {
        desc.push("executable");
    }
    if flags & flags::F_LNNO != 0 {
        desc.push("line numbers stripped");
    }
    if flags & flags::F_LSYMS != 0 {
        desc.push("local symbols stripped");
    }
    if flags & flags::F_CALL_SHARED != 0 {
        desc.push("shared");
    }
    if flags & flags::F_NO_UNRESOLVED != 0 {
        desc.push("no unresolved");
    }

    desc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ecoff_header(variant: EcoffVariant, num_sections: u16, flags: u16) -> Vec<u8> {
        let mut data = vec![0u8; 256];
        let le = variant.is_little_endian();

        // Magic
        match variant {
            EcoffVariant::MipsLe => {
                data[0] = 0x60;
                data[1] = 0x01;
            }
            EcoffVariant::MipsBe => {
                data[0] = 0x01;
                data[1] = 0x60;
            }
            EcoffVariant::Alpha => {
                data[0] = 0x83;
                data[1] = 0x01;
            }
        }

        // Number of sections
        if le {
            data[2] = (num_sections & 0xFF) as u8;
            data[3] = (num_sections >> 8) as u8;
        } else {
            data[2] = (num_sections >> 8) as u8;
            data[3] = (num_sections & 0xFF) as u8;
        }

        // Timestamp
        let ts = 0x12345678u32;
        if le {
            data[4..8].copy_from_slice(&ts.to_le_bytes());
        } else {
            data[4..8].copy_from_slice(&ts.to_be_bytes());
        }

        // Symbol table offset
        let sym_off = 0x00001000u32;
        if le {
            data[8..12].copy_from_slice(&sym_off.to_le_bytes());
        } else {
            data[8..12].copy_from_slice(&sym_off.to_be_bytes());
        }

        // Number of symbols
        let num_syms = 50u32;
        if le {
            data[12..16].copy_from_slice(&num_syms.to_le_bytes());
        } else {
            data[12..16].copy_from_slice(&num_syms.to_be_bytes());
        }

        // Optional header size (0 for object files)
        data[16] = 0;
        data[17] = 0;

        // Flags
        if le {
            data[18] = (flags & 0xFF) as u8;
            data[19] = (flags >> 8) as u8;
        } else {
            data[18] = (flags >> 8) as u8;
            data[19] = (flags & 0xFF) as u8;
        }

        data
    }

    #[test]
    fn test_detect_mips_le() {
        let data = make_ecoff_header(EcoffVariant::MipsLe, 3, 0);
        assert_eq!(detect(&data), Some(EcoffVariant::MipsLe));
    }

    #[test]
    fn test_detect_mips_be() {
        let data = make_ecoff_header(EcoffVariant::MipsBe, 3, 0);
        assert_eq!(detect(&data), Some(EcoffVariant::MipsBe));
    }

    #[test]
    fn test_detect_alpha() {
        let data = make_ecoff_header(EcoffVariant::Alpha, 5, 0);
        assert_eq!(detect(&data), Some(EcoffVariant::Alpha));
    }

    #[test]
    fn test_detect_invalid() {
        let data = vec![0x7F, b'E', b'L', b'F'];
        assert_eq!(detect(&data), None);
    }

    #[test]
    fn test_parse_mips_le() {
        let data = make_ecoff_header(EcoffVariant::MipsLe, 4, flags::F_EXEC);
        let result = parse(&data, EcoffVariant::MipsLe).unwrap();
        assert_eq!(result.isa, Isa::Mips);
        assert_eq!(result.bitwidth, 32);
        assert_eq!(result.endianness, Endianness::Little);
        assert_eq!(result.format, FileFormat::Ecoff);
        assert_eq!(result.metadata.section_count, Some(4));
    }

    #[test]
    fn test_parse_mips_be() {
        let data = make_ecoff_header(EcoffVariant::MipsBe, 3, flags::F_EXEC);
        let result = parse(&data, EcoffVariant::MipsBe).unwrap();
        assert_eq!(result.isa, Isa::Mips);
        assert_eq!(result.bitwidth, 32);
        assert_eq!(result.endianness, Endianness::Big);
        assert_eq!(result.format, FileFormat::Ecoff);
    }

    #[test]
    fn test_parse_alpha() {
        let data = make_ecoff_header(EcoffVariant::Alpha, 6, flags::F_EXEC);
        let result = parse(&data, EcoffVariant::Alpha).unwrap();
        assert_eq!(result.isa, Isa::Alpha);
        assert_eq!(result.bitwidth, 64);
        assert_eq!(result.endianness, Endianness::Little);
        assert_eq!(result.format, FileFormat::Ecoff);
        assert_eq!(result.metadata.section_count, Some(6));
    }

    #[test]
    fn test_variant_properties() {
        assert_eq!(EcoffVariant::MipsLe.isa(), Isa::Mips);
        assert_eq!(EcoffVariant::MipsBe.isa(), Isa::Mips);
        assert_eq!(EcoffVariant::Alpha.isa(), Isa::Alpha);

        assert!(EcoffVariant::MipsLe.is_little_endian());
        assert!(!EcoffVariant::MipsBe.is_little_endian());
        assert!(EcoffVariant::Alpha.is_little_endian());
    }
}
