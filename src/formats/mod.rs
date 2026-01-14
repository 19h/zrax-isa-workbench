//! Binary file format parsers.
//!
//! This module provides parsers for various executable file formats:
//! - ELF (Executable and Linkable Format)
//! - PE/COFF (Portable Executable)
//! - Mach-O (Mach Object)
//! - Raw binary analysis

pub mod elf;
pub mod macho;
pub mod pe;
pub mod raw;

use crate::error::{ClassifierError, Result};
use crate::types::{ClassificationResult, FileFormat};

/// Magic byte signatures for format detection.
pub mod magic {
    /// ELF magic bytes: 0x7F 'E' 'L' 'F'
    pub const ELF: [u8; 4] = [0x7F, b'E', b'L', b'F'];

    /// PE/COFF DOS stub magic: 'M' 'Z'
    pub const MZ: [u8; 2] = [b'M', b'Z'];

    /// PE signature: 'P' 'E' '\0' '\0'
    pub const PE: [u8; 4] = [b'P', b'E', 0, 0];

    /// Mach-O 32-bit big-endian
    pub const MACHO_32_BE: [u8; 4] = [0xFE, 0xED, 0xFA, 0xCE];

    /// Mach-O 32-bit little-endian
    pub const MACHO_32_LE: [u8; 4] = [0xCE, 0xFA, 0xED, 0xFE];

    /// Mach-O 64-bit big-endian
    pub const MACHO_64_BE: [u8; 4] = [0xFE, 0xED, 0xFA, 0xCF];

    /// Mach-O 64-bit little-endian
    pub const MACHO_64_LE: [u8; 4] = [0xCF, 0xFA, 0xED, 0xFE];

    /// Mach-O fat/universal big-endian
    pub const MACHO_FAT_BE: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

    /// Mach-O fat/universal little-endian
    pub const MACHO_FAT_LE: [u8; 4] = [0xBE, 0xBA, 0xFE, 0xCA];

    /// XCOFF 32-bit (AIX)
    pub const XCOFF_32: [u8; 2] = [0x01, 0xDF];

    /// XCOFF 64-bit (AIX)
    pub const XCOFF_64: [u8; 2] = [0x01, 0xF7];

    /// ECOFF MIPS little-endian
    pub const ECOFF_MIPS_LE: [u8; 2] = [0x01, 0x60];

    /// ECOFF MIPS big-endian
    pub const ECOFF_MIPS_BE: [u8; 2] = [0x60, 0x01];

    /// ECOFF Alpha
    pub const ECOFF_ALPHA: [u8; 2] = [0x01, 0x83];
}

/// Detected file format with parsing context.
#[derive(Debug, Clone)]
pub enum DetectedFormat {
    /// ELF format with class (32/64) and endianness
    Elf { class: u8, endian: u8 },
    /// PE/COFF with PE header offset
    Pe { pe_offset: u32 },
    /// Mach-O with bitwidth and endianness
    MachO { bits: u8, big_endian: bool },
    /// Mach-O fat/universal binary
    MachOFat { big_endian: bool },
    /// XCOFF (AIX)
    Xcoff { bits: u8 },
    /// ECOFF
    Ecoff { variant: EcoffVariant },
    /// Unknown/raw format
    Raw,
}

/// ECOFF variants
#[derive(Debug, Clone, Copy)]
pub enum EcoffVariant {
    MipsLe,
    MipsBe,
    Alpha,
}

/// Detect the file format from magic bytes.
pub fn detect_format(data: &[u8]) -> DetectedFormat {
    if data.len() < 4 {
        return DetectedFormat::Raw;
    }

    // ELF
    if data[..4] == magic::ELF {
        if data.len() >= 6 {
            return DetectedFormat::Elf {
                class: data[4],
                endian: data[5],
            };
        }
        return DetectedFormat::Raw;
    }

    // PE/COFF
    if data.len() >= 2 && data[..2] == magic::MZ {
        if data.len() >= 0x40 {
            let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
            let pe_off = pe_offset as usize;
            if pe_off + 4 <= data.len() && data[pe_off..pe_off + 4] == magic::PE {
                return DetectedFormat::Pe { pe_offset };
            }
        }
    }

    // Mach-O
    let magic4 = &data[..4];
    if magic4 == magic::MACHO_32_BE {
        return DetectedFormat::MachO {
            bits: 32,
            big_endian: true,
        };
    }
    if magic4 == magic::MACHO_32_LE {
        return DetectedFormat::MachO {
            bits: 32,
            big_endian: false,
        };
    }
    if magic4 == magic::MACHO_64_BE {
        return DetectedFormat::MachO {
            bits: 64,
            big_endian: true,
        };
    }
    if magic4 == magic::MACHO_64_LE {
        return DetectedFormat::MachO {
            bits: 64,
            big_endian: false,
        };
    }
    if magic4 == magic::MACHO_FAT_BE {
        return DetectedFormat::MachOFat { big_endian: true };
    }
    if magic4 == magic::MACHO_FAT_LE {
        return DetectedFormat::MachOFat { big_endian: false };
    }

    // XCOFF
    if data.len() >= 2 {
        if data[..2] == magic::XCOFF_32 {
            return DetectedFormat::Xcoff { bits: 32 };
        }
        if data[..2] == magic::XCOFF_64 {
            return DetectedFormat::Xcoff { bits: 64 };
        }
    }

    // ECOFF
    if data.len() >= 2 {
        if data[..2] == magic::ECOFF_MIPS_LE {
            return DetectedFormat::Ecoff {
                variant: EcoffVariant::MipsLe,
            };
        }
        if data[..2] == magic::ECOFF_MIPS_BE {
            return DetectedFormat::Ecoff {
                variant: EcoffVariant::MipsBe,
            };
        }
        if data[..2] == magic::ECOFF_ALPHA {
            return DetectedFormat::Ecoff {
                variant: EcoffVariant::Alpha,
            };
        }
    }

    DetectedFormat::Raw
}

/// Parse a binary file and return classification result.
pub fn parse_binary(data: &[u8]) -> Result<ClassificationResult> {
    let format = detect_format(data);

    match format {
        DetectedFormat::Elf { class, endian } => elf::parse(data, class, endian),
        DetectedFormat::Pe { pe_offset } => pe::parse(data, pe_offset),
        DetectedFormat::MachO { bits, big_endian } => macho::parse(data, bits, big_endian),
        DetectedFormat::MachOFat { big_endian } => macho::parse_fat(data, big_endian),
        DetectedFormat::Xcoff { bits } => {
            // Basic XCOFF support - report as PowerPC
            use crate::types::{Endianness, Isa};
            let isa = if bits == 64 { Isa::Ppc64 } else { Isa::Ppc };
            Ok(ClassificationResult::from_format(
                isa,
                bits,
                Endianness::Big,
                FileFormat::Xcoff,
            ))
        }
        DetectedFormat::Ecoff { variant } => {
            use crate::types::{Endianness, Isa};
            let (isa, endian) = match variant {
                EcoffVariant::MipsLe => (Isa::Mips, Endianness::Little),
                EcoffVariant::MipsBe => (Isa::Mips, Endianness::Big),
                EcoffVariant::Alpha => (Isa::Alpha, Endianness::Little),
            };
            Ok(ClassificationResult::from_format(
                isa,
                if matches!(variant, EcoffVariant::Alpha) {
                    64
                } else {
                    32
                },
                endian,
                FileFormat::Ecoff,
            ))
        }
        DetectedFormat::Raw => raw::analyze(data),
    }
}

/// Read bytes with bounds checking.
pub fn read_bytes<'a>(data: &'a [u8], offset: usize, len: usize) -> Result<&'a [u8]> {
    if offset + len > data.len() {
        return Err(ClassifierError::TruncatedData {
            offset,
            expected: len,
            actual: data.len().saturating_sub(offset),
        });
    }
    Ok(&data[offset..offset + len])
}

/// Read a u16 with specified endianness.
pub fn read_u16(data: &[u8], offset: usize, little_endian: bool) -> Result<u16> {
    let bytes = read_bytes(data, offset, 2)?;
    Ok(if little_endian {
        u16::from_le_bytes([bytes[0], bytes[1]])
    } else {
        u16::from_be_bytes([bytes[0], bytes[1]])
    })
}

/// Read a u32 with specified endianness.
pub fn read_u32(data: &[u8], offset: usize, little_endian: bool) -> Result<u32> {
    let bytes = read_bytes(data, offset, 4)?;
    Ok(if little_endian {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    })
}

/// Read a u64 with specified endianness.
pub fn read_u64(data: &[u8], offset: usize, little_endian: bool) -> Result<u64> {
    let bytes = read_bytes(data, offset, 8)?;
    Ok(if little_endian {
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    } else {
        u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_elf() {
        let data = [0x7F, b'E', b'L', b'F', 2, 1, 0, 0];
        match detect_format(&data) {
            DetectedFormat::Elf { class: 2, endian: 1 } => {}
            _ => panic!("Expected ELF detection"),
        }
    }

    #[test]
    fn test_detect_macho() {
        let data = [0xCF, 0xFA, 0xED, 0xFE];
        match detect_format(&data) {
            DetectedFormat::MachO {
                bits: 64,
                big_endian: false,
            } => {}
            _ => panic!("Expected Mach-O 64 LE detection"),
        }
    }

    #[test]
    fn test_read_u32() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u32(&data, 0, true).unwrap(), 0x04030201);
        assert_eq!(read_u32(&data, 0, false).unwrap(), 0x01020304);
    }
}
