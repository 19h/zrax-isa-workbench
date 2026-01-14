//! Binary file format parsers.
//!
//! This module provides parsers for various executable file formats:
//! - ELF (Executable and Linkable Format)
//! - PE/COFF (Portable Executable)
//! - Mach-O (Mach Object)
//! - COFF (Standalone Common Object File Format)
//! - XCOFF (AIX Extended COFF)
//! - ECOFF (Extended COFF for MIPS/Alpha)
//! - a.out (BSD, Plan 9, Minix)
//! - MZ/NE/LE/LX (DOS and OS/2)
//! - PEF (Classic Mac OS)
//! - WebAssembly
//! - Java class files
//! - DEX/ODEX/VDEX/ART (Android)
//! - Game console formats (XBE, XEX, SELF, NSO, DOL)
//! - Boot/kernel images (zImage, uImage, FIT)
//! - Hex formats (Intel HEX, S-record, TI-TXT)
//! - Archive formats (ar)
//! - Raw binary analysis

pub mod aout;
pub mod ar;
pub mod bflt;
pub mod coff;
pub mod console;
pub mod dex;
pub mod ecoff;
pub mod elf;
pub mod fatelf;
pub mod goff;
pub mod hex;
pub mod java;
pub mod kernel;
pub mod llvm_bc;
pub mod macho;
pub mod mz;
pub mod pe;
pub mod pef;
pub mod raw;
pub mod wasm;
pub mod xcoff;

use crate::error::{ClassifierError, Result};
use crate::types::ClassificationResult;

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

    /// ECOFF MIPS little-endian (magic 0x0160 stored as LE)
    pub const ECOFF_MIPS_LE: [u8; 2] = [0x60, 0x01];

    /// ECOFF MIPS big-endian (magic 0x0160 stored as BE)
    pub const ECOFF_MIPS_BE: [u8; 2] = [0x01, 0x60];

    /// ECOFF Alpha (magic 0x0183 stored as LE)
    pub const ECOFF_ALPHA: [u8; 2] = [0x83, 0x01];

    /// WebAssembly magic: "\0asm"
    pub const WASM: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

    /// Java class file magic: 0xCAFEBABE
    pub const JAVA_CLASS: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

    /// DEX magic: "dex\n"
    pub const DEX: [u8; 4] = [b'd', b'e', b'x', b'\n'];

    /// bFLT magic: "bFLT"
    pub const BFLT: [u8; 4] = [b'b', b'F', b'L', b'T'];

    /// PEF magic: "Joy!" + "peff"
    pub const PEF_TAG1: [u8; 4] = [b'J', b'o', b'y', b'!'];

    /// ar archive magic: "!<arch>\n"
    pub const AR: [u8; 8] = [b'!', b'<', b'a', b'r', b'c', b'h', b'>', b'\n'];

    /// U-Boot uImage magic
    pub const UIMAGE: u32 = 0x27051956;

    /// FDT/DTB magic
    pub const FDT: u32 = 0xD00DFEED;

    /// XBE (Xbox) magic: "XBEH"
    pub const XBE: [u8; 4] = [b'X', b'B', b'E', b'H'];

    /// XEX (Xbox 360) magic: "XEX2"
    pub const XEX: [u8; 4] = [b'X', b'E', b'X', b'2'];

    /// NSO (Switch) magic: "NSO0"
    pub const NSO: [u8; 4] = [b'N', b'S', b'O', b'0'];

    /// PS3 SELF magic: "SCE\0"
    pub const PS3_SELF: [u8; 4] = [b'S', b'C', b'E', 0];

    /// FatELF magic
    pub const FATELF: u32 = 0x1F0E70FA;

    /// GOFF record marker
    pub const GOFF: u8 = 0x03;

    /// LLVM bitcode magic: "BC" + 0xC0DE
    pub const LLVM_BC: [u8; 4] = [b'B', b'C', 0xC0, 0xDE];
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
    /// Standalone COFF (Windows object files)
    Coff { machine: u16 },
    /// XCOFF (AIX)
    Xcoff { bits: u8 },
    /// ECOFF
    Ecoff { variant: ecoff::EcoffVariant },
    /// a.out (BSD, Plan 9, Minix)
    Aout { variant: aout::AoutVariant },
    /// DOS MZ / NE / LE / LX
    Mz { variant: mz::ExtendedType },
    /// PEF (Classic Mac OS)
    Pef,
    /// WebAssembly
    Wasm,
    /// Java class file
    JavaClass,
    /// DEX/ODEX/VDEX/ART (Android)
    Dex { variant: dex::DexVariant },
    /// bFLT (uClinux)
    Bflt,
    /// Game console formats
    Console { variant: console::ConsoleFormat },
    /// Kernel/boot images
    Kernel { variant: kernel::KernelFormat },
    /// ar archive
    Ar { variant: ar::ArVariant },
    /// Intel HEX / S-record / TI-TXT
    Hex { variant: hex::HexVariant },
    /// GOFF (IBM z/Architecture)
    Goff,
    /// LLVM bitcode
    LlvmBc { variant: llvm_bc::LlvmVariant },
    /// FatELF multi-architecture
    FatElf,
    /// Unknown/raw format
    Raw,
}

/// Detect the file format from magic bytes.
pub fn detect_format(data: &[u8]) -> DetectedFormat {
    if data.len() < 4 {
        // Check for text-based hex formats (can work with minimal data)
        if let Some(variant) = hex::detect(data) {
            return DetectedFormat::Hex { variant };
        }
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

    // FatELF (check before Mach-O since magic could conflict)
    if fatelf::detect(data) {
        return DetectedFormat::FatElf;
    }

    // PE/COFF - check for PE first, then fall through to MZ/NE/LE/LX
    if data.len() >= 2 && data[..2] == magic::MZ {
        if data.len() >= 0x40 {
            let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
            let pe_off = pe_offset as usize;
            if pe_off + 4 <= data.len() && data[pe_off..pe_off + 4] == magic::PE {
                return DetectedFormat::Pe { pe_offset };
            }
        }
        // Not PE, try MZ/NE/LE/LX
        if let Some(variant) = mz::detect(data) {
            return DetectedFormat::Mz { variant };
        }
    }

    // Mach-O (check before Java class since 0xCAFEBABE conflicts with fat binary)
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
    // Mach-O fat uses 0xCAFEBABE which conflicts with Java class files
    // Differentiate by checking if it looks like valid fat header
    if magic4 == magic::MACHO_FAT_BE {
        // Check if it's a valid Mach-O fat binary vs Java class
        if data.len() >= 8 {
            let nfat_arch = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            // Java class files have minor/major version here (usually small numbers like 0, 52-65)
            // Mach-O fat binaries have nfat_arch (usually 1-4)
            // If nfat_arch is reasonable and followed by valid fat arch entries, it's Mach-O
            if nfat_arch > 0 && nfat_arch <= 20 {
                // Further check: see if we have enough data for fat_arch entries
                let fat_arch_size = 20; // Each fat_arch is 20 bytes
                if data.len() >= 8 + (nfat_arch as usize * fat_arch_size) {
                    // Check if first fat_arch looks valid (cputype should be reasonable)
                    let cputype = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                    // Valid cputypes are typically 7, 12, 18, 0x01000007, 0x0100000c, etc.
                    if cputype > 0 && (cputype < 100 || cputype > 0x01000000) {
                        return DetectedFormat::MachOFat { big_endian: true };
                    }
                }
            }
        }
        // Fall through to check for Java class
    }
    if magic4 == magic::MACHO_FAT_LE {
        return DetectedFormat::MachOFat { big_endian: false };
    }

    // Java class (after Mach-O fat check since 0xCAFEBABE conflicts)
    if java::detect(data) {
        return DetectedFormat::JavaClass;
    }

    // WebAssembly
    if wasm::detect(data) {
        return DetectedFormat::Wasm;
    }

    // DEX/ODEX/VDEX/ART (Android)
    if let Some(variant) = dex::detect(data) {
        return DetectedFormat::Dex { variant };
    }

    // PEF (Classic Mac OS)
    if pef::detect(data) {
        return DetectedFormat::Pef;
    }

    // bFLT (uClinux)
    if bflt::detect(data) {
        return DetectedFormat::Bflt;
    }

    // LLVM bitcode
    if let Some(variant) = llvm_bc::detect(data) {
        return DetectedFormat::LlvmBc { variant };
    }

    // ar archive
    if let Some(variant) = ar::detect(data) {
        return DetectedFormat::Ar { variant };
    }

    // Game console formats
    if let Some(variant) = console::detect(data) {
        return DetectedFormat::Console { variant };
    }

    // Kernel/boot images
    if let Some(variant) = kernel::detect(data) {
        return DetectedFormat::Kernel { variant };
    }

    // GOFF (IBM z/Architecture) - check before generic COFF
    if goff::detect(data) {
        return DetectedFormat::Goff;
    }

    // a.out (BSD, Plan 9, Minix)
    if let Some(variant) = aout::detect(data) {
        return DetectedFormat::Aout { variant };
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

    // ECOFF (check before standalone COFF since ECOFF has specific magic)
    if let Some(variant) = ecoff::detect(data) {
        return DetectedFormat::Ecoff { variant };
    }

    // Text-based hex formats (Intel HEX, S-record, TI-TXT)
    if let Some(variant) = hex::detect(data) {
        return DetectedFormat::Hex { variant };
    }

    // Standalone COFF (Windows object files)
    // Must be checked after other formats since COFF detection is heuristic-based
    if let Some(machine) = coff::detect(data) {
        return DetectedFormat::Coff { machine };
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
        DetectedFormat::Coff { machine: _ } => coff::parse(data),
        DetectedFormat::Xcoff { bits } => xcoff::parse(data, bits),
        DetectedFormat::Ecoff { variant } => ecoff::parse(data, variant),
        DetectedFormat::Aout { variant } => aout::parse(data, variant),
        DetectedFormat::Mz { variant } => mz::parse(data, variant),
        DetectedFormat::Pef => pef::parse(data),
        DetectedFormat::Wasm => wasm::parse(data),
        DetectedFormat::JavaClass => java::parse(data),
        DetectedFormat::Dex { variant } => dex::parse(data, variant),
        DetectedFormat::Bflt => bflt::parse(data),
        DetectedFormat::Console { variant } => console::parse(data, variant),
        DetectedFormat::Kernel { variant } => kernel::parse(data, variant),
        DetectedFormat::Ar { variant } => ar::parse(data, variant),
        DetectedFormat::Hex { variant } => hex::parse(data, variant),
        DetectedFormat::Goff => goff::parse(data),
        DetectedFormat::LlvmBc { variant } => llvm_bc::parse(data, variant),
        DetectedFormat::FatElf => fatelf::parse(data),
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

    #[test]
    fn test_detect_wasm() {
        let data = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        match detect_format(&data) {
            DetectedFormat::Wasm => {}
            other => panic!("Expected Wasm, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_java_class() {
        // Java class file magic 0xCAFEBABE followed by valid version
        let data = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34];
        match detect_format(&data) {
            DetectedFormat::JavaClass => {}
            other => panic!("Expected JavaClass, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_dex() {
        let data = [b'd', b'e', b'x', b'\n', b'0', b'3', b'5', 0x00];
        match detect_format(&data) {
            DetectedFormat::Dex { variant: dex::DexVariant::Dex { .. } } => {}
            other => panic!("Expected Dex, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_pef() {
        // "Joy!" + "peff"
        let data = [b'J', b'o', b'y', b'!', b'p', b'e', b'f', b'f', 0, 0, 0, 0];
        match detect_format(&data) {
            DetectedFormat::Pef => {}
            other => panic!("Expected Pef, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_bflt() {
        let data = [b'b', b'F', b'L', b'T', 0, 0, 0, 4];
        match detect_format(&data) {
            DetectedFormat::Bflt => {}
            other => panic!("Expected Bflt, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_ar() {
        let data = [b'!', b'<', b'a', b'r', b'c', b'h', b'>', b'\n'];
        match detect_format(&data) {
            DetectedFormat::Ar { .. } => {}
            other => panic!("Expected Ar, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_llvm_bc() {
        let data = [b'B', b'C', 0xC0, 0xDE, 0, 0, 0, 0];
        match detect_format(&data) {
            DetectedFormat::LlvmBc { variant: llvm_bc::LlvmVariant::Bitcode } => {}
            other => panic!("Expected LlvmBc Bitcode, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_console_xbe() {
        let data = [b'X', b'B', b'E', b'H', 0, 0, 0, 0];
        match detect_format(&data) {
            DetectedFormat::Console { variant: console::ConsoleFormat::Xbe } => {}
            other => panic!("Expected Console Xbe, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_console_nso() {
        let data = [b'N', b'S', b'O', b'0', 0, 0, 0, 0];
        match detect_format(&data) {
            DetectedFormat::Console { variant: console::ConsoleFormat::Nso } => {}
            other => panic!("Expected Console Nso, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_intel_hex() {
        let data = b":020000040800F2\r\n:1000000000";
        match detect_format(data) {
            DetectedFormat::Hex { variant: hex::HexVariant::IntelHex { .. } } => {}
            other => panic!("Expected Intel HEX, got {:?}", other),
        }
    }

    #[test]
    fn test_detect_srec() {
        let data = b"S00600004844521B\r\n";
        match detect_format(data) {
            DetectedFormat::Hex { variant: hex::HexVariant::Srec { .. } } => {}
            other => panic!("Expected S-record, got {:?}", other),
        }
    }
}
