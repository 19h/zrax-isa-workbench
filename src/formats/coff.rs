//! Standalone COFF (Common Object File Format) parser.
//!
//! COFF is used for Windows object files (.obj) and some embedded systems.
//! Unlike PE files, standalone COFF files don't have a DOS stub or PE signature -
//! they start directly with the COFF header.
//!
//! Note: PE files contain an embedded COFF header, but PE parsing is handled
//! separately in `pe.rs`. This module handles standalone COFF files only.

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u16, read_u32};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// COFF machine type constants (same as PE).
pub mod machine {
    pub const UNKNOWN: u16 = 0x0000;
    pub const I386: u16 = 0x014C;
    pub const R3000: u16 = 0x0162;
    pub const R4000: u16 = 0x0166;
    pub const R10000: u16 = 0x0168;
    pub const WCEMIPSV2: u16 = 0x0169;
    pub const ALPHA: u16 = 0x0184;
    pub const SH3: u16 = 0x01A2;
    pub const SH3DSP: u16 = 0x01A3;
    pub const SH3E: u16 = 0x01A4;
    pub const SH4: u16 = 0x01A6;
    pub const SH5: u16 = 0x01A8;
    pub const ARM: u16 = 0x01C0;
    pub const THUMB: u16 = 0x01C2;
    pub const ARMNT: u16 = 0x01C4;
    pub const AM33: u16 = 0x01D3;
    pub const POWERPC: u16 = 0x01F0;
    pub const POWERPCFP: u16 = 0x01F1;
    pub const IA64: u16 = 0x0200;
    pub const MIPS16: u16 = 0x0266;
    pub const ALPHA64: u16 = 0x0284;
    pub const MIPSFPU: u16 = 0x0366;
    pub const MIPSFPU16: u16 = 0x0466;
    pub const TRICORE: u16 = 0x0520;
    pub const EBC: u16 = 0x0EBC;
    pub const RISCV32: u16 = 0x5032;
    pub const RISCV64: u16 = 0x5064;
    pub const RISCV128: u16 = 0x5128;
    pub const LOONGARCH32: u16 = 0x6232;
    pub const LOONGARCH64: u16 = 0x6264;
    pub const AMD64: u16 = 0x8664;
    pub const M32R: u16 = 0x9041;
    pub const ARM64: u16 = 0xAA64;

    // Legacy / vendor COFF machine values seen in IDA reference corpus
    pub const H8300_LEGACY: u16 = 0x0083;
    pub const H8300S_LEGACY: u16 = 0x0283;
    pub const TI_C54X: u16 = 0x00C1;
    pub const TI_C6X: u16 = 0x00C2;
    pub const ARM_THUMB_LEGACY: u16 = 0x0A00;
    pub const M68K_LEGACY_BE: u16 = 0x5001;
    pub const ADSP_21XX_LEGACY: u16 = 0x521C;
    pub const MIPS_LEGACY_BE: u16 = 0x6001;
    pub const Z8_LEGACY: u16 = 0x8000;
    pub const TI_C6X_SWAPPED: u16 = 0xC200;

    /// Check if a machine type is valid/known.
    pub fn is_valid(machine: u16) -> bool {
        matches!(
            machine,
            I386 | R3000
                | R4000
                | R10000
                | WCEMIPSV2
                | ALPHA
                | SH3
                | SH3DSP
                | SH3E
                | SH4
                | SH5
                | ARM
                | THUMB
                | ARMNT
                | AM33
                | POWERPC
                | POWERPCFP
                | IA64
                | MIPS16
                | ALPHA64
                | MIPSFPU
                | MIPSFPU16
                | TRICORE
                | EBC
                | RISCV32
                | RISCV64
                | RISCV128
                | LOONGARCH32
                | LOONGARCH64
                | AMD64
                | M32R
                | ARM64
                | H8300_LEGACY
                | H8300S_LEGACY
                | TI_C54X
                | TI_C6X
                | ARM_THUMB_LEGACY
                | M68K_LEGACY_BE
                | ADSP_21XX_LEGACY
                | MIPS_LEGACY_BE
                | Z8_LEGACY
                | TI_C6X_SWAPPED
        )
    }
}

/// COFF characteristics flags.
pub mod characteristics {
    /// Relocation information was stripped.
    pub const RELOCS_STRIPPED: u16 = 0x0001;
    /// File is executable (no unresolved external references).
    pub const EXECUTABLE_IMAGE: u16 = 0x0002;
    /// Line numbers were stripped.
    pub const LINE_NUMS_STRIPPED: u16 = 0x0004;
    /// Local symbols were stripped.
    pub const LOCAL_SYMS_STRIPPED: u16 = 0x0008;
    /// Aggressively trim working set (obsolete).
    pub const AGGRESSIVE_WS_TRIM: u16 = 0x0010;
    /// Application can handle addresses beyond 2GB.
    pub const LARGE_ADDRESS_AWARE: u16 = 0x0020;
    /// Bytes are reversed lo (obsolete).
    pub const BYTES_REVERSED_LO: u16 = 0x0080;
    /// Machine is 32-bit.
    pub const MACHINE_32BIT: u16 = 0x0100;
    /// Debugging information was stripped.
    pub const DEBUG_STRIPPED: u16 = 0x0200;
    /// If image is on removable media, copy and run from swap.
    pub const REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
    /// If image is on network media, copy and run from swap.
    pub const NET_RUN_FROM_SWAP: u16 = 0x0800;
    /// System file.
    pub const SYSTEM: u16 = 0x1000;
    /// File is a DLL.
    pub const DLL: u16 = 0x2000;
    /// Only run on uniprocessor machine.
    pub const UP_SYSTEM_ONLY: u16 = 0x4000;
    /// Bytes are reversed hi (obsolete).
    pub const BYTES_REVERSED_HI: u16 = 0x8000;
}

/// COFF file header size in bytes.
pub const COFF_HEADER_SIZE: usize = 20;

/// Maximum reasonable number of sections for validation.
///
/// Some COFF variants (notably Microsoft bigobj) can legitimately exceed 96.
pub const MAX_SECTIONS: u16 = 4096;

/// Section header size in bytes.
pub const SECTION_HEADER_SIZE: usize = 40;

/// COFF bigobj signature constants (Microsoft anonymous object header v2).
pub const BIGOBJ_SIG1: u16 = 0x0000;
pub const BIGOBJ_SIG2: u16 = 0xFFFF;
pub const BIGOBJ_HEADER_SIZE: usize = 56;

/// Check if data starts with a COFF bigobj header.
fn is_bigobj_header(data: &[u8]) -> bool {
    if data.len() < BIGOBJ_HEADER_SIZE {
        return false;
    }
    let sig1 = u16::from_le_bytes([data[0], data[1]]);
    let sig2 = u16::from_le_bytes([data[2], data[3]]);
    sig1 == BIGOBJ_SIG1 && sig2 == BIGOBJ_SIG2
}

/// Extract machine type from either standard COFF or bigobj header.
fn extract_machine(data: &[u8]) -> Option<u16> {
    if data.len() < 2 {
        return None;
    }
    if is_bigobj_header(data) {
        // Bigobj stores machine at offset 6 (2 bytes, little-endian)
        if data.len() < 8 {
            return None;
        }
        return Some(u16::from_le_bytes([data[6], data[7]]));
    }
    Some(u16::from_le_bytes([data[0], data[1]]))
}

/// Map COFF machine type to ISA.
pub fn machine_to_isa(machine: u16) -> (Isa, u8, Endianness, Option<&'static str>) {
    match machine {
        machine::UNKNOWN => (Isa::Unknown(0), 0, Endianness::Little, None),
        machine::I386 => (Isa::X86, 32, Endianness::Little, None),
        machine::R3000 => (Isa::Mips, 32, Endianness::Little, Some("R3000")),
        machine::R4000 => (Isa::Mips, 32, Endianness::Little, Some("R4000")),
        machine::R10000 => (Isa::Mips, 32, Endianness::Little, Some("R10000")),
        machine::WCEMIPSV2 => (Isa::Mips, 32, Endianness::Little, Some("WCE-v2")),
        machine::MIPS16 => (Isa::Mips, 32, Endianness::Little, Some("MIPS16")),
        machine::MIPSFPU => (Isa::Mips, 32, Endianness::Little, Some("FPU")),
        machine::MIPSFPU16 => (Isa::Mips, 32, Endianness::Little, Some("MIPS16-FPU")),
        machine::ALPHA => (Isa::Alpha, 64, Endianness::Little, None),
        machine::ALPHA64 => (Isa::Alpha, 64, Endianness::Little, Some("AXP64")),
        machine::SH3 => (Isa::Sh, 32, Endianness::Little, Some("SH-3")),
        machine::SH3DSP => (Isa::Sh, 32, Endianness::Little, Some("SH-3 DSP")),
        machine::SH3E => (Isa::Sh, 32, Endianness::Little, Some("SH-3E")),
        machine::SH4 => (Isa::Sh4, 32, Endianness::Little, Some("SH-4")),
        machine::SH5 => (Isa::Sh, 64, Endianness::Little, Some("SH-5")),
        machine::ARM => (Isa::Arm, 32, Endianness::Little, None),
        machine::THUMB => (Isa::Arm, 32, Endianness::Little, Some("Thumb")),
        machine::ARMNT => (Isa::Arm, 32, Endianness::Little, Some("Thumb-2")),
        machine::AM33 => (Isa::Unknown(0x01D3), 32, Endianness::Little, Some("AM33")),
        machine::POWERPC => (Isa::Ppc, 32, Endianness::Little, None),
        machine::POWERPCFP => (Isa::Ppc, 32, Endianness::Little, Some("FP")),
        machine::IA64 => (Isa::Ia64, 64, Endianness::Little, None),
        machine::TRICORE => (Isa::Tricore, 32, Endianness::Little, None),
        machine::EBC => (Isa::Ebc, 64, Endianness::Little, Some("EFI Byte Code")),
        machine::RISCV32 => (Isa::RiscV32, 32, Endianness::Little, None),
        machine::RISCV64 => (Isa::RiscV64, 64, Endianness::Little, None),
        machine::RISCV128 => (Isa::RiscV128, 128, Endianness::Little, None),
        machine::LOONGARCH32 => (Isa::LoongArch32, 32, Endianness::Little, None),
        machine::LOONGARCH64 => (Isa::LoongArch64, 64, Endianness::Little, None),
        machine::AMD64 => (Isa::X86_64, 64, Endianness::Little, None),
        machine::M32R => (Isa::Unknown(0x9041), 32, Endianness::Little, Some("M32R")),
        machine::ARM64 => (Isa::AArch64, 64, Endianness::Little, None),
        machine::H8300_LEGACY => (Isa::Sh, 32, Endianness::Big, Some("H8/300")),
        machine::H8300S_LEGACY => (Isa::Sh, 32, Endianness::Big, Some("H8S")),
        machine::TI_C54X => (Isa::TiC5500, 32, Endianness::Little, Some("TMS320C54x")),
        machine::TI_C6X | machine::TI_C6X_SWAPPED => {
            (Isa::TiC6000, 32, Endianness::Little, Some("TMS320C6x"))
        }
        machine::ARM_THUMB_LEGACY => (Isa::Arm, 32, Endianness::Little, Some("Thumb")),
        machine::M68K_LEGACY_BE => (Isa::M68k, 32, Endianness::Big, Some("68k COFF")),
        machine::ADSP_21XX_LEGACY => (Isa::Sharc, 32, Endianness::Little, Some("ADSP-21xx")),
        machine::MIPS_LEGACY_BE => (Isa::Mips, 32, Endianness::Big, Some("MIPS BE COFF")),
        machine::Z8_LEGACY => (Isa::Z80, 16, Endianness::Little, Some("Z8")),
        other => (Isa::Unknown(other as u32), 32, Endianness::Little, None),
    }
}

/// Check if data looks like a valid standalone COFF file.
///
/// Returns `Some(machine)` if it looks like COFF, `None` otherwise.
pub fn detect(data: &[u8]) -> Option<u16> {
    if data.len() < COFF_HEADER_SIZE {
        return None;
    }

    // Don't match PE files (they have MZ header)
    if data.len() >= 2 && &data[0..2] == b"MZ" {
        return None;
    }

    // Don't match ELF files
    if data.len() >= 4 && &data[0..4] == b"\x7FELF" {
        return None;
    }

    // Microsoft bigobj has a different header layout.
    if is_bigobj_header(data) {
        let machine = extract_machine(data)?;
        return machine::is_valid(machine).then_some(machine);
    }

    let machine = extract_machine(data)?;

    // Must be a known machine type
    if !machine::is_valid(machine) {
        return None;
    }

    let num_sections = u16::from_le_bytes([data[2], data[3]]);
    let ptr_symbol_table = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let num_symbols = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let size_opt_header = u16::from_le_bytes([data[16], data[17]]);
    let characteristics = u16::from_le_bytes([data[18], data[19]]);

    // Sanity checks
    // Number of sections should be reasonable
    if num_sections > MAX_SECTIONS {
        return None;
    }

    // Optional header size should be reasonable.
    // Keep permissive to handle malformed-but-identifiable corpus files.
    if size_opt_header > 8192 {
        return None;
    }

    // Reject obviously empty/random headers.
    if num_sections == 0
        && ptr_symbol_table == 0
        && num_symbols == 0
        && size_opt_header == 0
        && characteristics == 0
    {
        return None;
    }

    // If sections exist, the section table start should be representable in the file.
    // Don't require full table fit: malformed/truncated COFF files are still useful
    // for architecture identification by machine type.
    if num_sections > 0 {
        let section_table_start = COFF_HEADER_SIZE + size_opt_header as usize;
        if section_table_start > data.len() {
            return None;
        }
    }

    Some(machine)
}

/// Parse a standalone COFF file.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < COFF_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: COFF_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let is_bigobj = is_bigobj_header(data);
    if is_bigobj && data.len() < BIGOBJ_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: BIGOBJ_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let machine = extract_machine(data).unwrap_or(read_u16(data, 0, true)?);

    let (num_sections, num_symbols, characteristics) = if is_bigobj {
        // Bigobj stores these as 32-bit fields.
        let sec32 = read_u32(data, 44, true).unwrap_or(0);
        let syms = read_u32(data, 52, true).unwrap_or(0);
        (sec32.min(u16::MAX as u32) as u16, syms, 0u16)
    } else {
        let num_sections = read_u16(data, 2, true)?;
        let num_symbols = read_u32(data, 12, true)?;
        let characteristics = read_u16(data, 18, true)?;
        (num_sections, num_symbols, characteristics)
    };

    let (isa, bitwidth, endianness, variant_note) = machine_to_isa(machine);

    // Build variant
    let variant = match variant_note {
        Some(note) => Variant::new(note),
        None => Variant::default(),
    };

    // Collect notes
    let mut notes = if is_bigobj {
        vec!["Standalone COFF bigobj object file".to_string()]
    } else {
        vec!["Standalone COFF object file".to_string()]
    };

    if characteristics & characteristics::MACHINE_32BIT != 0 {
        notes.push("32-bit machine".to_string());
    }
    if characteristics & characteristics::LARGE_ADDRESS_AWARE != 0 {
        notes.push("Large address aware".to_string());
    }
    if characteristics & characteristics::DEBUG_STRIPPED != 0 {
        notes.push("Debug info stripped".to_string());
    }

    let metadata = ClassificationMetadata {
        section_count: Some(num_sections as usize),
        symbol_count: if num_symbols > 0 {
            Some(num_symbols as usize)
        } else {
            None
        },
        raw_machine: Some(machine as u32),
        notes,
        ..Default::default()
    };

    let mut result = ClassificationResult::from_format(isa, bitwidth, endianness, FileFormat::Coff);
    result.variant = variant;
    result.metadata = metadata;

    Ok(result)
}

/// Get a human-readable description of a COFF machine type.
pub fn machine_description(machine: u16) -> &'static str {
    match machine {
        machine::UNKNOWN => "Unknown machine",
        machine::I386 => "Intel 386 or later",
        machine::R3000 => "MIPS R3000",
        machine::R4000 => "MIPS R4000",
        machine::R10000 => "MIPS R10000",
        machine::WCEMIPSV2 => "MIPS WCE v2",
        machine::ALPHA => "DEC Alpha",
        machine::SH3 => "Hitachi SH-3",
        machine::SH3DSP => "Hitachi SH-3 DSP",
        machine::SH3E => "Hitachi SH-3E",
        machine::SH4 => "Hitachi SH-4",
        machine::SH5 => "Hitachi SH-5",
        machine::ARM => "ARM little endian",
        machine::THUMB => "ARM Thumb",
        machine::ARMNT => "ARM Thumb-2",
        machine::AM33 => "Matsushita AM33",
        machine::POWERPC => "PowerPC little endian",
        machine::POWERPCFP => "PowerPC with FPU",
        machine::IA64 => "Intel IA-64",
        machine::MIPS16 => "MIPS16",
        machine::ALPHA64 => "DEC Alpha 64-bit",
        machine::MIPSFPU => "MIPS with FPU",
        machine::MIPSFPU16 => "MIPS16 with FPU",
        machine::TRICORE => "Infineon TriCore",
        machine::EBC => "EFI Byte Code",
        machine::RISCV32 => "RISC-V 32-bit",
        machine::RISCV64 => "RISC-V 64-bit",
        machine::RISCV128 => "RISC-V 128-bit",
        machine::LOONGARCH32 => "LoongArch 32-bit",
        machine::LOONGARCH64 => "LoongArch 64-bit",
        machine::AMD64 => "AMD64 / x86-64",
        machine::M32R => "Mitsubishi M32R",
        machine::ARM64 => "ARM64 / AArch64",
        machine::H8300_LEGACY => "Hitachi H8/300 (legacy)",
        machine::H8300S_LEGACY => "Hitachi H8S (legacy)",
        machine::TI_C54X => "Texas Instruments TMS320C54x",
        machine::TI_C6X => "Texas Instruments TMS320C6x",
        machine::ARM_THUMB_LEGACY => "ARM Thumb (legacy)",
        machine::M68K_LEGACY_BE => "Motorola 68k (legacy COFF)",
        machine::ADSP_21XX_LEGACY => "Analog Devices ADSP-21xx",
        machine::MIPS_LEGACY_BE => "MIPS (legacy big-endian COFF)",
        machine::Z8_LEGACY => "Zilog Z8",
        machine::TI_C6X_SWAPPED => "Texas Instruments TMS320C6x (swapped)",
        _ => "Unknown machine type",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_coff_header(machine: u16, num_sections: u16) -> Vec<u8> {
        // Calculate required size: header + section headers + some space for symbols
        let min_size = COFF_HEADER_SIZE + (num_sections as usize * SECTION_HEADER_SIZE) + 256;
        let mut data = vec![0u8; min_size];

        // Machine
        data[0] = (machine & 0xFF) as u8;
        data[1] = (machine >> 8) as u8;

        // Number of sections
        data[2] = (num_sections & 0xFF) as u8;
        data[3] = (num_sections >> 8) as u8;

        // Timestamp
        data[4..8].copy_from_slice(&0x12345678u32.to_le_bytes());

        // Pointer to symbol table (after headers)
        let sym_offset = COFF_HEADER_SIZE + (num_sections as usize * SECTION_HEADER_SIZE);
        data[8..12].copy_from_slice(&(sym_offset as u32).to_le_bytes());

        // Number of symbols
        data[12..16].copy_from_slice(&10u32.to_le_bytes());

        // Size of optional header (0 for object files)
        data[16] = 0;
        data[17] = 0;

        // Characteristics
        data[18] = characteristics::MACHINE_32BIT as u8;
        data[19] = 0;

        data
    }

    #[test]
    fn test_detect_x86_coff() {
        let data = make_coff_header(machine::I386, 3);
        assert_eq!(detect(&data), Some(machine::I386));
    }

    #[test]
    fn test_detect_x64_coff() {
        let data = make_coff_header(machine::AMD64, 5);
        assert_eq!(detect(&data), Some(machine::AMD64));
    }

    #[test]
    fn test_detect_arm64_coff() {
        let data = make_coff_header(machine::ARM64, 2);
        assert_eq!(detect(&data), Some(machine::ARM64));
    }

    #[test]
    fn test_reject_pe() {
        let mut data = make_coff_header(machine::AMD64, 3);
        data[0] = b'M';
        data[1] = b'Z';
        assert_eq!(detect(&data), None);
    }

    #[test]
    fn test_reject_elf() {
        let mut data = make_coff_header(machine::AMD64, 3);
        data[0..4].copy_from_slice(b"\x7FELF");
        assert_eq!(detect(&data), None);
    }

    #[test]
    fn test_parse_x86_coff() {
        let data = make_coff_header(machine::I386, 3);
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::X86);
        assert_eq!(result.bitwidth, 32);
        assert_eq!(result.format, FileFormat::Coff);
    }

    #[test]
    fn test_parse_x64_coff() {
        let data = make_coff_header(machine::AMD64, 5);
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::X86_64);
        assert_eq!(result.bitwidth, 64);
        assert_eq!(result.format, FileFormat::Coff);
    }

    #[test]
    fn test_machine_coverage() {
        assert_eq!(machine_to_isa(machine::I386).0, Isa::X86);
        assert_eq!(machine_to_isa(machine::AMD64).0, Isa::X86_64);
        assert_eq!(machine_to_isa(machine::ARM64).0, Isa::AArch64);
        assert_eq!(machine_to_isa(machine::RISCV64).0, Isa::RiscV64);
    }
}
