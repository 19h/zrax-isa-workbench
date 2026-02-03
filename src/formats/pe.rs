//! PE/COFF (Portable Executable) parser.
//!
//! Comprehensive PE parser supporting all machine types including
//! modern architectures like ARM64, ARM64EC, and RISC-V.

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u16, read_u32};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// PE machine type constants.
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
    pub const ARM64EC: u16 = 0xA641;
    pub const ARM64X: u16 = 0xA64E;
    pub const ARM64: u16 = 0xAA64;
}

/// Map PE machine type to ISA.
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

        machine::TRICORE => (
            Isa::Unknown(0x0520),
            32,
            Endianness::Little,
            Some("TriCore"),
        ),

        machine::EBC => (
            Isa::Unknown(0x0EBC),
            64,
            Endianness::Little,
            Some("EFI Byte Code"),
        ),

        machine::RISCV32 => (Isa::RiscV32, 32, Endianness::Little, None),
        machine::RISCV64 => (Isa::RiscV64, 64, Endianness::Little, None),
        machine::RISCV128 => (Isa::RiscV128, 128, Endianness::Little, None),

        machine::LOONGARCH32 => (Isa::LoongArch32, 32, Endianness::Little, None),
        machine::LOONGARCH64 => (Isa::LoongArch64, 64, Endianness::Little, None),

        machine::AMD64 => (Isa::X86_64, 64, Endianness::Little, None),

        machine::M32R => (Isa::Unknown(0x9041), 32, Endianness::Little, Some("M32R")),

        machine::ARM64EC => (Isa::AArch64, 64, Endianness::Little, Some("ARM64EC")),
        machine::ARM64X => (Isa::AArch64, 64, Endianness::Little, Some("ARM64X")),
        machine::ARM64 => (Isa::AArch64, 64, Endianness::Little, None),

        other => (Isa::Unknown(other as u32), 32, Endianness::Little, None),
    }
}

/// PE optional header magic values.
pub mod optional_magic {
    pub const PE32: u16 = 0x10B;
    pub const PE32PLUS: u16 = 0x20B;
    pub const ROM: u16 = 0x107;
}

/// Parse PE/COFF file.
pub fn parse(data: &[u8], pe_offset: u32) -> Result<ClassificationResult> {
    let pe_off = pe_offset as usize;

    // Verify PE signature
    if pe_off + 4 > data.len() {
        return Err(ClassifierError::TruncatedData {
            offset: pe_off,
            expected: 4,
            actual: data.len().saturating_sub(pe_off),
        });
    }

    if &data[pe_off..pe_off + 4] != b"PE\x00\x00" {
        return Err(ClassifierError::InvalidMagic {
            expected: "PE\\0\\0".to_string(),
            actual: format!("{:02X?}", &data[pe_off..pe_off + 4]),
        });
    }

    // COFF header starts at PE + 4
    let coff_off = pe_off + 4;

    if coff_off + 20 > data.len() {
        return Err(ClassifierError::TruncatedData {
            offset: coff_off,
            expected: 20,
            actual: data.len().saturating_sub(coff_off),
        });
    }

    // Read COFF header fields
    let machine = read_u16(data, coff_off, true)?;
    let num_sections = read_u16(data, coff_off + 2, true)?;
    let size_of_optional = read_u16(data, coff_off + 16, true)?;

    // Map machine to ISA
    let (isa, bitwidth, endianness, variant_note) = machine_to_isa(machine);

    // Read optional header if present
    let mut entry_point = None;
    let mut is_pe32plus = false;

    if size_of_optional > 0 {
        let opt_off = coff_off + 20;
        if opt_off + 2 <= data.len() {
            let magic = read_u16(data, opt_off, true)?;
            is_pe32plus = magic == optional_magic::PE32PLUS;

            // Entry point is at different offset based on format
            if opt_off + 24 <= data.len() {
                let ep = read_u32(data, opt_off + 16, true)?;
                entry_point = Some(ep as u64);
            }
        }
    }

    // Determine actual bitwidth from PE32+
    let actual_bitwidth = if is_pe32plus && bitwidth < 64 {
        64
    } else {
        bitwidth
    };

    // Build variant
    let variant = match variant_note {
        Some(note) => Variant::new(note),
        None => Variant::default(),
    };

    // Build metadata
    let metadata = ClassificationMetadata {
        entry_point,
        section_count: Some(num_sections as usize),
        raw_machine: Some(machine as u32),
        notes: if is_pe32plus {
            vec!["PE32+ format".to_string()]
        } else {
            vec!["PE32 format".to_string()]
        },
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(isa, actual_bitwidth, endianness, FileFormat::Pe);
    result.variant = variant;
    result.metadata = metadata;

    Ok(result)
}

/// Get a human-readable description of a PE machine type.
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
        machine::ARMNT => "ARM Thumb-2 (WinRT)",
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
        machine::ARM64EC => "ARM64EC (x64 emulation)",
        machine::ARM64X => "ARM64X (hybrid)",
        machine::ARM64 => "ARM64 / AArch64",
        _ => "Unknown machine type",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pe_header(machine: u16) -> Vec<u8> {
        let mut data = vec![0u8; 256];

        // DOS stub
        data[0] = b'M';
        data[1] = b'Z';

        // PE offset at 0x3C
        data[0x3C] = 0x80;

        // PE signature at 0x80
        let pe_off = 0x80;
        data[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");

        // COFF header
        let coff_off = pe_off + 4;
        data[coff_off] = (machine & 0xFF) as u8;
        data[coff_off + 1] = (machine >> 8) as u8;

        // Number of sections
        data[coff_off + 2] = 3;

        // Size of optional header
        data[coff_off + 16] = 0xF0;

        // Optional header magic (PE32+)
        let opt_off = coff_off + 20;
        data[opt_off] = 0x0B;
        data[opt_off + 1] = 0x02;

        data
    }

    #[test]
    fn test_parse_x64_pe() {
        let data = make_pe_header(machine::AMD64);
        let result = parse(&data, 0x80).unwrap();
        assert_eq!(result.isa, Isa::X86_64);
        assert_eq!(result.bitwidth, 64);
    }

    #[test]
    fn test_parse_arm64_pe() {
        let data = make_pe_header(machine::ARM64);
        let result = parse(&data, 0x80).unwrap();
        assert_eq!(result.isa, Isa::AArch64);
        assert_eq!(result.bitwidth, 64);
    }

    #[test]
    fn test_parse_arm64ec_pe() {
        let data = make_pe_header(machine::ARM64EC);
        let result = parse(&data, 0x80).unwrap();
        assert_eq!(result.isa, Isa::AArch64);
        assert!(result.variant.name.contains("ARM64EC"));
    }

    #[test]
    fn test_parse_riscv_pe() {
        let data = make_pe_header(machine::RISCV64);
        let result = parse(&data, 0x80).unwrap();
        assert_eq!(result.isa, Isa::RiscV64);
    }

    #[test]
    fn test_machine_coverage() {
        assert_eq!(machine_to_isa(machine::I386).0, Isa::X86);
        assert_eq!(machine_to_isa(machine::AMD64).0, Isa::X86_64);
        assert_eq!(machine_to_isa(machine::ARM).0, Isa::Arm);
        assert_eq!(machine_to_isa(machine::ARM64).0, Isa::AArch64);
        assert_eq!(machine_to_isa(machine::RISCV32).0, Isa::RiscV32);
        assert_eq!(machine_to_isa(machine::RISCV64).0, Isa::RiscV64);
        assert_eq!(machine_to_isa(machine::LOONGARCH64).0, Isa::LoongArch64);
    }
}
