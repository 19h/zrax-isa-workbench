//! Architecture-specific analysis and utilities.
//!
//! This module provides detailed analysis capabilities for each
//! supported ISA, including instruction decoding helpers and
//! architecture-specific constants.

pub mod aarch64;
pub mod alpha;
pub mod arc;
pub mod arm;
pub mod avr;
pub mod blackfin;
pub mod c166;
pub mod cellspu;
pub mod dalvik;
pub mod fr30;
pub mod hc11;
pub mod hcs12;
pub mod hexagon;
pub mod i860;
pub mod ia64;
pub mod jvm;
pub mod lanai;
pub mod loongarch;
pub mod m68k;
pub mod microblaze;
pub mod mips;
pub mod msp430;
pub mod nios2;
pub mod openrisc;
pub mod parisc;
pub mod ppc;
pub mod ppcvle;
pub mod riscv;
pub mod rl78;
pub mod s12z;
pub mod s390x;
pub mod sparc;
pub mod superh;
pub mod tricore;
pub mod v850;
pub mod vax;
pub mod wasm;
pub mod x86;
pub mod xtensa;

use crate::types::{Endianness, Isa};

/// Get the default endianness for an ISA.
pub fn default_endianness(isa: Isa) -> Endianness {
    match isa {
        // Little-endian by default
        Isa::X86 | Isa::X86_64 => Endianness::Little,
        Isa::AArch64 => Endianness::Little,
        Isa::RiscV32 | Isa::RiscV64 | Isa::RiscV128 => Endianness::Little,
        Isa::Alpha => Endianness::Little,
        Isa::LoongArch32 | Isa::LoongArch64 => Endianness::Little,
        Isa::Hexagon => Endianness::Little,
        Isa::Tricore => Endianness::Little,
        Isa::Hcs12 => Endianness::Big, // Motorola architecture — big-endian
        Isa::Hc11 => Endianness::Big,  // Motorola 68HC11 — big-endian
        Isa::C166 => Endianness::Little, // Infineon/Siemens C166 — little-endian
        Isa::Rl78 => Endianness::Little, // Renesas RL78 — little-endian
        Isa::V850 => Endianness::Little, // Renesas/NEC V850 — little-endian
        Isa::Rh850 => Endianness::Little, // Renesas RH850 — little-endian
        Isa::K78k0r => Endianness::Little, // NEC 78K0R — little-endian
        Isa::Bpf => Endianness::Little,
        Isa::Cuda => Endianness::Little,
        Isa::AmdGpu => Endianness::Little,
        Isa::Wasm => Endianness::Little, // WASM is little-endian

        // Big-endian by default
        Isa::Ppc | Isa::Ppc64 => Endianness::Big,
        Isa::PpcVle => Endianness::Big,
        Isa::Sparc | Isa::Sparc64 => Endianness::Big,
        Isa::S390 | Isa::S390x => Endianness::Big,
        Isa::M68k | Isa::ColdFire => Endianness::Big,
        Isa::Parisc => Endianness::Big,
        Isa::Lanai => Endianness::Big,
        Isa::McstElbrus => Endianness::Big,
        Isa::Jvm => Endianness::Big,         // JVM is big-endian
        Isa::Dalvik => Endianness::Little,   // DEX is little-endian
        Isa::Blackfin => Endianness::Little, // Blackfin is little-endian
        Isa::Ia64 => Endianness::Little,     // Itanium is little-endian
        Isa::Vax => Endianness::Little,      // VAX is little-endian
        Isa::I860 => Endianness::Little,     // i860 is little-endian
        Isa::CellSpu => Endianness::Big,     // Cell SPU is big-endian

        // Bi-endian (default to little)
        Isa::Arm => Endianness::Little,
        Isa::Mips | Isa::Mips64 => Endianness::Big, // Traditionally big
        Isa::Sh | Isa::Sh4 => Endianness::Little,

        // 8/16-bit micros
        Isa::Avr => Endianness::Little,
        Isa::Msp430 => Endianness::Little,
        Isa::Z80 => Endianness::Little,
        Isa::Mcs6502 => Endianness::Little,
        Isa::W65816 => Endianness::Little,
        Isa::Pic => Endianness::Little,
        Isa::Stm8 => Endianness::Big,
        Isa::S12z => Endianness::Big,

        // Other/Unknown
        _ => Endianness::Little,
    }
}

/// Get the typical instruction alignment for an ISA.
pub fn instruction_alignment(isa: Isa) -> usize {
    match isa {
        // Variable-length, byte-aligned
        Isa::X86 | Isa::X86_64 => 1,
        Isa::S390 | Isa::S390x => 2,
        Isa::M68k | Isa::ColdFire => 2,
        Isa::Z80 | Isa::Mcs6502 | Isa::W65816 => 1,
        Isa::Jvm => 1,      // JVM bytecode is byte-aligned
        Isa::Wasm => 1,     // WASM bytecode is byte-aligned
        Isa::Dalvik => 2,   // DEX bytecode is 2-byte aligned
        Isa::Vax => 1,      // VAX is byte-aligned (variable 1-37 bytes)
        Isa::Blackfin => 2, // Blackfin is 16-bit aligned (variable 16/32/64-bit)

        // Fixed 32-bit, 4-byte aligned
        Isa::Arm => 4,
        Isa::AArch64 => 4,
        Isa::Mips | Isa::Mips64 => 4,
        Isa::Ppc | Isa::Ppc64 => 4,
        Isa::Sparc | Isa::Sparc64 => 4,
        Isa::Alpha => 4,
        Isa::Parisc => 4,
        Isa::I860 => 4, // i860 is 32-bit fixed
        Isa::Lanai => 4,
        Isa::CellSpu => 4, // Cell SPU is 32-bit fixed
        Isa::Ia64 => 16,   // IA-64 bundles are 128-bit (16-byte) aligned
        Isa::LoongArch32 | Isa::LoongArch64 => 4,
        Isa::Hexagon => 4,

        // Mixed (compressed instructions)
        Isa::RiscV32 | Isa::RiscV64 | Isa::RiscV128 => 2, // 2-byte for C extension
        Isa::Sh | Isa::Sh4 => 2,

        // 16-bit aligned
        Isa::Avr => 2,
        Isa::Msp430 => 2,
        Isa::Tricore => 2, // TriCore has 16/32-bit instructions (16-bit aligned)
        Isa::Hcs12 => 1,   // HC12/HCS12X has variable-length instructions (1-8 bytes), byte-aligned
        Isa::S12z => 1,    // S12Z has variable-length instructions, byte-aligned
        Isa::Hc11 => 1,    // 68HC11 has variable-length instructions (1-5 bytes), byte-aligned
        Isa::Rl78 => 1,    // RL78 has variable-length instructions (1-4 bytes), byte-aligned
        Isa::V850 => 2,    // V850 has 16-bit and 32-bit instructions, 2-byte aligned
        Isa::Rh850 => 2,   // RH850 inherits V850-style 16/32-bit alignment
        Isa::PpcVle => 2,  // VLE supports 16-bit and 32-bit encodings

        _ => 4,
    }
}

/// Check if an ISA supports compressed/variable-length instructions.
pub fn supports_compressed(isa: Isa) -> bool {
    matches!(
        isa,
        Isa::X86
            | Isa::X86_64
            | Isa::RiscV32
            | Isa::RiscV64
            | Isa::RiscV128
            | Isa::S390
            | Isa::S390x
            | Isa::M68k
            | Isa::ColdFire
            | Isa::Sh
            | Isa::Sh4
            | Isa::Avr
            | Isa::Msp430
            | Isa::Xtensa
            | Isa::Jvm     // JVM has variable-length bytecode
            | Isa::Wasm    // WASM has variable-length bytecode (LEB128)
            | Isa::Dalvik  // DEX has variable-length bytecode
            | Isa::Vax     // VAX has variable-length CISC (1-37 bytes)
            | Isa::Blackfin // Blackfin has variable-length (16/32/64-bit)
            | Isa::Hcs12 // HC12/HCS12X has variable-length instructions (1-8 bytes)
            | Isa::S12z  // S12Z has variable-length instructions
            | Isa::Hc11  // 68HC11 has variable-length instructions (1-5 bytes)
            | Isa::Rl78  // RL78 has variable-length instructions (1-4 bytes)
            | Isa::V850  // V850 has 16/32-bit instructions
            | Isa::Rh850 // RH850 has 16/32-bit instructions
            | Isa::K78k0r // 78K0R has variable-length instructions
            | Isa::PpcVle // PowerPC VLE has 16/32-bit instructions
    )
}

/// Get the register width for an ISA.
pub fn register_width(isa: Isa) -> u8 {
    isa.default_bitwidth()
}

/// Common instruction patterns across architectures.
pub mod patterns {
    /// Generic NOP detection
    pub fn is_likely_nop(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }

        // Common NOP patterns
        match bytes.len() {
            1 => bytes[0] == 0x90, // x86 NOP
            2 => {
                let w = u16::from_le_bytes([bytes[0], bytes[1]]);
                w == 0x4E71    // m68k NOP
                    || w == 0x0009 // SuperH NOP
                    || w == 0xBF00 // Thumb NOP
                    || w == 0x0001 // RISC-V C.NOP
            }
            4 => {
                let le = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                let be = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

                le == 0xD503201F    // AArch64 NOP
                    || le == 0x00000013 // RISC-V NOP
                    || le == 0xE1A00000 // ARM NOP
                    || be == 0x00000000 // MIPS NOP
                    || be == 0x60000000 // PowerPC NOP
                    || be == 0x01000000 // SPARC NOP
            }
            _ => false,
        }
    }

    /// Generic RET detection
    pub fn is_likely_ret(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }

        match bytes.len() {
            1 => bytes[0] == 0xC3, // x86 RET
            2 => {
                let w = u16::from_le_bytes([bytes[0], bytes[1]]);
                w == 0x4E75    // m68k RTS
                    || w == 0x000B // SuperH RTS
                    || w == 0x4770 // Thumb BX LR
                    || w == 0x8082 // RISC-V C.RET
            }
            4 => {
                let le = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                let be = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

                le == 0xD65F03C0    // AArch64 RET
                    || le == 0x00008067 // RISC-V RET
                    || le == 0xE12FFF1E // ARM BX LR
                    || be == 0x03E00008 // MIPS JR $ra
                    || be == 0x4E800020 // PowerPC BLR
                    || be == 0x81C3E008 // SPARC RETL
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_endianness() {
        assert_eq!(default_endianness(Isa::X86_64), Endianness::Little);
        assert_eq!(default_endianness(Isa::Ppc64), Endianness::Big);
        assert_eq!(default_endianness(Isa::S390x), Endianness::Big);
    }

    #[test]
    fn test_instruction_alignment() {
        assert_eq!(instruction_alignment(Isa::X86), 1);
        assert_eq!(instruction_alignment(Isa::AArch64), 4);
        assert_eq!(instruction_alignment(Isa::RiscV64), 2);
    }

    #[test]
    fn test_nop_detection() {
        assert!(patterns::is_likely_nop(&[0x90]));
        assert!(patterns::is_likely_nop(&[0x1F, 0x20, 0x03, 0xD5]));
    }

    #[test]
    fn test_ret_detection() {
        assert!(patterns::is_likely_ret(&[0xC3]));
        assert!(patterns::is_likely_ret(&[0xC0, 0x03, 0x5F, 0xD6]));
    }
}
