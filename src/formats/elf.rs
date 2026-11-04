//! ELF (Executable and Linkable Format) parser.
//!
//! Comprehensive ELF parser supporting all e_machine values and
//! architecture-specific e_flags parsing.

use crate::error::{ClassifierError, Result};
use crate::formats::{field_name, read_u16, read_u32, read_u64, NamedRange};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, Extension, ExtensionCategory,
    FileFormat, Isa, Variant,
};

/// ELF class values (32-bit vs 64-bit)
pub mod class {
    pub const ELFCLASS32: u8 = 1;
    pub const ELFCLASS64: u8 = 2;
}

/// ELF data encoding (endianness)
pub mod data {
    pub const ELFDATA2LSB: u8 = 1; // Little-endian
    pub const ELFDATA2MSB: u8 = 2; // Big-endian
}

/// Complete e_machine value mapping.
///
/// This includes all values from the official ELF specification
/// plus vendor-specific extensions.
pub fn e_machine_to_isa(e_machine: u16, ei_class: u8) -> (Isa, u8) {
    let is_64 = ei_class == class::ELFCLASS64;

    match e_machine {
        // No machine
        0x00 => (Isa::Unknown(0), 0),

        // AT&T WE 32100
        0x01 => (Isa::Unknown(1), 32),

        // SPARC
        0x02 => (Isa::Sparc, 32),

        // Intel 80386
        0x03 => (Isa::X86, 32),

        // Motorola 68000
        0x04 => (Isa::M68k, 32),

        // Motorola 88000
        0x05 => (Isa::Unknown(5), 32),

        // Intel MCU
        0x06 => (Isa::X86, 32),

        // Intel 80860
        0x07 => (Isa::I860, 32),

        // MIPS I
        0x08 => {
            if is_64 {
                (Isa::Mips64, 64)
            } else {
                (Isa::Mips, 32)
            }
        }

        // IBM System/370
        0x09 => (Isa::S390, 32),

        // MIPS RS3000 LE
        0x0A => (Isa::Mips, 32),

        // HP PA-RISC; ELFCLASS64 objects are PA-RISC 2.0 wide (64-bit) code
        0x0F => (Isa::Parisc, if is_64 { 64 } else { 32 }),

        // Fujitsu VPP500
        0x11 => (Isa::Unknown(0x11), 32),

        // SPARC V8+
        0x12 => (Isa::Sparc, 32),

        // Intel 80960
        0x13 => (Isa::I960, 32),

        // PowerPC 32-bit
        0x14 => (Isa::Ppc, 32),

        // PowerPC 64-bit
        0x15 => (Isa::Ppc64, 64),

        // IBM S/390
        0x16 => {
            if is_64 {
                (Isa::S390x, 64)
            } else {
                (Isa::S390, 32)
            }
        }

        // IBM SPU/SPC
        0x17 => (Isa::CellSpu, 32),

        // NEC V800 / Renesas RH850 toolchains
        0x24 => (Isa::Rh850, 32),

        // Fujitsu FR20
        0x25 => (Isa::Unknown(0x25), 32),

        // TRW RH-32
        0x26 => (Isa::Unknown(0x26), 32),

        // Motorola RCE (historically reused by some C-SKY toolchains)
        0x27 => (Isa::Csky, 32),

        // ARM 32-bit
        0x28 => (Isa::Arm, 32),

        // DEC Alpha (unofficial)
        0x29 => (Isa::Alpha, 64),

        // Hitachi SuperH
        0x2A => (Isa::Sh, 32),

        // SPARC V9 64-bit
        0x2B => (Isa::Sparc64, 64),

        // Siemens TriCore
        0x2C => (Isa::Tricore, 32), // EM_TRICORE

        // ARC (ARCv1)
        0x2D => (Isa::Arc, 32),

        // Hitachi H8/300
        0x2E => (Isa::H8300, 16),

        // Hitachi H8/300H
        0x2F => (Isa::H8300, 16),

        // Hitachi H8S
        0x30 => (Isa::H8300, 16),

        // Hitachi H8/500
        0x31 => (Isa::H8500, 16),

        // Intel IA-64
        0x32 => (Isa::Ia64, 64),

        // Stanford MIPS-X
        0x33 => (Isa::Mips, 32),

        // Motorola ColdFire
        0x34 => (Isa::ColdFire, 32),

        // Motorola M68HC12 / HCS12
        0x35 => (Isa::Hcs12, 16),

        // Fujitsu MMA
        0x36 => (Isa::Unknown(0x36), 32),

        // Siemens PCP
        0x37 => (Isa::Unknown(0x37), 32),

        // Sony nCPU
        0x38 => (Isa::Unknown(0x38), 32),

        // Denso NDR1
        0x39 => (Isa::Unknown(0x39), 32),

        // Motorola StarCore
        0x3A => (Isa::Unknown(0x3A), 32),

        // Toyota ME16
        0x3B => (Isa::Unknown(0x3B), 16),

        // STMicro ST100
        0x3C => (Isa::Unknown(0x3C), 32),

        // TinyJ
        0x3D => (Isa::Unknown(0x3D), 32),

        // AMD x86-64
        0x3E => (Isa::X86_64, 64),

        // Sony DSP
        0x3F => (Isa::Unknown(0x3F), 32),

        // DEC PDP-10
        0x40 => (Isa::Unknown(0x40), 36),

        // DEC PDP-11
        0x41 => (Isa::Pdp11, 16),

        // Siemens FX66
        0x42 => (Isa::Unknown(0x42), 32),

        // STMicro ST9+
        0x43 => (Isa::St9, 16),

        // STMicro ST7
        0x44 => (Isa::St7, 8),

        // Motorola MC68HC16
        0x45 => (Isa::Hc16, 16),

        // Motorola MC68HC11
        0x46 => (Isa::Hc11, 16),

        // Motorola MC68HC08
        0x47 => (Isa::Hc08, 8),

        // Motorola MC68HC05
        0x48 => (Isa::Hc05, 8),

        // Silicon Graphics SVx
        0x49 => (Isa::Unknown(0x49), 32),

        // STMicro ST19
        0x4A => (Isa::Unknown(0x4A), 8),

        // DEC VAX
        0x4B => (Isa::Vax, 32),

        // Axis CRIS
        0x4C => (Isa::Unknown(0x4C), 32),

        // Infineon Javelin
        0x4D => (Isa::Unknown(0x4D), 32),

        // Element 14 Firepath
        0x4E => (Isa::Unknown(0x4E), 32),

        // LSI Logic DSP
        0x4F => (Isa::Unknown(0x4F), 16),

        // MMIX
        0x50 => (Isa::Unknown(0x50), 64),

        // Harvard HUANY
        0x51 => (Isa::Unknown(0x51), 32),

        // SiTera Prism
        0x52 => (Isa::Unknown(0x52), 32),

        // Atmel AVR
        0x53 => (Isa::Avr, 8),

        // Fujitsu FR30
        0x54 => (Isa::Fr30, 32),

        // Mitsubishi D10V
        0x55 => (Isa::Unknown(0x55), 16),

        // Mitsubishi D30V
        0x56 => (Isa::Unknown(0x56), 32),

        // NEC V850
        0x57 => (Isa::V850, 32),

        // Mitsubishi M32R
        0x58 => (Isa::M32r, 32),

        // Matsushita MN10300
        0x59 => (Isa::Mn10300, 32),

        // Matsushita MN10200
        0x5A => (Isa::Mn10200, 16),

        // picoJava
        0x5B => (Isa::Unknown(0x5B), 32),

        // OpenRISC
        0x5C => (Isa::OpenRisc, 32),

        // ARC ARCompact
        0x5D => (Isa::ArcCompact, 32),

        // Tensilica Xtensa
        0x5E => (Isa::Xtensa, 32),

        // Alphamosaic VideoCore
        0x5F => (Isa::Unknown(0x5F), 32),

        // Thompson GPP
        0x60 => (Isa::Unknown(0x60), 32),

        // NS 32000
        0x61 => (Isa::Unknown(0x61), 32),

        // Tenor Network TPC
        0x62 => (Isa::Unknown(0x62), 32),

        // Trebia SNP 1000
        0x63 => (Isa::Unknown(0x63), 32),

        // STMicro ST200
        0x64 => (Isa::Unknown(0x64), 32),

        // Ubicom IP2xxx
        0x65 => (Isa::Unknown(0x65), 16),

        // MAX Processor
        0x66 => (Isa::Unknown(0x66), 32),

        // NS CompactRISC
        0x67 => (Isa::Cr16, 16),

        // Fujitsu F2MC16
        0x68 => (Isa::F2mc16, 16),

        // TI MSP430
        0x69 => (Isa::Msp430, 16),

        // Analog Devices Blackfin
        0x6A => (Isa::Blackfin, 32),

        // Seiko Epson S1C33
        0x6B => (Isa::Unknown(0x6B), 32),

        // Sharp embedded
        0x6C => (Isa::Unknown(0x6C), 32),

        // Arca RISC
        0x6D => (Isa::Unknown(0x6D), 32),

        // PKU UniCore
        0x6E => (Isa::Unknown(0x6E), 32),

        // eXcess
        0x6F => (Isa::Unknown(0x6F), 32),

        // Icera Deep Execution
        0x70 => (Isa::Unknown(0x70), 32),

        // Altera Nios II
        0x71 => (Isa::Nios2, 32),

        // NS CompactRISC CRX
        0x72 => (Isa::Unknown(0x72), 16),

        // Motorola XGATE
        0x73 => (Isa::Unknown(0x73), 16),

        // Infineon C16x/C166/ST10
        0x74 => (Isa::C166, 16),

        // Renesas M16C
        0x75 => (Isa::M16c, 16),

        // Microchip dsPIC30F
        0x76 => (Isa::Unknown(0x76), 16),

        // Freescale CE
        0x77 => (Isa::Unknown(0x77), 32),

        // Renesas M32C
        0x78 => (Isa::M16c, 32),

        // Altium TSK3000
        0x83 => (Isa::Unknown(0x83), 32),

        // Freescale RS08
        0x84 => (Isa::Unknown(0x84), 8),

        // Analog Devices SHARC
        0x85 => (Isa::Sharc, 32),

        // Cyan eCOG2
        0x86 => (Isa::Unknown(0x86), 16),

        // Sunplus S+core7
        0x87 => (Isa::Unknown(0x87), 32),

        // NJR 24-bit DSP
        0x88 => (Isa::Unknown(0x88), 24),

        // Broadcom VideoCore III
        0x89 => (Isa::VideoCore3, 32),

        // Lattice RISC
        0x8A => (Isa::Unknown(0x8A), 32),

        // Seiko Epson C17
        0x8B => (Isa::Unknown(0x8B), 16),

        // TI TMS320C6000
        0x8C => (Isa::TiC6000, 32),

        // TI TMS320C2000
        // Map 0x8D to C28x (the modern and dominant C2000 variant)
        0x8D => (Isa::TiC28x, 32),

        // TI TMS320C55x
        0x8E => (Isa::TiC5500, 16),

        // TI ARP32
        0x8F => (Isa::Unknown(0x8F), 32),

        // TI PRU
        0x90 => (Isa::TiPru, 32),

        // STMicro VLIW DSP
        0xA0 => (Isa::Unknown(0xA0), 32),

        // Cypress M8C
        0xA1 => (Isa::Unknown(0xA1), 8),

        // Renesas R32C
        0xA2 => (Isa::R32c, 32),

        // NXP TriMedia
        0xA3 => (Isa::TriMedia, 32),

        // Qualcomm Hexagon
        0xA4 => (Isa::Hexagon, 32),

        // Intel 8051
        0xA5 => (Isa::I8051, 8),

        // STMicro STxP7x
        0xA6 => (Isa::Unknown(0xA6), 32),

        // Andes NDS32
        0xA7 => (Isa::Nds32, 32),

        // Cyan eCOG1X
        0xA8 => (Isa::Unknown(0xA8), 16),

        // Dallas MAXQ30
        0xA9 => (Isa::Unknown(0xA9), 16),

        // NJR 16-bit DSP
        0xAA => (Isa::Unknown(0xAA), 16),

        // M2000 RISC
        0xAB => (Isa::Unknown(0xAB), 32),

        // Cray NV2
        0xAC => (Isa::Unknown(0xAC), 64),

        // Renesas RX
        0xAD => (Isa::Rx, 32),

        // Imagination META
        0xAE => (Isa::Unknown(0xAE), 32),

        // MCST Elbrus
        0xAF => (Isa::McstElbrus, 64),

        // Cyan eCOG16
        0xB0 => (Isa::Unknown(0xB0), 16),

        // NS CompactRISC CR16
        0xB1 => (Isa::Cr16, 16),

        // Freescale ETPU
        0xB2 => (Isa::Unknown(0xB2), 32),

        // Infineon SLE9X
        0xB3 => (Isa::Unknown(0xB3), 16),

        // Intel L10M
        0xB4 => (Isa::Unknown(0xB4), 32),

        // Intel K10M
        0xB5 => (Isa::Unknown(0xB5), 32),

        // ARM 64-bit (AArch64)
        0xB7 => (Isa::AArch64, 64),

        // Atmel AVR32
        0xB9 => (Isa::Avr32, 32),

        // STMicro STM8
        0xBA => (Isa::Stm8, 8),

        // Tilera TILE64
        0xBB => (Isa::Tile64, 32),

        // Tilera TILEPro
        0xBC => (Isa::TilePro, 32),

        // Xilinx MicroBlaze
        0xBD => (Isa::MicroBlaze, 32),

        // NVIDIA CUDA
        0xBE => (Isa::Cuda, 64),

        // Tilera TILE-Gx
        0xBF => (Isa::TileGx, 64),

        // CloudShield
        0xC0 => (Isa::Unknown(0xC0), 32),

        // KIPO Core-A 1st
        0xC1 => (Isa::Unknown(0xC1), 32),

        // KIPO Core-A 2nd
        0xC2 => (Isa::Unknown(0xC2), 32),

        // Synopsys ARCv2
        0xC3 => (Isa::ArcCompact2, 32),

        // Open8 RISC
        0xC4 => (Isa::Unknown(0xC4), 8),

        // Renesas RL78
        0xC5 => (Isa::Rl78, 16),

        // Broadcom VideoCore V
        0xC6 => (Isa::VideoCore5, 32),

        // Renesas 78KOR (legacy 78K family)
        0xC7 => (Isa::K78k0r, 16),

        // Freescale 56800EX
        0xC8 => (Isa::Unknown(0xC8), 16),

        // Beyond BA1
        0xC9 => (Isa::Unknown(0xC9), 32),

        // Beyond BA2
        0xCA => (Isa::Unknown(0xCA), 32),

        // XMOS xCORE
        0xCB => (Isa::Unknown(0xCB), 32),

        // Microchip PIC
        0xCC => (Isa::Pic, 8),

        // KM211 KM32
        0xD2 => (Isa::Unknown(0xD2), 32),

        // KM211 KMX32
        0xD3 => (Isa::Unknown(0xD3), 32),

        // KM211 KMX16
        0xD4 => (Isa::Unknown(0xD4), 16),

        // KM211 KMX8
        0xD5 => (Isa::Unknown(0xD5), 8),

        // KM211 KVARC
        0xD6 => (Isa::Unknown(0xD6), 32),

        // Paneve CDP
        0xD7 => (Isa::Unknown(0xD7), 32),

        // Cognitive
        0xD8 => (Isa::Unknown(0xD8), 32),

        // Bluechip CoolEngine
        0xD9 => (Isa::Unknown(0xD9), 32),

        // Nanoradio RISC
        0xDA => (Isa::Unknown(0xDA), 32),

        // CSR Kalimba
        0xDB => (Isa::Unknown(0xDB), 24),

        // Zilog Z80
        0xDC => (Isa::Z80, 8),

        // VISIUMcore
        0xDD => (Isa::Unknown(0xDD), 32),

        // FTDI FT32
        0xDE => (Isa::Unknown(0xDE), 32),

        // Moxie
        0xDF => (Isa::Unknown(0xDF), 32),

        // AMD GPU
        0xE0 => (Isa::AmdGpu, 64),

        // RISC-V
        0xF3 => {
            if is_64 {
                (Isa::RiscV64, 64)
            } else {
                (Isa::RiscV32, 32)
            }
        }

        // Lanai
        0xF4 => (Isa::Lanai, 32),

        // CEVA
        0xF5 => (Isa::Unknown(0xF5), 32),

        // CEVA X2
        0xF6 => (Isa::Unknown(0xF6), 32),

        // Linux BPF
        0xF7 => (Isa::Bpf, 64),

        // Graphcore IPU
        0xF8 => (Isa::Unknown(0xF8), 32),

        // nanoMIPS (EM_NANOMIPS)
        0xF9 => {
            if is_64 {
                (Isa::Mips64, 64)
            } else {
                (Isa::Mips, 32)
            }
        }

        // Netronome NFP
        0xFA => (Isa::Unknown(0xFA), 32),

        // NEC VE
        0xFB => (Isa::Unknown(0xFB), 64),

        // C-SKY
        0xFC => (Isa::Csky, 32),

        // ARCv2.3 64-bit
        0xFD => (Isa::Unknown(0xFD), 64),

        // MOS 6502
        0xFE => (Isa::Mcs6502, 8),

        // ARCv2.3 32-bit
        0xFF => (Isa::ArcCompact2, 32),

        // Kalray VLIW
        0x100 => (Isa::Kvx, 64),

        // WDC 65816
        0x101 => (Isa::W65816, 16),

        // LoongArch
        0x102 => {
            if is_64 {
                (Isa::LoongArch64, 64)
            } else {
                (Isa::LoongArch32, 32)
            }
        }

        // ChipON KungFu32
        0x103 => (Isa::Unknown(0x103), 32),

        // DEC Alpha (official/experimental)
        0x9026 => (Isa::Alpha, 64),

        // Unknown
        other => (Isa::Unknown(other as u32), if is_64 { 64 } else { 32 }),
    }
}

/// Parse ELF e_flags for architecture-specific information.
pub fn parse_e_flags(isa: Isa, e_flags: u32, data: &[u8]) -> (Variant, Vec<Extension>) {
    match isa {
        Isa::Arm => parse_arm_flags(e_flags, data),
        Isa::AArch64 => parse_aarch64_flags(e_flags),
        Isa::RiscV32 | Isa::RiscV64 | Isa::RiscV128 => parse_riscv_flags(e_flags),
        Isa::Mips | Isa::Mips64 => parse_mips_flags(e_flags),
        Isa::Ppc | Isa::Ppc64 | Isa::PpcVle => parse_ppc_flags(isa, e_flags),
        Isa::Sh | Isa::Sh4 => parse_sh_flags(e_flags),
        Isa::Hexagon => parse_hexagon_flags(e_flags),
        Isa::LoongArch32 | Isa::LoongArch64 => parse_loongarch_flags(isa, e_flags),
        Isa::Sparc | Isa::Sparc64 => parse_sparc_flags(e_flags),
        _ => (Variant::default(), Vec::new()),
    }
}

/// Parse ARM32 ELF flags.
fn parse_arm_flags(e_flags: u32, _data: &[u8]) -> (Variant, Vec<Extension>) {
    let mut extensions = Vec::new();
    let mut variant_parts = Vec::new();

    // EABI version (bits 31:24)
    let eabi = (e_flags >> 24) & 0xFF;
    if eabi == 5 {
        variant_parts.push("EABI5");
    }

    // Float ABI
    if e_flags & 0x00000400 != 0 {
        variant_parts.push("hard-float");
    } else if e_flags & 0x00000200 != 0 {
        variant_parts.push("soft-float");
    }

    // BE8 mode
    if e_flags & 0x00800000 != 0 {
        extensions.push(Extension::new("BE8", ExtensionCategory::Other));
    }

    let variant_name = if variant_parts.is_empty() {
        String::new()
    } else {
        variant_parts.join(", ")
    };

    (Variant::new(variant_name), extensions)
}

/// GNU property types for AArch64.
mod gnu_property {
    /// GNU property note type
    pub const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc0000000;

    /// AArch64 feature bits
    pub const GNU_PROPERTY_AARCH64_FEATURE_1_BTI: u32 = 1 << 0;
    pub const GNU_PROPERTY_AARCH64_FEATURE_1_PAC: u32 = 1 << 1;
    pub const GNU_PROPERTY_AARCH64_FEATURE_1_GCS: u32 = 1 << 2;
}

/// Parse AArch64 ELF flags.
fn parse_aarch64_flags(_e_flags: u32) -> (Variant, Vec<Extension>) {
    // AArch64 doesn't use many e_flags bits
    // Extensions are typically detected from GNU properties, code, or attributes
    (Variant::default(), Vec::new())
}

/// Parse GNU property notes from ELF data to extract AArch64 feature flags.
///
/// This looks for .note.gnu.property sections or PT_GNU_PROPERTY segments
/// to find GNU_PROPERTY_AARCH64_FEATURE_1_AND properties.
fn parse_aarch64_gnu_properties(data: &[u8], is_64: bool, little_endian: bool) -> Vec<Extension> {
    let mut extensions = Vec::new();

    // Try to find and parse program headers to locate PT_GNU_PROPERTY
    let (e_phoff, e_phentsize, e_phnum) = if is_64 {
        if data.len() < 0x40 {
            return extensions;
        }
        let phoff = read_u64(data, 0x20, little_endian).unwrap_or(0) as usize;
        let phentsize = read_u16(data, 0x36, little_endian).unwrap_or(0) as usize;
        let phnum = read_u16(data, 0x38, little_endian).unwrap_or(0) as usize;
        (phoff, phentsize, phnum)
    } else {
        if data.len() < 0x34 {
            return extensions;
        }
        let phoff = read_u32(data, 0x1C, little_endian).unwrap_or(0) as usize;
        let phentsize = read_u16(data, 0x2A, little_endian).unwrap_or(0) as usize;
        let phnum = read_u16(data, 0x2C, little_endian).unwrap_or(0) as usize;
        (phoff, phentsize, phnum)
    };

    // PT_GNU_PROPERTY = 0x6474e553
    const PT_GNU_PROPERTY: u32 = 0x6474e553;
    // PT_NOTE = 4
    const PT_NOTE: u32 = 4;

    for i in 0..e_phnum {
        let ph_offset = e_phoff + i * e_phentsize;
        if ph_offset + e_phentsize > data.len() {
            break;
        }

        let p_type = read_u32(data, ph_offset, little_endian).unwrap_or(0);

        if p_type == PT_GNU_PROPERTY || p_type == PT_NOTE {
            let (p_offset, p_filesz) = if is_64 {
                let off = read_u64(data, ph_offset + 8, little_endian).unwrap_or(0) as usize;
                let sz = read_u64(data, ph_offset + 32, little_endian).unwrap_or(0) as usize;
                (off, sz)
            } else {
                let off = read_u32(data, ph_offset + 4, little_endian).unwrap_or(0) as usize;
                let sz = read_u32(data, ph_offset + 16, little_endian).unwrap_or(0) as usize;
                (off, sz)
            };

            if p_offset + p_filesz <= data.len() {
                let note_data = &data[p_offset..p_offset + p_filesz];
                if let Some(props) = parse_gnu_property_note(note_data, is_64, little_endian) {
                    extensions.extend(props);
                }
            }
        }
    }

    extensions
}

/// Parse a GNU property note section/segment.
fn parse_gnu_property_note(
    data: &[u8],
    is_64: bool,
    little_endian: bool,
) -> Option<Vec<Extension>> {
    let mut extensions = Vec::new();
    let mut offset = 0;

    // Note header: namesz (4), descsz (4), type (4), name (aligned), desc (aligned)
    while offset + 12 <= data.len() {
        let namesz = read_u32(data, offset, little_endian).ok()? as usize;
        let descsz = read_u32(data, offset + 4, little_endian).ok()? as usize;
        let note_type = read_u32(data, offset + 8, little_endian).ok()?;

        offset += 12;

        // Align to 4 or 8 bytes
        let align = if is_64 { 8 } else { 4 };
        let name_aligned = (namesz + align - 1) & !(align - 1);
        let desc_aligned = (descsz + align - 1) & !(align - 1);

        if offset + name_aligned + desc_aligned > data.len() {
            break;
        }

        // Check if this is a GNU note (name = "GNU\0")
        if namesz == 4 && offset + 4 <= data.len() {
            let name = &data[offset..offset + 4];
            if name == b"GNU\0" && note_type == 5 {
                // NT_GNU_PROPERTY_TYPE_0 = 5
                // Parse the properties in the descriptor
                let desc_start = offset + name_aligned;
                let desc_end = desc_start + descsz;

                if desc_end <= data.len() {
                    let mut prop_offset = desc_start;
                    while prop_offset + 8 <= desc_end {
                        let pr_type = read_u32(data, prop_offset, little_endian).ok()?;
                        let pr_datasz =
                            read_u32(data, prop_offset + 4, little_endian).ok()? as usize;

                        prop_offset += 8;

                        if prop_offset + pr_datasz > desc_end {
                            break;
                        }

                        // GNU_PROPERTY_AARCH64_FEATURE_1_AND
                        if pr_type == gnu_property::GNU_PROPERTY_AARCH64_FEATURE_1_AND
                            && pr_datasz >= 4
                        {
                            let features = read_u32(data, prop_offset, little_endian).ok()?;

                            if features & gnu_property::GNU_PROPERTY_AARCH64_FEATURE_1_BTI != 0 {
                                extensions.push(Extension::new("BTI", ExtensionCategory::Security));
                            }
                            if features & gnu_property::GNU_PROPERTY_AARCH64_FEATURE_1_PAC != 0 {
                                extensions.push(Extension::new("PAC", ExtensionCategory::Security));
                            }
                            if features & gnu_property::GNU_PROPERTY_AARCH64_FEATURE_1_GCS != 0 {
                                extensions.push(Extension::new("GCS", ExtensionCategory::Security));
                            }
                        }

                        // Align property data to 8 bytes for 64-bit
                        let pr_aligned = if is_64 {
                            (pr_datasz + 7) & !7
                        } else {
                            (pr_datasz + 3) & !3
                        };
                        prop_offset += pr_aligned;
                    }
                }
            }
        }

        offset += name_aligned + desc_aligned;
    }

    if extensions.is_empty() {
        None
    } else {
        Some(extensions)
    }
}

/// Parse RISC-V ELF flags.
fn parse_riscv_flags(e_flags: u32) -> (Variant, Vec<Extension>) {
    let mut extensions = Vec::new();
    let mut abi_parts = Vec::new();

    // RVC (Compressed) - bit 0
    if e_flags & 0x0001 != 0 {
        extensions.push(Extension::new("C", ExtensionCategory::Compressed));
    }

    // Float ABI - bits 2:1
    let float_abi = (e_flags >> 1) & 0x3;
    match float_abi {
        0 => abi_parts.push("soft-float"),
        1 => {
            abi_parts.push("single-float");
            extensions.push(Extension::new("F", ExtensionCategory::FloatingPoint));
        }
        2 => {
            abi_parts.push("double-float");
            extensions.push(Extension::new("F", ExtensionCategory::FloatingPoint));
            extensions.push(Extension::new("D", ExtensionCategory::FloatingPoint));
        }
        3 => {
            abi_parts.push("quad-float");
            extensions.push(Extension::new("F", ExtensionCategory::FloatingPoint));
            extensions.push(Extension::new("D", ExtensionCategory::FloatingPoint));
            extensions.push(Extension::new("Q", ExtensionCategory::FloatingPoint));
        }
        _ => {}
    }

    // RVE (16 registers) - bit 3
    if e_flags & 0x0008 != 0 {
        extensions.push(Extension::new("E", ExtensionCategory::Other));
    }

    // Ztso (TSO memory model) - bit 4
    if e_flags & 0x0010 != 0 {
        extensions.push(Extension::new("Ztso", ExtensionCategory::Other));
    }

    let abi_name = if abi_parts.is_empty() {
        String::new()
    } else {
        abi_parts.join(", ")
    };

    (Variant::with_abi("RISC-V", abi_name), extensions)
}

/// Parse MIPS ELF flags.
fn parse_mips_flags(e_flags: u32) -> (Variant, Vec<Extension>) {
    let mut extensions = Vec::new();

    // Architecture level - bits 31:28
    let arch = (e_flags >> 28) & 0xF;
    let arch_name = match arch {
        0x0 => "MIPS-I",
        0x1 => "MIPS-II",
        0x2 => "MIPS-III",
        0x3 => "MIPS-IV",
        0x4 => "MIPS-V",
        0x5 => "MIPS32",
        0x6 => "MIPS64",
        0x7 => "MIPS32R2",
        0x8 => "MIPS64R2",
        0x9 => "MIPS32R6",
        0xA => "MIPS64R6",
        _ => "MIPS",
    };

    // microMIPS - bit 25
    if e_flags & 0x02000000 != 0 {
        extensions.push(Extension::new("microMIPS", ExtensionCategory::Compressed));
    }

    // MIPS16e - bit 26
    if e_flags & 0x04000000 != 0 {
        extensions.push(Extension::new("MIPS16e", ExtensionCategory::Compressed));
    }

    // MDMX - bit 27
    if e_flags & 0x08000000 != 0 {
        extensions.push(Extension::new("MDMX", ExtensionCategory::Simd));
    }

    (Variant::new(arch_name), extensions)
}

/// `EF_PPC64_ABI` (binutils `include/elf/ppc64.h`): the 64-bit PowerPC ABI
/// version (1 = `ELFv1`, 2 = `ELFv2`, 0 = unspecified). 32-bit PowerPC defines
/// no ABI field in these bits.
const EF_PPC64_ABI: u32 = 0x3;

/// Parse PowerPC ELF flags. Only a 64-bit object with a defined ABI version
/// names an ABI.
fn parse_ppc_flags(isa: Isa, e_flags: u32) -> (Variant, Vec<Extension>) {
    let abi = match (isa, e_flags & EF_PPC64_ABI) {
        (Isa::Ppc64, 1) => Some("ELFv1"),
        (Isa::Ppc64, 2) => Some("ELFv2"),
        _ => None,
    };
    let variant = match abi {
        Some(abi) => Variant::with_abi("PowerPC", abi),
        None => Variant::new("PowerPC"),
    };
    (variant, Vec::new())
}

/// Parse SuperH ELF flags.
fn parse_sh_flags(e_flags: u32) -> (Variant, Vec<Extension>) {
    let variant = e_flags & 0x1F;
    let name = match variant {
        9 => "SH-4",
        12 => "SH-4A",
        13 => "SH-2A",
        _ => "",
    };

    (Variant::new(name), Vec::new())
}

/// `EF_HEXAGON_ISA` (LLVM `include/llvm/BinaryFormat/ELF.h`): the Hexagon
/// machine version in `e_flags[9:0]`. V2 to V55 are 1 to 5; from V60 on, the
/// value spells the version in hex digits (`0x65` is V65).
const EF_HEXAGON_ISA: u32 = 0x03ff;

/// `EF_HEXAGON_TINY_CORE`: the tiny-core form of a version (V67T, V71T).
const EF_HEXAGON_TINY_CORE: u32 = 0x8000;

/// Machine values of the versions before V60, which do not spell their
/// version.
const HEXAGON_EARLY_VERSIONS: [(u32, &str); 5] =
    [(1, "V2"), (2, "V3"), (3, "V4"), (4, "V5"), (5, "V55")];

/// First machine value that spells its version in hex digits (V60).
const HEXAGON_SPELLED_VERSIONS_FROM: u32 = 0x60;

/// The Hexagon version an `e_flags` machine value names, if it names one.
fn hexagon_version(machine: u32) -> Option<String> {
    if let Some((_, version)) = HEXAGON_EARLY_VERSIONS
        .iter()
        .find(|(value, _)| *value == machine)
    {
        return Some((*version).to_string());
    }
    let digits = format!("{machine:x}");
    let spells_a_version = machine >= HEXAGON_SPELLED_VERSIONS_FROM
        && digits.bytes().all(|digit| digit.is_ascii_digit());
    spells_a_version.then(|| format!("V{digits}"))
}

/// Parse Hexagon ELF flags: the machine version and the tiny-core flag. An
/// unspecified or unknown machine value gives no variant.
fn parse_hexagon_flags(e_flags: u32) -> (Variant, Vec<Extension>) {
    let Some(version) = hexagon_version(e_flags & EF_HEXAGON_ISA) else {
        return (Variant::default(), Vec::new());
    };
    let tiny_core = if e_flags & EF_HEXAGON_TINY_CORE == 0 {
        ""
    } else {
        "T"
    };
    (Variant::new(format!("{version}{tiny_core}")), Vec::new())
}

/// `EF_LARCH_ABI_MODIFIER_MASK` (glibc `elf.h`): `e_flags[2:0]`, the base
/// ABI modifier of a `LoongArch` object (1 = soft float, 2 = single, 3 = double;
/// 0 and 4-7 reserved). The `LoongArch` ELF psABI: `EI_CLASS` and this field give
/// the base ABI type. clang 23 writes 0x41, 0x42 and 0x43 for `lp64s`,
/// `lp64f` and `lp64d` (checked 2026-11-04).
const EF_LARCH_ABI_MODIFIER_MASK: u32 = 0x7;

/// Parse `LoongArch` ELF flags. The base ABI follows the ELF class (LP64 or
/// ILP32), the floating-point suffix the ABI modifier.
fn parse_loongarch_flags(isa: Isa, e_flags: u32) -> (Variant, Vec<Extension>) {
    let base = if isa == Isa::LoongArch64 {
        "LP64"
    } else {
        "ILP32"
    };
    let float = match e_flags & EF_LARCH_ABI_MODIFIER_MASK {
        1 => Some("S"),
        2 => Some("F"),
        3 => Some("D"),
        _ => None,
    };
    let variant = match float {
        Some(float) => Variant::with_abi("LoongArch", format!("{base}{float}")),
        None => Variant::new("LoongArch"),
    };
    (variant, Vec::new())
}

/// Parse SPARC ELF flags.
fn parse_sparc_flags(e_flags: u32) -> (Variant, Vec<Extension>) {
    let mut extensions = Vec::new();

    // Memory model
    let mm = e_flags & 0x3;
    if mm == 0x1 {
        extensions.push(Extension::new("PSO", ExtensionCategory::Other));
    } else if mm == 0x2 {
        extensions.push(Extension::new("RMO", ExtensionCategory::Other));
    }

    (Variant::default(), extensions)
}

/// Main ELF parsing function.
pub fn parse(data: &[u8], ei_class: u8, ei_data: u8) -> Result<ClassificationResult> {
    if data.len() < 16 {
        return Err(ClassifierError::FileTooSmall {
            expected: 16,
            actual: data.len(),
        });
    }

    let is_64 = ei_class == class::ELFCLASS64;
    let little_endian = ei_data == data::ELFDATA2LSB;

    let endianness = if little_endian {
        Endianness::Little
    } else {
        Endianness::Big
    };

    // Read e_machine
    let e_machine = read_u16(data, 0x12, little_endian)?;

    // Read e_flags (offset differs for 32/64-bit)
    let e_flags = if is_64 {
        read_u32(data, 0x30, little_endian)?
    } else {
        read_u32(data, 0x24, little_endian)?
    };

    // Read entry point
    let entry_point = if is_64 {
        read_u64(data, 0x18, little_endian)?
    } else {
        read_u32(data, 0x18, little_endian)? as u64
    };

    // Map e_machine to ISA
    let (mut isa, mut bitwidth) = e_machine_to_isa(e_machine, ei_class);

    // PPC VLE is encoded as a profile within PPC ELF files rather than a distinct
    // e_machine value. Toolchains commonly emit section/attribute names that
    // include explicit VLE markers.
    if matches!(isa, Isa::Ppc | Isa::Ppc64) && has_ppc_vle_marker(data) {
        isa = Isa::PpcVle;
        bitwidth = 32;
    }

    // Parse architecture-specific flags
    let (variant, mut extensions) = parse_e_flags(isa, e_flags, data);

    if isa == Isa::PpcVle {
        extensions.push(Extension::new("VLE", ExtensionCategory::Compressed));
    }

    // For AArch64, also parse GNU property notes for BTI/PAC/GCS info
    if isa == Isa::AArch64 {
        let gnu_extensions = parse_aarch64_gnu_properties(data, is_64, little_endian);
        // Merge, avoiding duplicates
        let existing: std::collections::HashSet<String> =
            extensions.iter().map(|e| e.name.clone()).collect();
        for ext in gnu_extensions {
            if !existing.contains(&ext.name) {
                extensions.push(ext);
            }
        }
    }

    // Build metadata
    let metadata = ClassificationMetadata {
        entry_point: Some(entry_point),
        flags: Some(e_flags),
        raw_machine: Some(e_machine as u32),
        ..Default::default()
    };

    let mut result = ClassificationResult::from_format(isa, bitwidth, endianness, FileFormat::Elf);
    result.variant = variant;
    result.extensions = extensions;
    result.metadata = metadata;

    Ok(result)
}

fn has_ppc_vle_marker(data: &[u8]) -> bool {
    const MARKERS: [&[u8]; 3] = [b".vletext", b".PPC.EMB.vle", b"vle_off"]; // binutils/GCC conventions

    MARKERS
        .iter()
        .any(|marker| data.windows(marker.len()).any(|window| window == *marker))
}

/// Section types without file bytes ("System V ABI", chapter 4,
/// "Sections", Figure 4-9).
const SHT_NULL: u32 = 0;
const SHT_NOBITS: u32 = 8;

/// `e_shstrndx` value meaning "the index is in section 0's `sh_link`".
const SHN_XINDEX: u16 = 0xffff;

/// Section headers read from one file.
const MAX_SECTIONS: u64 = 4096;

/// Longest section name read from the section-name string table.
const MAX_SECTION_NAME: usize = 256;

/// The section header fields used for file ranges.
struct SectionHeader {
    name: u32,
    kind: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
}

/// The header at `at`. 32-bit: `sh_name` 0, `sh_type` 4, `sh_flags` 8,
/// `sh_offset` 16, `sh_size` 20, `sh_link` 24. 64-bit: `sh_name` 0,
/// `sh_type` 4, `sh_flags` 8, `sh_offset` 24, `sh_size` 32, `sh_link` 40.
fn section_header(data: &[u8], at: usize, is_64: bool, le: bool) -> Option<SectionHeader> {
    let field = |offset: usize| at.checked_add(offset);
    let name = read_u32(data, field(0)?, le).ok()?;
    let kind = read_u32(data, field(4)?, le).ok()?;
    let (flags, offset, size, link) = if is_64 {
        (
            read_u64(data, field(8)?, le).ok()?,
            read_u64(data, field(24)?, le).ok()?,
            read_u64(data, field(32)?, le).ok()?,
            read_u32(data, field(40)?, le).ok()?,
        )
    } else {
        (
            u64::from(read_u32(data, field(8)?, le).ok()?),
            u64::from(read_u32(data, field(16)?, le).ok()?),
            u64::from(read_u32(data, field(20)?, le).ok()?),
            read_u32(data, field(24)?, le).ok()?,
        )
    };
    Some(SectionHeader {
        name,
        kind,
        flags,
        offset,
        size,
        link,
    })
}

/// The name at `offset` in the section-name string table.
fn section_name(strings: &[u8], offset: u32) -> String {
    let start = (offset as usize).min(strings.len());
    let end = strings.len().min(start.saturating_add(MAX_SECTION_NAME));
    field_name(&strings[start..end])
}

/// The section headers after index 0 and the section-name string table
/// (empty when absent); see [`sections`] for the fields read and the limits.
fn section_table(data: &[u8]) -> (Vec<SectionHeader>, &[u8]) {
    let is_64 = match data.get(4) {
        Some(&class::ELFCLASS32) => false,
        Some(&class::ELFCLASS64) => true,
        _ => return (Vec::new(), &[]),
    };
    let le = match data.get(5) {
        Some(&data::ELFDATA2LSB) => true,
        Some(&data::ELFDATA2MSB) => false,
        _ => return (Vec::new(), &[]),
    };
    let fields = if is_64 {
        read_u64(data, 0x28, le)
            .ok()
            .zip(read_u16(data, 0x3a, le).ok())
    } else {
        read_u32(data, 0x20, le)
            .ok()
            .map(u64::from)
            .zip(read_u16(data, 0x2e, le).ok())
    };
    let counts = if is_64 {
        read_u16(data, 0x3c, le)
            .ok()
            .zip(read_u16(data, 0x3e, le).ok())
    } else {
        read_u16(data, 0x30, le)
            .ok()
            .zip(read_u16(data, 0x32, le).ok())
    };
    let (Some((table, entry_size)), Some((count, string_index))) = (fields, counts) else {
        return (Vec::new(), &[]);
    };
    let header_size = if is_64 { 64 } else { 40 };
    let entry_size = usize::from(entry_size);
    let Ok(table) = usize::try_from(table) else {
        return (Vec::new(), &[]);
    };
    if table == 0 || table >= data.len() || entry_size < header_size {
        return (Vec::new(), &[]);
    }
    let Some(first) = section_header(data, table, is_64, le) else {
        return (Vec::new(), &[]);
    };
    let count = if count == 0 {
        first.size
    } else {
        u64::from(count)
    };
    let available = ((data.len() - table) / entry_size) as u64;
    let count = count.min(available).min(MAX_SECTIONS) as usize;
    let string_index = if string_index == SHN_XINDEX {
        first.link as usize
    } else {
        usize::from(string_index)
    };
    let header_at = |index: usize| table.checked_add(index.checked_mul(entry_size)?);
    let strings = (string_index < count)
        .then(|| section_header(data, header_at(string_index)?, is_64, le))
        .flatten()
        .and_then(|strtab| {
            let start = usize::try_from(strtab.offset).ok()?;
            let end = start.checked_add(usize::try_from(strtab.size).ok()?)?;
            data.get(start..end.min(data.len()))
        })
        .unwrap_or_default();
    let headers = (1..count)
        .filter_map(|index| section_header(data, header_at(index)?, is_64, le))
        .collect();
    (headers, strings)
}

/// Sections with file bytes, named from the section-name string table and
/// clipped to the input. ELF header: `e_shoff` at 0x20 (64-bit 0x28),
/// `e_shentsize`, `e_shnum` and `e_shstrndx` at 0x2E, 0x30 and 0x32
/// (64-bit 0x3A, 0x3C, 0x3E). `e_shnum` 0 takes the count from section 0's
/// `sh_size`, and `SHN_XINDEX` the string-table index from its `sh_link`.
/// The count is limited by the bytes available and by 4096.
pub fn sections(data: &[u8]) -> Vec<NamedRange> {
    let (headers, strings) = section_table(data);
    headers
        .into_iter()
        .filter(|header| header.kind != SHT_NULL && header.kind != SHT_NOBITS)
        .filter_map(|header| {
            NamedRange::clipped(
                section_name(strings, header.name),
                header.offset,
                header.size,
                data.len(),
            )
        })
        .collect()
}

/// `sh_flags` bit of sections that hold machine instructions ("System V
/// ABI", chapter 4, "Sections", Figure 4-11).
const SHF_EXECINSTR: u64 = 0x4;

/// File ranges `(offset, size)` that hold instructions: sections with
/// `SHF_EXECINSTR` and file bytes, or, without such sections, the
/// executable loadable segments. Sections are preferred: linkers place
/// read-only data in executable segments, and a library may carry another
/// core's firmware there.
pub(crate) fn executable_code(data: &[u8]) -> Vec<(usize, usize)> {
    let (headers, _) = section_table(data);
    let sections: Vec<(usize, usize)> = headers
        .iter()
        .filter(|header| header.kind != SHT_NOBITS && header.flags & SHF_EXECINSTR != 0)
        .filter_map(|header| {
            let range = NamedRange::clipped(String::new(), header.offset, header.size, data.len())?;
            Some((
                usize::try_from(range.offset).ok()?,
                usize::try_from(range.size).ok()?,
            ))
        })
        .collect();
    if sections.is_empty() {
        executable_segments(data)
    } else {
        sections
    }
}

/// `e_phnum` value meaning that the program header count is in section
/// 0's `sh_info` ("System V ABI", "ELF Header", `e_phnum`). Not followed
/// by [`file_extent`].
const PN_XNUM: u16 = 0xffff;

/// Where one ELF class keeps the fields that place file content.
struct Placement {
    /// Size of the ELF header (`Elf32_Ehdr`, `Elf64_Ehdr`).
    header_size: u64,
    /// Offsets of `e_phoff` and `e_shoff` in the ELF header.
    phoff: usize,
    shoff: usize,
    /// Offset of `e_phentsize`; `e_phnum`, `e_shentsize` and `e_shnum`
    /// follow it in 2-byte steps.
    phentsize: usize,
    /// Size of a program header (`Elf32_Phdr`, `Elf64_Phdr`), and the
    /// offsets of `p_offset`, `p_filesz` and `p_flags` in it (`p_type` is
    /// at 0 in both).
    phdr_size: usize,
    p_offset: usize,
    p_filesz: usize,
    p_flags: usize,
    /// Offset of `sh_size` in a section header.
    sh_size: usize,
}

const PLACEMENT_32: Placement = Placement {
    header_size: 52,
    phoff: 0x1c,
    shoff: 0x20,
    phentsize: 0x2a,
    phdr_size: 32,
    p_offset: 0x04,
    p_filesz: 0x10,
    p_flags: 0x18,
    sh_size: 0x14,
};

const PLACEMENT_64: Placement = Placement {
    header_size: 64,
    phoff: 0x20,
    shoff: 0x28,
    phentsize: 0x36,
    phdr_size: 56,
    p_offset: 0x08,
    p_filesz: 0x20,
    p_flags: 0x04,
    sh_size: 0x20,
};

/// Loadable segment type and the execute permission flag ("System V ABI",
/// chapter 5, "Program Header", Figures 5-2 and 5-3).
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
/// Most program headers read by [`executable_segments`].
const MAX_PROGRAM_HEADERS: usize = 4096;

/// File ranges `(offset, size)` of the executable loadable segments
/// (`PT_LOAD` with `PF_X`); see [`load_segments`].
pub(crate) fn executable_segments(data: &[u8]) -> Vec<(usize, usize)> {
    load_segments(data, |flags| flags & PF_X != 0)
}

/// File ranges `(offset, size)` of every loadable segment (`PT_LOAD`); see
/// [`load_segments`].
pub(crate) fn loadable_segments(data: &[u8]) -> Vec<(usize, usize)> {
    load_segments(data, |_| true)
}

/// File ranges `(offset, size)` of the `PT_LOAD` segments whose `p_flags`
/// `keep` accepts, clipped to the input. Empty for an invalid class or byte
/// order, no program header table, `PN_XNUM`, or entries smaller than
/// `Elf32_Phdr`/`Elf64_Phdr`; at most [`MAX_PROGRAM_HEADERS`] entries are
/// read, and reading stops at the first entry past the input.
fn load_segments(data: &[u8], keep: impl Fn(u32) -> bool) -> Vec<(usize, usize)> {
    let is_64 = match data.get(4) {
        Some(&class::ELFCLASS32) => false,
        Some(&class::ELFCLASS64) => true,
        _ => return Vec::new(),
    };
    let le = match data.get(5) {
        Some(&data::ELFDATA2LSB) => true,
        Some(&data::ELFDATA2MSB) => false,
        _ => return Vec::new(),
    };
    let place = if is_64 { &PLACEMENT_64 } else { &PLACEMENT_32 };
    let word = |at: usize| {
        if is_64 {
            read_u64(data, at, le).ok()
        } else {
            read_u32(data, at, le).ok().map(u64::from)
        }
    };
    let half = |at: usize| read_u16(data, at, le).ok();
    let (Some(table), Some(entry_size), Some(count)) = (
        word(place.phoff).and_then(|v| usize::try_from(v).ok()),
        half(place.phentsize),
        half(place.phentsize + 2),
    ) else {
        return Vec::new();
    };
    let entry_size = usize::from(entry_size);
    // An entry starting past the input cannot be read; checking that first
    // also keeps the field offsets added below far from overflow.
    if table == 0 || table >= data.len() || count == PN_XNUM || entry_size < place.phdr_size {
        return Vec::new();
    }
    let mut segments = Vec::new();
    for index in 0..usize::from(count).min(MAX_PROGRAM_HEADERS) {
        let Some(at) = index
            .checked_mul(entry_size)
            .and_then(|o| o.checked_add(table))
            .filter(|&at| at < data.len())
        else {
            break;
        };
        let fields = (
            read_u32(data, at, le).ok(),
            at.checked_add(place.p_flags)
                .and_then(|f| read_u32(data, f, le).ok()),
            at.checked_add(place.p_offset).and_then(word),
            at.checked_add(place.p_filesz).and_then(word),
        );
        let (Some(kind), Some(flags), Some(offset), Some(size)) = fields else {
            break;
        };
        if kind != PT_LOAD || !keep(flags) {
            continue;
        }
        let Ok(start) = usize::try_from(offset) else {
            continue;
        };
        if start >= data.len() {
            continue;
        }
        let end = usize::try_from(size)
            .map_or(data.len(), |size| start.saturating_add(size))
            .min(data.len());
        if end > start {
            segments.push((start, end - start));
        }
    }
    segments
}

/// The bytes an ELF image occupies from its start: the furthest end of
/// the ELF header, the program header table, the file range of every
/// segment and the section header table. Section contents outside every
/// segment count only when they lie before the section header table,
/// where linkers place them. An `e_shnum` of 0 with a section header
/// table takes the count from section 0's `sh_size`.
///
/// `None` for an invalid class or byte order, a truncated ELF header, a
/// program header entry smaller than `Elf32_Phdr`/`Elf64_Phdr`,
/// `PN_XNUM`, or an end past `u64::MAX`. When the program header table is
/// cut short, the result is the table's end, which exceeds `data.len()`.
pub(crate) fn file_extent(data: &[u8]) -> Option<u64> {
    let is_64 = match data.get(4) {
        Some(&class::ELFCLASS32) => false,
        Some(&class::ELFCLASS64) => true,
        _ => return None,
    };
    let le = match data.get(5) {
        Some(&data::ELFDATA2LSB) => true,
        Some(&data::ELFDATA2MSB) => false,
        _ => return None,
    };
    let place = if is_64 { &PLACEMENT_64 } else { &PLACEMENT_32 };
    let word = |at: usize| {
        if is_64 {
            read_u64(data, at, le).ok()
        } else {
            read_u32(data, at, le).ok().map(u64::from)
        }
    };
    let half = |at: usize| read_u16(data, at, le).ok();
    let phoff = word(place.phoff)?;
    let shoff = word(place.shoff)?;
    let phentsize = half(place.phentsize)?;
    let phnum = half(place.phentsize + 2)?;
    let shentsize = half(place.phentsize + 4)?;
    let shnum = half(place.phentsize + 6)?;
    if phnum == PN_XNUM || (phnum > 0 && usize::from(phentsize) < place.phdr_size) {
        return None;
    }

    let mut extent = place.header_size;
    if phnum > 0 {
        let table_size = u64::from(phentsize) * u64::from(phnum);
        let table_end = phoff.checked_add(table_size)?;
        if table_end > data.len() as u64 {
            return Some(table_end);
        }
        extent = extent.max(table_end);
        // The whole table lies inside `data`, so every entry is readable.
        for index in 0..u64::from(phnum) {
            let entry = usize::try_from(phoff + index * u64::from(phentsize)).ok()?;
            let file_size = word(entry + place.p_filesz)?;
            if file_size > 0 {
                let segment_end = word(entry + place.p_offset)?.checked_add(file_size)?;
                extent = extent.max(segment_end);
            }
        }
    }
    if shoff > 0 {
        let count = if shnum == 0 {
            usize::try_from(shoff)
                .ok()
                .and_then(|table| word(table.checked_add(place.sh_size)?))
                .unwrap_or(1)
        } else {
            u64::from(shnum)
        };
        let table_end = shoff.checked_add(count.checked_mul(u64::from(shentsize))?)?;
        extent = extent.max(table_end);
    }
    Some(extent)
}

/// Most ELF images followed after the first one (a bound on the walk).
const MAX_APPENDED_IMAGES: usize = 64;

/// ELF images stored back to back after the image at the start of `data`:
/// each starts where the previous one's [`file_extent`] ends, after
/// optional `0x00`/`0xFF` padding, and must fit in `data`. Returns
/// `(offset, size)` pairs in file order; the walk stops at the first byte
/// that is not padding or an ELF header (Qualcomm firehose bundles store an
/// outer ELF, then TME and programmer images this way; fw1 audit,
/// 2026-11-03).
pub(crate) fn appended_images(data: &[u8]) -> Vec<(usize, usize)> {
    let mut images = Vec::new();
    let Some(mut end) = file_extent(data).and_then(|extent| usize::try_from(extent).ok()) else {
        return images;
    };
    while end < data.len() && images.len() < MAX_APPENDED_IMAGES {
        let padding = data[end..]
            .iter()
            .take_while(|&&b| b == 0x00 || b == 0xff)
            .count();
        let start = end + padding;
        let rest = &data[start..];
        if !rest.starts_with(&super::magic::ELF) {
            break;
        }
        let Some(size) = file_extent(rest)
            .and_then(|extent| usize::try_from(extent).ok())
            .filter(|&size| size <= rest.len())
        else {
            break;
        };
        images.push((start, size));
        end = start + size;
    }
    images
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_elf_header(e_machine: u16, class: u8, endian: u8) -> Vec<u8> {
        let mut data = vec![0u8; 64];
        // ELF magic
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        data[4] = class;
        data[5] = endian;
        data[6] = 1; // EV_CURRENT

        // e_machine at offset 0x12
        if endian == 1 {
            data[0x12] = (e_machine & 0xFF) as u8;
            data[0x13] = (e_machine >> 8) as u8;
        } else {
            data[0x12] = (e_machine >> 8) as u8;
            data[0x13] = (e_machine & 0xFF) as u8;
        }

        data
    }

    #[test]
    fn test_parse_x86_64_elf() {
        let data = make_elf_header(0x3E, 2, 1);
        let result = parse(&data, 2, 1).unwrap();
        assert_eq!(result.isa, Isa::X86_64);
        assert_eq!(result.bitwidth, 64);
        assert_eq!(result.endianness, Endianness::Little);
    }

    #[test]
    fn test_parse_aarch64_elf() {
        let data = make_elf_header(0xB7, 2, 1);
        let result = parse(&data, 2, 1).unwrap();
        assert_eq!(result.isa, Isa::AArch64);
        assert_eq!(result.bitwidth, 64);
    }

    #[test]
    fn test_parse_riscv_elf() {
        let data = make_elf_header(0xF3, 2, 1);
        let result = parse(&data, 2, 1).unwrap();
        assert_eq!(result.isa, Isa::RiscV64);
    }

    #[test]
    fn test_parse_arm_elf() {
        let data = make_elf_header(0x28, 1, 1);
        let result = parse(&data, 1, 1).unwrap();
        assert_eq!(result.isa, Isa::Arm);
        assert_eq!(result.bitwidth, 32);
    }

    #[test]
    fn test_parse_ppc_vle_marker() {
        let mut data = make_elf_header(0x14, 1, 2);
        data.extend_from_slice(b"\0.vletext\0");

        let result = parse(&data, 1, 2).unwrap();
        assert_eq!(result.isa, Isa::PpcVle);
        assert!(result.extensions.iter().any(|e| e.name == "VLE"));
    }

    #[test]
    fn test_e_machine_coverage() {
        // Test a sampling of e_machine values
        assert_eq!(e_machine_to_isa(0x03, 1).0, Isa::X86);
        assert_eq!(e_machine_to_isa(0x3E, 2).0, Isa::X86_64);
        assert_eq!(e_machine_to_isa(0x28, 1).0, Isa::Arm);
        assert_eq!(e_machine_to_isa(0xB7, 2).0, Isa::AArch64);
        assert_eq!(e_machine_to_isa(0xF3, 2).0, Isa::RiscV64);
        assert_eq!(e_machine_to_isa(0x08, 1).0, Isa::Mips);
        assert_eq!(e_machine_to_isa(0x14, 1).0, Isa::Ppc);
        assert_eq!(e_machine_to_isa(0x15, 2).0, Isa::Ppc64);
        assert_eq!(e_machine_to_isa(0x16, 2).0, Isa::S390x);
        assert_eq!(e_machine_to_isa(0x2B, 2).0, Isa::Sparc64);
        assert_eq!(e_machine_to_isa(0x24, 1).0, Isa::Rh850);
        assert_eq!(e_machine_to_isa(0x54, 1).0, Isa::Fr30);
        assert_eq!(e_machine_to_isa(0xC7, 1).0, Isa::K78k0r);
        assert_eq!(e_machine_to_isa(0xA4, 1).0, Isa::Hexagon);
        assert_eq!(e_machine_to_isa(0xF4, 1).0, Isa::Lanai);
        assert_eq!(e_machine_to_isa(0x27, 1).0, Isa::Csky);
        assert_eq!(e_machine_to_isa(0xF9, 1).0, Isa::Mips);
        assert_eq!(e_machine_to_isa(0x102, 2).0, Isa::LoongArch64);
        assert_eq!(e_machine_to_isa(0x31, 1).0, Isa::H8500);
        assert_eq!(e_machine_to_isa(0x47, 1).0, Isa::Hc08);
        assert_eq!(e_machine_to_isa(0xA5, 1).0, Isa::I8051);
        assert_eq!(e_machine_to_isa(0xB1, 1).0, Isa::Cr16);
    }

    #[test]
    fn abi_names_come_only_from_defined_e_flags_fields() {
        let name = |isa: Isa, e_flags: u32| parse_e_flags(isa, e_flags, &[]).0.to_string();
        // Debian powerpc and powerpcspe binaries carry e_flags 0.
        assert_eq!(name(Isa::Ppc, 0), "PowerPC");
        assert_eq!(name(Isa::Ppc, 1), "PowerPC");
        assert_eq!(name(Isa::Ppc64, 0), "PowerPC");
        assert_eq!(name(Isa::Ppc64, 1), "PowerPC [ELFv1]");
        assert_eq!(name(Isa::Ppc64, 2), "PowerPC [ELFv2]");
        // ABI version 1 (0x40) with the soft, single and double modifiers.
        assert_eq!(name(Isa::LoongArch64, 0x43), "LoongArch [LP64D]");
        assert_eq!(name(Isa::LoongArch64, 0x42), "LoongArch [LP64F]");
        assert_eq!(name(Isa::LoongArch32, 0x41), "LoongArch [ILP32S]");
        assert_eq!(name(Isa::LoongArch64, 0x40), "LoongArch");
    }

    #[test]
    fn hexagon_versions_are_read_as_spelled_in_hex_digits() {
        let name = |e_flags: u32| parse_e_flags(Isa::Hexagon, e_flags, &[]).0.to_string();
        // Machine values of the qcm6490, sm8750 and kaanapali DSP libraries.
        assert_eq!(name(0x66), "V66");
        assert_eq!(name(0x79), "V79");
        assert_eq!(name(0x81), "V81");
        assert_eq!(name(0x60), "V60");
        assert_eq!(name(0x05), "V55");
        assert_eq!(name(0x8067), "V67T");
        assert_eq!(name(0), "");
        assert_eq!(name(0x6A), "");
        assert_eq!(name(0x40), "");
    }

    /// Write `value` as `size` bytes at `at` in the given byte order.
    fn put(data: &mut [u8], at: usize, size: usize, value: u64, le: bool) {
        let bytes = if le {
            value.to_le_bytes()[..size].to_vec()
        } else {
            value.to_be_bytes()[8 - size..].to_vec()
        };
        data[at..at + size].copy_from_slice(&bytes);
    }

    /// An ELF32 header (`e_phoff` 0x1C, `e_shoff` 0x20, `e_phentsize`,
    /// `e_phnum`, `e_shentsize`, `e_shnum` at 0x2A..0x32) with a program
    /// header table at 0x34 whose entries (`p_offset` 4, `p_filesz` 0x10)
    /// hold `segments` as (offset, file size), and a section header table
    /// of `sections` 40-byte entries at `shoff` (0 for none).
    fn elf32(le: bool, segments: &[(u64, u64)], shoff: u64, sections: u64) -> Vec<u8> {
        let mut data = make_elf_header(0x28, 1, if le { 1 } else { 2 });
        data.resize(0x34 + 32 * segments.len(), 0);
        put(&mut data, 0x1c, 4, 0x34, le);
        put(&mut data, 0x20, 4, shoff, le);
        put(&mut data, 0x2a, 2, 32, le);
        put(&mut data, 0x2c, 2, segments.len() as u64, le);
        put(&mut data, 0x2e, 2, 40, le);
        put(&mut data, 0x30, 2, sections, le);
        for (index, &(offset, file_size)) in segments.iter().enumerate() {
            let entry = 0x34 + 32 * index;
            put(&mut data, entry + 0x04, 4, offset, le);
            put(&mut data, entry + 0x10, 4, file_size, le);
        }
        data
    }

    #[test]
    fn file_extent_covers_headers_segments_and_section_headers() {
        for le in [true, false] {
            // The furthest end wins, not the last entry; an empty segment
            // has no file range.
            let data = elf32(le, &[(0x100, 0x80), (0x1000, 0), (0x120, 0x10)], 0, 0);
            assert_eq!(file_extent(&data), Some(0x180), "little-endian {le}");
            let data = elf32(le, &[(0x100, 0x80)], 0x400, 3);
            assert_eq!(file_extent(&data), Some(0x400 + 3 * 40));
        }
        // No segments and no sections: the ELF header alone.
        assert_eq!(file_extent(&elf32(true, &[], 0, 0)), Some(52));
    }

    #[test]
    fn file_extent_reads_the_64_bit_layout() {
        // ELF64: `e_phoff` 0x20, `e_phentsize` 0x36, `e_phnum` 0x38; one
        // program header at 0x40 with `p_offset` 8 and `p_filesz` 0x20.
        let mut data = make_elf_header(0xb7, 2, 1);
        data.resize(0x40 + 56, 0);
        put(&mut data, 0x20, 8, 0x40, true);
        put(&mut data, 0x36, 2, 56, true);
        put(&mut data, 0x38, 2, 1, true);
        put(&mut data, 0x40 + 0x08, 8, 0x1_0000, true);
        put(&mut data, 0x40 + 0x20, 8, 0x2345, true);
        assert_eq!(file_extent(&data), Some(0x1_2345));
    }

    #[test]
    fn file_extent_takes_a_large_section_count_from_section_0() {
        // `e_shnum` 0: section 0's `sh_size` (0x14) holds the count.
        let mut data = elf32(true, &[], 0x40, 0);
        data.resize(0x40 + 40, 0);
        put(&mut data, 0x40 + 0x14, 4, 0xff00, true);
        assert_eq!(file_extent(&data), Some(0x40 + 0xff00 * 40));
    }

    #[test]
    fn file_extent_rejects_what_it_cannot_place() {
        let valid = elf32(true, &[(0x100, 0x80)], 0, 0);
        let mut bad_class = valid.clone();
        bad_class[4] = 3;
        let mut bad_order = valid.clone();
        bad_order[5] = 0;
        let mut short_entry = valid.clone();
        put(&mut short_entry, 0x2a, 2, 31, true);
        let mut extended_count = valid.clone();
        put(&mut extended_count, 0x2c, 2, u64::from(PN_XNUM), true);
        for data in [bad_class, bad_order, short_entry, extended_count] {
            assert_eq!(file_extent(&data), None);
        }
        assert_eq!(file_extent(&valid[..0x30]), None, "truncated ELF header");
        // A program header table cut short reports its own end.
        assert_eq!(file_extent(&valid[..0x40]), Some(0x34 + 32));
    }
}
