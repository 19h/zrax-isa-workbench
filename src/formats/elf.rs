//! ELF (Executable and Linkable Format) parser.
//!
//! Comprehensive ELF parser supporting all e_machine values and
//! architecture-specific e_flags parsing.

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u16, read_u32, read_u64};
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

        // HP PA-RISC
        0x0F => (Isa::Parisc, 32),

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
        0x17 => (Isa::Unknown(0x17), 32),

        // NEC V800
        0x24 => (Isa::Unknown(0x24), 32),

        // Fujitsu FR20
        0x25 => (Isa::Unknown(0x25), 32),

        // TRW RH-32
        0x26 => (Isa::Unknown(0x26), 32),

        // Motorola RCE
        0x27 => (Isa::Unknown(0x27), 32),

        // ARM 32-bit
        0x28 => (Isa::Arm, 32),

        // DEC Alpha (unofficial)
        0x29 => (Isa::Alpha, 64),

        // Hitachi SuperH
        0x2A => (Isa::Sh, 32),

        // SPARC V9 64-bit
        0x2B => (Isa::Sparc64, 64),

        // Siemens TriCore
        0x2C => (Isa::Unknown(0x2C), 32),

        // ARC (ARCv1)
        0x2D => (Isa::Arc, 32),

        // Hitachi H8/300
        0x2E => (Isa::Unknown(0x2E), 16),

        // Hitachi H8/300H
        0x2F => (Isa::Unknown(0x2F), 16),

        // Hitachi H8S
        0x30 => (Isa::Unknown(0x30), 16),

        // Hitachi H8/500
        0x31 => (Isa::Unknown(0x31), 16),

        // Intel IA-64
        0x32 => (Isa::Ia64, 64),

        // Stanford MIPS-X
        0x33 => (Isa::Mips, 32),

        // Motorola ColdFire
        0x34 => (Isa::ColdFire, 32),

        // Motorola M68HC12
        0x35 => (Isa::Unknown(0x35), 16),

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
        0x43 => (Isa::Unknown(0x43), 8),

        // STMicro ST7
        0x44 => (Isa::Unknown(0x44), 8),

        // Motorola MC68HC16
        0x45 => (Isa::Unknown(0x45), 16),

        // Motorola MC68HC11
        0x46 => (Isa::Unknown(0x46), 8),

        // Motorola MC68HC08
        0x47 => (Isa::Unknown(0x47), 8),

        // Motorola MC68HC05
        0x48 => (Isa::Unknown(0x48), 8),

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
        0x54 => (Isa::Unknown(0x54), 32),

        // Mitsubishi D10V
        0x55 => (Isa::Unknown(0x55), 16),

        // Mitsubishi D30V
        0x56 => (Isa::Unknown(0x56), 32),

        // NEC V850
        0x57 => (Isa::V850, 32),

        // Mitsubishi M32R
        0x58 => (Isa::Unknown(0x58), 32),

        // Matsushita MN10300
        0x59 => (Isa::Unknown(0x59), 32),

        // Matsushita MN10200
        0x5A => (Isa::Unknown(0x5A), 16),

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
        0x67 => (Isa::Unknown(0x67), 16),

        // Fujitsu F2MC16
        0x68 => (Isa::Unknown(0x68), 16),

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

        // Infineon C16x
        0x74 => (Isa::Unknown(0x74), 16),

        // Renesas M16C
        0x75 => (Isa::Unknown(0x75), 16),

        // Microchip dsPIC30F
        0x76 => (Isa::Unknown(0x76), 16),

        // Freescale CE
        0x77 => (Isa::Unknown(0x77), 32),

        // Renesas M32C
        0x78 => (Isa::Unknown(0x78), 32),

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
        0x8D => (Isa::TiC2000, 16),

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
        0xA2 => (Isa::Unknown(0xA2), 32),

        // NXP TriMedia
        0xA3 => (Isa::Unknown(0xA3), 32),

        // Qualcomm Hexagon
        0xA4 => (Isa::Hexagon, 32),

        // Intel 8051
        0xA5 => (Isa::Unknown(0xA5), 8),

        // STMicro STxP7x
        0xA6 => (Isa::Unknown(0xA6), 32),

        // Andes NDS32
        0xA7 => (Isa::Unknown(0xA7), 32),

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
        0xB1 => (Isa::Unknown(0xB1), 16),

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
        0xC5 => (Isa::Unknown(0xC5), 16),

        // Broadcom VideoCore V
        0xC6 => (Isa::VideoCore5, 32),

        // Renesas 78KOR
        0xC7 => (Isa::Unknown(0xC7), 8),

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
        0xF4 => (Isa::Unknown(0xF4), 32),

        // CEVA
        0xF5 => (Isa::Unknown(0xF5), 32),

        // CEVA X2
        0xF6 => (Isa::Unknown(0xF6), 32),

        // Linux BPF
        0xF7 => (Isa::Bpf, 64),

        // Graphcore IPU
        0xF8 => (Isa::Unknown(0xF8), 32),

        // Imagination GPU
        0xF9 => (Isa::Unknown(0xF9), 32),

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
        Isa::Ppc64 => parse_ppc64_flags(e_flags),
        Isa::Sh | Isa::Sh4 => parse_sh_flags(e_flags),
        Isa::Hexagon => parse_hexagon_flags(e_flags),
        Isa::LoongArch32 | Isa::LoongArch64 => parse_loongarch_flags(e_flags),
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

/// Parse PowerPC64 ELF flags.
fn parse_ppc64_flags(e_flags: u32) -> (Variant, Vec<Extension>) {
    let abi = e_flags & 0x3;
    let abi_name = match abi {
        1 => "ELFv1",
        2 => "ELFv2",
        _ => "",
    };

    (Variant::with_abi("PowerPC64", abi_name), Vec::new())
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

/// Parse Hexagon ELF flags.
fn parse_hexagon_flags(e_flags: u32) -> (Variant, Vec<Extension>) {
    let version = e_flags & 0xFF;
    let name = format!("V{}", version);
    (Variant::new(name), Vec::new())
}

/// Parse LoongArch ELF flags.
fn parse_loongarch_flags(e_flags: u32) -> (Variant, Vec<Extension>) {
    let abi = e_flags & 0x7;
    let abi_name = match abi {
        0 => "LP64S",
        1 => "LP64F",
        2 => "LP64D",
        _ => "",
    };

    (Variant::with_abi("LoongArch", abi_name), Vec::new())
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
    let (isa, bitwidth) = e_machine_to_isa(e_machine, ei_class);

    // Parse architecture-specific flags
    let (variant, mut extensions) = parse_e_flags(isa, e_flags, data);

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
        assert_eq!(e_machine_to_isa(0xA4, 1).0, Isa::Hexagon);
        assert_eq!(e_machine_to_isa(0x102, 2).0, Isa::LoongArch64);
    }
}
