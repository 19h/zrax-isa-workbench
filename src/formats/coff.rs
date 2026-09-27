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
    /// Intel i860 COFF.
    pub const I860: u16 = 0x014D;
    /// Intel i960 COFF, read-only text.
    pub const I960_RO: u16 = 0x0160;
    /// Intel i960 COFF, writable text.
    pub const I960_RW: u16 = 0x0161;
    pub const H8300_LEGACY: u16 = 0x0083;
    pub const H8300S_LEGACY: u16 = 0x0283;
    /// TI COFF version 1 header magic (the target is in the header, not here).
    pub const TI_COFF1: u16 = 0x00C1;
    /// TI COFF version 2 header magic (the target is in the header, not here).
    pub const TI_COFF2: u16 = 0x00C2;
    pub const ARM_THUMB_LEGACY: u16 = 0x0A00;
    pub const M68K_LEGACY_BE: u16 = 0x5001;
    pub const ADSP_21XX_LEGACY: u16 = 0x521C;
    pub const MIPS_LEGACY_BE: u16 = 0x6001;
    pub const Z8_LEGACY: u16 = 0x8000;
    /// TI COFF2 magic written by a big-endian target.
    pub const TI_COFF2_BE: u16 = 0xC200;
    /// TI COFF1 magic written by a big-endian target.
    pub const TI_COFF1_BE: u16 = 0xC100;

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
                | I960_RO
                | I960_RW
                | I860
                | H8300S_LEGACY
                | TI_COFF1
                | TI_COFF2
                | TI_COFF1_BE
                | ARM_THUMB_LEGACY
                | M68K_LEGACY_BE
                | ADSP_21XX_LEGACY
                | MIPS_LEGACY_BE
                | Z8_LEGACY
                | TI_COFF2_BE
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
        machine::M32R => (Isa::M32r, 32, Endianness::Little, None),
        machine::ARM64 => (Isa::AArch64, 64, Endianness::Little, None),
        machine::I960_RO | machine::I960_RW => (Isa::I960, 32, Endianness::Little, None),
        machine::I860 => (Isa::I860, 32, Endianness::Little, None),
        machine::H8300_LEGACY => (Isa::H8300, 16, Endianness::Big, Some("H8/300")),
        machine::H8300S_LEGACY => (Isa::H8300, 16, Endianness::Big, Some("H8S")),
        // TI COFF: the real target is the target ID in the header, see ti_target().
        machine::TI_COFF1 | machine::TI_COFF2 | machine::TI_COFF1_BE | machine::TI_COFF2_BE => {
            (Isa::Unknown(machine as u32), 32, Endianness::Little, Some("TI COFF"))
        }
        machine::ARM_THUMB_LEGACY => (Isa::Arm, 32, Endianness::Little, Some("Thumb")),
        machine::M68K_LEGACY_BE => (Isa::M68k, 32, Endianness::Big, Some("68k COFF")),
        machine::ADSP_21XX_LEGACY => (Isa::Sharc, 32, Endianness::Little, Some("ADSP-21xx")),
        machine::MIPS_LEGACY_BE => (Isa::Mips, 32, Endianness::Big, Some("MIPS BE COFF")),
        machine::Z8_LEGACY => (Isa::Z8, 8, Endianness::Big, Some("Zilog Z8")),
        other => (Isa::Unknown(other as u32), 32, Endianness::Little, None),
    }
}

/// Map a TI COFF target ID (header offset 20) to an ISA.
///
/// See TI SPRAAO8 "Common Object File Format". The magic at offset 0 of a
/// TI COFF file is only the COFF *version* (0x00C1/0x00C2); the processor is
/// identified here.
pub fn ti_target(target_id: u16) -> Option<(Isa, u8, &'static str)> {
    Some(match target_id {
        0x0093 => (Isa::TiC3x, 32, "TMS320C3x/C4x"),
        0x0097 => (Isa::Arm, 32, "TMS470"),
        0x0098 => (Isa::TiC5500, 16, "TMS320C54x"),
        0x0099 => (Isa::TiC6000, 32, "TMS320C6000"),
        0x009C => (Isa::TiC5500, 16, "TMS320C55x"),
        0x009D => (Isa::TiC28x, 32, "TMS320C28x"),
        0x00A0 => (Isa::Msp430, 16, "MSP430"),
        0x00A1 => (Isa::TiC5500, 16, "TMS320C55x+"),
        _ => return None,
    })
}

/// Header layout of a COFF flavour: (big-endian, file header size, section header size).
fn layout(data: &[u8], machine: u16) -> (bool, usize, usize) {
    match machine {
        // Big-endian legacy COFF whose magic reads byte-swapped as little-endian.
        machine::M68K_LEGACY_BE
        | machine::MIPS_LEGACY_BE
        | machine::H8300_LEGACY
        | machine::H8300S_LEGACY => (true, COFF_HEADER_SIZE, SECTION_HEADER_SIZE),
        // Zilog COFF (ZDS): the whole header is little-endian.
        machine::Z8_LEGACY => (false, COFF_HEADER_SIZE, SECTION_HEADER_SIZE),
        // TI COFF: 22-byte file header (target ID at 20); COFF2 sections are 48 bytes.
        // GNU i960 COFF section headers carry an extra s_align word.
        machine::I960_RO | machine::I960_RW => (false, COFF_HEADER_SIZE, SECTION_HEADER_SIZE + 4),
        machine::TI_COFF2 => (false, COFF_HEADER_SIZE + 2, 48),
        machine::TI_COFF1 => (false, COFF_HEADER_SIZE + 2, SECTION_HEADER_SIZE),
        machine::TI_COFF2_BE => (true, COFF_HEADER_SIZE + 2, 48),
        machine::TI_COFF1_BE => (true, COFF_HEADER_SIZE + 2, SECTION_HEADER_SIZE),
        _ => {
            let _ = data;
            (false, COFF_HEADER_SIZE, SECTION_HEADER_SIZE)
        }
    }
}

/// Whether the file header and section table are consistent with the file.
fn header_is_plausible(data: &[u8], machine: u16) -> bool {
    let (be, header_size, section_size) = layout(data, machine);
    if data.len() < header_size {
        return false;
    }
    let u16_at = |o: usize| {
        let b = [data[o], data[o + 1]];
        if be { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) }
    };
    let u32_at = |o: usize| {
        let b = [data[o], data[o + 1], data[o + 2], data[o + 3]];
        if be { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
    };
    let num_sections = u16_at(2) as usize;
    let ptr_symbol_table = u64::from(u32_at(8));
    let num_symbols = u64::from(u32_at(12));
    let opt_size = u16_at(16) as usize;
    let file_len = data.len() as u64;

    if num_sections == 0 || num_sections > 1024 {
        return false;
    }
    if opt_size != 0 && !(28..=512).contains(&opt_size) {
        return false;
    }
    if ptr_symbol_table != 0 && ptr_symbol_table + num_symbols * 18 > file_len {
        return false;
    }
    let table = header_size + opt_size;
    if table + num_sections * section_size > data.len() {
        return false;
    }
    (0..num_sections).all(|i| {
        let sh = table + i * section_size;
        let name = &data[sh..sh + 8];
        let name_len = name.iter().position(|&b| b == 0).unwrap_or(8);
        // TI COFF2 and long-name COFF store a string-table offset (first
        // four bytes zero) instead of an inline name.
        let named = name_len > 0 && name[..name_len].iter().all(u8::is_ascii_graphic);
        let offset_name = name[..4] == [0, 0, 0, 0];
        let raw_size = u64::from(u32_at(sh + 16));
        let raw_ptr = u64::from(u32_at(sh + 20));
        (named || offset_name) && (raw_ptr == 0 || raw_ptr + raw_size <= file_len)
    })
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

    // The machine field is only two bytes, and raw firmware (vector tables,
    // literal pools) produces "valid" machine values all the time, so the rest
    // of the header must hold together before we call this COFF.
    let _ = (num_sections, ptr_symbol_table, num_symbols, size_opt_header, characteristics);
    if !header_is_plausible(data, machine) {
        return None;
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

    let (mut isa, mut bitwidth, mut endianness, mut variant_note) = machine_to_isa(machine);
    if matches!(
        machine,
        machine::TI_COFF1 | machine::TI_COFF2 | machine::TI_COFF1_BE | machine::TI_COFF2_BE
    ) {
        let big = matches!(machine, machine::TI_COFF1_BE | machine::TI_COFF2_BE);
        if let Ok(target) = read_u16(data, 20, !big) {
            if let Some((t_isa, t_bits, t_name)) = ti_target(target) {
                isa = t_isa;
                bitwidth = t_bits;
                variant_note = Some(t_name);
            } else {
                isa = Isa::Unknown(u32::from(target));
            }
        }
        endianness = if big { Endianness::Big } else { Endianness::Little };
    }

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
        machine::TI_COFF1 => "Texas Instruments COFF v1",
        machine::TI_COFF2 => "Texas Instruments COFF v2",
        machine::TI_COFF1_BE => "Texas Instruments COFF v1 (big-endian)",
        machine::ARM_THUMB_LEGACY => "ARM Thumb (legacy)",
        machine::M68K_LEGACY_BE => "Motorola 68k (legacy COFF)",
        machine::ADSP_21XX_LEGACY => "Analog Devices ADSP-21xx",
        machine::MIPS_LEGACY_BE => "MIPS (legacy big-endian COFF)",
        machine::Z8_LEGACY => "Zilog Z8",
        machine::TI_COFF2_BE => "Texas Instruments COFF v2 (big-endian)",
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

        // Section names, so the header passes the plausibility check.
        for i in 0..num_sections as usize {
            let sh = COFF_HEADER_SIZE + i * SECTION_HEADER_SIZE;
            data[sh..sh + 5].copy_from_slice(b".text");
        }

        // Characteristics
        data[18] = characteristics::MACHINE_32BIT as u8;
        data[19] = 0;

        data
    }

    fn make_bigobj_header(machine: u16, num_sections: u32) -> Vec<u8> {
        let mut data = vec![0u8; BIGOBJ_HEADER_SIZE + 256];

        // Bigobj signature
        data[0..2].copy_from_slice(&BIGOBJ_SIG1.to_le_bytes());
        data[2..4].copy_from_slice(&BIGOBJ_SIG2.to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes()); // version
        data[6..8].copy_from_slice(&machine.to_le_bytes());

        // NumberOfSections, PointerToSymbolTable, NumberOfSymbols
        data[44..48].copy_from_slice(&num_sections.to_le_bytes());
        data[48..52].copy_from_slice(&(BIGOBJ_HEADER_SIZE as u32).to_le_bytes());
        data[52..56].copy_from_slice(&10u32.to_le_bytes());

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
    fn test_detect_bigobj_x86() {
        let data = make_bigobj_header(machine::I386, 512);
        assert_eq!(detect(&data), Some(machine::I386));
    }

    #[test]
    fn test_parse_bigobj_x86() {
        let data = make_bigobj_header(machine::I386, 1024);
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::X86);
        assert_eq!(result.format, FileFormat::Coff);
        assert_eq!(result.metadata.raw_machine, Some(machine::I386 as u32));
    }

    #[test]
    fn test_zilog_z8_coff_is_little_endian() {
        let data = make_coff_header(machine::Z8_LEGACY, 2);
        assert_eq!(&data[..2], &[0x00, 0x80]);
        assert_eq!(detect(&data), Some(machine::Z8_LEGACY));
        assert_eq!(parse(&data).unwrap().isa, Isa::Z8);
    }

    #[test]
    fn test_ti_coff_c3x_target() {
        assert_eq!(ti_target(0x0093).map(|t| t.0), Some(Isa::TiC3x));
    }

    #[test]
    fn test_detect_legacy_arm_thumb_machine() {
        let data = make_coff_header(machine::ARM_THUMB_LEGACY, 3);
        assert_eq!(detect(&data), Some(machine::ARM_THUMB_LEGACY));
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::Arm);
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
