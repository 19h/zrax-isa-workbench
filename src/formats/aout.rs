//! a.out format parser (BSD, Plan 9, Minix variants).
//!
//! The a.out format was the original Unix executable format, with variants
//! across multiple architectures and operating systems:
//! - BSD a.out: PDP-11, VAX, m68k, SPARC, i386
//! - Plan 9 a.out: i386, AMD64, ARM, MIPS, PowerPC, SPARC, Alpha, ARM64
//! - Minix a.out: i386, m68k

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u16, read_u32};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// BSD a.out magic values (stored in a_midmag field).
pub mod magic {
    /// OMAGIC - Old impure format (text+data contiguous, writable)
    pub const OMAGIC: u16 = 0x0107;
    /// NMAGIC - Read-only text (text/data contiguous)
    pub const NMAGIC: u16 = 0x0108;
    /// ZMAGIC - Demand-load format (page-aligned)
    pub const ZMAGIC: u16 = 0x010B;
    /// QMAGIC - Compact demand load (deprecated)
    pub const QMAGIC: u16 = 0x00CC;
}

/// BSD Machine IDs (MID values from a_midmag field).
pub mod mid {
    pub const ZERO: u8 = 0;
    pub const SUN010: u8 = 1; // Sun 68010/68020
    pub const SUN020: u8 = 2; // Sun 68020
    pub const PC386: u8 = 100; // i386 BSD
    pub const HP200: u8 = 200; // HP 200
    pub const I386: u8 = 134; // i386 BSD
    pub const M68K: u8 = 135; // Motorola 68K
    pub const M68K4K: u8 = 136; // m68k 4k page size
    pub const NS32532: u8 = 137; // NS32532
    pub const SPARC: u8 = 138; // SPARC
    pub const PMAX: u8 = 139; // MIPS (DECstation)
    pub const VAX: u8 = 140; // VAX
    pub const ALPHA: u8 = 141; // Alpha
    pub const MIPS: u8 = 151; // MIPS
    pub const ARM6: u8 = 143; // ARM
    pub const HP300: u8 = 144; // HP 300
    pub const HPUX: u8 = 145; // HP-UX
    pub const HPUX800: u8 = 146; // HP-UX 800
}

/// Plan 9 magic values.
/// Formula: _MAGIC(b) = ((((4*b)+0)*b)+7)
pub mod plan9_magic {
    pub const A_MAGIC: u32 = 0x00000107; // MC68020 (263)
    pub const I_MAGIC: u32 = 0x00000197; // Intel 386 (407)
    pub const J_MAGIC: u32 = 0x00000263; // Intel 960 (611) - unused
    pub const K_MAGIC: u32 = 0x0000022B; // SPARC (555)
    pub const V_MAGIC: u32 = 0x00000367; // MIPS 3000 BE (871)
    pub const X_MAGIC: u32 = 0x00000463; // ATT DSP 3210 (1123) - unused
    pub const M_MAGIC: u32 = 0x00000567; // MIPS 4000 BE (1383)
    pub const D_MAGIC: u32 = 0x0000067B; // MIPS 4000 LE (1659) - unused
    pub const E_MAGIC: u32 = 0x0000051F; // ARM (1311)
    pub const Q_MAGIC: u32 = 0x00000597; // PowerPC (1431)
    pub const N_MAGIC: u32 = 0x00000627; // MIPS 4000 LE (1575)
    pub const L_MAGIC: u32 = 0x00000693; // DEC Alpha (1683)
    pub const P_MAGIC: u32 = 0x00000733; // MIPS 4000 LE (1843) - unused
    pub const U_MAGIC: u32 = 0x000007E3; // SPARC 64 (2019)
    pub const S_MAGIC: u32 = 0x00000893; // AMD64 (2195)
    pub const T_MAGIC: u32 = 0x00000973; // AMD64 (2419) - unused
    pub const R_MAGIC: u32 = 0x000009BF; // ARM64 (2495)
}

/// Minix a.out magic values.
pub mod minix_magic {
    pub const MINIX_COMBID: u32 = 0x04100301; // Combined I&D
    pub const MINIX_SEPID: u32 = 0x04200301; // Separate I&D
}

/// BSD a.out header size.
pub const BSD_AOUT_HEADER_SIZE: usize = 32;

/// Plan 9 a.out header size.
pub const PLAN9_HEADER_SIZE: usize = 32;

/// Minix a.out header size.
pub const MINIX_HEADER_SIZE: usize = 32;

/// Detected a.out variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AoutVariant {
    /// BSD a.out
    Bsd { mid: u8, magic: u16 },
    /// Plan 9 a.out
    Plan9 { magic: u32 },
    /// Minix a.out
    Minix { combined_id: bool },
}

/// Map BSD MID to ISA.
fn mid_to_isa(mid: u8) -> (Isa, u8, Endianness) {
    match mid {
        mid::ZERO => (Isa::Unknown(0), 32, Endianness::Little),
        mid::SUN010 | mid::SUN020 | mid::M68K | mid::M68K4K | mid::HP200 | mid::HP300 => {
            (Isa::M68k, 32, Endianness::Big)
        }
        mid::PC386 | mid::I386 => (Isa::X86, 32, Endianness::Little),
        mid::SPARC => (Isa::Sparc, 32, Endianness::Big),
        mid::VAX => (Isa::Vax, 32, Endianness::Little),
        mid::ALPHA => (Isa::Alpha, 64, Endianness::Little),
        mid::PMAX | mid::MIPS => (Isa::Mips, 32, Endianness::Little),
        mid::ARM6 => (Isa::Arm, 32, Endianness::Little),
        mid::NS32532 => (Isa::Unknown(0x32532), 32, Endianness::Little),
        _ => (Isa::Unknown(mid as u32), 32, Endianness::Little),
    }
}

/// Map Plan 9 magic to ISA.
fn plan9_magic_to_isa(magic: u32) -> (Isa, u8, Endianness) {
    match magic {
        plan9_magic::A_MAGIC => (Isa::M68k, 32, Endianness::Big),
        plan9_magic::I_MAGIC => (Isa::X86, 32, Endianness::Little),
        plan9_magic::K_MAGIC => (Isa::Sparc, 32, Endianness::Big),
        plan9_magic::V_MAGIC | plan9_magic::M_MAGIC => (Isa::Mips, 32, Endianness::Big),
        plan9_magic::N_MAGIC => (Isa::Mips, 32, Endianness::Little),
        plan9_magic::E_MAGIC => (Isa::Arm, 32, Endianness::Little),
        plan9_magic::Q_MAGIC => (Isa::Ppc, 32, Endianness::Big),
        plan9_magic::L_MAGIC => (Isa::Alpha, 64, Endianness::Little),
        plan9_magic::U_MAGIC => (Isa::Sparc64, 64, Endianness::Big),
        plan9_magic::S_MAGIC => (Isa::X86_64, 64, Endianness::Little),
        plan9_magic::R_MAGIC => (Isa::AArch64, 64, Endianness::Little),
        _ => (Isa::Unknown(magic), 32, Endianness::Little),
    }
}

/// Detect a.out variant from raw bytes.
pub fn detect(data: &[u8]) -> Option<AoutVariant> {
    if data.len() < 4 {
        return None;
    }

    // Try Plan 9 first (big-endian header)
    let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if matches!(
        magic_be,
        plan9_magic::A_MAGIC
            | plan9_magic::I_MAGIC
            | plan9_magic::K_MAGIC
            | plan9_magic::V_MAGIC
            | plan9_magic::M_MAGIC
            | plan9_magic::E_MAGIC
            | plan9_magic::Q_MAGIC
            | plan9_magic::N_MAGIC
            | plan9_magic::L_MAGIC
            | plan9_magic::U_MAGIC
            | plan9_magic::S_MAGIC
            | plan9_magic::R_MAGIC
    ) {
        return Some(AoutVariant::Plan9 { magic: magic_be });
    }

    // Try Minix
    let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic_le == minix_magic::MINIX_COMBID {
        return Some(AoutVariant::Minix { combined_id: true });
    }
    if magic_le == minix_magic::MINIX_SEPID {
        return Some(AoutVariant::Minix { combined_id: false });
    }

    // Try BSD a.out (extract magic from low 16 bits)
    // a_midmag format: flags<<26 | mid<<16 | magic
    // For little-endian, magic is in first two bytes
    let bsd_magic = u16::from_le_bytes([data[0], data[1]]);
    let mid = data[2];

    if matches!(
        bsd_magic,
        magic::OMAGIC | magic::NMAGIC | magic::ZMAGIC | magic::QMAGIC
    ) {
        return Some(AoutVariant::Bsd {
            mid,
            magic: bsd_magic,
        });
    }

    // Also check big-endian BSD (some m68k systems)
    let bsd_magic_be = u16::from_be_bytes([data[0], data[1]]);
    if matches!(bsd_magic_be, magic::OMAGIC | magic::NMAGIC | magic::ZMAGIC) {
        let mid_be = data[3];
        return Some(AoutVariant::Bsd {
            mid: mid_be,
            magic: bsd_magic_be,
        });
    }

    None
}

/// Parse BSD a.out.
fn parse_bsd(data: &[u8], mid: u8, aout_magic: u16) -> Result<ClassificationResult> {
    if data.len() < BSD_AOUT_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: BSD_AOUT_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let (isa, bitwidth, endianness) = mid_to_isa(mid);
    let le = endianness == Endianness::Little;

    // Parse header fields
    let text_size = read_u32(data, 4, le)?;
    let data_size = read_u32(data, 8, le)?;
    let _bss_size = read_u32(data, 12, le)?;
    let _sym_size = read_u32(data, 16, le)?;
    let entry = read_u32(data, 20, le)?;

    // Determine magic type string
    let magic_name = match aout_magic {
        magic::OMAGIC => "OMAGIC",
        magic::NMAGIC => "NMAGIC",
        magic::ZMAGIC => "ZMAGIC",
        magic::QMAGIC => "QMAGIC",
        _ => "Unknown",
    };

    let mut notes = vec![format!("BSD a.out ({})", magic_name)];
    notes.push(format!("MID: {} ({})", mid, mid_name(mid)));
    notes.push(format!(
        "Text: {} bytes, Data: {} bytes",
        text_size, data_size
    ));

    let metadata = ClassificationMetadata {
        entry_point: Some(entry as u64),
        code_size: Some(text_size as u64),
        notes,
        ..Default::default()
    };

    let mut result = ClassificationResult::from_format(isa, bitwidth, endianness, FileFormat::Aout);
    result.variant = Variant::new(magic_name);
    result.metadata = metadata;

    Ok(result)
}

/// Get MID name.
fn mid_name(mid: u8) -> &'static str {
    match mid {
        mid::ZERO => "unknown",
        mid::SUN010 => "Sun 68010/68020",
        mid::SUN020 => "Sun 68020",
        mid::PC386 => "PC 386",
        mid::I386 => "i386",
        mid::M68K => "m68k",
        mid::M68K4K => "m68k 4K",
        mid::SPARC => "SPARC",
        mid::PMAX => "MIPS (DECstation)",
        mid::VAX => "VAX",
        mid::ALPHA => "Alpha",
        mid::MIPS => "MIPS",
        mid::ARM6 => "ARM",
        mid::HP300 => "HP 300",
        _ => "unknown",
    }
}

/// Parse Plan 9 a.out.
fn parse_plan9(data: &[u8], magic: u32) -> Result<ClassificationResult> {
    if data.len() < PLAN9_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: PLAN9_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let (isa, bitwidth, endianness) = plan9_magic_to_isa(magic);

    // Plan 9 header is always big-endian
    let text_size = read_u32(data, 4, false)?;
    let data_size = read_u32(data, 8, false)?;
    let _bss_size = read_u32(data, 12, false)?;
    let _sym_size = read_u32(data, 16, false)?;
    let entry = read_u32(data, 20, false)?;
    let _spsz = read_u32(data, 24, false)?;
    let _pcsz = read_u32(data, 28, false)?;

    // Arch name
    let arch_name = match magic {
        plan9_magic::A_MAGIC => "MC68020",
        plan9_magic::I_MAGIC => "Intel 386",
        plan9_magic::K_MAGIC => "SPARC",
        plan9_magic::V_MAGIC | plan9_magic::M_MAGIC => "MIPS BE",
        plan9_magic::N_MAGIC => "MIPS LE",
        plan9_magic::E_MAGIC => "ARM",
        plan9_magic::Q_MAGIC => "PowerPC",
        plan9_magic::L_MAGIC => "Alpha",
        plan9_magic::U_MAGIC => "SPARC64",
        plan9_magic::S_MAGIC => "AMD64",
        plan9_magic::R_MAGIC => "ARM64",
        _ => "Unknown",
    };

    let mut notes = vec!["Plan 9 a.out".to_string()];
    notes.push(format!("Architecture: {}", arch_name));
    notes.push(format!(
        "Text: {} bytes, Data: {} bytes",
        text_size, data_size
    ));

    let metadata = ClassificationMetadata {
        entry_point: Some(entry as u64),
        code_size: Some(text_size as u64),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(isa, bitwidth, endianness, FileFormat::Plan9Aout);
    result.variant = Variant::new(arch_name);
    result.metadata = metadata;

    Ok(result)
}

/// Parse Minix a.out.
fn parse_minix(data: &[u8], combined_id: bool) -> Result<ClassificationResult> {
    if data.len() < MINIX_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: MINIX_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // Minix is little-endian (i386 or m68k)
    // Header after magic
    let header_len = read_u32(data, 4, true)?;
    let text_size = read_u32(data, 8, true)?;
    let data_size = read_u32(data, 12, true)?;
    let _bss_size = read_u32(data, 16, true)?;
    let entry = read_u32(data, 20, true)?;

    // Determine architecture from header length and other heuristics
    // Minix 3 typically uses i386
    let (isa, bitwidth, endianness) = (Isa::X86, 32, Endianness::Little);

    let id_type = if combined_id {
        "Combined I&D"
    } else {
        "Separate I&D"
    };

    let mut notes = vec!["Minix a.out".to_string()];
    notes.push(format!("Type: {}", id_type));
    notes.push(format!("Header: {} bytes", header_len));
    notes.push(format!(
        "Text: {} bytes, Data: {} bytes",
        text_size, data_size
    ));

    let metadata = ClassificationMetadata {
        entry_point: Some(entry as u64),
        code_size: Some(text_size as u64),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(isa, bitwidth, endianness, FileFormat::MinixAout);
    result.variant = Variant::new(id_type);
    result.metadata = metadata;

    Ok(result)
}

/// Parse an a.out file.
pub fn parse(data: &[u8], variant: AoutVariant) -> Result<ClassificationResult> {
    match variant {
        AoutVariant::Bsd { mid, magic } => parse_bsd(data, mid, magic),
        AoutVariant::Plan9 { magic } => parse_plan9(data, magic),
        AoutVariant::Minix { combined_id } => parse_minix(data, combined_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bsd_aout(magic: u16, mid: u8) -> Vec<u8> {
        let mut data = vec![0u8; 64];
        // a_midmag (little-endian: magic in first 2 bytes, mid in 3rd)
        data[0] = (magic & 0xFF) as u8;
        data[1] = (magic >> 8) as u8;
        data[2] = mid;
        data[3] = 0; // flags

        // Text size
        data[4..8].copy_from_slice(&1024u32.to_le_bytes());
        // Data size
        data[8..12].copy_from_slice(&512u32.to_le_bytes());
        // BSS size
        data[12..16].copy_from_slice(&256u32.to_le_bytes());
        // Symbol size
        data[16..20].copy_from_slice(&0u32.to_le_bytes());
        // Entry point
        data[20..24].copy_from_slice(&0x1000u32.to_le_bytes());

        data
    }

    fn make_plan9_aout(magic: u32) -> Vec<u8> {
        let mut data = vec![0u8; 64];
        // Magic (big-endian)
        data[0..4].copy_from_slice(&magic.to_be_bytes());
        // Text size
        data[4..8].copy_from_slice(&2048u32.to_be_bytes());
        // Data size
        data[8..12].copy_from_slice(&1024u32.to_be_bytes());
        // BSS size
        data[12..16].copy_from_slice(&512u32.to_be_bytes());
        // Symbol size
        data[16..20].copy_from_slice(&0u32.to_be_bytes());
        // Entry point
        data[20..24].copy_from_slice(&0x200000u32.to_be_bytes());

        data
    }

    #[test]
    fn test_detect_bsd_zmagic() {
        let data = make_bsd_aout(magic::ZMAGIC, mid::I386);
        let variant = detect(&data);
        assert!(matches!(
            variant,
            Some(AoutVariant::Bsd {
                mid: mid::I386,
                magic: magic::ZMAGIC
            })
        ));
    }

    #[test]
    fn test_detect_plan9_amd64() {
        let data = make_plan9_aout(plan9_magic::S_MAGIC);
        let variant = detect(&data);
        assert!(matches!(
            variant,
            Some(AoutVariant::Plan9 {
                magic: plan9_magic::S_MAGIC
            })
        ));
    }

    #[test]
    fn test_parse_bsd_i386() {
        let data = make_bsd_aout(magic::ZMAGIC, mid::I386);
        let variant = detect(&data).unwrap();
        let result = parse(&data, variant).unwrap();
        assert_eq!(result.isa, Isa::X86);
        assert_eq!(result.bitwidth, 32);
        assert_eq!(result.format, FileFormat::Aout);
    }

    #[test]
    fn test_parse_plan9_amd64() {
        let data = make_plan9_aout(plan9_magic::S_MAGIC);
        let variant = detect(&data).unwrap();
        let result = parse(&data, variant).unwrap();
        assert_eq!(result.isa, Isa::X86_64);
        assert_eq!(result.bitwidth, 64);
        assert_eq!(result.format, FileFormat::Plan9Aout);
    }

    #[test]
    fn test_parse_plan9_arm64() {
        let data = make_plan9_aout(plan9_magic::R_MAGIC);
        let variant = detect(&data).unwrap();
        let result = parse(&data, variant).unwrap();
        assert_eq!(result.isa, Isa::AArch64);
        assert_eq!(result.format, FileFormat::Plan9Aout);
    }
}
