//! DOS MZ, NE (New Executable), and LE/LX (Linear Executable) parser.
//!
//! This module handles legacy Microsoft/IBM executable formats:
//! - MZ: Original DOS executable format (16-bit real mode)
//! - NE: New Executable for 16-bit Windows and OS/2
//! - LE/LX: Linear Executable for OS/2 32-bit and VxD drivers

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u16, read_u32};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// MZ header signature.
pub const MZ_SIGNATURE: [u8; 2] = [b'M', b'Z'];
pub const ZM_SIGNATURE: [u8; 2] = [b'Z', b'M']; // Alternative (obsolete)

/// NE header signature.
pub const NE_SIGNATURE: [u8; 2] = [b'N', b'E'];

/// LE header signature.
pub const LE_SIGNATURE: [u8; 2] = [b'L', b'E'];

/// LX header signature.
pub const LX_SIGNATURE: [u8; 2] = [b'L', b'X'];

/// MZ header size.
pub const MZ_HEADER_SIZE: usize = 64;

/// NE header size.
pub const NE_HEADER_SIZE: usize = 64;

/// LE/LX header size.
pub const LE_HEADER_SIZE: usize = 196;

/// NE target OS values.
pub mod ne_os {
    pub const UNKNOWN: u8 = 0;
    pub const OS2: u8 = 1;
    pub const WINDOWS: u8 = 2;
    pub const DOS4: u8 = 3;
    pub const WINDOWS386: u8 = 4;
    pub const BOSS: u8 = 5;
}

/// LE/LX CPU types.
pub mod le_cpu {
    pub const UNKNOWN: u16 = 0;
    pub const I286: u16 = 1;
    pub const I386: u16 = 2;
    pub const I486: u16 = 3;
    pub const PENTIUM: u16 = 4;
    pub const I860: u16 = 0x20;
    pub const N11: u16 = 0x21;
    pub const MIPS1: u16 = 0x40;
    pub const MIPS2: u16 = 0x41;
    pub const MIPS3: u16 = 0x42;
}

/// LE/LX OS types.
pub mod le_os {
    pub const UNKNOWN: u16 = 0;
    pub const OS2: u16 = 1;
    pub const WINDOWS: u16 = 2;
    pub const DOS4: u16 = 3;
    pub const WINDOWS386: u16 = 4;
    pub const IBM_MVS: u16 = 5;
}

/// Detected extended executable type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedType {
    /// Pure DOS MZ executable
    Mz,
    /// NE (New Executable)
    Ne { target_os: u8 },
    /// LE (Linear Executable)
    Le { cpu: u16, os: u16 },
    /// LX (Linear Executable Extended)
    Lx { cpu: u16, os: u16 },
}

/// Detect MZ and extended types.
pub fn detect(data: &[u8]) -> Option<ExtendedType> {
    if data.len() < MZ_HEADER_SIZE {
        return None;
    }

    // Check for MZ signature
    if data[0..2] != MZ_SIGNATURE && data[0..2] != ZM_SIGNATURE {
        return None;
    }

    // Check for extended header pointer at offset 0x3C
    let lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

    // Check for extended header if pointer is valid
    if lfanew >= MZ_HEADER_SIZE && lfanew + 2 <= data.len() {
        let sig = &data[lfanew..lfanew + 2];

        // Check for NE
        if sig == NE_SIGNATURE && lfanew + NE_HEADER_SIZE <= data.len() {
            let target_os = data[lfanew + 0x36];
            return Some(ExtendedType::Ne { target_os });
        }

        // Check for LE
        if sig == LE_SIGNATURE && lfanew + 12 <= data.len() {
            let cpu = read_u16(data, lfanew + 8, true).ok()?;
            let os = read_u16(data, lfanew + 10, true).ok()?;
            return Some(ExtendedType::Le { cpu, os });
        }

        // Check for LX
        if sig == LX_SIGNATURE && lfanew + 12 <= data.len() {
            let cpu = read_u16(data, lfanew + 8, true).ok()?;
            let os = read_u16(data, lfanew + 10, true).ok()?;
            return Some(ExtendedType::Lx { cpu, os });
        }
    }

    // Pure MZ executable
    Some(ExtendedType::Mz)
}

/// Parse pure MZ (DOS) executable.
fn parse_mz(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < MZ_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: MZ_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // Parse MZ header fields
    let bytes_last_page = read_u16(data, 2, true)?;
    let pages = read_u16(data, 4, true)?;
    let relocs = read_u16(data, 6, true)?;
    let header_paragraphs = read_u16(data, 8, true)?;
    let _min_alloc = read_u16(data, 10, true)?;
    let _max_alloc = read_u16(data, 12, true)?;
    let ss = read_u16(data, 14, true)?;
    let sp = read_u16(data, 16, true)?;
    let _checksum = read_u16(data, 18, true)?;
    let ip = read_u16(data, 20, true)?;
    let cs = read_u16(data, 22, true)?;
    let reloc_offset = read_u16(data, 24, true)?;
    let overlay = read_u16(data, 26, true)?;

    // Calculate file size
    let file_size = if pages > 0 {
        ((pages - 1) as u32 * 512)
            + if bytes_last_page > 0 {
                bytes_last_page as u32
            } else {
                512
            }
    } else {
        0
    };

    let mut notes = vec!["DOS MZ executable".to_string()];
    notes.push(format!("Entry: {:04X}:{:04X}", cs, ip));
    notes.push(format!("Stack: {:04X}:{:04X}", ss, sp));
    notes.push(format!("Size: {} bytes ({} pages)", file_size, pages));
    notes.push(format!(
        "Relocations: {} at offset 0x{:04X}",
        relocs, reloc_offset
    ));
    notes.push(format!("Header size: {} paragraphs", header_paragraphs));

    if overlay > 0 {
        notes.push(format!("Overlay number: {}", overlay));
    }

    let metadata = ClassificationMetadata {
        entry_point: Some(((cs as u64) << 4) + ip as u64),
        code_size: Some(file_size as u64),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::X86, 16, Endianness::Little, FileFormat::Mz);
    result.variant = Variant::new("DOS real mode");
    result.metadata = metadata;

    Ok(result)
}

/// Parse NE (New Executable).
fn parse_ne(data: &[u8], target_os: u8) -> Result<ClassificationResult> {
    // Find NE header offset
    let lfanew = read_u32(data, 0x3C, true)? as usize;

    if lfanew + NE_HEADER_SIZE > data.len() {
        return Err(ClassifierError::TruncatedData {
            offset: lfanew,
            expected: NE_HEADER_SIZE,
            actual: data.len().saturating_sub(lfanew),
        });
    }

    let ne_off = lfanew;

    // Parse NE header
    let linker_major = data[ne_off + 2];
    let linker_minor = data[ne_off + 3];
    let _entry_table_off = read_u16(data, ne_off + 4, true)?;
    let _entry_table_len = read_u16(data, ne_off + 6, true)?;
    let flags = read_u16(data, ne_off + 0x0C, true)?;
    let _auto_data_seg = read_u16(data, ne_off + 0x0E, true)?;
    let _heap_size = read_u16(data, ne_off + 0x10, true)?;
    let _stack_size = read_u16(data, ne_off + 0x12, true)?;
    let entry_point = read_u32(data, ne_off + 0x14, true)?;
    let _initial_stack = read_u32(data, ne_off + 0x18, true)?;
    let segment_count = read_u16(data, ne_off + 0x1C, true)?;

    let os_name = match target_os {
        ne_os::UNKNOWN => "Unknown",
        ne_os::OS2 => "OS/2",
        ne_os::WINDOWS => "Windows",
        ne_os::DOS4 => "DOS 4.x",
        ne_os::WINDOWS386 => "Windows 386",
        ne_os::BOSS => "Borland OS Services",
        _ => "Unknown",
    };

    let module_type = if flags & 0x8000 != 0 {
        "DLL/Driver"
    } else {
        "Executable"
    };

    let mut notes = vec!["NE (New Executable)".to_string()];
    notes.push(format!("Target OS: {}", os_name));
    notes.push(format!("Type: {}", module_type));
    notes.push(format!("Linker: {}.{}", linker_major, linker_minor));
    notes.push(format!("Segments: {}", segment_count));

    if flags & 0x0008 != 0 {
        notes.push("Protected mode only".to_string());
    }

    let cs = (entry_point >> 16) as u16;
    let ip = (entry_point & 0xFFFF) as u16;
    notes.push(format!("Entry: segment {}:0x{:04X}", cs, ip));

    let metadata = ClassificationMetadata {
        entry_point: Some(entry_point as u64),
        section_count: Some(segment_count as usize),
        flags: Some(flags as u32),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::X86, 16, Endianness::Little, FileFormat::Ne);
    result.variant = Variant::new(os_name);
    result.metadata = metadata;

    Ok(result)
}

/// Parse LE/LX (Linear Executable).
fn parse_le_lx(data: &[u8], is_lx: bool, cpu: u16, os: u16) -> Result<ClassificationResult> {
    let lfanew = read_u32(data, 0x3C, true)? as usize;

    if lfanew + LE_HEADER_SIZE > data.len() {
        // Allow partial header
        if lfanew + 32 > data.len() {
            return Err(ClassifierError::TruncatedData {
                offset: lfanew,
                expected: LE_HEADER_SIZE,
                actual: data.len().saturating_sub(lfanew),
            });
        }
    }

    let le_off = lfanew;

    // Parse LE/LX header
    let byte_order = data[le_off + 2];
    let word_order = data[le_off + 3];
    let _format_level = read_u32(data, le_off + 4, true)?;
    let module_flags = read_u32(data, le_off + 0x10, true)?;
    let module_pages = read_u32(data, le_off + 0x14, true)?;
    let eip_object = read_u32(data, le_off + 0x18, true)?;
    let eip_offset = read_u32(data, le_off + 0x1C, true)?;

    // Determine ISA from CPU type
    let (isa, bitwidth) = match cpu {
        le_cpu::I286 => (Isa::X86, 16),
        le_cpu::I386 | le_cpu::I486 | le_cpu::PENTIUM => (Isa::X86, 32),
        le_cpu::MIPS1 | le_cpu::MIPS2 | le_cpu::MIPS3 => (Isa::Mips, 32),
        le_cpu::I860 => (Isa::I860, 32),
        _ => (Isa::X86, 32), // Default to i386
    };

    let os_name = match os {
        le_os::UNKNOWN => "Unknown",
        le_os::OS2 => "OS/2",
        le_os::WINDOWS => "Windows",
        le_os::DOS4 => "DOS 4.x",
        le_os::WINDOWS386 => "Windows 386",
        le_os::IBM_MVS => "IBM MVS",
        _ => "Unknown",
    };

    let cpu_name = match cpu {
        le_cpu::I286 => "80286",
        le_cpu::I386 => "80386",
        le_cpu::I486 => "80486",
        le_cpu::PENTIUM => "Pentium",
        le_cpu::MIPS1 => "MIPS-I",
        le_cpu::MIPS2 => "MIPS-II",
        le_cpu::MIPS3 => "MIPS-III",
        le_cpu::I860 => "i860",
        _ => "Unknown",
    };

    let format_name = if is_lx { "LX" } else { "LE" };
    let format = if is_lx {
        FileFormat::Lx
    } else {
        FileFormat::Le
    };

    let module_type = if module_flags & 0x00008000 != 0 {
        "DLL"
    } else if module_flags & 0x00020000 != 0 {
        "Physical device driver"
    } else if module_flags & 0x00028000 != 0 {
        "Virtual device driver"
    } else {
        "Executable"
    };

    let mut notes = vec![format!("{} (Linear Executable)", format_name)];
    notes.push(format!("Target OS: {}", os_name));
    notes.push(format!("CPU: {}", cpu_name));
    notes.push(format!("Type: {}", module_type));
    notes.push(format!("Pages: {}", module_pages));
    notes.push(format!("Entry: object {}:0x{:08X}", eip_object, eip_offset));

    if byte_order != 0 || word_order != 0 {
        notes.push(format!(
            "Byte order: {}, Word order: {}",
            if byte_order == 0 { "LE" } else { "BE" },
            if word_order == 0 { "LE" } else { "BE" }
        ));
    }

    let metadata = ClassificationMetadata {
        entry_point: Some(eip_offset as u64),
        flags: Some(module_flags),
        section_count: Some(module_pages as usize),
        notes,
        ..Default::default()
    };

    let mut result = ClassificationResult::from_format(isa, bitwidth, Endianness::Little, format);
    result.variant = Variant::new(format!("{} {}", os_name, cpu_name));
    result.metadata = metadata;

    Ok(result)
}

/// Parse MZ/NE/LE/LX file.
pub fn parse(data: &[u8], ext_type: ExtendedType) -> Result<ClassificationResult> {
    match ext_type {
        ExtendedType::Mz => parse_mz(data),
        ExtendedType::Ne { target_os } => parse_ne(data, target_os),
        ExtendedType::Le { cpu, os } => parse_le_lx(data, false, cpu, os),
        ExtendedType::Lx { cpu, os } => parse_le_lx(data, true, cpu, os),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mz_header() -> Vec<u8> {
        let mut data = vec![0u8; 128];
        // MZ signature
        data[0] = b'M';
        data[1] = b'Z';
        // Bytes on last page
        data[2..4].copy_from_slice(&256u16.to_le_bytes());
        // Pages in file
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        // Relocations
        data[6..8].copy_from_slice(&0u16.to_le_bytes());
        // Header paragraphs
        data[8..10].copy_from_slice(&4u16.to_le_bytes());
        // SS
        data[14..16].copy_from_slice(&0u16.to_le_bytes());
        // SP
        data[16..18].copy_from_slice(&0x100u16.to_le_bytes());
        // IP
        data[20..22].copy_from_slice(&0u16.to_le_bytes());
        // CS
        data[22..24].copy_from_slice(&0u16.to_le_bytes());
        // Reloc table offset
        data[24..26].copy_from_slice(&0x40u16.to_le_bytes());
        // lfanew = 0 (pure MZ)
        data[0x3C..0x40].copy_from_slice(&0u32.to_le_bytes());
        data
    }

    fn make_ne_header() -> Vec<u8> {
        let mut data = vec![0u8; 256];
        // MZ stub
        data[0] = b'M';
        data[1] = b'Z';
        // lfanew pointing to NE header at 0x80
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // NE header at 0x80
        let ne_off = 0x80;
        data[ne_off] = b'N';
        data[ne_off + 1] = b'E';
        data[ne_off + 2] = 5; // linker major
        data[ne_off + 3] = 0; // linker minor
                              // Target OS
        data[ne_off + 0x36] = ne_os::WINDOWS;
        // Segment count
        data[ne_off + 0x1C..ne_off + 0x1E].copy_from_slice(&4u16.to_le_bytes());

        data
    }

    fn make_le_header(cpu: u16, os: u16) -> Vec<u8> {
        let mut data = vec![0u8; 512];
        // MZ stub
        data[0] = b'M';
        data[1] = b'Z';
        // lfanew pointing to LE header at 0x80
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // LE header at 0x80
        let le_off = 0x80;
        data[le_off] = b'L';
        data[le_off + 1] = b'E';
        // CPU type
        data[le_off + 8..le_off + 10].copy_from_slice(&cpu.to_le_bytes());
        // OS type
        data[le_off + 10..le_off + 12].copy_from_slice(&os.to_le_bytes());
        // Module pages
        data[le_off + 0x14..le_off + 0x18].copy_from_slice(&10u32.to_le_bytes());
        // EIP object
        data[le_off + 0x18..le_off + 0x1C].copy_from_slice(&1u32.to_le_bytes());
        // EIP offset
        data[le_off + 0x1C..le_off + 0x20].copy_from_slice(&0x1000u32.to_le_bytes());

        data
    }

    #[test]
    fn test_detect_pure_mz() {
        let data = make_mz_header();
        let ext_type = detect(&data);
        assert!(matches!(ext_type, Some(ExtendedType::Mz)));
    }

    #[test]
    fn test_detect_ne() {
        let data = make_ne_header();
        let ext_type = detect(&data);
        assert!(matches!(
            ext_type,
            Some(ExtendedType::Ne {
                target_os: ne_os::WINDOWS
            })
        ));
    }

    #[test]
    fn test_detect_le() {
        let data = make_le_header(le_cpu::I386, le_os::OS2);
        let ext_type = detect(&data);
        assert!(matches!(
            ext_type,
            Some(ExtendedType::Le {
                cpu: le_cpu::I386,
                os: le_os::OS2
            })
        ));
    }

    #[test]
    fn test_parse_mz() {
        let data = make_mz_header();
        let ext_type = detect(&data).unwrap();
        let result = parse(&data, ext_type).unwrap();
        assert_eq!(result.isa, Isa::X86);
        assert_eq!(result.bitwidth, 16);
        assert_eq!(result.format, FileFormat::Mz);
    }

    #[test]
    fn test_parse_ne() {
        let data = make_ne_header();
        let ext_type = detect(&data).unwrap();
        let result = parse(&data, ext_type).unwrap();
        assert_eq!(result.isa, Isa::X86);
        assert_eq!(result.bitwidth, 16);
        assert_eq!(result.format, FileFormat::Ne);
    }

    #[test]
    fn test_parse_le() {
        let data = make_le_header(le_cpu::I386, le_os::OS2);
        let ext_type = detect(&data).unwrap();
        let result = parse(&data, ext_type).unwrap();
        assert_eq!(result.isa, Isa::X86);
        assert_eq!(result.bitwidth, 32);
        assert_eq!(result.format, FileFormat::Le);
    }
}
