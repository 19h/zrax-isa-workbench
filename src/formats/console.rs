//! Game console executable format parsers.
//!
//! This module handles:
//! - XBE (Original Xbox)
//! - XEX (Xbox 360)
//! - SELF/SPRX (PlayStation 3/4/5)
//! - NSO/NRO (Nintendo Switch)
//! - DOL/REL (GameCube/Wii)

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u16, read_u32, read_u64};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

// === XBE (Original Xbox) ===

/// XBE magic: "XBEH"
pub const XBE_MAGIC: [u8; 4] = [b'X', b'B', b'E', b'H'];

/// XBE header size.
pub const XBE_HEADER_SIZE: usize = 0x178;

/// XBE entry point XOR keys.
pub mod xbe_keys {
    pub const RETAIL_ENTRY: u32 = 0xA8FC57AB;
    pub const DEBUG_ENTRY: u32 = 0x94859D4B;
    pub const BETA_ENTRY: u32 = 0xE682F45B;
}

// === XEX (Xbox 360) ===

/// XEX2 magic
pub const XEX2_MAGIC: [u8; 4] = [b'X', b'E', b'X', b'2'];

/// XEX1 magic (older)
pub const XEX1_MAGIC: [u8; 4] = [b'X', b'E', b'X', b'1'];

/// XEX header size.
pub const XEX_HEADER_SIZE: usize = 24;

// === PlayStation SELF ===

/// PS3 SELF magic: "SCE\0"
pub const PS3_SELF_MAGIC: [u8; 4] = [b'S', b'C', b'E', 0];

/// PS4 SELF magic
pub const PS4_SELF_MAGIC: u32 = 0x4F15F3D1;

// === Nintendo Switch ===

/// NSO magic: "NSO0"
pub const NSO_MAGIC: [u8; 4] = [b'N', b'S', b'O', b'0'];

/// NRO magic: "NRO0"
pub const NRO_MAGIC: [u8; 4] = [b'N', b'R', b'O', b'0'];

/// NSO header size.
pub const NSO_HEADER_SIZE: usize = 0x100;

/// NRO header size.
pub const NRO_HEADER_SIZE: usize = 0x80;

// === GameCube/Wii DOL ===

/// DOL header size.
pub const DOL_HEADER_SIZE: usize = 0x100;

/// Console format variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleFormat {
    Xbe,
    Xex { version: u8 },
    SelfPs3,
    SelfPs4,
    SelfPs5,
    Nso,
    Nro,
    Dol,
}

/// Detect console format.
pub fn detect(data: &[u8]) -> Option<ConsoleFormat> {
    if data.len() < 4 {
        return None;
    }

    // XBE
    if data[0..4] == XBE_MAGIC {
        return Some(ConsoleFormat::Xbe);
    }

    // XEX
    if data[0..4] == XEX2_MAGIC {
        return Some(ConsoleFormat::Xex { version: 2 });
    }
    if data[0..4] == XEX1_MAGIC {
        return Some(ConsoleFormat::Xex { version: 1 });
    }

    // PS3 SELF
    if data[0..4] == PS3_SELF_MAGIC {
        return Some(ConsoleFormat::SelfPs3);
    }

    // PS4 SELF
    let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic_le == PS4_SELF_MAGIC {
        return Some(ConsoleFormat::SelfPs4);
    }

    // NSO
    if data[0..4] == NSO_MAGIC {
        return Some(ConsoleFormat::Nso);
    }

    // NRO - magic at offset 0x10
    if data.len() >= 0x14 && data[0x10..0x14] == NRO_MAGIC {
        return Some(ConsoleFormat::Nro);
    }

    // DOL - no magic, but starts with section offsets
    // Heuristic: first 7 u32s are text offsets, should be reasonable values
    if data.len() >= DOL_HEADER_SIZE {
        let text0_off = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let text0_addr = u32::from_be_bytes([data[0x48], data[0x49], data[0x4A], data[0x4B]]);
        let entry = u32::from_be_bytes([data[0xE0], data[0xE1], data[0xE2], data[0xE3]]);

        // DOL text section offset typically starts after header (0x100)
        // Entry point should be in a reasonable range for GameCube/Wii
        if text0_off >= 0x100
            && text0_off < 0x100000
            && text0_addr >= 0x80000000
            && entry >= 0x80000000
            && entry < 0x81800000
        {
            return Some(ConsoleFormat::Dol);
        }
    }

    None
}

/// Parse XBE file.
fn parse_xbe(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < XBE_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: XBE_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // XBE is little-endian (x86)
    let base_addr = read_u32(data, 0x104, true)?;
    let headers_size = read_u32(data, 0x108, true)?;
    let image_size = read_u32(data, 0x10C, true)?;
    let entry_xor = read_u32(data, 0x128, true)?;
    let _tls_addr = read_u32(data, 0x12C, true)?;
    let kernel_thunk_xor = read_u32(data, 0x158, true)?;

    // Decode entry point
    let entry_retail = entry_xor ^ xbe_keys::RETAIL_ENTRY;
    let entry_debug = entry_xor ^ xbe_keys::DEBUG_ENTRY;

    // Determine build type
    let build_type = if entry_retail >= base_addr && entry_retail < base_addr + image_size {
        "Retail"
    } else if entry_debug >= base_addr && entry_debug < base_addr + image_size {
        "Debug"
    } else {
        "Unknown"
    };

    let entry = if build_type == "Retail" {
        entry_retail
    } else {
        entry_debug
    };

    let mut notes = vec!["XBE (Original Xbox)".to_string()];
    notes.push(format!("Build: {}", build_type));
    notes.push(format!("Base address: 0x{:08X}", base_addr));
    notes.push(format!("Entry point: 0x{:08X}", entry));
    notes.push(format!("Image size: {} bytes", image_size));

    let metadata = ClassificationMetadata {
        entry_point: Some(entry as u64),
        code_size: Some(image_size as u64),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::X86, 32, Endianness::Little, FileFormat::Xbe);
    result.variant = Variant::new(build_type);
    result.metadata = metadata;

    Ok(result)
}

/// Parse XEX file.
fn parse_xex(data: &[u8], version: u8) -> Result<ClassificationResult> {
    if data.len() < XEX_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: XEX_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // XEX is big-endian (PowerPC)
    let module_flags = read_u32(data, 4, false)?;
    let pe_offset = read_u32(data, 8, false)?;
    let _reserved = read_u32(data, 12, false)?;
    let security_offset = read_u32(data, 16, false)?;
    let optional_header_count = read_u32(data, 20, false)?;

    let module_type = if module_flags & 1 != 0 {
        "Title"
    } else if module_flags & 8 != 0 {
        "DLL"
    } else if module_flags & 16 != 0 {
        "Patch"
    } else {
        "Unknown"
    };

    let mut notes = vec![format!("XEX{} (Xbox 360)", version)];
    notes.push(format!("Module type: {}", module_type));
    notes.push(format!("PE offset: 0x{:08X}", pe_offset));
    notes.push(format!("Optional headers: {}", optional_header_count));

    let metadata = ClassificationMetadata {
        flags: Some(module_flags),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::Ppc, 32, Endianness::Big, FileFormat::Xex);
    result.variant = Variant::new(format!("XEX{} {}", version, module_type));
    result.metadata = metadata;

    Ok(result)
}

/// Parse PS3 SELF file.
fn parse_self_ps3(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < 32 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 32,
            actual: data.len(),
        });
    }

    // PS3 SELF is big-endian
    let version = read_u32(data, 4, false)?;
    let _key_revision = read_u16(data, 8, false)?;
    let header_type = read_u16(data, 10, false)?;
    let _metadata_offset = read_u32(data, 12, false)?;
    let header_len = read_u64(data, 16, false)?;
    let _data_len = read_u64(data, 24, false)?;

    let type_name = match header_type {
        1 => "SELF",
        2 => "RVK",
        3 => "PKG",
        4 => "SPP",
        _ => "Unknown",
    };

    let mut notes = vec!["PS3 SELF/SPRX".to_string()];
    notes.push(format!("Header version: {}", version));
    notes.push(format!("Type: {}", type_name));
    notes.push(format!("Header length: {} bytes", header_len));

    let metadata = ClassificationMetadata {
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::Ppc64, 64, Endianness::Big, FileFormat::SelfPs3);
    result.variant = Variant::new("Cell BE");
    result.metadata = metadata;

    Ok(result)
}

/// Parse PS4/PS5 SELF file.
fn parse_self_ps4(data: &[u8], is_ps5: bool) -> Result<ClassificationResult> {
    if data.len() < 32 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 32,
            actual: data.len(),
        });
    }

    // PS4 SELF is little-endian (x86-64)
    let format = if is_ps5 {
        FileFormat::SelfPs5
    } else {
        FileFormat::SelfPs4
    };

    let platform = if is_ps5 { "PS5" } else { "PS4" };

    let mut notes = vec![format!("{} SELF/SPRX", platform)];

    let metadata = ClassificationMetadata {
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::X86_64, 64, Endianness::Little, format);
    result.variant = Variant::new(platform);
    result.metadata = metadata;

    Ok(result)
}

/// Parse NSO file.
fn parse_nso(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < NSO_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: NSO_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // NSO is little-endian (AArch64)
    let version = read_u32(data, 4, true)?;
    let _reserved = read_u32(data, 8, true)?;
    let flags = read_u32(data, 12, true)?;

    let text_file_off = read_u32(data, 16, true)?;
    let text_mem_off = read_u32(data, 20, true)?;
    let text_size = read_u32(data, 24, true)?;

    let ro_file_off = read_u32(data, 32, true)?;
    let _ro_mem_off = read_u32(data, 36, true)?;
    let ro_size = read_u32(data, 40, true)?;

    let data_file_off = read_u32(data, 48, true)?;
    let _data_mem_off = read_u32(data, 52, true)?;
    let data_size = read_u32(data, 56, true)?;

    let bss_size = read_u32(data, 60, true)?;

    let mut notes = vec!["NSO (Nintendo Switch)".to_string()];
    notes.push(format!("Version: {}", version));
    notes.push(format!(".text: {} bytes (compressed: {})", text_size, flags & 1 != 0));
    notes.push(format!(".rodata: {} bytes (compressed: {})", ro_size, flags & 2 != 0));
    notes.push(format!(".data: {} bytes (compressed: {})", data_size, flags & 4 != 0));
    notes.push(format!(".bss: {} bytes", bss_size));

    let metadata = ClassificationMetadata {
        entry_point: Some(text_mem_off as u64),
        code_size: Some(text_size as u64),
        flags: Some(flags),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::AArch64, 64, Endianness::Little, FileFormat::Nso);
    result.variant = Variant::new("Nintendo Switch");
    result.metadata = metadata;

    Ok(result)
}

/// Parse NRO file.
fn parse_nro(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < NRO_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: NRO_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // NRO header starts at offset 0x10 (after MOD0)
    let _reserved = read_u32(data, 0, true)?;
    let _mod_offset = read_u32(data, 4, true)?;

    // NRO header at 0x10
    let size = read_u32(data, 0x18, true)?;
    let _reserved2 = read_u32(data, 0x1C, true)?;

    let text_off = read_u32(data, 0x20, true)?;
    let text_size = read_u32(data, 0x24, true)?;
    let ro_off = read_u32(data, 0x28, true)?;
    let ro_size = read_u32(data, 0x2C, true)?;
    let data_off = read_u32(data, 0x30, true)?;
    let data_size = read_u32(data, 0x34, true)?;
    let bss_size = read_u32(data, 0x38, true)?;

    let mut notes = vec!["NRO (Nintendo Switch Homebrew)".to_string()];
    notes.push(format!("File size: {} bytes", size));
    notes.push(format!(".text: {} bytes at 0x{:X}", text_size, text_off));
    notes.push(format!(".rodata: {} bytes", ro_size));
    notes.push(format!(".data: {} bytes", data_size));
    notes.push(format!(".bss: {} bytes", bss_size));

    let metadata = ClassificationMetadata {
        entry_point: Some(text_off as u64),
        code_size: Some(text_size as u64),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::AArch64, 64, Endianness::Little, FileFormat::Nro);
    result.variant = Variant::new("Nintendo Switch Homebrew");
    result.metadata = metadata;

    Ok(result)
}

/// Parse DOL file.
fn parse_dol(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < DOL_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: DOL_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // DOL is big-endian (PowerPC)
    // Text sections (7)
    let mut text_total = 0u64;
    for i in 0..7 {
        let size = read_u32(data, 0x90 + i * 4, false)? as u64;
        text_total += size;
    }

    // Data sections (11)
    let mut data_total = 0u64;
    for i in 0..11 {
        let size = read_u32(data, 0xAC + i * 4, false)? as u64;
        data_total += size;
    }

    let bss_addr = read_u32(data, 0xD8, false)?;
    let bss_size = read_u32(data, 0xDC, false)?;
    let entry = read_u32(data, 0xE0, false)?;

    let mut notes = vec!["DOL (GameCube/Wii)".to_string()];
    notes.push(format!("Entry point: 0x{:08X}", entry));
    notes.push(format!("Text sections: {} bytes total", text_total));
    notes.push(format!("Data sections: {} bytes total", data_total));
    notes.push(format!("BSS: {} bytes at 0x{:08X}", bss_size, bss_addr));

    let metadata = ClassificationMetadata {
        entry_point: Some(entry as u64),
        code_size: Some(text_total),
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::Ppc, 32, Endianness::Big, FileFormat::Dol);
    result.variant = Variant::new("GameCube/Wii");
    result.metadata = metadata;

    Ok(result)
}

/// Parse console format file.
pub fn parse(data: &[u8], format: ConsoleFormat) -> Result<ClassificationResult> {
    match format {
        ConsoleFormat::Xbe => parse_xbe(data),
        ConsoleFormat::Xex { version } => parse_xex(data, version),
        ConsoleFormat::SelfPs3 => parse_self_ps3(data),
        ConsoleFormat::SelfPs4 => parse_self_ps4(data, false),
        ConsoleFormat::SelfPs5 => parse_self_ps4(data, true),
        ConsoleFormat::Nso => parse_nso(data),
        ConsoleFormat::Nro => parse_nro(data),
        ConsoleFormat::Dol => parse_dol(data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_xbe_header() -> Vec<u8> {
        let mut data = vec![0u8; XBE_HEADER_SIZE];
        data[0..4].copy_from_slice(&XBE_MAGIC);
        // Base address
        data[0x104..0x108].copy_from_slice(&0x00010000u32.to_le_bytes());
        // Image size
        data[0x10C..0x110].copy_from_slice(&0x00100000u32.to_le_bytes());
        // Entry XOR (retail: 0x00020000 ^ 0xA8FC57AB)
        let entry = 0x00020000u32 ^ xbe_keys::RETAIL_ENTRY;
        data[0x128..0x12C].copy_from_slice(&entry.to_le_bytes());
        data
    }

    fn make_nso_header() -> Vec<u8> {
        let mut data = vec![0u8; NSO_HEADER_SIZE];
        data[0..4].copy_from_slice(&NSO_MAGIC);
        // Flags
        data[12..16].copy_from_slice(&7u32.to_le_bytes()); // All compressed
        // Text size
        data[24..28].copy_from_slice(&0x10000u32.to_le_bytes());
        data
    }

    #[test]
    fn test_detect_xbe() {
        let data = make_xbe_header();
        assert!(matches!(detect(&data), Some(ConsoleFormat::Xbe)));
    }

    #[test]
    fn test_detect_nso() {
        let data = make_nso_header();
        assert!(matches!(detect(&data), Some(ConsoleFormat::Nso)));
    }

    #[test]
    fn test_parse_xbe() {
        let data = make_xbe_header();
        let format = detect(&data).unwrap();
        let result = parse(&data, format).unwrap();
        assert_eq!(result.isa, Isa::X86);
        assert_eq!(result.format, FileFormat::Xbe);
    }

    #[test]
    fn test_parse_nso() {
        let data = make_nso_header();
        let format = detect(&data).unwrap();
        let result = parse(&data, format).unwrap();
        assert_eq!(result.isa, Isa::AArch64);
        assert_eq!(result.format, FileFormat::Nso);
    }
}
