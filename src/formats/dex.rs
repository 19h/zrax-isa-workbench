//! DEX (Dalvik Executable) parser.
//!
//! DEX files contain bytecode for Android's Dalvik and ART virtual machines.
//! Related formats include ODEX (Optimized DEX), VDEX, and ART image files.

use crate::error::{ClassifierError, Result};
use crate::formats::read_u32;
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// DEX magic prefix: "dex\n"
pub const DEX_MAGIC_PREFIX: [u8; 4] = [b'd', b'e', b'x', b'\n'];

/// ODEX magic prefix
pub const ODEX_MAGIC_PREFIX: [u8; 4] = [b'd', b'e', b'y', b'\n'];

/// VDEX magic
pub const VDEX_MAGIC: [u8; 4] = [b'v', b'd', b'e', b'x'];

/// ART image magic
pub const ART_MAGIC: [u8; 4] = [b'a', b'r', b't', b'\n'];

/// DEX header size.
pub const DEX_HEADER_SIZE: usize = 112;

/// VDEX header size.
pub const VDEX_HEADER_SIZE: usize = 64;

/// Endian tag for little-endian (ENDIAN_CONSTANT)
pub const ENDIAN_CONSTANT: u32 = 0x12345678;

/// Endian tag for big-endian (REVERSE_ENDIAN_CONSTANT)
pub const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

/// DEX format variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DexVariant {
    /// Standard DEX file
    Dex { version: [u8; 3] },
    /// Optimized DEX file
    Odex { version: [u8; 3] },
    /// VDEX container
    Vdex { version: [u8; 4] },
    /// ART image file
    Art { version: [u8; 3] },
}

/// Detect DEX/ODEX/VDEX/ART format.
pub fn detect(data: &[u8]) -> Option<DexVariant> {
    if data.len() < 8 {
        return None;
    }

    // Check for DEX
    if data[0..4] == DEX_MAGIC_PREFIX {
        let mut version = [0u8; 3];
        version.copy_from_slice(&data[4..7]);
        return Some(DexVariant::Dex { version });
    }

    // Check for ODEX
    if data[0..4] == ODEX_MAGIC_PREFIX {
        let mut version = [0u8; 3];
        version.copy_from_slice(&data[4..7]);
        return Some(DexVariant::Odex { version });
    }

    // Check for VDEX
    if data[0..4] == VDEX_MAGIC {
        let mut version = [0u8; 4];
        version.copy_from_slice(&data[4..8]);
        return Some(DexVariant::Vdex { version });
    }

    // Check for ART
    if data[0..4] == ART_MAGIC {
        let mut version = [0u8; 3];
        version.copy_from_slice(&data[4..7]);
        return Some(DexVariant::Art { version });
    }

    None
}

/// Parse DEX/ODEX file.
fn parse_dex(data: &[u8], version: [u8; 3], is_odex: bool) -> Result<ClassificationResult> {
    if data.len() < DEX_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: DEX_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // Parse header fields
    let _checksum = read_u32(data, 8, true)?;
    // SHA-1 signature at 12-31
    let file_size = read_u32(data, 32, true)?;
    let header_size = read_u32(data, 36, true)?;
    let endian_tag = read_u32(data, 40, true)?;

    let little_endian = endian_tag == ENDIAN_CONSTANT;
    let le = little_endian;

    let _link_size = read_u32(data, 44, le)?;
    let _link_off = read_u32(data, 48, le)?;
    let _map_off = read_u32(data, 52, le)?;
    let string_ids_size = read_u32(data, 56, le)?;
    let _string_ids_off = read_u32(data, 60, le)?;
    let type_ids_size = read_u32(data, 64, le)?;
    let _type_ids_off = read_u32(data, 68, le)?;
    let proto_ids_size = read_u32(data, 72, le)?;
    let _proto_ids_off = read_u32(data, 76, le)?;
    let field_ids_size = read_u32(data, 80, le)?;
    let _field_ids_off = read_u32(data, 84, le)?;
    let method_ids_size = read_u32(data, 88, le)?;
    let _method_ids_off = read_u32(data, 92, le)?;
    let class_defs_size = read_u32(data, 96, le)?;
    let _class_defs_off = read_u32(data, 100, le)?;
    let _data_size = read_u32(data, 104, le)?;
    let _data_off = read_u32(data, 108, le)?;

    // Parse version string
    let version_str = String::from_utf8_lossy(&version);
    let version_num: u32 = version_str.trim_end_matches('\0').parse().unwrap_or(0);

    // Map DEX version to Android version
    let android_version = match version_num {
        35 => "Android 6.0 (API 23) or earlier",
        37 => "Android 7.0+ (API 24+)",
        38 => "Android 8.0+ (API 26+)",
        39 => "Android 9.0+ (API 28+)",
        40 => "Android 10+ (API 29+)",
        41 => "Android 12+ (API 31+)",
        _ => "Unknown Android version",
    };

    let format_name = if is_odex { "ODEX" } else { "DEX" };
    let format = if is_odex {
        FileFormat::Odex
    } else {
        FileFormat::Dex
    };

    let mut notes = vec![format!(
        "{} file version {}",
        format_name,
        version_str.trim()
    )];
    notes.push(format!("Target: {}", android_version));
    notes.push(format!("File size: {} bytes", file_size));
    notes.push(format!("Header size: {} bytes", header_size));
    notes.push(format!(
        "Endianness: {}",
        if little_endian { "little" } else { "big" }
    ));
    notes.push(format!("Strings: {}", string_ids_size));
    notes.push(format!("Types: {}", type_ids_size));
    notes.push(format!("Prototypes: {}", proto_ids_size));
    notes.push(format!("Fields: {}", field_ids_size));
    notes.push(format!("Methods: {}", method_ids_size));
    notes.push(format!("Classes: {}", class_defs_size));

    let metadata = ClassificationMetadata {
        code_size: Some(file_size as u64),
        notes,
        ..Default::default()
    };

    let endianness = if little_endian {
        Endianness::Little
    } else {
        Endianness::Big
    };

    let mut result = ClassificationResult::from_format(Isa::Dalvik, 32, endianness, format);
    result.variant = Variant::new(format!("DEX {}", version_str.trim()));
    result.metadata = metadata;

    Ok(result)
}

/// Parse VDEX file.
fn parse_vdex(data: &[u8], version: [u8; 4]) -> Result<ClassificationResult> {
    if data.len() < VDEX_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: VDEX_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let version_str = String::from_utf8_lossy(&version);

    let mut notes = vec!["VDEX container file".to_string()];
    notes.push(format!("Version: {}", version_str.trim()));

    let metadata = ClassificationMetadata {
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::Dalvik, 32, Endianness::Little, FileFormat::Vdex);
    result.variant = Variant::new(format!("VDEX {}", version_str.trim()));
    result.metadata = metadata;

    Ok(result)
}

/// Parse ART image file.
fn parse_art(data: &[u8], version: [u8; 3]) -> Result<ClassificationResult> {
    let version_str = String::from_utf8_lossy(&version);

    let mut notes = vec!["ART image file".to_string()];
    notes.push(format!("Version: {}", version_str.trim()));

    let metadata = ClassificationMetadata {
        notes,
        ..Default::default()
    };

    let mut result =
        ClassificationResult::from_format(Isa::Dalvik, 32, Endianness::Little, FileFormat::Art);
    result.variant = Variant::new(format!("ART {}", version_str.trim()));
    result.metadata = metadata;

    Ok(result)
}

/// Parse DEX/ODEX/VDEX/ART file.
pub fn parse(data: &[u8], variant: DexVariant) -> Result<ClassificationResult> {
    match variant {
        DexVariant::Dex { version } => parse_dex(data, version, false),
        DexVariant::Odex { version } => parse_dex(data, version, true),
        DexVariant::Vdex { version } => parse_vdex(data, version),
        DexVariant::Art { version } => parse_art(data, version),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dex_header(version: &[u8; 3]) -> Vec<u8> {
        let mut data = vec![0u8; DEX_HEADER_SIZE];

        // Magic: "dex\n"
        data[0..4].copy_from_slice(&DEX_MAGIC_PREFIX);
        // Version: "035\0" etc
        data[4..7].copy_from_slice(version);
        data[7] = 0;

        // Checksum (fake)
        data[8..12].copy_from_slice(&0x12345678u32.to_le_bytes());

        // File size
        data[32..36].copy_from_slice(&(DEX_HEADER_SIZE as u32).to_le_bytes());
        // Header size
        data[36..40].copy_from_slice(&112u32.to_le_bytes());
        // Endian tag
        data[40..44].copy_from_slice(&ENDIAN_CONSTANT.to_le_bytes());

        // String IDs
        data[56..60].copy_from_slice(&10u32.to_le_bytes());
        // Type IDs
        data[64..68].copy_from_slice(&5u32.to_le_bytes());
        // Method IDs
        data[88..92].copy_from_slice(&20u32.to_le_bytes());
        // Class defs
        data[96..100].copy_from_slice(&3u32.to_le_bytes());

        data
    }

    #[test]
    fn test_detect_dex() {
        let data = make_dex_header(b"035");
        let variant = detect(&data);
        assert!(matches!(variant, Some(DexVariant::Dex { .. })));
    }

    #[test]
    fn test_detect_not_dex() {
        let data = vec![0x7F, b'E', b'L', b'F'];
        assert!(detect(&data).is_none());
    }

    #[test]
    fn test_parse_dex035() {
        let data = make_dex_header(b"035");
        let variant = detect(&data).unwrap();
        let result = parse(&data, variant).unwrap();
        assert_eq!(result.isa, Isa::Dalvik);
        assert_eq!(result.format, FileFormat::Dex);
    }

    #[test]
    fn test_parse_dex039() {
        let data = make_dex_header(b"039");
        let variant = detect(&data).unwrap();
        let result = parse(&data, variant).unwrap();
        assert_eq!(result.isa, Isa::Dalvik);
        assert!(result.variant.name.contains("039"));
    }
}
