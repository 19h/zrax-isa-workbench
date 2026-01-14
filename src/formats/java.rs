//! Java class file parser.
//!
//! Java class files contain bytecode for the Java Virtual Machine (JVM).
//! The format is platform-independent and has been stable since Java 1.0.

use crate::error::{ClassifierError, Result};
use crate::formats::{read_u16, read_u32};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// Java class file magic: 0xCAFEBABE
pub const JAVA_MAGIC: u32 = 0xCAFEBABE;

/// Class file header size (without constant pool).
pub const CLASS_HEADER_SIZE: usize = 10;

/// Access flags for classes.
pub mod access_flags {
    pub const PUBLIC: u16 = 0x0001;
    pub const FINAL: u16 = 0x0010;
    pub const SUPER: u16 = 0x0020;
    pub const INTERFACE: u16 = 0x0200;
    pub const ABSTRACT: u16 = 0x0400;
    pub const SYNTHETIC: u16 = 0x1000;
    pub const ANNOTATION: u16 = 0x2000;
    pub const ENUM: u16 = 0x4000;
    pub const MODULE: u16 = 0x8000;
}

/// Constant pool tags.
pub mod cp_tag {
    pub const UTF8: u8 = 1;
    pub const INTEGER: u8 = 3;
    pub const FLOAT: u8 = 4;
    pub const LONG: u8 = 5;
    pub const DOUBLE: u8 = 6;
    pub const CLASS: u8 = 7;
    pub const STRING: u8 = 8;
    pub const FIELDREF: u8 = 9;
    pub const METHODREF: u8 = 10;
    pub const INTERFACE_METHODREF: u8 = 11;
    pub const NAME_AND_TYPE: u8 = 12;
    pub const METHOD_HANDLE: u8 = 15;
    pub const METHOD_TYPE: u8 = 16;
    pub const DYNAMIC: u8 = 17;
    pub const INVOKE_DYNAMIC: u8 = 18;
    pub const MODULE: u8 = 19;
    pub const PACKAGE: u8 = 20;
}

/// Detect Java class file.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // Java class files are big-endian
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    magic == JAVA_MAGIC
}

/// Map major version to Java release.
fn major_version_to_java(major: u16) -> Option<&'static str> {
    match major {
        45 => Some("Java 1.1"),
        46 => Some("Java 1.2"),
        47 => Some("Java 1.3"),
        48 => Some("Java 1.4"),
        49 => Some("Java 5"),
        50 => Some("Java 6"),
        51 => Some("Java 7"),
        52 => Some("Java 8"),
        53 => Some("Java 9"),
        54 => Some("Java 10"),
        55 => Some("Java 11"),
        56 => Some("Java 12"),
        57 => Some("Java 13"),
        58 => Some("Java 14"),
        59 => Some("Java 15"),
        60 => Some("Java 16"),
        61 => Some("Java 17"),
        62 => Some("Java 18"),
        63 => Some("Java 19"),
        64 => Some("Java 20"),
        65 => Some("Java 21"),
        66 => Some("Java 22"),
        67 => Some("Java 23"),
        68 => Some("Java 24"),
        _ => None,
    }
}

/// Parse Java class file.
pub fn parse(data: &[u8]) -> Result<ClassificationResult> {
    if data.len() < CLASS_HEADER_SIZE {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: CLASS_HEADER_SIZE,
            actual: data.len(),
        });
    }

    // Java class files are big-endian
    let magic = read_u32(data, 0, false)?;
    if magic != JAVA_MAGIC {
        return Err(ClassifierError::InvalidMagic {
            expected: "CAFEBABE".to_string(),
            actual: format!("{:08X}", magic),
        });
    }

    let minor_version = read_u16(data, 4, false)?;
    let major_version = read_u16(data, 6, false)?;
    let constant_pool_count = read_u16(data, 8, false)?;

    let mut notes = vec!["Java class file".to_string()];

    // Java version
    let java_version = major_version_to_java(major_version);
    if let Some(ver) = java_version {
        notes.push(format!("Target: {} (class version {}.{})", ver, major_version, minor_version));
    } else {
        notes.push(format!("Class version: {}.{}", major_version, minor_version));
    }

    notes.push(format!("Constant pool entries: {}", constant_pool_count - 1));

    // Try to parse access flags and class info if we can skip the constant pool
    // This requires parsing the entire constant pool, which is complex
    // For now, we'll just report basic info

    let metadata = ClassificationMetadata {
        flags: Some(((major_version as u32) << 16) | minor_version as u32),
        notes,
        ..Default::default()
    };

    let variant_name = java_version.unwrap_or("Unknown").to_string();

    let mut result = ClassificationResult::from_format(
        Isa::Jvm,
        32,
        Endianness::Big,
        FileFormat::JavaClass,
    );
    result.variant = Variant::new(variant_name);
    result.metadata = metadata;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_java_class(major: u16, minor: u16) -> Vec<u8> {
        let mut data = vec![0u8; 64];

        // Magic
        data[0..4].copy_from_slice(&JAVA_MAGIC.to_be_bytes());
        // Minor version
        data[4..6].copy_from_slice(&minor.to_be_bytes());
        // Major version
        data[6..8].copy_from_slice(&major.to_be_bytes());
        // Constant pool count (1 = empty, since indices start at 1)
        data[8..10].copy_from_slice(&2u16.to_be_bytes());

        data
    }

    #[test]
    fn test_detect_java() {
        let data = make_java_class(52, 0);
        assert!(detect(&data));
    }

    #[test]
    fn test_detect_not_java() {
        let data = vec![0x7F, b'E', b'L', b'F'];
        assert!(!detect(&data));
    }

    #[test]
    fn test_parse_java8() {
        let data = make_java_class(52, 0);
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::Jvm);
        assert_eq!(result.format, FileFormat::JavaClass);
        assert!(result.variant.name.contains("Java 8"));
    }

    #[test]
    fn test_parse_java17() {
        let data = make_java_class(61, 0);
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::Jvm);
        assert!(result.variant.name.contains("Java 17"));
    }

    #[test]
    fn test_parse_java21() {
        let data = make_java_class(65, 0);
        let result = parse(&data).unwrap();
        assert_eq!(result.isa, Isa::Jvm);
        assert!(result.variant.name.contains("Java 21"));
    }
}
