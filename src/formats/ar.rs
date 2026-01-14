//! ar archive format parser.
//!
//! ar archives are used for Unix static libraries (.a files).
//! The format is ISA-independent but contains object files for a specific architecture.

use crate::error::{ClassifierError, Result};
use crate::types::{
    ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant,
};

/// ar archive magic: "!<arch>\n"
pub const AR_MAGIC: [u8; 8] = [b'!', b'<', b'a', b'r', b'c', b'h', b'>', b'\n'];

/// Windows COFF archive/import library magic
pub const COFF_ARCHIVE_MAGIC: [u8; 8] = [b'!', b'<', b'a', b'r', b'c', b'h', b'>', b'\n'];

/// ar member header size
pub const AR_MEMBER_HEADER_SIZE: usize = 60;

/// ar member header field offsets
pub mod ar_header {
    pub const NAME_OFFSET: usize = 0;
    pub const NAME_SIZE: usize = 16;
    pub const DATE_OFFSET: usize = 16;
    pub const DATE_SIZE: usize = 12;
    pub const UID_OFFSET: usize = 28;
    pub const UID_SIZE: usize = 6;
    pub const GID_OFFSET: usize = 34;
    pub const GID_SIZE: usize = 6;
    pub const MODE_OFFSET: usize = 40;
    pub const MODE_SIZE: usize = 8;
    pub const SIZE_OFFSET: usize = 48;
    pub const SIZE_SIZE: usize = 10;
    pub const FMAG_OFFSET: usize = 58;
    pub const FMAG: [u8; 2] = [b'`', b'\n'];
}

/// ar archive variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArVariant {
    /// GNU/SysV ar format
    Gnu,
    /// BSD ar format
    Bsd,
    /// Windows COFF import library
    WindowsLib,
}

/// Detect ar archive format.
pub fn detect(data: &[u8]) -> Option<ArVariant> {
    if data.len() < 8 {
        return None;
    }

    if data[0..8] != AR_MAGIC {
        return None;
    }

    // Check first member to determine variant
    if data.len() >= 8 + AR_MEMBER_HEADER_SIZE {
        let member_off = 8;
        let name = &data[member_off..member_off + 16];

        // GNU format uses "/" for symbol table
        if name.starts_with(b"/               ") || name.starts_with(b"//              ") {
            return Some(ArVariant::Gnu);
        }

        // BSD format uses "__.SYMDEF" or "#1/" prefix
        if name.starts_with(b"__.SYMDEF") || name.starts_with(b"#1/") {
            return Some(ArVariant::Bsd);
        }

        // Windows import library
        if name.starts_with(b"/               ") {
            // Check if second member looks like COFF import
            // For now, default to GNU
            return Some(ArVariant::Gnu);
        }
    }

    // Default to GNU variant
    Some(ArVariant::Gnu)
}

/// Parse ar archive.
pub fn parse(data: &[u8], variant: ArVariant) -> Result<ClassificationResult> {
    if data.len() < 8 {
        return Err(ClassifierError::TruncatedData {
            offset: 0,
            expected: 8,
            actual: data.len(),
        });
    }

    // Count members
    let mut member_count = 0;
    let mut offset = 8; // Skip magic
    let mut member_names: Vec<String> = Vec::new();

    while offset + AR_MEMBER_HEADER_SIZE <= data.len() {
        // Verify magic at end of header
        if data[offset + ar_header::FMAG_OFFSET..offset + ar_header::FMAG_OFFSET + 2]
            != ar_header::FMAG
        {
            break;
        }

        // Read name
        let name_bytes = &data[offset..offset + 16];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end()
            .trim_end_matches('/')
            .to_string();

        // Read size
        let size_str = String::from_utf8_lossy(
            &data[offset + ar_header::SIZE_OFFSET..offset + ar_header::SIZE_OFFSET + ar_header::SIZE_SIZE],
        );
        let size: usize = size_str.trim().parse().unwrap_or(0);

        // Skip special entries
        if !name.is_empty() && !name.starts_with('/') && name != "__.SYMDEF" && !name.starts_with("#1/") {
            if member_names.len() < 10 {
                member_names.push(name);
            }
            member_count += 1;
        }

        // Move to next member (aligned to even boundary)
        offset += AR_MEMBER_HEADER_SIZE + size;
        if offset % 2 != 0 {
            offset += 1;
        }
    }

    let variant_name = match variant {
        ArVariant::Gnu => "GNU/SysV ar",
        ArVariant::Bsd => "BSD ar",
        ArVariant::WindowsLib => "Windows import library",
    };

    let format = match variant {
        ArVariant::WindowsLib => FileFormat::WindowsLib,
        _ => FileFormat::Archive,
    };

    let mut notes = vec![format!("{} archive", variant_name)];
    notes.push(format!("Members: {}", member_count));

    if !member_names.is_empty() {
        let preview: Vec<&str> = member_names.iter().take(5).map(|s| s.as_str()).collect();
        notes.push(format!(
            "Contents: {}{}",
            preview.join(", "),
            if member_names.len() > 5 { ", ..." } else { "" }
        ));
    }

    let metadata = ClassificationMetadata {
        section_count: Some(member_count),
        notes,
        ..Default::default()
    };

    // ar archives are ISA-independent containers
    let mut result = ClassificationResult::from_format(
        Isa::Unknown(0),
        0,
        Endianness::Little,
        format,
    );
    result.variant = Variant::new(variant_name);
    result.metadata = metadata;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ar_archive() -> Vec<u8> {
        let mut data = Vec::new();

        // Magic
        data.extend_from_slice(&AR_MAGIC);

        // First member (symbol table for GNU format)
        let mut header = [b' '; AR_MEMBER_HEADER_SIZE];
        header[0..16].copy_from_slice(b"/               ");
        header[48..58].copy_from_slice(b"0         ");
        header[58..60].copy_from_slice(&ar_header::FMAG);
        data.extend_from_slice(&header);

        // Second member
        let mut header = [b' '; AR_MEMBER_HEADER_SIZE];
        header[0..16].copy_from_slice(b"test.o/         ");
        header[48..58].copy_from_slice(b"100       ");
        header[58..60].copy_from_slice(&ar_header::FMAG);
        data.extend_from_slice(&header);
        data.extend_from_slice(&[0u8; 100]); // Fake object content

        data
    }

    #[test]
    fn test_detect_ar() {
        let data = make_ar_archive();
        assert!(detect(&data).is_some());
    }

    #[test]
    fn test_detect_not_ar() {
        let data = vec![0x7F, b'E', b'L', b'F'];
        assert!(detect(&data).is_none());
    }

    #[test]
    fn test_parse_ar() {
        let data = make_ar_archive();
        let variant = detect(&data).unwrap();
        let result = parse(&data, variant).unwrap();
        assert_eq!(result.format, FileFormat::Archive);
    }
}
