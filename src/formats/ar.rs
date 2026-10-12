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
    let members = parse_members(data)?;
    let member_count = members.len();
    let member_names: Vec<&str> = members.iter().take(10).map(|m| m.name.as_str()).collect();

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
        let preview: Vec<&str> = member_names.iter().take(5).copied().collect();
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
    let mut result =
        ClassificationResult::from_format(Isa::Unknown(0), 0, Endianness::Little, format);
    result.confidence = 0.0;
    result.variant = Variant::new(variant_name);
    result.metadata = metadata;

    Ok(result)
}

/// An ordinary archive member. GNU/TI long names and BSD inline names are
/// resolved; symbol and name index members are excluded from ISA analysis.
#[derive(Debug)]
pub struct Member<'a> {
    pub name: String,
    /// File offset of `data`, after any BSD inline name.
    pub offset: usize,
    pub data: &'a [u8],
}

fn member_error(message: &str) -> ClassifierError {
    ClassifierError::ArchiveParseError {
        message: format!("Archive: {message}"),
    }
}

/// Parse every member strictly: unlike the summary in [`parse`], a
/// malformed header, truncated member or missing alignment byte is an error.
pub fn parse_members(data: &[u8]) -> Result<Vec<Member<'_>>> {
    if !data.starts_with(&AR_MAGIC) {
        return Err(member_error("Invalid ar signature"));
    }
    let mut pos = AR_MAGIC.len();
    let mut long_names: &[u8] = &[];
    let mut members = Vec::new();
    while pos < data.len() {
        let header = data
            .get(pos..pos.saturating_add(AR_MEMBER_HEADER_SIZE))
            .ok_or_else(|| member_error("Truncated member header"))?;
        if header[ar_header::FMAG_OFFSET..] != ar_header::FMAG {
            return Err(member_error("Invalid member header terminator"));
        }
        let size_field =
            &header[ar_header::SIZE_OFFSET..ar_header::SIZE_OFFSET + ar_header::SIZE_SIZE];
        let size = std::str::from_utf8(size_field)
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .ok_or_else(|| member_error("Invalid decimal member size"))?;
        let start = pos + AR_MEMBER_HEADER_SIZE;
        let end = start
            .checked_add(size)
            .ok_or_else(|| member_error("Member size overflow"))?;
        let body = data
            .get(start..end)
            .ok_or_else(|| member_error("Truncated member contents"))?;
        let name_field =
            &header[ar_header::NAME_OFFSET..ar_header::NAME_OFFSET + ar_header::NAME_SIZE];
        let raw_name = std::str::from_utf8(name_field)
            .map_err(|_| member_error("Invalid member name"))?
            .trim_end();

        if raw_name == "//" {
            // GNU/TI long-name table, indexed by later "/<offset>" names.
            long_names = body;
        } else {
            let (name, inline_len) = member_name(raw_name, body, long_names)?;
            if is_object_member(&name) {
                members.push(Member {
                    name,
                    offset: start + inline_len,
                    data: &body[inline_len..],
                });
            }
        }

        // Members start at even offsets; odd-sized data is followed by "\n".
        pos = end;
        if pos % 2 != 0 {
            if data.get(pos) != Some(&b'\n') {
                return Err(member_error("Missing odd-member alignment byte"));
            }
            pos += 1;
        }
    }
    Ok(members)
}

/// Resolve a member name. Returns the name and the length of a BSD name
/// stored inline at the start of `body`.
fn member_name(raw_name: &str, body: &[u8], long_names: &[u8]) -> Result<(String, usize)> {
    // BSD "#1/<length>": the name occupies the first bytes of the member.
    if let Some(len) = raw_name.strip_prefix("#1/") {
        let len = len
            .parse::<usize>()
            .map_err(|_| member_error("Invalid BSD name length"))?;
        let name = body
            .get(..len)
            .ok_or_else(|| member_error("Truncated BSD member name"))?;
        let name = String::from_utf8_lossy(name)
            .trim_end_matches('\0')
            .to_string();
        return Ok((name, len));
    }
    // GNU/TI "/<offset>" into the long-name table.
    if let Some(offset) = raw_name
        .strip_prefix('/')
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
    {
        let offset = offset
            .parse::<usize>()
            .map_err(|_| member_error("Invalid long-name offset"))?;
        let tail = long_names
            .get(offset..)
            .ok_or_else(|| member_error("Long-name offset outside table"))?;
        let len = tail
            .iter()
            .position(|b| matches!(b, b'\n' | 0))
            .ok_or_else(|| member_error("Unterminated long member name"))?;
        let name = String::from_utf8_lossy(&tail[..len])
            .trim_end_matches('/')
            .to_string();
        return Ok((name, 0));
    }
    Ok((raw_name.trim_end_matches('/').to_string(), 0))
}

/// Symbol tables ("/", "__.SYMDEF", "__TI_.SYMDEF") and other special members
/// are not object files.
fn is_object_member(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.starts_with("__.SYMDEF")
        && !name.starts_with("__TI_.SYMDEF")
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
