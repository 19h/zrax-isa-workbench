//! Windows Imaging Format (WIM) images (`.wim`, split parts `.swm`, and the
//! `.esd` files of the same format): the header, the lookup table of
//! resources, the XML data, the integrity table, and each image's metadata
//! resource, whose directory tree names the files. Files in a recognized
//! format are the container's children, labeled `/<image>/<path>` and
//! classified by their own parsers.
//!
//! Primary sources (pins and hashes in `docs/wim.md`):
//! - Microsoft, "Windows Imaging File Format (WIM)" (Download Center 13096,
//!   `Windows Imaging File Format.rtf`, version 1.1 of 2024-07-15, text of
//!   October 2007): the header, resource headers, the lookup table, the
//!   metadata resource (security data, `DIRENTRY`, `STREAMENTRY`), chunked
//!   file resources, the integrity table, the XML data and split WIMs.
//! - wimlib v1.14.5 (commit `cd5e231c348c255ae5088873b5a66ee0eb96fa07`):
//!   `include/wimlib/header.h` (versions, flags, LZMS and solid
//!   resources), `resource.h` and `src/resource.c` (resource headers, chunk
//!   tables, solid resource headers), `src/blob_table.c` (lookup table
//!   entries and solid runs), `src/metadata_resource.c`, `src/security.c`
//!   and `src/dentry.c` (the metadata resource, dentry and stream entry
//!   layouts, stream types), `src/xml.c`, `src/integrity.c`, `src/wim.c`
//!   (compression flags and chunk size bounds) and `src/header.c`.
//! - 7-Zip 26.03 `CPP/7zip/Archive/Wim/WimIn.cpp` as a second reader (a
//!   chunk size of 0 means 32 KiB; directory walks bounded by the resource
//!   size).
//!
//! Resources are stored, or compressed in chunks with XPRESS, LZX or LZMS
//! (see [`crate::formats::compressed`]), on their own or as solid
//! resources that hold many files. A WIM names no CPU: the container target
//! is always unknown, the image names and architectures in the XML data
//! are reported as text, and the ISA comes from the files. The SHA-1 of
//! every resource that is decoded whole is verified against the lookup
//! table, as is the integrity table when present.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::size_text;
use crate::formats::container::Container;
use crate::types::FileFormat;
use std::fmt::Write as _;

mod files;
mod header;
mod integrity;
mod lookup;
mod metadata;
mod resource;
mod xml;

use header::Header;

/// The header magic at offset 0 (MSWIM `ImageTag`; wimlib `WIM_MAGIC`).
const MAGIC: &[u8; 8] = b"MSWIM\0\0\0";

/// The header size field and the one size that wimlib and 7-Zip accept for
/// versions 1.13 and 0xE00 (wimlib `WIM_HEADER_DISK_SIZE`).
const HEADER_SIZE_FIELD: usize = 0x08;
const HEADER_SIZE: usize = 208;

/// The total part count (MSWIM `usTotalParts`).
const TOTAL_PARTS_FIELD: usize = 0x2A;

/// Length of a SHA-1 digest, the key of every resource.
const HASH_SIZE: usize = 20;

/// A SHA-1 digest from the lookup table or a directory entry.
type Hash = [u8; HASH_SIZE];

/// A WIM layout recognized by [`detect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// A whole WIM file: one part of one.
    Image,
    /// One part of a split WIM (`.swm`): the header names more than one
    /// part.
    SplitPart,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Image | Self::SplitPart => FileFormat::Wim,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Image => "WIM image",
            Self::SplitPart => "split WIM part",
        }
    }

    /// Recognized from a magic value: the eight-byte `MSWIM\0\0\0` and the
    /// header size 208, twelve bytes in all, so the layout is strong.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Image | Self::SplitPart => false,
        }
    }
}

/// Strong recognition: `MSWIM\0\0\0` at offset 0 and a header size of 208.
/// A total part count above 1 makes the input a split part. The key lies in
/// the first 12 bytes, so a damaged image is still recognized and becomes a
/// parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let header_size = le_u32(data, HEADER_SIZE_FIELD).ok()? as usize;
    if !data.starts_with(MAGIC) || header_size != HEADER_SIZE {
        return None;
    }
    match le_u16(data, TOTAL_PARTS_FIELD) {
        Ok(parts) if parts > 1 => Some(Layout::SplitPart),
        _ => Some(Layout::Image),
    }
}

/// Parse a WIM into the shared container model: the header, lookup table,
/// XML data and integrity table in notes and metadata, and every file
/// stream in a recognized format as a child labeled by its image and path,
/// in image order and directory order.
///
/// # Errors
///
/// [`ClassifierError::WimParseError`] for a missing magic, a header size
/// other than 208, a truncated header, an unsupported version, invalid part
/// numbers, compression flags without a codec, an unsupported chunk size,
/// or a lookup table that lies outside the input or holds an invalid
/// resource. Damaged images, files and XML data are reported in notes.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Image | Layout::SplitPart => parse(data, layout),
    }
}

fn parse(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let header = Header::read(data)?;
    let table = lookup::read(data, &header)?;
    let mut c = Container::new(layout.format(), layout.label(), "wim");
    header.push_notes(&mut c);
    table.push_notes(&header, &mut c);
    let xml = xml::read(data, &header, &mut c);
    integrity::check(data, &header, &mut c);
    if xml.as_ref().is_some_and(|xml| xml.encrypted) {
        c.opaque = true;
        c.notes.push(
            "The XML data marks an encrypted ESD (`ESD/ENCRYPTED`): resources are encrypted and \
             were not decoded"
                .to_string(),
        );
    } else {
        files::list(data, &header, &table, xml.as_ref(), &mut c);
    }
    c.consumed = data.len();
    let end = table.furthest_end(&header).min(data.len());
    if end < data.len() {
        c.notes.push(format!(
            "{} after the last resource at 0x{end:X}",
            size_text(data.len() - end)
        ));
    }
    Ok(c)
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::WimParseError {
        message: message.into(),
    }
}

/// The `len` bytes of `what` at file offset `start`.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid {what} range at 0x{start:X}")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} + {len} B")))
}

/// Little-endian 16-bit field at `at`.
fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2, "WIM field")?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_le_bytes(bytes))
}

/// Little-endian 32-bit field at `at`.
fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4, "WIM field")?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_le_bytes(bytes))
}

/// Little-endian 64-bit field at `at`.
fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    let bytes: [u8; 8] = slice(data, at, 8, "WIM field")?
        .try_into()
        .expect("slice has exactly 8 bytes");
    Ok(u64::from_le_bytes(bytes))
}

/// The SHA-1 digest at `at`.
fn hash_at(data: &[u8], at: usize) -> Result<Hash> {
    Ok(slice(data, at, HASH_SIZE, "WIM hash")?
        .try_into()
        .expect("slice has exactly 20 bytes"))
}

/// A 64-bit size or offset as `usize`, or an error naming `what`.
fn to_usize(value: u64, what: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| error(format!("Invalid {what} 0x{value:X}")))
}

/// Lowercase hexadecimal digits of a digest, as SHA-1 values are written.
fn hex(hash: &Hash) -> String {
    let mut text = String::with_capacity(2 * HASH_SIZE);
    for byte in hash {
        write!(text, "{byte:02x}").expect("writing to a String succeeds");
    }
    text
}

/// `n` followed by the singular or plural noun, for notes.
fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_needs_the_magic_and_the_header_size() {
        let mut header = vec![0u8; HEADER_SIZE];
        header[..8].copy_from_slice(MAGIC);
        header[HEADER_SIZE_FIELD] = 0xd0;
        assert_eq!(detect(&header), Some(Layout::Image));
        assert_eq!(detect(&header[..12]), Some(Layout::Image));
        assert_eq!(detect(&header[..11]), None);
        header[TOTAL_PARTS_FIELD] = 2;
        assert_eq!(detect(&header), Some(Layout::SplitPart));
        header[HEADER_SIZE_FIELD] = 0x60;
        assert_eq!(detect(&header), None);
        header[HEADER_SIZE_FIELD] = 0xd0;
        header[5] = b'X';
        assert_eq!(detect(&header), None);
    }

    #[test]
    fn layouts_report_their_format_and_strength() {
        assert_eq!(Layout::Image.format(), FileFormat::Wim);
        assert_eq!(Layout::SplitPart.label(), "split WIM part");
        assert!(!Layout::Image.is_weak());
    }

    #[test]
    fn digests_print_as_lowercase_hex() {
        let mut hash = [0u8; HASH_SIZE];
        hash[0] = 0xab;
        hash[19] = 0x01;
        assert_eq!(hex(&hash), format!("ab{}01", "0".repeat(36)));
    }
}
