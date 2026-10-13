//! Java runtime images: jimage files (the `lib/modules` file of a JDK or
//! jlink runtime image) and JMOD files (jlink's module packaging format).
//!
//! Sources, all `OpenJDK` tag `jdk-21+35`:
//! - jimage layout: `src/java.base/share/native/libjimage/imageFile.hpp`
//!   (header, index, perfect hash, location attributes, strings) and
//!   `imageFile.cpp` (`ImageFileReader::open`, `ImageStrings::find`,
//!   `ImageLocation::set_data`, `get_resource`);
//!   `src/java.base/share/classes/jdk/internal/jimage/ImageHeader.java`,
//!   `ImageLocation.java`, `BasicImageReader.java` and
//!   `ImageStringsReader.java` (the Java reader); the writer in
//!   `src/jdk.jlink/share/classes/jdk/tools/jlink/internal/`
//!   (`BasicImageWriter.java`, `ImageLocationWriter.java`,
//!   `ImageStringsWriter.java`, `PerfectHashBuilder.java`,
//!   `ImageResourcesTree.java`).
//! - Compressed resources: `imageDecompressor.hpp`/`.cpp` (native) and
//!   `jdk/internal/jimage/decompressor/` (`Decompressor.java`,
//!   `CompressedResourceHeader.java`, `ZipDecompressor.java`,
//!   `StringSharingDecompressor.java`, `CompressIndexes.java`); see the
//!   `resource` submodule.
//! - JMOD: `src/java.base/share/classes/jdk/internal/jmod/JmodFile.java`
//!   and `src/jdk.jlink/share/classes/jdk/tools/jmod/JmodOutputStream.java`;
//!   see the `jmod` submodule.
//!
//! Neither format names an ISA. A jimage's byte order is the byte order of
//! the platform jlink wrote it for, not a property of the code: its class
//! files are JVM bytecode in the class file's own big-endian layout. Class
//! files and other resources in a recognized format are children,
//! classified from their own bytes; a JMOD's ZIP archive is one child that
//! the ZIP parser lists.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{self, Child, Container, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use crate::types::FileFormat;
use std::borrow::Cow;

mod jimage;
mod jmod;
mod resource;

/// Bytes at the start of a resource that are checked for a recognized
/// format before the whole resource is checked and listed.
const RECOGNITION_PREFIX: usize = 4 << 10;

/// Names shown in one note before the rest are only counted.
const NOTE_NAMES: usize = 8;

/// A Java runtime image layout recognized by [`detect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// jimage whose header and index are little-endian (`DA DA FE CA`).
    JimageLittleEndian,
    /// jimage whose header and index are big-endian (`CA FE DA DA`).
    JimageBigEndian,
    /// JMOD file: `JM`, version 1.0 and a ZIP archive.
    Jmod,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::JimageLittleEndian | Self::JimageBigEndian => FileFormat::Jimage,
            Self::Jmod => FileFormat::Jmod,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::JimageLittleEndian => "jimage (little-endian)",
            Self::JimageBigEndian => "jimage (big-endian)",
            Self::Jmod => "JMOD",
        }
    }

    /// Recognized from complete structure rather than a magic value. Every
    /// layout here carries a magic, so none is weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::JimageLittleEndian | Self::JimageBigEndian | Self::Jmod => false,
        }
    }
}

/// Strong recognition: the jimage magic `0xCAFEDADA` in either byte order
/// with major version 1, or `JM`, version 1.0 and a ZIP local file header.
pub fn detect(data: &[u8]) -> Option<Layout> {
    jimage::detect(data).or_else(|| jmod::detect(data))
}

/// Parse a jimage or JMOD file into the shared container model.
///
/// # Errors
///
/// [`ClassifierError::JavaImageParseError`] for a truncated or inconsistent
/// header, index, location or resource range, or a JMOD header that is not
/// followed by a ZIP archive. A resource that does not decode is not an
/// error; it is left out and counted in a note.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::JimageLittleEndian => jimage::parse(data, true),
        Layout::JimageBigEndian => jimage::parse(data, false),
        Layout::Jmod => jmod::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::JavaImageParseError {
        message: message.into(),
    }
}

/// The `len` bytes of `what` at offset `start` of `data`.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid {what} range at 0x{start:X}")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} + {len} B")))
}

fn array<const N: usize>(data: &[u8], at: usize, what: &str) -> Result<[u8; N]> {
    Ok(slice(data, at, N, what)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

/// A u32 in the byte order `le` selects (true means little-endian).
fn u32_at(data: &[u8], at: usize, le: bool, what: &str) -> Result<u32> {
    let bytes = array(data, at, what)?;
    Ok(if le {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

/// An i32 in the byte order `le` selects (true means little-endian).
fn i32_at(data: &[u8], at: usize, le: bool, what: &str) -> Result<i32> {
    let bytes = array(data, at, what)?;
    Ok(if le {
        i32::from_le_bytes(bytes)
    } else {
        i32::from_be_bytes(bytes)
    })
}

/// A u64 in the byte order `le` selects (true means little-endian).
fn u64_at(data: &[u8], at: usize, le: bool, what: &str) -> Result<u64> {
    let bytes = array(data, at, what)?;
    Ok(if le {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Decimal size with the largest exact binary unit.
fn size_text(n: usize) -> String {
    if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// Names for a note: the first [`NOTE_NAMES`] are kept, the rest only
/// counted, so a note stays small for any image.
#[derive(Debug, Default)]
struct NameList {
    shown: Vec<String>,
    total: usize,
}

impl NameList {
    fn push(&mut self, name: impl Into<String>) {
        if self.shown.len() < NOTE_NAMES {
            self.shown.push(name.into());
        }
        self.total += 1;
    }

    fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// The shown names joined by `, `, with the count of the others.
    fn text(&self) -> String {
        let hidden = self.total - self.shown.len();
        let shown = self.shown.join(", ");
        if hidden > 0 {
            format!("{shown} and {hidden} more")
        } else {
            shown
        }
    }
}

/// Decoded bytes, counted against [`MAX_EXTRACTED`]. Every decode is
/// charged before it happens, so the decoding work of one image is bounded
/// too.
#[derive(Debug, Default)]
struct Budget {
    used: usize,
}

impl Budget {
    /// Account for `size` more decoded bytes. Returns false, charging
    /// nothing, once the limit would pass.
    fn charge(&mut self, size: usize) -> bool {
        match self.used.checked_add(size) {
            Some(total) if total <= MAX_EXTRACTED => {
                self.used = total;
                true
            }
            _ => false,
        }
    }
}

/// Whether `bytes`, a resource's contents, are a recognized format: first
/// its leading [`RECOGNITION_PREFIX`] bytes, then the whole resource, so
/// unrecognized resources are not run through every detector in full.
fn is_member(bytes: &[u8]) -> bool {
    let prefix_len = bytes.len().min(RECOGNITION_PREFIX);
    container::is_recognized(&bytes[..prefix_len]) && container::is_recognized(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_report_their_format_and_strength() {
        assert_eq!(Layout::JimageLittleEndian.format(), FileFormat::Jimage);
        assert_eq!(Layout::JimageBigEndian.format(), FileFormat::Jimage);
        assert_eq!(Layout::Jmod.format(), FileFormat::Jmod);
        assert!(!Layout::JimageLittleEndian.is_weak());
        assert!(!Layout::JimageBigEndian.is_weak());
        assert!(!Layout::Jmod.is_weak());
        assert_eq!(Layout::JimageBigEndian.label(), "jimage (big-endian)");
    }

    #[test]
    fn readers_honour_the_requested_byte_order() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 0xff];
        assert_eq!(u32_at(&bytes, 0, true, "field").unwrap(), 0x0403_0201);
        assert_eq!(u32_at(&bytes, 0, false, "field").unwrap(), 0x0102_0304);
        assert_eq!(i32_at(&[0xff; 4], 0, true, "field").unwrap(), -1);
        assert_eq!(
            u64_at(&bytes, 0, false, "field").unwrap(),
            0x0102_0304_0506_0708
        );
        let truncated = u32_at(&bytes, 6, true, "jimage field").unwrap_err();
        assert!(truncated
            .to_string()
            .contains("Truncated jimage field at 0x6 + 4 B"));
        assert!(slice(&bytes, usize::MAX, 2, "field").is_err());
    }

    #[test]
    fn name_lists_count_the_names_they_leave_out() {
        let mut names = NameList::default();
        assert!(names.is_empty());
        for i in 0..10 {
            names.push(format!("m{i}"));
        }
        assert_eq!(names.text(), "m0, m1, m2, m3, m4, m5, m6, m7 and 2 more");
        assert_eq!(size_text(64 << 20), "64 MiB");
        assert_eq!(size_text(4096), "4 KiB");
        assert_eq!(size_text(29), "29 B");
    }

    #[test]
    fn budget_stops_at_the_extraction_limit() {
        let mut budget = Budget::default();
        assert!(budget.charge(MAX_EXTRACTED));
        assert!(!budget.charge(1));
        assert!(!budget.charge(usize::MAX));
        assert_eq!(budget.used, MAX_EXTRACTED);
    }

    #[test]
    fn members_need_a_recognized_prefix_and_contents() {
        assert!(is_member(b"\xca\xfe\xba\xbe\0\0\0\x41\x01\x01"));
        assert!(!is_member(b"plain text resource"));
        assert!(is_padding(&[0, 0xff, 0]));
        assert!(!is_padding(b"x"));
    }
}
