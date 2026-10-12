//! Apple images: Image4 containers (`IMG4`, `IM4P`, and the `IM4M` manifest
//! and `IM4R` restore-info parts) and dyld shared caches.
//!
//! Sources, pinned:
//! - Image4 has no published wire specification. Three independent
//!   implementations agree on the layout used here: xerub/img4lib commit
//!   `69772c72f3c08f021ec9fa4c386f2b3df60a38b7` (`libvfs/vfs_img4.c`),
//!   m1stadev/PyIMG4 commit `80491329a41ff90f1df1a2bcaa122d190db94bf3`
//!   (`pyimg4/parser.py`, `pyimg4/types.py`) and tihmstar/img4tool commit
//!   `bb2d63494c58993f5c8ce2ed7df207ab1063587b` (`img4tool/img4tool.cpp`).
//!   apple-oss-distributions/xnu commit
//!   `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`
//!   (`EXTERNAL_HEADERS/img4/firmware.h`) names the `krnl` four-character
//!   code `KernelCache`. See [`img4`].
//! - dyld shared cache: apple-oss-distributions/dyld tag `dyld-1378`
//!   (`include/mach-o/dyld_cache_format.h`, `common/DyldSharedCache.cpp`,
//!   `cache_builder/SubCache.cpp`, `other-tools/dsc_extractor.cpp`), and tags
//!   `dyld-97.1`, `dyld-210.2.3`, `dyld-360.22` and `dyld-519.2.2`
//!   (`launch-cache/dyld_cache_format.h`, `launch-cache/Architectures.hpp`)
//!   for older header versions and big-endian PowerPC caches. See [`dyld`].
//!
//! No Image4 field names an ISA: the four-character type is a firmware role,
//! so the ISA comes from the payload (a kernelcache's Mach-O header or the
//! code model). The dyld cache magic carries an architecture token, which is
//! an explicit target field.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Target};
use crate::types::{Endianness, FileFormat, Isa};
use std::fmt::Write;

mod dyld;
mod img4;

/// Prefix of the family's metadata keys (`apple_im4p_type`,
/// `apple_dyld_uuid`, `apple_component_0`).
const KEY_PREFIX: &str = "apple";

/// An Apple layout recognized from its magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Image4 file: an `IM4P` payload with an optional `IM4M` manifest and
    /// `IM4R` restore info.
    Img4,
    /// Image4 payload: a four-character type, a description and the payload
    /// bytes, optionally encrypted or compressed.
    Im4p,
    /// Standalone Image4 manifest; metadata only.
    Im4m,
    /// Standalone Image4 restore info; metadata only.
    Im4r,
    /// dyld shared cache file (a main cache or one of its subcaches).
    DyldCache,
}

impl Layout {
    /// The reported file format. Standalone manifests and restore info are
    /// parts of an `IMG4` and report that format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Img4 | Self::Im4m | Self::Im4r => FileFormat::Img4,
            Self::Im4p => FileFormat::Im4p,
            Self::DyldCache => FileFormat::DyldCache,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Img4 => "IMG4 image",
            Self::Im4p => "IM4P payload",
            Self::Im4m => "IM4M manifest",
            Self::Im4r => "IM4R restore info",
            Self::DyldCache => "dyld shared cache",
        }
    }

    /// Every Apple layout starts with a magic, so none is weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Img4 | Self::Im4p | Self::Im4m | Self::Im4r | Self::DyldCache => false,
        }
    }
}

/// Strong recognition: an Image4 DER header (`SEQUENCE`, then the
/// `IA5String` magic) or the `dyld_v1` cache magic. The rest of the file
/// is not checked, so a damaged image becomes a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if let Some(layout) = img4::detect(data) {
        return Some(layout);
    }
    dyld::detect(data).then_some(Layout::DyldCache)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::AppleParseError`] for malformed DER, a missing or
/// misplaced Image4 element, or a dyld cache header or table that does not
/// fit the file.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Img4 => img4::parse_img4(data),
        Layout::Im4p => img4::parse_im4p(data),
        Layout::Im4m => img4::parse_im4m(data),
        Layout::Im4r => img4::parse_im4r(data),
        Layout::DyldCache => dyld::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::AppleParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated file range 0x{start:X} + {len} B")))
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// At most `limit` bytes of `bytes` as text, with characters outside
/// printable ASCII shown as `.` and an ellipsis when cut.
fn printable(bytes: &[u8], limit: usize) -> String {
    let mut text: String = bytes
        .iter()
        .take(limit)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect();
    if bytes.len() > limit {
        text.push_str("...");
    }
    text
}

/// `count` followed by the singular or plural noun: "1 mapping",
/// "2 mappings".
fn counted(count: usize, singular: &str, plural: &str) -> String {
    let noun = if count == 1 { singular } else { plural };
    format!("{count} {noun}")
}

/// A four-character code as text, or as hex when it is not printable ASCII.
fn fourcc_text(fourcc: [u8; 4]) -> String {
    if fourcc.iter().all(u8::is_ascii_graphic) {
        fourcc.iter().map(|&b| char::from(b)).collect()
    } else {
        format!("0x{:08X}", u32::from_be_bytes(fourcc))
    }
}

/// Bytes as uppercase hex, without separators.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(text, "{b:02X}").expect("writing to a String cannot fail");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_replaces_control_bytes_and_marks_truncation() {
        assert_eq!(printable(b"iBoot-1\n", 16), "iBoot-1.");
        assert_eq!(printable(b"abcdef", 3), "abc...");
    }

    #[test]
    fn counted_picks_the_noun_form() {
        assert_eq!(counted(1, "image", "images"), "1 image");
        assert_eq!(counted(0, "image", "images"), "0 images");
    }

    #[test]
    fn fourcc_text_falls_back_to_hex() {
        assert_eq!(fourcc_text(*b"krnl"), "krnl");
        assert_eq!(fourcc_text([0, 1, 2, 3]), "0x00010203");
    }

    #[test]
    fn detect_needs_a_magic() {
        assert_eq!(detect(b"dyld_v1   arm64\0"), Some(Layout::DyldCache));
        assert_eq!(
            detect(&[0x30, 0x06, 0x16, 0x04, b'I', b'M', b'4', b'P']),
            Some(Layout::Im4p)
        );
        assert_eq!(
            detect(&[0x30, 0x06, 0x16, 0x04, b'I', b'M', b'4', b'X']),
            None
        );
        assert_eq!(detect(b"dyld_v0    i386\0"), None);
    }
}
