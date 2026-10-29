//! Apple images: Image4 containers (`IMG4`, `IM4P`, and the `IM4M` manifest
//! and `IM4R` restore-info parts), dyld shared caches, and the legacy Img3
//! and 8900 firmware containers.
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
//! - Img3 and 8900: The Apple Wiki (successor of The iPhone Wiki) "IMG3
//!   File Format" revision 312068, "KBAG" revision 190028 and "S5L File
//!   Formats" revision 312559; planetbeing/xpwn commit
//!   `20c32e5c12d1b22a9d55a59a0ff6267f539b77f4` (`includes/xpwn/img3.h`,
//!   `ipsw-patch/img3.c`, `includes/xpwn/8900.h`, `ipsw-patch/8900.c`,
//!   `includes/xpwn/img2.h`). See [`img3`] and [`s5l8900`].
//!
//! No Image4 field names an ISA: the four-character type is a firmware role,
//! so the ISA comes from the payload (a kernelcache's Mach-O header or the
//! code model). The dyld cache magic carries an architecture token, which is
//! an explicit target field. Img3 and 8900 headers name no ISA either.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Target};
use crate::types::{Endianness, FileFormat, Isa};
use std::fmt::Write;

mod dyld;
mod img3;
mod img4;
mod s5l8900;

/// Keybag material exactly as encoded in an IM4P. It may be device-wrapped;
/// merely reading these bytes does not establish that they are usable keys.
#[derive(Debug, serde::Serialize)]
pub struct Image4Keybag {
    /// Keybag class (1 production, 2 development; other values retained).
    pub class: u64,
    /// Encoded IV bytes as hexadecimal, without unwrapping.
    pub iv: String,
    /// Encoded key bytes as hexadecimal, without unwrapping.
    pub key: String,
}

/// Payload coordinates and encoded keybag material for inline inspection.
#[derive(Debug, serde::Serialize)]
pub struct Image4Info {
    /// Firmware role, not an ISA claim.
    pub label: String,
    /// Payload offset in the immediate input file, in bytes.
    pub offset: usize,
    /// Stored payload size in bytes.
    pub size: usize,
    /// Encoded keybags, in file order. These are not persisted by the UI.
    pub keybags: Vec<Image4Keybag>,
}

/// Inspect the payload fields of an IMG4 or IM4P for the inline decryption
/// controls. Returns `None` for other formats. This does not authenticate the
/// manifest or unwrap keybag material.
///
/// # Errors
///
/// [`ClassifierError::AppleParseError`] for malformed Image4 payload fields.
pub fn image4_info(data: &[u8]) -> Result<Option<Image4Info>> {
    img4::info(data)
}

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
    /// Img3 firmware image: a tagged container whose `DATA` tag is the
    /// payload, encrypted when a `KBAG` tag is present.
    Img3,
    /// S5L8900 `8900` container: a 2 KiB header, the payload (plaintext or
    /// encrypted) and a footer signature and certificate.
    Apple8900,
}

impl Layout {
    /// The reported file format. Standalone manifests and restore info are
    /// parts of an `IMG4` and report that format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Img4 | Self::Im4m | Self::Im4r => FileFormat::Img4,
            Self::Im4p => FileFormat::Im4p,
            Self::DyldCache => FileFormat::DyldCache,
            Self::Img3 => FileFormat::Img3,
            Self::Apple8900 => FileFormat::Apple8900,
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
            Self::Img3 => "Img3 image",
            Self::Apple8900 => "8900 container",
        }
    }

    /// Every Apple layout starts with a magic, so none is weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Img4
            | Self::Im4p
            | Self::Im4m
            | Self::Im4r
            | Self::DyldCache
            | Self::Img3
            | Self::Apple8900 => false,
        }
    }
}

/// Strong recognition: an Image4 DER header (`SEQUENCE`, then the
/// `IA5String` magic), the `dyld_v1` cache magic, the Img3 magic (`3gmI`
/// as stored) or the 8900 magic and version text. The rest of the file is
/// not checked, so a damaged image becomes a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if let Some(layout) = img4::detect(data) {
        return Some(layout);
    }
    if dyld::detect(data) {
        return Some(Layout::DyldCache);
    }
    if img3::detect(data) {
        return Some(Layout::Img3);
    }
    s5l8900::detect(data).then_some(Layout::Apple8900)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::AppleParseError`] for malformed DER, a missing or
/// misplaced Image4 element, a dyld cache header or table that does not
/// fit the file, or an Img3 tag or 8900 header range that does not fit
/// the image.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Img4 => img4::parse_img4(data),
        Layout::Im4p => img4::parse_im4p(data),
        Layout::Im4m => img4::parse_im4m(data),
        Layout::Im4r => img4::parse_im4r(data),
        Layout::DyldCache => dyld::parse(data),
        Layout::Img3 => img3::parse(data),
        Layout::Apple8900 => s5l8900::parse(data),
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

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2)?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_le_bytes(bytes))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_le_bytes(bytes))
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
