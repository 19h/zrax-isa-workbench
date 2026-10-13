//! QNX Neutrino image filesystems (IFS): bootable images (a startup header,
//! the startup program and an image filesystem that may be compressed) and
//! bare image filesystems.
//!
//! Sources:
//! - QNX `sys/startup.h` (Apache-2.0 release, `$Rev: 169802`; copy pinned
//!   at askac/dumpifs `b7bac90e8312`): `struct startup_header`, the `flags1`
//!   bits and compression field, `struct startup_trailer`.
//! - QNX `sys/image.h` (`$Rev: 153052`; vocho/openqnx `cc95df3543a1`
//!   `trunk/services/system/public/sys/image.h`): `struct image_header`,
//!   `union image_dirent`, `struct image_trailer` and `union script_cmd`.
//! - mkifs `mk_image_fsys.c` (`$Rev: 203655`), `mkxfs.c` and `booter.c`,
//!   vocho/openqnx `cc95df3543a1` `trunk/utils/m/mkxfs/mkxfs/`: the image
//!   layout, the trailer checksums (`iwrite`), the compression framing
//!   (`gzopen`, `lzoflush`, `uclflush`) and the boot script encoding
//!   (`parse_script_cmd`).
//! - dumpifs `dumpifs.c`, same commit, `trunk/utils/m/mkxfs/dumpifs/`: the
//!   reader's decompression loops and directory walk.
//! - QNX SDP 7.0.0 and 8.0 "Building Embedded Systems", "The startup
//!   header", and the SDP 8.0 Utilities Reference, `mkifs` ("Output image
//!   format", `compress` attribute).
//!
//! The startup header's `machine` field is the ELF `e_machine` of the
//! startup program, explicit architecture evidence mapped through the ELF
//! table. Members of the image filesystem are classified on their own bytes
//! (an executable by its own ELF header). Every multi-byte field is stored in
//! the target byte order that the structure's big-endian flag selects.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::size_text;
use crate::formats::container::Container;
use crate::types::FileFormat;

mod imagefs;
mod script;
mod startup;

/// `STARTUP_HDR_SIGNATURE`, stored in the target byte order.
const STARTUP_HDR_SIGNATURE: u32 = 0x00ff_7eeb;

/// Offset of `preboot_size` in `struct startup_header`.
const PREBOOT_SIZE_OFFSET: usize = 0x30;

/// Largest boot prefix before a startup header: `preboot_size` is 16 bits,
/// and mkifs pads the prefix to a multiple of four bytes.
const MAX_PREBOOT: usize = 0xfffc;

/// `IMAGE_SIGNATURE`, at the start of every image filesystem.
const IMAGE_SIGNATURE: &[u8; 7] = b"imagefs";

/// Size of `struct startup_trailer` and `struct image_trailer`: one 32-bit
/// checksum.
const TRAILER_SIZE: usize = 4;

/// Prefix of the container's metadata keys.
const KEY_PREFIX: &str = "qnx";

/// A QNX image layout recognized by its signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// A startup header, the startup program and an image filesystem; also
    /// the dummy startup header that records the compression of a
    /// non-bootable image.
    Bootable {
        /// File offset of the startup header, which equals the size of the
        /// boot prefix before it (`preboot_size`).
        header_offset: usize,
    },
    /// An image filesystem without a startup header (`imagefs` at offset 0).
    ImageFs,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Bootable { .. } | Self::ImageFs => FileFormat::QnxIfs,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Bootable { .. } => "QNX bootable image",
            Self::ImageFs => "QNX image filesystem",
        }
    }

    /// Recognized from complete structure rather than a magic value. Both
    /// layouts carry a signature, so neither is weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Bootable { .. } | Self::ImageFs => false,
        }
    }
}

/// Strong recognition: `imagefs` at offset 0, the startup signature at
/// offset 0 in either byte order, or the startup signature after a boot
/// prefix whose size the header's `preboot_size` states.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if data.starts_with(IMAGE_SIGNATURE) {
        return Some(Layout::ImageFs);
    }
    startup_header_offset(data).map(|header_offset| Layout::Bootable { header_offset })
}

/// Parse a QNX image into the shared container model.
///
/// # Errors
///
/// [`ClassifierError::QnxParseError`] for a truncated or inconsistent
/// startup header, a startup or image checksum that does not match, or an
/// image directory that does not fit its image filesystem. A compressed
/// image filesystem that does not decode is not an error; it is kept as an
/// opaque component with a note.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Bootable { header_offset } => startup::parse(data, header_offset),
        Layout::ImageFs => imagefs::parse(data),
    }
}

/// The offset of a startup header: 0 when the signature starts the file,
/// otherwise the first four-byte aligned offset within [`MAX_PREBOOT`]
/// whose signature is followed by a `preboot_size` naming that offset. A
/// boot prefix carries code that may contain the signature value, so the
/// self-reference is what tells the header apart.
fn startup_header_offset(data: &[u8]) -> Option<usize> {
    if signature_order(data, 0).is_some() {
        return Some(0);
    }
    let last = data
        .len()
        .checked_sub(PREBOOT_SIZE_OFFSET + 2)?
        .min(MAX_PREBOOT);
    (4..=last).step_by(4).find(|&offset| {
        signature_order(data, offset).is_some_and(|le| {
            u16_at(data, offset + PREBOOT_SIZE_OFFSET, le)
                .is_ok_and(|preboot| usize::from(preboot) == offset)
        })
    })
}

/// The byte order of a startup signature at `at`: `Some(true)` when it is
/// stored little-endian, `Some(false)` when big-endian.
fn signature_order(data: &[u8], at: usize) -> Option<bool> {
    let bytes: [u8; 4] = data.get(at..at.checked_add(4)?)?.try_into().ok()?;
    if u32::from_le_bytes(bytes) == STARTUP_HDR_SIGNATURE {
        Some(true)
    } else if u32::from_be_bytes(bytes) == STARTUP_HDR_SIGNATURE {
        Some(false)
    } else {
        None
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::QnxParseError {
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

fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(data, at, N)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

/// A u16 in the byte order `le` selects (true means little-endian).
fn u16_at(data: &[u8], at: usize, le: bool) -> Result<u16> {
    let bytes = array(data, at)?;
    Ok(if le {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

/// A u32 in the byte order `le` selects (true means little-endian).
fn u32_at(data: &[u8], at: usize, le: bool) -> Result<u32> {
    let bytes = array(data, at)?;
    Ok(if le {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(array(data, at)?))
}

/// A size or offset field as `usize`.
fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("usize holds a u32")
}

/// Whether the 32-bit words of `bytes`, read in the byte order `le`
/// selects, sum to zero modulo 2^32. mkifs adds every word it writes and
/// stores the negated sum in the trailer, so a region that ends with its
/// trailer sums to zero. `bytes` holds whole words.
fn has_zero_word_sum(bytes: &[u8], le: bool) -> bool {
    let sum = bytes.chunks_exact(4).fold(0u32, |sum, word| {
        let word: [u8; 4] = word.try_into().expect("chunk has exactly 4 bytes");
        let value = if le {
            u32::from_le_bytes(word)
        } else {
            u32::from_be_bytes(word)
        };
        sum.wrapping_add(value)
    });
    sum == 0
}

/// `value` rounded up to a multiple of four bytes.
fn round_up4(value: usize) -> Option<usize> {
    Some(value.checked_add(3)? & !3)
}

/// "little-endian" or "big-endian".
fn byte_order_name(le: bool) -> &'static str {
    if le {
        "little-endian"
    } else {
        "big-endian"
    }
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// A note for the bytes after an image that ends at `end`, if any. mkifs
/// documents an optional boot postfix that other programs append ("You can
/// always append a wrapper directly to the end of an image file"), so such
/// bytes are reported rather than rejected.
fn trailing_note(data: &[u8], end: usize) -> Option<String> {
    let trailing = data.get(end..).unwrap_or_default();
    if trailing.is_empty() {
        None
    } else if is_padding(trailing) {
        Some(format!(
            "Image ends at 0x{end:X}; {} of padding follow",
            size_text(trailing.len())
        ))
    } else {
        Some(format!(
            "Image ends at 0x{end:X}; {} after it (a boot postfix or appended data) are not analyzed",
            size_text(trailing.len())
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_signatures_are_found_in_either_byte_order() {
        assert_eq!(signature_order(&[0xeb, 0x7e, 0xff, 0x00], 0), Some(true));
        assert_eq!(signature_order(&[0x00, 0xff, 0x7e, 0xeb], 0), Some(false));
        assert_eq!(signature_order(&[0xeb, 0x7e, 0xff], 0), None);
        assert_eq!(signature_order(&[0; 8], usize::MAX), None);
    }

    #[test]
    fn a_prefixed_header_must_name_its_own_offset() {
        let mut data = vec![0u8; 0x200];
        data[0x40..0x44].copy_from_slice(&STARTUP_HDR_SIGNATURE.to_le_bytes());
        assert_eq!(startup_header_offset(&data), None);
        data[0x40 + PREBOOT_SIZE_OFFSET..0x42 + PREBOOT_SIZE_OFFSET]
            .copy_from_slice(&0x40u16.to_le_bytes());
        assert_eq!(startup_header_offset(&data), Some(0x40));
        // An unaligned signature is never a header.
        let mut unaligned = vec![0u8; 0x200];
        unaligned[0x41..0x45].copy_from_slice(&STARTUP_HDR_SIGNATURE.to_le_bytes());
        unaligned[0x41 + PREBOOT_SIZE_OFFSET] = 0x41;
        assert_eq!(startup_header_offset(&unaligned), None);
        assert_eq!(startup_header_offset(&[]), None);
    }

    #[test]
    fn word_sums_follow_the_byte_order() {
        let mut words = 5u32.to_be_bytes().to_vec();
        words.extend_from_slice(&5u32.wrapping_neg().to_be_bytes());
        assert!(has_zero_word_sum(&words, false));
        assert!(!has_zero_word_sum(&words, true));
        assert!(has_zero_word_sum(&[], true));
    }

    #[test]
    fn readers_honour_the_requested_byte_order() {
        let bytes = [1, 2, 3, 4];
        assert_eq!(u16_at(&bytes, 0, true).unwrap(), 0x0201);
        assert_eq!(u16_at(&bytes, 0, false).unwrap(), 0x0102);
        assert_eq!(u32_at(&bytes, 0, false).unwrap(), 0x0102_0304);
        assert_eq!(be_u16(&bytes, 2).unwrap(), 0x0304);
        assert!(u32_at(&bytes, 1, true).is_err());
        assert!(slice(&bytes, usize::MAX, 2).is_err());
        assert_eq!(round_up4(5), Some(8));
        assert_eq!(round_up4(usize::MAX), None);
    }
}
