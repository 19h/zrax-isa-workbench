//! Windows CE ROM images: `B000FF` BIN files written by `romimage` and raw
//! ROM images (`.nb0`), with the ROM header (`ROMHDR`), the module table of
//! contents (`TOCentry`, `e32_rom`, `o32_rom`) and the file table
//! (`FILESentry`).
//!
//! Sources (pinned revisions and checksums in `docs/wince.md`):
//! - Microsoft Learn, "Windows Embedded CE Binary Image Data Format (Windows
//!   Embedded CE 6.0)", `ee478913(v=winembedded.60)`: sync bytes, image
//!   header, records and the terminating record.
//! - Microsoft Learn, "ROMHDR (Compact 2013)", `ee482991(v=winembedded.80)`.
//! - Microsoft `romldr.h` and `pehdr.h` (Windows Embedded Compact 7
//!   `public/common/oak/inc`): `ROM_SIGNATURE_OFFSET`, `ROM_SIGNATURE`,
//!   `ROM_TOC_POINTER_OFFSET`, the `ROMHDR_*` offsets, `TOCentry`,
//!   `FILESentry`, `e32_rom`, `o32_rom` and the `IMAGE_SCN_*` flags; the
//!   Windows CE 2.11 `romldr.h` for the version-stable `e32_rom` prefix.
//! - Microsoft BLCOMMON `blcommon.c` (Windows CE 5.0 boot loader library):
//!   the record checksum, the terminator test, the ROM offset and the
//!   statement that the TOC immediately follows the ROMHDR.
//! - Microsoft Device Emulator shared source (2006),
//!   `boards/loadbin_nb0.cpp`: BIN records start at offset 15 and the
//!   terminator's length is the entry point.
//! - itsme `dumprom.cpp` (CVS revision 1.1, 2005): FILES entries follow the
//!   TOC, `o32_rom` data is `min(o32_vsize, o32_psize)` bytes at
//!   `o32_dataptr`, and raw images are mapped by solving for the base that
//!   makes the ROMHDR's own `physfirst` consistent.
//!
//! The ROMHDR's `usCPUType` holds an `IMAGE_FILE_MACHINE_*` value ("CPU
//! (machine) Type" in `romldr.h`), which is the format's own target field
//! and is mapped through the PE/COFF machine table. Everything else (load
//! addresses, module names) is reported without ISA meaning. Every field is
//! little-endian.

use crate::error::{ClassifierError, Result};
use crate::formats::container::Container;
use crate::types::FileFormat;

mod bin;
mod memory;
mod nb0;
mod rom;

/// Prefix of this family's metadata keys.
const KEY_PREFIX: &str = "wince";

/// A Windows CE ROM image layout recognized by [`detect`] or
/// [`detect_weak`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `B000FF` BIN file: image header and checksummed records.
    Bin,
    /// Raw ROM image (`.nb0`): the image bytes from `physfirst`, with the
    /// ROM signature at offset 0x40.
    RawRom,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        FileFormat::WinCeImage
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Bin => "Windows CE BIN image",
            Self::RawRom => "Windows CE raw ROM image",
        }
    }

    /// Raw ROM images have no file header and are recognized from their
    /// complete ROM structure.
    pub fn is_weak(self) -> bool {
        self == Self::RawRom
    }
}

/// Strong recognition: the seven sync bytes `B000FF\n` at offset 0. The
/// header and records are checked by the parser, so a damaged BIN file is a
/// parse error rather than raw code.
pub fn detect(data: &[u8]) -> Option<Layout> {
    bin::has_sync(data).then_some(Layout::Bin)
}

/// Weak recognition of a raw ROM image: `ECEC` at offset 0x40 must point
/// to exactly one ROMHDR that is consistent with its own position, whose
/// image fits the file with only padding after it, and whose module and
/// file tables validate.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    nb0::is_valid(data).then_some(Layout::RawRom)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::WinCeParseError`] for a truncated or inconsistent BIN
/// header or record, a record checksum mismatch, or a raw image without one
/// consistent ROM structure.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Bin => bin::parse(data),
        Layout::RawRom => nb0::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::WinCeParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`; `what` names them in the error.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid {what} range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} + {len} B")))
}

fn le_u16(bytes: &[u8], at: usize) -> Result<u16> {
    let field: [u8; 2] = slice(bytes, at, 2, "field")?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_le_bytes(field))
}

fn le_u32(bytes: &[u8], at: usize) -> Result<u32> {
    let field: [u8; 4] = slice(bytes, at, 4, "field")?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_le_bytes(field))
}

/// A file offset or size read from a 32-bit field.
fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("usize holds a u32 on supported targets")
}

/// A byte count as `u64`.
fn to_u64(n: usize) -> u64 {
    u64::try_from(n).expect("u64 holds a usize on supported targets")
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Decimal size with the largest exact binary unit.
fn size_text(n: u64) -> String {
    if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// `"1 module"`, `"2 modules"`.
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
    fn strong_detection_needs_the_whole_sync() {
        assert_eq!(detect(b"B000FF\n"), Some(Layout::Bin));
        assert_eq!(detect(b"B000FF\nrest"), Some(Layout::Bin));
        assert_eq!(detect(b"B000FF"), None);
        assert_eq!(detect(b"B000FF\r"), None);
        assert_eq!(detect(b"N000FF\n"), None);
        assert_eq!(detect_weak(&[0u8; 0x200]), None);
    }

    #[test]
    fn layouts_report_one_format_and_their_strength() {
        assert_eq!(Layout::Bin.format(), FileFormat::WinCeImage);
        assert_eq!(Layout::RawRom.format(), FileFormat::WinCeImage);
        assert!(!Layout::Bin.is_weak());
        assert!(Layout::RawRom.is_weak());
        assert_ne!(Layout::Bin.label(), Layout::RawRom.label());
    }

    #[test]
    fn readers_name_the_truncated_range() {
        let data = [1, 2, 3];
        assert_eq!(le_u16(&data, 1).unwrap(), 0x0302);
        assert_eq!(
            le_u32(&data, 1).unwrap_err().to_string(),
            "Windows CE image parse error: Truncated field at 0x1 + 4 B"
        );
        assert!(slice(&data, usize::MAX, 2, "record").is_err());
    }

    #[test]
    fn helpers_format_sizes_and_counts() {
        assert_eq!(size_text(4096), "4 KiB");
        assert_eq!(size_text(3 << 20), "3 MiB");
        assert_eq!(size_text(1000), "1000 B");
        assert_eq!(count(1, "file", "files"), "1 file");
        assert_eq!(count(2, "file", "files"), "2 files");
        assert!(is_padding(&[0, 0xff]));
        assert!(!is_padding(&[1]));
    }
}
