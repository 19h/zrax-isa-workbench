//! Apple disk images: UDIF (`.dmg`) images, which end with a 512-byte
//! `koly` trailer, and encrypted disk images (Encrypted Encoding version 2
//! `encrcdsa` headers and version 1 `cdsaencr` footers).
//!
//! Apple publishes no UDIF specification. Sources (pins in `docs/dmg.md`):
//! - libdmg-hfsplus commit `7ac55ec64c96f7800d9818ce64c79670e7f02b67`:
//!   `includes/dmg/dmg.h` (`UDIFResourceFile`, `BLKXTable`, `BLKXRun`, the
//!   chunk types and checksum type 2), `dmg/io.c` (`extractBLKX`),
//!   `dmg/resources.c` (`readResources`), `dmg/dmglib.c` (`buildDmg`,
//!   `calculateMasterChecksum`) and `includes/dmg/filevault.h`.
//! - 7-Zip commit `9128b80e3a471108678e2b3ec3c985861c8d7b0f`,
//!   `CPP/7zip/Archive/DmgHandler.cpp`: trailer and fork range checks,
//!   block table validation (`CFile::Parse`), chunk positions, the table
//!   and master CRC-32 rules, the binary resource fork, chunk type
//!   `0x80000008` as xz.
//! - darling-dmg commit `1a6de10c5886c40a414090701b2520bd0417ce29`:
//!   `src/DMGDisk.cpp` and `src/DMGPartition.cpp` (`CFName` and `Name`,
//!   chunk positions relative to the data fork).
//! - Apple, *Inside Macintosh: More Macintosh Toolbox* (1993), chapter 1,
//!   "Resource File Format", Figures 1-11 to 1-17 (binary resource forks).
//! - keramics commit `4712c949645a1499635bc109692d4a9aedb9ba01`,
//!   `docs/formats/src/udif.md` and `cdsaencr.md`; apfs-fuse commit
//!   `66b86bd525e8cb90f9012543be89b1f092b75cf3`,
//!   `ApfsLib/DiskImageFile.cpp` (encrypted header and footer layouts).
//!
//! A UDIF image stores a disk as block tables (`blkx` resources, one per
//! partition of the disk) whose chunks are zero fill, raw sectors or
//! compressed runs (ADC, zlib, bzip2, LZFSE, LZMA in xz). The tables live
//! in an XML property list or, in old images, a binary resource fork; the
//! trailer locates both. Each volume partition (or a whole disk stored as
//! one table) becomes one child: its first `min(size, MAX_PAYLOAD)` bytes
//! assembled from its chunks, listed and classified on its own when it
//! holds a recognized format, so a filesystem or partitioned disk describes
//! itself. Partition-map, boot-record, driver and free-space tables are
//! decoded only to verify their checksums: on their own they describe
//! nothing. None of these formats names an ISA. Encrypted images are
//! opaque: their key parameters are reported, never used.

use crate::error::{ClassifierError, Result};
use crate::formats::container::Container;
use crate::types::FileFormat;

mod blkx;
mod encrypted;
mod koly;
mod plist;
mod rsrc;
mod udif;

/// Prefix of generated metadata keys.
const KEY_PREFIX: &str = "dmg";

/// Bytes of the 512-byte sectors that block tables count in.
const SECTOR_SIZE: u64 = 512;

/// Longest partition name shown in labels, notes and metadata, in
/// characters.
const MAX_TEXT: usize = 256;

/// Most block tables read from one image: one per partition, so far more
/// than any disk holds.
const MAX_TABLES: usize = crate::formats::container::MAX_COMPONENTS;

/// An Apple disk image layout recognized by [`detect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// UDIF image: a `koly` trailer at the end that locates the data fork
    /// and the block tables.
    Udif,
    /// Encrypted Encoding version 2: an `encrcdsa` header at offset 0.
    EncryptedV2,
    /// Encrypted Encoding version 1: a `cdsaencr` footer at the end.
    EncryptedV1,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Udif | Self::EncryptedV2 | Self::EncryptedV1 => FileFormat::AppleDmg,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Udif => "UDIF disk image",
            Self::EncryptedV2 => "Encrypted disk image (encrcdsa)",
            Self::EncryptedV1 => "Encrypted disk image (cdsaencr)",
        }
    }

    /// Recognized from complete structure rather than a magic value. The
    /// UDIF trailer is a 96-bit key (signature, version and size) whose
    /// fork ranges and property list must describe the file; the encrypted
    /// layouts carry 64-bit signatures, the version 2 header also its
    /// version. None is weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Udif | Self::EncryptedV2 | Self::EncryptedV1 => false,
        }
    }
}

/// Strong recognition: a `koly` trailer of version 4 and size 512 whose
/// forks lie before it and whose XML property list (or binary resource
/// fork) is where it says; else an `encrcdsa` header of version 2 at
/// offset 0; else a `cdsaencr` footer at the end. The UDIF trailer is
/// checked first: an image is never both encrypted and readable.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if koly::is_present(data) {
        return Some(Layout::Udif);
    }
    if encrypted::is_v2(data) {
        return Some(Layout::EncryptedV2);
    }
    if encrypted::is_v1(data) {
        return Some(Layout::EncryptedV1);
    }
    None
}

/// Parse an Apple disk image into the shared container model: one child
/// per partition that holds a recognized format, notes and metadata.
///
/// # Errors
///
/// [`ClassifierError::DmgParseError`] for a truncated or inconsistent
/// trailer, property list, resource fork, block table or chunk: a bad
/// signature, version or size, a fork or chunk outside the file, a chunk
/// that does not decode to its size, or a CRC-32 that does not match.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Udif => udif::parse(data),
        Layout::EncryptedV2 => encrypted::parse_v2(data),
        Layout::EncryptedV1 => encrypted::parse_v1(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::DmgParseError {
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

/// The `len` bytes at the 64-bit file offset `start`.
fn range<'a>(data: &'a [u8], start: u64, len: u64, what: &str) -> Result<&'a [u8]> {
    match (usize::try_from(start), usize::try_from(len)) {
        (Ok(start), Ok(len)) => slice(data, start, len, what),
        _ => Err(error(format!("Truncated {what} at 0x{start:X} + {len} B"))),
    }
}

fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(bytes, at, N, "header field")?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn be_u16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(array(bytes, at)?))
}

fn be_u32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(bytes, at)?))
}

fn be_u64(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(array(bytes, at)?))
}

/// Decimal size with the largest exact binary unit.
fn size_text(n: u64) -> String {
    if n >= 1 << 30 && n % (1 << 30) == 0 {
        format!("{} GiB", n >> 30)
    } else if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// `n` and the noun in the number it takes: "1 block table", "8 block
/// tables".
fn counted(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// Display form of untrusted text: control characters as `?`, cut after
/// [`MAX_TEXT`] characters.
fn display_text(text: &str) -> String {
    let mut shown = String::new();
    for (i, ch) in text.chars().enumerate() {
        if i == MAX_TEXT {
            shown.push_str("...");
            break;
        }
        shown.push(if ch.is_control() { '?' } else { ch });
    }
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_use_the_largest_exact_binary_unit() {
        assert_eq!(size_text(512), "512 B");
        assert_eq!(size_text(1 << 20), "1 MiB");
        assert_eq!(size_text(1_048_577), "1048577 B");
        assert_eq!(size_text(3 << 30), "3 GiB");
    }

    #[test]
    fn display_text_hides_control_characters_and_cuts_long_names() {
        assert_eq!(display_text("disk\u{1}image"), "disk?image");
        let long = "x".repeat(MAX_TEXT + 10);
        assert_eq!(display_text(&long).len(), MAX_TEXT + 3);
    }

    #[test]
    fn ranges_beyond_the_input_are_truncation_errors() {
        let data = [0u8; 16];
        assert_eq!(
            range(&data, 8, 16, "data fork").unwrap_err().to_string(),
            "Apple disk image parse error: Truncated data fork at 0x8 + 16 B"
        );
        assert!(range(&data, u64::MAX, 1, "data fork").is_err());
        assert_eq!(range(&data, 4, 4, "data fork").unwrap(), &[0; 4]);
    }
}
