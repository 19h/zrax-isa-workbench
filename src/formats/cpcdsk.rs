//! Amstrad CPC and ZX Spectrum +3 disk images (CPCEMU `MV - CPC` and
//! Extended `EXTENDED CPC DSK` files), the CP/M 2.2 filesystem that AMSDOS
//! and +3DOS write on them, and the 128-byte AMSDOS and +3DOS file headers,
//! inside a disk image or as standalone files.
//!
//! Sources (pinned revisions and SHA-256 sums in `docs/cpcdsk.md`):
//! - [DSK] "Disk image file format" and [EDSK] "Extended DSK image
//!   definition" Rev.5 (Vieth, Doewich, Thacker; cpctech documents in the
//!   `aaru-dps/docs` mirror at commit `9c008310`): the disk information
//!   block, the Track-Info block and the sector information list.
//! - [CAP32] Caprice32 `src/slotshandler.cpp` `dsk_load` (commit
//!   `6c12c4c9`), [MAME] `src/lib/formats/dsk_dsk.cpp` (commit `cefe0536`)
//!   and [LIBDSK] `LibDsk` 1.5.12 `lib/drvcpcem.c` and `lib/dskgeom.c`:
//!   identification by `MV - CPC` and `EXTENDED CPC DSK`, Track-Info blocks
//!   of more than 29 sectors, the `Offset-Info` trailer and the PCW disk
//!   specification.
//! - [AMSROM] Kevin Thacker's disassembly of the AMSDOS ROM (`amsdos.asm`):
//!   format selection from the first sector ID, the three XDPBs, the boot
//!   sector `|CPM` loads, and the header checksum. [AMSHDR] cpcwiki.eu
//!   "AMSDOS Header" (oldid 125127) and [IDSK] iDSK `src/GestDsk.h` (commit
//!   `bd620361`): the header fields.
//! - [P3MAN] ZX Spectrum +3 manual, chapter 8 parts 26 ("Using machine
//!   code") and 27 ("Guide to +3DOS"): the +3DOS header, the disk
//!   specification, `DOS BOOT` and the XDPBs. [Z88DK] z88dk
//!   `src/appmake/zx-util.c` (commit `9138a24f`): the header's file length
//!   includes the header.
//! - [DRI] Digital Research, "CP/M 2.2 Operating System Manual", Figure 5-2
//!   (FCB) and section 6.10 (DPB, Tables 6-8 to 6-10); [CPM22F] and
//!   [AMSFMT] John Elliott, "CP/M 2.2 disc formats" and "Amstrad CP/M disc
//!   formats": directory entries, extents and Amstrad format detection.
//!
//! Disk image fields are little-endian; sector data is stored in the order
//! of each track's sector information list. The disk image names no
//! processor: emulators of several machines use it. A file whose first
//! record is a valid AMSDOS header belongs to the Amstrad CPC, and one with
//! a +3DOS header to the Spectrum +3; both run Z80 code, so headered
//! binary and CODE files, and the boot sectors those systems execute, are
//! Z80 children. Everything else is classified from its own bytes.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Container, Target};
use crate::types::{Endianness, FileFormat, Isa};

mod cpm;
mod header;
mod image;

/// Identifying prefix of a CPCEMU disk image: "'MV - CPC' must be present
/// ... It is sufficient to check this" ([DSK]; [CAP32], [MAME], [LIBDSK]).
const STANDARD_SIGNATURE: &[u8; 8] = b"MV - CPC";

/// Identifying prefix of an extended disk image ([MAME]; [EDSK] calls
/// `EXTENDED` the tag, which alone is an ordinary word).
const EXTENDED_SIGNATURE: &[u8; 16] = b"EXTENDED CPC DSK";

/// Z80 code: 8-bit, little-endian operands. The CPC and the Spectrum +3
/// both run Z80 code ([AMSROM]; [P3MAN] part 26).
const Z80: Target = Target::new(Isa::Z80, 8, Endianness::Little);

/// The CPU both platforms fix for their Z80 children: the sources name the
/// Z80, not a derivative, so the code model's variant guess is replaced.
const CPU_VARIANT: &str = "Z80";

/// Bit 7 of each name character is an attribute, not part of the name
/// ([DRI] Table 5-2; [P3MAN] "File attributes").
const ATTRIBUTE_BIT: u8 = 0x80;

/// Characters of the name part of an 8.3 name; the extension follows.
const BASE_NAME_SIZE: usize = 8;

/// A CPC or +3 disk image, or a file with an AMSDOS or +3DOS header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// CPCEMU disk image (`MV - CPC`): every track block has one size.
    Standard,
    /// Extended disk image (`EXTENDED CPC DSK`): a track size table and a
    /// stored length for every sector.
    Extended,
    /// A file with a +3DOS header (`PLUS3DOS` and the soft-EOF byte).
    Plus3Dos,
    /// A file with an AMSDOS header, recognized by its checksum and fields.
    Amsdos,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Standard | Self::Extended => FileFormat::CpcDsk,
            Self::Plus3Dos => FileFormat::Plus3Dos,
            Self::Amsdos => FileFormat::Amsdos,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Standard => "CPCEMU disk image",
            Self::Extended => "Extended CPC disk image",
            Self::Plus3Dos => "+3DOS file",
            Self::Amsdos => "AMSDOS file",
        }
    }

    /// AMSDOS headers have no signature; the others start with one.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::Amsdos)
    }
}

/// Strong recognition: the disk image signatures, or the +3DOS signature
/// and soft-EOF byte, at offset 0. The rest is checked by
/// [`parse_container`], so a damaged image or header is a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if data.starts_with(STANDARD_SIGNATURE) {
        Some(Layout::Standard)
    } else if data.starts_with(EXTENDED_SIGNATURE) {
        Some(Layout::Extended)
    } else if data.starts_with(header::PLUS3DOS_SIGNATURE) {
        Some(Layout::Plus3Dos)
    } else {
        None
    }
}

/// Weak recognition of a standalone AMSDOS file: the header checksum, the
/// user number, a printable name, the zero fields, an allocated file type,
/// matching logical and real lengths, and a file size within one record of
/// the header's length.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    header::standalone_amsdos(data)
        .is_ok()
        .then_some(Layout::Amsdos)
}

/// Parse `data` as the given layout. A disk image lists the files of its
/// CP/M directory (headered binaries as Z80 code, other headered files as
/// opaque data, headerless files when they are a recognized format) and the
/// boot sector; a headered file loads its body at the header's address.
///
/// # Errors
///
/// [`ClassifierError::CpcDskParseError`] for a disk information block,
/// Track-Info block or sector list that does not fit the file, a +3DOS
/// header with a bad checksum, issue or length, or an AMSDOS header that
/// does not validate. Damage inside the filesystem is reported in notes.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Standard | Layout::Extended => cpm::parse_disk(data, layout),
        Layout::Plus3Dos => header::parse_plus3dos(data),
        Layout::Amsdos => header::parse_amsdos(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::CpcDskParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid file range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated image at 0x{start:X} + {len} B")))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes = slice(data, at, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// `value` rounded up to a multiple of `unit`, which is not zero. The
/// values are sizes within one disk image, far from `usize::MAX`.
fn round_up(value: usize, unit: usize) -> usize {
    let remainder = value % unit;
    if remainder == 0 {
        value
    } else {
        value - remainder + unit
    }
}

/// `count` with the singular or plural form of the words after it.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// ASCII text with every other byte shown as `.`, trailing spaces and NULs
/// removed.
fn printable(bytes: &[u8]) -> String {
    let text: String = bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect();
    let kept = bytes
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |last| last + 1);
    text.chars().take(kept).collect()
}

/// An 8.3 name (eight name and three extension characters, padded with
/// spaces) as `NAME.EXT` with attribute bits cleared, or `NAME` when the
/// extension is blank.
fn file_name(characters: &[u8]) -> String {
    let cleared: Vec<u8> = characters.iter().map(|b| b & !ATTRIBUTE_BIT).collect();
    let (base, extension) = cleared.split_at(BASE_NAME_SIZE.min(cleared.len()));
    let base = printable(base);
    let extension = printable(extension);
    if extension.is_empty() {
        base
    } else {
        format!("{base}.{extension}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_clear_attribute_bits() {
        assert_eq!(file_name(b"DISC    BIN"), "DISC.BIN");
        assert_eq!(file_name(b"README     "), "README");
        // Read-only (T1') and system (T2') attributes.
        assert_eq!(file_name(b"GAME    \xc2\xc9N"), "GAME.BIN");
    }

    #[test]
    fn signatures_select_layouts() {
        assert_eq!(
            detect(b"MV - CPCEMU Disk-File\r\nDisk-Info\r\n"),
            Some(Layout::Standard)
        );
        assert_eq!(
            detect(b"EXTENDED CPC DSK File\r\nDisk-Info\r\n"),
            Some(Layout::Extended)
        );
        assert_eq!(detect(b"PLUS3DOS\x1a\x01\x00"), Some(Layout::Plus3Dos));
        // The tag alone, and the +3DOS signature without its soft EOF.
        assert_eq!(detect(b"EXTENDED PLAY"), None);
        assert_eq!(detect(b"PLUS3DOS "), None);
    }

    #[test]
    fn rounding_and_text_helpers() {
        assert_eq!(round_up(0, 128), 0);
        assert_eq!(round_up(1, 128), 128);
        assert_eq!(round_up(256, 128), 256);
        assert_eq!(printable(b"CPDRead v3.24\0"), "CPDRead v3.24");
        assert_eq!(printable(b"A\x01B  "), "A.B");
        assert_eq!(counted(1, "file", "files"), "1 file");
        assert_eq!(counted(2, "file", "files"), "2 files");
    }
}
