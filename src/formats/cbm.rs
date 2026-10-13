//! Commodore disk and tape images: D64 (1541), D71 (1571) and D81 (1581)
//! disk images and T64 tape images.
//!
//! Primary sources (pins and SHA-256 hashes in `docs/cbm.md`):
//! - VICE manual `doc/vice.texi`, chapter "The emulator file formats",
//!   sections "The T64 tape image format", "The D64 disk image format",
//!   "The D71 disk image format" and "The D81 disk image format" (the disk
//!   sections are Peter Schepers' documents as edited for VICE), at
//!   VICE-Team/svn-mirror tag `r46282` (commit `eb723e0f`).
//! - VICE `src/tape/t64.c`, `src/tape/t64.h` and `src/tape/tape.c` (T64
//!   fields, signatures, end-address repair, loading at the start address),
//!   `src/vdrive/vdrive-bam.c` (the BAM that formatting writes, the free
//!   block count) and `src/vdrive/vdrive-iec.c` (the last sector's byte
//!   count), same commit.
//! - file(1) `magic/Magdir/c64` v1.16 (tag `FILE5_46`): the BAM and header
//!   signatures at 0x16500 (D64, D71) and 0x61800 (D81).
//! - MAME `src/mame/commodore/c64.cpp`, `c128.cpp`, `vic20.cpp` and
//!   `plus4.cpp` at `17842be9`: the platform CPUs.
//!
//! Disk images have no magic: a layout is recognized from its exact size,
//! the BAM (or 1581 header and BAM) signature that formatting writes and a
//! directory chain that stays inside the image. T64 files carry a
//! signature.
//!
//! Neither format has an ISA field, but both exist only for the Commodore
//! 8-bit computers, whose KERNAL loads a program file into the memory of a
//! 6502-family CPU (VIC-20 6502, C64 6510, C16 and Plus/4 7501, C128 8502).
//! Each PRG file is therefore a child of 6502-family code, after its
//! two-byte load address on disk; SEQ, USR and REL files and 1581
//! partitions are opaque data, and DEL entries are skipped.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Target};
use crate::types::{Endianness, FileFormat, Isa};
use std::fmt::Write as _;

mod dos;
mod t64;

/// Prefix of the generated metadata keys.
const KEY_PREFIX: &str = "cbm";

/// 6502-family code: 8-bit, little-endian operands.
const MOS_6502: Target = Target::new(Isa::Mcs6502, 8, Endianness::Little);

/// The PETSCII shifted space that pads disk names (VICE manual, D64
/// section: "padded with $A0").
const SHIFTED_SPACE: u8 = 0xa0;

/// Notes listed for damaged entries before the rest are only counted.
const MAX_PROBLEM_NOTES: usize = 16;

/// The bits of a directory entry's type byte (VICE manual, D64 section;
/// VICE `cbmdos.h`, `CBMDOS_FT_*`).
const FILE_TYPE_MASK: u8 = 0x0f;
const FILE_LOCKED: u8 = 0x40;
const FILE_CLOSED: u8 = 0x80;

/// CBM DOS file types (VICE `cbmdos.h`); 5 is a 1581 partition.
const TYPE_DEL: u8 = 0;
const TYPE_SEQ: u8 = 1;
const TYPE_PRG: u8 = 2;
const TYPE_USR: u8 = 3;
const TYPE_REL: u8 = 4;
const TYPE_CBM: u8 = 5;

/// A CBM DOS disk image layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskImage {
    /// 1541 disk of 35 tracks (683 sectors).
    D64,
    /// 1541 disk of 40 tracks (768 sectors; tracks 36-40 have 17 sectors).
    D64Extended,
    /// 1571 double-sided disk of 70 tracks (1366 sectors).
    D71,
    /// 1581 disk of 80 tracks of 40 sectors (3200 sectors).
    D81,
}

/// A Commodore image layout recognized by [`detect`] or [`detect_weak`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// A CBM DOS disk image, optionally followed by one error byte per
    /// sector.
    Disk(DiskImage),
    /// T64 tape image.
    T64,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Disk(DiskImage::D64 | DiskImage::D64Extended) => FileFormat::D64,
            Self::Disk(DiskImage::D71) => FileFormat::D71,
            Self::Disk(DiskImage::D81) => FileFormat::D81,
            Self::T64 => FileFormat::T64,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Disk(DiskImage::D64) => "D64 disk image (35 tracks)",
            Self::Disk(DiskImage::D64Extended) => "D64 disk image (40 tracks)",
            Self::Disk(DiskImage::D71) => "D71 disk image",
            Self::Disk(DiskImage::D81) => "D81 disk image",
            Self::T64 => "T64 tape image",
        }
    }

    /// Disk images have no magic and are recognized from their complete
    /// structure.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::Disk(_))
    }
}

/// Strong recognition: a T64 signature at offset 0.
pub fn detect(data: &[u8]) -> Option<Layout> {
    t64::detect(data).then_some(Layout::T64)
}

/// Weak recognition of D64, D71 and D81 images: an exact image size (with
/// or without error bytes), the BAM signature that formatting writes
/// (directory link 18/1 and DOS version `A`; 1571 double-sided flag; 1581
/// header `28 03 44 00` and BAM version `D` with its complement) and a
/// directory chain inside the image that visits no sector twice.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    dos::detect(data).map(Layout::Disk)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::CbmParseError`] for an image whose size, BAM, header
/// or directory chain does not validate, or a T64 file whose header or
/// directory is truncated or inconsistent. Damaged files are reported in
/// notes instead.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Disk(image) => dos::parse(data, image),
        Layout::T64 => t64::parse(data),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::CbmParseError {
        message: message.into(),
    }
}

/// The `size` bytes of `what` at file offset `offset`.
fn range<'a>(data: &'a [u8], what: &str, offset: usize, size: usize) -> Result<&'a [u8]> {
    offset
        .checked_add(size)
        .and_then(|end| data.get(offset..end))
        .ok_or_else(|| {
            error(format!(
                "Truncated {what}: 0x{offset:X} + {size} B exceeds the {} B file",
                data.len()
            ))
        })
}

/// A CBM DOS file type: the low four bits of a type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileType {
    Del,
    Seq,
    Prg,
    Usr,
    Rel,
    /// A 1581 partition (`CBM`).
    Partition,
    /// A value the DOS does not define.
    Other(u8),
}

impl FileType {
    fn of(type_byte: u8) -> Self {
        match type_byte & FILE_TYPE_MASK {
            TYPE_DEL => Self::Del,
            TYPE_SEQ => Self::Seq,
            TYPE_PRG => Self::Prg,
            TYPE_USR => Self::Usr,
            TYPE_REL => Self::Rel,
            TYPE_CBM => Self::Partition,
            other => Self::Other(other),
        }
    }

    /// The name a directory listing shows.
    fn name(self) -> String {
        match self {
            Self::Del => "DEL".to_string(),
            Self::Seq => "SEQ".to_string(),
            Self::Prg => "PRG".to_string(),
            Self::Usr => "USR".to_string(),
            Self::Rel => "REL".to_string(),
            Self::Partition => "CBM".to_string(),
            Self::Other(value) => format!("type {value}"),
        }
    }
}

/// The child label of a file: its type and name, and for a program its
/// load address.
fn file_label(kind: &str, name: &str, load_address: Option<u16>) -> String {
    match load_address {
        Some(address) => format!("{kind} \"{name}\" at 0x{address:04X}"),
        None => format!("{kind} \"{name}\""),
    }
}

/// A program file: 6502-family code that is never parsed as a nested
/// container.
fn program(child: Child<'_>) -> Child<'_> {
    child.with_target(MOS_6502).as_code()
}

/// Whether a PETSCII byte is shown as itself: space, punctuation, digits
/// and the letters, which the power-on (uppercase and graphics) character
/// set shows as their ASCII counterparts. The quote and 0x5C (a pound sign
/// in PETSCII) are escaped so that labels stay unambiguous.
fn is_plain_petscii(byte: u8) -> bool {
    matches!(byte, 0x20..=0x5d) && byte != b'"' && byte != b'\\'
}

/// PETSCII as display text: plain bytes as ASCII, every other byte as
/// `\xNN`.
fn petscii_text(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for &byte in bytes {
        if is_plain_petscii(byte) {
            text.push(char::from(byte));
        } else {
            let _ = write!(text, "\\x{byte:02X}");
        }
    }
    text
}

/// A disk name or file name: the bytes before the first shifted space,
/// which the DOS treats as the end of the name.
fn padded_name(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|&b| b == SHIFTED_SPACE)
        .unwrap_or(bytes.len());
    petscii_text(&bytes[..end])
}

/// A T64 name or description: trailing spaces (VICE), shifted spaces
/// (`DirMaster`, per file(1)) and NULs removed.
fn tape_text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .rposition(|&b| !matches!(b, b' ' | SHIFTED_SPACE | 0))
        .map_or(0, |last| last + 1);
    petscii_text(&bytes[..end])
}

/// Defects below the top-level structure, reported as notes: the first
/// [`MAX_PROBLEM_NOTES`] in full, the rest counted.
#[derive(Default)]
struct Problems {
    notes: Vec<String>,
    unlisted: usize,
}

impl Problems {
    fn push(&mut self, note: String) {
        if self.notes.len() < MAX_PROBLEM_NOTES {
            self.notes.push(note);
        } else {
            self.unlisted += 1;
        }
    }

    fn append_to(self, notes: &mut Vec<String>) {
        notes.extend(self.notes);
        if self.unlisted > 0 {
            notes.push(format!(
                "{} further problems were not listed",
                self.unlisted
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn petscii_names_end_at_the_shifted_space_and_escape_the_rest() {
        assert_eq!(padded_name(b"GAME 1\xa0\xa0\xa0"), "GAME 1");
        assert_eq!(padded_name(b"A\xa0B"), "A");
        assert_eq!(padded_name(b"\x93\"\\Z"), "\\x93\\x22\\x5CZ");
        assert_eq!(padded_name(b"[]^_\xc1"), "[]\\x5E\\x5F\\xC1");
    }

    #[test]
    fn tape_text_trims_every_padding() {
        assert_eq!(tape_text(b"DEMO TAPE   \xa0\0"), "DEMO TAPE");
        assert_eq!(tape_text(b"    "), "");
    }

    #[test]
    fn file_types_use_the_low_four_bits() {
        assert_eq!(FileType::of(0x82), FileType::Prg);
        assert_eq!(FileType::of(0xc1), FileType::Seq);
        assert_eq!(FileType::of(0x80), FileType::Del);
        assert_eq!(FileType::of(0x85), FileType::Partition);
        assert_eq!(FileType::of(0x8f), FileType::Other(15));
        assert_eq!(FileType::Other(7).name(), "type 7");
    }

    #[test]
    fn problems_are_capped() {
        let mut problems = Problems::default();
        for i in 0..MAX_PROBLEM_NOTES + 3 {
            problems.push(format!("problem {i}"));
        }
        let mut notes = Vec::new();
        problems.append_to(&mut notes);
        assert_eq!(notes.len(), MAX_PROBLEM_NOTES + 1);
        assert_eq!(
            notes[MAX_PROBLEM_NOTES],
            "3 further problems were not listed"
        );
    }
}
