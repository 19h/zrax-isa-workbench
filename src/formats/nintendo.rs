//! Nintendo console ROM images: Nintendo DS / `DSi` cartridges, Game Boy
//! Advance cartridges, Game Boy / Game Boy Color cartridges, iNES and NES
//! 2.0 images, SNES ROMs with an internal header, and Nintendo 64 ROMs in
//! their three dump byte orders.
//!
//! Primary sources, by layout (revisions are pinned in
//! `docs/nintendo-roms.md`):
//! - Nintendo DS / `DSi`: GBATEK "DS Cartridge Header", "`DSi` Cartridge
//!   Header", "DS Cartridge Secure Area" and "DS Technical Data"
//!   (<https://problemkaputt.de/gbatek.htm>, fetched 2026-10-12, SHA-256
//!   `919ca0de…53121c8`); devkitPro ndstool `source/header.cpp` at
//!   `76e8b681bb225d945a48852821e03114e6c7ce1c` (`CalcHeaderCRC`,
//!   `CalcLogoCRC`, `DetectRomType`). See [`nds`].
//! - Game Boy Advance: GBATEK "GBA Cartridge Header"; devkitPro gba-tools
//!   `src/gbafix.c` at `054d507f90d32784274b6cf7e03f1c43d02d7a57` (logo
//!   bytes, `HeaderComplement`). See [`gba`].
//! - Game Boy / Color: Pan Docs "The Cartridge Header", gbdev/pandocs
//!   `src/The_Cartridge_Header.md` at
//!   `4b31c4ba0bccc94080b80216287d14519d18e160`. See [`gb`].
//! - NES: `NESdev` Wiki "iNES" (oldid 23194), "NES 2.0" (oldid 24342) and
//!   "CPU" (oldid 24046). See [`nes`].
//! - SNES: `SNESdev` Wiki "ROM header" (oldid 1456) and "ROM file formats"
//!   (oldid 858); bsnes `bsnes/heuristics/super-famicom.cpp` at
//!   `78474e5d39f58872dc21aca18cf9eb583b147fe7`. See [`snes`].
//! - Nintendo 64: N64brew Wiki "ROM Header" (oldid 5925) and "VR4300"
//!   (oldid 5928); mupen64plus-core `src/main/rom.c` at
//!   `ba95bab92a76744753bfe61470823a4937850ab0` (byte orders);
//!   pmret/papermario `tools/n64crc.c` at
//!   `adaf3e6e730025fb6f5ddf07cc5147426c2025d6` (CIC identification and
//!   check code). See [`n64`].
//!
//! None of these headers has a CPU field. Each platform fixes its CPU, so
//! the platform is the explicit target, as an XBE names x86: ARM946E-S and
//! ARM7TDMI (DS), ARM7TDMI (GBA), the Sharp SM83 (Game Boy), a Ricoh 6502
//! without decimal mode (NES), the Ricoh 5A22 65C816 (SNES) and the VR4300
//! (N64). Data the CPU never executes (NES CHR ROM, encrypted DS areas) is
//! listed as opaque.

use crate::error::{ClassifierError, Result};
use crate::formats::checksum;
use crate::formats::container::{Child, Container, Section, Target};
use crate::types::{Endianness, FileFormat, Isa};
use std::borrow::Cow;
use std::ops::Range;

mod gb;
mod gba;
mod n64;
mod nds;
mod nes;
mod snes;

/// The 156-byte Nintendo logo of the GBA header (file 0x004) and the DS
/// header (file 0x0C0), from gbafix.c `good_header.logo`. Its
/// CRC-16/MODBUS is the DS logo checksum 0xCF56.
#[rustfmt::skip]
const NINTENDO_LOGO: [u8; 156] = [
    0x24, 0xFF, 0xAE, 0x51, 0x69, 0x9A, 0xA2, 0x21, 0x3D, 0x84, 0x82, 0x0A, 0x84, 0xE4, 0x09, 0xAD,
    0x11, 0x24, 0x8B, 0x98, 0xC0, 0x81, 0x7F, 0x21, 0xA3, 0x52, 0xBE, 0x19, 0x93, 0x09, 0xCE, 0x20,
    0x10, 0x46, 0x4A, 0x4A, 0xF8, 0x27, 0x31, 0xEC, 0x58, 0xC7, 0xE8, 0x33, 0x82, 0xE3, 0xCE, 0xBF,
    0x85, 0xF4, 0xDF, 0x94, 0xCE, 0x4B, 0x09, 0xC1, 0x94, 0x56, 0x8A, 0xC0, 0x13, 0x72, 0xA7, 0xFC,
    0x9F, 0x84, 0x4D, 0x73, 0xA3, 0xCA, 0x9A, 0x61, 0x58, 0x97, 0xA3, 0x27, 0xFC, 0x03, 0x98, 0x76,
    0x23, 0x1D, 0xC7, 0x61, 0x03, 0x04, 0xAE, 0x56, 0xBF, 0x38, 0x84, 0x00, 0x40, 0xA7, 0x0E, 0xFD,
    0xFF, 0x52, 0xFE, 0x03, 0x6F, 0x95, 0x30, 0xF1, 0x97, 0xFB, 0xC0, 0x85, 0x60, 0xD6, 0x80, 0x25,
    0xA9, 0x63, 0xBE, 0x03, 0x01, 0x4E, 0x38, 0xE2, 0xF9, 0xA2, 0x34, 0xFF, 0xBB, 0x3E, 0x03, 0x44,
    0x78, 0x00, 0x90, 0xCB, 0x88, 0x11, 0x3A, 0x94, 0x65, 0xC0, 0x7C, 0x63, 0x87, 0xF0, 0x3C, 0xAF,
    0xD6, 0x25, 0xE4, 0x8B, 0x38, 0x0A, 0xAC, 0x72, 0x21, 0xD4, 0xF8, 0x07,
];

/// 32-bit Arm code, little-endian: both DS cores and the GBA core.
const ARM_LITTLE: Target = Target::new(Isa::Arm, 32, Endianness::Little);

/// The DS ARM9 core (GBATEK "DS Technical Data").
const ARM946E_S: &str = "ARMv5TE (ARM946E-S)";

/// The DS ARM7 core and the GBA CPU (GBATEK).
const ARM7TDMI: &str = "ARMv4T (ARM7TDMI)";

/// JIS X 0201 katakana, which SNES and N64 titles may use (N64brew "ROM
/// Header"). Unicode maps 0xA1-0xDF to the half-width forms U+FF61-U+FF9F
/// (from the Unicode JIS X 0201 mapping, not the cited console sources).
const KATAKANA: Range<u8> = 0xA1..0xE0;
const HALFWIDTH_KATAKANA: u32 = 0xFF61;

/// How a SNES ROM maps its internal header (`SNESdev` Wiki "ROM header",
/// "Header location").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnesMapping {
    /// Header at ROM offset 0x7FC0 (bank 0x00 maps ROM 0x0000-0x7FFF at
    /// CPU 0x8000).
    LoRom,
    /// Header at ROM offset 0xFFC0.
    HiRom,
    /// Header at ROM offset 0x40FFC0.
    ExHiRom,
}

/// Byte order of a Nintendo 64 ROM dump (mupen64plus-core `rom.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N64ByteOrder {
    /// Native big-endian order (`.z64`, first bytes `80 37 12 40`).
    Native,
    /// Bytes swapped within each 16-bit halfword (`.v64`, `37 80 40 12`).
    ByteSwapped,
    /// Bytes reversed within each 32-bit word (`.n64`, `40 12 37 80`).
    WordSwapped,
}

/// A recognized Nintendo ROM layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Nintendo DS or `DSi` cartridge image (`.nds`).
    Nds,
    /// Game Boy Advance cartridge or multiboot image (`.gba`, `.mb`).
    Gba,
    /// Game Boy cartridge without a CGB flag (`.gb`).
    Gb,
    /// Game Boy Color cartridge: CGB flag 0x80 or 0xC0 (`.gbc`).
    Gbc,
    /// iNES header, including archaic iNES and iNES 0.7 (`.nes`).
    Ines,
    /// NES 2.0 header (`.nes`).
    Nes20,
    /// SNES ROM whose internal header validates at exactly one location.
    Snes {
        /// Where the header is.
        mapping: SnesMapping,
        /// A 512-byte copier header precedes the ROM.
        copier_header: bool,
    },
    /// SNES ROM whose internal header validates at more than one location;
    /// the mapping is not determined and nothing is analyzed.
    SnesAmbiguous,
    /// Nintendo 64 ROM (`.z64`, `.v64`, `.n64`).
    N64(N64ByteOrder),
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Nds => FileFormat::NdsRom,
            Self::Gba => FileFormat::GbaRom,
            Self::Gb | Self::Gbc => FileFormat::GbRom,
            Self::Ines | Self::Nes20 => FileFormat::NesRom,
            Self::Snes { .. } | Self::SnesAmbiguous => FileFormat::SnesRom,
            Self::N64(_) => FileFormat::N64Rom,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Nds => "Nintendo DS cartridge",
            Self::Gba => "Game Boy Advance cartridge",
            Self::Gb => "Game Boy cartridge",
            Self::Gbc => "Game Boy Color cartridge",
            Self::Ines => "iNES",
            Self::Nes20 => "NES 2.0",
            Self::Snes {
                mapping: SnesMapping::LoRom,
                copier_header: false,
            } => "SNES LoROM",
            Self::Snes {
                mapping: SnesMapping::LoRom,
                copier_header: true,
            } => "SNES LoROM with copier header",
            Self::Snes {
                mapping: SnesMapping::HiRom,
                copier_header: false,
            } => "SNES HiROM",
            Self::Snes {
                mapping: SnesMapping::HiRom,
                copier_header: true,
            } => "SNES HiROM with copier header",
            Self::Snes {
                mapping: SnesMapping::ExHiRom,
                copier_header: false,
            } => "SNES ExHiROM",
            Self::Snes {
                mapping: SnesMapping::ExHiRom,
                copier_header: true,
            } => "SNES ExHiROM with copier header",
            Self::SnesAmbiguous => "SNES (ambiguous internal header)",
            Self::N64(N64ByteOrder::Native) => "N64 native byte order (.z64)",
            Self::N64(N64ByteOrder::ByteSwapped) => "N64 byte-swapped (.v64)",
            Self::N64(N64ByteOrder::WordSwapped) => "N64 word-swapped (.n64)",
        }
    }

    /// Recognized from complete structure rather than a magic value: the
    /// SNES header has no magic.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::Snes { .. } | Self::SnesAmbiguous)
    }
}

/// Recognize a magic-bearing Nintendo layout: the iNES and N64 first
/// words, or the DS, GBA and Game Boy headers by their logo and checksum
/// fields. A broken image with these anchors is still recognized, so its
/// parse error is reported.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if let Some(layout) = nes::detect(data) {
        return Some(layout);
    }
    if let Some(order) = n64::detect(data) {
        return Some(Layout::N64(order));
    }
    if nds::detect(data) {
        return Some(Layout::Nds);
    }
    if gba::detect(data) {
        return Some(Layout::Gba);
    }
    gb::detect(data)
}

/// Recognize a SNES ROM from a complete internal header: checksum and
/// complement, map mode matching the location, title and reset vector.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    snes::detect(data)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::NintendoRomParseError`] for a truncated header, a
/// checksum that does not match, or a code area outside the file or the
/// platform's memory.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Nds => nds::parse(data),
        Layout::Gba => gba::parse(data),
        Layout::Gb | Layout::Gbc => gb::parse(data),
        Layout::Ines | Layout::Nes20 => nes::parse(data, layout),
        Layout::Snes {
            mapping,
            copier_header,
        } => snes::parse(
            data,
            snes::Location {
                mapping,
                copier_header,
            },
        ),
        Layout::SnesAmbiguous => snes::parse_ambiguous(data),
        Layout::N64(order) => n64::parse(data, order),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::NintendoRomParseError {
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

/// The `N` header bytes at `at`.
fn field<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    let bytes = range(data, "header", at, N)?;
    Ok(bytes.try_into().expect("range returns exactly N bytes"))
}

fn byte(data: &[u8], at: usize) -> Result<u8> {
    Ok(field::<1>(data, at)?[0])
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(field(data, at)?))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(field(data, at)?))
}

fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(field(data, at)?))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(field(data, at)?))
}

/// A 32-bit file offset or size field as `usize`.
fn le_usize(data: &[u8], at: usize) -> Result<usize> {
    let value = le_u32(data, at)?;
    usize::try_from(value).map_err(|_| error(format!("Unsupported offset 0x{value:X} at 0x{at:X}")))
}

/// Header text: printable ASCII, and JIS X 0201 katakana as half-width
/// forms; other bytes become U+FFFD. Trailing spaces and NULs are removed.
fn header_text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |last| last + 1);
    bytes[..end]
        .iter()
        .map(|&b| match b {
            0x20..=0x7E => char::from(b),
            b if KATAKANA.contains(&b) => {
                char::from_u32(HALFWIDTH_KATAKANA + u32::from(b - KATAKANA.start))
                    .expect("U+FF61-U+FF9F are characters")
            }
            _ => char::REPLACEMENT_CHARACTER,
        })
        .collect()
}

/// A size in `B`, `KiB` or `MiB`, whichever divides it.
fn size_text(size: u64) -> String {
    const KIB: u64 = 1 << 10;
    const MIB: u64 = 1 << 20;
    if size >= MIB && size % MIB == 0 {
        format!("{} MiB", size / MIB)
    } else if size >= KIB && size % KIB == 0 {
        format!("{} KiB", size / KIB)
    } else {
        format!("{size} B")
    }
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xFF))
}

/// A load section with its own label, stored as-is or after `transform`.
fn section<'a>(
    label: &str,
    address: u64,
    offset: usize,
    data: Cow<'a, [u8]>,
    transform: Option<&'static str>,
) -> Section<'a> {
    Section {
        label: label.to_string(),
        address,
        offset,
        stored_size: data.len(),
        data,
        transform,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logo_crc_is_the_ds_logo_checksum() {
        assert_eq!(checksum::crc16_modbus(&NINTENDO_LOGO), 0xCF56);
    }

    #[test]
    fn header_text_trims_padding_and_maps_katakana() {
        assert_eq!(header_text(b"ZELDA   \0\0"), "ZELDA");
        assert_eq!(header_text(&[0xB1, 0xB2, b' ']), "\u{FF71}\u{FF72}");
        assert_eq!(header_text(&[0x01, b'A']), "\u{FFFD}A");
        assert_eq!(header_text(b"    "), "");
    }

    #[test]
    fn sizes_use_binary_units() {
        assert_eq!(size_text(16 << 10), "16 KiB");
        assert_eq!(size_text(4 << 20), "4 MiB");
        assert_eq!(size_text(1536 << 10), "1536 KiB");
        assert_eq!(size_text(300), "300 B");
    }

    #[test]
    fn only_snes_layouts_are_weak() {
        assert!(Layout::SnesAmbiguous.is_weak());
        assert!(!Layout::N64(N64ByteOrder::Native).is_weak());
        assert_eq!(Layout::Gbc.format(), FileFormat::GbRom);
    }
}
