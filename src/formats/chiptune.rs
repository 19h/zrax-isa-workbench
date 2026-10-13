//! Chiptune program files: the music driver is machine code for the
//! platform's CPU, loaded at an address the header gives.
//!
//! - NSF and `NSFe` (NES Sound Format): `NESdev` wiki "NSF" and "`NSFe`" pages
//!   (header `NESM\x1A`, 128 bytes, little-endian; `NSFe` chunks `INFO`,
//!   `DATA`, `NEND`). CPU: the NES's Ricoh 2A03, a 6502 without decimal mode.
//! - PSID and RSID (Commodore 64 SID tunes): HVSC "SID file format
//!   description" (`SID_file_format.txt`, versions 1-4; header big-endian).
//!   CPU: MOS 6510, a 6502 with an I/O port. RSID files flagged as C64
//!   BASIC and PSID files flagged as MUS data hold no machine code.
//! - GBS (Game Boy Sound System): `gbsformat.txt` by Scott Worley (2001),
//!   header `GBS`, version 1, 0x70 bytes, little-endian. CPU: the Game Boy's
//!   Sharp SM83, modelled by the code model as a Z80-family variant.
//! - PSF family (`PSF` plus a platform version byte): see [`psf`] and
//!   [`psf2`]. Neill Corlett, "PSF specification v1.6" (16 March 2006), and
//!   the per-platform documents for USF, GSF, SNSF, 2SF and NCSF.
//! - HES (PC Engine): Mamiya, "HES Music Format Spec V1.00"; see [`hes`].
//! - KSS (MSX, Sega Master System and Game Gear): Mamiya, "KSS Music Format
//!   Spec V1.03", and libkss `kssxspec.md` for `KSSX`; see [`kss`].
//! - SAP (Atari 8-bit): the ASAP project's "SAP file format
//!   specification"; see [`sap`].
//! - AY (`ZXAYEMUL`, ZX Spectrum and Amstrad CPC): the AY-3-8910/12
//!   Emulator's "AY" format description by Sergey Bulba; see [`ay`].
//! - SNDH (Atari ST) and Pack-Ice (`ICE!`) packed files: "SNDH file
//!   structure, Revision 2.2"; see [`sndh`].
//!
//! Source revisions are pinned in `docs/chiptune.md` and
//! `docs/chiptune-sound-programs.md`. The file format names
//! the platform, and with it the CPU, so the target is explicit, as for SNES
//! SPC files. The PSF version byte is such a platform field; PSF2 and NCSF
//! name no CPU and leave the ISA to their members.

use crate::error::{ClassifierError, Result};
use crate::formats::checksum;
use crate::formats::compressed::{self, Codec};
use crate::formats::container::{self, Child, Container, Section, Target};
use crate::formats::MAX_PAYLOAD;
use crate::types::{Endianness, FileFormat, Isa};
use std::borrow::Cow;

mod ay;
mod hes;
mod kss;
mod psf;
mod psf2;
mod sap;
mod sndh;

/// NSF header magic and size.
const NSF_MAGIC: &[u8; 5] = b"NESM\x1a";
const NSF_HEADER_SIZE: usize = 0x80;

/// NSF fields (little-endian).
const NSF_VERSION: usize = 0x05;
const NSF_SONGS: usize = 0x06;
const NSF_START_SONG: usize = 0x07;
const NSF_LOAD: usize = 0x08;
const NSF_INIT: usize = 0x0a;
const NSF_PLAY: usize = 0x0c;
const NSF_TITLE: usize = 0x0e;
const NSF_ARTIST: usize = 0x2e;
const NSF_BANKS: usize = 0x70;
const NSF2_PROGRAM_LENGTH: usize = 0x7d;

/// NSF programs load into cartridge space; FDS tunes from `$6000`.
const NSF_LOWEST_LOAD: u16 = 0x6000;

/// `NSFe` chunk stream magic and the chunk IDs read here.
const NSFE_MAGIC: &[u8; 4] = b"NSFE";
const NSFE_INFO: &[u8; 4] = b"INFO";
const NSFE_DATA: &[u8; 4] = b"DATA";
const NSFE_BANK: &[u8; 4] = b"BANK";
const NSFE_END: &[u8; 4] = b"NEND";
const NSFE_AUTH: &[u8; 4] = b"auth";

/// `NSFe` `INFO`: load, init and play addresses, region, chips, songs, start.
const NSFE_INFO_MIN: usize = 9;

/// PSID/RSID magics, header fields (big-endian) and flags.
const PSID_MAGIC: &[u8; 4] = b"PSID";
const RSID_MAGIC: &[u8; 4] = b"RSID";
const SID_VERSION: usize = 0x04;
const SID_DATA_OFFSET: usize = 0x06;
const SID_LOAD: usize = 0x08;
const SID_INIT: usize = 0x0a;
const SID_PLAY: usize = 0x0c;
const SID_SONGS: usize = 0x0e;
const SID_START_SONG: usize = 0x10;
const SID_NAME: usize = 0x16;
const SID_AUTHOR: usize = 0x36;
const SID_FLAGS: usize = 0x76;
const SID_V1_DATA_OFFSET: u16 = 0x76;
const SID_V2_DATA_OFFSET: u16 = 0x7c;
const SID_MAX_SONGS: u16 = 256;
const SID_FLAG_MUS: u16 = 0x0001;
const SID_FLAG_BASIC: u16 = 0x0002;

/// GBS header magic, version, fields (little-endian) and size.
const GBS_MAGIC: &[u8; 3] = b"GBS";
const GBS_VERSION: u8 = 1;
const GBS_SONGS: usize = 0x04;
const GBS_FIRST_SONG: usize = 0x05;
const GBS_LOAD: usize = 0x06;
const GBS_INIT: usize = 0x08;
const GBS_PLAY: usize = 0x0a;
const GBS_TITLE: usize = 0x10;
const GBS_AUTHOR: usize = 0x30;
const GBS_HEADER_SIZE: usize = 0x70;

/// GBS code loads into cartridge ROM, `$0400`-`$7FFF`.
const GBS_LOWEST_LOAD: u16 = 0x0400;
const GBS_HIGHEST_LOAD: u16 = 0x7fff;

/// Header text fields are 32 bytes, NUL-padded.
const TEXT_FIELD: usize = 32;

/// A recognized chiptune layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// NES Sound Format, fixed header.
    Nsf,
    /// NES Sound Format, extended chunk stream.
    Nsfe,
    /// Commodore 64 PSID or RSID tune.
    Sid,
    /// Game Boy Sound System tune.
    Gbs,
    /// Portable Sound Format file for the platform its version byte names.
    Psf(PsfPlatform),
    /// PC Engine HES tune (`HESM`).
    Hes,
    /// KSS tune with the original `KSCC` header.
    Kss,
    /// KSS tune with the extended `KSSX` header.
    Kssx,
    /// Atari 8-bit SAP tune.
    Sap,
    /// ZX Spectrum or Amstrad CPC AY tune of type `EMUL` (`ZXAYEMUL`).
    Ay,
    /// Atari ST SNDH tune.
    Sndh,
    /// Pack-Ice (`ICE!`) packed file.
    PackIce,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Nsf | Self::Nsfe => FileFormat::Nsf,
            Self::Sid => FileFormat::Sid,
            Self::Gbs => FileFormat::Gbs,
            Self::Psf(_) => FileFormat::Psf,
            Self::Hes => FileFormat::Hes,
            Self::Kss | Self::Kssx => FileFormat::Kss,
            Self::Sap => FileFormat::Sap,
            Self::Ay => FileFormat::AyTune,
            Self::Sndh => FileFormat::Sndh,
            Self::PackIce => FileFormat::PackIce,
        }
    }

    /// Human-readable layout name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Nsf => "NES Sound Format",
            Self::Nsfe => "NES Sound Format (NSFe)",
            Self::Sid => "Commodore 64 SID tune",
            Self::Gbs => "Game Boy Sound System",
            Self::Psf(platform) => platform.label(),
            Self::Hes => "PC Engine HES (HuC6280)",
            Self::Kss => "KSS (KSCC header)",
            Self::Kssx => "KSS (KSSX header)",
            Self::Sap => "Atari 8-bit SAP",
            Self::Ay => "AY (ZXAYEMUL)",
            Self::Sndh => "Atari ST SNDH",
            Self::PackIce => "Pack-Ice packed file",
        }
    }

    /// Every layout carries a magic and is validated before recognition.
    pub fn is_weak(self) -> bool {
        false
    }
}

/// The platform a PSF version byte names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsfPlatform {
    /// 0x01: `PlayStation` (PSF1).
    PlayStation,
    /// 0x02: `PlayStation` 2 (PSF2).
    PlayStation2,
    /// 0x11: Sega Saturn (SSF).
    Saturn,
    /// 0x12: Sega Dreamcast (DSF).
    Dreamcast,
    /// 0x13: Sega Genesis, reserved without a published layout.
    Genesis,
    /// 0x21: Nintendo 64 (USF).
    Nintendo64,
    /// 0x22: Game Boy Advance (GSF).
    GameBoyAdvance,
    /// 0x23: Super NES (SNSF).
    SuperNes,
    /// 0x24: Nintendo DS (2SF).
    NintendoDs,
    /// 0x25: Nintendo DS Nitro Composer sound data (NCSF).
    NitroComposer,
    /// 0x41: Capcom `QSound` (QSF).
    QSound,
}

/// PSF version bytes: PSF v1.6 "Basic File Structure" (0x01, 0x02, 0x11,
/// 0x12, 0x21, 0x22, 0x41), the PSF wiki's live specification (0x13,
/// 0x23), the 2SF specification (0x24) and the NCSF specification (0x25).
const PSF_VERSIONS: [(u8, PsfPlatform, &str); 11] = [
    (0x01, PsfPlatform::PlayStation, "PSF1 (PlayStation)"),
    (0x02, PsfPlatform::PlayStation2, "PSF2 (PlayStation 2)"),
    (0x11, PsfPlatform::Saturn, "SSF (Sega Saturn)"),
    (0x12, PsfPlatform::Dreamcast, "DSF (Sega Dreamcast)"),
    (0x13, PsfPlatform::Genesis, "PSF (Sega Genesis)"),
    (0x21, PsfPlatform::Nintendo64, "USF (Nintendo 64)"),
    (0x22, PsfPlatform::GameBoyAdvance, "GSF (Game Boy Advance)"),
    (0x23, PsfPlatform::SuperNes, "SNSF (Super NES)"),
    (0x24, PsfPlatform::NintendoDs, "2SF (Nintendo DS)"),
    (
        0x25,
        PsfPlatform::NitroComposer,
        "NCSF (Nintendo DS sound data)",
    ),
    (0x41, PsfPlatform::QSound, "QSF (Capcom QSound)"),
];

impl PsfPlatform {
    /// The platform a version byte names, if the byte is assigned.
    pub fn from_version(version: u8) -> Option<Self> {
        PSF_VERSIONS
            .iter()
            .find(|(byte, _, _)| *byte == version)
            .map(|(_, platform, _)| *platform)
    }

    /// The version byte.
    pub fn version(self) -> u8 {
        PSF_VERSIONS
            .iter()
            .find(|(_, platform, _)| *platform == self)
            .map_or(0, |(byte, _, _)| *byte)
    }

    /// Layout name, reported as the classification variant.
    pub fn label(self) -> &'static str {
        PSF_VERSIONS
            .iter()
            .find(|(_, platform, _)| *platform == self)
            .map_or("PSF", |(_, _, label)| label)
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::ChiptuneParseError {
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

fn byte(data: &[u8], at: usize) -> Result<u8> {
    Ok(slice(data, at, 1)?[0])
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes = slice(data, at, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes = slice(data, at, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes = slice(data, at, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes = slice(data, at, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Text of at most `limit` characters from untrusted bytes, for notes.
fn bounded_text(bytes: &[u8], limit: usize) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .take(limit)
        .collect::<String>()
        .trim()
        .to_string()
}

/// A section of `data` loaded at `address`, stored at `offset`.
fn borrowed_section(label: String, address: u64, offset: usize, data: &[u8]) -> Section<'_> {
    Section {
        label,
        address,
        offset,
        stored_size: data.len(),
        data: Cow::Borrowed(data),
        transform: None,
    }
}

/// A NUL-padded header text field.
fn text(data: &[u8], at: usize) -> String {
    let field = data.get(at..at + TEXT_FIELD).unwrap_or_default();
    let len = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..len]).trim().to_string()
}

/// The 6502 of the NES, an 8-bit little-endian CPU.
const NES_CPU: Target = Target::new(Isa::Mcs6502, 8, Endianness::Little);

/// The 6510 of the Commodore 64.
const C64_CPU: Target = Target::new(Isa::Mcs6502, 8, Endianness::Little);

/// The SM83 of the Game Boy, a Z80-family CPU.
const GAME_BOY_CPU: Target = Target::new(Isa::Z80, 8, Endianness::Little);

/// Strong recognition: a magic plus consistent header fields.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let layout = if data.starts_with(NSF_MAGIC) {
        Layout::Nsf
    } else if data.starts_with(NSFE_MAGIC) {
        Layout::Nsfe
    } else if data.starts_with(PSID_MAGIC) || data.starts_with(RSID_MAGIC) {
        Layout::Sid
    } else if data.starts_with(GBS_MAGIC) && data.get(3) == Some(&GBS_VERSION) {
        Layout::Gbs
    } else {
        return detect_magic(data);
    };
    parse_container(data, layout).is_ok().then_some(layout)
}

/// The layouts added after NSF, SID and GBS are recognized from their magic,
/// so a corrupt file is reported as a parse error instead of raw code:
/// `PSF` and an assigned version byte (with areas that fit the file),
/// `HESM`, `KSCC` or `KSSX`, `SAP` and CR/LF (then a defined tag),
/// `ZXAYEMUL`, `SNDH` at offset 12 (then a header tag) and `ICE!`.
fn detect_magic(data: &[u8]) -> Option<Layout> {
    if let Some(platform) = psf::detect(data) {
        Some(Layout::Psf(platform))
    } else if hes::detect(data) {
        Some(Layout::Hes)
    } else if let Some(layout) = kss::detect(data) {
        Some(layout)
    } else if sap::detect(data) {
        Some(Layout::Sap)
    } else if ay::detect(data) {
        Some(Layout::Ay)
    } else if sndh::detect(data) {
        Some(Layout::Sndh)
    } else if sndh::detect_pack_ice(data) {
        Some(Layout::PackIce)
    } else {
        None
    }
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::ChiptuneParseError`] for a truncated header, song
/// numbers or addresses outside their ranges, or a missing program; for
/// PSF files also a CRC-32 mismatch or a program that does not decode.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Nsf => nsf(data),
        Layout::Nsfe => nsfe(data),
        Layout::Sid => sid(data),
        Layout::Gbs => gbs(data),
        Layout::Psf(platform) => psf::parse(data, platform),
        Layout::Hes => hes::parse(data),
        Layout::Kss | Layout::Kssx => kss::parse(data, layout),
        Layout::Sap => sap::parse(data),
        Layout::Ay => ay::parse(data),
        Layout::Sndh => sndh::parse(data),
        Layout::PackIce => sndh::parse_pack_ice(data),
    }
}

/// A container with one code section at `load`.
fn program(layout: Layout, target: Target, load: u16, offset: usize, code: &[u8]) -> Container<'_> {
    let mut c = Container::new(layout.format(), layout.label(), "chiptune");
    c.target = Some(target);
    c.consumed = offset + code.len();
    c.push_section(u64::from(load), offset, Cow::Borrowed(code));
    if let Some(section) = c.sections.last_mut() {
        section.label = "Program".into();
    }
    c.code_sections = true;
    c
}

fn check_songs(songs: u16, start: u16) -> Result<()> {
    if songs == 0 || start == 0 || start > songs {
        return Err(error(format!(
            "Invalid song numbers: start song {start} of {songs}"
        )));
    }
    Ok(())
}

/// NSF: fixed header, then program data from `$load`. Version 2 headers
/// may give the program length; trailing `NSFe`-style metadata is noted.
fn nsf(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, NSF_HEADER_SIZE)?;
    if !header.starts_with(NSF_MAGIC) {
        return Err(error("Missing NSF magic"));
    }
    let version = header[NSF_VERSION];
    check_songs(
        u16::from(header[NSF_SONGS]),
        u16::from(header[NSF_START_SONG]),
    )?;
    let load = le_u16(header, NSF_LOAD)?;
    let init = le_u16(header, NSF_INIT)?;
    let play = le_u16(header, NSF_PLAY)?;
    if version == 0 || load < NSF_LOWEST_LOAD || init < NSF_LOWEST_LOAD || play < NSF_LOWEST_LOAD {
        return Err(error(format!(
            "Invalid NSF header: version {version}, load 0x{load:04X}, init 0x{init:04X}, play 0x{play:04X}"
        )));
    }
    let declared = if version >= 2 {
        let bytes = slice(header, NSF2_PROGRAM_LENGTH, 3)?;
        usize::from(bytes[0]) | usize::from(bytes[1]) << 8 | usize::from(bytes[2]) << 16
    } else {
        0
    };
    let available = data.len() - NSF_HEADER_SIZE;
    let length = if declared == 0 { available } else { declared };
    let code = slice(data, NSF_HEADER_SIZE, length)?;
    if code.is_empty() {
        return Err(error("Missing NSF program data"));
    }
    let mut c = program(Layout::Nsf, NES_CPU, load, NSF_HEADER_SIZE, code);
    c.entry = Some(u64::from(init));
    c.notes.push(format!(
        "NSF version {version}: {} by {}; {} songs",
        text(header, NSF_TITLE),
        text(header, NSF_ARTIST),
        header[NSF_SONGS]
    ));
    c.notes.push(format!(
        "Ricoh 2A03 (6502 without decimal mode) driver loaded at 0x{load:04X}; init 0x{init:04X}, play 0x{play:04X}"
    ));
    if header[NSF_BANKS..NSF_BANKS + 8].iter().any(|b| *b != 0) {
        c.notes
            .push("Bank-switched: the program is mapped in 4 KiB banks".into());
    }
    if declared != 0 && declared < available {
        c.notes.push(format!(
            "{} B of NSF2 metadata follow the program",
            available - declared
        ));
    }
    Ok(c)
}

/// `NSFe`: `NSFE`, then chunks of a little-endian length, a four-character
/// ID and data, ending with `NEND`. `INFO` and `DATA` are required; an
/// unknown chunk whose ID starts with an uppercase letter must be
/// understood, so it is an error.
fn nsfe(data: &[u8]) -> Result<Container<'_>> {
    if !data.starts_with(NSFE_MAGIC) {
        return Err(error("Missing NSFe magic"));
    }
    let mut pos = NSFE_MAGIC.len();
    let mut info = None;
    let mut program_at = None;
    let mut banked = false;
    let mut author = None;
    loop {
        let len = le_u32(data, pos)? as usize;
        let id = slice(data, pos + 4, 4)?;
        let body_at = pos + 8;
        let body = slice(data, body_at, len)?;
        match id {
            _ if id == NSFE_END => break,
            _ if id == NSFE_INFO => {
                if body.len() < NSFE_INFO_MIN {
                    return Err(error("Truncated NSFe INFO chunk"));
                }
                info = Some(body);
            }
            _ if id == NSFE_DATA => program_at = Some((body_at, body)),
            _ if id == NSFE_BANK => banked = true,
            _ if id == NSFE_AUTH => {
                author = Some(String::from_utf8_lossy(body).replace('\0', "; "));
            }
            _ if id[0].is_ascii_uppercase() => {
                return Err(error(format!(
                    "Unsupported required NSFe chunk {} at 0x{pos:X}",
                    String::from_utf8_lossy(id)
                )));
            }
            _ => {}
        }
        pos = body_at + len;
    }
    let info = info.ok_or_else(|| error("Missing NSFe INFO chunk"))?;
    let (offset, code) = program_at.ok_or_else(|| error("Missing NSFe DATA chunk"))?;
    if code.is_empty() {
        return Err(error("Missing NSFe program data"));
    }
    let load = le_u16(info, 0)?;
    let init = le_u16(info, 2)?;
    let play = le_u16(info, 4)?;
    if load < NSF_LOWEST_LOAD || init < NSF_LOWEST_LOAD || play < NSF_LOWEST_LOAD {
        return Err(error(format!(
            "Invalid NSFe INFO addresses: load 0x{load:04X}, init 0x{init:04X}, play 0x{play:04X}"
        )));
    }
    let mut c = program(Layout::Nsfe, NES_CPU, load, offset, code);
    c.consumed = pos + 8;
    c.entry = Some(u64::from(init));
    c.notes.push(format!(
        "NSFe: Ricoh 2A03 (6502 without decimal mode) driver loaded at 0x{load:04X}; init 0x{init:04X}, play 0x{play:04X}"
    ));
    if let Some(author) = author {
        c.notes.push(format!("Credits: {author}"));
    }
    if banked {
        c.notes
            .push("Bank-switched: the program is mapped in 4 KiB banks".into());
    }
    Ok(c)
}

/// PSID/RSID: big-endian header, then the C64 program at `dataOffset`; a
/// zero load address means the program's first two bytes give it
/// (little-endian, as in a C64 PRG file).
fn sid(data: &[u8]) -> Result<Container<'_>> {
    let rsid = data.starts_with(RSID_MAGIC);
    if !rsid && !data.starts_with(PSID_MAGIC) {
        return Err(error("Missing PSID/RSID magic"));
    }
    let version = be_u16(data, SID_VERSION)?;
    let data_offset = be_u16(data, SID_DATA_OFFSET)?;
    let expected_offset = if version == 1 {
        SID_V1_DATA_OFFSET
    } else {
        SID_V2_DATA_OFFSET
    };
    if !(1..=4).contains(&version) || (rsid && version == 1) || data_offset != expected_offset {
        return Err(error(format!(
            "Invalid SID header: version {version}, data offset 0x{data_offset:X}"
        )));
    }
    let songs = be_u16(data, SID_SONGS)?;
    if songs > SID_MAX_SONGS {
        return Err(error(format!("Invalid SID song count {songs}")));
    }
    check_songs(songs, be_u16(data, SID_START_SONG)?)?;
    let flags = if version >= 2 {
        be_u16(data, SID_FLAGS)?
    } else {
        0
    };
    let init = be_u16(data, SID_INIT)?;
    let play = be_u16(data, SID_PLAY)?;
    let mut offset = usize::from(data_offset);
    let mut load = be_u16(data, SID_LOAD)?;
    if load == 0 {
        load = le_u16(data, offset)?;
        offset += 2;
    } else if rsid {
        return Err(error(
            "Invalid RSID header: the load address must be in the data",
        ));
    }
    let code = data
        .get(offset..)
        .filter(|code| !code.is_empty())
        .ok_or_else(|| error("Missing SID program data"))?;
    let layout = Layout::Sid;
    let mut c = program(layout, C64_CPU, load, offset, code);
    c.entry = Some(u64::from(if init == 0 { load } else { init }));
    c.notes.push(format!(
        "{} version {version}: {} by {}; {songs} songs",
        if rsid { "RSID" } else { "PSID" },
        text(data, SID_NAME),
        text(data, SID_AUTHOR)
    ));
    let basic = rsid && flags & SID_FLAG_BASIC != 0;
    let mus = !rsid && flags & SID_FLAG_MUS != 0;
    if basic || mus {
        c.opaque = true;
        c.notes.push(if basic {
            "Program is C64 BASIC, not machine code".into()
        } else {
            "Program is Compute! Sidplayer MUS data, not machine code".into()
        });
    } else {
        c.notes.push(format!(
            "MOS 6510 driver loaded at 0x{load:04X}; init 0x{init:04X}, play 0x{play:04X}"
        ));
    }
    Ok(c)
}

/// GBS: header, then code loaded at `load` in cartridge ROM.
fn gbs(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, GBS_HEADER_SIZE)?;
    if !header.starts_with(GBS_MAGIC) || header[3] != GBS_VERSION {
        return Err(error("Missing GBS magic or version 1"));
    }
    check_songs(
        u16::from(byte(header, GBS_SONGS)?),
        u16::from(byte(header, GBS_FIRST_SONG)?),
    )?;
    let load = le_u16(header, GBS_LOAD)?;
    let init = le_u16(header, GBS_INIT)?;
    let play = le_u16(header, GBS_PLAY)?;
    let in_rom = |address: u16| (load..=GBS_HIGHEST_LOAD).contains(&address);
    if !(GBS_LOWEST_LOAD..=GBS_HIGHEST_LOAD).contains(&load) || !in_rom(init) || !in_rom(play) {
        return Err(error(format!(
            "Invalid GBS addresses: load 0x{load:04X}, init 0x{init:04X}, play 0x{play:04X}"
        )));
    }
    let code = &data[GBS_HEADER_SIZE..];
    if code.is_empty() {
        return Err(error("Missing GBS program data"));
    }
    let mut c = program(Layout::Gbs, GAME_BOY_CPU, load, GBS_HEADER_SIZE, code);
    c.entry = Some(u64::from(init));
    c.notes.push(format!(
        "GBS: {} by {}; {} songs",
        text(header, GBS_TITLE),
        text(header, GBS_AUTHOR),
        header[GBS_SONGS]
    ));
    c.notes.push(format!(
        "Sharp SM83 driver loaded at 0x{load:04X}; init 0x{init:04X}, play 0x{play:04X}; the code model treats SM83 as a Z80-family variant"
    ));
    Ok(c)
}
