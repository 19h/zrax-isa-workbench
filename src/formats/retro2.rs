//! More console and home-computer images: Sega Master System / Game Gear
//! ROMs, Sega 32X ROMs, Sega Saturn `IP.BIN`, Sega CD / Mega-CD system areas,
//! MSX cartridge ROMs, Atari Lynx `.lnx`, Atari 7800 `.a78`, Commodore 64
//! `.crt`, Atari ST GEMDOS executables, ZX Spectrum `.z80` and `.sna`
//! snapshots, Bandai `WonderSwan` ROMs and Neo Geo Pocket ROMs.
//!
//! Primary sources, by layout (pins, revisions and hashes in
//! `docs/retro2.md`):
//! - Master System / Game Gear: SMS Power! "ROM Header"; Charles `MacDonald`,
//!   "SMS/GG hardware notes" (2002-11-12); WLA-DX `wlalink/compute.c` at
//!   `7ae11df1` (checksum); `PicoDrive` `pico/media.c` at `26ecb2b6`. See
//!   [`sms`].
//! - Sega 32X: Sega "32X Hardware Manual" (1994) §5.1 and §5.2;
//!   rom-properties `md_structs.h` and `MegaDrive.cpp` at `b53204ff`;
//!   `PicoDrive` `pico/32x/32x.c` at `26ecb2b6`. See [`mars`].
//! - Sega Saturn: Sega ST-040-R4-051795 "Disc Format Standards
//!   Specification Sheet" §4; ST-103-R1-040194; Hitachi SH7604 Hardware
//!   Manual ADE-602-085C §2.2.2; Yabause `yabause.c` at `7e38821d`. See
//!   [`saturn`].
//! - Sega CD / Mega-CD: Sega "Mega-CD Disc Format Specifications" Ver 2.00
//!   (1992-02-24) Fig. 3-2 and Appendices 2-3; "Mega-CD BIOS Manual" Ver
//!   2.00 §4; "Mega-CD Outline" §2. See [`segacd`].
//! - MSX: ASCII "MSX2 Technical Handbook" chapter 5 §7.3.1
//!   (Konamiman/MSX2-Technical-Handbook at `43959e90`). See [`msx`].
//! - Atari Lynx: Mednafen `lynx/cart.cpp` and `c65c02.h`
//!   (libretro/beetle-lynx-libretro at `fcdefcfb`); cc65
//!   `libsrc/lynx/exehdr.s` and `bootldr.s` at `e47ac506`. See [`lynx`].
//! - Atari 7800: 7800 8-bit dev wiki "A78 Header Specification" (oldid
//!   1120); cc65 `libsrc/atari7800/exehdr.s` and `cfg/atari7800.cfg` at
//!   `e47ac506`; MAME `a78_slot.cpp` and `a7800.cpp` at `17842be9`. See
//!   [`a7800`].
//! - Commodore 64: VICE manual §17.14 "The CRT cartridge image format";
//!   MAME `src/lib/formats/cbm_crt.cpp` and `c64.cpp` at `17842be9`. See
//!   [`c64crt`].
//! - Atari ST: TOS.HYP §5.5 "The program format"; `EmuTOS` `bdos/pghdr.h`,
//!   `bdos/kpgmld.c` and `bdos/proc.c` at `02c2db75`. See [`atarist`].
//! - ZX Spectrum: World of Spectrum "Z80 File Format" (rev. 1.12),
//!   "formats.htm" SNA (rev. 1.13) and "128kreference.htm". See [`zx`].
//! - `WonderSwan`: trap15 "`WSMan` rev.7" (Cartridge Metadata, CPU
//!   Overview); "`WStech` doc v2.4" §6; Mednafen `wswan` (libretro
//!   beetle-wswan-libretro at `4b012958`). See [`wswan`].
//! - Neo Geo Pocket: `NeeGee` "Everything You Always Wanted To Know About
//!   `NeoGeo` Pocket Color" (2000-04-16); `NeoPop` `ngp/rom.h` and `mem.h`
//!   (libretro beetle-ngp-libretro at `a50d5ac2`). See [`ngp`].
//!
//! Each platform has one documented main CPU, so the platform names it, as
//! for the formats in `retro.rs` and `nintendo.rs`: Z80 (Master System,
//! Game Gear, MSX, ZX Spectrum), 68000 (32X 68000 side, Sega CD, Atari ST),
//! SH-2 (32X SH-2 side, Saturn), 6502 family (Lynx 65C02, 7800 6502, C64
//! 6510), the NEC V30MZ (80186-compatible x86) and the Toshiba TLCS-900/H.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Container, Section, Target};
use crate::types::{Endianness, FileFormat, Isa};
use std::borrow::Cow;

mod a7800;
mod atarist;
mod c64crt;
mod lynx;
mod mars;
mod msx;
mod ngp;
mod saturn;
mod segacd;
mod sms;
mod wswan;
mod zx;

/// Which Sega 8-bit system a `TMR SEGA` header's region code names (SMS
/// Power! "ROM Header", region code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegaSystem {
    /// Region code 3 or 4: Master System.
    MasterSystem,
    /// Region code 5, 6 or 7: Game Gear.
    GameGear,
    /// Any other region code.
    Unspecified,
}

/// Where an MSX cartridge header sits in the Z80 address space (MSX2
/// Technical Handbook, Figure 5.48: "4000H or 8000H").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsxBase {
    /// The header is at 0x4000 (page 1).
    Page1,
    /// The header is at 0x8000 (page 2).
    Page2,
}

/// A `.z80` snapshot version (World of Spectrum "Z80 File Format").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Z80Version {
    /// Version 1: 30-byte header and one 48 KiB block.
    V1,
    /// Version 2: additional header of 23 bytes and 16 KiB pages.
    V2,
    /// Version 3: additional header of 54 or 55 bytes and 16 KiB pages.
    V3,
}

/// A `.sna` snapshot model (World of Spectrum "formats.htm", SNA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnaModel {
    /// 48K snapshot: 49179 bytes.
    K48,
    /// 128K snapshot: 131103 or 147487 bytes.
    K128,
}

/// A console or home-computer image layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Master System or Game Gear ROM with a `TMR SEGA` header.
    Sega8Bit(SegaSystem),
    /// Sega 32X ROM: a Mega Drive ROM with the 32X security program.
    Sega32x,
    /// Sega Saturn `IP.BIN` (the start of a disc's system area).
    SaturnIp,
    /// Sega CD / Mega-CD system area (`SEGADISCSYSTEM`).
    SegaCd,
    /// MSX cartridge ROM with an `AB` header.
    Msx(MsxBase),
    /// Atari Lynx `.lnx` cartridge image.
    Lynx,
    /// Atari 7800 `.a78` cartridge image.
    Atari7800,
    /// Commodore 64 `.crt` cartridge image.
    C64Crt,
    /// Atari ST GEMDOS executable (`.prg`, `.tos`, `.ttp`).
    AtariStPrg,
    /// ZX Spectrum `.z80` snapshot.
    Z80Snapshot(Z80Version),
    /// ZX Spectrum `.sna` snapshot.
    SnaSnapshot(SnaModel),
    /// Bandai `WonderSwan` or `WonderSwan` Color ROM.
    WonderSwan,
    /// Neo Geo Pocket or Neo Geo Pocket Color ROM.
    NeoGeoPocket,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Sega8Bit(_) => FileFormat::SmsRom,
            Self::Sega32x => FileFormat::Sega32xRom,
            Self::SaturnIp => FileFormat::SaturnIp,
            Self::SegaCd => FileFormat::SegaCdIp,
            Self::Msx(_) => FileFormat::MsxRom,
            Self::Lynx => FileFormat::LynxRom,
            Self::Atari7800 => FileFormat::Atari7800Rom,
            Self::C64Crt => FileFormat::C64Crt,
            Self::AtariStPrg => FileFormat::AtariStPrg,
            Self::Z80Snapshot(_) | Self::SnaSnapshot(_) => FileFormat::ZxSnapshot,
            Self::WonderSwan => FileFormat::WonderSwanRom,
            Self::NeoGeoPocket => FileFormat::NgpRom,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Sega8Bit(SegaSystem::MasterSystem) => "Master System ROM",
            Self::Sega8Bit(SegaSystem::GameGear) => "Game Gear ROM",
            Self::Sega8Bit(SegaSystem::Unspecified) => "Master System / Game Gear ROM",
            Self::Sega32x => "Sega 32X ROM",
            Self::SaturnIp => "Saturn IP.BIN",
            Self::SegaCd => "Sega CD system area",
            Self::Msx(MsxBase::Page1) => "MSX cartridge ROM at 0x4000",
            Self::Msx(MsxBase::Page2) => "MSX cartridge ROM at 0x8000",
            Self::Lynx => "Atari Lynx LNX",
            Self::Atari7800 => "Atari 7800 A78",
            Self::C64Crt => "C64 CRT",
            Self::AtariStPrg => "GEMDOS executable",
            Self::Z80Snapshot(Z80Version::V1) => ".z80 snapshot version 1",
            Self::Z80Snapshot(Z80Version::V2) => ".z80 snapshot version 2",
            Self::Z80Snapshot(Z80Version::V3) => ".z80 snapshot version 3",
            Self::SnaSnapshot(SnaModel::K48) => ".sna 48K snapshot",
            Self::SnaSnapshot(SnaModel::K128) => ".sna 128K snapshot",
            Self::WonderSwan => "WonderSwan ROM",
            Self::NeoGeoPocket => "Neo Geo Pocket ROM",
        }
    }

    /// Recognized from complete structure rather than a magic value: MSX
    /// headers (a two-byte ID), snapshots (no magic) and `WonderSwan` ROMs
    /// (a footer with a checksum).
    pub fn is_weak(self) -> bool {
        matches!(
            self,
            Self::Msx(_) | Self::Z80Snapshot(_) | Self::SnaSnapshot(_) | Self::WonderSwan
        )
    }
}

/// Strong recognition of the 32X: a linear Mega Drive ROM that carries the
/// 32X security program. It must run before `retro::detect`, whose Mega
/// Drive check would claim the same ROM.
pub fn detect_32x(data: &[u8]) -> Option<Layout> {
    mars::detect(data).then_some(Layout::Sega32x)
}

/// Strong recognition from identification strings at fixed offsets
/// (`SEGA SEGASATURN `, `SEGADISCSYSTEM`, `LYNX`, `ATARI7800`, `C64
/// CARTRIDGE`, the SNK recognition code, `TMR SEGA`) and of GEMDOS
/// executables, whose two-byte magic is accepted only with consistent
/// sizes and a valid relocation table.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if saturn::detect(data) {
        Some(Layout::SaturnIp)
    } else if segacd::detect(data) {
        Some(Layout::SegaCd)
    } else if lynx::detect(data) {
        Some(Layout::Lynx)
    } else if a7800::detect(data) {
        Some(Layout::Atari7800)
    } else if c64crt::detect(data) {
        Some(Layout::C64Crt)
    } else if ngp::detect(data) {
        Some(Layout::NeoGeoPocket)
    } else if let Some(system) = sms::detect(data) {
        Some(Layout::Sega8Bit(system))
    } else {
        atarist::detect(data).then_some(Layout::AtariStPrg)
    }
}

/// Recognition of the magic-less layouts from their complete structure:
/// `.z80` snapshots that decode exactly, `.sna` snapshots of an exact size
/// with sane registers, MSX headers whose addresses fit exactly one page,
/// and `WonderSwan` footers whose checksum matches.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    if let Some(layout) = zx::detect(data) {
        return Some(layout);
    }
    if let Some(base) = msx::detect(data) {
        return Some(Layout::Msx(base));
    }
    wswan::detect(data).then_some(Layout::WonderSwan)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::RetroHomeParseError`] for a truncated or inconsistent
/// header, a region outside the file, a relocation table or snapshot block
/// that does not decode, or trailing data that is not padding.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Sega8Bit(_) => sms::parse(data),
        Layout::Sega32x => mars::parse(data),
        Layout::SaturnIp => saturn::parse(data),
        Layout::SegaCd => segacd::parse(data),
        Layout::Msx(base) => msx::parse(data, base),
        Layout::Lynx => lynx::parse(data),
        Layout::Atari7800 => a7800::parse(data),
        Layout::C64Crt => c64crt::parse(data),
        Layout::AtariStPrg => atarist::parse(data),
        Layout::Z80Snapshot(version) => zx::parse_z80(data, version),
        Layout::SnaSnapshot(model) => zx::parse_sna(data, model),
        Layout::WonderSwan => wswan::parse(data),
        Layout::NeoGeoPocket => ngp::parse(data),
    }
}

/// Z80 code: 8-bit, little-endian operands (Master System, Game Gear, MSX,
/// ZX Spectrum).
const Z80: Target = Target::new(Isa::Z80, 8, Endianness::Little);

/// 6502-family code: 8-bit, little-endian operands (Lynx, 7800, C64).
const MOS_6502: Target = Target::new(Isa::Mcs6502, 8, Endianness::Little);

/// 68000 code, big-endian (32X 68000 side, Sega CD, Atari ST).
const M68000: Target = Target::new(Isa::M68k, 32, Endianness::Big);

/// SH-2 code, big-endian (32X SH-2 side, Saturn).
const SH2: Target = Target::new(Isa::Sh, 32, Endianness::Big);

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::RetroHomeParseError {
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

/// Whether `magic` is stored at `offset`.
fn has_magic(data: &[u8], offset: usize, magic: &[u8]) -> bool {
    data.get(offset..)
        .is_some_and(|rest| rest.starts_with(magic))
}

/// A space- or NUL-padded ASCII field: printable ASCII kept, other bytes
/// replaced, trailing spaces and NULs removed.
fn header_text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |last| last + 1);
    bytes[..end]
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                char::REPLACEMENT_CHARACTER
            }
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
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Trailing bytes after an image: nothing, or `0x00`/`0xFF` padding that is
/// reported in a note. Anything else is not part of the image.
fn expect_padding(data: &[u8], end: usize, what: &str) -> Result<Option<String>> {
    let trailer = data.get(end..).unwrap_or_default();
    if trailer.is_empty() {
        return Ok(None);
    }
    if is_padding(trailer) {
        return Ok(Some(format!(
            "{} of padding after the {what}",
            size_text(trailer.len() as u64)
        )));
    }
    Err(error(format!(
        "Invalid trailing data: {} B at 0x{end:X} after the {what}",
        trailer.len()
    )))
}

/// A load section with its own label, stored as-is at `offset`.
fn stored_section(
    label: impl Into<String>,
    address: u64,
    offset: usize,
    bytes: &[u8],
) -> Section<'_> {
    Section {
        label: label.into(),
        address,
        offset,
        stored_size: bytes.len(),
        data: Cow::Borrowed(bytes),
        transform: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_text_trims_padding_and_replaces_non_ascii() {
        assert_eq!(header_text(b"SONIC   \0\0"), "SONIC");
        assert_eq!(header_text(&[0x01, b'A']), "\u{FFFD}A");
        assert_eq!(header_text(b"    "), "");
    }

    #[test]
    fn sizes_use_binary_units() {
        assert_eq!(size_text(16 << 10), "16 KiB");
        assert_eq!(size_text(4 << 20), "4 MiB");
        assert_eq!(size_text(300), "300 B");
    }

    #[test]
    fn trailing_bytes_must_be_padding() {
        let data = [1, 2, 0xff, 0x00];
        assert_eq!(
            expect_padding(&data, 2, "ROM").unwrap(),
            Some("2 B of padding after the ROM".to_string())
        );
        assert_eq!(expect_padding(&data, 4, "ROM").unwrap(), None);
        assert!(expect_padding(&data, 1, "ROM").is_err());
    }

    #[test]
    fn only_structure_only_layouts_are_weak() {
        assert!(Layout::Msx(MsxBase::Page1).is_weak());
        assert!(Layout::SnaSnapshot(SnaModel::K48).is_weak());
        assert!(Layout::WonderSwan.is_weak());
        assert!(!Layout::AtariStPrg.is_weak());
        assert!(!Layout::Sega32x.is_weak());
        assert_eq!(
            Layout::Z80Snapshot(Z80Version::V3).format(),
            FileFormat::ZxSnapshot
        );
    }
}
