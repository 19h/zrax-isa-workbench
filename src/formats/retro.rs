//! Console executables and ROM images: Sega Mega Drive / Genesis cartridge
//! ROMs (with the 32X SH-2 program header), `PlayStation` `PS-X EXE`, Dreamcast
//! `IP.BIN`, Wii U RPX/RPL, Nintendo 3DS NCCH (with `ExeFS` and `ExHeader`) and
//! `3DSX`, and PSP `EBOOT.PBP`.
//!
//! Primary sources, by layout (pins and revisions in `docs/retro.md`):
//! - Mega Drive: Plutiedev "ROM header reference"; Sega Retro "ROM header"
//!   (oldid 1155876); rom-properties `src/libromdata/Console/md_structs.h`
//!   at `b53204ff`; Genesis Plus GX `core/loadrom.c` at `49c58476`
//!   (checksum, byte-swapped and SMD dumps); `PicoDrive` `pico/32x/32x.c` at
//!   `26ecb2b6` (32X header).
//! - `PS-X EXE`: psx-spx "CDROM File Playstation EXE and SYSTEM.CNF";
//!   `PSn00bSDK` `libpsn00b/include/psxapi.h` and `tools/util/elf2x.c` at
//!   `5d9aa2d3`.
//! - Dreamcast: Marcus Comstedt, "IP0000.BIN" and "IP.BIN and `1ST_READ.BIN`";
//!   `KallistiOS` `utils/makeip/src/field.c` and `crc.c` at `568c3404`.
//! - Wii U: wut-tools `src/common/elf.h`, `src/elf2rpl/main.cpp` and
//!   `src/readrpl` at `b22de1a3`; decaf-emu `cafe_loader_rpl.h` at
//!   `e6c528a2`.
//! - 3DS: 3dbrew "NCCH" (oldid 23516), "`ExeFS`" (oldid 16109),
//!   "NCCH/Extended Header" (oldid 23704) and "3DSX Format" (oldid 14592);
//!   ctrtool `ctrtool/src/lzss.c` at `d52c2b0e` (`.code` compression, see
//!   `compressed::Codec::Blz`); devkitPro 3dstools `src/3dsx.h` at
//!   `718d6f23`.
//! - PSP: PSPSDK `tools/pack-pbp.c` at `e2b2b313`; PPSSPP
//!   `Core/ELF/PBPReader.cpp`, `Core/ELF/PrxDecrypter.h` and
//!   `Core/ELF/ParamSFO.cpp` at `b419238f`.
//!
//! Each of these platforms has one documented main CPU. As for the formats
//! in `console.rs`, a platform format names that CPU, so the container
//! states it as its target. The Wii U name comes from the ELF `e_machine`
//! field instead, and a plain-ELF PSP `DATA.PSP` is classified from its own
//! `e_machine`. A 3DS NCCH names a CPU only when its form type marks it as
//! an executable (CXI).

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Section, Target};
use crate::formats::MAX_PAYLOAD;
use crate::types::{Endianness, FileFormat, Isa};
use std::borrow::Cow;

mod dreamcast;
pub(crate) mod genesis;
mod n3ds;
mod n3dsx;
mod pbp;
mod psx;
mod rpx;

/// A console image layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Sega Mega Drive / Genesis cartridge ROM, in one of its dump orders.
    GenesisRom(GenesisDump),
    /// `PlayStation` `PS-X EXE` executable.
    PsxExe,
    /// Dreamcast `IP.BIN` boot area.
    DreamcastIp,
    /// Wii U RPX executable or RPL library (Cafe OS ELF).
    WiiURpx,
    /// Nintendo 3DS NCCH partition (CXI or CFA).
    N3dsNcch,
    /// Nintendo 3DS homebrew `3DSX` executable.
    N3ds3dsx,
    /// PSP `EBOOT.PBP` package.
    PspPbp,
}

/// How a Mega Drive ROM dump stores the cartridge bytes (Genesis Plus GX
/// `core/loadrom.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisDump {
    /// The cartridge bytes in address order (`.bin`, `.gen`, `.md`).
    Linear,
    /// Every pair of bytes swapped.
    ByteSwapped,
    /// Copier format (`.smd`): a 512-byte header, then 16 KiB blocks that
    /// store the odd bytes first and the even bytes second.
    Interleaved,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::GenesisRom(_) => FileFormat::GenesisRom,
            Self::PsxExe => FileFormat::PsxExe,
            Self::DreamcastIp => FileFormat::DreamcastIp,
            Self::WiiURpx => FileFormat::WiiURpx,
            Self::N3dsNcch => FileFormat::N3dsNcch,
            Self::N3ds3dsx => FileFormat::N3ds3dsx,
            Self::PspPbp => FileFormat::PspPbp,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::GenesisRom(GenesisDump::Linear) => "Mega Drive / Genesis ROM",
            Self::GenesisRom(GenesisDump::ByteSwapped) => {
                "Mega Drive / Genesis ROM (byte-swapped dump)"
            }
            Self::GenesisRom(GenesisDump::Interleaved) => {
                "Mega Drive / Genesis ROM (SMD interleaved dump)"
            }
            Self::PsxExe => "PS-X EXE",
            Self::DreamcastIp => "Dreamcast IP.BIN",
            Self::WiiURpx => "Wii U RPX/RPL",
            Self::N3dsNcch => "3DS NCCH",
            Self::N3ds3dsx => "3DSX",
            Self::PspPbp => "PSP PBP",
        }
    }

    /// Recognized from complete structure rather than a magic value. Every
    /// layout here carries a magic value or a fixed identification string,
    /// so none is weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::GenesisRom(_)
            | Self::PsxExe
            | Self::DreamcastIp
            | Self::WiiURpx
            | Self::N3dsNcch
            | Self::N3ds3dsx
            | Self::PspPbp => false,
        }
    }
}

/// Strong recognition of the layouts that do not start with ELF magic,
/// from their identification strings. Wii U RPX/RPL files are ELF files;
/// see [`detect_rpx`].
pub fn detect(data: &[u8]) -> Option<Layout> {
    if dreamcast::detect(data) {
        Some(Layout::DreamcastIp)
    } else if psx::detect(data) {
        Some(Layout::PsxExe)
    } else if n3ds::detect(data) {
        Some(Layout::N3dsNcch)
    } else if n3dsx::detect(data) {
        Some(Layout::N3ds3dsx)
    } else if pbp::detect(data) {
        Some(Layout::PspPbp)
    } else {
        genesis::detect(data).map(Layout::GenesisRom)
    }
}

/// Strong recognition of a Wii U RPX/RPL: ELF magic, 32-bit, big-endian,
/// `EI_OSABI` `0xCA` and `EI_ABIVERSION` `0xFE`. It must run before the
/// generic ELF check.
pub fn detect_rpx(data: &[u8]) -> Option<Layout> {
    rpx::detect(data).then_some(Layout::WiiURpx)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::RetroConsoleParseError`] for a truncated or
/// inconsistent header, a region outside the file, or a compressed section
/// that does not decode to its declared size.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::GenesisRom(dump) => genesis::parse(data, dump),
        Layout::PsxExe => psx::parse(data),
        Layout::DreamcastIp => dreamcast::parse(data),
        Layout::WiiURpx => rpx::parse(data),
        Layout::N3dsNcch => n3ds::parse(data),
        Layout::N3ds3dsx => n3dsx::parse(data),
        Layout::PspPbp => pbp::parse(data),
    }
}

/// 3DS application code: the ARM11 `MPCore` application cores run ARM and
/// Thumb code, little-endian (3dbrew). That the core implements `ARMv6K` is
/// from ARM's documentation of the ARM11 `MPCore`, not from the 3DS sources.
const ARM11: Target = Target::new(Isa::Arm, 32, Endianness::Little);
const ARM11_VARIANT: &str = "ARM11 MPCore (ARMv6K)";

/// The note shared by the 3DS layouts, which name no CPU themselves.
const ARM11_NOTE: &str =
    "The header names no CPU; 3DS application code runs on the ARM11 MPCore cores (ARM and Thumb)";

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::RetroConsoleParseError {
        message: message.into(),
    }
}

/// A byte range of the input: `offset` and `size` in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Region {
    offset: usize,
    size: usize,
}

impl Region {
    /// One past the last byte; callers construct regions inside the input,
    /// so the sum does not overflow.
    fn end(self) -> usize {
        self.offset + self.size
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

/// The `N` bytes at `at`, as an array.
fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(data, at, N)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(array(data, at)?))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(data, at)?))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(data, at)?))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(data, at)?))
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(array(data, at)?))
}

/// A little-endian 32-bit size or offset at `at`, as `usize`.
fn le_usize(data: &[u8], at: usize, what: &str) -> Result<usize> {
    let value = le_u32(data, at)?;
    usize::try_from(value).map_err(|_| error(format!("Invalid {what} 0x{value:X}")))
}

/// A big-endian 32-bit size or offset at `at`, as `usize`.
fn be_usize(data: &[u8], at: usize, what: &str) -> Result<usize> {
    let value = be_u32(data, at)?;
    usize::try_from(value).map_err(|_| error(format!("Invalid {what} 0x{value:X}")))
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// A NUL- or space-padded ASCII field: bytes up to the first NUL, printable
/// ASCII kept, anything else (Shift-JIS titles, control bytes) replaced, and
/// surrounding spaces removed.
fn text(field: &[u8]) -> String {
    let end = memchr::memchr(0, field).unwrap_or(field.len());
    let printable: String = field[..end]
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                char::REPLACEMENT_CHARACTER
            }
        })
        .collect();
    printable.trim().to_string()
}

/// Decimal size with the largest exact binary unit.
fn size_text(n: usize) -> String {
    if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n % (1 << 10) == 0 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// A load section with its own label, stored at `offset`.
fn section<'a>(
    label: impl Into<String>,
    address: u64,
    offset: usize,
    stored_size: usize,
    data: Cow<'a, [u8]>,
    transform: Option<&'static str>,
) -> Section<'a> {
    Section {
        label: label.into(),
        address,
        offset,
        stored_size,
        data,
        transform,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_fields_stop_at_nul_trim_spaces_and_replace_non_ascii() {
        assert_eq!(text(b"SEGA GENESIS    "), "SEGA GENESIS");
        assert_eq!(text(b"CtrApp\0\0"), "CtrApp");
        assert_eq!(text(b"\x82\xa0 A"), "\u{fffd}\u{fffd} A");
    }

    #[test]
    fn sizes_use_binary_units() {
        assert_eq!(size_text(512), "512 B");
        assert_eq!(size_text(0x8000), "32 KiB");
        assert_eq!(size_text(4 << 20), "4 MiB");
    }

    #[test]
    fn layouts_report_their_formats_and_are_strong() {
        assert_eq!(Layout::PspPbp.format(), FileFormat::PspPbp);
        assert_eq!(
            Layout::GenesisRom(GenesisDump::Interleaved).format(),
            FileFormat::GenesisRom
        );
        assert!(!Layout::WiiURpx.is_weak());
        assert!(!Layout::GenesisRom(GenesisDump::Linear).is_weak());
    }
}
