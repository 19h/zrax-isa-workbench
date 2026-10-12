//! Automotive flash containers: ASAM ODX documents (ODX-F flash data),
//! Honda RWD calibration files, Toyota CUW calibration containers and
//! Mercedes-Benz CFF (Caesar) flash files.
//!
//! Sources, per layout: odxtools 11.7.0 for ODX (the ASAM MCD-2D schemas
//! are not public); rwd-xray `83b990e3` for RWD; `kaikozlov/ghidra_rh850`
//! `7b31684d` (`tools/techstream/parse_cuw_container.py`) for CUW;
//! `CaesarSuite` `f8e8463f` for CFF. Only ODX is published by a standards
//! body; the other layouts come from community reverse engineering and say
//! so in their notes. None of these formats names the ECU's CPU, so the ISA
//! always comes from extracted flash data. Mercedes SMR-F has no public
//! layout and is not recognized. PDX packages (ODX in a ZIP) are reached
//! through the ZIP container.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, MAX_COMPONENTS};
use crate::types::FileFormat;
use std::borrow::Cow;

mod cff;
mod cuw;
mod odx;
mod rwd;
mod xml;

pub(crate) use odx::{external_flash_data, ExternalFlashData, FlashCoding};

/// A recognized automotive layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// ASAM ODX document; flash data when its category is FLASH.
    Odx,
    /// Honda RWD calibration file (formats `0x5A` and `0x31`).
    HondaRwd,
    /// Toyota CUW calibration container.
    ToyotaCuw,
    /// Mercedes-Benz Caesar flash file.
    MercedesCff,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Odx => FileFormat::Odx,
            Self::HondaRwd => FileFormat::HondaRwd,
            Self::ToyotaCuw => FileFormat::ToyotaCuw,
            Self::MercedesCff => FileFormat::MercedesCff,
        }
    }

    /// Human-readable layout name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Odx => "ASAM ODX document",
            Self::HondaRwd => "Honda RWD calibration",
            Self::ToyotaCuw => "Toyota CUW calibration",
            Self::MercedesCff => "Mercedes-Benz CFF flash file",
        }
    }

    /// CFF has no magic and is recognized from its checksum and header.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::MercedesCff)
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::AutomotiveParseError {
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

fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2)?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_be_bytes(bytes))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_be_bytes(bytes))
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

/// Magic-bearing or checksum-validated layouts: an ODX root element, the
/// CUW magic, or an RWD signature whose trailing sum checks.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if data.starts_with(cuw::MAGIC) {
        Some(Layout::ToyotaCuw)
    } else if rwd::is_rwd(data) {
        Some(Layout::HondaRwd)
    } else if odx::is_odx(data) {
        Some(Layout::Odx)
    } else {
        None
    }
}

/// Magic-less layouts, recognized only when the checksum and header are
/// consistent.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    cff::is_cff(data).then_some(Layout::MercedesCff)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::AutomotiveParseError`] for malformed structure, a
/// failed checksum or a range outside the file.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Odx => odx::parse(data),
        Layout::HondaRwd => rwd::parse(data),
        Layout::ToyotaCuw => cuw::parse(data),
        Layout::MercedesCff => cff::parse(data),
    }
}
