//! MCU update images: UF2 block files, STM32 `DfuSe` files, Silicon Labs
//! Gecko Bootloader (GBL v3) files and Cypress/Infineon `.cyacd`/`.cyacd2`
//! bootloader text files.
//!
//! Sources, by layout (details and pinned revisions in `docs/mcu.md`):
//! - UF2: microsoft/uf2 `README.md` and `utils/uf2families.json` at commit
//!   `90e9741f217f5a40c98ba74d663e408041037578`; pico-sdk 2.1.1
//!   `src/common/boot_uf2_headers/include/boot/uf2.h`; RP2350 datasheet,
//!   section 5.5 (Table 469) and erratum RP2350-E10 (see [`uf2`]).
//! - `DfuSe`: dfu-util v0.11 `src/dfuse.c` and `src/dfu_file.c`, `MicroPython`
//!   v1.24.0 `tools/pydfu.py` and `tools/dfu.py`, and the USB Device
//!   Firmware Upgrade Specification 1.1, Appendix B (DFU suffix) (see
//!   [`dfuse`]).
//! - GBL: `gecko_sdk` v4.5.1 `platform/bootloader/parser/gbl/btl_gbl_format.h`,
//!   `btl_gbl_format.c` and `btl_gbl_parser.c`; `simplicity_sdk` v2025.6.3 for
//!   the delta tags (see [`gbl`]).
//! - `.cyacd`: Cypress Bootloader Host `cybtldr_parse.c` (2011-2012) and
//!   cyflash `cyacd.py`; `.cyacd2`: Infineon AN213924 rev *H, ".cyacd2 file
//!   format", and `mtb-example-psoc4-dfu-host` `source/cybtldr_parse.c`
//!   (see [`cyacd`]).
//!
//! Only UF2 names a target: its family ID (flag `0x2000`, the README's
//! "board family ID") is the format's own target field, mapped to the ISA of
//! the family's application core. `DfuSe`, GBL and the Cypress formats carry no
//! architecture field; USB IDs, silicon IDs and vendor names are reported as
//! metadata and never become an ISA, so their payloads go to the code model.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, Section, Target, MAX_COMPONENTS};
use crate::formats::{compressed, MAX_PAYLOAD};
use crate::types::{Endianness, FileFormat, Isa};
use std::borrow::Cow;

mod cyacd;
mod dfuse;
mod gbl;
mod uf2;

/// A recognized MCU update image layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// UF2: a sequence of 512-byte blocks with three magic words.
    Uf2,
    /// STM32 `DfuSe`: `DfuSe` prefix, `Target` images, 16-byte DFU suffix.
    Dfuse,
    /// Silicon Labs Gecko Bootloader GBL v3: a little-endian tag stream.
    Gbl,
    /// Cypress `PSoC` Creator bootloadable `.cyacd` text (big-endian rows).
    Cyacd,
    /// Infineon DFU SDK `.cyacd2` text (little-endian rows).
    Cyacd2,
}

impl Layout {
    /// Every layout, for exhaustive tests.
    pub const ALL: &'static [Self] =
        &[Self::Uf2, Self::Dfuse, Self::Gbl, Self::Cyacd, Self::Cyacd2];

    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Uf2 => FileFormat::Uf2,
            Self::Dfuse => FileFormat::Dfuse,
            Self::Gbl => FileFormat::Gbl,
            Self::Cyacd | Self::Cyacd2 => FileFormat::Cyacd,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Uf2 => "UF2 block file",
            Self::Dfuse => "DfuSe 1.1a file",
            Self::Gbl => "GBL v3 file",
            Self::Cyacd => ".cyacd bootloadable",
            Self::Cyacd2 => ".cyacd2 DFU image",
        }
    }

    /// The Cypress text layouts have no magic and are recognized from
    /// complete structure.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::Cyacd | Self::Cyacd2)
    }

    /// Prefix of the layout's metadata keys.
    fn key_prefix(self) -> &'static str {
        match self {
            Self::Uf2 => "uf2",
            Self::Dfuse => "dfuse",
            Self::Gbl => "gbl",
            Self::Cyacd | Self::Cyacd2 => "cyacd",
        }
    }
}

/// Strong recognition: the UF2 start magics, the `DfuSe` signature, or the
/// GBL header tag at offset 0. A damaged file with one of these is a parse
/// error, not raw code.
pub fn detect(data: &[u8]) -> Option<Layout> {
    if uf2::has_magic(data) {
        Some(Layout::Uf2)
    } else if dfuse::has_magic(data) {
        Some(Layout::Dfuse)
    } else if gbl::has_magic(data) {
        Some(Layout::Gbl)
    } else {
        None
    }
}

/// Weak recognition of the magic-less `.cyacd` and `.cyacd2` text layouts:
/// the header and every row must parse, and every `.cyacd` row checksum
/// must match.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    cyacd::detect(data)
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::McuImageParseError`] for a truncated or inconsistent
/// block, prefix, tag, row or checksum, and [`ClassifierError::PayloadLimit`]
/// when the extracted bytes exceed [`MAX_PAYLOAD`].
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Uf2 => uf2::parse(data),
        Layout::Dfuse => dfuse::parse(data),
        Layout::Gbl => gbl::parse(data),
        Layout::Cyacd | Layout::Cyacd2 => cyacd::parse(data, layout),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::McuImageParseError {
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

/// Round up to a multiple of four bytes.
fn align4(n: usize) -> Result<usize> {
    Ok(n.checked_add(3)
        .ok_or_else(|| error("Alignment overflow"))?
        & !3)
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Bytes as uppercase hex digits, in file order.
fn hex_string(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

/// The bytes of a NUL-terminated string field, without the terminator.
fn until_nul(bytes: &[u8]) -> &[u8] {
    let len = memchr::memchr(0, bytes).unwrap_or(bytes.len());
    &bytes[..len]
}

/// `"1 block"`, `"2 blocks"`.
fn count(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// Load sections of one container, capped at [`MAX_COMPONENTS`]; sections
/// past the cap are counted and reported by [`Sections::finish`].
struct Sections {
    left_out: usize,
    left_out_size: usize,
}

impl Sections {
    fn new() -> Self {
        Self {
            left_out: 0,
            left_out_size: 0,
        }
    }

    /// Append `section`, or count it when the cap is reached.
    fn push<'a>(&mut self, c: &mut Container<'a>, section: Section<'a>) {
        if c.sections.len() < MAX_COMPONENTS {
            c.sections.push(section);
        } else {
            self.left_out += 1;
            self.left_out_size = self.left_out_size.saturating_add(section.data.len());
        }
    }

    /// Note the sections left out, if any.
    fn finish(self, c: &mut Container<'_>) {
        if self.left_out > 0 {
            c.notes.push(format!(
                "{} ({} B) not listed or analyzed (limit {MAX_COMPONENTS})",
                count(
                    self.left_out,
                    "further load section",
                    "further load sections"
                ),
                self.left_out_size
            ));
        }
    }
}

/// A load section whose bytes were reassembled or decoded from the stored
/// range `offset..offset + stored_size`.
fn transformed_section<'a>(
    label: String,
    address: u64,
    offset: usize,
    stored_size: usize,
    data: Vec<u8>,
    transform: &'static str,
) -> Section<'a> {
    Section {
        label,
        address,
        offset,
        stored_size,
        data: Cow::Owned(data),
        transform: Some(transform),
    }
}

/// A load section of bytes stored as-is at `offset`.
fn stored_section(label: String, address: u64, offset: usize, data: &[u8]) -> Section<'_> {
    Section {
        label,
        address,
        offset,
        stored_size: data.len(),
        data: Cow::Borrowed(data),
        transform: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_report_their_formats_and_strength() {
        for &layout in Layout::ALL {
            assert_eq!(layout.is_weak(), layout.format() == FileFormat::Cyacd);
            assert!(!layout.label().is_empty());
        }
        assert_eq!(detect(b"DfuSe\x01"), Some(Layout::Dfuse));
        assert_eq!(detect(&[0xeb, 0x17, 0xa6, 0x03]), Some(Layout::Gbl));
        assert_eq!(
            detect(&[0x55, 0x46, 0x32, 0x0a, 0x57, 0x51, 0x5d, 0x9e]),
            Some(Layout::Uf2)
        );
        assert_eq!(detect(b"not an image"), None);
    }

    #[test]
    fn readers_report_truncation_offsets() {
        let data = [1, 2, 3];
        assert_eq!(le_u16(&data, 1).unwrap(), 0x0302);
        let message = le_u32(&data, 1).unwrap_err().to_string();
        assert_eq!(
            message,
            "MCU image parse error: Truncated file range 0x1 + 4 B"
        );
        assert!(slice(&data, usize::MAX, 2).is_err());
        assert_eq!(align4(5).unwrap(), 8);
        assert!(align4(usize::MAX).is_err());
        assert_eq!(hex_string(&[0x0a, 0xff]), "0AFF");
        assert_eq!(until_nul(b"name\0rest"), b"name");
        assert_eq!(count(1, "block", "blocks"), "1 block");
        assert_eq!(count(3, "block", "blocks"), "3 blocks");
    }

    #[test]
    fn sections_past_the_cap_are_counted_not_listed() {
        let mut c = Container::new(FileFormat::Uf2, "test", "test");
        let mut sections = Sections::new();
        let bytes = [0u8; 2];
        for i in 0..=MAX_COMPONENTS {
            sections.push(&mut c, stored_section(format!("s{i}"), 0, 0, &bytes));
        }
        sections.finish(&mut c);
        assert_eq!(c.sections.len(), MAX_COMPONENTS);
        assert_eq!(
            c.notes,
            ["1 further load section (2 B) not listed or analyzed (limit 4096)"]
        );
    }
}
