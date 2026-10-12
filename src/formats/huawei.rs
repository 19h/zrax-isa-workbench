//! Huawei `UPDATE.APP` firmware packages.
//!
//! Huawei publishes no specification; the layout follows the open-source
//! splitter `split_updata.pl` at commit `7f318240` (`data_structure`,
//! `splitupdate`). A package starts with 92 zero bytes, then entries, each
//! aligned to four bytes: magic `55 AA 5A A5`, header length (u32 LE), an
//! unknown word, hardware ID (8 B), file sequence (4 B), data size (u32
//! LE), date, time, partition type and a blank field (16 B each), header
//! checksum, block size and a blank field (u16 each), the per-block data
//! checksums filling the rest of the header, then the partition data.
//! The package names no CPU; each partition is classified on its own.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Child, Container, MAX_COMPONENTS};
use crate::types::FileFormat;

/// Entry magic.
const ENTRY_MAGIC: [u8; 4] = [0x55, 0xaa, 0x5a, 0xa5];

/// Zero bytes before the first entry.
const LEADING_ZEROS: usize = 92;

/// Fixed part of an entry header, before the block checksums.
const FIXED_HEADER: usize = 98;

/// Entry header fields.
const HEADER_LENGTH: usize = 4;
const HARDWARE_ID: usize = 12;
const DATA_SIZE: usize = 24;
const DATE: usize = 28;
const TIME: usize = 44;
const PARTITION_TYPE: usize = 60;
const FIELD: usize = 16;

/// The only layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `UPDATE.APP` package.
    UpdateApp,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        FileFormat::HuaweiUpdate
    }

    /// Human-readable layout name.
    pub fn label(self) -> &'static str {
        "Huawei UPDATE.APP"
    }

    /// Recognized from its entry magic after the zero prefix.
    pub fn is_weak(self) -> bool {
        false
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::HuaweiParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated UPDATE.APP at 0x{start:X} + {len} B")))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes = slice(data, at, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// A NUL-padded text field.
fn text(field: &[u8]) -> String {
    let len = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..len]).trim().to_string()
}

/// Round up to a multiple of four bytes.
fn align4(n: usize) -> Result<usize> {
    Ok(n.checked_add(3)
        .ok_or_else(|| error("Alignment overflow"))?
        & !3)
}

/// The first entry's offset: after the zero prefix, or at 0.
fn first_entry(data: &[u8]) -> Option<usize> {
    if data.starts_with(&ENTRY_MAGIC) {
        return Some(0);
    }
    let prefix = data.get(..LEADING_ZEROS)?;
    let magic = data.get(LEADING_ZEROS..LEADING_ZEROS + 4)?;
    (prefix.iter().all(|b| *b == 0) && magic == ENTRY_MAGIC).then_some(LEADING_ZEROS)
}

/// Strong recognition: the entry magic at 0 or after the zero prefix.
pub fn detect(data: &[u8]) -> Option<Layout> {
    first_entry(data).map(|_| Layout::UpdateApp)
}

/// Parse an `UPDATE.APP` package into its partitions.
///
/// # Errors
///
/// [`ClassifierError::HuaweiParseError`] for a missing magic, a header
/// shorter than its fixed part, or data beyond the file.
pub fn parse_container(data: &[u8], _layout: Layout) -> Result<Container<'_>> {
    let mut pos = first_entry(data).ok_or_else(|| error("Missing UPDATE.APP entry magic"))?;
    let mut c = Container::new(
        FileFormat::HuaweiUpdate,
        Layout::UpdateApp.label(),
        "huawei",
    );
    let mut hardware = None;
    while pos < data.len() && c.children.len() < MAX_COMPONENTS {
        if slice(data, pos, 4)? != ENTRY_MAGIC {
            if data[pos..].iter().all(|b| *b == 0) {
                break;
            }
            return Err(error(format!(
                "Missing UPDATE.APP entry magic at 0x{pos:X}"
            )));
        }
        let header_len = le_u32(data, pos + HEADER_LENGTH)? as usize;
        if header_len < FIXED_HEADER {
            return Err(error(format!(
                "Invalid UPDATE.APP header length {header_len} B at 0x{pos:X}"
            )));
        }
        let header = slice(data, pos, header_len)?;
        let size = le_u32(header, DATA_SIZE)? as usize;
        let name = text(&header[PARTITION_TYPE..PARTITION_TYPE + FIELD]);
        let date = text(&header[DATE..DATE + FIELD]);
        let time = text(&header[TIME..TIME + FIELD]);
        hardware.get_or_insert_with(|| text(&header[HARDWARE_ID..HARDWARE_ID + 8]));
        let data_at = pos + header_len;
        let payload = slice(data, data_at, size).map_err(|_| {
            error(format!(
                "Truncated UPDATE.APP partition {name}: 0x{data_at:X} + {size} B"
            ))
        })?;
        c.notes
            .push(format!("{name}: {size} B, built {date} {time}"));
        let label = if name.is_empty() {
            format!("Partition {}", c.children.len() + 1)
        } else {
            name
        };
        c.children.push(Child::stored(label, data_at, payload));
        pos = align4(data_at + size)?;
    }
    c.consumed = pos.min(data.len());
    let hardware = hardware.unwrap_or_default();
    c.notes.insert(
        0,
        format!(
            "Huawei UPDATE.APP with {} partitions; hardware ID {hardware}; per-block checksums not verified",
            c.children.len()
        ),
    );
    Ok(c)
}
