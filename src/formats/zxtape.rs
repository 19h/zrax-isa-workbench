//! ZX Spectrum tape images: TZX and TAP.
//!
//! Layouts follow the World of Spectrum "TZX format" specification,
//! revision 1.20, and its TAP description: TZX is `ZXTape!\x1A`, a version,
//! then blocks identified by an ID byte, each with a length rule; TAP is a
//! sequence of a little-endian length and the block. Both carry the
//! Spectrum ROM's tape blocks: a flag byte, the data and an XOR checksum
//! that makes the XOR of the whole block zero. A header block (flag 0x00,
//! 17 data bytes) names a file type, a name, the data length and, for
//! `Bytes` (type 3), the load address of the data block (flag 0xFF) that
//! follows. The platform's CPU is the Z80.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Container, Target, MAX_COMPONENTS};
use crate::types::{Endianness, FileFormat, Isa};
use std::borrow::Cow;

/// TZX signature and header size.
const TZX_MAGIC: &[u8; 8] = b"ZXTape!\x1a";
const TZX_HEADER_SIZE: usize = 10;

/// TZX block IDs whose data are ROM-format tape blocks.
const TZX_STANDARD: u8 = 0x10;
const TZX_TURBO: u8 = 0x11;
const TZX_PURE_DATA: u8 = 0x14;

/// ROM tape block flags and the header block's size and types.
const FLAG_HEADER: u8 = 0x00;
const FLAG_DATA: u8 = 0xff;
const HEADER_BLOCK_SIZE: usize = 19;
const TYPE_PROGRAM: u8 = 0;
const TYPE_BYTES: u8 = 3;

/// Fewest TAP blocks for structural recognition: a header and its data.
const TAP_MIN_BLOCKS: usize = 2;

/// ROM-format tape blocks with the file offset of their flag byte.
type Blocks<'a> = Vec<(usize, &'a [u8])>;

/// A recognized tape layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// TZX tape image.
    Tzx,
    /// TAP tape image.
    Tap,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        FileFormat::ZxTape
    }

    /// Human-readable layout name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Tzx => "ZX Spectrum TZX tape",
            Self::Tap => "ZX Spectrum TAP tape",
        }
    }

    /// TAP files have no signature.
    pub fn is_weak(self) -> bool {
        matches!(self, Self::Tap)
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::ZxTapeParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated tape block at 0x{start:X} + {len} B")))
}

fn byte(data: &[u8], at: usize) -> Result<usize> {
    Ok(usize::from(slice(data, at, 1)?[0]))
}

fn le_u16(data: &[u8], at: usize) -> Result<usize> {
    let bytes = slice(data, at, 2)?;
    Ok(usize::from(u16::from_le_bytes([bytes[0], bytes[1]])))
}

fn le_u24(data: &[u8], at: usize) -> Result<usize> {
    let bytes = slice(data, at, 3)?;
    Ok(usize::from(bytes[0]) | usize::from(bytes[1]) << 8 | usize::from(bytes[2]) << 16)
}

fn le_u32(data: &[u8], at: usize) -> Result<usize> {
    let bytes = slice(data, at, 4)?;
    usize::try_from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .map_err(|_| error("Invalid tape block length"))
}

/// Does the XOR of a ROM tape block (flag, data, checksum) vanish?
fn checksum_ok(block: &[u8]) -> bool {
    block.iter().fold(0u8, |x, b| x ^ b) == 0
}

/// Strong recognition: the TZX signature.
pub fn detect(data: &[u8]) -> Option<Layout> {
    data.starts_with(TZX_MAGIC).then_some(Layout::Tzx)
}

/// Weak recognition: a TAP file whose blocks cover the input exactly, all
/// with valid checksums, starting with a ROM header block.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    let blocks = tap_blocks(data).ok()?;
    let starts_with_header = blocks
        .first()
        .is_some_and(|(_, block)| block.len() == HEADER_BLOCK_SIZE && block[0] == FLAG_HEADER);
    let valid = blocks.len() >= TAP_MIN_BLOCKS
        && starts_with_header
        && blocks.iter().all(|(_, block)| checksum_ok(block));
    valid.then_some(Layout::Tap)
}

/// TAP blocks: a little-endian length, then the block.
fn tap_blocks(data: &[u8]) -> Result<Blocks<'_>> {
    let mut pos = 0;
    let mut blocks = Vec::new();
    while pos < data.len() {
        let len = le_u16(data, pos)?;
        if len == 0 {
            return Err(error(format!("Invalid empty TAP block at 0x{pos:X}")));
        }
        blocks.push((pos + 2, slice(data, pos + 2, len)?));
        pos += 2 + len;
        if blocks.len() > MAX_COMPONENTS {
            return Err(error("TAP file has too many blocks"));
        }
    }
    Ok(blocks)
}

/// Length of a TZX block's body after its ID byte, per the specification's
/// table; `at` is the offset after the ID.
fn tzx_block_length(data: &[u8], id: u8, at: usize) -> Result<usize> {
    let length = match id {
        0x10 => 4 + le_u16(data, at + 2)?,
        0x11 => 0x12 + le_u24(data, at + 0x0f)?,
        0x12 => 4,
        0x13 => 1 + 2 * byte(data, at)?,
        0x14 => 0x0a + le_u24(data, at + 7)?,
        0x15 => 8 + le_u24(data, at + 5)?,
        0x18 | 0x19 | 0x2a | 0x2b => 4 + le_u32(data, at)?,
        0x20 | 0x23 | 0x24 => 2,
        0x21 | 0x30 => 1 + byte(data, at)?,
        0x22 | 0x25 | 0x27 => 0,
        0x26 => 2 + 2 * le_u16(data, at)?,
        0x28 | 0x32 => 2 + le_u16(data, at)?,
        0x31 => 2 + byte(data, at + 1)?,
        0x33 => 1 + 3 * byte(data, at)?,
        0x35 => 0x14 + le_u32(data, at + 0x10)?,
        0x5a => 9,
        other => {
            return Err(error(format!(
                "Unsupported TZX block 0x{other:02X} at 0x{:X}",
                at - 1
            )))
        }
    };
    Ok(length)
}

/// ROM-format tape blocks of a TZX file, with their file offsets.
fn tzx_blocks(data: &[u8]) -> Result<(Blocks<'_>, String)> {
    let header = slice(data, 0, TZX_HEADER_SIZE)?;
    if !header.starts_with(TZX_MAGIC) {
        return Err(error("Missing TZX signature"));
    }
    let version = format!("{}.{:02}", header[8], header[9]);
    let mut pos = TZX_HEADER_SIZE;
    let mut blocks = Vec::new();
    let mut count = 0;
    while pos < data.len() {
        let id = data[pos];
        let length = tzx_block_length(data, id, pos + 1)?;
        let body = slice(data, pos + 1, length)?;
        let data_at = match id {
            TZX_STANDARD => Some(4),
            TZX_TURBO => Some(0x12),
            TZX_PURE_DATA => Some(0x0a),
            _ => None,
        };
        if let Some(skip) = data_at {
            blocks.push((pos + 1 + skip, &body[skip..]));
        }
        pos += 1 + length;
        count += 1;
        if count > MAX_COMPONENTS * 4 {
            return Err(error("TZX file has too many blocks"));
        }
    }
    Ok((blocks, version))
}

/// Pair ROM header blocks with the data block after them; `Bytes` data
/// become load sections at their load address.
fn load_blocks<'a>(c: &mut Container<'a>, blocks: &[(usize, &'a [u8])]) {
    let mut bad_checksums = 0;
    let mut headerless = 0;
    let mut pending: Option<(u8, String, usize, usize)> = None;
    for &(offset, block) in blocks {
        if block.is_empty() {
            continue;
        }
        if !checksum_ok(block) {
            bad_checksums += 1;
        }
        match (block[0], pending.take()) {
            (FLAG_HEADER, _) if block.len() == HEADER_BLOCK_SIZE => {
                let name = String::from_utf8_lossy(&block[2..12])
                    .trim_end()
                    .to_string();
                let length = usize::from(u16::from_le_bytes([block[12], block[13]]));
                let start = usize::from(u16::from_le_bytes([block[14], block[15]]));
                pending = Some((block[1], name, length, start));
            }
            (FLAG_DATA, Some((TYPE_BYTES, name, length, start))) if block.len() >= 2 => {
                let code = &block[1..block.len() - 1];
                let code = &code[..code.len().min(length)];
                c.push_section(start as u64, offset + 1, Cow::Borrowed(code));
                if let Some(section) = c.sections.last_mut() {
                    section.label = format!("Bytes \"{name}\" at 0x{start:04X}");
                }
            }
            (FLAG_DATA, Some((TYPE_PROGRAM, name, _, _))) => {
                c.notes
                    .push(format!("BASIC program \"{name}\" (not machine code)"));
            }
            (FLAG_DATA, Some(_)) => {}
            _ => headerless += 1,
        }
    }
    if headerless > 0 {
        c.notes.push(format!(
            "{headerless} headerless or custom blocks with no load address; not analyzed"
        ));
    }
    if bad_checksums > 0 {
        c.notes
            .push(format!("{bad_checksums} blocks fail their XOR checksum"));
    }
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::ZxTapeParseError`] for a missing signature, an
/// unknown TZX block or a block beyond the file.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let mut c = Container::new(FileFormat::ZxTape, layout.label(), "zxtape");
    c.target = Some(Target::new(Isa::Z80, 8, Endianness::Little));
    c.consumed = data.len();
    let blocks = match layout {
        Layout::Tzx => {
            let (blocks, version) = tzx_blocks(data)?;
            c.notes.push(format!(
                "TZX version {version}; {} data blocks",
                blocks.len()
            ));
            blocks
        }
        Layout::Tap => {
            let blocks = tap_blocks(data)?;
            c.notes.push(format!("TAP image; {} blocks", blocks.len()));
            blocks
        }
    };
    load_blocks(&mut c, &blocks);
    c.code_sections = true;
    c.notes
        .push("ZX Spectrum tape; the platform's CPU is the Z80".into());
    Ok(c)
}
