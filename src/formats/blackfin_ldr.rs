//! Analog Devices Blackfin LDR boot streams.
//!
//! An LDR file is the block stream the Blackfin boot ROM loads. Layouts
//! follow ldr-utils at commit `2253efd1` (`lfd_bf548.c`, `lfd_bf537.c`,
//! `lfd_bf561.c`) and U-Boot v2016.01
//! `arch/blackfin/include/asm/mach-common/bits/bootrom.h` and
//! `common/cmd_bootldr.c`; all fields are little-endian.
//!
//! - `BF51x`, `BF52x`, `BF54x` and `BF59x`: 16-byte headers of block code, target
//!   address, byte count and argument. The block code carries the signature
//!   `0xAD` in bits 31-24 and an XOR checksum in bits 23-16 chosen so the
//!   XOR of all 16 header bytes is zero. `FILL` blocks have no data.
//! - `BF53x`: 10-byte headers of target address, byte count and flags;
//!   `ZEROFILL` blocks have no data. `BF56x` adds a 4-byte global header
//!   whose top nibble is `0xA`.
//!
//! The format is the Blackfin boot ROM's own, so the target is Blackfin.
//! Several boot streams (one per DXE) may follow each other; each ends with
//! a `FINAL` block.

use crate::error::{ClassifierError, Result};
use crate::formats::container::{Container, Target, MAX_COMPONENTS};
use crate::types::{Endianness, FileFormat, Isa};
use std::borrow::Cow;

/// `BF54x`-style block header size and fields.
const BF54X_HEADER: usize = 16;
const BF54X_SIGNATURE: u8 = 0xad;
const BFLAG_FILL: u32 = 0x0000_0100;
const BFLAG_INIT: u32 = 0x0000_0800;
const BFLAG_IGNORE: u32 = 0x0000_1000;
const BFLAG_FINAL: u32 = 0x0000_8000;

/// `BF53x` block header size and flags.
const BF53X_HEADER: usize = 10;
const BF53X_ZEROFILL: u16 = 0x0001;
const BF53X_INIT: u16 = 0x0008;
const BF53X_IGNORE: u16 = 0x0010;
const BF53X_FINAL: u16 = 0x8000;

/// `BF53x` streams start with a block loaded into L1 memory: U-Boot's
/// `ldr_valid_signature` requires `address & 0xFF0FFF0F == 0xFF000000`.
const BF53X_FIRST_ADDRESS_MASK: u32 = 0xff0f_ff0f;
const BF53X_FIRST_ADDRESS: u32 = 0xff00_0000;

/// `BF56x` global header: signature `0xA` in the top nibble of byte 3.
const BF56X_GLOBAL_HEADER: usize = 4;
const BF56X_SIGNATURE: u8 = 0xa;

/// A recognized LDR layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// 16-byte signed headers (`BF51x`, `BF52x`, `BF54x`, `BF59x`).
    Bf54x,
    /// 10-byte headers (`BF53x`).
    Bf53x,
    /// `BF53x`-style headers after a 4-byte global header (`BF56x`).
    Bf56x,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        FileFormat::BlackfinLdr
    }

    /// Human-readable layout name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Bf54x => "Blackfin LDR (BF54x block headers)",
            Self::Bf53x => "Blackfin LDR (BF53x block headers)",
            Self::Bf56x => "Blackfin LDR (BF56x)",
        }
    }

    /// `BF53x` and `BF56x` headers carry no signature byte.
    pub fn is_weak(self) -> bool {
        !matches!(self, Self::Bf54x)
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::BlackfinLdrParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated LDR block at 0x{start:X} + {len} B")))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes = slice(data, at, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes = slice(data, at, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// Does a `BF54x`-style header start at `at`: signature and XOR checksum?
fn is_bf54x_header(data: &[u8], at: usize) -> bool {
    data.get(at..at + BF54X_HEADER).is_some_and(|header| {
        header[3] == BF54X_SIGNATURE && header.iter().fold(0u8, |x, b| x ^ b) == 0
    })
}

/// Strong recognition: a signed, checksummed `BF54x`-style first header.
pub fn detect(data: &[u8]) -> Option<Layout> {
    (is_bf54x_header(data, 0) && parse_container(data, Layout::Bf54x).is_ok())
        .then_some(Layout::Bf54x)
}

/// Weak recognition: a `BF56x` global header or a `BF53x` first block in L1
/// memory, and a complete block walk ending in a final block followed only
/// by padding.
pub fn detect_weak(data: &[u8]) -> Option<Layout> {
    let bf56x = data.len() > BF56X_GLOBAL_HEADER && data[3] >> 4 == BF56X_SIGNATURE;
    let layout = if bf56x { Layout::Bf56x } else { Layout::Bf53x };
    parse_container(data, layout).is_ok().then_some(layout)
}

/// One loaded block.
struct Block {
    address: u32,
    offset: usize,
    size: usize,
    init: bool,
}

/// Walk `BF54x`-style blocks from 0. Returns the loaded blocks, the end
/// offset and the number of boot streams.
fn bf54x_blocks(data: &[u8]) -> Result<(Vec<Block>, usize, usize)> {
    let mut pos = 0;
    let mut blocks = Vec::new();
    let mut streams = 0;
    loop {
        if !is_bf54x_header(data, pos) {
            return Err(error(format!(
                "Invalid LDR block header at 0x{pos:X}: signature or checksum"
            )));
        }
        let code = le_u32(data, pos)?;
        let address = le_u32(data, pos + 4)?;
        let count = le_u32(data, pos + 8)? as usize;
        let data_at = pos + BF54X_HEADER;
        let stored = if code & BFLAG_FILL != 0 { 0 } else { count };
        slice(data, data_at, stored)?;
        if code & (BFLAG_FILL | BFLAG_IGNORE) == 0 && count > 0 {
            blocks.push(Block {
                address,
                offset: data_at,
                size: count,
                init: code & BFLAG_INIT != 0,
            });
        }
        pos = data_at + stored;
        if code & BFLAG_FINAL != 0 {
            streams += 1;
            if !is_bf54x_header(data, pos) {
                return Ok((blocks, pos, streams));
            }
        }
        if blocks.len() > MAX_COMPONENTS {
            return Err(error("LDR stream has too many blocks"));
        }
    }
}

/// Walk `BF53x`-style blocks from `start` to the final block.
fn bf53x_blocks(data: &[u8], start: usize) -> Result<(Vec<Block>, usize)> {
    let first = le_u32(data, start)?;
    if first & BF53X_FIRST_ADDRESS_MASK != BF53X_FIRST_ADDRESS {
        return Err(error(format!(
            "Invalid BF53x LDR first block address 0x{first:08X}"
        )));
    }
    let mut pos = start;
    let mut blocks = Vec::new();
    loop {
        let address = le_u32(data, pos)?;
        let count = le_u32(data, pos + 4)? as usize;
        let flags = le_u16(data, pos + 8)?;
        let data_at = pos + BF53X_HEADER;
        let stored = if flags & BF53X_ZEROFILL != 0 {
            0
        } else {
            count
        };
        slice(data, data_at, stored)?;
        if flags & (BF53X_ZEROFILL | BF53X_IGNORE) == 0 && count > 0 {
            blocks.push(Block {
                address,
                offset: data_at,
                size: count,
                init: flags & BF53X_INIT != 0,
            });
        }
        pos = data_at + stored;
        if flags & BF53X_FINAL != 0 {
            return Ok((blocks, pos));
        }
        if blocks.len() > MAX_COMPONENTS {
            return Err(error("LDR stream has too many blocks"));
        }
    }
}

/// Parse `data` as the given layout.
///
/// # Errors
///
/// [`ClassifierError::BlackfinLdrParseError`] for a bad header, a block
/// beyond the file, a stream without a final block, or non-padding bytes
/// after it.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let (blocks, end, streams) = match layout {
        Layout::Bf54x => bf54x_blocks(data)?,
        Layout::Bf53x => {
            let (blocks, end) = bf53x_blocks(data, 0)?;
            (blocks, end, 1)
        }
        Layout::Bf56x => {
            if data.len() <= BF56X_GLOBAL_HEADER || data[3] >> 4 != BF56X_SIGNATURE {
                return Err(error("Missing BF56x LDR global header"));
            }
            let (blocks, end) = bf53x_blocks(data, BF56X_GLOBAL_HEADER)?;
            (blocks, end, 1)
        }
    };
    if !is_padding(&data[end..]) {
        return Err(error(format!(
            "Unexpected bytes after the final LDR block at 0x{end:X}"
        )));
    }
    if blocks.is_empty() {
        return Err(error("LDR stream loads no data"));
    }
    let mut c = Container::new(FileFormat::BlackfinLdr, layout.label(), "ldr");
    c.target = Some(Target::new(Isa::Blackfin, 32, Endianness::Little));
    c.consumed = end;
    c.notes.push(format!(
        "Blackfin boot ROM stream: {streams} boot stream(s), {} loaded blocks",
        blocks.len()
    ));
    let init_blocks = blocks.iter().filter(|b| b.init).count();
    if init_blocks > 0 {
        c.notes.push(format!(
            "{init_blocks} initialization block(s) run during boot"
        ));
    }
    for block in &blocks {
        c.push_section(
            u64::from(block.address),
            block.offset,
            Cow::Borrowed(&data[block.offset..block.offset + block.size]),
        );
    }
    c.code_sections = true;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `BF54x`-style header with its XOR checksum filled in.
    fn header(code: u32, address: u32, count: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&(code | 0xad00_0000).to_le_bytes());
        h.extend_from_slice(&address.to_le_bytes());
        h.extend_from_slice(&count.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        let check = h.iter().fold(0u8, |x, b| x ^ b);
        h[2] = check;
        h
    }

    #[test]
    fn bf54x_streams_load_their_blocks() {
        let mut data = header(BFLAG_IGNORE | 0x4000, 0xff80_0000, 0);
        data.extend(header(0x1, 0xffa0_0000, 8));
        data.extend_from_slice(&[0x10; 8]);
        data.extend(header(BFLAG_FILL, 0xff80_0100, 64));
        data.extend(header(BFLAG_FINAL, 0xffa0_0100, 4));
        data.extend_from_slice(&[0x20; 4]);
        assert_eq!(detect(&data), Some(Layout::Bf54x));
        let c = parse_container(&data, Layout::Bf54x).unwrap();
        assert_eq!(c.sections.len(), 2);
        assert_eq!(c.sections[0].address, 0xffa0_0000);
        let mut bad = data.clone();
        bad[20] ^= 1;
        assert!(parse_container(&bad, Layout::Bf54x).is_err());
        for end in 0..data.len() {
            assert!(
                parse_container(&data[..end], Layout::Bf54x).is_err(),
                "prefix {end}"
            );
        }
    }

    #[test]
    fn bf53x_streams_need_an_l1_first_block_and_a_final_block() {
        let mut data = Vec::new();
        for (address, count, flags, body) in [
            (0xffa0_0000u32, 4u32, 0u16, &[1u8, 2, 3, 4][..]),
            (0xffa0_0010, 4, BF53X_FINAL, &[5, 6, 7, 8][..]),
        ] {
            data.extend_from_slice(&address.to_le_bytes());
            data.extend_from_slice(&count.to_le_bytes());
            data.extend_from_slice(&flags.to_le_bytes());
            data.extend_from_slice(body);
        }
        assert_eq!(detect_weak(&data), Some(Layout::Bf53x));
        let mut sdram_first = data.clone();
        sdram_first[3] = 0x00;
        assert_eq!(detect_weak(&sdram_first), None);
        assert_eq!(detect_weak(&data[..data.len() - 1]), None);
    }
}
