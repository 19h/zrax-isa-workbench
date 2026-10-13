//! Compressed and packed console disc containers: Dolphin GCZ, `GameCube`
//! and Wii CISO, WBFS (Wii Backup File System), and PSP CSO and ZSO
//! images.
//!
//! Sources (pins and hashes in `docs/discimg.md`):
//! - GCZ: Dolphin tag `2606` (`6094cfcf7b8f`),
//!   `Source/Core/DiscIO/CompressedBlob.h` and `CompressedBlob.cpp` (header,
//!   block pointer and hash tables, zlib blocks), `DiscUtils.cpp`
//!   (`IsDiscImageBlockSizeValid`) and `Source/Core/DolphinTool/
//!   ConvertCommand.cpp` (sub-type values). See [`gcz`].
//! - CISO: Dolphin `CISOBlob.h` and `CISOBlob.cpp`; Wiimms ISO Tools
//!   `fc1c0b840cb3` `project/src/lib-ciso.h` and `lib-ciso.c`. See
//!   [`ciso`].
//! - WBFS: Dolphin `WbfsBlob.h` and `WbfsBlob.cpp`; Wiimms ISO Tools
//!   `project/src/libwbfs/file-formats.h`, `libwbfs.h`, `libwbfs.c` and
//!   `project/src/wbfs-interface.c`. See [`wbfs`].
//! - CSO and ZSO: maxcso v1.13.0 (`80e6e8349814`) `README_CSO.md`,
//!   `README_ZSO.md`, `src/cso.h` and `src/input.cpp`; PPSSPP v1.17.1
//!   (`d479b74ed9c3`) `Core/FileSystems/BlockDevices.cpp`. See [`cso`].
//!
//! Each container stores a disc image in blocks, compressed (GCZ, CSO,
//! ZSO) or left out when unused (CISO, WBFS). The decoded disc is one child
//! per disc (WBFS holds one per used slot): its first `min(disc size,
//! MAX_PAYLOAD)` bytes, with blocks that are not stored read as zeros. The
//! child is classified on its own, so the console disc parsers or ISO 9660
//! describe it. None of these containers names an ISA.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::{self, size_text, Codec};
use crate::formats::container::{Child, Container};
use crate::formats::MAX_PAYLOAD;
use crate::types::FileFormat;
use std::borrow::Cow;

mod ciso;
mod cso;
mod gcz;
mod wbfs;

/// A PSP compressed ISO flavour (maxcso `README_CSO.md`, `README_ZSO.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cso {
    /// `CISO` version 0 or 1: raw DEFLATE blocks; the high index bit marks
    /// a block stored uncompressed.
    V1,
    /// `CISO` version 2: a block whose stored length is at least the block
    /// size is uncompressed; others are LZ4 (high index bit) or DEFLATE.
    V2,
    /// `ZISO`: LZ4 blocks; the high index bit marks a block stored
    /// uncompressed.
    Zso,
}

/// A disc container layout recognized by its magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Dolphin GCZ: magic 0xB10BC001 (little-endian) with a consistent
    /// block count.
    Gcz,
    /// `GameCube` or Wii CISO: `CISO`, a block size that is a multiple of
    /// 32 KiB and a block map of 0 and 1 bytes.
    Ciso,
    /// WBFS image: `WBFS` with plausible sector shifts.
    Wbfs,
    /// PSP CSO or ZSO image: `CISO` or `ZISO` with a power-of-two block
    /// size of at least 2 KiB and version 0 to 2.
    Cso(Cso),
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Gcz => FileFormat::Gcz,
            Self::Ciso => FileFormat::Ciso,
            Self::Wbfs => FileFormat::Wbfs,
            Self::Cso(_) => FileFormat::Cso,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Gcz => "GCZ disc image",
            Self::Ciso => "CISO disc image",
            Self::Wbfs => "WBFS image",
            Self::Cso(Cso::V1) => "CSO v1 image",
            Self::Cso(Cso::V2) => "CSO v2 image",
            Self::Cso(Cso::Zso) => "ZSO image",
        }
    }

    /// Recognized from complete structure rather than a magic value. Every
    /// layout has a four-byte magic at offset 0 and header fields that
    /// detection checks, so none is weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Gcz | Self::Ciso | Self::Wbfs | Self::Cso(_) => false,
        }
    }
}

/// Strong recognition: the GCZ, `WBFS`, `CISO` or `ZISO` magic at offset 0
/// and the header fields that every reader needs. A `GameCube` CISO and a
/// PSP CSO both start with `CISO`; the `GameCube` block map is tested first
/// (see [`ciso::detect`]).
pub fn detect(data: &[u8]) -> Option<Layout> {
    gcz::detect(data)
        .or_else(|| wbfs::detect(data))
        .or_else(|| ciso::detect(data))
        .or_else(|| cso::detect(data))
}

/// Parse a disc container into the shared container model.
///
/// # Errors
///
/// [`ClassifierError::DiscImageParseError`] for a truncated or inconsistent
/// header or block table, a block that does not decode to its size, a
/// block the decoded disc needs that lies outside the file, or bytes other
/// than padding after the stored data.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    match layout {
        Layout::Gcz => gcz::parse(data),
        Layout::Ciso => ciso::parse(data),
        Layout::Wbfs => wbfs::parse(data),
        Layout::Cso(version) => cso::parse(data, version),
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::DiscImageParseError {
        message: message.into(),
    }
}

/// The `len` bytes at `start`, named `what` in the error.
fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    start
        .checked_add(len)
        .and_then(|end| data.get(start..end))
        .ok_or_else(|| error(format!("Truncated {what} at 0x{start:X} + {len} B")))
}

/// The bytes `start..start + len` of `data` for a range computed from the
/// container, or `None` when it does not lie in the file.
fn range(data: &[u8], start: u64, len: u64) -> Option<&[u8]> {
    let start = usize::try_from(start).ok()?;
    let len = usize::try_from(len).ok()?;
    data.get(start..start.checked_add(len)?)
}

fn array<const N: usize>(data: &[u8], at: usize, what: &str) -> Result<[u8; N]> {
    Ok(slice(data, at, N, what)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn le_u32(data: &[u8], at: usize, what: &str) -> Result<u32> {
    Ok(u32::from_le_bytes(array(data, at, what)?))
}

fn le_u64(data: &[u8], at: usize, what: &str) -> Result<u64> {
    Ok(u64::from_le_bytes(array(data, at, what)?))
}

fn be_u16(data: &[u8], at: usize, what: &str) -> Result<u16> {
    Ok(u16::from_be_bytes(array(data, at, what)?))
}

fn be_u32(data: &[u8], at: usize, what: &str) -> Result<u32> {
    Ok(u32::from_be_bytes(array(data, at, what)?))
}

/// `value / divisor`, rounded up; `divisor` is nonzero.
fn div_ceil(value: u64, divisor: u64) -> u64 {
    value / divisor + u64::from(value % divisor != 0)
}

/// `value` rounded up to a multiple of `alignment`, a power of two.
fn align_up(value: u64, alignment: u64) -> Option<u64> {
    Some(value.checked_add(alignment - 1)? & !(alignment - 1))
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xFF))
}

/// `n` with the singular or plural noun.
fn counted(n: u64, singular: &str, plural: &str) -> String {
    format!("{n} {}", if n == 1 { singular } else { plural })
}

/// The message of a codec error without the compressed-stream prefix, for
/// an error that names the block.
fn codec_message(e: ClassifierError) -> String {
    match e {
        ClassifierError::CompressedParseError { message } => message,
        other => other.to_string(),
    }
}

/// Decode the block named `what` with `codec` into at most `limit` bytes.
/// Raw LZ4 blocks stop at the limit, because the stored length may include
/// alignment padding after the stream (maxcso `README_ZSO.md`).
fn decode_block(codec: Codec, stored: &[u8], limit: usize, what: &str) -> Result<Vec<u8>> {
    let decoded = match codec {
        Codec::Lz4Block => compressed::decode_prefix(codec, stored, limit),
        _ => compressed::decode_limited(codec, stored, limit).map(|decoded| decoded.data),
    };
    decoded.map_err(|e| error(format!("Invalid {what}: {}", codec_message(e))))
}

/// Text up to the first NUL of `raw`: printable ASCII kept, every other
/// byte shown as U+FFFD. Game IDs are ASCII letters and digits.
fn ascii_text(raw: &[u8]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    raw[..end]
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '\u{FFFD}'
            }
        })
        .collect()
}

/// A decoded disc: its first `min(size, MAX_PAYLOAD)` bytes, zero where no
/// block has been copied in.
struct Disc {
    /// The disc size in bytes, as the container states or implies it.
    size: u64,
    /// The decoded prefix.
    bytes: Vec<u8>,
}

impl Disc {
    /// A zeroed prefix of a disc of `size` bytes. `size` comes from a
    /// validated header, and the allocation is capped at [`MAX_PAYLOAD`].
    fn new(size: u64) -> Self {
        let len = usize::try_from(size).map_or(MAX_PAYLOAD, |size| size.min(MAX_PAYLOAD));
        Self {
            size,
            bytes: vec![0; len],
        }
    }

    /// How many blocks of `block_size` bytes (nonzero) the prefix touches.
    fn blocks(&self, block_size: u64) -> u64 {
        div_ceil(self.bytes.len() as u64, block_size)
    }

    /// The prefix bytes that block `index` covers, for blocks of
    /// `block_size` bytes; empty when the block starts past the prefix.
    fn block_mut(&mut self, index: u64, block_size: u64) -> &mut [u8] {
        let len = self.bytes.len() as u64;
        let start = index.saturating_mul(block_size).min(len);
        let end = start.saturating_add(block_size).min(len);
        let start = usize::try_from(start).expect("the prefix fits in memory");
        let end = usize::try_from(end).expect("the prefix fits in memory");
        &mut self.bytes[start..end]
    }

    /// Whether the prefix is the whole disc.
    fn is_complete(&self) -> bool {
        self.bytes.len() as u64 == self.size
    }
}

/// Where a disc's stored bytes lie in the file, as its child reports them:
/// the data area, or the first run of consecutive blocks when they are
/// scattered.
#[derive(Debug, Clone, Copy)]
struct StoredSpan {
    /// File offset of the stored bytes.
    offset: usize,
    /// Stored size in bytes.
    size: usize,
}

/// Add `disc` as a child decoded through `transform`, with a note when only
/// a prefix of it was decoded.
fn push_disc(
    c: &mut Container<'_>,
    label: String,
    disc: Disc,
    stored: StoredSpan,
    transform: &'static str,
) {
    if !disc.is_complete() {
        c.notes.push(format!(
            "{label} is {} B; only the first {} were decoded and are analyzed",
            disc.size,
            size_text(MAX_PAYLOAD)
        ));
    }
    c.children.push(Child::decoded(
        label,
        stored.offset,
        stored.size,
        Cow::Owned(disc.bytes),
        transform,
    ));
}

/// Compare `end`, where the stored data named `what` ends by the header,
/// with the file and set the container size. A shorter file gets a note:
/// blocks past its end are not in this file (a truncated or split image),
/// and reading one that the decoded disc needs is an error. Bytes after the
/// end must be padding.
fn check_extent(c: &mut Container<'_>, data: &[u8], end: u64, what: &str) -> Result<()> {
    let len = data.len() as u64;
    if end > len {
        c.notes.push(format!(
            "The file holds {len} B of the {end} B up to the end of {what}; blocks past the end of the file are not in it"
        ));
        c.consumed = data.len();
        return Ok(());
    }
    let end = usize::try_from(end).expect("the end lies in the file");
    let trailing = &data[end..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} after {what} at 0x{end:X}",
            size_text(trailing.len())
        )));
    }
    c.consumed = end;
    Ok(())
}

/// The note every layout ends with: the container names no ISA.
fn push_no_isa_note(c: &mut Container<'_>, what: &str) {
    c.notes.push(format!(
        "{what} names no ISA; each decoded disc is classified on its own"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disc_blocks_cover_the_prefix_only() {
        let mut disc = Disc::new(10);
        assert_eq!(disc.blocks(4), 3);
        assert_eq!(disc.block_mut(2, 4).len(), 2);
        assert_eq!(disc.block_mut(3, 4).len(), 0);
        assert_eq!(disc.block_mut(u64::MAX, u64::MAX).len(), 0);
        assert!(disc.is_complete());
        let large = Disc::new(u64::MAX);
        assert_eq!(large.bytes.len(), MAX_PAYLOAD);
        assert!(!large.is_complete());
    }

    #[test]
    fn helpers_round_and_bound() {
        assert_eq!(div_ceil(0, 4), 0);
        assert_eq!(div_ceil(9, 4), 3);
        assert_eq!(div_ceil(u64::MAX, 1), u64::MAX);
        assert_eq!(align_up(0x100 + 2 * 4482, 512), Some(9728));
        assert_eq!(align_up(u64::MAX, 512), None);
        assert!(range(&[0; 4], 2, 3).is_none());
        assert!(range(&[0; 4], u64::MAX, 1).is_none());
        assert!(slice(&[0; 4], usize::MAX, 2, "test").is_err());
        assert_eq!(ascii_text(b"RZRP01\0junk"), "RZRP01");
        assert_eq!(ascii_text(b"A\x82B"), "A\u{FFFD}B");
        assert_eq!(counted(1, "disc", "discs"), "1 disc");
        assert_eq!(counted(2, "disc", "discs"), "2 discs");
    }

    #[test]
    fn codec_errors_lose_their_prefix() {
        let message = codec_message(compressed::decode(Codec::Zlib, b"\x78\x9c").unwrap_err());
        assert!(
            !message.starts_with("Compressed stream parse error"),
            "{message}"
        );
        assert!(message.starts_with("Truncated zlib stream"), "{message}");
    }
}
