//! decmpfs (`AppleFSCompression`) files: the `com.apple.decmpfs` attribute
//! and its header ([XNU] `decmpfs_disk_header`), and the compression types
//! [FUSE] `Decmpfs.cpp` reads: data in the attribute (type 1, [XNU]
//! `CMP_Type1`, and type 9 after a `0xCC` marker), zlib, LZVN or LZFSE
//! after the header in the attribute (types 3, 7, 11), and the same codecs
//! as 64 KiB chunks in the `com.apple.ResourceFork` attribute (types 4, 8,
//! 12). On APFS either attribute may be embedded in its record or stored as
//! a data stream.

use super::*;
use crate::formats::compressed::{self, Codec};

/// `DECMPFS_XATTR_NAME` and `XATTR_RESOURCEFORK_NAME`.
pub(super) const DECMPFS_XATTR_NAME: &[u8] = b"com.apple.decmpfs";
pub(super) const RESOURCE_FORK_XATTR_NAME: &[u8] = b"com.apple.ResourceFork";

/// `UF_COMPRESSED` in `bsd_flags` ([XNU] `sys/stat.h`).
pub(super) const UF_COMPRESSED: u32 = 0x0000_0020;

/// `DECMPFS_MAGIC` (`cmpf`), stored little-endian.
const DECMPFS_MAGIC: u32 = 0x636d_7066;

/// `decmpfs_disk_header`: `compression_magic` (0), `compression_type` (4),
/// `uncompressed_size` (8), then the attribute bytes.
pub(super) const DECMPFS_HEADER_SIZE: usize = 16;

/// Compression types (`CMP_Type1` from [XNU]; the others from [FUSE]).
const CMP_TYPE1: u32 = 1;
const ZLIB_ATTRIBUTE: u32 = 3;
const ZLIB_RESOURCE_FORK: u32 = 4;
const LZVN_ATTRIBUTE: u32 = 7;
const LZVN_RESOURCE_FORK: u32 = 8;
const LZFSE_ATTRIBUTE: u32 = 11;
const LZFSE_RESOURCE_FORK: u32 = 12;
/// Type 9: the data itself after a marker byte ([FUSE] "Uncompressed,
/// Attr"; the marker [FUSE] asserts).
const UNCOMPRESSED_ATTRIBUTE: u32 = 9;
const UNCOMPRESSED_MARKER: u8 = 0xcc;

/// Decoded bytes per resource fork chunk; a stored chunk adds one marker
/// byte ([FUSE] rejects chunks over 0x10001 B).
const COMPRESSION_UNIT_SIZE: usize = 65_536;
const MAX_CHUNK_SIZE: usize = COMPRESSION_UNIT_SIZE + 1;

/// Markers of a unit stored without compression: a zlib unit whose first
/// byte has the low nibble 0xF (no zlib header has), and an LZVN unit that
/// starts with the end-of-stream opcode 0x06 ([FUSE] `DecompressFile`).
const ZLIB_STORED_NIBBLE: u8 = 0x0f;
const LZVN_STORED_MARKER: u8 = 0x06;

/// The zlib block table follows the Resource Manager header's `dataOffset`
/// (big-endian, at 0) and the resource's 4-byte length; each entry is a
/// little-endian offset (from the table) and size.
const RESOURCE_LENGTH_SIZE: usize = 4;
const ZLIB_TABLE_ENTRY_SIZE: usize = 8;

/// How a compression unit is coded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Compression {
    /// Type 1: the data itself.
    Stored,
    /// Type 9: a `0xCC` marker byte, then the data itself.
    Raw,
    Zlib,
    Lzvn,
    Lzfse,
}

impl Compression {
    /// Short name, for notes.
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Raw => "raw",
            Self::Zlib => "zlib",
            Self::Lzvn => "LZVN",
            Self::Lzfse => "LZFSE",
        }
    }

    /// The slice transform of a decoded member.
    pub(super) fn transform(self) -> &'static str {
        match self {
            Self::Stored => "decmpfs attribute data",
            Self::Raw => "decmpfs raw",
            Self::Zlib => "decmpfs zlib",
            Self::Lzvn => "decmpfs LZVN",
            Self::Lzfse => "decmpfs LZFSE",
        }
    }
}

/// Where the compressed data is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Storage {
    /// After the header in the `com.apple.decmpfs` attribute.
    Attribute,
    /// In 64 KiB chunks in the `com.apple.ResourceFork` attribute.
    ResourceFork,
}

/// A compression type the reader decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Method {
    pub(super) compression: Compression,
    pub(super) storage: Storage,
}

/// A `decmpfs_disk_header`.
#[derive(Debug, Clone, Copy)]
pub(super) struct Header {
    /// `compression_type`.
    pub(super) compression_type: u32,
    /// `uncompressed_size`: the file's size in bytes.
    pub(super) size: u64,
}

impl Header {
    /// The header at the start of a `com.apple.decmpfs` attribute.
    pub(super) fn parse(attribute: &[u8]) -> Result<Self> {
        if attribute.len() < DECMPFS_HEADER_SIZE {
            return Err(error(format!(
                "Invalid com.apple.decmpfs attribute of {} B",
                attribute.len()
            )));
        }
        let magic = le_u32(attribute, 0)?;
        if magic != DECMPFS_MAGIC {
            return Err(error(format!(
                "Invalid com.apple.decmpfs magic 0x{magic:08X}"
            )));
        }
        Ok(Self {
            compression_type: le_u32(attribute, 4)?,
            size: le_u64(attribute, 8)?,
        })
    }

    /// The method of a compression type the reader decodes.
    pub(super) fn method(&self) -> Option<Method> {
        let (compression, storage) = match self.compression_type {
            CMP_TYPE1 => (Compression::Stored, Storage::Attribute),
            ZLIB_ATTRIBUTE => (Compression::Zlib, Storage::Attribute),
            ZLIB_RESOURCE_FORK => (Compression::Zlib, Storage::ResourceFork),
            LZVN_ATTRIBUTE => (Compression::Lzvn, Storage::Attribute),
            LZVN_RESOURCE_FORK => (Compression::Lzvn, Storage::ResourceFork),
            LZFSE_ATTRIBUTE => (Compression::Lzfse, Storage::Attribute),
            LZFSE_RESOURCE_FORK => (Compression::Lzfse, Storage::ResourceFork),
            UNCOMPRESSED_ATTRIBUTE => (Compression::Raw, Storage::Attribute),
            _ => return None,
        };
        Some(Method {
            compression,
            storage,
        })
    }
}

/// Decode a compression unit (the data after an attribute's header, or a
/// resource fork chunk) that must decode to exactly `size` bytes.
fn decode_unit(compression: Compression, unit: &[u8], size: usize) -> Result<Vec<u8>> {
    let decode = |codec| {
        compressed::decode_limited(codec, unit, size)
            .map(|decoded| decoded.data)
            .map_err(|e| error(format!("Invalid decmpfs data: {e}")))
    };
    let Some(&first) = unit.first() else {
        if compression == Compression::Stored && size == 0 {
            return Ok(Vec::new());
        }
        return Err(error("Truncated decmpfs data: an empty compression unit"));
    };
    let decoded = match compression {
        Compression::Stored => unit.to_vec(),
        Compression::Raw if first == UNCOMPRESSED_MARKER => unit[1..].to_vec(),
        Compression::Raw => {
            return Err(error(format!(
                "Invalid decmpfs type 9 data: marker 0x{first:02X}, 0xCC expected"
            )))
        }
        Compression::Zlib if first & ZLIB_STORED_NIBBLE == ZLIB_STORED_NIBBLE => unit[1..].to_vec(),
        Compression::Lzvn if first == LZVN_STORED_MARKER => unit[1..].to_vec(),
        Compression::Zlib => decode(Codec::Zlib)?,
        Compression::Lzvn => decode(Codec::Lzvn)?,
        Compression::Lzfse => decode(Codec::Lzfse)?,
    };
    if decoded.len() != size {
        return Err(error(format!(
            "Invalid decmpfs data: {} B decoded, {size} B expected",
            decoded.len()
        )));
    }
    Ok(decoded)
}

/// Decode the data stored after the header of an attribute.
pub(super) fn decode_attribute(
    compression: Compression,
    attribute: &[u8],
    size: usize,
) -> Result<Vec<u8>> {
    let payload = attribute
        .get(DECMPFS_HEADER_SIZE..)
        .ok_or_else(|| error("Truncated com.apple.decmpfs attribute"))?;
    decode_unit(compression, payload, size)
}

/// A chunk of a compressed resource fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Chunk {
    /// Offset in the fork.
    offset: usize,
    /// Stored size.
    size: usize,
}

/// Chunks of 64 KiB that hold `size` bytes.
fn chunk_count(size: usize) -> usize {
    size / COMPRESSION_UNIT_SIZE + usize::from(size % COMPRESSION_UNIT_SIZE != 0)
}

/// A chunk that must lie in the fork and fit a 64 KiB unit.
fn chunk_in(fork: &[u8], offset: usize, size: usize) -> Result<Chunk> {
    let fits = offset
        .checked_add(size)
        .is_some_and(|end| end <= fork.len());
    if size > MAX_CHUNK_SIZE || !fits {
        return Err(error(format!(
            "Invalid decmpfs chunk at 0x{offset:X} + {size} B in a resource fork of {} B",
            fork.len()
        )));
    }
    Ok(Chunk { offset, size })
}

/// The block table of a zlib resource fork (type 4): after the Resource
/// Manager `dataOffset` and the resource length, a little-endian count and
/// that many pairs of offset (from the count) and size.
fn zlib_chunks(fork: &[u8], count: usize) -> Result<Vec<Chunk>> {
    let data_offset = be_u32(fork, 0)? as usize;
    let table = data_offset
        .checked_add(RESOURCE_LENGTH_SIZE)
        .ok_or_else(|| error("Invalid decmpfs resource fork data offset"))?;
    let stated = le_u32(fork, table)? as usize;
    if stated != count {
        return Err(error(format!(
            "Invalid decmpfs zlib block table at 0x{table:X}: {stated} blocks, {count} expected"
        )));
    }
    let entries = slice(fork, table + 4, ZLIB_TABLE_ENTRY_SIZE * count)?;
    let mut chunks = Vec::with_capacity(count);
    for entry in entries.chunks_exact(ZLIB_TABLE_ENTRY_SIZE) {
        let offset = le_u32(entry, 0)? as usize;
        let size = le_u32(entry, 4)? as usize;
        chunks.push(chunk_in(fork, table.saturating_add(offset), size)?);
    }
    Ok(chunks)
}

/// The offset table of an LZVN or LZFSE resource fork (types 8, 12):
/// count + 1 little-endian offsets from the fork start, the first being the
/// table's own size; chunk `i` lies between offsets `i` and `i + 1`.
fn offset_chunks(fork: &[u8], count: usize) -> Result<Vec<Chunk>> {
    let table_size = 4 * (count + 1);
    let stated = le_u32(fork, 0)? as usize;
    if stated != table_size {
        return Err(error(format!(
            "Invalid decmpfs chunk table: {stated} B, {table_size} B expected"
        )));
    }
    let table = slice(fork, 0, table_size)?;
    let mut chunks = Vec::with_capacity(count);
    for pair in table.windows(8).step_by(4) {
        let start = le_u32(pair, 0)? as usize;
        let end = le_u32(pair, 4)? as usize;
        let size = end.checked_sub(start).ok_or_else(|| {
            error(format!(
                "Invalid decmpfs chunk table: offset 0x{end:X} before 0x{start:X}"
            ))
        })?;
        chunks.push(chunk_in(fork, start, size)?);
    }
    Ok(chunks)
}

/// Decode the chunks of a compressed resource fork for a file of `size`
/// bytes, stopping once `limit` bytes are decoded (at most `size`).
pub(super) fn decode_resource_fork(
    compression: Compression,
    fork: &[u8],
    size: usize,
    limit: usize,
) -> Result<Vec<u8>> {
    let count = chunk_count(size);
    // Each chunk table entry takes at least 4 bytes, so a count that the
    // fork cannot hold is rejected before anything is allocated.
    if count > fork.len() / 4 {
        return Err(error(format!(
            "Invalid decmpfs resource fork: {} B cannot hold {count} chunks",
            fork.len()
        )));
    }
    let chunks = match compression {
        Compression::Zlib => zlib_chunks(fork, count)?,
        Compression::Lzvn | Compression::Lzfse => offset_chunks(fork, count)?,
        Compression::Stored | Compression::Raw => {
            return Err(error(
                "Invalid decmpfs type: stored data in the resource fork",
            ))
        }
    };
    // The output grows with the chunks that decode; the stated size only
    // bounds it.
    let mut decoded = Vec::with_capacity(limit.min(size).min(COMPRESSION_UNIT_SIZE));
    for (i, chunk) in chunks.iter().enumerate() {
        if decoded.len() >= limit {
            break;
        }
        let expected = (size - i * COMPRESSION_UNIT_SIZE).min(COMPRESSION_UNIT_SIZE);
        let unit = &fork[chunk.offset..chunk.offset + chunk.size];
        decoded.extend(decode_unit(compression, unit, expected)?);
    }
    Ok(decoded)
}

/// A big-endian 32-bit word (the Resource Manager header's byte order).
fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(compression_type: u32, size: u64) -> Vec<u8> {
        let mut attribute = DECMPFS_MAGIC.to_le_bytes().to_vec();
        attribute.extend(compression_type.to_le_bytes());
        attribute.extend(size.to_le_bytes());
        attribute
    }

    #[test]
    fn headers_name_their_methods() {
        let parsed = Header::parse(&header(LZVN_RESOURCE_FORK, 0x3_2000)).unwrap();
        assert_eq!(parsed.size, 0x3_2000);
        assert_eq!(
            parsed.method(),
            Some(Method {
                compression: Compression::Lzvn,
                storage: Storage::ResourceFork,
            })
        );
        assert_eq!(Header::parse(&header(13, 1)).unwrap().method(), None);
        let mut bad = header(ZLIB_ATTRIBUTE, 1);
        bad[0] ^= 1;
        assert!(Header::parse(&bad).is_err());
        assert!(Header::parse(&header(1, 1)[..15]).is_err());
    }

    #[test]
    fn stored_units_follow_their_marker_byte() {
        assert_eq!(
            decode_unit(Compression::Zlib, b"\xffabc", 3).unwrap(),
            b"abc"
        );
        assert_eq!(
            decode_unit(Compression::Lzvn, b"\x06abc", 3).unwrap(),
            b"abc"
        );
        assert!(decode_unit(Compression::Lzvn, b"\x06abc", 4).is_err());
        assert!(decode_unit(Compression::Zlib, b"", 0).is_err());
        assert_eq!(decode_unit(Compression::Stored, b"", 0).unwrap(), b"");
        assert_eq!(
            decode_unit(Compression::Raw, b"\xccabc", 3).unwrap(),
            b"abc"
        );
        assert!(decode_unit(Compression::Raw, b"abcd", 3).is_err());
    }

    #[test]
    fn offset_tables_must_match_the_chunk_count() {
        // Two chunks: a table of 12 B, chunks at 12..14 and 14..17.
        let mut fork = Vec::new();
        for offset in [12u32, 14, 17] {
            fork.extend(offset.to_le_bytes());
        }
        fork.extend(b"\x06a\x06bc");
        assert_eq!(
            offset_chunks(&fork, 2).unwrap(),
            [
                Chunk {
                    offset: 12,
                    size: 2
                },
                Chunk {
                    offset: 14,
                    size: 3
                }
            ]
        );
        assert!(offset_chunks(&fork, 1).is_err());
        assert!(offset_chunks(&fork[..16], 2).is_err());
        assert_eq!(chunk_count(COMPRESSION_UNIT_SIZE + 1), 2);
        assert!(decode_resource_fork(Compression::Lzvn, &fork, 64 << 20, 1).is_err());
    }
}
