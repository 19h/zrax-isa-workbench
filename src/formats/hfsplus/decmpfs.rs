//! decmpfs (`AppleFSCompression`) files: the `com.apple.decmpfs` attribute
//! in the attributes B-tree ([HFS] `HFSPlusAttrKey`, `HFSPlusAttrData`),
//! its header ([XNU] `decmpfs_disk_header`), and the compression types the
//! open-source readers document (The Sleuth Kit, libfshfs, apfs-fuse): data
//! stored in the attribute (type 1, [XNU] `CMP_Type1`), zlib, LZVN or LZFSE
//! in the attribute (types 3, 7, 11), and the same codecs as 64 KiB chunks
//! in the resource fork (types 4, 8, 12).

use super::catalog::name_text;
use super::*;
use crate::formats::compressed::{self, Codec};
use std::cmp::Ordering;

/// The attribute that holds a compressed file's header (`DECMPFS_XATTR_NAME`).
const DECMPFS_XATTR_NAME: &str = "com.apple.decmpfs";

/// `DECMPFS_MAGIC` (`cmpf`), stored little-endian.
const DECMPFS_MAGIC: u32 = 0x636d_7066;

/// `decmpfs_disk_header`: `compression_magic` (0), `compression_type` (4),
/// `uncompressed_size` (8), then the attribute bytes.
pub(super) const DECMPFS_HEADER_SIZE: usize = 16;

/// `MAX_DECMPFS_XATTR_SIZE`: the largest attribute xnu reads.
const MAX_DECMPFS_XATTR_SIZE: usize = 3802;

/// Compression types (`CMP_Type1` from [XNU]; the others from The Sleuth
/// Kit `DECMPFS_TYPE_*` and libfshfs `kAFSCType*`).
const CMP_TYPE1: u32 = 1;
const ZLIB_ATTRIBUTE: u32 = 3;
const ZLIB_RESOURCE_FORK: u32 = 4;
const LZVN_ATTRIBUTE: u32 = 7;
const LZVN_RESOURCE_FORK: u32 = 8;
const LZFSE_ATTRIBUTE: u32 = 11;
const LZFSE_RESOURCE_FORK: u32 = 12;

/// Decoded bytes per resource fork chunk (TSK `COMPRESSION_UNIT_SIZE`); a
/// stored chunk adds one marker byte.
const COMPRESSION_UNIT_SIZE: usize = 65_536;
const MAX_CHUNK_SIZE: usize = COMPRESSION_UNIT_SIZE + 1;

/// Markers of a unit stored without compression: a zlib unit whose first
/// byte has the low nibble 0xF (no zlib header has), and an LZVN unit that
/// starts with the end-of-stream opcode 0x06 (TSK
/// `decmpfs_decompress_zlib_block`, `decmpfs_decompress_lzvn_block`).
const ZLIB_STORED_NIBBLE: u8 = 0x0f;
const LZVN_STORED_MARKER: u8 = 0x06;

/// Attribute record types (`kHFSPlusAttrInlineData`, `kHFSPlusAttrForkData`).
const ATTR_INLINE_DATA: u32 = 0x10;
const ATTR_FORK_DATA: u32 = 0x20;

/// `HFSPlusAttrData`: `recordType` (0), `reserved[2]` (4), `attrSize`
/// (12), `attrData` (16).
const ATTR_DATA_SIZE_FIELD: usize = 12;
const ATTR_DATA_OFFSET: usize = 16;

/// `HFSPlusAttrKey` after `keyLength`: `pad` (0), `fileID` (2),
/// `startBlock` (6), `attrNameLen` (10), `attrName` (12).
const ATTR_KEY_FILE_ID: usize = 2;
const ATTR_KEY_NAME_LENGTH: usize = 10;
const ATTR_KEY_NAME: usize = 12;

/// The block table of a zlib resource fork follows the Resource Manager
/// header's `dataOffset` (big-endian, at 0) and the resource's 4-byte data
/// length.
const RESOURCE_LENGTH_SIZE: usize = 4;

/// How a compression unit is coded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Compression {
    /// Type 1: the data itself.
    Stored,
    Zlib,
    Lzvn,
    Lzfse,
}

impl Compression {
    /// Short name, for notes.
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Zlib => "zlib",
            Self::Lzvn => "LZVN",
            Self::Lzfse => "LZFSE",
        }
    }

    /// The slice transform of a decoded member.
    pub(super) fn transform(self) -> &'static str {
        match self {
            Self::Stored => "decmpfs attribute data",
            Self::Zlib => "decmpfs zlib",
            Self::Lzvn => "decmpfs LZVN",
            Self::Lzfse => "decmpfs LZFSE",
        }
    }
}

/// Where the compressed data is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Storage {
    /// After the header in the attribute.
    Attribute,
    /// In 64 KiB chunks in the resource fork.
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
    /// Parse and check the header of an attribute of `attribute_size`
    /// bytes, as xnu `decmpfs_fetch_compressed_header` checks it.
    pub(super) fn parse(attribute: &[u8]) -> Result<Self> {
        if !(DECMPFS_HEADER_SIZE..=MAX_DECMPFS_XATTR_SIZE).contains(&attribute.len()) {
            return Err(error(format!(
                "Invalid {DECMPFS_XATTR_NAME} attribute of {} B",
                attribute.len()
            )));
        }
        let magic = le_u32(attribute, 0)?;
        if magic != DECMPFS_MAGIC {
            return Err(error(format!(
                "Invalid {DECMPFS_XATTR_NAME} magic 0x{magic:08X}"
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
            _ => return None,
        };
        Some(Method {
            compression,
            storage,
        })
    }
}

/// A file's `com.apple.decmpfs` attribute.
pub(super) struct Attribute {
    /// The attribute's bytes (`attrData`).
    pub(super) bytes: Vec<u8>,
    /// File offset of the attribute's first byte, when its node is mapped.
    pub(super) offset: Option<usize>,
}

/// An attribute key: the file and the attribute name (UTF-16BE).
struct AttributeKey<'k> {
    file_id: u32,
    name: &'k [u8],
}

impl<'k> AttributeKey<'k> {
    fn parse(key: &'k [u8]) -> Result<Self> {
        let length = usize::from(be_u16(key, ATTR_KEY_NAME_LENGTH)?);
        let name = slice(key, ATTR_KEY_NAME, 2 * length)
            .map_err(|_| error(format!("Invalid attribute key of {} B", key.len())))?;
        Ok(Self {
            file_id: be_u32(key, ATTR_KEY_FILE_ID)?,
            name,
        })
    }
}

impl Filesystem<'_> {
    /// The `com.apple.decmpfs` attribute of `file_id`. Attribute keys sort
    /// by `fileID` first, so a file's attributes are consecutive from the
    /// first key with its `fileID`.
    pub(super) fn decmpfs_attribute(&self, file_id: u32) -> ReadResult<Option<Attribute>> {
        let Some(tree) = &self.attributes else {
            return Ok(None);
        };
        let order = |key: &[u8]| {
            let key = AttributeKey::parse(key)?;
            Ok(key.file_id.cmp(&file_id).then(if key.name.is_empty() {
                Ordering::Equal
            } else {
                Ordering::Greater
            }))
        };
        let Some(mut cursor) = tree.lower_bound(&self.vol, &order)? else {
            return Ok(None);
        };
        while let Some(record) = cursor.next(tree, &self.vol)? {
            let key = AttributeKey::parse(record.key)?;
            if key.file_id != file_id {
                return Ok(None);
            }
            if name_text(key.name) != DECMPFS_XATTR_NAME {
                continue;
            }
            let record_type = be_u32(record.data, 0)?;
            if record_type == ATTR_FORK_DATA {
                return invalid(format!(
                    "Unsupported {DECMPFS_XATTR_NAME} attribute stored in extents"
                ));
            }
            if record_type != ATTR_INLINE_DATA {
                return invalid(format!(
                    "Invalid {DECMPFS_XATTR_NAME} attribute record type 0x{record_type:X}"
                ));
            }
            let size = be_u32(record.data, ATTR_DATA_SIZE_FIELD)? as usize;
            let bytes = slice(record.data, ATTR_DATA_OFFSET, size).map_err(|_| {
                error(format!(
                    "Truncated {DECMPFS_XATTR_NAME} attribute: {size} B in a record of {} B",
                    record.data.len()
                ))
            })?;
            let offset = tree.file_offset(
                &self.vol,
                record.node,
                record.data_offset + ATTR_DATA_OFFSET,
            );
            return Ok(Some(Attribute {
                bytes: bytes.to_vec(),
                offset,
            }));
        }
        Ok(None)
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
    let first = unit.first().copied();
    let decoded = match compression {
        Compression::Stored => unit.to_vec(),
        _ if first.is_none() => {
            return Err(error("Truncated decmpfs data: an empty compression unit"))
        }
        Compression::Zlib
            if first.is_some_and(|b| b & ZLIB_STORED_NIBBLE == ZLIB_STORED_NIBBLE) =>
        {
            unit[1..].to_vec()
        }
        Compression::Lzvn if first == Some(LZVN_STORED_MARKER) => unit[1..].to_vec(),
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
        .ok_or_else(|| error(format!("Truncated {DECMPFS_XATTR_NAME} attribute")))?;
    decode_unit(compression, payload, size)
}

/// Bytes of the data after an attribute's header.
pub(super) fn attribute_payload_size(attribute: &[u8]) -> usize {
    attribute.len().saturating_sub(DECMPFS_HEADER_SIZE)
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

/// The block table of a zlib resource fork (type 4): at the Resource
/// Manager `dataOffset` plus the 4-byte resource length, a little-endian
/// count and count pairs of offset (from the table) and size.
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
    let entries = slice(fork, table + 4, 8 * count)?;
    let mut chunks = Vec::with_capacity(count);
    for entry in entries.chunks_exact(8) {
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

/// Decode the chunks of a compressed resource fork for a file of `size`
/// bytes, stopping once `limit` bytes are decoded (at most `size`).
pub(super) fn decode_resource_fork(
    compression: Compression,
    fork: &[u8],
    size: usize,
    limit: usize,
) -> Result<Vec<u8>> {
    let count = chunk_count(size);
    let chunks = match compression {
        Compression::Zlib => zlib_chunks(fork, count)?,
        Compression::Lzvn | Compression::Lzfse => offset_chunks(fork, count)?,
        Compression::Stored => {
            return Err(error(
                "Invalid decmpfs type: stored data in the resource fork",
            ))
        }
    };
    let mut decoded = Vec::with_capacity(limit.min(size));
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
        assert!(Header::parse(&bad[..15]).is_err());
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
    }

    #[test]
    fn offset_tables_must_match_the_chunk_count() {
        // Two chunks: table of 12 B, chunks at 12..14 and 14..17.
        let mut fork = Vec::new();
        for offset in [12u32, 14, 17] {
            fork.extend(offset.to_le_bytes());
        }
        fork.extend(b"\x06a\x06bc");
        let chunks = offset_chunks(&fork, 2).unwrap();
        assert_eq!(
            chunks,
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
    }
}
