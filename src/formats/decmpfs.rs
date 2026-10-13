//! decmpfs (`AppleFSCompression`) file data, shared by the HFS+ and APFS
//! families: the header of the `com.apple.decmpfs` attribute ([XNU]
//! `decmpfs_disk_header`), the compression types the open-source readers
//! document, the chunk tables of a compressed resource fork, and decoding
//! through `compressed::decode_limited`. Each family locates the attribute
//! and the resource fork its own way (HFS+: the attributes B-tree and the
//! file's resource fork; APFS: the `com.apple.decmpfs` and
//! `com.apple.ResourceFork` extended attributes) and supplies its error
//! variant and bounds-checked reads through [`Family`].
//!
//! Sources:
//! - [XNU] apple-oss-distributions/xnu tag `xnu-11215.1.10`:
//!   `bsd/sys/decmpfs.h` (`decmpfs_disk_header`, `DECMPFS_MAGIC`,
//!   `DECMPFS_XATTR_NAME`, `MAX_DECMPFS_XATTR_SIZE`, `CMP_Type1`) and
//!   `bsd/kern/decmpfs.c` (`decmpfs_fetch_compressed_header`,
//!   `decmpfs_validate_compressed_file_Type1`).
//! - The types above 1, which `AppleFSCompression` (closed source) defines:
//!   [FUSE] sgan81/apfs-fuse commit
//!   `66b86bd525e8cb90f9012543be89b1f092b75cf3`, `ApfsLib/Decmpfs.cpp`
//!   (`DecompressFile`: types 3, 4, 7, 8, 9, 11 and 12, the chunk tables and
//!   the stored-chunk markers); [FSHFS] libyal/libfshfs commit
//!   `78321de1eda54b30261adf59b938781128591b2e`, "Hierarchical File System
//!   (HFS).asciidoc", "Compression method" and "Raw compressed data"; [TSK]
//!   The Sleuth Kit `sleuthkit-4.12.1`, `tsk/fs/decmpfs.h`
//!   (`DECMPFS_TYPE_*`, `COMPRESSION_UNIT_SIZE`) and `tsk/fs/decmpfs.c`.
//!
//! The header, the zlib block table entries and the LZVN and LZFSE offset
//! tables are little-endian; the Resource Manager header of a type 4 fork is
//! big-endian. Sizes are bytes of decoded file data; offsets are bytes from
//! the start of the attribute or the resource fork.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::{self, Codec};

/// `DECMPFS_XATTR_NAME`: the attribute that holds a compressed file's
/// header.
pub(crate) const DECMPFS_XATTR_NAME: &str = "com.apple.decmpfs";

/// `DECMPFS_MAGIC` (`cmpf`), stored little-endian.
const DECMPFS_MAGIC: u32 = 0x636d_7066;

/// `decmpfs_disk_header`: `compression_magic` (0), `compression_type` (4),
/// `uncompressed_size` (8), then the attribute bytes.
pub(crate) const DECMPFS_HEADER_SIZE: usize = 16;

/// `MAX_DECMPFS_XATTR_SIZE`: the largest attribute xnu reads
/// (`decmpfs_fetch_compressed_header`).
pub(crate) const MAX_DECMPFS_XATTR_SIZE: usize = 3802;

/// Compression types: `CMP_Type1` from [XNU]; the others as [FUSE] and
/// [FSHFS] number them (`kAFSCType*`).
const CMP_TYPE1: u32 = 1;
const ZLIB_ATTRIBUTE: u32 = 3;
const ZLIB_RESOURCE_FORK: u32 = 4;
const LZVN_ATTRIBUTE: u32 = 7;
const LZVN_RESOURCE_FORK: u32 = 8;
const LZFSE_ATTRIBUTE: u32 = 11;
const LZFSE_RESOURCE_FORK: u32 = 12;
/// Type 9 (`kAFSCTypeRawChunk`, [FUSE] "Uncompressed, Attr"): the data
/// itself after a marker byte, which [FUSE] asserts and [FSHFS] describes.
const RAW_ATTRIBUTE: u32 = 9;
const RAW_MARKER: u8 = 0xcc;

/// Decoded bytes per resource fork chunk ([TSK] `COMPRESSION_UNIT_SIZE`); a
/// stored chunk adds one marker byte ([FUSE] rejects chunks over 0x10001 B).
const COMPRESSION_UNIT_SIZE: usize = 65_536;
const MAX_CHUNK_SIZE: usize = COMPRESSION_UNIT_SIZE + 1;

/// Markers of a unit stored without compression: a zlib unit whose first
/// byte has the low nibble 0xF (no zlib header has), and an LZVN unit that
/// starts with the end-of-stream opcode 0x06 ([FUSE] `DecompressFile`;
/// [TSK] `decmpfs_decompress_zlib_block`, `decmpfs_decompress_lzvn_block`).
const ZLIB_STORED_NIBBLE: u8 = 0x0f;
const LZVN_STORED_MARKER: u8 = 0x06;

/// The zlib block table follows the Resource Manager header's `dataOffset`
/// (big-endian, at 0) and the resource's 4-byte length; after its 4-byte
/// count, each entry is a little-endian offset (from the count) and size.
const RESOURCE_LENGTH_SIZE: usize = 4;
const ZLIB_TABLE_COUNT_SIZE: usize = 4;
const ZLIB_TABLE_ENTRY_SIZE: usize = 8;

/// Each entry of an LZVN or LZFSE offset table is a little-endian 32-bit
/// offset.
const OFFSET_TABLE_ENTRY_SIZE: usize = 4;

/// The file-system family whose file is decoded. Problems are reported in
/// the family's own error variant, and reads past the end of an attribute
/// or fork in the family's own wording. The constants are the checks in
/// which the HFS+ and APFS readers differed before they shared this
/// decoder; each family keeps its own (AGENTS.md section 6, step 6).
pub(crate) trait Family {
    /// The largest `com.apple.decmpfs` attribute accepted, in bytes.
    const MAX_ATTRIBUTE_SIZE: usize;

    /// Whether a resource fork too small to hold a 4-byte table entry per
    /// chunk is refused before its chunk table is read. Otherwise the chunk
    /// table read reports what it finds.
    const REFUSES_SHORT_FORKS: bool;

    /// Whether type 1 data that is empty although the file is not is
    /// reported as a truncated unit. Otherwise it is reported as data of
    /// the wrong size.
    const EMPTY_TYPE1_IS_TRUNCATED: bool;

    /// The family's parse error with `message`.
    fn error(message: impl Into<String>) -> ClassifierError;

    /// The `len` bytes at `start` of `data`, or the family's error for a
    /// range outside it.
    fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]>;
}

fn be_u32<F: Family>(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = F::slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_be_bytes(bytes))
}

fn le_u32<F: Family>(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = F::slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_le_bytes(bytes))
}

fn le_u64<F: Family>(data: &[u8], at: usize) -> Result<u64> {
    let bytes: [u8; 8] = F::slice(data, at, 8)?
        .try_into()
        .expect("slice has exactly 8 bytes");
    Ok(u64::from_le_bytes(bytes))
}

/// How a compression unit is coded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Compression {
    /// Type 1: the data itself.
    Stored,
    /// Type 9: a `0xCC` marker byte, then the data itself.
    Raw,
    /// Types 3 and 4.
    Zlib,
    /// Types 7 and 8.
    Lzvn,
    /// Types 11 and 12.
    Lzfse,
}

impl Compression {
    /// Short name, for notes.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Raw => "raw",
            Self::Zlib => "zlib",
            Self::Lzvn => "LZVN",
            Self::Lzfse => "LZFSE",
        }
    }

    /// The slice transform of a decoded member.
    pub(crate) fn transform(self) -> &'static str {
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
pub(crate) enum Storage {
    /// After the header in the `com.apple.decmpfs` attribute.
    Attribute,
    /// In 64 KiB chunks in the resource fork (on APFS, the
    /// `com.apple.ResourceFork` attribute).
    ResourceFork,
}

/// A compression type the decoder reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Method {
    /// How each unit is coded.
    pub(crate) compression: Compression,
    /// Where the units are.
    pub(crate) storage: Storage,
}

/// A `decmpfs_disk_header`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Header {
    /// `compression_type`.
    pub(crate) compression_type: u32,
    /// `uncompressed_size`: the file's size in bytes.
    pub(crate) size: u64,
}

impl Header {
    /// The header at the start of a `com.apple.decmpfs` attribute, which
    /// must hold the header and at most `F::MAX_ATTRIBUTE_SIZE` bytes, as
    /// xnu `decmpfs_fetch_compressed_header` checks it.
    pub(crate) fn parse<F: Family>(attribute: &[u8]) -> Result<Self> {
        if !(DECMPFS_HEADER_SIZE..=F::MAX_ATTRIBUTE_SIZE).contains(&attribute.len()) {
            return Err(F::error(format!(
                "Invalid {DECMPFS_XATTR_NAME} attribute of {} B",
                attribute.len()
            )));
        }
        let magic = le_u32::<F>(attribute, 0)?;
        if magic != DECMPFS_MAGIC {
            return Err(F::error(format!(
                "Invalid {DECMPFS_XATTR_NAME} magic 0x{magic:08X}"
            )));
        }
        Ok(Self {
            compression_type: le_u32::<F>(attribute, 4)?,
            size: le_u64::<F>(attribute, 8)?,
        })
    }

    /// The method of a compression type the decoder reads.
    pub(crate) fn method(&self) -> Option<Method> {
        let (compression, storage) = match self.compression_type {
            CMP_TYPE1 => (Compression::Stored, Storage::Attribute),
            ZLIB_ATTRIBUTE => (Compression::Zlib, Storage::Attribute),
            ZLIB_RESOURCE_FORK => (Compression::Zlib, Storage::ResourceFork),
            LZVN_ATTRIBUTE => (Compression::Lzvn, Storage::Attribute),
            LZVN_RESOURCE_FORK => (Compression::Lzvn, Storage::ResourceFork),
            RAW_ATTRIBUTE => (Compression::Raw, Storage::Attribute),
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

/// Bytes of the data after an attribute's header.
pub(crate) fn attribute_payload_size(attribute: &[u8]) -> usize {
    attribute.len().saturating_sub(DECMPFS_HEADER_SIZE)
}

/// Decode the data stored after the header of an attribute, which must
/// decode to exactly `size` bytes.
pub(crate) fn decode_attribute<F: Family>(
    compression: Compression,
    attribute: &[u8],
    size: usize,
) -> Result<Vec<u8>> {
    let payload = attribute
        .get(DECMPFS_HEADER_SIZE..)
        .ok_or_else(|| F::error(format!("Truncated {DECMPFS_XATTR_NAME} attribute")))?;
    decode_unit::<F>(compression, payload, size)
}

/// Decode the chunks of a compressed resource fork for a file of `size`
/// bytes, stopping once `limit` bytes are decoded (at most `size`).
pub(crate) fn decode_resource_fork<F: Family>(
    compression: Compression,
    fork: &[u8],
    size: usize,
    limit: usize,
) -> Result<Vec<u8>> {
    let count = chunk_count(size);
    if F::REFUSES_SHORT_FORKS && count > fork.len() / OFFSET_TABLE_ENTRY_SIZE {
        return Err(F::error(format!(
            "Invalid decmpfs resource fork: {} B cannot hold {count} chunks",
            fork.len()
        )));
    }
    let chunks = match compression {
        Compression::Zlib => zlib_chunks::<F>(fork, count)?,
        Compression::Lzvn | Compression::Lzfse => offset_chunks::<F>(fork, count)?,
        Compression::Stored | Compression::Raw => {
            return Err(F::error(
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
        // `i` is below the chunk count, so `i` units precede the size.
        let expected = (size - i * COMPRESSION_UNIT_SIZE).min(COMPRESSION_UNIT_SIZE);
        let unit = &fork[chunk.offset..chunk.offset + chunk.size];
        decoded.extend(decode_unit::<F>(compression, unit, expected)?);
    }
    Ok(decoded)
}

/// Decode a compression unit (the data after an attribute's header, or a
/// resource fork chunk) that must decode to exactly `size` bytes.
fn decode_unit<F: Family>(compression: Compression, unit: &[u8], size: usize) -> Result<Vec<u8>> {
    let Some(&first) = unit.first() else {
        return empty_unit::<F>(compression, size);
    };
    let decoded = match compression {
        Compression::Stored => unit.to_vec(),
        Compression::Raw if first == RAW_MARKER => unit[1..].to_vec(),
        Compression::Raw => {
            return Err(F::error(format!(
                "Invalid decmpfs type 9 data: marker 0x{first:02X}, 0xCC expected"
            )))
        }
        Compression::Zlib if first & ZLIB_STORED_NIBBLE == ZLIB_STORED_NIBBLE => unit[1..].to_vec(),
        Compression::Lzvn if first == LZVN_STORED_MARKER => unit[1..].to_vec(),
        Compression::Zlib => decode_codec::<F>(Codec::Zlib, unit, size)?,
        Compression::Lzvn => decode_codec::<F>(Codec::Lzvn, unit, size)?,
        Compression::Lzfse => decode_codec::<F>(Codec::Lzfse, unit, size)?,
    };
    expect_size::<F>(decoded, size)
}

/// An empty compression unit: the data of an empty type 1 file, type 1
/// data of the wrong size (unless the family reports it as truncated), or
/// a truncated unit.
fn empty_unit<F: Family>(compression: Compression, size: usize) -> Result<Vec<u8>> {
    if compression == Compression::Stored && (size == 0 || !F::EMPTY_TYPE1_IS_TRUNCATED) {
        return expect_size::<F>(Vec::new(), size);
    }
    Err(F::error(
        "Truncated decmpfs data: an empty compression unit",
    ))
}

/// Decode a unit with `codec`, up to `size` bytes.
fn decode_codec<F: Family>(codec: Codec, unit: &[u8], size: usize) -> Result<Vec<u8>> {
    compressed::decode_limited(codec, unit, size)
        .map(|decoded| decoded.data)
        .map_err(|e| F::error(format!("Invalid decmpfs data: {e}")))
}

/// `decoded`, which must be `size` bytes.
fn expect_size<F: Family>(decoded: Vec<u8>, size: usize) -> Result<Vec<u8>> {
    if decoded.len() != size {
        return Err(F::error(format!(
            "Invalid decmpfs data: {} B decoded, {size} B expected",
            decoded.len()
        )));
    }
    Ok(decoded)
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
fn chunk_in<F: Family>(fork: &[u8], offset: usize, size: usize) -> Result<Chunk> {
    let fits = offset
        .checked_add(size)
        .is_some_and(|end| end <= fork.len());
    if size > MAX_CHUNK_SIZE || !fits {
        return Err(F::error(format!(
            "Invalid decmpfs chunk at 0x{offset:X} + {size} B in a resource fork of {} B",
            fork.len()
        )));
    }
    Ok(Chunk { offset, size })
}

/// The block table of a zlib resource fork (type 4): after the Resource
/// Manager `dataOffset` and the resource length, a little-endian count and
/// that many pairs of offset (from the count) and size.
fn zlib_chunks<F: Family>(fork: &[u8], count: usize) -> Result<Vec<Chunk>> {
    let data_offset = be_u32::<F>(fork, 0)? as usize;
    let table = data_offset
        .checked_add(RESOURCE_LENGTH_SIZE)
        .ok_or_else(|| F::error("Invalid decmpfs resource fork data offset"))?;
    let stated = le_u32::<F>(fork, table)? as usize;
    if stated != count {
        return Err(F::error(format!(
            "Invalid decmpfs zlib block table at 0x{table:X}: {stated} blocks, {count} expected"
        )));
    }
    // The count was read at `table`, so `table` plus its size is in the fork.
    let entries = F::slice(
        fork,
        table + ZLIB_TABLE_COUNT_SIZE,
        ZLIB_TABLE_ENTRY_SIZE * count,
    )?;
    let mut chunks = Vec::with_capacity(count);
    for entry in entries.chunks_exact(ZLIB_TABLE_ENTRY_SIZE) {
        let offset = le_u32::<F>(entry, 0)? as usize;
        let size = le_u32::<F>(entry, 4)? as usize;
        chunks.push(chunk_in::<F>(fork, table.saturating_add(offset), size)?);
    }
    Ok(chunks)
}

/// The offset table of an LZVN or LZFSE resource fork (types 8, 12):
/// count + 1 little-endian offsets from the fork start, the first being the
/// table's own size; chunk `i` lies between offsets `i` and `i + 1`.
fn offset_chunks<F: Family>(fork: &[u8], count: usize) -> Result<Vec<Chunk>> {
    let table_size = OFFSET_TABLE_ENTRY_SIZE * (count + 1);
    let stated = le_u32::<F>(fork, 0)? as usize;
    if stated != table_size {
        return Err(F::error(format!(
            "Invalid decmpfs chunk table: {stated} B, {table_size} B expected"
        )));
    }
    let table = F::slice(fork, 0, table_size)?;
    let mut chunks = Vec::with_capacity(count);
    for pair in table
        .windows(2 * OFFSET_TABLE_ENTRY_SIZE)
        .step_by(OFFSET_TABLE_ENTRY_SIZE)
    {
        let start = le_u32::<F>(pair, 0)? as usize;
        let end = le_u32::<F>(pair, OFFSET_TABLE_ENTRY_SIZE)? as usize;
        let size = end.checked_sub(start).ok_or_else(|| {
            F::error(format!(
                "Invalid decmpfs chunk table: offset 0x{end:X} before 0x{start:X}"
            ))
        })?;
        chunks.push(chunk_in::<F>(fork, start, size)?);
    }
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A family with xnu's attribute limit that reports what the chunk
    /// table finds and type 1 data by its size, as HFS+ does.
    struct Strict;

    /// A family without an attribute limit that refuses short forks and
    /// reports empty type 1 data as truncated, as APFS does.
    struct Early;

    fn test_error(message: impl Into<String>) -> ClassifierError {
        ClassifierError::HfsPlusParseError {
            message: message.into(),
        }
    }

    fn test_slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
        start
            .checked_add(len)
            .and_then(|end| data.get(start..end))
            .ok_or_else(|| test_error(format!("Truncated test data at 0x{start:X} + {len} B")))
    }

    impl Family for Strict {
        const MAX_ATTRIBUTE_SIZE: usize = MAX_DECMPFS_XATTR_SIZE;
        const REFUSES_SHORT_FORKS: bool = false;
        const EMPTY_TYPE1_IS_TRUNCATED: bool = false;

        fn error(message: impl Into<String>) -> ClassifierError {
            test_error(message)
        }

        fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
            test_slice(data, start, len)
        }
    }

    impl Family for Early {
        const MAX_ATTRIBUTE_SIZE: usize = usize::MAX;
        const REFUSES_SHORT_FORKS: bool = true;
        const EMPTY_TYPE1_IS_TRUNCATED: bool = true;

        fn error(message: impl Into<String>) -> ClassifierError {
            test_error(message)
        }

        fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
            test_slice(data, start, len)
        }
    }

    fn header(compression_type: u32, size: u64) -> Vec<u8> {
        let mut attribute = DECMPFS_MAGIC.to_le_bytes().to_vec();
        attribute.extend(compression_type.to_le_bytes());
        attribute.extend(size.to_le_bytes());
        attribute
    }

    /// The message of a test family's error.
    fn text(e: ClassifierError) -> String {
        match e {
            ClassifierError::HfsPlusParseError { message } => message,
            other => other.to_string(),
        }
    }

    fn message(result: Result<Vec<u8>>) -> String {
        text(result.expect_err("fails"))
    }

    #[test]
    fn headers_name_their_methods() {
        let parsed = Header::parse::<Strict>(&header(LZVN_RESOURCE_FORK, 0x3_2000)).unwrap();
        assert_eq!(parsed.size, 0x3_2000);
        assert_eq!(
            parsed.method(),
            Some(Method {
                compression: Compression::Lzvn,
                storage: Storage::ResourceFork,
            })
        );
        assert_eq!(
            Header::parse::<Strict>(&header(RAW_ATTRIBUTE, 1))
                .unwrap()
                .method(),
            Some(Method {
                compression: Compression::Raw,
                storage: Storage::Attribute,
            })
        );
        for unknown in [5, 10, 13, 14, 0x8000_0001] {
            assert_eq!(
                Header::parse::<Strict>(&header(unknown, 1))
                    .unwrap()
                    .method(),
                None
            );
        }
        let mut bad = header(ZLIB_ATTRIBUTE, 1);
        bad[0] ^= 1;
        assert!(Header::parse::<Strict>(&bad).is_err());
        assert!(Header::parse::<Strict>(&header(1, 1)[..15]).is_err());
    }

    #[test]
    fn attributes_over_the_family_limit_are_refused() {
        let mut attribute = header(CMP_TYPE1, 3787);
        attribute.resize(MAX_DECMPFS_XATTR_SIZE + 1, b'a');
        assert_eq!(
            text(Header::parse::<Strict>(&attribute).expect_err("over xnu's limit")),
            "Invalid com.apple.decmpfs attribute of 3803 B"
        );
        assert!(Header::parse::<Early>(&attribute).is_ok());
        attribute.truncate(MAX_DECMPFS_XATTR_SIZE);
        assert!(Header::parse::<Strict>(&attribute).is_ok());
    }

    #[test]
    fn stored_units_follow_their_marker_byte() {
        assert_eq!(
            decode_unit::<Strict>(Compression::Zlib, b"\xffabc", 3).unwrap(),
            b"abc"
        );
        assert_eq!(
            decode_unit::<Strict>(Compression::Lzvn, b"\x06abc", 3).unwrap(),
            b"abc"
        );
        assert!(decode_unit::<Strict>(Compression::Lzvn, b"\x06abc", 4).is_err());
        assert!(decode_unit::<Strict>(Compression::Zlib, b"", 0).is_err());
        assert_eq!(
            decode_unit::<Strict>(Compression::Stored, b"", 0).unwrap(),
            b""
        );
        assert_eq!(
            decode_unit::<Early>(Compression::Stored, b"", 0).unwrap(),
            b""
        );
    }

    #[test]
    fn raw_units_need_their_marker_and_size() {
        assert_eq!(
            decode_unit::<Strict>(Compression::Raw, b"\xccabc", 3).unwrap(),
            b"abc"
        );
        assert_eq!(
            message(decode_unit::<Strict>(Compression::Raw, b"abcd", 3)),
            "Invalid decmpfs type 9 data: marker 0x61, 0xCC expected"
        );
        assert_eq!(
            message(decode_unit::<Strict>(Compression::Raw, b"\xccab", 3)),
            "Invalid decmpfs data: 2 B decoded, 3 B expected"
        );
        assert_eq!(
            message(decode_unit::<Strict>(Compression::Raw, b"", 3)),
            "Truncated decmpfs data: an empty compression unit"
        );
        let mut attribute = header(RAW_ATTRIBUTE, 3);
        attribute.extend(b"\xccabc");
        assert_eq!(
            decode_attribute::<Strict>(Compression::Raw, &attribute, 3).unwrap(),
            b"abc"
        );
        assert_eq!(attribute_payload_size(&attribute), 4);
    }

    #[test]
    fn empty_type1_data_is_reported_as_each_family_reports_it() {
        assert_eq!(
            message(decode_unit::<Strict>(Compression::Stored, b"", 3)),
            "Invalid decmpfs data: 0 B decoded, 3 B expected"
        );
        assert_eq!(
            message(decode_unit::<Early>(Compression::Stored, b"", 3)),
            "Truncated decmpfs data: an empty compression unit"
        );
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
            offset_chunks::<Strict>(&fork, 2).unwrap(),
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
        assert!(offset_chunks::<Strict>(&fork, 1).is_err());
        assert!(offset_chunks::<Strict>(&fork[..16], 2).is_err());
        assert_eq!(chunk_count(COMPRESSION_UNIT_SIZE + 1), 2);
        // 1024 chunks: the 17-byte fork cannot hold their table.
        let size = 64 << 20;
        assert_eq!(
            message(decode_resource_fork::<Early>(
                Compression::Lzvn,
                &fork,
                size,
                1
            )),
            "Invalid decmpfs resource fork: 17 B cannot hold 1024 chunks"
        );
        assert_eq!(
            message(decode_resource_fork::<Strict>(
                Compression::Lzvn,
                &fork,
                size,
                1
            )),
            "Invalid decmpfs chunk table: 12 B, 4100 B expected"
        );
    }

    #[test]
    fn zlib_block_tables_follow_the_resource_manager_header() {
        // `dataOffset` 0x10 at 0, the resource length at 0x10, then at 0x14
        // the count and one (offset, size) pair from 0x14: a stored chunk
        // of 4 B at 0x20.
        let mut fork = vec![0u8; 0x14];
        fork[..4].copy_from_slice(&0x10u32.to_be_bytes());
        fork.extend(1u32.to_le_bytes());
        fork.extend(12u32.to_le_bytes());
        fork.extend(4u32.to_le_bytes());
        fork.extend(b"\xffabc");
        assert_eq!(
            zlib_chunks::<Strict>(&fork, 1).unwrap(),
            [Chunk {
                offset: 0x20,
                size: 4
            }]
        );
        assert_eq!(
            decode_resource_fork::<Strict>(Compression::Zlib, &fork, 3, 3).unwrap(),
            b"abc"
        );
        assert!(zlib_chunks::<Strict>(&fork, 2).is_err());
        assert!(zlib_chunks::<Strict>(&fork[..0x1f], 1).is_err());
    }

    #[test]
    fn resource_forks_never_hold_stored_or_raw_data() {
        let fork = 4u32.to_le_bytes();
        for compression in [Compression::Stored, Compression::Raw] {
            assert_eq!(
                message(decode_resource_fork::<Strict>(compression, &fork, 0, 0)),
                "Invalid decmpfs type: stored data in the resource fork"
            );
        }
    }
}
