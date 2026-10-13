//! Resource contents (MSWIM "WIM File Resource"; wimlib `src/resource.c`
//! `read_compressed_wim_resource`):
//! - A stored resource is its bytes; its stored size must equal its size.
//! - A compressed resource starts with a chunk table of `chunks - 1`
//!   entries, 4 bytes each (8 when the uncompressed size exceeds
//!   0xFFFFFFFF), each the offset of the next chunk from the end of the
//!   table; chunk 0 starts right after the table. Every chunk decodes to
//!   the chunk size but the last, which decodes to the rest.
//! - A solid resource starts with its uncompressed size (8), chunk size (4)
//!   and compression format (4), then the stored size of every chunk (4
//!   each), then the chunks (wimlib `alt_chunk_table_header_disk`).
//! - A chunk whose stored size equals its uncompressed size is stored as
//!   is; a larger stored size or an empty chunk is invalid.

use super::header::{Compression, ResourceHeader};
use super::lookup::{Location, SolidResource};
use super::*;
use crate::formats::compressed::{self, Codec};
use crate::formats::container::MAX_EXTRACTED;
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;

/// Chunk table entries grow to 8 bytes in resources larger than this
/// (wimlib `get_chunk_entry_size`).
const MAX_SHORT_ENTRY_RESOURCE: u64 = 0xffff_ffff;

/// Size of a solid resource's header and of its chunk table entries.
pub(super) const SOLID_HEADER_SIZE: usize = 16;
const SOLID_ENTRY_SIZE: usize = 4;

/// Solid resource header fields (wimlib `alt_chunk_table_header_disk`).
pub(super) const SOLID_SIZE_FIELD: usize = 0;
pub(super) const SOLID_CHUNK_SIZE_FIELD: usize = 8;
pub(super) const SOLID_FORMAT_FIELD: usize = 12;

/// Smallest LZX window (wimlib `LZX_MIN_WINDOW_ORDER`).
const MIN_LZX_WINDOW_BITS: u32 = 15;

/// Most chunk bytes decoded for one WIM, metadata included. Solid chunks
/// of 64 MiB that many blobs share are decoded again for blobs out of
/// order; the bound is ours.
pub(super) const MAX_DECODED: usize = 8 * MAX_EXTRACTED;

/// Bytes read from a resource.
#[derive(Debug)]
pub(super) struct Bytes<'a> {
    /// The bytes: borrowed from the input when stored, owned when decoded.
    pub(super) data: Cow<'a, [u8]>,
    /// File offset and size of the stored bytes they came from.
    pub(super) offset: usize,
    pub(super) stored_size: usize,
    /// Codec that produced `data`, when it was decoded.
    pub(super) transform: Option<&'static str>,
}

/// What a chunk table's entries hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    /// Offsets of chunks 1 and later from the end of the table.
    Offsets,
    /// Stored sizes of every chunk.
    Sizes,
}

/// A chunk's place in the file and its uncompressed size.
#[derive(Debug, Clone, Copy)]
struct ChunkExtent {
    offset: usize,
    stored_size: usize,
    size: usize,
}

impl ChunkExtent {
    fn is_stored(&self) -> bool {
        self.stored_size == self.size
    }
}

/// The chunk table of a compressed or solid resource.
struct ChunkTable<'a> {
    entries: &'a [u8],
    entry_size: usize,
    kind: EntryKind,
    /// Stored bytes of the chunks, after the table, and their file offset.
    chunks: &'a [u8],
    chunks_offset: usize,
    count: usize,
    chunk_size: usize,
    size: u64,
    compression: Option<Compression>,
    /// Start of every chunk in `chunks`, for [`EntryKind::Sizes`] tables.
    starts: Vec<usize>,
}

impl<'a> ChunkTable<'a> {
    /// The table of a non-solid compressed resource.
    fn compressed(
        data: &'a [u8],
        resource: &ResourceHeader,
        compression: Compression,
        chunk_size: u32,
    ) -> Result<Self> {
        let stored = resource_bytes(data, resource)?;
        let chunk_size = chunk_size as usize;
        let count = chunk_count(resource.size, chunk_size)?;
        let entry_size = if resource.size > MAX_SHORT_ENTRY_RESOURCE {
            8
        } else {
            4
        };
        let table_size = count
            .saturating_sub(1)
            .checked_mul(entry_size)
            .filter(|&size| size <= stored.len())
            .ok_or_else(|| {
                error(format!(
                    "Truncated WIM chunk table at 0x{:X}: {count} chunks in {} B",
                    resource.offset,
                    stored.len()
                ))
            })?;
        Ok(Self {
            entries: &stored[..table_size],
            entry_size,
            kind: EntryKind::Offsets,
            chunks: &stored[table_size..],
            chunks_offset: to_usize(resource.offset, "WIM resource offset")? + table_size,
            count,
            chunk_size,
            size: resource.size,
            compression: Some(compression),
            starts: Vec::new(),
        })
    }

    /// The table of a solid resource.
    fn solid(data: &'a [u8], solid: &SolidResource) -> Result<Self> {
        let stored = resource_bytes(data, &solid.header)?;
        let chunk_size = solid.chunk_size as usize;
        let count = chunk_count(solid.size, chunk_size)?;
        let table_end = count
            .checked_mul(SOLID_ENTRY_SIZE)
            .and_then(|size| size.checked_add(SOLID_HEADER_SIZE))
            .filter(|&end| end <= stored.len())
            .ok_or_else(|| {
                error(format!(
                    "Truncated WIM solid chunk table at 0x{:X}: {count} chunks in {} B",
                    solid.header.offset,
                    stored.len()
                ))
            })?;
        let entries = &stored[SOLID_HEADER_SIZE..table_end];
        let mut starts = Vec::with_capacity(count);
        let mut start = 0usize;
        for entry in entries.chunks_exact(SOLID_ENTRY_SIZE) {
            starts.push(start);
            let size = u32::from_le_bytes(entry.try_into().expect("4-byte entry")) as usize;
            start = start.checked_add(size).ok_or_else(|| {
                error(format!(
                    "Invalid WIM solid chunk table at 0x{:X}: sizes overflow",
                    solid.header.offset
                ))
            })?;
        }
        Ok(Self {
            entries,
            entry_size: SOLID_ENTRY_SIZE,
            kind: EntryKind::Sizes,
            chunks: &stored[table_end..],
            chunks_offset: to_usize(solid.header.offset, "WIM resource offset")? + table_end,
            count,
            chunk_size,
            size: solid.size,
            compression: solid.compression,
            starts,
        })
    }

    /// Entry `index` of the table, as a position in the chunk bytes.
    fn entry(&self, index: usize) -> Result<usize> {
        let at = index * self.entry_size;
        let bytes = &self.entries[at..at + self.entry_size];
        let value = if self.entry_size == 8 {
            u64::from_le_bytes(bytes.try_into().expect("8-byte entry"))
        } else {
            u64::from(u32::from_le_bytes(bytes.try_into().expect("4-byte entry")))
        };
        to_usize(value, "WIM chunk table entry")
    }

    /// Where chunk `index` (below `count`) is stored and how large it is.
    fn extent(&self, index: usize) -> Result<ChunkExtent> {
        let last = index + 1 == self.count;
        let size = if last {
            let before = index as u64 * self.chunk_size as u64;
            usize::try_from(self.size - before).expect("the last chunk is at most a chunk")
        } else {
            self.chunk_size
        };
        let (start, end) = match self.kind {
            EntryKind::Offsets => {
                let start = if index == 0 {
                    0
                } else {
                    self.entry(index - 1)?
                };
                let end = if last {
                    self.chunks.len()
                } else {
                    self.entry(index)?
                };
                (start, end)
            }
            EntryKind::Sizes => {
                let start = self.starts[index];
                (start, start.saturating_add(self.entry(index)?))
            }
        };
        if start > end || end > self.chunks.len() {
            return Err(error(format!(
                "Invalid WIM chunk table at 0x{:X}: chunk {index} lies at 0x{start:X}..0x{end:X} \
                 of {} B",
                self.chunks_offset,
                self.chunks.len()
            )));
        }
        let stored_size = end - start;
        if stored_size == 0 || stored_size > size {
            return Err(error(format!(
                "Invalid WIM chunk {index} at 0x{:X}: {stored_size} B stored for {size} B",
                self.chunks_offset + start
            )));
        }
        Ok(ChunkExtent {
            offset: self.chunks_offset + start,
            stored_size,
            size,
        })
    }

    /// The uncompressed bytes of the chunk at `extent`.
    fn chunk(&self, data: &'a [u8], extent: ChunkExtent) -> Result<Cow<'a, [u8]>> {
        let stored = &data[extent.offset..extent.offset + extent.stored_size];
        if extent.is_stored() {
            return Ok(Cow::Borrowed(stored));
        }
        let codec = self.codec()?;
        // LZMS chunks may be up to 1 GiB; the codecs decode at most
        // `MAX_PAYLOAD`.
        if extent.size > MAX_PAYLOAD {
            return Err(error(format!(
                "Unsupported {} chunk of {} at 0x{:X}: chunks above {} are not decoded",
                codec.name(),
                size_text(extent.size),
                extent.offset,
                size_text(MAX_PAYLOAD)
            )));
        }
        let decoded = compressed::decode_limited(codec, stored, extent.size).map_err(|e| {
            error(format!(
                "Invalid {} chunk at 0x{:X}: {}",
                codec.name(),
                extent.offset,
                message(&e)
            ))
        })?;
        if decoded.data.len() != extent.size {
            return Err(error(format!(
                "Invalid {} chunk at 0x{:X}: {} B decoded for {} B",
                codec.name(),
                extent.offset,
                decoded.data.len(),
                extent.size
            )));
        }
        Ok(Cow::Owned(decoded.data))
    }

    /// The codec of this table's chunks.
    fn codec(&self) -> Result<Codec> {
        match self.compression {
            Some(Compression::Xpress) => Ok(Codec::XpressHuffman),
            Some(Compression::Lzx) => {
                let order = self.chunk_size.trailing_zeros().max(MIN_LZX_WINDOW_BITS);
                Ok(Codec::LzxWim {
                    window_bits: u8::try_from(order).expect("at most 64 bits"),
                })
            }
            Some(Compression::Lzms) => Ok(Codec::Lzms),
            None => Err(error(
                "Invalid WIM chunk: a resource without compression has a compressed chunk",
            )),
        }
    }

    /// The chunks that hold `len` bytes at `start`, and the offset of
    /// `start` in the first of them.
    fn plan(&self, start: u64, len: usize) -> Result<Plan> {
        let end = start
            .checked_add(len as u64)
            .filter(|&end| end <= self.size)
            .ok_or_else(|| {
                error(format!(
                    "Invalid WIM range of {len} B at 0x{start:X} in a resource of {} B",
                    self.size
                ))
            })?;
        let chunk_size = self.chunk_size as u64;
        let first = to_usize(start / chunk_size, "WIM chunk index")?;
        let last = to_usize((end - 1) / chunk_size, "WIM chunk index")?;
        let extents = (first..=last)
            .map(|index| self.extent(index))
            .collect::<Result<Vec<_>>>()?;
        Ok(Plan {
            first,
            skip: usize::try_from(start % chunk_size).expect("below the chunk size"),
            extents,
        })
    }
}

/// The chunks of one read.
struct Plan {
    /// Index of the first chunk.
    first: usize,
    /// Offset of the read in the first chunk.
    skip: usize,
    extents: Vec<ChunkExtent>,
}

/// A run of stored bytes in the input.
struct StoredRange {
    /// File offset of the first byte.
    offset: usize,
    /// Size in bytes.
    size: usize,
}

impl Plan {
    /// Where the read starts in the plan's chunk `i`.
    fn skip_in(&self, i: usize) -> usize {
        if i == 0 {
            self.skip
        } else {
            0
        }
    }

    /// The stored bytes the read covers, from the first chunk's stored
    /// bytes to the end of the last's.
    fn stored_range(&self) -> StoredRange {
        let first = self.extents.first().expect("at least one chunk");
        let last = self.extents.last().expect("at least one chunk");
        StoredRange {
            offset: first.offset,
            size: last.offset + last.stored_size - first.offset,
        }
    }

    /// The bytes, at their own file offset, when every chunk of the read is
    /// stored: stored chunks are contiguous in the input.
    fn borrowed<'a>(&self, data: &'a [u8], len: usize) -> Option<Bytes<'a>> {
        if !self.extents.iter().all(ChunkExtent::is_stored) {
            return None;
        }
        let begin = self.extents[0].offset + self.skip;
        Some(Bytes {
            data: Cow::Borrowed(&data[begin..begin + len]),
            offset: begin,
            stored_size: len,
            transform: None,
        })
    }
}

/// The stored bytes of a resource, which must lie inside the input.
fn resource_bytes<'a>(data: &'a [u8], resource: &ResourceHeader) -> Result<&'a [u8]> {
    let offset = to_usize(resource.offset, "WIM resource offset")?;
    let size = to_usize(resource.stored_size, "WIM resource size")?;
    slice(data, offset, size, "WIM resource")
}

/// Chunks of `chunk_size` bytes that hold `size` bytes.
fn chunk_count(size: u64, chunk_size: usize) -> Result<usize> {
    if !chunk_size.is_power_of_two() {
        return Err(error(format!(
            "Invalid WIM chunk size {chunk_size} B: not a power of two"
        )));
    }
    let chunk_size = chunk_size as u64;
    let count = size / chunk_size + u64::from(size % chunk_size != 0);
    to_usize(count, "WIM chunk count")
}

/// An error's message without the family prefix, for notes.
pub(super) fn message(e: &ClassifierError) -> String {
    match e {
        ClassifierError::WimParseError { message }
        | ClassifierError::CompressedParseError { message } => message.clone(),
        other => other.to_string(),
    }
}

/// Most recently decoded chunk of a solid resource, kept because many
/// blobs share one chunk.
struct CachedChunk {
    resource: usize,
    index: usize,
    bytes: Vec<u8>,
}

/// Reads blobs and resources of one WIM, decoding at most [`MAX_DECODED`]
/// chunk bytes.
pub(super) struct Reader<'a, 'h> {
    data: &'a [u8],
    header: &'h Header,
    solid: &'h [SolidResource],
    cache: Option<CachedChunk>,
    /// Chunk bytes decoded so far, and whether a chunk was refused for the
    /// limit.
    decoded: usize,
    exhausted: bool,
}

impl<'a, 'h> Reader<'a, 'h> {
    pub(super) fn new(data: &'a [u8], header: &'h Header, solid: &'h [SolidResource]) -> Self {
        Self {
            data,
            header,
            solid,
            cache: None,
            decoded: 0,
            exhausted: false,
        }
    }

    /// Whether a read stopped at the decoding limit.
    pub(super) fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Count a chunk that is about to be decoded against [`MAX_DECODED`].
    fn charge(&mut self, extent: &ChunkExtent) -> Result<()> {
        if extent.is_stored() {
            return Ok(());
        }
        if self.decoded + extent.size > MAX_DECODED {
            self.exhausted = true;
            return Err(error(format!(
                "Unsupported WIM read: the {} decoding limit was reached",
                size_text(MAX_DECODED)
            )));
        }
        self.decoded += extent.size;
        Ok(())
    }

    /// The first `len` bytes of a blob of `size` bytes at `location`.
    pub(super) fn read(&mut self, location: &Location, size: u64, len: usize) -> Result<Bytes<'a>> {
        if len as u64 > size {
            return Err(error(format!(
                "Invalid WIM read of {len} B from a blob of {size} B"
            )));
        }
        match *location {
            Location::Resource(resource) => self.read_resource(&resource, len),
            Location::Solid { resource, offset } => self.read_solid(resource, offset, len),
        }
    }

    /// The first `len` bytes of a resource of its own. Borrowed bytes come
    /// with their own offset; decoded bytes with the whole resource as
    /// their stored extent.
    pub(super) fn read_resource(
        &mut self,
        resource: &ResourceHeader,
        len: usize,
    ) -> Result<Bytes<'a>> {
        let offset = to_usize(resource.offset, "WIM resource offset")?;
        let stored_size = to_usize(resource.stored_size, "WIM resource size")?;
        if !resource.is_compressed() {
            if resource.stored_size != resource.size {
                return Err(error(format!(
                    "Invalid WIM resource at 0x{offset:X}: stored, but {} B stored for {} B",
                    resource.stored_size, resource.size
                )));
            }
            return Ok(Bytes {
                data: Cow::Borrowed(slice(self.data, offset, len, "WIM resource")?),
                offset,
                stored_size: len,
                transform: None,
            });
        }
        let compression = self.header.compression.ok_or_else(|| {
            error(format!(
                "Invalid WIM resource at 0x{offset:X}: compressed in an uncompressed WIM"
            ))
        })?;
        let table =
            ChunkTable::compressed(self.data, resource, compression, self.header.chunk_size)?;
        if len == 0 {
            return Ok(Bytes {
                data: Cow::Borrowed(&[]),
                offset: table.chunks_offset,
                stored_size: 0,
                transform: None,
            });
        }
        let plan = table.plan(0, len)?;
        if let Some(bytes) = plan.borrowed(self.data, len) {
            return Ok(bytes);
        }
        let mut out = Vec::with_capacity(len);
        for (i, extent) in plan.extents.iter().enumerate() {
            self.charge(extent)?;
            let chunk = table.chunk(self.data, *extent)?;
            append(&mut out, &chunk, plan.skip_in(i), len);
        }
        Ok(Bytes {
            data: Cow::Owned(out),
            offset,
            stored_size,
            transform: Some(table.codec()?.name()),
        })
    }

    /// `len` bytes at `start` of solid resource `index`; the stored extent
    /// runs from the first chunk that holds them to the last.
    fn read_solid(&mut self, index: usize, start: u64, len: usize) -> Result<Bytes<'a>> {
        let solid = self
            .solid
            .get(index)
            .ok_or_else(|| error(format!("Invalid WIM solid resource index {index}")))?;
        let table = ChunkTable::solid(self.data, solid)?;
        if len == 0 {
            return Ok(Bytes {
                data: Cow::Borrowed(&[]),
                offset: table.chunks_offset,
                stored_size: 0,
                transform: None,
            });
        }
        let plan = table.plan(start, len)?;
        if let Some(bytes) = plan.borrowed(self.data, len) {
            return Ok(bytes);
        }
        let mut out = Vec::with_capacity(len);
        for (i, extent) in plan.extents.iter().enumerate() {
            let chunk_index = plan.first + i;
            let from = plan.skip_in(i);
            let cached = self
                .cache
                .as_ref()
                .filter(|cached| cached.resource == index && cached.index == chunk_index);
            if let Some(cached) = cached {
                append(&mut out, &cached.bytes, from, len);
                continue;
            }
            self.charge(extent)?;
            match table.chunk(self.data, *extent)? {
                Cow::Borrowed(stored) => append(&mut out, stored, from, len),
                Cow::Owned(decoded) => {
                    append(&mut out, &decoded, from, len);
                    self.cache = Some(CachedChunk {
                        resource: index,
                        index: chunk_index,
                        bytes: decoded,
                    });
                }
            }
        }
        let stored = plan.stored_range();
        Ok(Bytes {
            data: Cow::Owned(out),
            offset: stored.offset,
            stored_size: stored.size,
            transform: Some(table.codec()?.name()),
        })
    }
}

/// Append the bytes of `chunk` from `from` on that a read of `len` bytes
/// still needs.
fn append(out: &mut Vec<u8>, chunk: &[u8], from: usize, len: usize) {
    let take = (len - out.len()).min(chunk.len() - from);
    out.extend_from_slice(&chunk[from..from + take]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_above_the_payload_limit_are_not_decoded() {
        // A solid LZMS resource at offset 0 of 128 MiB in one 128 MiB chunk
        // of 100 stored bytes: its header (uncompressed size, chunk size,
        // compression format 3), the chunk's stored size and the chunk.
        const CHUNK_SIZE: u32 = 128 << 20;
        const STORED: u32 = 100;
        let mut data = Vec::new();
        data.extend_from_slice(&u64::from(CHUNK_SIZE).to_le_bytes());
        data.extend_from_slice(&CHUNK_SIZE.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&STORED.to_le_bytes());
        data.resize(data.len() + STORED as usize, 0x55);
        let solid = SolidResource {
            header: ResourceHeader {
                stored_size: data.len() as u64,
                flags: super::header::RESOURCE_SOLID,
                offset: 0,
                // The lookup table's marker of a solid resource entry.
                size: 0x1_0000_0000,
            },
            size: u64::from(CHUNK_SIZE),
            chunk_size: CHUNK_SIZE,
            compression: Some(Compression::Lzms),
        };
        let table = ChunkTable::solid(&data, &solid).unwrap();
        let extent = table.extent(0).unwrap();
        assert_eq!(extent.size, 128 << 20);
        let e = table.chunk(&data, extent).unwrap_err();
        assert_eq!(
            message(&e),
            "Unsupported LZMS chunk of 128 MiB at 0x14: chunks above 64 MiB are not decoded"
        );
    }
}
