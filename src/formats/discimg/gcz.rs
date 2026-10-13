//! Dolphin GCZ images (`CompressedBlob.h`, `CompressedBlob.cpp`).
//!
//! The 32-byte `CompressedBlobHeader` is written in host byte order ("Code
//! not big-endian safe"), which is little-endian on every platform Dolphin
//! runs on: magic 0xB10BC001 (0x00), sub-type (0x04), compressed data size
//! (0x08, 8 B), data size (0x10, 8 B), block size (0x18) and block count
//! (0x1C). Then one 64-bit block pointer per block, the block's offset from
//! the data area with bit 63 set when the block is stored uncompressed; one
//! Adler-32 per block; and the blocks. A block's stored size is the
//! distance to the next pointer, or to the compressed data size for the
//! last (`GetBlockCompressedSize`).
//!
//! Every block decodes to the block size: a zlib stream (`deflateInit`
//! level 9; `inflateInit`), or the raw block. `ConvertToGCZ` zero-pads the
//! last block before compressing it. The Adler-32 covers the stored bytes:
//! `Compress` hashes the output it writes and `GetBlock` the bytes it reads
//! (the header comment "hash of decompressed data" does not match the
//! code).

use super::*;
use crate::formats::checksum;

/// `GCZ_MAGIC`, stored little-endian (`01 C0 0B B1`).
const GCZ_MAGIC: u32 = 0xB10B_C001;

/// `sizeof(CompressedBlobHeader)`, where the block pointers start.
const HEADER_SIZE: usize = 0x20;

/// Header field offsets.
const SUB_TYPE: usize = 0x04;
const COMPRESSED_DATA_SIZE: usize = 0x08;
const DATA_SIZE: usize = 0x10;
const BLOCK_SIZE: usize = 0x18;
const NUM_BLOCKS: usize = 0x1C;

/// A block pointer (`u64`) and a block hash (`u32`) per block.
const POINTER_SIZE: usize = 8;
const HASH_SIZE: usize = 4;

/// Bit 63 of a block pointer: the block is stored uncompressed (`Output`).
const UNCOMPRESSED_FLAG: u64 = 1 << 63;

/// Sub-types `DolphinTool`'s `ConvertCommand` writes: the volume type, or
/// all ones when the input is not a recognized volume.
const SUB_TYPE_GAMECUBE: u32 = 0;
const SUB_TYPE_WII: u32 = 1;
const SUB_TYPE_UNSET: u32 = u32::MAX;

/// Smallest block size decoded. Our bound, not Dolphin's: it keeps the
/// decoded prefix to at most 131072 zlib streams. Dolphin writes powers of
/// two from 16 KiB (`GCZ_FALLBACK_BLOCK_SIZE`, `PREFERRED_MIN_BLOCK_SIZE`
/// 32 KiB).
const MIN_BLOCK_SIZE: u32 = 0x200;

/// Transform name of the decoded disc.
const TRANSFORM: &str = "GCZ";

/// The `CompressedBlobHeader` fields after the magic.
struct Header {
    magic: u32,
    sub_type: u32,
    /// Bytes of block data after the tables.
    compressed_data_size: u64,
    /// Decoded disc size.
    data_size: u64,
    /// Decoded block size.
    block_size: u32,
    /// Number of blocks.
    blocks: u32,
}

/// One block table entry.
struct Block {
    /// Offset of the stored bytes from the data area.
    offset: u64,
    /// Stored size in bytes.
    stored_size: u64,
    /// Stored as the raw block rather than a zlib stream.
    uncompressed: bool,
    /// Adler-32 of the stored bytes.
    hash: u32,
}

/// The header; the file must hold all 32 bytes.
fn header(data: &[u8]) -> Result<Header> {
    let header = slice(data, 0, HEADER_SIZE, "GCZ header")?;
    let what = "GCZ header";
    Ok(Header {
        magic: le_u32(header, 0, what)?,
        sub_type: le_u32(header, SUB_TYPE, what)?,
        compressed_data_size: le_u64(header, COMPRESSED_DATA_SIZE, what)?,
        data_size: le_u64(header, DATA_SIZE, what)?,
        block_size: le_u32(header, BLOCK_SIZE, what)?,
        blocks: le_u32(header, NUM_BLOCKS, what)?,
    })
}

/// Whether the block count is the one `ConvertToGCZ` writes: the data size
/// in blocks, rounded up.
fn is_consistent(header: &Header) -> bool {
    header.block_size.is_power_of_two()
        && u64::from(header.blocks) == div_ceil(header.data_size, u64::from(header.block_size))
}

/// Strong recognition: the magic, a power-of-two block size (Dolphin's
/// `IsDiscImageBlockSizeValid`) and a block count that matches the data
/// size, so the 32-bit magic alone is not enough.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let header = header(data).ok()?;
    (header.magic == GCZ_MAGIC && is_consistent(&header)).then_some(Layout::Gcz)
}

/// Parse a GCZ image: the header, both tables, every stored block's
/// Adler-32, and the decoded disc as one child.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = header(data)?;
    validate(&header)?;
    let table_size = u64::from(header.blocks) * (POINTER_SIZE + HASH_SIZE) as u64;
    let data_offset = HEADER_SIZE as u64 + table_size;
    if data_offset > data.len() as u64 {
        return Err(error(format!(
            "Truncated GCZ block table: {} need {table_size} B at 0x{HEADER_SIZE:X}; the file holds {} B",
            counted(u64::from(header.blocks), "block", "blocks"),
            data.len()
        )));
    }
    let data_offset = usize::try_from(data_offset).expect("the tables lie in the file");
    let blocks = blocks(data, &header)?;
    let data_end = (data_offset as u64)
        .checked_add(header.compressed_data_size)
        .ok_or_else(|| error("Invalid GCZ compressed data size: the data end overflows"))?;

    let mut c = Container::new(FileFormat::Gcz, Layout::Gcz.label(), "gcz");
    let stored_blocks = blocks.iter().filter(|b| b.uncompressed).count() as u64;
    c.notes.push(format!(
        "GCZ: {} of {}; {} zlib-compressed, {stored_blocks} stored uncompressed; disc size {} B; sub-type {}",
        counted(u64::from(header.blocks), "block", "blocks"),
        size_text(header.block_size as usize),
        u64::from(header.blocks) - stored_blocks,
        header.data_size,
        sub_type_name(header.sub_type)
    ));
    check_extent(&mut c, data, data_end, "the GCZ block data")?;
    push_hash_notes(&mut c, data, data_offset, &blocks);
    push_metadata(&mut c, &header, stored_blocks);
    let disc = decode(data, data_offset, &header, &blocks)?;
    if disc.size == 0 {
        c.notes
            .push("The GCZ holds an empty disc (data size 0)".into());
    } else {
        let stored = StoredSpan {
            offset: data_offset,
            size: usize::try_from(header.compressed_data_size)
                .unwrap_or(usize::MAX)
                .min(data.len() - data_offset),
        };
        push_disc(&mut c, "Disc image".into(), disc, stored, TRANSFORM);
    }
    push_no_isa_note(&mut c, "GCZ");
    Ok(c)
}

/// The header checks that detection leaves to the parser.
fn validate(header: &Header) -> Result<()> {
    if header.magic != GCZ_MAGIC {
        return Err(error(format!(
            "Invalid GCZ magic 0x{:08X} at 0x0",
            header.magic
        )));
    }
    let block_size = header.block_size;
    if !block_size.is_power_of_two() {
        return Err(error(format!(
            "Invalid GCZ block size {block_size} B: not a power of two"
        )));
    }
    if block_size < MIN_BLOCK_SIZE || block_size as usize > MAX_PAYLOAD {
        return Err(error(format!(
            "Unsupported GCZ block size {block_size} B (supported: {} to {})",
            size_text(MIN_BLOCK_SIZE as usize),
            size_text(MAX_PAYLOAD)
        )));
    }
    let expected = div_ceil(header.data_size, u64::from(block_size));
    if u64::from(header.blocks) != expected {
        return Err(error(format!(
            "Invalid GCZ block count {} at 0x{NUM_BLOCKS:X}: {} B of data in {block_size} B blocks need {expected}",
            header.blocks, header.data_size
        )));
    }
    Ok(())
}

/// The block table: pointers in order, stored sizes up to the next block
/// (or the end of the compressed data), and the hashes.
fn blocks(data: &[u8], header: &Header) -> Result<Vec<Block>> {
    let count = header.blocks as usize;
    let pointer_at = |i: usize| HEADER_SIZE + i * POINTER_SIZE;
    let hash_at = |i: usize| HEADER_SIZE + count * POINTER_SIZE + i * HASH_SIZE;
    let mut blocks = Vec::with_capacity(count);
    for i in 0..count {
        let pointer = le_u64(data, pointer_at(i), "GCZ block pointer")?;
        let offset = pointer & !UNCOMPRESSED_FLAG;
        let end = if i + 1 < count {
            le_u64(data, pointer_at(i + 1), "GCZ block pointer")? & !UNCOMPRESSED_FLAG
        } else {
            header.compressed_data_size
        };
        let stored_size = end.checked_sub(offset).ok_or_else(|| {
            error(format!(
                "Invalid GCZ block pointer {i} at 0x{:X}: block data at 0x{offset:X} end at 0x{end:X}",
                pointer_at(i)
            ))
        })?;
        let uncompressed = pointer & UNCOMPRESSED_FLAG != 0;
        if uncompressed && stored_size != u64::from(header.block_size) {
            return Err(error(format!(
                "Invalid GCZ block {i}: stored uncompressed in {stored_size} B instead of the {} B block size",
                header.block_size
            )));
        }
        blocks.push(Block {
            offset,
            stored_size,
            uncompressed,
            hash: le_u32(data, hash_at(i), "GCZ block hash")?,
        });
    }
    Ok(blocks)
}

/// Name of a sub-type value.
fn sub_type_name(sub_type: u32) -> String {
    match sub_type {
        SUB_TYPE_GAMECUBE => "0 (GameCube disc)".into(),
        SUB_TYPE_WII => "1 (Wii disc)".into(),
        SUB_TYPE_UNSET => "0xFFFFFFFF (not set)".into(),
        other => format!("0x{other:X} (unknown)"),
    }
}

/// Verify the Adler-32 of every stored block in the file and say what was
/// found. Dolphin's `GetBlock` logs a mismatch ("is corrupt") and still
/// returns the block, so a mismatch is a note: the disc it presents is the
/// same.
fn push_hash_notes(c: &mut Container<'_>, data: &[u8], data_offset: usize, blocks: &[Block]) {
    let mut verified = 0u64;
    let mut mismatched = 0u64;
    let mut outside = 0u64;
    let mut first_mismatch = None;
    for (i, block) in blocks.iter().enumerate() {
        let start = (data_offset as u64).saturating_add(block.offset);
        let Some(stored) = range(data, start, block.stored_size) else {
            outside += 1;
            continue;
        };
        let computed = checksum::adler32(stored);
        if computed == block.hash {
            verified += 1;
        } else {
            mismatched += 1;
            first_mismatch.get_or_insert(format!(
                "block {i}, stored 0x{:08X}, computed 0x{computed:08X}",
                block.hash
            ));
        }
    }
    let total = blocks.len() as u64;
    if mismatched == 0 && outside == 0 {
        c.notes.push(format!(
            "Adler-32 of the stored bytes verified for all {}",
            counted(total, "block", "blocks")
        ));
    } else if verified > 0 {
        c.notes.push(format!(
            "Adler-32 of the stored bytes verified for {verified} of {}",
            counted(total, "block", "blocks")
        ));
    }
    if let Some(first) = first_mismatch {
        c.notes.push(format!(
            "Adler-32 mismatch in {} (first: {first}); Dolphin logs the mismatch and still reads the block",
            counted(mismatched, "block", "blocks")
        ));
    }
    if outside > 0 {
        c.notes.push(format!(
            "Adler-32 not verified for {} outside the file",
            counted(outside, "block", "blocks")
        ));
    }
}

fn push_metadata(c: &mut Container<'_>, header: &Header, stored_blocks: u64) {
    c.push_metadata(
        "gcz_sub_type",
        "Sub-type (0 GameCube, 1 Wii)",
        u64::from(header.sub_type),
    );
    c.push_metadata(
        "gcz_block_size",
        "Block size (B)",
        u64::from(header.block_size),
    );
    c.push_metadata("gcz_blocks", "Blocks", u64::from(header.blocks));
    c.push_metadata(
        "gcz_stored_blocks",
        "Blocks stored uncompressed",
        stored_blocks,
    );
    c.push_metadata("gcz_disc_size", "Disc size (B)", header.data_size);
    c.push_metadata(
        "gcz_compressed_data_size",
        "Compressed data size (B)",
        header.compressed_data_size,
    );
}

/// Decode the blocks the disc prefix covers. Each must lie in the file and
/// decode to exactly the block size, as `GetBlock` requires.
fn decode(data: &[u8], data_offset: usize, header: &Header, blocks: &[Block]) -> Result<Disc> {
    let block_size = u64::from(header.block_size);
    let mut disc = Disc::new(header.data_size);
    for (i, block) in blocks.iter().enumerate().take(
        usize::try_from(disc.blocks(block_size))
            .expect("the prefix has at most one block per byte"),
    ) {
        let at = (data_offset as u64).saturating_add(block.offset);
        let stored = range(data, at, block.stored_size).ok_or_else(|| {
            error(format!(
                "Truncated GCZ block {i} at 0x{at:X} + {} B: it lies outside the file",
                block.stored_size
            ))
        })?;
        let out = disc.block_mut(i as u64, block_size);
        if block.uncompressed {
            out.copy_from_slice(&stored[..out.len()]);
            continue;
        }
        let what = format!("GCZ block {i} at 0x{at:X}");
        let decoded = decode_block(Codec::Zlib, stored, header.block_size as usize, &what)?;
        if decoded.len() != header.block_size as usize {
            return Err(error(format!(
                "Invalid {what}: decodes to {} B instead of the {} B block size",
                decoded.len(),
                header.block_size
            )));
        }
        out.copy_from_slice(&decoded[..out.len()]);
    }
    Ok(disc)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header with `blocks` blocks of `block_size` for `data_size` bytes.
    fn header_bytes(data_size: u64, block_size: u32, blocks: u32) -> Vec<u8> {
        let mut bytes = GCZ_MAGIC.to_le_bytes().to_vec();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&data_size.to_le_bytes());
        bytes.extend_from_slice(&block_size.to_le_bytes());
        bytes.extend_from_slice(&blocks.to_le_bytes());
        bytes
    }

    #[test]
    fn detection_needs_a_consistent_block_count() {
        assert_eq!(detect(&header_bytes(0x5000, 0x4000, 2)), Some(Layout::Gcz));
        assert_eq!(detect(&header_bytes(0x4000, 0x4000, 1)), Some(Layout::Gcz));
        assert_eq!(detect(&header_bytes(0x5000, 0x4000, 1)), None);
        assert_eq!(detect(&header_bytes(0x5000, 0x3000, 2)), None);
        assert_eq!(detect(&header_bytes(0x5000, 0x4000, 2)[..0x1F]), None);
    }

    #[test]
    fn sub_types_are_named() {
        assert_eq!(sub_type_name(0), "0 (GameCube disc)");
        assert_eq!(sub_type_name(1), "1 (Wii disc)");
        assert_eq!(sub_type_name(u32::MAX), "0xFFFFFFFF (not set)");
        assert_eq!(sub_type_name(7), "0x7 (unknown)");
    }
}
