//! Android sparse images (`libsparse/sparse_format.h` and
//! `libsparse/sparse_read.cpp` at system/core `a3b721a3`).
//!
//! A 28-byte file header is followed by chunks, each a 12-byte header and
//! its data: RAW blocks, a 4-byte FILL pattern, `DONT_CARE` (no data) or a
//! CRC32 of the output so far. `chunk_sz` counts output blocks, `total_sz`
//! counts input bytes including the chunk header. All fields are
//! little-endian. The expanded image is a partition image (filesystem,
//! `super` image, boot image) and is classified as one component.

use super::*;
use crate::formats::checksum;

/// Fixed part of the file and chunk headers; larger declared sizes are
/// skipped, as libsparse does.
const FILE_HEADER_SIZE: usize = 28;
const CHUNK_HEADER_SIZE: usize = 12;

/// Major version libsparse reads ("reject images with higher major
/// versions").
const MAJOR_VERSION: u16 = 1;

/// Chunk types (`CHUNK_TYPE_*`).
const CHUNK_TYPE_RAW: u16 = 0xcac1;
const CHUNK_TYPE_FILL: u16 = 0xcac2;
const CHUNK_TYPE_DONT_CARE: u16 = 0xcac3;
const CHUNK_TYPE_CRC32: u16 = 0xcac4;

/// FILL and CRC32 chunks carry exactly four data bytes.
const WORD_DATA_SIZE: usize = 4;

/// Expansion transform name for the component.
const TRANSFORM: &str = "Android sparse";

/// The file header fields after the magic.
struct Header {
    minor_version: u16,
    file_header_size: usize,
    chunk_header_size: usize,
    block_size: u32,
    total_blocks: u32,
    total_chunks: u32,
    image_checksum: u32,
}

/// What a chunk contributes to the output.
enum Content<'a> {
    Raw(&'a [u8]),
    Fill([u8; 4]),
    DontCare,
    Crc32(u32),
}

/// One chunk: file offset of its header, output blocks, content.
struct Chunk<'a> {
    offset: usize,
    blocks: u32,
    content: Content<'a>,
}

/// File header: magic (4), major and minor version (u16), file and chunk
/// header sizes (u16), block size, total blocks, total chunks and image
/// checksum (u32).
fn header(data: &[u8]) -> Result<Header> {
    let header = slice(data, 0, FILE_HEADER_SIZE, "sparse image header")?;
    if le_u32(header, 0)? != SPARSE_MAGIC {
        return Err(error("Missing sparse image magic"));
    }
    let major = le_u16(header, 4)?;
    if major != MAJOR_VERSION {
        return Err(error(format!(
            "Unsupported sparse image major version {major}"
        )));
    }
    let file_header_size = usize::from(le_u16(header, 8)?);
    let chunk_header_size = usize::from(le_u16(header, 10)?);
    if file_header_size < FILE_HEADER_SIZE {
        return Err(error(format!(
            "Invalid sparse file header size {file_header_size} B"
        )));
    }
    if chunk_header_size < CHUNK_HEADER_SIZE {
        return Err(error(format!(
            "Invalid sparse chunk header size {chunk_header_size} B"
        )));
    }
    let block_size = le_u32(header, 12)?;
    if block_size == 0 || block_size % 4 != 0 {
        return Err(error(format!("Invalid sparse block size {block_size} B")));
    }
    let total_blocks = le_u32(header, 16)?;
    if total_blocks == 0 {
        return Err(error("Invalid sparse image: total_blks is 0"));
    }
    Ok(Header {
        minor_version: le_u16(header, 6)?,
        file_header_size,
        chunk_header_size,
        block_size,
        total_blocks,
        total_chunks: le_u32(header, 20)?,
        image_checksum: le_u32(header, 24)?,
    })
}

/// Walk the chunk list: chunk type (u16), reserved (u16), output blocks
/// (u32), input bytes including the header (u32). The blocks must add up
/// to the header's `total_blks`, and only padding may follow the last
/// chunk.
fn chunks<'a>(data: &'a [u8], header: &Header) -> Result<Vec<Chunk<'a>>> {
    let mut pos = header.file_header_size;
    slice(data, 0, pos, "sparse image header")?;
    let room = (data.len() - pos) / header.chunk_header_size;
    if header.total_chunks as usize > room {
        return Err(error(format!(
            "Truncated sparse image: {} chunks declared, at most {room} fit in the file",
            header.total_chunks
        )));
    }
    let block_size = u64::from(header.block_size);
    let mut chunks = Vec::with_capacity(header.total_chunks as usize);
    let mut blocks = 0u64;
    for i in 0..header.total_chunks {
        let chunk_header = slice(data, pos, header.chunk_header_size, "sparse chunk header")?;
        let kind = le_u16(chunk_header, 0)?;
        let chunk_blocks = le_u32(chunk_header, 4)?;
        let total_size = le_u32(chunk_header, 8)? as usize;
        let data_size = total_size
            .checked_sub(header.chunk_header_size)
            .ok_or_else(|| {
                error(format!(
                    "Invalid sparse chunk {i} at 0x{pos:X}: total size {total_size} B is less than its header"
                ))
            })?;
        let body = slice(
            data,
            pos + header.chunk_header_size,
            data_size,
            "sparse chunk data",
        )?;
        let content = match kind {
            CHUNK_TYPE_RAW => {
                if data_size as u64 != u64::from(chunk_blocks) * block_size {
                    return Err(error(format!(
                        "Invalid sparse RAW chunk {i} at 0x{pos:X}: {data_size} B of data for {chunk_blocks} blocks"
                    )));
                }
                Content::Raw(body)
            }
            CHUNK_TYPE_FILL => Content::Fill(word(body, i, pos, "FILL")?),
            CHUNK_TYPE_DONT_CARE => {
                if data_size != 0 {
                    return Err(error(format!(
                        "Invalid sparse DONT_CARE chunk {i} at 0x{pos:X}: {data_size} B of data"
                    )));
                }
                Content::DontCare
            }
            CHUNK_TYPE_CRC32 => Content::Crc32(u32::from_le_bytes(word(body, i, pos, "CRC32")?)),
            _ => {
                // libsparse logs and reads the next header from inside this
                // chunk's data; a classifier must not guess.
                return Err(error(format!(
                    "Unknown sparse chunk type 0x{kind:04X} at 0x{pos:X}"
                )));
            }
        };
        // CRC32 chunks contribute no output blocks (libsparse ignores chunk_sz).
        let output_blocks = if matches!(content, Content::Crc32(_)) {
            0
        } else {
            chunk_blocks
        };
        blocks += u64::from(output_blocks);
        if blocks > u64::from(header.total_blocks) {
            return Err(error(format!(
                "Invalid sparse image: chunk {i} at 0x{pos:X} ends past total_blks {}",
                header.total_blocks
            )));
        }
        chunks.push(Chunk {
            offset: pos,
            blocks: output_blocks,
            content,
        });
        pos += total_size;
    }
    if blocks != u64::from(header.total_blocks) {
        return Err(error(format!(
            "Invalid sparse image: chunks cover {blocks} blocks, header declares {}",
            header.total_blocks
        )));
    }
    let trailing = &data[pos..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} after the last sparse chunk at 0x{pos:X}",
            size_text(trailing.len())
        )));
    }
    Ok(chunks)
}

/// The four data bytes of a FILL or CRC32 chunk.
fn word(body: &[u8], index: u32, pos: usize, kind: &str) -> Result<[u8; 4]> {
    body.try_into().map_err(|_| {
        error(format!(
            "Invalid sparse {kind} chunk {index} at 0x{pos:X}: {} B of data, expected {WORD_DATA_SIZE}",
            body.len()
        ))
    })
}

/// The expanded image, cut at [`MAX_PAYLOAD`], and what was checked.
struct Expansion {
    image: Vec<u8>,
    /// The full expanded size in bytes.
    full_size: u64,
    crc_verified: usize,
    crc_unchecked: usize,
}

/// Expand the chunks into the first [`MAX_PAYLOAD`] bytes of the image:
/// RAW bytes, FILL patterns, zeros for `DONT_CARE`. CRC32 chunks are checked
/// against the CRC-32 of everything expanded before them while that is
/// complete.
fn expand(chunks: &[Chunk<'_>], header: &Header) -> Result<Expansion> {
    let block_size = u64::from(header.block_size);
    let full_size = u64::from(header.total_blocks) * block_size;
    let cap = usize::try_from(full_size).map_or(MAX_PAYLOAD, |size| size.min(MAX_PAYLOAD));
    let mut image = vec![0u8; cap];
    // Raw CRC-32 register of the output so far, while it is all expanded.
    let mut crc = Some(!0u32);
    let mut expansion = Expansion {
        image: Vec::new(),
        full_size,
        crc_verified: 0,
        crc_unchecked: 0,
    };
    let mut at = 0u64;
    for chunk in chunks {
        let size = u64::from(chunk.blocks) * block_size;
        let end = at + size;
        let start = usize::try_from(at).unwrap_or(usize::MAX).min(cap);
        let stop = usize::try_from(end).unwrap_or(usize::MAX).min(cap);
        let out = &mut image[start..stop];
        match &chunk.content {
            Content::Raw(bytes) => out.copy_from_slice(&bytes[..out.len()]),
            Content::Fill(pattern) => {
                for (byte, value) in out.iter_mut().zip(pattern.iter().cycle()) {
                    *byte = *value;
                }
            }
            Content::DontCare => {}
            Content::Crc32(stored) => match crc {
                Some(register) if !register != *stored => {
                    return Err(error(format!(
                        "Invalid sparse CRC32 chunk at 0x{:X}: stored 0x{stored:08X}, computed 0x{:08X}",
                        chunk.offset, !register
                    )));
                }
                Some(_) => expansion.crc_verified += 1,
                None => expansion.crc_unchecked += 1,
            },
        }
        crc = match crc {
            Some(register) if stop as u64 == end => {
                Some(checksum::crc32_update(register, &image[start..stop]))
            }
            _ => None,
        };
        at = end;
    }
    expansion.image = image;
    Ok(expansion)
}

/// Parse a sparse image into one "Expanded image" component.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = header(data)?;
    let chunks = chunks(data, &header)?;
    let expansion = expand(&chunks, &header)?;
    let count = |kind: fn(&Content<'_>) -> bool| chunks.iter().filter(|c| kind(&c.content)).count();
    let raw = count(|c| matches!(c, Content::Raw(_)));
    let fill = count(|c| matches!(c, Content::Fill(_)));
    let dont_care = count(|c| matches!(c, Content::DontCare));
    let crc = count(|c| matches!(c, Content::Crc32(_)));

    let mut c = Container::new(
        FileFormat::AndroidSparse,
        format!("Sparse image v{MAJOR_VERSION}.{}", header.minor_version),
        KEY_PREFIX,
    );
    c.consumed = data.len();
    c.notes.push(format!(
        "Android sparse image v{MAJOR_VERSION}.{}; block size {} B; {} blocks ({} B expanded) in {} chunks: {raw} RAW, {fill} FILL, {dont_care} DONT_CARE, {crc} CRC32",
        header.minor_version,
        header.block_size,
        header.total_blocks,
        expansion.full_size,
        chunks.len()
    ));
    if expansion.crc_verified > 0 {
        c.notes.push(format!(
            "{} CRC32 chunks verified against the expanded data",
            expansion.crc_verified
        ));
    }
    if expansion.crc_unchecked > 0 {
        c.notes.push(format!(
            "{} CRC32 chunks after the {} expansion limit not verified",
            expansion.crc_unchecked,
            size_text(MAX_PAYLOAD)
        ));
    }
    let complete = expansion.image.len() as u64 == expansion.full_size;
    if header.image_checksum != 0 {
        // libsparse writes 0 here and never checks it.
        c.notes.push(if !complete {
            "Header image_checksum not verified: the image exceeds the expansion limit".into()
        } else if checksum::crc32(&expansion.image) == header.image_checksum {
            "Header image_checksum matches the CRC-32 of the expanded image".into()
        } else {
            format!(
                "Header image_checksum 0x{:08X} does not match the CRC-32 of the expanded image; libsparse does not check it",
                header.image_checksum
            )
        });
    }
    if !complete {
        c.notes.push(format!(
            "Expanded image is {} B; only the first {} were expanded and analyzed",
            expansion.full_size,
            size_text(MAX_PAYLOAD)
        ));
    }
    c.notes.push(
        "Sparse chunks carry no ISA; the expanded partition image is classified on its own".into(),
    );
    c.push_metadata(
        "android_sparse_block_size",
        "Block size (B)",
        u64::from(header.block_size),
    );
    c.push_metadata(
        "android_sparse_total_blocks",
        "Total blocks",
        u64::from(header.total_blocks),
    );
    c.push_metadata(
        "android_sparse_total_chunks",
        "Total chunks",
        u64::from(header.total_chunks),
    );
    c.push_metadata(
        "android_sparse_expanded_size",
        "Expanded size (B)",
        expansion.full_size,
    );
    c.children.push(Child::decoded(
        "Expanded image",
        0,
        data.len(),
        Cow::Owned(expansion.image),
        TRANSFORM,
    ));
    Ok(c)
}
