//! The .xz container and LZMA-alone (`.lzma`) streams.
//!
//! The xz layout follows "The .xz File Format", version 1.2.1 (2024-04-08,
//! tukaani.org/xz/xz-file-format-1.2.1.txt): stream header, blocks with
//! filter chains, index and footer. LZMA2 and the BCJ/delta filters are
//! decoded by `lzma-rust2`; this module walks the container itself so that
//! the dictionary size is bounded before anything is allocated, the
//! consumed length is exact and every CRC and check is verified.
//! LZMA-alone follows LZMA SDK `DOC/lzma-specification.txt`: properties
//! byte, dictionary size (u32 LE) and decoded size (u64 LE, all ones when an
//! end marker terminates the stream).

use super::*;
use lzma_rust2::filter::bcj::BcjReader;
use lzma_rust2::filter::delta::DeltaReader;
use lzma_rust2::{Lzma2Reader, LzmaReader};
use sha2::{Digest, Sha256};
use std::io::Read;

/// Stream header magic.
pub(super) const XZ_MAGIC: [u8; 6] = [0xfd, b'7', b'z', b'X', b'Z', 0x00];

/// Stream footer magic.
const FOOTER_MAGIC: [u8; 2] = *b"YZ";

/// Stream header and footer size.
const STREAM_HEADER_SIZE: usize = 12;

/// Check types (section 2.1.1.2).
const CHECK_NONE: u8 = 0x00;
const CHECK_CRC32: u8 = 0x01;
const CHECK_CRC64: u8 = 0x04;
const CHECK_SHA256: u8 = 0x0a;

/// Filter IDs (section 5.3).
const FILTER_DELTA: u64 = 0x03;
const FILTER_X86: u64 = 0x04;
const FILTER_POWERPC: u64 = 0x05;
const FILTER_IA64: u64 = 0x06;
const FILTER_ARM: u64 = 0x07;
const FILTER_ARM_THUMB: u64 = 0x08;
const FILTER_SPARC: u64 = 0x09;
const FILTER_ARM64: u64 = 0x0a;
const FILTER_RISCV: u64 = 0x0b;
const FILTER_LZMA2: u64 = 0x21;

/// Block flags (section 3.1.2).
const BLOCK_FILTER_COUNT: u8 = 0x03;
const BLOCK_RESERVED: u8 = 0x3c;
const BLOCK_COMPRESSED_SIZE: u8 = 0x40;
const BLOCK_UNCOMPRESSED_SIZE: u8 = 0x80;

/// Largest valid LZMA2 dictionary-size property (section 5.3.1).
const LZMA2_DICT_MAX_BITS: u8 = 40;

/// LZMA-alone header: properties (1), dictionary size (4), decoded size (8).
const LZMA_HEADER_SIZE: usize = 13;

/// Largest valid LZMA properties byte: `(pb * 5 + lp) * 9 + lc` with
/// `lc <= 8`, `lp <= 4`, `pb <= 4`.
const LZMA_PROPERTIES_MAX: u8 = (4 * 5 + 4) * 9 + 8;

/// LZMA-alone decoded size meaning "terminated by an end marker".
const LZMA_SIZE_UNKNOWN: u64 = u64::MAX;

/// Smallest dictionary the LZMA decoders accept.
const DICT_MIN: u32 = 4096;

/// A multibyte integer (section 1.2): seven bits per byte, least
/// significant group first, at most nine bytes.
fn varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for i in 0..9 {
        let b = *data
            .get(*pos)
            .ok_or_else(|| error("Truncated xz multibyte integer"))?;
        *pos += 1;
        value |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            if b == 0 && i > 0 {
                return Err(error("Invalid xz multibyte integer"));
            }
            return Ok(value);
        }
    }
    Err(error("Invalid xz multibyte integer"))
}

/// Bytes stored for each check type.
fn check_size(check: u8) -> Result<usize> {
    match check {
        CHECK_NONE => Ok(0),
        CHECK_CRC32 => Ok(4),
        CHECK_CRC64 => Ok(8),
        CHECK_SHA256 => Ok(32),
        other => Err(error(format!("Unsupported xz check type 0x{other:02X}"))),
    }
}

fn check_name(check: u8) -> Option<&'static str> {
    match check {
        CHECK_CRC32 => Some("xz CRC-32"),
        CHECK_CRC64 => Some("xz CRC-64"),
        CHECK_SHA256 => Some("xz SHA-256"),
        _ => None,
    }
}

fn verify_check(check: u8, stored: &[u8], block: &[u8]) -> Result<()> {
    let matches = match check {
        CHECK_NONE => true,
        CHECK_CRC32 => stored == checksum::crc32(block).to_le_bytes(),
        CHECK_CRC64 => stored == checksum::crc64(block).to_le_bytes(),
        CHECK_SHA256 => stored == Sha256::digest(block).as_slice(),
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(error("Invalid xz block check"))
    }
}

/// LZMA2 dictionary size from its one-byte property.
fn lzma2_dict_size(property: u8) -> Result<u64> {
    match property {
        bits if bits > LZMA2_DICT_MAX_BITS => Err(error("Invalid xz LZMA2 dictionary size")),
        LZMA2_DICT_MAX_BITS => Ok(u64::from(u32::MAX)),
        bits => Ok((2 | u64::from(bits & 1)) << (bits / 2 + 11)),
    }
}

/// The dictionary to allocate: matches cannot reach further back than the
/// output cap, so a larger declared dictionary is never needed.
fn bounded_dict(declared: u64, limit: usize) -> u32 {
    let cap = u64::try_from(limit)
        .unwrap_or(u64::MAX)
        .max(u64::from(DICT_MIN));
    u32::try_from(declared.clamp(u64::from(DICT_MIN), cap)).unwrap_or(u32::MAX)
}

/// One filter in a block's chain.
struct Filter {
    id: u64,
    properties: Vec<u8>,
}

/// Block header (section 3.1): size byte, flags, optional sizes, filter
/// flags, zero padding and CRC-32.
struct BlockHeader {
    size: usize,
    compressed: Option<u64>,
    uncompressed: Option<u64>,
    filters: Vec<Filter>,
}

fn block_header(data: &[u8], start: usize) -> Result<BlockHeader> {
    let size = (usize::from(data[start]) + 1) * 4;
    let header = slice(data, start, size)?;
    let stored_crc = le_u32(header, size - 4)?;
    if checksum::crc32(&header[..size - 4]) != stored_crc {
        return Err(error(format!(
            "Invalid xz block header CRC-32 at 0x{start:X}"
        )));
    }
    let flags = header[1];
    if flags & BLOCK_RESERVED != 0 {
        return Err(error("Unsupported xz block flags"));
    }
    let body = &header[..size - 4];
    let mut pos = 2;
    let compressed = if flags & BLOCK_COMPRESSED_SIZE != 0 {
        Some(varint(body, &mut pos)?)
    } else {
        None
    };
    let uncompressed = if flags & BLOCK_UNCOMPRESSED_SIZE != 0 {
        Some(varint(body, &mut pos)?)
    } else {
        None
    };
    let mut filters = Vec::new();
    for _ in 0..=(flags & BLOCK_FILTER_COUNT) {
        let id = varint(body, &mut pos)?;
        let properties_size = usize::try_from(varint(body, &mut pos)?)
            .map_err(|_| error("Invalid xz filter properties"))?;
        let properties = slice(body, pos, properties_size)?.to_vec();
        pos += properties_size;
        filters.push(Filter { id, properties });
    }
    if !is_zero(&body[pos.min(body.len())..]) {
        return Err(error("Invalid xz block header padding"));
    }
    Ok(BlockHeader {
        size,
        compressed,
        uncompressed,
        filters,
    })
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0)
}

/// Optional four-byte start offset of a BCJ filter.
fn bcj_start(filter: &Filter) -> Result<usize> {
    match filter.properties.len() {
        0 => Ok(0),
        4 => Ok(usize::try_from(le_u32(&filter.properties, 0)?)
            .map_err(|_| error("Invalid xz BCJ start offset"))?),
        _ => Err(error("Invalid xz BCJ filter properties")),
    }
}

/// Decode a block's compressed data from `input` through its filter chain.
/// Filters are listed in encoding order, so the last (LZMA2) reads the
/// compressed bytes and the first produces the output.
fn decode_block(filters: &[Filter], input: &mut &[u8], limit: usize) -> Result<Vec<u8>> {
    let (last, rest) = filters
        .split_last()
        .ok_or_else(|| error("Missing xz filter"))?;
    if last.id != FILTER_LZMA2 || last.properties.len() != 1 {
        return Err(error(format!("Unsupported xz filter 0x{:X}", last.id)));
    }
    let dict = bounded_dict(lzma2_dict_size(last.properties[0])?, limit);
    let mut reader: Box<dyn Read + '_> = Box::new(Lzma2Reader::new(input, dict, None));
    for filter in rest.iter().rev() {
        reader = match filter.id {
            FILTER_DELTA => {
                let [distance] = filter.properties[..] else {
                    return Err(error("Invalid xz delta filter properties"));
                };
                Box::new(DeltaReader::new(reader, usize::from(distance) + 1))
            }
            FILTER_X86 => Box::new(BcjReader::new_x86(reader, bcj_start(filter)?)),
            FILTER_POWERPC => Box::new(BcjReader::new_ppc(reader, bcj_start(filter)?)),
            FILTER_IA64 => Box::new(BcjReader::new_ia64(reader, bcj_start(filter)?)),
            FILTER_ARM => Box::new(BcjReader::new_arm(reader, bcj_start(filter)?)),
            FILTER_ARM_THUMB => Box::new(BcjReader::new_arm_thumb(reader, bcj_start(filter)?)),
            FILTER_SPARC => Box::new(BcjReader::new_sparc(reader, bcj_start(filter)?)),
            FILTER_ARM64 => Box::new(BcjReader::new_arm64(reader, bcj_start(filter)?)),
            FILTER_RISCV => Box::new(BcjReader::new_riscv(reader, bcj_start(filter)?)),
            other => return Err(error(format!("Unsupported xz filter 0x{other:X}"))),
        };
    }
    read_capped(reader, limit, "xz")
}

/// Decode one stream starting at `start`, appending to `out`. Returns the
/// stream's end offset and its check type.
fn stream(data: &[u8], start: usize, out: &mut Vec<u8>, limit: usize) -> Result<(usize, u8)> {
    let header = slice(data, start, STREAM_HEADER_SIZE)?;
    if header[..6] != XZ_MAGIC {
        return Err(error(format!("Missing xz stream header at 0x{start:X}")));
    }
    let flags = [header[6], header[7]];
    if flags[0] != 0 || flags[1] & 0xf0 != 0 {
        return Err(error("Unsupported xz stream flags"));
    }
    if checksum::crc32(&flags) != le_u32(header, 8)? {
        return Err(error("Invalid xz stream header CRC-32"));
    }
    let check = flags[1];
    let check_len = check_size(check)?;
    let mut pos = start + STREAM_HEADER_SIZE;
    let mut records: Vec<(u64, u64)> = Vec::new();
    loop {
        let indicator = *data.get(pos).ok_or_else(|| error("Truncated xz stream"))?;
        if indicator == 0 {
            break;
        }
        let block = block_header(data, pos)?;
        let compressed_start = pos + block.size;
        let mut input = data
            .get(compressed_start..)
            .ok_or_else(|| error("Truncated xz block"))?;
        let available = input.len();
        let remaining = limit.saturating_sub(out.len());
        let decoded = decode_block(&block.filters, &mut input, remaining)?;
        let compressed = (available - input.len()) as u64;
        if block.compressed.is_some_and(|size| size != compressed)
            || block
                .uncompressed
                .is_some_and(|size| size != decoded.len() as u64)
        {
            return Err(error(format!("Invalid xz block sizes at 0x{pos:X}")));
        }
        let mut end = compressed_start + available - input.len();
        let padded = align4(end - pos)? + pos;
        if !is_zero(slice(data, end, padded - end)?) {
            return Err(error("Invalid xz block padding"));
        }
        end = padded;
        verify_check(check, slice(data, end, check_len)?, &decoded)?;
        let unpadded = (block.size as u64) + compressed + check_len as u64;
        records.push((unpadded, decoded.len() as u64));
        out.extend_from_slice(&decoded);
        pos = end + check_len;
    }
    let index_size = index(data, pos, &records)?;
    let footer_start = pos + index_size;
    let footer = slice(data, footer_start, STREAM_HEADER_SIZE)?;
    if footer[10..] != FOOTER_MAGIC || footer[8..10] != flags {
        return Err(error("Invalid xz stream footer"));
    }
    if checksum::crc32(&footer[4..10]) != le_u32(footer, 0)? {
        return Err(error("Invalid xz stream footer CRC-32"));
    }
    let backward = (u64::from(le_u32(footer, 4)?) + 1) * 4;
    if backward != index_size as u64 {
        return Err(error("Invalid xz backward size"));
    }
    Ok((footer_start + STREAM_HEADER_SIZE, check))
}

/// Validate the index at `start` against the decoded blocks; returns its
/// size including padding and CRC-32.
fn index(data: &[u8], start: usize, records: &[(u64, u64)]) -> Result<usize> {
    let mut pos = start + 1;
    let count = varint(data, &mut pos)?;
    if count != records.len() as u64 {
        return Err(error("Invalid xz index record count"));
    }
    for &(unpadded, uncompressed) in records {
        if varint(data, &mut pos)? != unpadded || varint(data, &mut pos)? != uncompressed {
            return Err(error("Invalid xz index record"));
        }
    }
    let padded = align4(pos - start)? + start;
    if !is_zero(slice(data, pos, padded - pos)?) {
        return Err(error("Invalid xz index padding"));
    }
    if checksum::crc32(slice(data, start, padded - start)?) != le_u32(data, padded)? {
        return Err(error("Invalid xz index CRC-32"));
    }
    Ok(padded + 4 - start)
}

/// Decode concatenated xz streams with optional four-byte zero padding.
pub(super) fn xz(data: &[u8], limit: usize) -> Result<Decoded> {
    let mut out = Vec::new();
    let mut pos = 0;
    let mut checks = Vec::new();
    loop {
        let (end, check) = stream(data, pos, &mut out, limit)?;
        checks.push(check);
        pos = end;
        while data.get(pos..pos + 4).is_some_and(is_zero) {
            pos += 4;
        }
        if !data[pos..].starts_with(&XZ_MAGIC) {
            break;
        }
    }
    let first = checks[0];
    let check = if checks.iter().all(|c| *c == first) {
        check_name(first)
    } else {
        Some("xz block checks")
    };
    Ok(Decoded {
        data: out,
        consumed: Some(pos),
        check: check.filter(|_| checks.iter().all(|c| *c != CHECK_NONE)),
    })
}

/// LZMA-alone header fields.
pub(super) struct LzmaHeader {
    properties: u8,
    dict_size: u32,
    decoded_size: u64,
}

/// Validate an LZMA-alone header. The properties byte and dictionary are
/// the only structure the format has, so recognition also requires a
/// complete decode.
pub(super) fn lzma_header(data: &[u8]) -> Result<LzmaHeader> {
    let header = slice(data, 0, LZMA_HEADER_SIZE)?;
    let properties = header[0];
    if properties > LZMA_PROPERTIES_MAX {
        return Err(error(format!("Invalid LZMA properties 0x{properties:02X}")));
    }
    Ok(LzmaHeader {
        properties,
        dict_size: le_u32(header, 1)?,
        decoded_size: u64::from(le_u32(header, 5)?) | (u64::from(le_u32(header, 9)?) << 32),
    })
}

/// Decode an LZMA-alone stream.
pub(super) fn lzma(data: &[u8], limit: usize) -> Result<Decoded> {
    let header = lzma_header(data)?;
    if header.decoded_size != LZMA_SIZE_UNKNOWN
        && header.decoded_size > u64::try_from(limit).unwrap_or(u64::MAX)
    {
        return Err(exceeds(limit));
    }
    let dict = bounded_dict(u64::from(header.dict_size), limit);
    let mut input = &data[LZMA_HEADER_SIZE..];
    let available = input.len();
    let reader = LzmaReader::new_with_props(
        &mut input,
        header.decoded_size,
        header.properties,
        dict,
        None,
    )
    .map_err(|e| error(format!("Invalid LZMA stream: {e}")))?;
    let out = read_capped(reader, limit, "LZMA")?;
    if header.decoded_size != LZMA_SIZE_UNKNOWN && out.len() as u64 != header.decoded_size {
        return Err(error("Truncated LZMA stream"));
    }
    Ok(Decoded {
        data: out,
        consumed: Some(LZMA_HEADER_SIZE + available - input.len()),
        check: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_follow_the_xz_encoding() {
        let mut pos = 0;
        assert_eq!(varint(&[0x7f], &mut pos).unwrap(), 0x7f);
        pos = 0;
        assert_eq!(varint(&[0x80, 0x01], &mut pos).unwrap(), 0x80);
        pos = 0;
        assert!(varint(&[0x80, 0x00], &mut pos).is_err());
        pos = 0;
        assert!(varint(&[0xff; 10], &mut pos).is_err());
    }

    #[test]
    fn lzma2_dictionary_sizes_match_the_specification() {
        assert_eq!(lzma2_dict_size(0).unwrap(), 4096);
        assert_eq!(lzma2_dict_size(1).unwrap(), 6144);
        assert_eq!(lzma2_dict_size(16).unwrap(), 1 << 20);
        assert_eq!(lzma2_dict_size(40).unwrap(), u64::from(u32::MAX));
        assert!(lzma2_dict_size(41).is_err());
        assert_eq!(bounded_dict(u64::from(u32::MAX), 1 << 20), 1 << 20);
    }
}
