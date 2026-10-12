//! Nintendo backward LZ ("BLZ", "reverse LZSS"): the compression of 3DS
//! `ExeFS` `.code` when the `ExHeader` sets `CompressExefsCode`.
//!
//! Layout and algorithm from ctrtool `ctrtool/src/lzss.c` in
//! `3DSGuy/Project_CTR` at `d52c2b0e788c2d085763d7c5dcc4b2edd9ffb7d8`
//! (`lzss_get_decompressed_size`, `lzss_decompress`). The stream is decoded
//! from its end towards its start. The last eight bytes are a footer of two
//! little-endian words: `buffer_top_and_bottom` (bits 31-24: bytes at the
//! end that are footer or padding; bits 23-0: length of the compressed
//! region, counted back from the end) and `original_bottom` (the decoded
//! size minus the stored size). Bytes below the compressed region are
//! stored as-is and keep their position.
//!
//! The stream has no magic, so it is never recognized standalone; only a
//! container field names it.

use super::*;

/// Footer size: `buffer_top_and_bottom` and `original_bottom`.
const FOOTER_SIZE: usize = 8;

/// `buffer_top_and_bottom` bits 23-0: compressed region length.
const REGION_LENGTH_MASK: u32 = 0x00ff_ffff;

/// `buffer_top_and_bottom` bits 31-24: footer and padding length.
const HEADER_LENGTH_SHIFT: u32 = 24;

/// A control bit set selects a back-reference instead of a literal.
const MATCH_FLAG: u8 = 0x80;

/// Back-reference token: bits 15-12 length minus [`MIN_MATCH`], bits 11-0
/// displacement minus [`DISPLACEMENT_BIAS`].
const LENGTH_SHIFT: u32 = 12;
const LENGTH_MASK: u16 = 0xf;
const DISPLACEMENT_MASK: u16 = 0x0fff;
const MIN_MATCH: usize = 3;
const DISPLACEMENT_BIAS: usize = 2;

/// Control bits per control byte.
const TOKENS_PER_CONTROL: usize = 8;

/// The footer fields of a BLZ stream, in stream coordinates.
struct Footer {
    /// Where decoding starts reading (below the footer and padding).
    read_start: usize,
    /// Start of the compressed region; bytes below it are stored as-is.
    region_start: usize,
    /// Decoded size in bytes.
    decoded_size: usize,
}

/// Read and validate the footer of `data`, refusing a decoded size beyond
/// `limit` before anything is allocated.
fn footer(data: &[u8], limit: usize) -> Result<Footer> {
    if data.len() < FOOTER_SIZE {
        return Err(error(format!(
            "Truncated BLZ stream: {} B, footer needs {FOOTER_SIZE} B",
            data.len()
        )));
    }
    let footer_at = data.len() - FOOTER_SIZE;
    let top_and_bottom = le_u32(data, footer_at)?;
    let original_bottom = le_u32(data, footer_at + 4)?;
    let header_length = (top_and_bottom >> HEADER_LENGTH_SHIFT) as usize;
    let region_length = (top_and_bottom & REGION_LENGTH_MASK) as usize;
    // The footer itself lies inside the skipped header length, which lies
    // inside the compressed region (derived from the decoder's cursors).
    if header_length < FOOTER_SIZE || header_length > region_length || region_length > data.len() {
        return Err(error(format!(
            "Invalid BLZ footer: header length {header_length} B, compressed region {region_length} B, stream {} B",
            data.len()
        )));
    }
    let decoded_size = usize::try_from(original_bottom)
        .ok()
        .and_then(|extra| data.len().checked_add(extra))
        .ok_or_else(|| error("Invalid BLZ decoded size"))?;
    if decoded_size > limit {
        return Err(exceeds(limit));
    }
    Ok(Footer {
        read_start: data.len() - header_length,
        region_start: data.len() - region_length,
        decoded_size,
    })
}

/// Decode a BLZ stream into at most `limit` bytes.
pub(super) fn decode(data: &[u8], limit: usize) -> Result<Decoded> {
    let footer = footer(data, limit)?;
    let mut out = data.to_vec();
    out.resize(footer.decoded_size, 0);
    let stop = footer.region_start;
    let mut index = footer.read_start;
    let mut out_pos = footer.decoded_size;
    while index > stop {
        index -= 1;
        let mut control = data[index];
        for _ in 0..TOKENS_PER_CONTROL {
            if index <= stop || out_pos == 0 {
                break;
            }
            if control & MATCH_FLAG == 0 {
                index -= 1;
                out_pos -= 1;
                out[out_pos] = data[index];
            } else {
                out_pos = copy_match(data, &mut index, stop, &mut out, out_pos)?;
            }
            control <<= 1;
        }
    }
    // Every decoded byte above the stored-as-is prefix must have been
    // written; otherwise the region and the declared size disagree (derived
    // from the decoder's cursors, which meet at the region start).
    if out_pos != stop {
        return Err(error(format!(
            "Invalid BLZ stream: decoding ended at 0x{out_pos:X}, expected 0x{stop:X}"
        )));
    }
    Ok(Decoded {
        data: out,
        consumed: Some(data.len()),
        check: None,
    })
}

/// Copy one back-reference below `out_pos`, reading its two-byte token
/// just below `index`. Returns the new write position.
fn copy_match(
    data: &[u8],
    index: &mut usize,
    stop: usize,
    out: &mut [u8],
    out_pos: usize,
) -> Result<usize> {
    // A token below the region start would read stored bytes (stricter
    // than ctrtool, which only requires two bytes below the cursor).
    if *index < stop + 2 {
        return Err(error(format!(
            "Truncated BLZ back-reference at 0x{:X}",
            *index
        )));
    }
    *index -= 2;
    let token = u16::from_le_bytes([data[*index], data[*index + 1]]);
    let length = usize::from((token >> LENGTH_SHIFT) & LENGTH_MASK) + MIN_MATCH;
    let displacement = usize::from(token & DISPLACEMENT_MASK) + DISPLACEMENT_BIAS;
    if out_pos < length {
        return Err(error(format!(
            "Invalid BLZ back-reference at 0x{:X}: length {length} B below the output start",
            *index
        )));
    }
    let mut pos = out_pos;
    for _ in 0..length {
        let source = pos + displacement;
        let byte = *out.get(source).ok_or_else(|| {
            error(format!(
                "Invalid BLZ back-reference at 0x{:X}: displacement beyond the output",
                *index
            ))
        })?;
        pos -= 1;
        out[pos] = byte;
    }
    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "PQ" stored as-is, then a compressed region that decodes to "abc"
    /// repeated 19 times: control byte `0b0001_1100` (three literals, three
    /// back-references), literals read downwards ("c", "b", "a"), and three
    /// tokens `0xF000` (length 15 + 3, displacement 0 + 2, so a distance of
    /// three bytes). Footer: header length 8, region length 10 + 8, decoded
    /// size 2 + 57 = stream size 20 + 39.
    fn stream() -> Vec<u8> {
        let mut data = b"PQ".to_vec();
        for _ in 0..3 {
            data.extend_from_slice(&0xf000u16.to_le_bytes());
        }
        data.extend_from_slice(b"abc");
        data.push(0b0001_1100);
        let top_and_bottom = (8u32 << 24) | 0x12;
        data.extend_from_slice(&top_and_bottom.to_le_bytes());
        data.extend_from_slice(&39u32.to_le_bytes());
        data
    }

    fn expected() -> Vec<u8> {
        let mut out = b"PQ".to_vec();
        out.extend_from_slice(&b"abc".repeat(19));
        out
    }

    #[test]
    fn blz_decodes_literals_and_back_references_from_the_end() {
        let decoded = decode(&stream(), MAX_PAYLOAD).unwrap();
        assert_eq!(decoded.data, expected());
        assert_eq!(decoded.consumed, Some(20));
    }

    #[test]
    fn blz_refuses_a_decoded_size_beyond_the_limit() {
        assert!(decode(&stream(), 58).is_err());
        assert!(decode(&stream(), 59).is_ok());
    }

    #[test]
    fn blz_rejects_inconsistent_footers_and_truncation() {
        // Footer bytes 12..16 hold `buffer_top_and_bottom`, 16..20
        // `original_bottom`.
        let mut short_header = stream();
        short_header[15] = 7;
        assert!(decode(&short_header, MAX_PAYLOAD).is_err());

        let mut long_region = stream();
        long_region[12] = 21;
        assert!(decode(&long_region, MAX_PAYLOAD).is_err());

        let mut wrong_size = stream();
        wrong_size[16] = 40;
        assert!(decode(&wrong_size, MAX_PAYLOAD).is_err());

        let data = stream();
        for end in 0..data.len() {
            assert!(decode(&data[..end], MAX_PAYLOAD).is_err(), "prefix {end}");
        }
    }

    #[test]
    fn blz_rejects_back_references_outside_the_output() {
        // One literal, then a token with displacement 0xFFF + 2.
        let mut data = vec![0xff, 0x0f, b'z', 0b0100_0000];
        let top_and_bottom = (8u32 << 24) | 0x0c;
        data.extend_from_slice(&top_and_bottom.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        assert!(decode(&data, MAX_PAYLOAD).is_err());
    }
}
