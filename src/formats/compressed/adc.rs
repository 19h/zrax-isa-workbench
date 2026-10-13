//! Apple Data Compression (ADC), the codec of UDIF chunk type `0x80000004`
//! (`hdiutil` format UDCO).
//!
//! Layout from libdmg-hfsplus `dmg/adc.c` (`adc_decompress`,
//! `adc_chunk_type`, `adc_chunk_size`, `adc_chunk_offset`) at commit
//! `7ac55ec64c96f7800d9818ce64c79670e7f02b67`, cross-checked against 7-Zip
//! `CPP/7zip/Archive/DmgHandler.cpp` (`CAdcDecoder::Code`) at commit
//! `9128b80e3a471108678e2b3ec3c985861c8d7b0f`. The stream is a sequence of
//! tokens with no header, size field or end marker:
//!
//! - a first byte with bit 7 set starts a literal run of
//!   `(byte & 0x7F) + 1` bytes, which follow;
//! - bit 7 clear and bit 6 set: a three-byte match of `(byte & 0x3F) + 4`
//!   bytes whose distance minus one is the next two bytes, big-endian;
//! - both clear: a two-byte match of `((byte & 0x3F) >> 2) + 3` bytes whose
//!   distance minus one is bits 1-0 of the first byte and the next byte.
//!
//! Matches copy byte by byte from the output, so a match may overlap the
//! bytes it writes (a distance of one repeats the last byte). The stream
//! has no magic and is decoded only where a UDIF block table names it.

use super::*;

/// Bit 7 of a token starts a literal run.
const LITERAL_FLAG: u8 = 0x80;

/// The literal run length minus one.
const LITERAL_LENGTH_MASK: u8 = 0x7f;

/// Bit 6 of a match token selects the three-byte form.
const LONG_MATCH_FLAG: u8 = 0x40;

/// The length field of a match token.
const MATCH_LENGTH_MASK: u8 = 0x3f;

/// A two-byte match keeps its length in bits 5-2 and the high bits of its
/// distance in bits 1-0.
const SHORT_LENGTH_SHIFT: u32 = 2;
const SHORT_DISTANCE_MASK: u8 = 0x03;

/// The shortest lengths each form encodes.
const SHORT_MIN_MATCH: usize = 3;
const LONG_MIN_MATCH: usize = 4;

/// The stream being read.
struct Input<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Input<'a> {
    /// The next `len` bytes.
    fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let bytes = self
            .pos
            .checked_add(len)
            .and_then(|end| self.data.get(self.pos..end))
            .ok_or_else(|| error(format!("Truncated ADC stream at 0x{:X}", self.pos)))?;
        self.pos += len;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }
}

/// A back-reference: copy `length` bytes from `distance` bytes back.
struct Match {
    length: usize,
    distance: usize,
}

/// Read the rest of a match token whose first byte is `token`.
fn read_match(input: &mut Input<'_>, token: u8) -> Result<Match> {
    if token & LONG_MATCH_FLAG != 0 {
        let distance = input.bytes(2)?;
        return Ok(Match {
            length: usize::from(token & MATCH_LENGTH_MASK) + LONG_MIN_MATCH,
            distance: usize::from(u16::from_be_bytes([distance[0], distance[1]])) + 1,
        });
    }
    let low = input.byte()?;
    Ok(Match {
        length: usize::from((token & MATCH_LENGTH_MASK) >> SHORT_LENGTH_SHIFT) + SHORT_MIN_MATCH,
        distance: (usize::from(token & SHORT_DISTANCE_MASK) << 8 | usize::from(low)) + 1,
    })
}

/// Decode a whole ADC stream into at most `limit` bytes. Every input byte
/// belongs to a token, so the loop is bounded by the input size; output
/// beyond `limit` is an error, as for the other codecs.
pub(super) fn decode(data: &[u8], limit: usize) -> Result<Decoded> {
    let mut input = Input { data, pos: 0 };
    let mut out: Vec<u8> = Vec::with_capacity(limit.min(data.len().saturating_mul(4)));
    while input.pos < data.len() {
        let at = input.pos;
        let token = input.byte()?;
        if token & LITERAL_FLAG != 0 {
            let length = usize::from(token & LITERAL_LENGTH_MASK) + 1;
            let literals = input.bytes(length)?;
            if out.len() + length > limit {
                return Err(exceeds(limit));
            }
            out.extend_from_slice(literals);
            continue;
        }
        let Match { length, distance } = read_match(&mut input, token)?;
        if distance > out.len() {
            return Err(error(format!(
                "Invalid ADC match at 0x{at:X}: distance {distance} B, {} B decoded",
                out.len()
            )));
        }
        if out.len() + length > limit {
            return Err(exceeds(limit));
        }
        let start = out.len() - distance;
        for i in 0..length {
            let b = out[start + i];
            out.push(b);
        }
    }
    Ok(Decoded {
        data: out,
        consumed: Some(data.len()),
        check: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_runs_copy_the_following_bytes() {
        // 0x82: a literal run of three bytes.
        let decoded = decode(&[0x82, b'a', b'b', b'c'], 64).unwrap();
        assert_eq!(decoded.data, b"abc");
        assert_eq!(decoded.consumed, Some(4));
    }

    #[test]
    fn short_matches_copy_back_with_ten_bit_distances() {
        // Literals "abc", then a two-byte match: length (0b0000 >> 0) + 3,
        // distance (0b00 << 8 | 2) + 1 = 3.
        let stream = [0x82, b'a', b'b', b'c', 0x00, 0x02];
        assert_eq!(decode(&stream, 64).unwrap().data, b"abcabc");
        // Length field 0b1111 (token 0x3C): 15 + 3 = 18 bytes; distance 1
        // repeats the last byte.
        let stream = [0x80, b'z', 0x3c, 0x00];
        assert_eq!(decode(&stream, 64).unwrap().data, [b'z'; 19]);
        // The high distance bits come from the token: 0x01 << 8 | 0xFF + 1
        // = 512 back.
        let mut stream = Vec::new();
        for chunk in (0..=255u8)
            .cycle()
            .take(512)
            .collect::<Vec<_>>()
            .chunks(128)
        {
            stream.push(0x80 | u8::try_from(chunk.len() - 1).expect("at most 128"));
            stream.extend_from_slice(chunk);
        }
        stream.extend_from_slice(&[0x01, 0xff]);
        let decoded = decode(&stream, 1024).unwrap().data;
        assert_eq!(&decoded[512..], &[0, 1, 2]);
    }

    #[test]
    fn long_matches_use_sixteen_bit_distances() {
        // Literals "xyz", then a three-byte match: length 0x05 + 4 = 9,
        // distance 0x0002 + 1 = 3 (overlapping its own output).
        let stream = [0x82, b'x', b'y', b'z', 0x45, 0x00, 0x02];
        assert_eq!(decode(&stream, 64).unwrap().data, b"xyzxyzxyzxyz");
    }

    #[test]
    fn matches_before_the_output_start_are_errors() {
        let message = decode(&[0x80, b'a', 0x00, 0x05], 64)
            .unwrap_err()
            .to_string();
        assert_eq!(
            message,
            "Compressed stream parse error: Invalid ADC match at 0x2: distance 6 B, 1 B decoded"
        );
        assert!(decode(&[0x00, 0x00], 64).is_err());
    }

    #[test]
    fn truncated_tokens_and_oversized_output_are_errors() {
        let stream = [0x82, b'x', b'y', b'z', 0x45, 0x00, 0x02];
        // Every prefix that ends inside a token is an error; the prefix
        // that ends after the literal run is a complete stream.
        for end in [1, 2, 3, 5, 6] {
            assert!(decode(&stream[..end], 64).is_err(), "prefix {end}");
        }
        assert_eq!(decode(&stream[..4], 64).unwrap().data, b"xyz");
        assert!(decode(&stream, 11).is_err());
        assert_eq!(decode(&stream, 12).unwrap().data.len(), 12);
        assert_eq!(decode(&[], 64).unwrap().data, b"");
    }
}
