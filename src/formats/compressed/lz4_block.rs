//! Raw LZ4 block streams: LZ4 sequences with no frame, size header or
//! checksum, as lz4 v1.10.0 `doc/lz4_Block_format.md` defines them.
//!
//! A sequence is a token (literal length in the high nibble, match length
//! minus four in the low nibble; a nibble of 15 continues in further bytes
//! while they are 255), the literals, a little-endian 16-bit match offset
//! counted back from the end of the output, and the continued match length.
//! The last sequence holds only literals, so the stream ends with its input.
//! Silicon Labs GBL "program LZ4" tags store one such stream
//! (`gecko_sdk` v4.5.1 `platform/bootloader/parser/compression/btl_decompress_lz4.c`
//! starts in the token state, with no frame header).

use super::*;

/// The shortest match the format encodes.
const MIN_MATCH: usize = 4;

/// A length nibble of 15 continues in further bytes.
const NIBBLE_CONTINUES: usize = 15;

/// A continuation byte of 255 adds 255 and continues.
const BYTE_CONTINUES: u8 = 255;

/// The token's low nibble holds the match length minus four.
const MATCH_NIBBLE_MASK: u8 = 0x0f;

/// Size of a match offset.
const OFFSET_SIZE: usize = 2;

/// The stream being read.
struct Input<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Input<'a> {
    fn is_at_end(&self) -> bool {
        self.pos == self.data.len()
    }

    /// The next `len` bytes.
    fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let bytes = self
            .pos
            .checked_add(len)
            .and_then(|end| self.data.get(self.pos..end))
            .ok_or_else(|| error(format!("Truncated LZ4 block stream at 0x{:X}", self.pos)))?;
        self.pos += len;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    /// A length nibble and its continuation bytes. Every continuation byte
    /// is read from the input, so the loop is bounded by its size.
    fn length(&mut self, nibble: u8) -> Result<usize> {
        let mut length = usize::from(nibble);
        if length != NIBBLE_CONTINUES {
            return Ok(length);
        }
        loop {
            let byte = self.byte()?;
            length = length
                .checked_add(usize::from(byte))
                .ok_or_else(|| error("LZ4 length overflow"))?;
            if byte != BYTE_CONTINUES {
                return Ok(length);
            }
        }
    }
}

/// Decode a raw LZ4 block stream into at most `limit` bytes.
pub(super) fn decode(data: &[u8], limit: usize) -> Result<Decoded> {
    decode_until(data, limit, AtLimit::Fail)
}

/// [`decode`], or with [`AtLimit::Stop`] the first `limit` bytes: decoding
/// ends once the output reaches the limit, and the rest of the input is not
/// read. Containers that pad each block to an alignment rely on this, as
/// maxcso v1.13.0 `src/input.cpp` does with `LZ4_decompress_safe_partial`
/// ("It could include padding").
pub(super) fn decode_until(data: &[u8], limit: usize, at_limit: AtLimit) -> Result<Decoded> {
    if data.is_empty() {
        return Err(error("Truncated LZ4 block stream at 0x0"));
    }
    let mut input = Input { data, pos: 0 };
    let mut out = Vec::new();
    loop {
        let token = input.byte()?;
        let literal_size = input.length(token >> 4)?;
        let literals = input.bytes(literal_size)?;
        if out.len().saturating_add(literal_size) > limit {
            if at_limit == AtLimit::Stop {
                out.extend_from_slice(&literals[..limit - out.len()]);
                return Ok(stopped(out));
            }
            return Err(exceeds(limit));
        }
        out.extend_from_slice(literals);
        if input.is_at_end() {
            break;
        }
        if at_limit == AtLimit::Stop && out.len() == limit {
            return Ok(stopped(out));
        }
        let offset_at = input.pos;
        let offset = usize::from(u16::from_le_bytes(
            input
                .bytes(OFFSET_SIZE)?
                .try_into()
                .expect("two offset bytes"),
        ));
        if offset == 0 || offset > out.len() {
            return Err(error(format!(
                "Invalid LZ4 match offset {offset} at 0x{offset_at:X} with {} B decoded",
                out.len()
            )));
        }
        let match_size = input
            .length(token & MATCH_NIBBLE_MASK)?
            .checked_add(MIN_MATCH)
            .ok_or_else(|| error("LZ4 length overflow"))?;
        let room = limit - out.len();
        if match_size > room && at_limit == AtLimit::Fail {
            return Err(exceeds(limit));
        }
        // A match may overlap its own output (offset < length), so it is
        // copied a byte at a time.
        let start = out.len() - offset;
        let copied = match_size.min(room);
        out.reserve(copied);
        for i in start..start + copied {
            out.push(out[i]);
        }
        if at_limit == AtLimit::Stop && out.len() == limit {
            return Ok(stopped(out));
        }
    }
    Ok(Decoded {
        data: out,
        consumed: Some(data.len()),
        check: None,
    })
}

/// Output that stopped at the limit: how much input it used is not known.
fn stopped(out: Vec<u8>) -> Decoded {
    Decoded {
        data: out,
        consumed: None,
        check: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_from_the_reference_encoder_decode() {
        let payload = b"program data program data program data, then more data".repeat(40);
        let block = lz4_flex::block::compress(&payload);
        let decoded = decode(&block, MAX_PAYLOAD).unwrap();
        assert_eq!(decoded.data, payload);
        assert_eq!(decoded.consumed, Some(block.len()));
        assert!(decode(&block, payload.len() - 1).is_err());
    }

    #[test]
    fn overlapping_matches_repeat_their_source() {
        // Token 0x1F: one literal 'a', match length 15 + 4 + 0x01 = 20 at
        // offset 1, then a final literal-only sequence holding 'b'.
        let stream = [0x1f, b'a', 0x01, 0x00, 0x01, 0x10, b'b'];
        let decoded = decode(&stream, MAX_PAYLOAD).unwrap();
        assert_eq!(decoded.data, [b"a".repeat(21), b"b".to_vec()].concat());
    }

    #[test]
    fn stopping_at_the_limit_ignores_padding_after_the_block() {
        let payload = b"sector sector sector sector".repeat(30);
        let mut padded = lz4_flex::block::compress(&payload);
        padded.extend_from_slice(&[0; 13]);
        assert!(decode(&padded, payload.len()).is_err());
        let decoded = decode_until(&padded, payload.len(), AtLimit::Stop).unwrap();
        assert_eq!(decoded.data, payload);
        assert_eq!(decoded.consumed, None);
        // A limit inside a match or a literal run keeps the first bytes.
        for limit in [1, 7, 100, payload.len() - 1] {
            let prefix = decode_until(&padded, limit, AtLimit::Stop).unwrap();
            assert_eq!(prefix.data, &payload[..limit], "limit {limit}");
        }
        // A stream that ends before the limit still ends with its input.
        let exact = lz4_flex::block::compress(&payload);
        let whole = decode_until(&exact, payload.len() + 10, AtLimit::Stop).unwrap();
        assert_eq!(whole.data, payload);
        assert_eq!(whole.consumed, Some(exact.len()));
    }

    #[test]
    fn bad_offsets_and_truncation_are_errors() {
        // Offset 0, and an offset before the start of the output.
        assert!(decode(&[0x10, b'a', 0x00, 0x00, 0x00], MAX_PAYLOAD).is_err());
        assert!(decode(&[0x10, b'a', 0x02, 0x00, 0x00], MAX_PAYLOAD).is_err());
        // Literal length 2 with one literal present; a cut offset.
        assert!(decode(&[0x20, b'a'], MAX_PAYLOAD).is_err());
        assert!(decode(&[0x10, b'a', 0x01], MAX_PAYLOAD).is_err());
        assert!(decode(&[], MAX_PAYLOAD).is_err());
    }
}
