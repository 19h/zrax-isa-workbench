//! XPRESS, the LZ77+Huffman variant of the Xpress Compression Algorithm, as
//! WIM resources store it in chunks of at most 64 KiB.
//!
//! Sources: [MS-XCA] "Xpress Compression Algorithm" v20240423 (revision
//! 10.0) sections 2.1.4.3 (the table, the length encoding and the
//! end-of-data symbol) and 2.2.4 (decompression); wimlib v1.14.5
//! `src/xpress_decompress.c` and `include/wimlib/xpress_constants.h`,
//! cross-checked with 7-Zip 26.03 `CPP/7zip/Compress/XpressDecoder.cpp`.
//!
//! Wire format:
//! - A 256-byte table of 512 4-bit code lengths, the even symbol's in the
//!   low nibble ([MS-XCA] 2.1.4.3), for a canonical code of at most 15 bits
//!   that fills the code space exactly ([MS-XCA] 2.2.4; see
//!   [`super::huffman`]).
//! - Then the 16-bit word bitstream. Symbols 0-255 are literals. Symbol
//!   `256 + 16 * b + h` is a match whose offset is `1 << b` plus `b` more
//!   bits and whose length header is `h`: headers 0-14 are lengths 3-17;
//!   header 15 adds 15 and a byte read from the input, and a byte of 255 is
//!   replaced by the 16-bit length that follows it; 3 is added last.
//! - The extra length bytes sit where a reader that keeps at least 16 bits
//!   buffered after every symbol has reached in the input ([MS-XCA] 2.2.4).
//!   This reader buffers words only when it needs bits and tops up to 16
//!   bits after a match symbol, which reaches the same place (wimlib
//!   `xpress_decompress`).
//! - [MS-XCA] codes 64 KiB of output per table; a WIM chunk is at most
//!   64 KiB (wimlib `xpress_create_decompressor`), so one table covers the
//!   stream.
//!
//! The format has no magic and is decoded only where a WIM header names
//! it. [`decode`] produces exactly `limit` bytes, the chunk size that the
//! resource states, and does not require the end-of-data symbol 256 that
//! encoders append ([MS-XCA] 2.1.4.3: "Implementations of the
//! decompression algorithm may expect" it; wimlib does not read it).

use super::huffman::{BitSource, Bits, Huffman};
use super::*;

/// Codec name in error messages.
const CODEC: &str = "XPRESS";

/// Symbols of the Huffman alphabet: 256 literals and 256 match headers.
const NUM_SYMBOLS: usize = 512;

/// The table of 4-bit code lengths at the start of the stream.
const TABLE_SIZE: usize = NUM_SYMBOLS / 2;

/// Literal symbols.
const NUM_LITERALS: u16 = 256;

/// Longest code ([MS-XCA] 2.1.4.2: lengths are stored in 4 bits).
const MAX_CODE_LENGTH: u32 = 15;

/// Output that one table covers ([MS-XCA] 2.2.4 `BlockEnd`), and the
/// largest WIM chunk (wimlib `XPRESS_MAX_OFFSET + 1`).
pub(super) const MAX_STREAM: usize = 64 << 10;

/// A match header holds the length header in its low 4 bits and the
/// offset's bit count in the next 4.
const LENGTH_HEADER_MASK: u16 = 0x0f;
const OFFSET_BITS_SHIFT: u16 = 4;

/// Length header 15 is followed by a length byte; a byte of 255 by a
/// 16-bit length.
const EXTENDED_HEADER: usize = 15;
const EXTENDED_BYTE: u8 = 0xff;

/// Shortest match ([MS-XCA] 2.1.4.1).
const MIN_MATCH: usize = 3;

/// Bits the reader buffers after a match symbol, before it reads the
/// offset bits and any length bytes ([MS-XCA] 2.2.4).
const BUFFERED_AFTER_MATCH: u32 = 16;

/// Decode exactly `limit` bytes, at most 64 KiB, of an XPRESS stream.
///
/// # Errors
///
/// A stream longer than one table covers, a truncated table, a table whose
/// code does not fill the code space, a match that reaches before the
/// output or past `limit`, a 16-bit length below 15, or a stream that ends
/// before `limit` bytes are decoded.
pub(super) fn decode(data: &[u8], limit: usize) -> Result<Decoded> {
    if limit > MAX_STREAM {
        return Err(error(format!(
            "Unsupported XPRESS stream of {}: one table covers at most {}",
            size_text(limit),
            size_text(MAX_STREAM)
        )));
    }
    let table = data
        .get(..TABLE_SIZE)
        .ok_or_else(|| error(format!("Truncated XPRESS Huffman table: {} B", data.len())))?;
    let mut lengths = [0u8; NUM_SYMBOLS];
    for (pair, &byte) in lengths.chunks_exact_mut(2).zip(table) {
        pair[0] = byte & 0x0f;
        pair[1] = byte >> 4;
    }
    let code = Huffman::build(&lengths, CODEC, "Huffman", MAX_CODE_LENGTH)?
        .ok_or_else(|| error("Invalid XPRESS Huffman table: no codes"))?;
    let mut bits = Bits::new(data, CODEC);
    bits.pos = TABLE_SIZE;
    let mut out = Vec::with_capacity(limit);
    while out.len() < limit {
        let symbol = code.decode(&mut bits)?;
        if let Ok(literal) = u8::try_from(symbol) {
            out.push(literal);
            continue;
        }
        let header = symbol - NUM_LITERALS;
        bits.ensure(BUFFERED_AFTER_MATCH)?;
        let offset_bits = u32::from(header >> OFFSET_BITS_SHIFT);
        let offset = (1usize << offset_bits) | bits.read(offset_bits)? as usize;
        let length = match usize::from(header & LENGTH_HEADER_MASK) {
            EXTENDED_HEADER => extended_length(&mut bits)?,
            short => short,
        } + MIN_MATCH;
        copy_match(&mut out, offset, length, limit)?;
    }
    Ok(Decoded {
        data: out,
        consumed: Some(bits.consumed()),
        check: None,
    })
}

/// The length after header 15, before the 3 is added: 15 plus the next
/// input byte, or the 16-bit value after a byte of 255 ([MS-XCA] 2.2.4,
/// which rejects a 16-bit value below 15).
fn extended_length(bits: &mut Bits<'_>) -> Result<usize> {
    let at = bits.pos;
    let byte = bits.input_byte()?;
    if byte != EXTENDED_BYTE {
        return Ok(EXTENDED_HEADER + usize::from(byte));
    }
    let low = bits.input_byte()?;
    let high = bits.input_byte()?;
    let length = usize::from(u16::from_le_bytes([low, high]));
    if length < EXTENDED_HEADER {
        return Err(error(format!(
            "Invalid XPRESS match length {length} at 0x{at:X}: a 16-bit length is at least 15"
        )));
    }
    Ok(length)
}

/// Copy `length` bytes from `offset` bytes back, one byte at a time so that
/// a match may overlap its own output ([MS-XCA] 2.2.4).
fn copy_match(out: &mut Vec<u8>, offset: usize, length: usize, limit: usize) -> Result<()> {
    if offset > out.len() {
        return Err(error(format!(
            "Invalid XPRESS match offset {offset} at output 0x{:X}",
            out.len()
        )));
    }
    if length > limit - out.len() {
        return Err(error(format!(
            "Invalid XPRESS match of {length} B at output 0x{:X}: it runs past the {} B stream",
            out.len(),
            limit
        )));
    }
    let start = out.len() - offset;
    for i in 0..length {
        let byte = out[start + i];
        out.push(byte);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes the bitstream the way [MS-XCA] 2.1.4.3 `WriteBits`,
    /// `WriteByte` and `FlushBits` do: two word slots are reserved ahead of
    /// the bytes, a full word is written into its slot when the next bit
    /// arrives, and the flush writes the last word and leaves a zero word.
    struct Writer {
        out: Vec<u8>,
        slot: usize,
        next_slot: usize,
        word: u32,
        filled: u32,
    }

    impl Writer {
        /// After a table of all 9-bit codes (`0x99` bytes): literal `b` has
        /// code `b` and match header `256 + h` has code `256 + h`.
        fn nine_bit_table() -> Self {
            let mut out = vec![0x99; TABLE_SIZE];
            out.extend_from_slice(&[0; 4]);
            Self {
                out,
                slot: TABLE_SIZE,
                next_slot: TABLE_SIZE + 2,
                word: 0,
                filled: 0,
            }
        }

        fn bits(&mut self, value: u32, count: u32) {
            for i in (0..count).rev() {
                if self.filled == 16 {
                    self.flush_word();
                }
                self.word = (self.word << 1) | ((value >> i) & 1);
                self.filled += 1;
            }
        }

        fn flush_word(&mut self) {
            let word = u16::try_from(self.word & 0xffff).unwrap();
            self.out[self.slot..self.slot + 2].copy_from_slice(&word.to_le_bytes());
            self.slot = self.next_slot;
            self.next_slot = self.out.len();
            self.out.extend_from_slice(&[0, 0]);
            self.word = 0;
            self.filled = 0;
        }

        fn byte(&mut self, byte: u8) {
            self.out.push(byte);
        }

        fn literal(&mut self, byte: u8) {
            self.bits(u32::from(byte), 9);
        }

        /// A match symbol, its length bytes and its offset bits, in the
        /// order of the [MS-XCA] 2.1.4.3 pseudocode.
        fn copy(&mut self, length: usize, offset: u32) {
            let offset_bits = offset.ilog2();
            let adjusted = length - MIN_MATCH;
            let header = adjusted.min(EXTENDED_HEADER);
            let symbol = 256 + 16 * offset_bits + u32::try_from(header).unwrap();
            self.bits(symbol, 9);
            if adjusted >= EXTENDED_HEADER {
                let rest = adjusted - EXTENDED_HEADER;
                if rest < 255 {
                    self.byte(u8::try_from(rest).unwrap());
                } else {
                    self.byte(EXTENDED_BYTE);
                    let value = u16::try_from(adjusted).unwrap();
                    self.out.extend_from_slice(&value.to_le_bytes());
                }
            }
            self.bits(offset - (1 << offset_bits), offset_bits);
        }

        /// The end-of-data symbol 256, then `FlushBits`.
        fn finish(mut self) -> Vec<u8> {
            self.bits(256, 9);
            let word = u16::try_from((self.word << (16 - self.filled)) & 0xffff).unwrap();
            self.out[self.slot..self.slot + 2].copy_from_slice(&word.to_le_bytes());
            self.out
        }
    }

    #[test]
    fn literals_and_overlapping_matches_decode() {
        let mut w = Writer::nine_bit_table();
        for &b in b"abc" {
            w.literal(b);
        }
        w.copy(6, 3);
        w.copy(4, 1);
        let stream = w.finish();
        let decoded = decode(&stream, 13).unwrap();
        assert_eq!(decoded.data, b"abcabcabccccc");
        assert_eq!(decoded.check, None);
    }

    #[test]
    fn length_bytes_are_read_where_the_specification_places_them() {
        // Lengths 18 (header 15, byte 0), 40 (byte 22), 300 (byte 255 and
        // 16-bit 297) and 2000, at word boundaries and inside words.
        let mut expected = b"0123456789".to_vec();
        let mut w = Writer::nine_bit_table();
        for &b in b"0123456789" {
            w.literal(b);
        }
        for (length, offset) in [(18, 10), (40, 7), (300, 1), (2000, 33), (17, 2)] {
            w.copy(length, offset);
            let start = expected.len() - offset as usize;
            for i in 0..length {
                expected.push(expected[start + i]);
            }
            w.literal(b'x');
            expected.push(b'x');
        }
        let stream = w.finish();
        assert_eq!(decode(&stream, expected.len()).unwrap().data, expected);
    }

    #[test]
    fn the_table_must_fill_the_code_space() {
        let mut w = Writer::nine_bit_table();
        w.literal(b'a');
        let stream = w.finish();
        assert_eq!(decode(&stream, 1).unwrap().data, b"a");
        let mut incomplete = stream.clone();
        incomplete[0] = 0x09;
        assert!(decode(&incomplete, 1).is_err());
        let mut empty = stream.clone();
        empty[..TABLE_SIZE].fill(0);
        assert!(decode(&empty, 1).is_err());
        assert!(decode(&stream[..TABLE_SIZE - 1], 1).is_err());
    }

    #[test]
    fn matches_must_stay_inside_the_output() {
        let mut before_start = Writer::nine_bit_table();
        before_start.literal(b'a');
        before_start.copy(3, 2);
        assert!(decode(&before_start.finish(), 4).is_err());
        let mut past_end = Writer::nine_bit_table();
        past_end.literal(b'a');
        past_end.copy(5, 1);
        let stream = past_end.finish();
        assert!(decode(&stream, 5).is_err());
        assert_eq!(decode(&stream, 6).unwrap().data, b"aaaaaa");
        assert!(decode(&stream, MAX_STREAM + 1).is_err());
    }

    #[test]
    fn a_short_sixteen_bit_length_is_invalid() {
        let mut w = Writer::nine_bit_table();
        w.literal(b'a');
        w.bits(256 + 15, 9);
        w.byte(EXTENDED_BYTE);
        w.out.extend_from_slice(&14u16.to_le_bytes());
        assert!(decode(&w.finish(), 30).is_err());
    }

    #[test]
    fn truncated_streams_fail() {
        let mut w = Writer::nine_bit_table();
        for &b in b"truncate me" {
            w.literal(b);
        }
        w.copy(20, 11);
        let stream = w.finish();
        let expected = decode(&stream, 31).unwrap().data;
        assert_eq!(&expected[..11], b"truncate me");
        // The reader pads one word of zeros, which the flushed zero word
        // already is.
        assert_eq!(
            decode(&stream[..stream.len() - 2], 31).unwrap().data,
            expected
        );
        for end in 0..=TABLE_SIZE {
            assert!(decode(&stream[..end], 31).is_err(), "prefix {end}");
        }
        for end in TABLE_SIZE..stream.len() {
            if let Ok(decoded) = decode(&stream[..end], 31) {
                assert_eq!(decoded.data.len(), 31, "prefix {end}");
            }
        }
    }
}
