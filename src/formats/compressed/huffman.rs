//! Canonical Huffman decoding and the 16-bit word bitstream that the LZX,
//! XPRESS and LZMS decoders share.
//!
//! - The bitstream ([`Bits`]) is a sequence of 16-bit little-endian words
//!   whose bits are read most significant first: LZX ([MS-PATCH] v20250819
//!   section 2.2; libmspack `mspack/readbits.h`) and XPRESS ([MS-XCA]
//!   v20240423 section 2.2.4; wimlib v1.14.5 `decompress_common.h`
//!   `input_bitstream`). Past the end of the input it supplies one word of
//!   zeros, as libmspack's `read_input` does, so the last code can be
//!   peeked at with a full code length; reading beyond that is an error.
//! - A canonical code ([`Huffman`]) assigns codes shortest first and,
//!   within a length, by increasing symbol, read most significant bit first
//!   ([MS-PATCH] 2.5; [MS-XCA] 2.2.4, whose table construction orders
//!   symbols "by bit length (from low to high), and then by symbol value").
//!   Codes must fill the code space exactly: an incomplete or
//!   over-subscribed code is an error, as in libmspack's
//!   `make_decode_table` and [MS-XCA] ("If `CurrentTableEntry` does not
//!   equal 2^15 ... The compressed data is not valid").

use super::*;

/// Codes up to this length are decoded by one table lookup.
const TABLE_BITS: u32 = 10;

/// Longest code length a length table may give (LZX trees, [MS-PATCH]
/// 2.5).
const LONGEST_CODE: usize = 16;

/// Zero bytes the bit reader supplies after the end of the input (one
/// 16-bit word, libmspack `read_input`).
const END_PADDING: usize = 2;

/// A source of bits, most significant first, for [`Huffman::decode`].
pub(super) trait BitSource {
    /// Buffer at least `n` bits (at most 17).
    ///
    /// # Errors
    ///
    /// The stream ends before `n` bits.
    fn ensure(&mut self, n: u32) -> Result<()>;

    /// The next `n` bits (1 to 16) without consuming them; call
    /// [`Self::ensure`] first.
    fn peek(&self, n: u32) -> u32;

    /// Consume `n` buffered bits.
    fn remove(&mut self, n: u32);
}

/// The 16-bit word bitstream reader.
pub(super) struct Bits<'a> {
    data: &'a [u8],
    /// Codec name for error messages.
    codec: &'static str,
    /// Next unread byte; at most [`END_PADDING`] past the input's end.
    pub(super) pos: usize,
    /// Buffered bits, most significant first.
    buffer: u32,
    /// Number of buffered bits.
    count: u32,
}

impl<'a> Bits<'a> {
    pub(super) fn new(data: &'a [u8], codec: &'static str) -> Self {
        Self {
            data,
            codec,
            pos: 0,
            buffer: 0,
            count: 0,
        }
    }

    /// `Truncated <codec> stream at 0x...`.
    pub(super) fn truncated(&self, pos: usize) -> ClassifierError {
        error(format!("Truncated {} stream at 0x{pos:X}", self.codec))
    }

    /// The next byte of the byte stream, or a padding zero.
    pub(super) fn byte(&mut self) -> Result<u8> {
        let byte = match self.data.get(self.pos) {
            Some(&byte) => byte,
            None if self.pos < self.data.len() + END_PADDING => 0,
            None => return Err(self.truncated(self.pos)),
        };
        self.pos += 1;
        Ok(byte)
    }

    /// The next byte of the input itself, never a padding zero: the length
    /// bytes that XPRESS interleaves with the bitstream ([MS-XCA] 2.2.4
    /// requires an error for "an improper memory access outside the
    /// buffer").
    pub(super) fn input_byte(&mut self) -> Result<u8> {
        let byte = *self
            .data
            .get(self.pos)
            .ok_or_else(|| self.truncated(self.pos))?;
        self.pos += 1;
        Ok(byte)
    }

    /// The next `n` bits (0 to 17) as a number.
    pub(super) fn read(&mut self, n: u32) -> Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        self.ensure(n)?;
        let value = self.peek(n);
        self.remove(n);
        Ok(value)
    }

    /// Drop the rest of the current 16-bit word, as at every LZX frame end.
    pub(super) fn align_frame(&mut self) -> Result<()> {
        if self.count > 0 {
            self.ensure(16)?;
        }
        self.remove(self.count & 15);
        Ok(())
    }

    /// Switch to the byte stream of an uncompressed block: drop 1-16 bits,
    /// a whole word when the stream is already aligned.
    pub(super) fn start_bytes(&mut self) -> Result<()> {
        if self.count == 0 {
            self.ensure(16)?;
        }
        self.buffer = 0;
        self.count = 0;
        Ok(())
    }

    /// Copy `out.len()` bytes of the byte stream into `out`.
    pub(super) fn copy_bytes(&mut self, out: &mut [u8]) -> Result<()> {
        let end = self
            .pos
            .checked_add(out.len())
            .filter(|&end| end <= self.data.len() + END_PADDING)
            .ok_or_else(|| self.truncated(self.pos))?;
        let available = self.data.len().min(end).saturating_sub(self.pos);
        out[..available].copy_from_slice(&self.data[self.pos..self.pos + available]);
        out[available..].fill(0);
        self.pos = end;
        Ok(())
    }

    /// Copy `out.len()` bytes of the input itself into `out`, never padding
    /// zeros: wimlib's `bitstream_read_bytes` and 7-Zip's LZX decoder in WIM
    /// mode require every byte of an uncompressed block.
    pub(super) fn copy_input(&mut self, out: &mut [u8]) -> Result<()> {
        let end = self
            .pos
            .checked_add(out.len())
            .filter(|&end| end <= self.data.len())
            .ok_or_else(|| self.truncated(self.pos))?;
        out.copy_from_slice(&self.data[self.pos..end]);
        self.pos = end;
        Ok(())
    }

    /// A little-endian 32-bit value from the byte stream.
    pub(super) fn le_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.copy_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// A little-endian 32-bit value from the input itself, never padding.
    pub(super) fn input_le_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.copy_input(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Input bytes consumed, without a buffered word that was not used.
    pub(super) fn consumed(&self) -> usize {
        let buffered = usize::try_from(self.count / 8).unwrap_or(0);
        self.pos.saturating_sub(buffered).min(self.data.len())
    }
}

impl BitSource for Bits<'_> {
    /// Buffer at least `n` bits (at most 17), a 16-bit word at a time.
    fn ensure(&mut self, n: u32) -> Result<()> {
        while self.count < n {
            let low = self.byte()?;
            let high = self.byte()?;
            let word = u32::from(u16::from_le_bytes([low, high]));
            self.buffer |= word << (16 - self.count);
            self.count += 16;
        }
        Ok(())
    }

    fn peek(&self, n: u32) -> u32 {
        self.buffer >> (32 - n)
    }

    fn remove(&mut self, n: u32) {
        self.buffer = if n >= 32 { 0 } else { self.buffer << n };
        self.count -= n;
    }
}

/// One entry of a decoding table.
#[derive(Debug, Clone, Copy, Default)]
struct Entry {
    symbol: u16,
    /// Code length; 0 when the code is longer than [`TABLE_BITS`].
    length: u8,
}

/// A canonical Huffman code.
pub(super) struct Huffman {
    /// Codec name for error messages.
    codec: &'static str,
    /// Longest code the codec allows; this many bits are peeked to decode.
    max_length: u32,
    /// Indexed by the next [`TABLE_BITS`] bits.
    table: Vec<Entry>,
    /// Per code length: the first code, the number of codes and the index
    /// of the first symbol in `sorted`.
    first_code: [u32; 17],
    count: [u32; 17],
    first_index: [usize; 17],
    /// Symbols ordered by code length, then by value.
    sorted: Vec<u16>,
}

impl Huffman {
    /// The code with these lengths (0 means unused) for a codec whose codes
    /// are at most `max_length` bits (`TABLE_BITS` to 16). `None` when
    /// every length is zero. A code that is incomplete or over-subscribed,
    /// or a length over `max_length`, is an error naming `<codec> <tree>`.
    pub(super) fn build(
        lengths: &[u8],
        codec: &'static str,
        tree: &str,
        max_length: u32,
    ) -> Result<Option<Self>> {
        let mut count = [0u32; 17];
        for &length in lengths {
            if usize::from(length) > LONGEST_CODE || u32::from(length) > max_length {
                return Err(error(format!(
                    "Invalid {codec} {tree} tree: code length {length}"
                )));
            }
            count[usize::from(length)] += 1;
        }
        count[0] = 0;
        if count.iter().all(|&n| n == 0) {
            return Ok(None);
        }
        // Kraft: the codes must fill the code space exactly.
        let mut left: i64 = 1;
        for &n in &count[1..] {
            left = left * 2 - i64::from(n);
            if left < 0 {
                return Err(error(format!(
                    "Invalid {codec} {tree} tree: over-subscribed code"
                )));
            }
        }
        if left != 0 {
            return Err(error(format!(
                "Invalid {codec} {tree} tree: incomplete code"
            )));
        }
        let mut first_code = [0u32; 17];
        let mut first_index = [0usize; 17];
        let mut code = 0u32;
        let mut index = 0usize;
        for length in 1..17 {
            code = (code + count[length - 1]) << 1;
            first_code[length] = code;
            first_index[length] = index;
            index += count[length] as usize;
        }
        let mut sorted = vec![0u16; index];
        let mut next = first_index;
        for (symbol, &length) in lengths.iter().enumerate() {
            if length > 0 {
                let slot = &mut next[usize::from(length)];
                sorted[*slot] =
                    u16::try_from(symbol).expect("tables have fewer than 65536 symbols");
                *slot += 1;
            }
        }
        let mut table = vec![Entry::default(); 1 << TABLE_BITS];
        for length in 1..=TABLE_BITS as usize {
            let start = first_index[length];
            for (i, &symbol) in sorted[start..start + count[length] as usize]
                .iter()
                .enumerate()
            {
                let code = first_code[length] as usize + i;
                let shift = TABLE_BITS as usize - length;
                let entry = Entry {
                    symbol,
                    length: u8::try_from(length).expect("lengths are at most 16"),
                };
                table[code << shift..(code + 1) << shift].fill(entry);
            }
        }
        Ok(Some(Self {
            codec,
            max_length,
            table,
            first_code,
            count,
            first_index,
            sorted,
        }))
    }

    /// Decode one symbol.
    pub(super) fn decode(&self, bits: &mut impl BitSource) -> Result<u16> {
        bits.ensure(self.max_length)?;
        let next = bits.peek(self.max_length);
        let entry = self.table[(next >> (self.max_length - TABLE_BITS)) as usize];
        if entry.length > 0 {
            bits.remove(u32::from(entry.length));
            return Ok(entry.symbol);
        }
        for length in TABLE_BITS + 1..=self.max_length {
            let code = next >> (self.max_length - length);
            let at = length as usize;
            let index = code.wrapping_sub(self.first_code[at]);
            if code >= self.first_code[at] && index < self.count[at] {
                bits.remove(length);
                return Ok(self.sorted[self.first_index[at] + index as usize]);
            }
        }
        // Unreachable for a complete code, which `build` requires.
        Err(error(format!("Invalid {} code", self.codec)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huffman_codes_must_be_complete() {
        assert!(Huffman::build(&[1, 1], "LZX", "test", 16)
            .unwrap()
            .is_some());
        assert!(Huffman::build(&[0, 0, 0], "LZX", "test", 16)
            .unwrap()
            .is_none());
        assert!(Huffman::build(&[1], "LZX", "test", 16).is_err());
        assert!(Huffman::build(&[1, 1, 1], "LZX", "test", 16).is_err());
        assert!(Huffman::build(&[1, 2, 3, 3], "LZX", "test", 16)
            .unwrap()
            .is_some());
        let too_long = Huffman::build(&[1, 2, 16, 16], "XPRESS", "Huffman", 15);
        assert_eq!(
            too_long.err().map(|e| e.to_string()),
            Some(
                "Compressed stream parse error: Invalid XPRESS Huffman tree: code length 16"
                    .to_string()
            )
        );
    }

    #[test]
    fn canonical_codes_decode_short_and_long_symbols() {
        // Lengths 1, 2, ..., 15, 16, 16: codes 0, 10, 110, ..., 1111111111111110,
        // 1111111111111111 (MSB first).
        let mut lengths: Vec<u8> = (1..=16).collect();
        lengths.push(16);
        let code = Huffman::build(&lengths, "LZX", "test", 16)
            .unwrap()
            .unwrap();
        // Symbol 0 (`0`), symbol 1 (`10`), symbol 16 (sixteen ones), then
        // symbol 12 (twelve ones and a zero): the words 0101111111111111
        // and 1111111111111110, stored little-endian; the last decode
        // peeks into the padding word.
        let stream = [0xff, 0x5f, 0xfe, 0xff];
        let mut bits = Bits::new(&stream, "LZX");
        assert_eq!(code.decode(&mut bits).unwrap(), 0);
        assert_eq!(code.decode(&mut bits).unwrap(), 1);
        assert_eq!(code.decode(&mut bits).unwrap(), 16);
        assert_eq!(code.decode(&mut bits).unwrap(), 12);
    }

    #[test]
    fn fifteen_bit_codes_peek_fifteen_bits() {
        // Lengths 1..=15 and a second 15: the code space of a 15-bit code.
        let mut lengths: Vec<u8> = (1..=15).collect();
        lengths.push(15);
        let code = Huffman::build(&lengths, "XPRESS", "Huffman", 15)
            .unwrap()
            .unwrap();
        // Symbol 15 (fifteen ones), then symbol 0 (`0`): the word
        // 1111111111111110.
        let stream = [0xfe, 0xff];
        let mut bits = Bits::new(&stream, "XPRESS");
        assert_eq!(code.decode(&mut bits).unwrap(), 15);
        assert_eq!(code.decode(&mut bits).unwrap(), 0);
    }

    #[test]
    fn the_bit_reader_pads_one_word_and_then_fails() {
        let mut bits = Bits::new(&[0x34, 0x12], "LZX");
        assert_eq!(bits.read(4).unwrap(), 0x1);
        assert_eq!(bits.read(12).unwrap(), 0x234);
        assert_eq!(bits.read(16).unwrap(), 0);
        assert!(bits.read(1).is_err());
        let mut bytes = Bits::new(&[7], "XPRESS");
        assert_eq!(bytes.input_byte().unwrap(), 7);
        assert_eq!(
            bytes.input_byte().err().map(|e| e.to_string()),
            Some("Compressed stream parse error: Truncated XPRESS stream at 0x1".to_string())
        );
    }
}
