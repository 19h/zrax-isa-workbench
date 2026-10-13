//! LZNT1, the codec of NTFS compressed attributes.
//!
//! Source: [MS-XCA] "Xpress Compression Algorithm" v20240423 (revision
//! 10.0), section 2.5 "LZNT1 Algorithm Details" (buffer format, chunk
//! headers, flag groups, compressed words and processing rules) and section
//! 3.3 "LZNT1" (the example the unit tests decode). Where the specification
//! leaves a case open, the decoder follows ntfs-3g tag `2022.10.3`,
//! `libntfs-3g/compress.c` (`ntfs_decompress`), which reads the chunks of
//! NTFS compression units:
//!
//! - A buffer is a sequence of chunks, each starting with a 16-bit
//!   little-endian header. A header of 0 ends the buffer; otherwise bit 15
//!   marks a compressed chunk, bits 14-12 hold the signature 3 and bits
//!   11-0 the chunk size, header included, minus 3. The end header is
//!   optional, so the buffer also ends with its input.
//! - An uncompressed chunk holds the bytes after its header as they are.
//! - A compressed chunk is a sequence of flag groups: a flag byte whose
//!   bits, least significant first, mark each of the next eight elements as
//!   a literal byte (0) or a 16-bit little-endian compressed word (1). The
//!   chunk size ends the last group.
//! - A compressed word holds a displacement in its high D bits and a length
//!   in its low 16 - D bits, where D is the largest value of 4 to 12 for
//!   which 2^(D-1) is less than the bytes already decoded in the chunk (4
//!   when there is none). It copies length + 3 bytes from displacement + 1
//!   bytes back, byte by byte, so a copy may overlap the bytes it writes.
//! - Chunks decode independently to at most 4096 bytes, so a copy may not
//!   reach before the start of its chunk; ntfs-3g refuses such a copy, and
//!   a compressed word as the first element of a chunk.
//! - [MS-XCA] compresses its input in units of 4096 bytes, so only the last
//!   chunk decodes to fewer. A shorter chunk before another one is
//!   zero-filled to 4096 bytes, as ntfs-3g fills it.
//!
//! The codec has no magic and is decoded only where a container names it.

use super::*;

/// Bytes a chunk decodes to, except possibly the last ([MS-XCA] 2.5.3).
const CHUNK_SIZE: usize = 4096;

/// Chunk header fields ([MS-XCA] 2.5.1.2).
const CHUNK_HEADER_SIZE: usize = 2;
const CHUNK_COMPRESSED: u16 = 0x8000;
const CHUNK_SIGNATURE_MASK: u16 = 0x7000;
const CHUNK_SIGNATURE: u16 = 0x3000;
const CHUNK_SIZE_MASK: u16 = 0x0fff;

/// The header's size field is the chunk size minus three.
const CHUNK_SIZE_BIAS: usize = 3;

/// A compressed word stores its length minus three and its displacement
/// minus one ([MS-XCA] 2.5.1.4).
const MIN_MATCH: usize = 3;

/// Bits of a compressed word, and the range of its displacement field.
const WORD_BITS: u32 = 16;
const MIN_DISPLACEMENT_BITS: u32 = 4;
const MAX_DISPLACEMENT_BITS: u32 = 12;

/// Elements described by one flag byte.
const FLAG_GROUP_ELEMENTS: u32 = 8;

/// The width of the displacement field of a compressed word after
/// `written` bytes of the chunk: the largest value of 4 to 12 for which
/// 2^(value - 1) is less than `written`, or 4 ([MS-XCA] 2.5.1.4).
fn displacement_bits(written: usize) -> u32 {
    let mut bits = MIN_DISPLACEMENT_BITS;
    while bits < MAX_DISPLACEMENT_BITS && (1usize << bits) < written {
        bits += 1;
    }
    bits
}

/// Decode an LZNT1 buffer into at most `limit` bytes. Output beyond
/// `limit` is an error, as for the other codecs. `consumed` is the size of
/// the chunks, without an end header.
pub(super) fn decode(data: &[u8], limit: usize) -> Result<Decoded> {
    decode_until(data, limit, AtLimit::Fail)
}

/// The decoded bytes and the limit they may not pass.
struct Output {
    bytes: Vec<u8>,
    limit: usize,
    at_limit: AtLimit,
    /// Decoding stopped at the limit before the end of the buffer.
    stopped: bool,
}

impl Output {
    /// How many of `len` further bytes may be written: all of them, or at
    /// the limit, as many as fit when decoding stops there.
    fn room(&mut self, len: usize) -> Result<usize> {
        let free = self.limit - self.bytes.len();
        if len <= free {
            Ok(len)
        } else if self.at_limit == AtLimit::Stop {
            self.stopped = true;
            Ok(free)
        } else {
            Err(exceeds(self.limit))
        }
    }

    /// Whether decoding stops here because the output is full.
    fn stops(&self) -> bool {
        self.at_limit == AtLimit::Stop && self.bytes.len() == self.limit
    }
}

/// [`decode`], stopping at the limit when `at_limit` says so. The loop
/// reads every input byte at most once, so it is bounded by the input
/// size.
pub(super) fn decode_until(data: &[u8], limit: usize, at_limit: AtLimit) -> Result<Decoded> {
    let mut out = Output {
        bytes: Vec::with_capacity(limit.min(data.len().saturating_mul(8))),
        limit,
        at_limit,
        stopped: false,
    };
    let mut pos = 0;
    while pos < data.len() {
        if out.stops() {
            out.stopped = true;
            break;
        }
        let Some(header) = data.get(pos..pos + CHUNK_HEADER_SIZE) else {
            // One byte is left: an end header cut short is padding.
            if data[pos] == 0 {
                break;
            }
            return Err(error(format!("Truncated LZNT1 chunk header at 0x{pos:X}")));
        };
        let header = u16::from_le_bytes([header[0], header[1]]);
        if header == 0 {
            break;
        }
        if header & CHUNK_SIGNATURE_MASK != CHUNK_SIGNATURE {
            return Err(error(format!(
                "Invalid LZNT1 chunk signature at 0x{pos:X}: header 0x{header:04X}"
            )));
        }
        let size = usize::from(header & CHUNK_SIZE_MASK) + CHUNK_SIZE_BIAS;
        let end = pos + size;
        let Some(body) = data.get(pos + CHUNK_HEADER_SIZE..end) else {
            return Err(error(format!(
                "Truncated LZNT1 chunk at 0x{pos:X}: {size} B, {} B left",
                data.len() - pos
            )));
        };
        fill_previous_chunk(&mut out)?;
        if header & CHUNK_COMPRESSED == 0 {
            let room = out.room(body.len())?;
            out.bytes.extend_from_slice(&body[..room]);
        } else {
            decode_chunk(body, pos + CHUNK_HEADER_SIZE, &mut out)?;
        }
        pos = end;
    }
    Ok(Decoded {
        consumed: (!out.stopped).then_some(pos),
        data: out.bytes,
        check: None,
    })
}

/// Zero-fill a chunk that decoded to fewer than 4096 bytes, now that
/// another chunk follows it.
fn fill_previous_chunk(out: &mut Output) -> Result<()> {
    let short = out.bytes.len() % CHUNK_SIZE;
    if short == 0 {
        return Ok(());
    }
    let room = out.room(CHUNK_SIZE - short)?;
    let filled = out.bytes.len() + room;
    out.bytes.resize(filled, 0);
    Ok(())
}

/// Decode the flag groups of one compressed chunk, whose first group starts
/// at input offset `offset`, and append the result to `out`, stopping when
/// it is full.
fn decode_chunk(body: &[u8], offset: usize, out: &mut Output) -> Result<()> {
    let start = out.bytes.len();
    let mut pos = 0;
    while pos < body.len() {
        let flags = body[pos];
        pos += 1;
        for element in 0..FLAG_GROUP_ELEMENTS {
            if pos >= body.len() {
                break;
            }
            if out.stops() {
                out.stopped = true;
                return Ok(());
            }
            let at = offset + pos;
            let written = out.bytes.len() - start;
            if flags >> element & 1 == 0 {
                if written >= CHUNK_SIZE {
                    return Err(oversized_chunk(at));
                }
                if out.room(1)? == 1 {
                    out.bytes.push(body[pos]);
                }
                pos += 1;
                continue;
            }
            let word = body
                .get(pos..pos + 2)
                .ok_or_else(|| error(format!("Truncated LZNT1 compressed word at 0x{at:X}")))?;
            let word = u16::from_le_bytes([word[0], word[1]]);
            pos += 2;
            let length_bits = WORD_BITS - displacement_bits(written);
            let displacement = usize::from(word >> length_bits) + 1;
            let length = usize::from(word & ((1 << length_bits) - 1)) + MIN_MATCH;
            if displacement > written {
                return Err(error(format!(
                    "Invalid LZNT1 compressed word at 0x{at:X}: displacement {displacement} B, \
                     {written} B decoded in the chunk"
                )));
            }
            if written + length > CHUNK_SIZE {
                return Err(oversized_chunk(at));
            }
            let from = out.bytes.len() - displacement;
            for i in 0..out.room(length)? {
                let b = out.bytes[from + i];
                out.bytes.push(b);
            }
        }
    }
    Ok(())
}

/// The error for a chunk that decodes to more than 4096 bytes.
fn oversized_chunk(at: usize) -> ClassifierError {
    error(format!(
        "Invalid LZNT1 chunk: the element at 0x{at:X} decodes past {CHUNK_SIZE} B"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 59-byte buffer of [MS-XCA] section 3.3.
    const SPEC_EXAMPLE: [u8; 59] = [
        0x38, 0xb0, 0x88, 0x46, 0x23, 0x20, 0x00, 0x20, 0x47, 0x20, 0x41, 0x00, 0x10, 0xa2, 0x47,
        0x01, 0xa0, 0x45, 0x20, 0x44, 0x00, 0x08, 0x45, 0x01, 0x50, 0x79, 0x00, 0xc0, 0x45, 0x20,
        0x05, 0x24, 0x13, 0x88, 0x05, 0xb4, 0x02, 0x4a, 0x44, 0xef, 0x03, 0x58, 0x02, 0x8c, 0x09,
        0x16, 0x01, 0x48, 0x45, 0x00, 0xbe, 0x00, 0x9e, 0x00, 0x04, 0x01, 0x18, 0x90, 0x00,
    ];

    /// The 142-byte string, with its terminating NUL, that the example
    /// decodes to.
    const SPEC_TEXT: &[u8] =
        b"F# F# G A A G F# E D D E F# F# E E F# F# G A A G F# E D D E F# E D D E \
E F# D E F# G F# D E F# G F# E D E A F# F# G A A G F# E D D E F# E D D\0";

    /// A compressed chunk header for `size` bytes, header included.
    fn compressed_header(size: usize) -> [u8; 2] {
        let field = u16::try_from(size - CHUNK_SIZE_BIAS).expect("chunk fits");
        (CHUNK_COMPRESSED | CHUNK_SIGNATURE | field).to_le_bytes()
    }

    /// A compressed chunk of literal-only flag groups holding `bytes`.
    fn literal_chunk(bytes: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for group in bytes.chunks(8) {
            body.push(0);
            body.extend_from_slice(group);
        }
        let mut chunk = compressed_header(body.len() + CHUNK_HEADER_SIZE).to_vec();
        chunk.extend_from_slice(&body);
        chunk
    }

    #[test]
    fn the_specification_example_decodes() {
        assert_eq!(SPEC_TEXT.len(), 142);
        let decoded = decode(&SPEC_EXAMPLE, 4096).unwrap();
        assert_eq!(decoded.data, SPEC_TEXT);
        assert_eq!(decoded.consumed, Some(59));
    }

    #[test]
    fn displacement_widths_grow_with_the_decoded_bytes() {
        let widths = [
            (0, 4),
            (1, 4),
            (16, 4),
            (17, 5),
            (32, 5),
            (33, 6),
            (2048, 11),
            (2049, 12),
            (4096, 12),
        ];
        for (written, bits) in widths {
            assert_eq!(displacement_bits(written), bits, "{written} B written");
        }
    }

    #[test]
    fn uncompressed_chunks_copy_their_bytes() {
        // Header 0x3002: uncompressed, signature 3, 5 bytes with the header.
        let decoded = decode(&[0x02, 0x30, b'a', b'b', b'c'], 64).unwrap();
        assert_eq!(decoded.data, b"abc");
        assert_eq!(decoded.consumed, Some(5));
    }

    #[test]
    fn matches_overlap_their_output_and_use_wider_displacements_later() {
        // "ab", then a word with 4 displacement bits: displacement 1 + 1,
        // length 5 + 3 copies "abababab".
        let mut body = vec![0b0000_0100, b'a', b'b'];
        body.extend_from_slice(&((1u16 << 12) | 5).to_le_bytes());
        let mut stream = compressed_header(body.len() + 2).to_vec();
        stream.extend_from_slice(&body);
        assert_eq!(decode(&stream, 64).unwrap().data, b"ababababab");

        // After 17 literals the displacement field is 5 bits wide: a word
        // with displacement 16 + 1 and length 0 + 3 copies bytes 0-2.
        let literals = b"0123456789abcdefg";
        let mut body = Vec::new();
        for (i, group) in literals.chunks(8).enumerate() {
            let flags = if i == 2 { 0b0000_0010 } else { 0 };
            body.push(flags);
            body.extend_from_slice(group);
            if i == 2 {
                body.extend_from_slice(&(16u16 << 11).to_le_bytes());
            }
        }
        let mut stream = compressed_header(body.len() + 2).to_vec();
        stream.extend_from_slice(&body);
        let decoded = decode(&stream, 64).unwrap().data;
        assert_eq!(&decoded[..17], literals);
        assert_eq!(&decoded[17..], b"012");
    }

    #[test]
    fn a_short_chunk_before_another_is_zero_filled() {
        let mut stream = literal_chunk(b"first");
        stream.extend_from_slice(&literal_chunk(b"second"));
        let decoded = decode(&stream, 8192).unwrap().data;
        assert_eq!(decoded.len(), CHUNK_SIZE + 6);
        assert_eq!(&decoded[..5], b"first");
        assert!(decoded[5..CHUNK_SIZE].iter().all(|&b| b == 0));
        assert_eq!(&decoded[CHUNK_SIZE..], b"second");
        assert!(decode(&stream, CHUNK_SIZE).is_err());
    }

    #[test]
    fn an_end_header_ends_the_buffer() {
        let mut stream = literal_chunk(b"data");
        let chunks = stream.len();
        stream.extend_from_slice(&[0, 0, 0xde, 0xad]);
        let decoded = decode(&stream, 64).unwrap();
        assert_eq!(decoded.data, b"data");
        assert_eq!(decoded.consumed, Some(chunks));
        let mut odd = literal_chunk(b"data");
        odd.push(0);
        assert_eq!(decode(&odd, 64).unwrap().data, b"data");
        assert_eq!(decode(&[], 64).unwrap().data, b"");
    }

    #[test]
    fn malformed_chunks_are_errors() {
        let message = |stream: &[u8]| decode(stream, 8192).unwrap_err().to_string();
        // Signature 2 instead of 3.
        assert_eq!(
            message(&[0x02, 0xa0, 0x00, b'a', b'b']),
            "Compressed stream parse error: Invalid LZNT1 chunk signature at 0x0: header 0xA002"
        );
        // A word as the first element reaches before the chunk.
        assert_eq!(
            message(&[0x02, 0xb0, 0x01, 0x00, 0x00]),
            "Compressed stream parse error: Invalid LZNT1 compressed word at 0x3: \
             displacement 1 B, 0 B decoded in the chunk"
        );
        // A chunk size past the input, and a word cut by the chunk end.
        assert!(message(&[0x10, 0xb0, 0x00, b'a']).starts_with(
            "Compressed stream parse error: Truncated LZNT1 chunk at 0x0: 19 B, 4 B left"
        ));
        assert!(message(&[0x02, 0xb0, 0x02, b'a', 0x00])
            .contains("Truncated LZNT1 compressed word at 0x4"));
        assert!(message(&[0x41]).contains("Truncated LZNT1 chunk header at 0x0"));
        // After one literal the length field is 12 bits wide. A copy of
        // 0xFFF + 3 bytes would decode past 4096 bytes in the chunk; a copy
        // of 0xFFC + 3 fills the chunk, so a literal after it would.
        let chunk = |body: &[u8]| {
            let mut stream = compressed_header(body.len() + 2).to_vec();
            stream.extend_from_slice(body);
            stream
        };
        let long_copy = chunk(&[0b0000_0010, b'x', 0xff, 0x0f]);
        assert_eq!(
            message(&long_copy),
            "Compressed stream parse error: Invalid LZNT1 chunk: the element at 0x4 decodes past \
             4096 B"
        );
        let full = chunk(&[0b0000_0010, b'x', 0xfc, 0x0f]);
        assert_eq!(decode(&full, 8192).unwrap().data, vec![b'x'; CHUNK_SIZE]);
        let overfull = chunk(&[0b0000_0010, b'x', 0xfc, 0x0f, b'y']);
        assert!(message(&overfull).contains("the element at 0x6 decodes past 4096 B"));
    }

    #[test]
    fn output_beyond_the_limit_is_an_error() {
        assert!(decode(&SPEC_EXAMPLE, 141).is_err());
        assert_eq!(decode(&SPEC_EXAMPLE, 142).unwrap().data.len(), 142);
        assert!(decode(&[0x02, 0x30, b'a', b'b', b'c'], 2).is_err());
    }

    #[test]
    fn decoding_can_stop_at_the_limit() {
        for limit in [0, 1, 3, 9, 10, 141] {
            let decoded = decode_until(&SPEC_EXAMPLE, limit, AtLimit::Stop).unwrap();
            assert_eq!(decoded.data, &SPEC_TEXT[..limit], "limit {limit}");
            assert_eq!(decoded.consumed, None);
        }
        let whole = decode_until(&SPEC_EXAMPLE, 142, AtLimit::Stop).unwrap();
        assert_eq!(whole.data, SPEC_TEXT);
        assert_eq!(whole.consumed, Some(59));
        let mut stream = literal_chunk(b"first");
        stream.extend_from_slice(&literal_chunk(b"second"));
        let filled = decode_until(&stream, 100, AtLimit::Stop).unwrap().data;
        assert_eq!(&filled[..5], b"first");
        assert_eq!(filled.len(), 100);
    }
}
