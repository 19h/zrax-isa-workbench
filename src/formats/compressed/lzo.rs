//! LZO1X decompression (lzop blocks and raw streams) and the lzop file
//! format.
//!
//! The LZO1X bitstream follows Linux `Documentation/staging/lzo.rst` and
//! `lib/lzo/lzo1x_decompress_safe.c` (v6.6), without the Linux-only
//! run-length extension (bitstream version 1, which lzop never writes).
//! The lzop header and block framing follow lzop 1.04 `src/lzop.c`
//! (`write_header`, `p_header` and `x_decompress`). Squashfs stores raw
//! LZO1X blocks without lzop framing (squashfs-tools 4.6.1
//! `lzo_wrapper.h`).

use super::*;

/// lzop file magic: `\x89LZO\0\r\n\x1a\n`.
pub(super) const LZOP_MAGIC: [u8; 9] = [0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a];

/// Header and block flags (lzop `conf.h` `F_*`).
const F_ADLER32_D: u32 = 0x0000_0001;
const F_ADLER32_C: u32 = 0x0000_0002;
const F_H_EXTRA_FIELD: u32 = 0x0000_0040;
const F_CRC32_D: u32 = 0x0000_0100;
const F_CRC32_C: u32 = 0x0000_0200;
const F_H_FILTER: u32 = 0x0000_0800;
const F_H_CRC32: u32 = 0x0000_1000;

/// Compression methods that produce LZO1X streams (lzop `M_LZO1X_1`,
/// `M_LZO1X_1_15`, `M_LZO1X_999`).
const LZO1X_METHODS: [u8; 3] = [1, 2, 3];

/// First lzop version whose header carries `version_needed`, the level byte
/// and the high half of the modification time.
const LZOP_VERSION_EXTENDED: u16 = 0x0940;

/// lzop never writes blocks larger than this (lzop `MAX_BLOCK_SIZE`).
const LZOP_MAX_BLOCK: usize = 64 << 20;

/// Largest match distance encodable by the two-byte M2 form.
const M2_MAX_OFFSET: usize = 0x0800;

/// Base distance of the M4 form.
const M4_BASE: usize = 0x4000;

/// Bound on consecutive zero bytes in a length extension (Linux
/// `MAX_255_COUNT`), so lengths cannot overflow.
const MAX_255_COUNT: usize = usize::MAX / 255 - 2;

/// Decode one raw LZO1X block into exactly `expected` bytes.
pub(super) fn lzo1x(input: &[u8], expected: usize) -> Result<Vec<u8>> {
    let mut decoder = Lzo1x {
        input,
        ip: 0,
        out: Vec::with_capacity(expected),
        limit: expected,
        limit_kind: OutputLimit::Declared,
    };
    decoder.run()?;
    if decoder.ip != input.len() {
        return Err(error(format!(
            "Invalid LZO1X block: {} B of input not consumed",
            input.len() - decoder.ip
        )));
    }
    if decoder.out.len() != expected {
        return Err(error(format!(
            "Invalid LZO1X block: decoded {} B, header declares {} B",
            decoder.out.len(),
            expected
        )));
    }
    Ok(decoder.out)
}

/// Decode one raw LZO1X block that has no declared size, as Squashfs,
/// UBIFS and JFFS2 store data, into at most `limit` bytes. The block ends
/// at its end-of-stream marker; `consumed` says where, so containers can
/// compare it and the decoded size with what they stored.
pub(super) fn lzo1x_block(input: &[u8], limit: usize) -> Result<Decoded> {
    let mut decoder = Lzo1x {
        input,
        ip: 0,
        out: Vec::new(),
        limit,
        limit_kind: OutputLimit::Caller,
    };
    decoder.run()?;
    Ok(Decoded {
        data: decoder.out,
        consumed: Some(decoder.ip),
        check: None,
    })
}

/// Where a decoder's output limit comes from, which decides the error
/// reported when the output would pass it.
#[derive(Clone, Copy)]
enum OutputLimit {
    /// The lzop block header declares the decoded size.
    Declared,
    /// The caller's extraction limit.
    Caller,
}

struct Lzo1x<'a> {
    input: &'a [u8],
    ip: usize,
    out: Vec<u8>,
    limit: usize,
    limit_kind: OutputLimit,
}

/// What follows a decoded match or literal run.
enum Step {
    /// Copy `n` (0-3) trailing literals, then continue in state `n`.
    Trailing(usize),
    /// The end-of-stream marker was decoded.
    End,
}

impl Lzo1x<'_> {
    fn byte(&mut self) -> Result<usize> {
        let b = *self
            .input
            .get(self.ip)
            .ok_or_else(|| error("Truncated LZO1X block"))?;
        self.ip += 1;
        Ok(usize::from(b))
    }

    fn le16(&mut self) -> Result<usize> {
        let low = self.byte()?;
        let high = self.byte()?;
        Ok(low | (high << 8))
    }

    /// Length extension: each zero byte adds 255, the final byte its value.
    fn extended_length(&mut self, base: usize) -> Result<usize> {
        let mut zeros = 0usize;
        while self.input.get(self.ip) == Some(&0) {
            self.ip += 1;
            zeros += 1;
            if zeros > MAX_255_COUNT {
                return Err(error("Invalid LZO1X length extension"));
            }
        }
        let last = self.byte()?;
        Ok(zeros * 255 + base + last)
    }

    /// Fail unless `count` more output bytes fit within the limit.
    fn reserve(&self, count: usize) -> Result<()> {
        let fits = self
            .out
            .len()
            .checked_add(count)
            .is_some_and(|end| end <= self.limit);
        if fits {
            return Ok(());
        }
        Err(match self.limit_kind {
            OutputLimit::Declared => error("LZO1X output exceeds the declared block size"),
            OutputLimit::Caller => exceeds(self.limit),
        })
    }

    fn literals(&mut self, count: usize) -> Result<()> {
        let end = self
            .ip
            .checked_add(count)
            .filter(|end| *end <= self.input.len())
            .ok_or_else(|| error("Truncated LZO1X literal run"))?;
        self.reserve(count)?;
        self.out.extend_from_slice(&self.input[self.ip..end]);
        self.ip = end;
        Ok(())
    }

    /// Copy `length` bytes starting `distance` bytes back.
    fn copy_match(&mut self, distance: usize, length: usize) -> Result<()> {
        if distance == 0 || distance > self.out.len() {
            return Err(error("Invalid LZO1X match distance"));
        }
        self.reserve(length)?;
        let start = self.out.len() - distance;
        for i in 0..length {
            let b = self.out[start + i];
            self.out.push(b);
        }
        Ok(())
    }

    fn run(&mut self) -> Result<()> {
        // State is the number of literals copied after the previous
        // instruction: 0, 1-3, or 4 for a literal run of four or more.
        let mut state;
        let first = *self
            .input
            .first()
            .ok_or_else(|| error("Truncated LZO1X block"))?;
        if first > 17 {
            self.ip = 1;
            let count = usize::from(first) - 17;
            self.literals(count)?;
            state = if count < 4 { count } else { 4 };
        } else {
            state = 0;
        }
        loop {
            let t = self.byte()?;
            let step = if t < 16 {
                match state {
                    0 => {
                        // Literal run of 4 or more bytes.
                        let count = if t == 0 {
                            self.extended_length(15)? + 3
                        } else {
                            t + 3
                        };
                        self.literals(count)?;
                        state = 4;
                        continue;
                    }
                    4 => {
                        // Three-byte match after a long literal run.
                        let distance = 1 + M2_MAX_OFFSET + (t >> 2) + (self.byte()? << 2);
                        self.copy_match(distance, 3)?;
                        Step::Trailing(t & 3)
                    }
                    _ => {
                        // Two-byte match after one to three literals.
                        let distance = 1 + (t >> 2) + (self.byte()? << 2);
                        self.copy_match(distance, 2)?;
                        Step::Trailing(t & 3)
                    }
                }
            } else if t >= 64 {
                // M2: length 3-8, distance up to 2 KiB.
                let distance = 1 + ((t >> 2) & 7) + (self.byte()? << 3);
                self.copy_match(distance, (t >> 5) + 1)?;
                Step::Trailing(t & 3)
            } else if t >= 32 {
                // M3: distance up to 16 KiB.
                let length = match t & 31 {
                    0 => self.extended_length(31)? + 2,
                    n => n + 2,
                };
                let word = self.le16()?;
                self.copy_match(1 + (word >> 2), length)?;
                Step::Trailing(word & 3)
            } else {
                // M4: distance 16-48 KiB, or the end-of-stream marker.
                let length = match t & 7 {
                    0 => self.extended_length(7)? + 2,
                    n => n + 2,
                };
                let word = self.le16()?;
                let distance = ((t & 8) << 11) + (word >> 2);
                if distance == 0 {
                    if length != 3 {
                        return Err(error("Invalid LZO1X end-of-stream marker"));
                    }
                    Step::End
                } else {
                    self.copy_match(distance + M4_BASE, length)?;
                    Step::Trailing(word & 3)
                }
            };
            match step {
                Step::End => return Ok(()),
                Step::Trailing(count) => {
                    self.literals(count)?;
                    state = count;
                }
            }
        }
    }
}

/// The parts of an lzop header that affect decoding.
struct LzopHeader {
    flags: u32,
    /// File offset of the first block.
    end: usize,
}

/// lzop header: magic (9), version (2), library version (2), version needed
/// (2, from 0x0940), method (1), level (1, from 0x0940), flags (4), filter
/// (4, if `F_H_FILTER`), mode (4), modification time (4 + 4 from 0x0940),
/// name length (1) and name, header checksum (4), optional extra field.
/// Multi-byte fields are big-endian.
fn lzop_header(data: &[u8]) -> Result<LzopHeader> {
    if !data.starts_with(&LZOP_MAGIC) {
        return Err(error("Missing lzop magic"));
    }
    let mut pos = LZOP_MAGIC.len();
    let version = be_u16(data, pos)?;
    pos += 4;
    if version >= LZOP_VERSION_EXTENDED {
        pos += 2;
    }
    let method = *data
        .get(pos)
        .ok_or_else(|| error("Truncated lzop header"))?;
    if !LZO1X_METHODS.contains(&method) {
        return Err(error(format!("Unsupported lzop method {method}")));
    }
    pos += 1;
    if version >= LZOP_VERSION_EXTENDED {
        pos += 1;
    }
    let flags = be_u32(data, pos)?;
    pos += 4;
    if flags & F_H_FILTER != 0 {
        return Err(error("Unsupported lzop filter"));
    }
    pos += 8;
    if version >= LZOP_VERSION_EXTENDED {
        pos += 4;
    }
    let name_len = usize::from(
        *data
            .get(pos)
            .ok_or_else(|| error("Truncated lzop header"))?,
    );
    pos += 1 + name_len;
    let checked = slice(data, LZOP_MAGIC.len(), pos.saturating_sub(LZOP_MAGIC.len()))?;
    let stored = be_u32(data, pos)?;
    let computed = if flags & F_H_CRC32 != 0 {
        checksum::crc32(checked)
    } else {
        checksum::adler32(checked)
    };
    if stored != computed {
        return Err(error(format!(
            "Invalid lzop header checksum 0x{stored:08X}, computed 0x{computed:08X}"
        )));
    }
    pos += 4;
    if flags & F_H_EXTRA_FIELD != 0 {
        let extra = usize::try_from(be_u32(data, pos)?)
            .map_err(|_| error("Invalid lzop extra field length"))?;
        pos = pos
            .checked_add(8)
            .and_then(|p| p.checked_add(extra))
            .ok_or_else(|| error("Invalid lzop extra field length"))?;
    }
    Ok(LzopHeader { flags, end: pos })
}

/// Verify an optional block checksum selected by `adler`/`crc` flags.
fn block_check(
    data: &[u8],
    pos: &mut usize,
    flags: u32,
    adler: u32,
    crc: u32,
    bytes: &[u8],
) -> Result<()> {
    if flags & adler != 0 {
        let stored = be_u32(data, *pos)?;
        *pos += 4;
        if stored != checksum::adler32(bytes) {
            return Err(error("Invalid lzop block Adler-32"));
        }
    }
    if flags & crc != 0 {
        let stored = be_u32(data, *pos)?;
        *pos += 4;
        if stored != checksum::crc32(bytes) {
            return Err(error("Invalid lzop block CRC-32"));
        }
    }
    Ok(())
}

/// Decode an lzop file: header, then blocks of decoded size, stored size,
/// optional checksums and data, until a zero decoded size.
pub(super) fn lzop(data: &[u8], limit: usize) -> Result<Decoded> {
    let header = lzop_header(data)?;
    let mut pos = header.end;
    let mut out = Vec::new();
    loop {
        let decoded_size =
            usize::try_from(be_u32(data, pos)?).map_err(|_| error("Invalid lzop block size"))?;
        pos += 4;
        if decoded_size == 0 {
            break;
        }
        let stored_size =
            usize::try_from(be_u32(data, pos)?).map_err(|_| error("Invalid lzop block size"))?;
        pos += 4;
        if decoded_size > LZOP_MAX_BLOCK || stored_size > decoded_size {
            return Err(error(format!(
                "Invalid lzop block sizes at 0x{:X}",
                pos - 8
            )));
        }
        if out.len() + decoded_size > limit {
            return Err(exceeds(limit));
        }
        let checks_at = pos;
        let mut skip = 0;
        for flag in [F_ADLER32_D, F_CRC32_D] {
            if header.flags & flag != 0 {
                skip += 4;
            }
        }
        if stored_size < decoded_size {
            for flag in [F_ADLER32_C, F_CRC32_C] {
                if header.flags & flag != 0 {
                    skip += 4;
                }
            }
        }
        let stored = slice(data, checks_at + skip, stored_size)?;
        let block = if stored_size == decoded_size {
            stored.to_vec()
        } else {
            lzo1x(stored, decoded_size)?
        };
        let mut check_pos = checks_at;
        block_check(
            data,
            &mut check_pos,
            header.flags,
            F_ADLER32_D,
            F_CRC32_D,
            &block,
        )?;
        if stored_size < decoded_size {
            block_check(
                data,
                &mut check_pos,
                header.flags,
                F_ADLER32_C,
                F_CRC32_C,
                stored,
            )?;
        }
        out.extend_from_slice(&block);
        pos = checks_at + skip + stored_size;
    }
    let verified = header.flags & (F_ADLER32_D | F_CRC32_D) != 0;
    Ok(Decoded {
        data: out,
        consumed: Some(pos),
        check: verified.then_some("lzop block checksums"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "abcabcabcabc": literal run "abc" (first byte 17 + 3), an M2 match
    /// of length 8 at distance 3, then the M4 end marker `11 00 00`.
    const REPEATED: &[u8] = &[20, b'a', b'b', b'c', 0xe8, 0x00, 0x11, 0x00, 0x00];

    #[test]
    fn lzo1x_decodes_literals_matches_and_end_marker() {
        // M2 byte 0xE8: length (0xE8 >> 5) + 1 = 8, distance 1 + ((0xE8 >> 2) & 7) + 0 = 3.
        let decoded = lzo1x(REPEATED, 11).unwrap();
        assert_eq!(decoded, b"abcabcabcab");
    }

    #[test]
    fn lzo1x_rejects_truncation_and_bad_sizes() {
        for end in 0..REPEATED.len() {
            assert!(lzo1x(&REPEATED[..end], 11).is_err(), "prefix {end}");
        }
        assert!(lzo1x(REPEATED, 10).is_err());
        assert!(lzo1x(REPEATED, 12).is_err());
    }

    #[test]
    fn raw_lzo1x_blocks_decode_up_to_the_limit() {
        let decoded = lzo1x_block(REPEATED, 4096).unwrap();
        assert_eq!(decoded.data, b"abcabcabcab");
        assert_eq!(decoded.consumed, Some(REPEATED.len()));
        assert!(lzo1x_block(REPEATED, 10).is_err());
        for end in 0..REPEATED.len() {
            assert!(lzo1x_block(&REPEATED[..end], 4096).is_err(), "prefix {end}");
        }
    }

    #[test]
    fn raw_lzo1x_blocks_stop_at_the_end_marker() {
        let mut stream = REPEATED.to_vec();
        stream.extend_from_slice(b"trailing");
        let decoded = lzo1x_block(&stream, 4096).unwrap();
        assert_eq!(decoded.data, b"abcabcabcab");
        assert_eq!(decoded.consumed, Some(REPEATED.len()));
    }

    #[test]
    fn lzo1x_rejects_distances_before_output_start() {
        // Literal "a", then an M2 match at distance 8 with one byte of output.
        let bad = [18, b'a', 0xfc, 0x00, 0x11, 0x00, 0x00];
        assert!(lzo1x(&bad, 9).is_err());
    }
}
