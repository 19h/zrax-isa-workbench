//! JFFS2's own compressors: rtime and the two rubin variants.
//!
//! Linux v6.11 `fs/jffs2/compr_rtime.c` (`jffs2_rtime_decompress`) and
//! `fs/jffs2/compr_rubin.c` (`rubin_do_decompress`, `init_decode`,
//! `__do_decode`, `decode`, `in_byte`). Neither format records its decoded
//! size; the JFFS2 inode node stores it as `dsize` and passes it as the
//! limit:
//! - rtime is a sequence of (byte, repeat count) pairs; decoding stops at
//!   the limit, as the kernel's does, or where the input ends;
//! - rubin is a binary arithmetic code with eight per-bit probabilities and
//!   no end marker, so [`rubin`] decodes exactly `limit` bytes.
//!
//! The kernel decoders read and write without bounds checks; these stop
//! with an error instead of reading past the input or writing past the
//! limit.

use super::*;

/// Width of the rubin range registers (`RUBIN_REG_SIZE`).
const RUBIN_REG_SIZE: u32 = 16;

/// Top bit of a rubin register, and the bits below it (`UPPER_BIT_RUBIN`,
/// `LOWER_BITS_RUBIN`).
const UPPER_BIT_RUBIN: u64 = 1 << (RUBIN_REG_SIZE - 1);
const LOWER_BITS_RUBIN: u64 = UPPER_BIT_RUBIN - 1;

/// Probability denominator and per-bit table of the fixed `rubinmips`
/// model (`BIT_DIVIDER_MIPS`, `bits_mips`).
const BIT_DIVIDER_MIPS: u64 = 1043;
const BITS_MIPS: [u64; 8] = [277, 249, 290, 267, 229, 341, 212, 241];

/// The dynamic model stores its eight probabilities, out of 256, in the
/// first eight bytes of the node data (`jffs2_dynrubin_decompress`).
const DYNRUBIN_DIVIDER: u64 = 256;
const DYNRUBIN_TABLE_SIZE: usize = 8;

/// A consistent coder renormalizes by at most 17 bits per symbol; the loop
/// stops with an error past this bound (own bound, a termination guard).
const MAX_RENORMALIZE_BITS: u32 = 32;

/// Decode rtime pairs until `limit` bytes are produced or the input ends.
/// Each pair copies its byte, then repeats `count` bytes from just after
/// the previous occurrence of that byte. The positions table keeps 16-bit
/// offsets, as the kernel's `unsigned short positions[256]` does.
pub(super) fn rtime(input: &[u8], limit: usize) -> Result<Decoded> {
    let mut positions = [0u16; 256];
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0;
    while out.len() < limit && pos < input.len() {
        let pair = input
            .get(pos..pos + 2)
            .ok_or_else(|| error("Truncated rtime data: odd input length"))?;
        let value = pair[0];
        let repeat = usize::from(pair[1]);
        pos += 2;
        if out.len() + 1 + repeat > limit {
            return Err(exceeds(limit));
        }
        out.push(value);
        let start = usize::from(positions[usize::from(value)]);
        positions[usize::from(value)] =
            u16::try_from(out.len() & usize::from(u16::MAX)).expect("masked to 16 bits");
        // `start` is at most the position of the byte just written, and
        // each step writes one byte, so `back` stays behind the write
        // position; the copy may overlap the bytes it produces, as in the
        // kernel.
        for back in start..start + repeat {
            let repeated = out[back];
            out.push(repeated);
        }
    }
    Ok(Decoded {
        data: out,
        consumed: Some(pos),
        check: None,
    })
}

/// Which probability model a rubin stream uses.
#[derive(Debug, Clone, Copy)]
pub(super) enum RubinModel {
    /// The fixed `bits_mips` table.
    Mips,
    /// Eight table bytes stored before the coded bits.
    Dynamic,
}

/// Decode exactly `size` bytes of rubin data.
pub(super) fn rubin(input: &[u8], size: usize, model: RubinModel) -> Result<Decoded> {
    let (divider, bits, table_size) = match model {
        RubinModel::Mips => (BIT_DIVIDER_MIPS, BITS_MIPS, 0),
        RubinModel::Dynamic => {
            let table = slice(input, 0, DYNRUBIN_TABLE_SIZE)
                .map_err(|_| error("Truncated dynrubin probability table"))?;
            let mut bits = [0u64; 8];
            for (bit, &probability) in bits.iter_mut().zip(table) {
                *bit = u64::from(probability);
            }
            (DYNRUBIN_DIVIDER, bits, DYNRUBIN_TABLE_SIZE)
        }
    };
    let mut decoder = Rubin::new(&input[table_size..], divider, bits)?;
    // Not preallocated: `size` comes from the container, and a stream
    // that runs out of bits stops long before it on corrupt input.
    let mut out = Vec::new();
    for _ in 0..size {
        out.push(decoder.byte()?);
    }
    Ok(Decoded {
        data: out,
        consumed: Some(table_size + (decoder.bit + 7) / 8),
        check: None,
    })
}

/// Rubin decoder state (`struct rubin_state`).
struct Rubin<'a> {
    input: &'a [u8],
    /// Next bit to read, counted from the most significant bit of byte 0.
    bit: usize,
    /// Range width.
    p: u64,
    /// Range base.
    q: u64,
    /// Code register: the input bits under the range.
    rec_q: u64,
    divider: u64,
    /// Probability of a 1, out of `divider`, for each bit of a byte.
    bits: [u64; 8],
}

impl<'a> Rubin<'a> {
    /// `init_rubin` and `init_decode`: the code register starts with the
    /// first 16 input bits.
    fn new(input: &'a [u8], divider: u64, bits: [u64; 8]) -> Result<Self> {
        let mut decoder = Self {
            input,
            bit: 0,
            p: 2 * UPPER_BIT_RUBIN,
            q: 0,
            rec_q: 0,
            divider,
            bits,
        };
        for _ in 0..RUBIN_REG_SIZE {
            decoder.rec_q = decoder.rec_q * 2 + decoder.pull_bit()?;
        }
        Ok(decoder)
    }

    /// `pullbit`, most significant bit first.
    fn pull_bit(&mut self) -> Result<u64> {
        let byte = self
            .input
            .get(self.bit >> 3)
            .ok_or_else(|| error("Truncated rubin data"))?;
        let value = (byte >> (7 - (self.bit & 7))) & 1;
        self.bit += 1;
        Ok(u64::from(value))
    }

    /// `__do_decode`: shift the range until it spans more than half the
    /// register, then shift as many input bits into the code register.
    fn renormalize(&mut self) -> Result<()> {
        let mut shifts = 0;
        loop {
            shifts += 1;
            self.q = (self.q & LOWER_BITS_RUBIN) << 1;
            self.p <<= 1;
            if self.q < UPPER_BIT_RUBIN && self.p + self.q > UPPER_BIT_RUBIN {
                break;
            }
            if shifts >= MAX_RENORMALIZE_BITS {
                return Err(error("Invalid rubin coder state"));
            }
        }
        for _ in 0..shifts {
            let bit = self.pull_bit()?;
            self.rec_q = ((self.rec_q & LOWER_BITS_RUBIN) << 1) + bit;
        }
        Ok(())
    }

    /// `decode`: one bit that is 0 with probability `zero / (zero + one)`.
    fn decode(&mut self, zero: u64, one: u64) -> Result<bool> {
        if self.q >= UPPER_BIT_RUBIN || self.p + self.q <= UPPER_BIT_RUBIN {
            self.renormalize()?;
        }
        let mut split = (zero * self.p / (zero + one)).max(1);
        if split >= self.p {
            split = self.p - 1;
        }
        let symbol = self.rec_q >= self.q + split;
        if symbol {
            self.q += split;
            split = self.p - split;
        }
        self.p = split;
        Ok(symbol)
    }

    /// `in_byte`: eight bits, least significant first, each with its own
    /// probability.
    fn byte(&mut self) -> Result<u8> {
        let mut result = 0u8;
        for i in 0..8 {
            let one = self.bits[i];
            if self.decode(self.divider - one, one)? {
                result |= 1 << i;
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Port of the kernel's `jffs2_rtime_compress`, for round trips.
    fn rtime_compress(data: &[u8]) -> Vec<u8> {
        let mut positions = [0usize; 256];
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let value = data[pos];
            out.push(value);
            pos += 1;
            let mut back = positions[usize::from(value)];
            positions[usize::from(value)] = pos;
            let mut run = 0u8;
            while back < pos && pos < data.len() && data[pos] == data[back] && run < 255 {
                pos += 1;
                back += 1;
                run += 1;
            }
            out.push(run);
        }
        out
    }

    /// Port of the kernel's rubin encoder (`init_rubin`, `encode`,
    /// `out_byte`, `end_rubin`), without the output-size limit.
    fn rubin_compress(data: &[u8], divider: u64, bits: [u64; 8]) -> Vec<u8> {
        let mut out_bits: Vec<bool> = Vec::new();
        let mut p = 2 * UPPER_BIT_RUBIN;
        let mut q = 0u64;
        for &byte in data {
            for (i, one) in bits.iter().enumerate() {
                let symbol = (byte >> i) & 1 == 1;
                while q >= UPPER_BIT_RUBIN || p + q <= UPPER_BIT_RUBIN {
                    out_bits.push(q & UPPER_BIT_RUBIN != 0);
                    q = (q & LOWER_BITS_RUBIN) << 1;
                    p <<= 1;
                }
                let zero = divider - one;
                let mut split = (zero * p / (zero + one)).max(1);
                if split >= p {
                    split = p - 1;
                }
                if symbol {
                    p -= split;
                    q += split;
                } else {
                    p = split;
                }
            }
        }
        for _ in 0..RUBIN_REG_SIZE {
            out_bits.push(q & UPPER_BIT_RUBIN != 0);
            q = (q & LOWER_BITS_RUBIN) << 1;
        }
        out_bits
            .chunks(8)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0u8, |byte, (i, bit)| byte | (u8::from(*bit) << (7 - i)))
            })
            .collect()
    }

    #[test]
    fn rtime_round_trips_runs_and_overlapping_copies() {
        let data = b"aaaaaaaaaabcabcabcabc\x00\x00\x00\x00zrax rtime zrax rtime".repeat(3);
        let packed = rtime_compress(&data);
        assert!(packed.len() < data.len());
        let decoded = rtime(&packed, data.len()).unwrap();
        assert_eq!(decoded.data, data);
        assert_eq!(decoded.consumed, Some(packed.len()));
        assert!(rtime(&packed, data.len() - 1).is_err());
        assert_eq!(
            rtime(&packed[..packed.len() - 2], data.len())
                .unwrap()
                .data
                .len(),
            data.len() - 1 - usize::from(packed[packed.len() - 1])
        );
        assert!(rtime(&packed[..packed.len() - 1], data.len()).is_err());
    }

    /// The kernel compressor's pairs for "abababab": `a` and `b` with no
    /// repeat, then `a` repeating five bytes from offset 1.
    #[test]
    fn rtime_matches_the_kernel_pair_layout() {
        let decoded = rtime(&[b'a', 0, b'b', 0, b'a', 5], 8).unwrap();
        assert_eq!(decoded.data, b"abababab");
    }

    #[test]
    fn rubin_round_trips_both_models() {
        let data = b"rubin rubin rubin \x00\x00\x00\x00\x7fELF\x01\x02".repeat(8);
        let packed = rubin_compress(&data, BIT_DIVIDER_MIPS, BITS_MIPS);
        let decoded = rubin(&packed, data.len(), RubinModel::Mips).unwrap();
        assert_eq!(decoded.data, data);
        assert_eq!(decoded.consumed, Some(packed.len()));

        let table = [12u8, 200, 1, 255, 128, 64, 90, 33];
        let mut dynamic = table.to_vec();
        dynamic.extend(rubin_compress(
            &data,
            DYNRUBIN_DIVIDER,
            table.map(u64::from),
        ));
        let decoded = rubin(&dynamic, data.len(), RubinModel::Dynamic).unwrap();
        assert_eq!(decoded.data, data);
    }

    #[test]
    fn rubin_rejects_short_input_without_panicking() {
        assert!(rubin(&[], 1, RubinModel::Mips).is_err());
        assert!(rubin(&[0xff; 7], 1, RubinModel::Dynamic).is_err());
        assert!(rubin(&[0x55; 4], 4096, RubinModel::Mips).is_err());
        assert_eq!(rubin(&[0; 2], 0, RubinModel::Mips).unwrap().data, b"");
        // A zero probability (never written by the compressor) still
        // terminates.
        let _ = rubin(
            &[0, 0, 0, 0, 0, 0, 0, 0, 0xa5, 0x5a, 0xff],
            4,
            RubinModel::Dynamic,
        );
    }
}
