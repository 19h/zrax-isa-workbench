//! Checksums shared by container parsers.
//!
//! CRC-32 is the IEEE 802.3 / ISO-HDLC variant (reflected polynomial
//! `0xEDB88320`, initial value and final XOR `0xFFFFFFFF`) used by gzip,
//! ZIP, PNG, OAD and most firmware trailers. Adler-32 is defined by RFC 1950,
//! section 9. CRC-16/MODBUS (reflected polynomial `0xA001`, initial value
//! `0xFFFF`, no final XOR) is the Nintendo DS header checksum. CRC-64 is
//! the ECMA-182 / XZ variant (reflected polynomial `0xC96C5795D7870F42`,
//! initial value and final XOR all ones; XZ file format 1.2.1, section 6).
//! CRC-16/IBM-3740 (polynomial `0x1021`, most significant bit first,
//! initial value `0xFFFF`, no final XOR; also called CRC-16/CCITT-FALSE) is
//! the Lattice iCE40 bitstream CRC.
//! SHA-1 is FIPS 180-4, used only to check identifiers that formats store,
//! never as evidence of authenticity.

/// Reflected IEEE 802.3 CRC-32 polynomial.
const CRC32_POLYNOMIAL: u32 = 0xedb8_8320;

/// CRC-16/IBM-3740 polynomial, most significant bit first.
const CRC16_CCITT_POLYNOMIAL: u16 = 0x1021;

/// Reflected ECMA-182 CRC-64 polynomial.
const CRC64_POLYNOMIAL: u64 = 0xc96c_5795_d787_0f42;

/// Largest number of bytes Adler-32 can sum before its 32-bit accumulators
/// must be reduced (RFC 1950 `NMAX`).
const ADLER_BLOCK: usize = 5552;

/// Adler-32 modulus (largest prime below 2^16).
const ADLER_MODULUS: u32 = 65521;

/// Byte-at-a-time lookup table for [`CRC32_POLYNOMIAL`].
const CRC32_TABLE: [u32; 256] = crc32_table();

const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i: u32 = 0;
    while i < 256 {
        let mut crc = i;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ CRC32_POLYNOMIAL
            };
            bit += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
}

/// Byte-at-a-time lookup table for [`CRC64_POLYNOMIAL`].
const CRC64_TABLE: [u64; 256] = crc64_table();

const fn crc64_table() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut i: u32 = 0;
    while i < 256 {
        let mut crc = i as u64;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ CRC64_POLYNOMIAL
            };
            bit += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
}

/// Continue an IEEE CRC-32 over `data`. `crc` is the raw register (start
/// with `0xFFFFFFFF`, finish with `!crc`), so callers can checksum
/// discontiguous ranges or use the un-inverted DFU convention.
pub fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = CRC32_TABLE[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

/// IEEE CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    !crc32_update(!0, data)
}

/// ECMA-182 CRC-64 of `data`, as used by XZ block checks.
pub fn crc64(data: &[u8]) -> u64 {
    let mut crc = !0u64;
    for &b in data {
        crc = CRC64_TABLE[((crc ^ u64::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Adler-32 of `data` (RFC 1950).
pub fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for block in data.chunks(ADLER_BLOCK) {
        for &byte in block {
            a += u32::from(byte);
            b += a;
        }
        a %= ADLER_MODULUS;
        b %= ADLER_MODULUS;
    }
    (b << 16) | a
}

/// CRC-16/MODBUS of `data`.
pub fn crc16_modbus(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xffff;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xa001
            };
        }
    }
    crc
}

/// Continue a CRC-16/IBM-3740 over `data`. `crc` is the register (start
/// with `0xFFFF`); appending the result big-endian brings it to zero.
pub fn crc16_ibm3740_update(mut crc: u16, data: &[u8]) -> u16 {
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ CRC16_CCITT_POLYNOMIAL
            };
        }
    }
    crc
}

/// CRC-16/IBM-3740 of `data`.
pub fn crc16_ibm3740(data: &[u8]) -> u16 {
    crc16_ibm3740_update(0xffff, data)
}

/// SHA-1 initial hash value (FIPS 180-4, section 5.3.1).
const SHA1_INITIAL: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// SHA-1 round constants for rounds 0-19, 20-39, 40-59 and 60-79 (FIPS
/// 180-4, section 4.2.1).
const SHA1_ROUND_CONSTANTS: [u32; 4] = [0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xca62_c1d6];

/// SHA-1 message block size in bytes.
const SHA1_BLOCK: usize = 64;

/// Incremental SHA-1 (FIPS 180-4), for digests that formats store as
/// identifiers (the Android boot image `id`). It is not collision
/// resistant and is never evidence of authenticity.
#[derive(Debug, Clone)]
pub struct Sha1 {
    state: [u32; 5],
    block: [u8; SHA1_BLOCK],
    filled: usize,
    length: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self {
            state: SHA1_INITIAL,
            block: [0; SHA1_BLOCK],
            filled: 0,
            length: 0,
        }
    }
}

impl Sha1 {
    /// A hasher with no input.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `data` to the message.
    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let take = (SHA1_BLOCK - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled == SHA1_BLOCK {
                let block = self.block;
                self.compress(&block);
                self.filled = 0;
            }
        }
    }

    /// The 20-byte digest: the message, a one bit, zero padding and the
    /// 64-bit big-endian message length in bits.
    pub fn finish(mut self) -> [u8; 20] {
        let bits = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        while self.filled != SHA1_BLOCK - 8 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut digest = [0u8; 20];
        for (out, word) in digest.chunks_exact_mut(4).zip(self.state) {
            out.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// Process one 64-byte block (FIPS 180-4, section 6.1.2).
    fn compress(&mut self, block: &[u8; SHA1_BLOCK]) {
        let mut schedule = [0u32; 80];
        for (word, bytes) in schedule.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().expect("four bytes"));
        }
        for t in 16..80 {
            schedule[t] = (schedule[t - 3] ^ schedule[t - 8] ^ schedule[t - 14] ^ schedule[t - 16])
                .rotate_left(1);
        }
        // The working variables a to e of FIPS 180-4, section 6.1.2.
        let mut working = self.state;
        for (t, &word) in schedule.iter().enumerate() {
            let [first, second, third, fourth, fifth] = working;
            let (mix, constant) = match t / 20 {
                0 => (
                    (second & third) | (!second & fourth),
                    SHA1_ROUND_CONSTANTS[0],
                ),
                1 => (second ^ third ^ fourth, SHA1_ROUND_CONSTANTS[1]),
                2 => (
                    (second & third) | (second & fourth) | (third & fourth),
                    SHA1_ROUND_CONSTANTS[2],
                ),
                _ => (second ^ third ^ fourth, SHA1_ROUND_CONSTANTS[3]),
            };
            let temp = first
                .rotate_left(5)
                .wrapping_add(mix)
                .wrapping_add(fifth)
                .wrapping_add(constant)
                .wrapping_add(word);
            working = [temp, first, second.rotate_left(30), third, fourth];
        }
        for (state, value) in self.state.iter_mut().zip(working) {
            *state = state.wrapping_add(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 example messages (NIST CSRC "Examples with intermediate
    /// values", SHA-1) and the one-million-'a' test of RFC 3174.
    #[test]
    fn sha1_matches_published_test_vectors() {
        let digest = |parts: &[&[u8]]| {
            let mut sha = Sha1::new();
            for part in parts {
                sha.update(part);
            }
            sha.finish()
        };
        assert_eq!(
            digest(&[b"abc"]),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
        assert_eq!(
            digest(&[
                b"abcdbcdecdefdefgefghfghighij",
                b"hijkijkljklmklmnlmnomnopnopq"
            ]),
            [
                0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51,
                0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1
            ]
        );
        assert_eq!(
            digest(&[&vec![b'a'; 1_000_000]]),
            [
                0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad,
                0x27, 0x31, 0x65, 0x34, 0x01, 0x6f
            ]
        );
        assert_eq!(
            digest(&[]),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    /// Check values from the CRC RevEng catalogue and RFC 1950 for the
    /// ASCII string "123456789".
    #[test]
    fn checksums_match_published_check_values() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(adler32(b"123456789"), 0x091e_01de);
        assert_eq!(crc16_modbus(b"123456789"), 0x4b37);
        assert_eq!(crc64(b"123456789"), 0x995d_c9bb_df19_39fa);
        assert_eq!(crc32(b""), 0);
        assert_eq!(adler32(b""), 1);
    }

    #[test]
    fn crc32_update_composes_over_split_input() {
        let whole = crc32(b"hello world");
        let split = !crc32_update(crc32_update(!0, b"hello "), b"world");
        assert_eq!(whole, split);
    }

    #[test]
    fn adler32_reduces_long_runs_without_overflow() {
        let data = vec![0xffu8; 1 << 20];
        let mut a: u64 = 1;
        let mut b: u64 = 0;
        for &byte in &data {
            a = (a + u64::from(byte)) % u64::from(ADLER_MODULUS);
            b = (b + a) % u64::from(ADLER_MODULUS);
        }
        assert_eq!(u64::from(adler32(&data)), (b << 16) | a);
    }

    /// CRC RevEng catalogue check value for CRC-16/IBM-3740, and the zero
    /// residue after the big-endian CRC that the iCE40 CRC check relies on.
    #[test]
    fn crc16_ibm3740_matches_its_check_value_and_residue() {
        assert_eq!(crc16_ibm3740(b"123456789"), 0x29b1);
        let mut message = b"123456789".to_vec();
        message.extend_from_slice(&0x29b1u16.to_be_bytes());
        assert_eq!(crc16_ibm3740(&message), 0);
    }
}
