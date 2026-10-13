//! Checksums shared by container parsers.
//!
//! CRC-32 is the IEEE 802.3 / ISO-HDLC variant (reflected polynomial
//! `0xEDB88320`, initial value and final XOR `0xFFFFFFFF`) used by gzip,
//! ZIP, PNG, OAD and most firmware trailers. Adler-32 is defined by RFC 1950,
//! section 9. CRC-16/MODBUS (reflected polynomial `0xA001`, initial value
//! `0xFFFF`, no final XOR) is the Nintendo DS header checksum and the ext4
//! `gdt_csum` group descriptor checksum (Linux `lib/crc16.c`). CRC-64 is
//! the ECMA-182 / XZ variant (reflected polynomial `0xC96C5795D7870F42`,
//! initial value and final XOR all ones; XZ file format 1.2.1, section 6).
//! CRC-16/IBM-3740 (polynomial `0x1021`, most significant bit first,
//! initial value `0xFFFF`, no final XOR; also called CRC-16/CCITT-FALSE) is
//! the Lattice iCE40 bitstream CRC.
//! SHA-1 is FIPS 180-4, used only to check identifiers that formats store,
//! never as evidence of authenticity.
//! CRC-32C is the Castagnoli variant (reflected polynomial `0x82F63B78`)
//! used by iSCSI and the ext4 `metadata_csum` feature, which keeps the raw
//! register without the final XOR (Linux v6.11 `fs/ext4/ext4.h`,
//! `ext4_chksum`).
//! MD5 is RFC 1321, used only to check the ESP-IDF partition table MD5
//! record, which detects corruption and is never evidence of authenticity.

/// Reflected IEEE 802.3 CRC-32 polynomial.
const CRC32_POLYNOMIAL: u32 = 0xedb8_8320;

/// CRC-16/IBM-3740 polynomial, most significant bit first.
const CRC16_CCITT_POLYNOMIAL: u16 = 0x1021;

/// Reflected Castagnoli CRC-32C polynomial.
const CRC32C_POLYNOMIAL: u32 = 0x82f6_3b78;

/// Reflected ECMA-182 CRC-64 polynomial.
const CRC64_POLYNOMIAL: u64 = 0xc96c_5795_d787_0f42;

/// Largest number of bytes Adler-32 can sum before its 32-bit accumulators
/// must be reduced (RFC 1950 `NMAX`).
const ADLER_BLOCK: usize = 5552;

/// Adler-32 modulus (largest prime below 2^16).
const ADLER_MODULUS: u32 = 65521;

/// Byte-at-a-time lookup table for [`CRC32_POLYNOMIAL`].
const CRC32_TABLE: [u32; 256] = reflected_crc32_table(CRC32_POLYNOMIAL);

/// Byte-at-a-time lookup table for [`CRC32C_POLYNOMIAL`].
const CRC32C_TABLE: [u32; 256] = reflected_crc32_table(CRC32C_POLYNOMIAL);

const fn reflected_crc32_table(polynomial: u32) -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i: u32 = 0;
    while i < 256 {
        let mut crc = i;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ polynomial
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

/// Continue a Castagnoli CRC-32C over `data`. `crc` is the raw register:
/// the standard CRC-32C starts with `0xFFFFFFFF` and finishes with `!crc`;
/// ext4 seeds it with `0xFFFFFFFF` (or a checksum seed) and stores the
/// register as it is.
pub fn crc32c_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = CRC32C_TABLE[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
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
    crc16_modbus_update(0xffff, data)
}

/// Continue a CRC-16/MODBUS over `data`. The CRC has no final XOR, so
/// `crc` is both the register and the result: start with `0xFFFF` (the
/// ext4 `gdt_csum` seed `~0`) and chain calls over discontiguous ranges.
pub fn crc16_modbus_update(mut crc: u16, data: &[u8]) -> u16 {
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

/// MD5 initial state A, B, C, D (RFC 1321, section 3.3).
const MD5_INITIAL: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// MD5 sine table `T[1..64]`, `floor(2^32 * abs(sin(i)))` (RFC 1321,
/// section 3.4).
#[rustfmt::skip]
const MD5_SINE_TABLE: [u32; 64] = [
    0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee,
    0xf57c_0faf, 0x4787_c62a, 0xa830_4613, 0xfd46_9501,
    0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be,
    0x6b90_1122, 0xfd98_7193, 0xa679_438e, 0x49b4_0821,
    0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa,
    0xd62f_105d, 0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8,
    0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed,
    0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a,
    0xfffa_3942, 0x8771_f681, 0x6d9d_6122, 0xfde5_380c,
    0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70,
    0x289b_7ec6, 0xeaa1_27fa, 0xd4ef_3085, 0x0488_1d05,
    0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665,
    0xf429_2244, 0x432a_ff97, 0xab94_23a7, 0xfc93_a039,
    0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
    0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1,
    0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb, 0xeb86_d391,
];

/// MD5 left-rotation amounts for the four steps of rounds 1 to 4 (RFC
/// 1321, section 3.4).
const MD5_SHIFTS: [[u32; 4]; 4] = [
    [7, 12, 17, 22],
    [5, 9, 14, 20],
    [4, 11, 16, 23],
    [6, 10, 15, 21],
];

/// MD5 message block size in bytes.
const MD5_BLOCK: usize = 64;

/// Incremental MD5 (RFC 1321), for checksums that formats store to detect
/// corruption (the ESP-IDF partition table MD5 record). It is not collision
/// resistant and is never evidence of authenticity.
#[derive(Debug, Clone)]
pub struct Md5 {
    state: [u32; 4],
    block: [u8; MD5_BLOCK],
    filled: usize,
    length: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Self {
            state: MD5_INITIAL,
            block: [0; MD5_BLOCK],
            filled: 0,
            length: 0,
        }
    }
}

impl Md5 {
    /// A hasher with no input.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `data` to the message.
    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let take = (MD5_BLOCK - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled == MD5_BLOCK {
                let block = self.block;
                self.compress(&block);
                self.filled = 0;
            }
        }
    }

    /// The 16-byte digest: the message, a one bit, zero padding and the
    /// 64-bit little-endian message length in bits (RFC 1321, sections
    /// 3.1, 3.2 and 3.5).
    pub fn finish(mut self) -> [u8; 16] {
        let bits = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        while self.filled != MD5_BLOCK - 8 {
            self.update(&[0]);
        }
        self.update(&bits.to_le_bytes());
        let mut digest = [0u8; 16];
        for (out, word) in digest.chunks_exact_mut(4).zip(self.state) {
            out.copy_from_slice(&word.to_le_bytes());
        }
        digest
    }

    /// Process one 64-byte block (RFC 1321, section 3.4).
    fn compress(&mut self, block: &[u8; MD5_BLOCK]) {
        let mut words = [0u32; 16];
        for (word, bytes) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().expect("four bytes"));
        }
        // The working variables a, b, c and d of RFC 1321, section 3.4.
        let mut working = self.state;
        for (step, &sine) in MD5_SINE_TABLE.iter().enumerate() {
            let [first, second, third, fourth] = working;
            let round = step / 16;
            let (mix, word) = match round {
                0 => ((second & third) | (!second & fourth), step),
                1 => ((second & fourth) | (third & !fourth), (5 * step + 1) % 16),
                2 => (second ^ third ^ fourth, (3 * step + 5) % 16),
                _ => (third ^ (second | !fourth), (7 * step) % 16),
            };
            let rotated = first
                .wrapping_add(mix)
                .wrapping_add(sine)
                .wrapping_add(words[word])
                .rotate_left(MD5_SHIFTS[round][step % 4]);
            working = [fourth, second.wrapping_add(rotated), second, third];
        }
        for (state, value) in self.state.iter_mut().zip(working) {
            *state = state.wrapping_add(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

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

    /// The test suite of RFC 1321, appendix A.5, hashed whole and split
    /// across block boundaries.
    #[test]
    fn md5_matches_the_rfc_1321_test_suite() {
        let hex = |digest: [u8; 16]| {
            let mut text = String::new();
            for b in digest {
                write!(text, "{b:02x}").expect("writing to a String cannot fail");
            }
            text
        };
        let vectors: [(&[u8], &str); 7] = [
            (b"", "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a", "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (message, expected) in vectors {
            let mut whole = Md5::new();
            whole.update(message);
            assert_eq!(hex(whole.finish()), expected);
            for split in 0..message.len() {
                let mut parts = Md5::new();
                parts.update(&message[..split]);
                parts.update(&message[split..]);
                assert_eq!(hex(parts.finish()), expected, "split at {split}");
            }
        }
    }

    /// Check values from the CRC RevEng catalogue and RFC 1950 for the
    /// ASCII string "123456789".
    #[test]
    fn checksums_match_published_check_values() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(adler32(b"123456789"), 0x091e_01de);
        assert_eq!(crc16_modbus(b"123456789"), 0x4b37);
        assert_eq!(crc64(b"123456789"), 0x995d_c9bb_df19_39fa);
        assert_eq!(!crc32c_update(!0, b"123456789"), 0xe306_9283);
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
    fn crc16_and_crc32c_updates_compose_over_split_input() {
        let split = crc16_modbus_update(crc16_modbus_update(0xffff, b"1234"), b"56789");
        assert_eq!(split, crc16_modbus(b"123456789"));
        let split = crc32c_update(crc32c_update(!0, b"1234"), b"56789");
        assert_eq!(split, crc32c_update(!0, b"123456789"));
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
