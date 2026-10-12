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

#[cfg(test)]
mod tests {
    use super::*;

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
