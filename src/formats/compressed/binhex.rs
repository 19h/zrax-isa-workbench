//! `BinHex` 4.0 (`.hqx`): a Macintosh file encoded as 7-bit text (RFC 1741,
//! "MIME Content Type for `BinHex` Encoded Files", Appendix "`BinHex` 4.0
//! Definition", Peter N. Lewis).
//!
//! The line `(This file must be converted with BinHex 4.0)` is followed by
//! a colon, the data as 6-bit values in a 64-character alphabet (line breaks
//! and other white space ignored) and a closing colon. The decoded bytes are
//! run-length encoded: `0x90` and a count repeat the previous byte `count`
//! times in all, a count of 0 stands for a literal `0x90`. The expanded
//! stream holds the header (name length, name, version 0, file type (4),
//! creator (4), Finder flags (2), data fork length (4), resource fork length
//! (4), all big-endian, and a CRC (2)), then the data fork and its CRC, and
//! the resource fork and its CRC. Each CRC is CRC-16/XMODEM (polynomial
//! 0x1021, initial value 0) over the preceding part.
//!
//! The data fork is the decoded payload; the resource fork is not
//! classified.

use super::{error, Decoded};
use crate::error::Result;

/// The line a `BinHex` 4.0 file starts with (after optional white space).
pub(super) const BANNER: &[u8] = b"(This file must be converted with BinHex 4.0)";

/// The 64 characters of the encoding, in value order.
const ALPHABET: &[u8; 64] = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";

/// Marker of the run-length encoding.
const RUN_MARKER: u8 = 0x90;

/// Delimiter around the encoded data.
const COLON: u8 = b':';

/// Header bytes after the name: version (1), type (4), creator (4), flags
/// (2), data and resource fork lengths (4 each).
const HEADER_AFTER_NAME: usize = 1 + 4 + 4 + 2 + 4 + 4;
const CRC_SIZE: usize = 2;

/// Whether `data` starts with the `BinHex` 4.0 banner, after optional white
/// space.
pub(super) fn has_banner(data: &[u8]) -> bool {
    data[leading_whitespace(data)..].starts_with(BANNER)
}

fn leading_whitespace(data: &[u8]) -> usize {
    data.iter().take_while(|b| b.is_ascii_whitespace()).count()
}

/// Value of one character of the alphabet.
fn value(character: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|&a| a == character)
        .and_then(|v| u8::try_from(v).ok())
}

/// CRC-16/XMODEM of `bytes`.
fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in bytes {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// The 8-bit bytes of the encoded text between the colons, and the offset
/// after the closing colon.
fn six_bit_decode(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    let banner = leading_whitespace(data);
    let after_banner = banner + BANNER.len();
    let open = data[after_banner..]
        .iter()
        .position(|&b| b == COLON)
        .map(|at| after_banner + at + 1)
        .ok_or_else(|| error("Missing BinHex data after the banner"))?;
    let mut out = Vec::with_capacity((data.len() - open) * 3 / 4);
    let mut bits = 0u32;
    let mut count = 0u32;
    for (at, &character) in data.iter().enumerate().skip(open) {
        if character == COLON {
            return Ok((out, at + 1));
        }
        if character.is_ascii_whitespace() {
            continue;
        }
        let v = value(character).ok_or_else(|| {
            error(format!(
                "Invalid BinHex character 0x{character:02X} at 0x{at:X}"
            ))
        })?;
        bits = ((bits << 6) | u32::from(v)) & 0xFFFF;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count).to_be_bytes()[3]);
        }
    }
    Err(error("Truncated BinHex data: no closing colon"))
}

/// Expand the run-length encoding, at most `limit` bytes.
fn expand_runs(packed: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(packed.len().min(limit));
    let mut previous = None;
    let mut bytes = packed.iter().copied();
    while let Some(byte) = bytes.next() {
        if byte == RUN_MARKER {
            let count = bytes
                .next()
                .ok_or_else(|| error("Truncated BinHex run at the end of the data"))?;
            if count == 0 {
                out.push(RUN_MARKER);
                previous = Some(RUN_MARKER);
            } else {
                let repeated =
                    previous.ok_or_else(|| error("Invalid BinHex run before any byte"))?;
                out.extend(std::iter::repeat(repeated).take(usize::from(count) - 1));
            }
        } else {
            out.push(byte);
            previous = Some(byte);
        }
        if out.len() > limit {
            return Err(error(format!("BinHex data expands beyond {limit} B")));
        }
    }
    Ok(out)
}

fn be_u32(bytes: &[u8], at: usize) -> Result<u32> {
    let field: [u8; 4] = bytes
        .get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| error(format!("Truncated BinHex header at 0x{at:X}")))?;
    Ok(u32::from_be_bytes(field))
}

/// `length` bytes at `at` followed by a matching CRC, or an error naming `what`.
fn checked<'a>(stream: &'a [u8], at: usize, length: usize, what: &str) -> Result<&'a [u8]> {
    let end = at
        .checked_add(length)
        .filter(|end| end + CRC_SIZE <= stream.len())
        .ok_or_else(|| error(format!("Truncated BinHex {what} at 0x{at:X} + {length} B")))?;
    let stored = u16::from_be_bytes([stream[end], stream[end + 1]]);
    let part = &stream[at..end];
    if crc16(part) != stored {
        return Err(error(format!("Invalid BinHex {what} CRC 0x{stored:04X}")));
    }
    Ok(part)
}

/// The data fork of a `BinHex` 4.0 file, with every CRC verified.
pub(super) fn decode(data: &[u8], limit: usize) -> Result<Decoded> {
    if !has_banner(data) {
        return Err(error("Missing BinHex 4.0 banner"));
    }
    let (packed, end) = six_bit_decode(data)?;
    let stream = expand_runs(&packed, limit.saturating_add(packed.len()))?;
    let name_length = usize::from(
        *stream
            .first()
            .ok_or_else(|| error("Truncated BinHex header at 0x0"))?,
    );
    let header_length = 1 + name_length + HEADER_AFTER_NAME;
    let header = checked(&stream, 0, header_length, "header")?;
    let length = |at: usize| -> Result<usize> {
        usize::try_from(be_u32(header, at)?).map_err(|_| error("Invalid BinHex fork length"))
    };
    let data_length = length(1 + name_length + 11)?;
    let resource_length = length(1 + name_length + 15)?;
    let data_at = header_length + CRC_SIZE;
    let fork = checked(&stream, data_at, data_length, "data fork")?;
    let resource_at = data_at + data_length + CRC_SIZE;
    checked(&stream, resource_at, resource_length, "resource fork")?;
    if fork.len() > limit {
        return Err(error(format!(
            "BinHex data fork of {} B beyond {limit} B",
            fork.len()
        )));
    }
    // White space after the closing colon is part of the text file.
    let trailing = data[end..]
        .iter()
        .take_while(|b| b.is_ascii_whitespace())
        .count();
    Ok(Decoded {
        data: fork.to_vec(),
        consumed: Some(end + trailing),
        check: Some("BinHex CRC-16 of header and forks"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode `stream` (already run-length encoded) as `BinHex` text.
    fn encode(stream: &[u8]) -> Vec<u8> {
        let mut text = BANNER.to_vec();
        text.extend_from_slice(b"\r\r:");
        let mut bits = 0u32;
        let mut count = 0u32;
        for &byte in stream {
            bits = (bits << 8) | u32::from(byte);
            count += 8;
            while count >= 6 {
                count -= 6;
                text.push(ALPHABET[((bits >> count) & 0x3F) as usize]);
            }
        }
        if count > 0 {
            text.push(ALPHABET[((bits << (6 - count)) & 0x3F) as usize]);
        }
        text.extend_from_slice(b":\r");
        text
    }

    /// The expanded stream of a file named `name` with the given forks.
    fn stream(name: &[u8], data_fork: &[u8], resource_fork: &[u8]) -> Vec<u8> {
        let mut header = vec![u8::try_from(name.len()).expect("short name")];
        header.extend_from_slice(name);
        header.push(0); // version
        header.extend_from_slice(b"BINAzrax"); // type, creator
        header.extend_from_slice(&[0, 0]); // Finder flags
        header.extend_from_slice(&u32::try_from(data_fork.len()).expect("small").to_be_bytes());
        header.extend_from_slice(
            &u32::try_from(resource_fork.len())
                .expect("small")
                .to_be_bytes(),
        );
        let mut out = header.clone();
        out.extend_from_slice(&crc16(&header).to_be_bytes());
        out.extend_from_slice(data_fork);
        out.extend_from_slice(&crc16(data_fork).to_be_bytes());
        out.extend_from_slice(resource_fork);
        out.extend_from_slice(&crc16(resource_fork).to_be_bytes());
        out
    }

    /// Run-length encode `stream`, escaping 0x90 and folding runs of four
    /// or more.
    fn pack(stream: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < stream.len() {
            let byte = stream[i];
            let run = stream[i..]
                .iter()
                .take_while(|&&b| b == byte)
                .count()
                .min(255);
            if byte == RUN_MARKER {
                out.extend_from_slice(&[RUN_MARKER, 0]);
                i += 1;
            } else if run >= 4 {
                out.extend_from_slice(&[byte, RUN_MARKER, u8::try_from(run).expect("at most 255")]);
                i += run;
            } else {
                out.push(byte);
                i += 1;
            }
        }
        out
    }

    #[test]
    fn crc16_is_xmodem() {
        assert_eq!(crc16(b"123456789"), 0x31C3);
    }

    #[test]
    fn data_fork_is_decoded_with_runs_escapes_and_crcs() {
        let data_fork: Vec<u8> = [&[0x90, 1, 2][..], &[7; 300], b"tail"].concat();
        let text = encode(&pack(&stream(b"fw.bin", &data_fork, b"rsrc")));
        let decoded = decode(&text, 1 << 20).expect("valid BinHex");
        assert_eq!(decoded.data, data_fork);
        assert_eq!(decoded.consumed, Some(text.len()));
    }

    #[test]
    fn corrupt_or_truncated_text_is_rejected() {
        let text = encode(&pack(&stream(b"fw.bin", b"payload bytes", b"")));
        for end in 0..text.len() - 1 {
            assert!(decode(&text[..end], 1 << 20).is_err(), "truncated at {end}");
        }
        let close = text
            .iter()
            .rposition(|&b| b == COLON)
            .expect("closing colon");
        let mut bad = text.clone();
        bad[close - 3] = if bad[close - 3] == b'!' { b'"' } else { b'!' };
        assert!(
            decode(&bad, 1 << 20).is_err(),
            "a changed character breaks a CRC"
        );
        let mut invalid = text;
        invalid[close - 2] = b'7';
        assert!(
            decode(&invalid, 1 << 20).is_err(),
            "7 is not in the alphabet"
        );
    }
}
