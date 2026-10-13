//! Honda RWD calibration files, formats `0x5A` and `0x31`.
//!
//! Honda publishes no specification; the layout follows the community tool
//! rwd-xray at commit `83b990e3` (`format/x5a.py`, `format/x31.py`,
//! `format/base.py`, `tools/rwd-builder.py`). A file starts with a format
//! byte and CR LF and ends with a little-endian 32-bit sum of every byte
//! before it. The firmware is enciphered with a byte substitution chosen by
//! a 3-byte key; rwd-xray selects the decoder by searching for the part
//! number taken from the file name, which the file itself does not contain,
//! so the firmware stays opaque here. Files ship gzip-wrapped (`.rwd.gz`),
//! which the gzip container handles.

use super::*;

/// Format byte, then CR LF.
const FORMAT_5A: u8 = 0x5a;
const FORMAT_31: u8 = 0x31;
const SIGNATURE_TAIL: [u8; 2] = [0x0d, 0x0a];

/// Format `0x5A` has six length-prefixed headers.
const HEADER_COUNT: usize = 6;

/// Header 2 holds the varying byte of the CAN address `0x18DA__F1`;
/// header 3 previous firmware versions; header 5 the cipher key.
const HEADER_CAN_ADDRESS: usize = 2;
const HEADER_PREVIOUS_VERSIONS: usize = 3;
const HEADER_KEY: usize = 5;

/// Format `0x31` records: a 16-bit address in 16-byte units, 128 data bytes.
const RECORD_DATA: usize = 128;
const RECORD_SIZE: usize = 2 + RECORD_DATA;

/// Format `0x31` header type of the cipher key.
const KEY_HEADER_TYPE: u8 = b'&';

/// Is `data` a format `0x5A` or `0x31` RWD file whose trailing sum checks?
pub(super) fn is_rwd(data: &[u8]) -> bool {
    data.len() >= 7
        && matches!(data[0], FORMAT_5A | FORMAT_31)
        && data[1..3] == SIGNATURE_TAIL
        && trailer_matches(data)
}

/// The trailing little-endian sum of every preceding byte, modulo 2^32.
fn trailer_matches(data: &[u8]) -> bool {
    let Some(body_end) = data.len().checked_sub(4) else {
        return false;
    };
    let sum = data[..body_end]
        .iter()
        .fold(0u32, |sum, &b| sum.wrapping_add(u32::from(b)));
    data[body_end..] == sum.to_le_bytes()
}

/// The six format `0x5A` headers.
struct Headers5a<'a> {
    /// The values of each header, in file order.
    headers: Vec<Vec<&'a [u8]>>,
    /// File offset just past the last header, where the firmware start
    /// address and length follow.
    end: usize,
}

/// Format `0x5A` headers: each a value count, then that many values of a
/// length byte and the value bytes.
fn headers_5a(data: &[u8], end: usize) -> Result<Headers5a<'_>> {
    let mut pos = 3;
    let mut headers = Vec::with_capacity(HEADER_COUNT);
    for index in 0..HEADER_COUNT {
        let count = usize::from(*slice(&data[..end], pos, 1)?.first().expect("one byte"));
        pos += 1;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let len = usize::from(*slice(&data[..end], pos, 1)?.first().expect("one byte"));
            values.push(
                slice(&data[..end], pos + 1, len)
                    .map_err(|_| error(format!("Truncated RWD header {index} at 0x{pos:X}")))?,
            );
            pos += 1 + len;
        }
        headers.push(values);
    }
    Ok(Headers5a { headers, end: pos })
}

fn parse_5a<'a>(data: &'a [u8], c: &mut Container<'a>, end: usize) -> Result<()> {
    let Headers5a { headers, end: pos } = headers_5a(data, end)?;
    let start = be_u32(&data[..end], pos)?;
    let length = be_u32(&data[..end], pos + 4)? as usize;
    let firmware_at = pos + 8;
    if firmware_at.checked_add(length) != Some(end) {
        return Err(error(format!(
            "Invalid RWD firmware length {length} B: {} B remain before the checksum",
            end.saturating_sub(firmware_at)
        )));
    }
    if let [address] = headers[HEADER_CAN_ADDRESS][..] {
        if let [byte] = address[..] {
            c.notes.push(format!("CAN address 0x18DA{byte:02X}F1"));
        }
    }
    let versions: Vec<String> = headers[HEADER_PREVIOUS_VERSIONS]
        .iter()
        .map(|v| {
            String::from_utf8_lossy(v)
                .trim_end_matches('\0')
                .to_string()
        })
        .collect();
    if !versions.is_empty() {
        c.notes
            .push(format!("Supersedes firmware {}", versions.join(", ")));
    }
    if let [key] = headers[HEADER_KEY][..] {
        c.push_metadata("rwd_cipher_key", "Cipher key", hex_text(key));
    }
    c.notes.push(format!(
        "Firmware block of {length} B for address 0x{start:08X}"
    ));
    c.children.push(Child::opaque(
        format!("Firmware at 0x{start:08X}"),
        firmware_at,
        &data[firmware_at..end],
    ));
    Ok(())
}

/// Uppercase hexadecimal text of `bytes`.
fn hex_text(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut text, b| {
        let _ = write!(text, "{b:02X}");
        text
    })
}

/// One format `0x31` header.
struct Header31<'a> {
    /// The type character that opens and closes the header.
    kind: u8,
    /// The values, without their CR LF terminators.
    values: Vec<&'a [u8]>,
}

/// The six format `0x31` headers.
struct Headers31<'a> {
    /// The headers in file order.
    headers: Vec<Header31<'a>>,
    /// File offset just past the last header: the first record.
    end: usize,
}

/// Format `0x31` headers: each opens with `T CR LF`, holds CR LF-terminated
/// values, and closes with the same `T CR LF`.
fn headers_31(data: &[u8], end: usize) -> Result<Headers31<'_>> {
    let mut pos = 3;
    let mut headers = Vec::with_capacity(HEADER_COUNT);
    for index in 0..HEADER_COUNT {
        let open = slice(&data[..end], pos, 3)?;
        if open[1..] != SIGNATURE_TAIL {
            return Err(error(format!(
                "Invalid RWD header {index} delimiter at 0x{pos:X}"
            )));
        }
        let kind = open[0];
        pos += 3;
        let mut values = Vec::new();
        loop {
            let rest = &data[pos..end];
            if rest.len() >= 3 && rest[0] == kind && rest[1..3] == SIGNATURE_TAIL {
                pos += 3;
                break;
            }
            let len = memchr::memmem::find(rest, &SIGNATURE_TAIL)
                .ok_or_else(|| error(format!("Truncated RWD header {index} at 0x{pos:X}")))?;
            values.push(&rest[..len]);
            pos += len + 2;
        }
        headers.push(Header31 { kind, values });
    }
    Ok(Headers31 { headers, end: pos })
}

fn parse_31<'a>(data: &'a [u8], c: &mut Container<'a>, end: usize) -> Result<()> {
    let Headers31 {
        headers,
        end: firmware_at,
    } = headers_31(data, end)?;
    if let Some(header) = headers.iter().find(|h| h.kind == KEY_HEADER_TYPE) {
        if let [key] = header.values[..] {
            c.push_metadata(
                "rwd_cipher_key",
                "Cipher key",
                String::from_utf8_lossy(key).to_string(),
            );
        }
    }
    let firmware = &data[firmware_at..end];
    if firmware.len() % RECORD_SIZE != 0 {
        return Err(error(format!(
            "Invalid RWD record area: {} B is not a multiple of {RECORD_SIZE} B",
            firmware.len()
        )));
    }
    // Consecutive records extend a block; a jump starts a new one.
    let mut block: Option<(u64, usize, usize)> = None;
    let mut previous: Option<u64> = None;
    let mut blocks = Vec::new();
    for (i, record) in firmware.chunks_exact(RECORD_SIZE).enumerate() {
        let address = (u64::from(record[0]) << 12) | (u64::from(record[1]) << 4);
        if previous.is_some_and(|p| address < p) {
            return Err(error(format!("Invalid RWD record order at record {i}")));
        }
        let offset = firmware_at + i * RECORD_SIZE;
        block = match block {
            Some((start, first, count)) if start + (count * RECORD_DATA) as u64 == address => {
                Some((start, first, count + 1))
            }
            Some(done) => {
                blocks.push(done);
                Some((address, offset, 1))
            }
            None => Some((address, offset, 1)),
        };
        previous = Some(address);
    }
    blocks.extend(block);
    for (start, offset, count) in blocks.into_iter().take(MAX_COMPONENTS) {
        c.children.push(Child::opaque(
            format!("Firmware at 0x{start:08X} ({count} records)"),
            offset,
            &data[offset..offset + count * RECORD_SIZE],
        ));
    }
    Ok(())
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if data.len() < 7 || !matches!(data[0], FORMAT_5A | FORMAT_31) || data[1..3] != SIGNATURE_TAIL {
        return Err(error("Missing RWD signature"));
    }
    if !trailer_matches(data) {
        return Err(error("Invalid RWD trailing checksum"));
    }
    let end = data.len() - 4;
    let mut c = Container::new(
        FileFormat::HondaRwd,
        format!("RWD format 0x{:02X}", data[0]),
        "rwd",
    );
    c.consumed = data.len();
    c.notes.push(format!(
        "Honda RWD calibration file, format 0x{:02X}; trailing checksum verified",
        data[0]
    ));
    if data[0] == FORMAT_5A {
        parse_5a(data, &mut c, end)?;
    } else {
        parse_31(data, &mut c, end)?;
    }
    c.notes.push(
        "Firmware is enciphered with a key-selected byte substitution; the decoder cannot be chosen from the file alone, so it is not analyzed"
            .into(),
    );
    Ok(c)
}
