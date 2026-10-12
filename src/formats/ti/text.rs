//! Strict TI hex-utility output decoders. Hex digits represent bytes in
//! printed order; target ROM widths and byte lanes are not encoded.
use super::*;

fn hex(s: &[u8]) -> Result<u64> {
    if s.is_empty() || s.len() > 16 {
        return Err(err("Invalid hexadecimal field width"));
    }
    s.iter().try_fold(0u64, |v, b| {
        (char::from(*b))
            .to_digit(16)
            .map(|n| (v << 4) | u64::from(n))
            .ok_or_else(|| err("Invalid hexadecimal digit"))
    })
}
fn decode(s: &[u8]) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(err("Odd number of hex digits"));
    }
    s.chunks_exact(2).map(|p| Ok(hex(p)? as u8)).collect()
}
pub(super) fn detect(data: &[u8]) -> Option<Variant> {
    let d = data.trim_ascii();
    let kind = if d.starts_with(&[2]) {
        Variant::AsciiHex
    } else if d.starts_with(b"K") {
        Variant::Tagged
    } else if d.starts_with(b"%") {
        Variant::Tektronix
    } else if d.starts_with(b"1651 ") || d.starts_with(b"1651\t") {
        return ccs(d).ok().map(|_| Variant::CcsData);
    } else {
        return None;
    };
    // Text signatures are weak; validate every record and checksum.
    parse(d, kind).ok().map(|_| kind)
}
pub(super) fn parse(data: &[u8], kind: Variant) -> Result<Container<'_>> {
    match kind {
        Variant::AsciiHex => ascii(data),
        Variant::Tagged => tagged(data),
        Variant::Tektronix => tek(data),
        _ => Err(err("Invalid text kind")),
    }
}
fn push<'a>(
    c: &mut Container<'a>,
    address: u64,
    offset: usize,
    v: Vec<u8>,
    total: &mut usize,
) -> Result<()> {
    *total = total
        .checked_add(v.len())
        .filter(|n| *n <= MAX_PAYLOAD)
        .ok_or_else(|| err("Decoded text payload exceeds 64 MiB"))?;
    if !v.is_empty() {
        c.section(address, offset, Cow::Owned(v))?;
    }
    Ok(())
}

/// SPRU296 section 5.1.2. Sample bit width and memory byte order are not
/// represented by this header. Validate the text and retain metadata only.
pub(super) fn ccs(data: &[u8]) -> Result<Container<'_>> {
    let s = std::str::from_utf8(data).map_err(|_| err("CCS data is not text"))?;
    let mut lines = s.lines().filter(|line| !line.trim().is_empty());
    let header: Vec<_> = lines
        .next()
        .ok_or_else(|| err("Missing CCS data header"))?
        .split_whitespace()
        .collect();
    if header.len() != 5 || header[0] != "1651" {
        return Err(err("Invalid CCS GO DSP header"));
    }
    let number = |s: &str| {
        hex(s
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .trim_end_matches(['h', 'H'])
            .as_bytes())
    };
    let kind = number(header[1])?;
    let address = number(header[2])?;
    let page = number(header[3])?;
    let length = number(header[4])?;
    if !(1..=4).contains(&kind) {
        return Err(err("Unsupported CCS sample format"));
    }
    let mut actual = 0u64;
    for line in lines {
        let sample = line.trim();
        match kind {
            1 => {
                number(sample)?;
            }
            2 | 3 => {
                sample
                    .parse::<i64>()
                    .map_err(|_| err("Invalid CCS integer sample"))?;
            }
            4 => {
                let n = sample
                    .parse::<f64>()
                    .map_err(|_| err("Invalid CCS float sample"))?;
                if !n.is_finite() {
                    return Err(err("Nonfinite CCS float sample"));
                }
            }
            _ => unreachable!(),
        }
        actual += 1;
    }
    if actual == 0 || (length != 0 && length != actual) {
        return Err(err("CCS sample count does not match declared length"));
    }
    let mut c = Container::new(Variant::CcsData);
    c.opaque = true;
    c.consumed = data.len();
    c.notes.push(format!("Sample format {kind}; default target address 0x{address:X}; page 0x{page:X}; declared {length}, actual {actual} samples"));
    c.notes.push("Target word width and byte order are unknown; sample data is not treated as machine code; zero header length permits debugger override".into());
    Ok(c)
}
fn ascii(data: &[u8]) -> Result<Container<'_>> {
    let d = data.trim_ascii();
    if d.first() != Some(&2) {
        return Err(err("Missing ASCII-Hex STX"));
    }
    let end = d
        .iter()
        .position(|b| *b == 3)
        .ok_or_else(|| err("Missing ASCII-Hex ETX"))?;
    if !d[end + 1..].iter().all(u8::is_ascii_whitespace) {
        return Err(err("Data after ASCII-Hex ETX"));
    }
    let mut c = Container::new(Variant::AsciiHex);
    let mut pos = 1;
    let mut address = 0;
    let mut start = pos;
    let mut out = Vec::new();
    let mut total = 0;
    while pos < end {
        if d[pos].is_ascii_whitespace() {
            pos += 1;
            continue;
        }
        if d[pos] == b'$' {
            push(&mut c, address, start, std::mem::take(&mut out), &mut total)?;
            if bytes(d, pos, 2)? != b"$A" {
                return Err(err("Unknown ASCII-Hex control record"));
            }
            pos += 2;
            let begin = pos;
            while pos < end && d[pos].is_ascii_hexdigit() {
                pos += 1;
            }
            if !(4..=8).contains(&(pos - begin)) || d.get(pos) != Some(&b',') {
                return Err(err("Invalid ASCII-Hex address record"));
            }
            address = hex(&d[begin..pos])?;
            pos += 1;
            start = pos;
        } else {
            let begin = pos;
            while pos < end && d[pos].is_ascii_hexdigit() {
                pos += 1;
            }
            if pos == begin || (pos - begin) % 2 != 0 || pos - begin > 16 {
                return Err(err("Invalid ASCII-Hex data token"));
            }
            if total + out.len() + (pos - begin) / 2 > MAX_PAYLOAD {
                return Err(err("ASCII-Hex exceeds 64 MiB"));
            }
            out.extend(decode(&d[begin..pos])?);
        }
    }
    push(&mut c, address, start, out, &mut total)?;
    if c.sections.is_empty() {
        return Err(err("ASCII-Hex has no data"));
    }
    c.notes.push("Bytes decoded in printed order; ROM word width and byte-lane files are not identified by this encoding".into());
    c.consumed = data.len();
    Ok(c)
}
fn tagged(data: &[u8]) -> Result<Container<'_>> {
    let mut c = Container::new(Variant::Tagged);
    let mut first = true;
    let mut eof = false;
    let mut address = 0u64;
    let mut total = 0;
    let mut offset = 0;
    for line in data.split_inclusive(|b| *b == b'\n') {
        let record = line.trim_ascii();
        let line_offset = offset;
        offset += line.len();
        if record.is_empty() {
            continue;
        }
        if eof {
            return Err(err("Record after TI-tagged EOF"));
        }
        if first {
            if record.first() != Some(&b'K') || record.last() != Some(&b'F') || record.len() < 3 {
                return Err(err("Missing TI-tagged program identifier"));
            }
            c.notes.push(format!(
                "Program identifier: {}",
                String::from_utf8_lossy(&record[1..record.len() - 1])
            ));
            first = false;
            continue;
        }
        if record == b":" {
            eof = true;
            continue;
        }
        let mut pos = 0;
        let mut out = Vec::new();
        let mut start = address;
        let mut checked = false;
        while pos < record.len() {
            let tag = record[pos];
            let at = pos;
            pos += 1;
            match tag {
                b'9' => {
                    push(
                        &mut c,
                        start,
                        line_offset,
                        std::mem::take(&mut out),
                        &mut total,
                    )?;
                    address = hex(bytes(record, pos, 4)?)?;
                    start = address;
                    pos += 4;
                }
                b'B' => {
                    let v = decode(bytes(record, pos, 4)?)?;
                    out.extend(v);
                    address = address
                        .checked_add(1)
                        .ok_or_else(|| err("Tagged address overflow"))?;
                    pos += 4;
                }
                b'*' => {
                    out.extend(decode(bytes(record, pos, 2)?)?);
                    pos += 2;
                    address = address
                        .checked_add(1)
                        .ok_or_else(|| err("Tagged address overflow"))?;
                }
                b'7' | b'8' => {
                    let value = hex(bytes(record, pos, 4)?)? as u16;
                    if checked || record.get(pos + 4) != Some(&b'F') || pos + 5 != record.len() {
                        return Err(err("Checksum must be the final TI-tagged field"));
                    }
                    if tag == b'7' {
                        let sum = record[..=at]
                            .iter()
                            .fold(0u16, |v, b| v.wrapping_add(u16::from(*b)));
                        if sum.wrapping_add(value) != 0 {
                            return Err(err("TI-tagged checksum mismatch"));
                        }
                    }
                    pos += 4;
                    checked = true;
                }
                b'F' => {
                    if pos != record.len() {
                        return Err(err("Unexpected bytes after TI-tagged end-of-record"));
                    }
                    if !checked {
                        return Err(err("TI-tagged data record lacks checksum tag"));
                    }
                }
                _ => return Err(err(format!("Unknown TI-tagged tag {}", char::from(tag)))),
            }
            if total + out.len() > MAX_PAYLOAD {
                return Err(err("TI-tagged exceeds 64 MiB"));
            }
        }
        if record.last() != Some(&b'F') {
            return Err(err("Missing TI-tagged end-of-record"));
        }
        push(&mut c, start, line_offset, out, &mut total)?;
    }
    if first || !eof || c.sections.is_empty() {
        return Err(err("Incomplete TI-tagged file"));
    }
    c.consumed = data.len();
    c.notes.push("Tagged addresses are 16-bit target locations; data words are decoded most significant byte first; target ISA/ROM width is not encoded".into());
    Ok(c)
}
fn tek(data: &[u8]) -> Result<Container<'_>> {
    let mut c = Container::new(Variant::Tektronix);
    let mut total = 0;
    let mut offset = 0;
    let mut eof = false;
    for line in data.split_inclusive(|b| *b == b'\n') {
        let s = line.trim_ascii();
        let at = offset;
        offset += line.len();
        if s.is_empty() {
            continue;
        }
        if eof || s.first() != Some(&b'%') {
            return Err(err("Invalid Extended Tektronix record"));
        }
        if hex(bytes(s, 1, 2)?)? as usize != s.len() - 1 {
            return Err(err("Extended Tektronix record length mismatch"));
        }
        let kind = hex(bytes(s, 3, 1)?)?;
        let checksum = hex(bytes(s, 4, 2)?)? as u8;
        let sum = s[1..4].iter().chain(s[6..].iter()).try_fold(0u8, |n, b| {
            Ok::<u8, ClassifierError>(n.wrapping_add(hex(&[*b])? as u8))
        })?;
        if sum != checksum {
            return Err(err("Extended Tektronix checksum mismatch"));
        }
        let n = hex(bytes(s, 6, 1)?)? as usize;
        if n == 0 || n > 8 {
            return Err(err("Invalid Extended Tektronix address width"));
        }
        let address = hex(bytes(s, 7, n)?)?;
        let payload = decode(&s[7 + n..])?;
        match kind {
            6 => push(&mut c, address, at, payload, &mut total)?,
            8 => {
                if !payload.is_empty() {
                    return Err(err("Payload in Tektronix termination record"));
                }
                c.entry = Some(address);
                eof = true;
            }
            _ => return Err(err("Unknown Extended Tektronix block type")),
        }
    }
    if !eof || c.sections.is_empty() {
        return Err(err("Incomplete Extended Tektronix image"));
    }
    c.consumed = data.len();
    c.notes.push(
        "Extended Tektronix checksums verified; target ISA and ROM width are not encoded".into(),
    );
    Ok(c)
}
