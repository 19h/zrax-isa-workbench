//! Strict TI hex-utility output decoders. Hex digits represent bytes in
//! printed order; target ROM widths and byte lanes are not encoded.
use super::*;

const STX: u8 = 0x02;
const ETX: u8 = 0x03;

/// Parse 1 to 16 hexadecimal digits.
fn parse_hex(digits: &[u8]) -> Result<u64> {
    if digits.is_empty() || digits.len() > 16 {
        return Err(error("Invalid hexadecimal field width"));
    }
    digits.iter().try_fold(0u64, |value, digit| {
        char::from(*digit)
            .to_digit(16)
            .map(|nibble| (value << 4) | u64::from(nibble))
            .ok_or_else(|| error("Invalid hexadecimal digit"))
    })
}

/// Decode pairs of hexadecimal digits into bytes.
fn decode_hex(digits: &[u8]) -> Result<Vec<u8>> {
    if digits.len() % 2 != 0 {
        return Err(error("Odd number of hex digits"));
    }
    digits
        .chunks_exact(2)
        .map(|pair| Ok(parse_hex(pair)? as u8))
        .collect()
}

pub(super) fn detect(data: &[u8]) -> Option<Variant> {
    let text = data.trim_ascii();
    let kind = if text.starts_with(&[STX]) {
        Variant::AsciiHex
    } else if text.starts_with(b"K") {
        Variant::Tagged
    } else if text.starts_with(b"%") {
        Variant::Tektronix
    } else if text.starts_with(b"1651 ") || text.starts_with(b"1651\t") {
        return ccs(text).ok().map(|_| Variant::CcsData);
    } else {
        return None;
    };
    // Text signatures are weak; validate every record and checksum.
    parse(text, kind).ok().map(|_| kind)
}

pub(super) fn parse(data: &[u8], kind: Variant) -> Result<Container<'_>> {
    match kind {
        Variant::AsciiHex => ascii_hex(data),
        Variant::Tagged => tagged(data),
        Variant::Tektronix => tektronix(data),
        _ => Err(error("Invalid text kind")),
    }
}

/// Add a decoded run of bytes as a section, keeping the total decoded size
/// within [`MAX_PAYLOAD`]. Empty runs only count toward the total.
fn push_run(
    c: &mut Container<'_>,
    address: u64,
    offset: usize,
    run: Vec<u8>,
    total: &mut usize,
) -> Result<()> {
    *total = total
        .checked_add(run.len())
        .filter(|n| *n <= MAX_PAYLOAD)
        .ok_or_else(|| error("Decoded text payload exceeds 64 MiB"))?;
    if !run.is_empty() {
        c.push_section(address, offset, Cow::Owned(run))?;
    }
    Ok(())
}

/// SPRU296 section 5.1.2. Sample bit width and memory byte order are not
/// represented by this header. Validate the text and retain metadata only.
pub(super) fn ccs(data: &[u8]) -> Result<Container<'_>> {
    let text = std::str::from_utf8(data).map_err(|_| error("CCS data is not text"))?;
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    // "1651 <format> <address> <page> <length>"
    let header: Vec<_> = lines
        .next()
        .ok_or_else(|| error("Missing CCS data header"))?
        .split_whitespace()
        .collect();
    if header.len() != 5 || header[0] != "1651" {
        return Err(error("Invalid CCS GO DSP header"));
    }
    let number = |s: &str| {
        let digits = s
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .trim_end_matches(['h', 'H']);
        parse_hex(digits.as_bytes())
    };
    let sample_format = number(header[1])?;
    let address = number(header[2])?;
    let page = number(header[3])?;
    let length = number(header[4])?;
    if !(1..=4).contains(&sample_format) {
        return Err(error("Unsupported CCS sample format"));
    }
    let mut samples = 0u64;
    for line in lines {
        let sample = line.trim();
        match sample_format {
            // Hexadecimal
            1 => {
                number(sample)?;
            }
            // Integer or long
            2 | 3 => {
                sample
                    .parse::<i64>()
                    .map_err(|_| error("Invalid CCS integer sample"))?;
            }
            // Float
            4 => {
                let value = sample
                    .parse::<f64>()
                    .map_err(|_| error("Invalid CCS float sample"))?;
                if !value.is_finite() {
                    return Err(error("Nonfinite CCS float sample"));
                }
            }
            _ => unreachable!("format was validated above"),
        }
        samples += 1;
    }
    if samples == 0 || (length != 0 && length != samples) {
        return Err(error("CCS sample count does not match declared length"));
    }
    let mut c = Container::new(Variant::CcsData);
    c.opaque = true;
    c.consumed = data.len();
    c.notes.push(format!(
        "Sample format {sample_format}; default target address 0x{address:X}; page 0x{page:X}; declared {length}, actual {samples} samples"
    ));
    c.notes.push("Target word width and byte order are unknown; sample data is not treated as machine code; zero header length permits debugger override".into());
    Ok(c)
}

/// STX, whitespace-separated hex bytes and ETX. "$A<address>," starts a new
/// run at the given address.
fn ascii_hex(data: &[u8]) -> Result<Container<'_>> {
    let text = data.trim_ascii();
    if text.first() != Some(&STX) {
        return Err(error("Missing ASCII-Hex STX"));
    }
    let end = text
        .iter()
        .position(|b| *b == ETX)
        .ok_or_else(|| error("Missing ASCII-Hex ETX"))?;
    if !text[end + 1..].iter().all(u8::is_ascii_whitespace) {
        return Err(error("Data after ASCII-Hex ETX"));
    }
    let digits_end = |start: usize| {
        start
            + text[start..end]
                .iter()
                .take_while(|b| b.is_ascii_hexdigit())
                .count()
    };
    let mut c = Container::new(Variant::AsciiHex);
    let mut pos = 1;
    let mut address = 0;
    let mut run_start = pos;
    let mut run = Vec::new();
    let mut total = 0;
    while pos < end {
        if text[pos].is_ascii_whitespace() {
            pos += 1;
        } else if text[pos] == b'$' {
            push_run(
                &mut c,
                address,
                run_start,
                std::mem::take(&mut run),
                &mut total,
            )?;
            if slice(text, pos, 2)? != b"$A" {
                return Err(error("Unknown ASCII-Hex control record"));
            }
            let digits = pos + 2;
            pos = digits_end(digits);
            if !(4..=8).contains(&(pos - digits)) || text.get(pos) != Some(&b',') {
                return Err(error("Invalid ASCII-Hex address record"));
            }
            address = parse_hex(&text[digits..pos])?;
            pos += 1;
            run_start = pos;
        } else {
            let digits = pos;
            pos = digits_end(digits);
            let len = pos - digits;
            if len == 0 || len % 2 != 0 || len > 16 {
                return Err(error("Invalid ASCII-Hex data token"));
            }
            if total + run.len() + len / 2 > MAX_PAYLOAD {
                return Err(error("ASCII-Hex exceeds 64 MiB"));
            }
            run.extend(decode_hex(&text[digits..pos])?);
        }
    }
    push_run(&mut c, address, run_start, run, &mut total)?;
    if c.sections.is_empty() {
        return Err(error("ASCII-Hex has no data"));
    }
    c.notes.push("Bytes decoded in printed order; ROM word width and byte-lane files are not identified by this encoding".into());
    c.consumed = data.len();
    Ok(c)
}

/// SDSMAC tagged object: a "K<identifier>F" line, then records of tagged
/// fields that each end with "F", then ":" at end of file. Tags: "9" sets
/// the 16-bit load address, "B" is a data word, "*" a data byte, "7" a
/// checksum and "8" an ignored checksum.
fn tagged(data: &[u8]) -> Result<Container<'_>> {
    let mut c = Container::new(Variant::Tagged);
    let mut identified = false;
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
            return Err(error("Record after TI-tagged EOF"));
        }
        if !identified {
            if record.first() != Some(&b'K') || record.last() != Some(&b'F') || record.len() < 3 {
                return Err(error("Missing TI-tagged program identifier"));
            }
            c.notes.push(format!(
                "Program identifier: {}",
                String::from_utf8_lossy(&record[1..record.len() - 1])
            ));
            identified = true;
            continue;
        }
        if record == b":" {
            eof = true;
            continue;
        }
        let mut pos = 0;
        let mut run = Vec::new();
        let mut run_address = address;
        let mut has_checksum = false;
        while pos < record.len() {
            let tag = record[pos];
            let tag_at = pos;
            pos += 1;
            match tag {
                b'9' => {
                    push_run(
                        &mut c,
                        run_address,
                        line_offset,
                        std::mem::take(&mut run),
                        &mut total,
                    )?;
                    address = parse_hex(slice(record, pos, 4)?)?;
                    run_address = address;
                    pos += 4;
                }
                b'B' => {
                    run.extend(decode_hex(slice(record, pos, 4)?)?);
                    address = address
                        .checked_add(1)
                        .ok_or_else(|| error("Tagged address overflow"))?;
                    pos += 4;
                }
                b'*' => {
                    run.extend(decode_hex(slice(record, pos, 2)?)?);
                    pos += 2;
                    address = address
                        .checked_add(1)
                        .ok_or_else(|| error("Tagged address overflow"))?;
                }
                b'7' | b'8' => {
                    let value = parse_hex(slice(record, pos, 4)?)? as u16;
                    if has_checksum || record.get(pos + 4) != Some(&b'F') || pos + 5 != record.len()
                    {
                        return Err(error("Checksum must be the final TI-tagged field"));
                    }
                    // The checksum negates the sum of the record's characters
                    // up to and including its tag.
                    if tag == b'7' {
                        let sum = record[..=tag_at]
                            .iter()
                            .fold(0u16, |sum, b| sum.wrapping_add(u16::from(*b)));
                        if sum.wrapping_add(value) != 0 {
                            return Err(error("TI-tagged checksum mismatch"));
                        }
                    }
                    pos += 4;
                    has_checksum = true;
                }
                b'F' => {
                    if pos != record.len() {
                        return Err(error("Unexpected bytes after TI-tagged end-of-record"));
                    }
                    if !has_checksum {
                        return Err(error("TI-tagged data record lacks checksum tag"));
                    }
                }
                _ => return Err(error(format!("Unknown TI-tagged tag {}", char::from(tag)))),
            }
            if total + run.len() > MAX_PAYLOAD {
                return Err(error("TI-tagged exceeds 64 MiB"));
            }
        }
        if record.last() != Some(&b'F') {
            return Err(error("Missing TI-tagged end-of-record"));
        }
        push_run(&mut c, run_address, line_offset, run, &mut total)?;
    }
    if !identified || !eof || c.sections.is_empty() {
        return Err(error("Incomplete TI-tagged file"));
    }
    c.consumed = data.len();
    c.notes.push("Tagged addresses are 16-bit target locations; data words are decoded most significant byte first; target ISA/ROM width is not encoded".into());
    Ok(c)
}

/// Extended Tektronix: "%", record length (2 digits, excluding "%"), block
/// type (6 = data, 8 = termination with entry point), checksum (2 digits,
/// the sum of every other digit's value), address length (1 digit), address
/// and data.
fn tektronix(data: &[u8]) -> Result<Container<'_>> {
    let mut c = Container::new(Variant::Tektronix);
    let mut total = 0;
    let mut offset = 0;
    let mut eof = false;
    for line in data.split_inclusive(|b| *b == b'\n') {
        let record = line.trim_ascii();
        let line_offset = offset;
        offset += line.len();
        if record.is_empty() {
            continue;
        }
        if eof || record.first() != Some(&b'%') {
            return Err(error("Invalid Extended Tektronix record"));
        }
        if parse_hex(slice(record, 1, 2)?)? as usize != record.len() - 1 {
            return Err(error("Extended Tektronix record length mismatch"));
        }
        let kind = parse_hex(slice(record, 3, 1)?)?;
        let checksum = parse_hex(slice(record, 4, 2)?)? as u8;
        let sum = record[1..4]
            .iter()
            .chain(&record[6..])
            .try_fold(0u8, |sum, digit| {
                parse_hex(std::slice::from_ref(digit)).map(|n| sum.wrapping_add(n as u8))
            })?;
        if sum != checksum {
            return Err(error("Extended Tektronix checksum mismatch"));
        }
        let address_len = parse_hex(slice(record, 6, 1)?)? as usize;
        if address_len == 0 || address_len > 8 {
            return Err(error("Invalid Extended Tektronix address width"));
        }
        let address = parse_hex(slice(record, 7, address_len)?)?;
        let payload = decode_hex(&record[7 + address_len..])?;
        match kind {
            6 => push_run(&mut c, address, line_offset, payload, &mut total)?,
            8 => {
                if !payload.is_empty() {
                    return Err(error("Payload in Tektronix termination record"));
                }
                c.entry = Some(address);
                eof = true;
            }
            _ => return Err(error("Unknown Extended Tektronix block type")),
        }
    }
    if !eof || c.sections.is_empty() {
        return Err(error("Incomplete Extended Tektronix image"));
    }
    c.consumed = data.len();
    c.notes.push(
        "Extended Tektronix checksums verified; target ISA and ROM width are not encoded".into(),
    );
    Ok(c)
}
