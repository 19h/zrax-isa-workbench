//! Text-based hex formats: Intel HEX, Motorola S-record, TI-TXT.
//!
//! These are containers for a memory image, not for an ISA: the records say
//! where bytes go, never what they are. Parsing therefore decodes the image
//! ([`parse_with_payload`]) so the code in it can be classified.
//!
//! Detection requires a well-formed first record (valid hex, consistent
//! length and, for Intel HEX / S-record, a correct checksum). A leading `:`,
//! `S` or `@` byte on its own is far too common in binary data to mean
//! anything.

use crate::error::{ClassifierError, Result};
use crate::types::{ClassificationMetadata, ClassificationResult, Endianness, FileFormat, Isa, Variant};

/// Intel HEX record types.
pub mod intel_hex {
    pub const DATA: u8 = 0x00;
    pub const EOF: u8 = 0x01;
    pub const EXT_SEGMENT: u8 = 0x02;
    pub const START_SEGMENT: u8 = 0x03;
    pub const EXT_LINEAR: u8 = 0x04;
    pub const START_LINEAR: u8 = 0x05;
}

/// Detected hex format variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexVariant {
    /// Intel HEX format
    IntelHex {
        /// Has 32-bit addressing (type 04/05 records)
        is_32bit: bool,
    },
    /// Motorola S-record format
    Srec {
        /// Address size (2, 3, or 4 bytes)
        addr_size: u8,
    },
    /// TI-TXT format
    TiTxt,
}

/// Largest decoded image we keep for classification.
const MAX_IMAGE: usize = 64 << 20;

fn lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split(|&b| b == b'\n').map(|l| l.trim_ascii()).filter(|l| !l.is_empty())
}

fn unhex(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    s.chunks(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16)?;
            let lo = (p[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

/// An Intel HEX record: (type, address, data), checksum verified.
fn intel_record(line: &[u8]) -> Option<(u8, u16, Vec<u8>)> {
    let b = unhex(line.strip_prefix(b":")?)?;
    if b.len() < 5 || b.len() != usize::from(b[0]) + 5 {
        return None;
    }
    if b.iter().fold(0u8, |a, &x| a.wrapping_add(x)) != 0 {
        return None;
    }
    Some((b[3], u16::from_be_bytes([b[1], b[2]]), b[4..b.len() - 1].to_vec()))
}

/// An S-record: (type digit, address, data), checksum verified.
fn srec_record(line: &[u8]) -> Option<(u8, u32, Vec<u8>)> {
    if line.len() < 4 || line[0] != b'S' || !line[1].is_ascii_digit() {
        return None;
    }
    let kind = line[1] - b'0';
    let b = unhex(&line[2..])?;
    if b.len() < 3 || b.len() != usize::from(b[0]) + 1 {
        return None;
    }
    if b.iter().fold(0u8, |a, &x| a.wrapping_add(x)) != 0xFF {
        return None;
    }
    let addr_len = match kind {
        0 | 1 | 5 | 9 => 2,
        2 | 6 | 8 => 3,
        3 | 7 => 4,
        _ => return None,
    };
    if b.len() < 2 + addr_len {
        return None;
    }
    let addr = b[1..=addr_len].iter().fold(0u32, |a, &x| a << 8 | u32::from(x));
    Some((kind, addr, b[1 + addr_len..b.len() - 1].to_vec()))
}

fn ti_address(line: &[u8]) -> Option<u32> {
    let digits = line.strip_prefix(b"@")?;
    if digits.is_empty() || digits.len() > 8 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
}

fn ti_data(line: &[u8]) -> Option<Vec<u8>> {
    line.split(|&b| b == b' ' || b == b'\t')
        .filter(|t| !t.is_empty())
        .map(|t| if t.len() == 2 { unhex(t).map(|v| v[0]) } else { None })
        .collect()
}

/// Detect hex format.
pub fn detect(data: &[u8]) -> Option<HexVariant> {
    let mut it = lines(data);
    let first = it.next()?;
    match first.first()? {
        b':' => {
            intel_record(first)?;
            let is_32bit = lines(data)
                .take(200)
                .filter_map(intel_record)
                .any(|(t, _, _)| t == intel_hex::EXT_LINEAR || t == intel_hex::START_LINEAR);
            Some(HexVariant::IntelHex { is_32bit })
        }
        b'S' => {
            srec_record(first)?;
            let addr_size = lines(data)
                .take(200)
                .filter_map(srec_record)
                .map(|(k, _, _)| match k {
                    2 | 8 => 3u8,
                    3 | 7 => 4,
                    _ => 2,
                })
                .max()
                .unwrap_or(2);
            Some(HexVariant::Srec { addr_size })
        }
        b'@' => {
            ti_address(first)?;
            ti_data(it.next()?)?;
            Some(HexVariant::TiTxt)
        }
        _ => None,
    }
}

/// Decoded image and statistics.
struct Image {
    /// (address, bytes) in file order.
    chunks: Vec<(u64, Vec<u8>)>,
    records: usize,
    bad_records: usize,
    entry: Option<u64>,
    has_eof: bool,
}

impl Image {
    fn new() -> Self {
        Self { chunks: Vec::new(), records: 0, bad_records: 0, entry: None, has_eof: false }
    }

    fn push(&mut self, addr: u64, bytes: Vec<u8>) {
        if !bytes.is_empty() && self.bytes() < MAX_IMAGE {
            self.chunks.push((addr, bytes));
        }
    }

    fn bytes(&self) -> usize {
        self.chunks.iter().map(|c| c.1.len()).sum()
    }

    /// Data in address order. Gaps are dropped: the code model works on byte
    /// pairs and does not care about absolute addresses.
    fn flatten(mut self) -> Vec<u8> {
        self.chunks.sort_by_key(|c| c.0);
        self.chunks.into_iter().flat_map(|c| c.1).collect()
    }

    fn range(&self) -> Option<(u64, u64)> {
        let lo = self.chunks.iter().map(|c| c.0).min()?;
        let hi = self.chunks.iter().map(|c| c.0 + c.1.len() as u64).max()?;
        Some((lo, hi))
    }
}

fn decode_intel(data: &[u8]) -> Image {
    let mut img = Image::new();
    let mut base = 0u64;
    for line in lines(data) {
        let Some((kind, addr, bytes)) = intel_record(line) else {
            img.bad_records += usize::from(line.first() == Some(&b':'));
            continue;
        };
        img.records += 1;
        match kind {
            intel_hex::DATA => img.push(base + u64::from(addr), bytes),
            intel_hex::EOF => img.has_eof = true,
            intel_hex::EXT_SEGMENT if bytes.len() == 2 => {
                base = u64::from(u16::from_be_bytes([bytes[0], bytes[1]])) << 4;
            }
            intel_hex::EXT_LINEAR if bytes.len() == 2 => {
                base = u64::from(u16::from_be_bytes([bytes[0], bytes[1]])) << 16;
            }
            intel_hex::START_SEGMENT if bytes.len() == 4 => {
                let cs = u64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
                let ip = u64::from(u16::from_be_bytes([bytes[2], bytes[3]]));
                img.entry = Some((cs << 4) + ip);
            }
            intel_hex::START_LINEAR if bytes.len() == 4 => {
                img.entry = Some(u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])));
            }
            _ => {}
        }
    }
    img
}

fn decode_srec(data: &[u8]) -> Image {
    let mut img = Image::new();
    for line in lines(data) {
        let Some((kind, addr, bytes)) = srec_record(line) else {
            img.bad_records += usize::from(line.first() == Some(&b'S'));
            continue;
        };
        img.records += 1;
        match kind {
            1..=3 => img.push(u64::from(addr), bytes),
            7..=9 => {
                img.entry = Some(u64::from(addr));
                img.has_eof = true;
            }
            _ => {}
        }
    }
    img
}

fn decode_ti_txt(data: &[u8]) -> Image {
    let mut img = Image::new();
    let mut addr = 0u64;
    for line in lines(data) {
        if line.eq_ignore_ascii_case(b"q") {
            img.has_eof = true;
            break;
        }
        if let Some(a) = ti_address(line) {
            addr = u64::from(a);
            img.records += 1;
        } else if let Some(bytes) = ti_data(line) {
            let n = bytes.len() as u64;
            img.push(addr, bytes);
            addr += n;
            img.records += 1;
        } else {
            img.bad_records += 1;
        }
    }
    img
}

/// Parse a hex file: container metadata plus the decoded memory image.
///
/// The ISA is always `Unknown`; callers classify the returned image.
pub fn parse_with_payload(data: &[u8], variant: HexVariant) -> Result<(ClassificationResult, Vec<u8>)> {
    let (img, format, label, bits) = match variant {
        HexVariant::IntelHex { is_32bit } => (
            decode_intel(data),
            FileFormat::IntelHex,
            if is_32bit { "Intel HEX (32-bit addressing)" } else { "Intel HEX (16/20-bit addressing)" },
            if is_32bit { 32 } else { 16 },
        ),
        HexVariant::Srec { addr_size } => (
            decode_srec(data),
            FileFormat::Srec,
            match addr_size {
                2 => "S-record (S19, 16-bit addresses)",
                3 => "S-record (S28, 24-bit addresses)",
                _ => "S-record (S37, 32-bit addresses)",
            },
            u8::from(addr_size) * 8,
        ),
        HexVariant::TiTxt => (decode_ti_txt(data), FileFormat::TiTxt, "TI-TXT", 16),
    };
    if img.records == 0 {
        return Err(ClassifierError::InvalidSection {
            kind: "record".to_string(),
            index: 0,
            message: format!("{label}: no valid records"),
        });
    }

    let mut notes = vec![
        label.to_string(),
        format!("Records: {} valid, {} malformed", img.records, img.bad_records),
        format!("Data bytes: {}", img.bytes()),
    ];
    if let Some((lo, hi)) = img.range() {
        notes.push(format!("Address range: 0x{lo:X} - 0x{hi:X}"));
    }
    if !img.has_eof {
        notes.push("No end-of-file record".to_string());
    }
    let metadata = ClassificationMetadata {
        entry_point: img.entry,
        code_size: Some(img.bytes() as u64),
        notes,
        ..Default::default()
    };
    let mut result = ClassificationResult::from_format(Isa::Unknown(0), bits, Endianness::Little, format);
    result.confidence = 0.0;
    result.variant = Variant::new(label);
    result.metadata = metadata;
    Ok((result, img.flatten()))
}

/// Parse hex format file (metadata only; see [`parse_with_payload`]).
pub fn parse(data: &[u8], variant: HexVariant) -> Result<ClassificationResult> {
    parse_with_payload(data, variant).map(|(r, _)| r)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IHEX: &[u8] = b":10010000214601360121470136007EFE09D2190140\n:00000001FF\n";
    const SREC: &[u8] = b"S00600004844521B\nS1130000285F245F2212226A000424290008237C2A\nS5030001FB\nS9030000FC\n";

    #[test]
    fn test_detect_intel_hex() {
        assert!(matches!(detect(IHEX), Some(HexVariant::IntelHex { is_32bit: false })));
    }

    #[test]
    fn test_detect_srec() {
        assert!(matches!(detect(SREC), Some(HexVariant::Srec { addr_size: 2 })));
    }

    #[test]
    fn test_detect_ti_txt() {
        let data = b"@1000\n01 02 03 04 05 06 07 08\n@2000\n11 12 13 14\nq\n";
        assert!(matches!(detect(data), Some(HexVariant::TiTxt)));
    }

    #[test]
    fn test_reject_binary_that_starts_like_hex() {
        // Leading ':' / 'S' + digit / '@' followed by binary: not hex files,
        // and must not panic on non-UTF-8 bytes.
        assert_eq!(detect(b":\x00\xff\xfe\x80\x81abcdef\n"), None);
        assert_eq!(detect(b"S1\xe2\x82\xac\xe2\x82\xac\x00\x10"), None);
        assert_eq!(detect(b"@@\x90\x90\xc3"), None);
        assert_eq!(detect(b":10010000214601360121470136007EFE09D2190141\n"), None); // bad checksum
    }

    #[test]
    fn test_parse_decodes_image() {
        let (r, img) = parse_with_payload(IHEX, detect(IHEX).unwrap()).unwrap();
        assert_eq!(r.format, FileFormat::IntelHex);
        assert_eq!(img.len(), 16);
        assert_eq!(&img[..4], &[0x21, 0x46, 0x01, 0x36]);
        let (r, img) = parse_with_payload(SREC, detect(SREC).unwrap()).unwrap();
        assert_eq!(r.format, FileFormat::Srec);
        assert_eq!(img.len(), 16);
        assert_eq!(r.metadata.entry_point, Some(0));
    }

    #[test]
    fn test_malformed_lines_do_not_panic() {
        let data = b":10010000214601360121470136007EFE09D2190140\n:02\n:0200000\n:\xff\xff\nS\n:00000001FF\n";
        let (_, img) = parse_with_payload(data, HexVariant::IntelHex { is_32bit: false }).unwrap();
        assert_eq!(img.len(), 16);
    }
}
