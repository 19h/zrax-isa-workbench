//! 8900 containers, the S5L8900 boot ROM's file format (iPhone OS 1.x).
//!
//! Layout, from The Apple Wiki "S5L File Formats" (revision 312559,
//! section 8900, `Apple8900Header`) and xpwn `includes/xpwn/8900.h`
//! (`Apple8900Header`) and `ipsw-patch/8900.c` (`flipApple8900Header`,
//! `createAbstractFileFrom8900`): the magic is the text `8900`, every
//! other field is little-endian.
//!
//! Header (0x800 bytes): magic (0), version text `1.0` (4), format (7: 4
//! plaintext, 3 encrypted with key 0x837, 2 boot plaintext, 1 boot
//! encrypted with the UID key), unknown (8), payload size (0x0C), footer
//! signature offset (0x10) and footer certificate offset (0x14), both from
//! the end of the header, certificate length (0x18), salt (0x1C, 32
//! bytes), unknown (0x3C), security epoch (0x3E), header signature (0x40,
//! 16 bytes: the AES-encrypted SHA-1 of the first 0x40 bytes). The payload
//! follows the header; the footer signature is 0x80 bytes. A payload is
//! usually an IMG2 file (xpwn `img2.h`, magic `Img2` stored `2gmI`).

use super::*;

/// The magic and the only version the sources show.
const MAGIC: &[u8; 4] = b"8900";
const VERSION: &[u8; 3] = b"1.0";
const VERSION_OFFSET: usize = 4;

/// Header fields and size.
const FORMAT: usize = 7;
const PAYLOAD_SIZE: usize = 0x0c;
const SIGNATURE_OFFSET: usize = 0x10;
const CERTIFICATE_OFFSET: usize = 0x14;
const CERTIFICATE_SIZE: usize = 0x18;
const EPOCH: usize = 0x3e;
const HEADER_SIZE: usize = 0x800;

/// The footer signature size (xpwn reads 0x80 bytes).
const SIGNATURE_SIZE: usize = 0x80;

/// Format byte values (The Apple Wiki "S5L File Formats").
const FORMAT_BOOT_ENCRYPTED: u8 = 1;
const FORMAT_BOOT_PLAIN: u8 = 2;
const FORMAT_ENCRYPTED: u8 = 3;
const FORMAT_PLAIN: u8 = 4;

/// IMG2 magic as stored (`IMG2_SIGNATURE` `0x496D6732`, little-endian).
const IMG2_STORED_MAGIC: &[u8; 4] = b"2gmI";

/// The magic and the version text. Requiring both keeps text that starts
/// with the digits 8900 from becoming a parse error.
pub(super) fn detect(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
        && data.get(VERSION_OFFSET..VERSION_OFFSET + VERSION.len()) == Some(VERSION.as_slice())
}

/// What the format byte says about the payload.
struct PayloadFormat {
    encrypted: bool,
    /// The format byte's meaning, for notes.
    description: &'static str,
}

/// The payload format the format byte names.
fn format_kind(format: u8) -> Result<PayloadFormat> {
    let (encrypted, description) = match format {
        FORMAT_PLAIN => (false, "plaintext"),
        FORMAT_BOOT_PLAIN => (false, "boot plaintext"),
        FORMAT_ENCRYPTED => (true, "encrypted with key 0x837"),
        FORMAT_BOOT_ENCRYPTED => (true, "boot, encrypted with the device UID key"),
        other => return Err(error(format!("Unknown 8900 format {other}"))),
    };
    Ok(PayloadFormat {
        encrypted,
        description,
    })
}

/// A footer part: its file offset and bytes.
struct FooterPart<'a> {
    offset: usize,
    bytes: &'a [u8],
}

impl FooterPart<'_> {
    /// File offset just past the part.
    fn end(&self) -> usize {
        self.offset + self.bytes.len()
    }
}

/// The footer part at `offset` after the header.
fn footer<'a>(data: &'a [u8], offset: usize, len: usize, what: &str) -> Result<FooterPart<'a>> {
    let start = HEADER_SIZE
        .checked_add(offset)
        .ok_or_else(|| error(format!("Invalid 8900 {what} offset 0x{offset:X}")))?;
    let bytes = slice(data, start, len)
        .map_err(|_| error(format!("Truncated 8900 {what} at 0x{start:X} + {len} B")))?;
    Ok(FooterPart {
        offset: start,
        bytes,
    })
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, HEADER_SIZE)?;
    if !detect(header) {
        return Err(error("Missing 8900 magic and version 1.0"));
    }
    let format = header[FORMAT];
    let PayloadFormat {
        encrypted,
        description,
    } = format_kind(format)?;
    let payload_size = le_u32(header, PAYLOAD_SIZE)? as usize;
    let payload = slice(data, HEADER_SIZE, payload_size).map_err(|_| {
        error(format!(
            "Truncated 8900 payload at 0x{HEADER_SIZE:X}: {payload_size} B declared, {} B present",
            data.len() - HEADER_SIZE
        ))
    })?;
    let signature_offset = le_u32(header, SIGNATURE_OFFSET)? as usize;
    let signature = footer(data, signature_offset, SIGNATURE_SIZE, "footer signature")?;
    let certificate_offset = le_u32(header, CERTIFICATE_OFFSET)? as usize;
    let certificate_size = le_u32(header, CERTIFICATE_SIZE)? as usize;
    let certificate = footer(
        data,
        certificate_offset,
        certificate_size,
        "footer certificate",
    )?;
    let end = (HEADER_SIZE + payload.len())
        .max(signature.end())
        .max(certificate.end());
    let trailing = &data[end..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} B after the 8900 image at 0x{end:X}",
            trailing.len()
        )));
    }
    let epoch = le_u16(header, EPOCH)?;

    let mut c = Container::new(FileFormat::Apple8900, Layout::Apple8900.label(), KEY_PREFIX);
    c.consumed = end;
    c.notes.push(format!(
        "8900 container version 1.0, format {format} ({description}); payload {payload_size} B at 0x{HEADER_SIZE:X}; security epoch {epoch}"
    ));
    c.notes.push(format!(
        "Footer signature ({SIGNATURE_SIZE} B at 0x{:X}) and certificate ({certificate_size} B at 0x{:X}) present; not verified; the header signature (AES with key 0x837) is not verified",
        signature.offset, certificate.offset
    ));
    c.notes
        .push("8900 fields name no ISA; the ISA comes from the payload".to_string());
    c.push_metadata("apple_8900_format", "8900 format", u64::from(format));
    c.push_metadata(
        "apple_8900_payload_size",
        "8900 payload size (B)",
        payload_size as u64,
    );
    c.push_metadata("apple_8900_epoch", "Security epoch", u64::from(epoch));
    c.push_metadata(
        "apple_8900_certificate_size",
        "Footer certificate size (B); not verified",
        certificate_size as u64,
    );
    let label = "8900 payload";
    if encrypted {
        c.notes
            .push(format!("Payload {description}; not decrypted"));
        c.children.push(Child::opaque(label, HEADER_SIZE, payload));
        return Ok(c);
    }
    if payload.starts_with(IMG2_STORED_MAGIC) {
        c.notes.push(
            "Payload starts with an IMG2 header (xpwn img2.h); IMG2 is not parsed".to_string(),
        );
    }
    c.children.push(Child::stored(label, HEADER_SIZE, payload));
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_needs_the_version_text() {
        assert!(detect(b"89001.0\x04"));
        assert!(!detect(b"8900,1,2"));
        assert!(!detect(b"8900"));
    }

    #[test]
    fn formats_one_and_three_are_encrypted() {
        assert!(!format_kind(4).unwrap().encrypted);
        assert!(!format_kind(2).unwrap().encrypted);
        assert!(format_kind(3).unwrap().encrypted);
        assert!(format_kind(1).unwrap().encrypted);
        assert!(format_kind(5).is_err());
    }
}
