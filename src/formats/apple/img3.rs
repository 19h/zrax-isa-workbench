//! Img3 firmware images (iPhone OS 2.0 to iOS 9, A6X and older devices).
//!
//! Layout, from The Apple Wiki "IMG3 File Format" (revision 312068,
//! `img3File`, `img3Tag`), "KBAG" (revision 190028) and "S5L File Formats"
//! (revision 312559), and xpwn `includes/xpwn/img3.h`
//! (`AppleImg3RootHeader`, `AppleImg3KBAGHeader`, the tag magics) and
//! `ipsw-patch/img3.c` (`readImg3Root`, `readImg3Element`,
//! `writeImg3Root`). Every number is little-endian, magics included, so
//! `Img3` is stored as `3gmI` and `DATA` as `ATAD`.
//!
//! Root header (20 bytes): magic (0), full size (4), size of the tags
//! after the header (8), offset of the `SHSH` tag from the end of the
//! header (0x0C), image type four-character code (0x10). Tags follow: a
//! four-character code, the total length including the 12-byte tag header
//! and padding, the data length, the data and padding. A `KBAG` tag holds
//! the crypt state (1 production, 2 development GID key), the AES key size
//! in bits and the IV and key encrypted with the GID key; its presence
//! means `DATA` is encrypted.

use super::*;

/// `IMG3_MAGIC`.
const IMG3_MAGIC: u32 = 0x496d_6733;

/// Root header fields and size (`AppleImg3RootHeader`).
const FULL_SIZE: usize = 4;
const TAGS_SIZE: usize = 8;
const SHSH_OFFSET: usize = 0x0c;
const IDENT: usize = 0x10;
const ROOT_HEADER_SIZE: usize = 0x14;

/// Tag header (`AppleImg3Header`): code, total length, data length.
const TAG_HEADER_SIZE: usize = 12;

/// Tag codes (xpwn `img3.h`; The Apple Wiki tag list for `CHIP`, `PROD`,
/// `SDOM` and `ECID`).
const TAG_DATA: u32 = 0x4441_5441;
const TAG_TYPE: u32 = 0x5459_5045;
const TAG_KBAG: u32 = 0x4b42_4147;
const TAG_SHSH: u32 = 0x5348_5348;
const TAG_CERT: u32 = 0x4345_5254;
const TAG_VERS: u32 = 0x5645_5253;
const TAG_SEPO: u32 = 0x5345_504f;
const TAG_BORD: u32 = 0x424f_5244;
const TAG_CHIP: u32 = 0x4348_4950;
const TAG_PROD: u32 = 0x5052_4f44;
const TAG_SDOM: u32 = 0x5344_4f4d;

/// Integer tags reported in metadata, with their labels. `ECID`, the
/// device-unique chip ID, is deliberately not reported.
const VALUE_TAGS: [(u32, &str, &str); 5] = [
    (TAG_CHIP, "apple_img3_chip", "Chip (CHIP)"),
    (TAG_BORD, "apple_img3_board", "Board (BORD)"),
    (
        TAG_SEPO,
        "apple_img3_security_epoch",
        "Security epoch (SEPO)",
    ),
    (
        TAG_SDOM,
        "apple_img3_security_domain",
        "Security domain (SDOM)",
    ),
    (TAG_PROD, "apple_img3_production", "Production mode (PROD)"),
];

/// `KBAG` contents: crypt state, AES key size in bits, then the IV and the
/// key (The Apple Wiki "KBAG").
const KBAG_HEADER_SIZE: usize = 8;
const KBAG_IV_SIZE: usize = 16;
const CRYPT_PRODUCTION: u32 = 1;
const CRYPT_DEVELOPMENT: u32 = 2;
const AES_KEY_BITS: [u32; 3] = [128, 192, 256];

/// Longest version text shown (our bound).
const MAX_TEXT_SIZE: usize = 64;

pub(super) fn detect(data: &[u8]) -> bool {
    data.get(..4)
        .map(|m| u32::from_le_bytes(m.try_into().expect("four bytes")))
        == Some(IMG3_MAGIC)
}

/// A tag in file coordinates.
struct Tag<'a> {
    code: u32,
    /// File offset of the tag header.
    offset: usize,
    data: &'a [u8],
}

/// The four-character code of a little-endian tag value, in reading order.
fn code_text(code: u32) -> String {
    fourcc_text(code.to_be_bytes())
}

/// The tags in `[ROOT_HEADER_SIZE, end)`. Every tag takes at least its
/// 12-byte header, so the walk is bounded by the tag area.
fn tags(image: &[u8], end: usize) -> Result<Vec<Tag<'_>>> {
    let mut tags = Vec::new();
    let mut pos = ROOT_HEADER_SIZE;
    while pos < end {
        let available = end - pos;
        if available < TAG_HEADER_SIZE {
            return Err(error(format!(
                "Truncated Img3 tag at 0x{pos:X}: {available} B left in the tag area"
            )));
        }
        let header = slice(image, pos, TAG_HEADER_SIZE)?;
        let code = le_u32(header, 0)?;
        let total = le_u32(header, 4)? as usize;
        let data_len = le_u32(header, 8)? as usize;
        let name = code_text(code);
        if total < TAG_HEADER_SIZE || total > available {
            return Err(error(format!(
                "Invalid Img3 tag {name} at 0x{pos:X}: total length {total} B, {available} B left in the tag area"
            )));
        }
        if data_len > total - TAG_HEADER_SIZE {
            return Err(error(format!(
                "Invalid Img3 tag {name} at 0x{pos:X}: data length {data_len} B exceeds the {total} B tag"
            )));
        }
        tags.push(Tag {
            code,
            offset: pos,
            data: &image[pos + TAG_HEADER_SIZE..pos + TAG_HEADER_SIZE + data_len],
        });
        pos += total;
    }
    Ok(tags)
}

/// A parsed `KBAG`.
struct Keybag {
    crypt_state: u32,
    key_bits: u32,
}

fn keybag(tag: &Tag<'_>) -> Result<Keybag> {
    let invalid =
        |reason: String| error(format!("Invalid Img3 KBAG at 0x{:X}: {reason}", tag.offset));
    if tag.data.len() < KBAG_HEADER_SIZE {
        return Err(invalid(format!("{} B of data", tag.data.len())));
    }
    let crypt_state = le_u32(tag.data, 0)?;
    let key_bits = le_u32(tag.data, 4)?;
    if !AES_KEY_BITS.contains(&key_bits) {
        return Err(invalid(format!("key size {key_bits} bits")));
    }
    let needed = KBAG_HEADER_SIZE + KBAG_IV_SIZE + key_bits as usize / 8;
    if tag.data.len() < needed {
        return Err(invalid(format!(
            "{} B of data, {needed} B needed for the IV and a {key_bits}-bit key",
            tag.data.len()
        )));
    }
    Ok(Keybag {
        crypt_state,
        key_bits,
    })
}

fn keybag_text(bags: &[Keybag]) -> String {
    let kinds: Vec<String> = bags
        .iter()
        .map(|bag| {
            let state = match bag.crypt_state {
                CRYPT_PRODUCTION => "production".to_string(),
                CRYPT_DEVELOPMENT => "development".to_string(),
                other => format!("crypt state {other}"),
            };
            format!("{state} AES-{}", bag.key_bits)
        })
        .collect();
    format!(
        "{}: {}",
        counted(bags.len(), "KBAG", "KBAGs"),
        kinds.join(", ")
    )
}

/// The value of a four-byte integer tag, as hex.
fn tag_value(tag: &Tag<'_>) -> Option<String> {
    let bytes: [u8; 4] = tag.data.get(..4)?.try_into().ok()?;
    Some(format!("0x{:X}", u32::from_le_bytes(bytes)))
}

/// Signature, certificate and integer-tag notes and metadata.
fn describe_tags(c: &mut Container<'_>, tags: &[Tag<'_>], shsh_offset: usize) {
    let codes: Vec<String> = tags.iter().map(|t| code_text(t.code)).collect();
    c.notes.push(format!("Img3 tags: {}", codes.join(", ")));
    for (code, key, label) in VALUE_TAGS {
        if let Some(value) = tags.iter().find(|t| t.code == code).and_then(tag_value) {
            c.push_metadata(key, label, value);
        }
    }
    if let Some(version) = tags.iter().find(|t| t.code == TAG_VERS) {
        c.push_metadata(
            "apple_img3_version",
            "Version (VERS, bytes as text)",
            printable(version.data, MAX_TEXT_SIZE),
        );
    }
    let shsh = tags.iter().find(|t| t.code == TAG_SHSH);
    let cert = tags.iter().find(|t| t.code == TAG_CERT);
    let signature = match (shsh, cert) {
        (Some(shsh), Some(cert)) => format!(
            "SHSH signature ({} B) and CERT certificate chain ({} B) present; not verified",
            shsh.data.len(),
            cert.data.len()
        ),
        (Some(shsh), None) => format!(
            "SHSH signature ({} B) present, no CERT; not verified",
            shsh.data.len()
        ),
        (None, Some(cert)) => format!(
            "CERT certificate chain ({} B) present, no SHSH signature; not verified",
            cert.data.len()
        ),
        (None, None) => "Unsigned: no SHSH or CERT tag".to_string(),
    };
    c.notes.push(signature);
    if let Some(shsh) = shsh {
        if shsh.offset != ROOT_HEADER_SIZE + shsh_offset {
            c.notes.push(format!(
                "SHSH tag at 0x{:X}, but the header's signed-area size names 0x{:X}",
                shsh.offset,
                ROOT_HEADER_SIZE + shsh_offset
            ));
        }
    }
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, ROOT_HEADER_SIZE)?;
    if le_u32(header, 0)? != IMG3_MAGIC {
        return Err(error("Missing Img3 magic"));
    }
    let full_size = le_u32(header, FULL_SIZE)? as usize;
    let tags_size = le_u32(header, TAGS_SIZE)? as usize;
    let shsh_offset = le_u32(header, SHSH_OFFSET)? as usize;
    let ident = le_u32(header, IDENT)?;
    if full_size < ROOT_HEADER_SIZE {
        return Err(error(format!(
            "Invalid Img3 full size {full_size} B: shorter than the 20 B header"
        )));
    }
    let image = slice(data, 0, full_size)?;
    let tags_end = ROOT_HEADER_SIZE
        .checked_add(tags_size)
        .filter(|end| *end <= full_size)
        .ok_or_else(|| {
            error(format!(
                "Invalid Img3 tag area size {tags_size} B: exceeds the {full_size} B image"
            ))
        })?;
    let trailing = &data[full_size..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected {} B after the Img3 image at 0x{full_size:X}",
            trailing.len()
        )));
    }
    let tags = tags(image, tags_end)?;
    let mut payloads = tags.iter().filter(|t| t.code == TAG_DATA);
    let payload = payloads.next();
    if let Some(duplicate) = payloads.next() {
        return Err(error(format!(
            "Duplicate Img3 DATA tag at 0x{:X}",
            duplicate.offset
        )));
    }
    let keybags = tags
        .iter()
        .filter(|t| t.code == TAG_KBAG)
        .map(keybag)
        .collect::<Result<Vec<_>>>()?;

    let label = code_text(ident);
    let mut c = Container::new(FileFormat::Img3, Layout::Img3.label(), KEY_PREFIX);
    c.consumed = full_size;
    c.notes
        .push(format!("Img3 image type {label}; {tags_size} B of tags"));
    c.notes
        .push("Img3 fields name no ISA; the ISA comes from the DATA payload".to_string());
    if let Some(kind) = tags.iter().find(|t| t.code == TAG_TYPE) {
        let named = kind
            .data
            .get(..4)
            .map(|b| code_text(u32::from_le_bytes(b.try_into().expect("four bytes"))));
        if named.as_deref() != Some(label.as_str()) {
            c.notes.push(format!(
                "TYPE tag names {}, the header names {label}",
                named.unwrap_or_else(|| "nothing".to_string())
            ));
        }
    }
    if tags_end < full_size && !is_padding(&image[tags_end..]) {
        c.notes.push(format!(
            "{} B between the tag area and the full size at 0x{tags_end:X}",
            full_size - tags_end
        ));
    }
    c.push_metadata("apple_img3_type", "Img3 type", label.clone());
    describe_tags(&mut c, &tags, shsh_offset);
    let Some(payload) = payload else {
        c.notes.push("No DATA tag; nothing to analyze".to_string());
        return Ok(c);
    };
    let offset = payload.offset + TAG_HEADER_SIZE;
    c.push_metadata(
        "apple_img3_data_offset",
        "DATA file offset",
        format!("0x{offset:X}"),
    );
    c.push_metadata(
        "apple_img3_data_size",
        "DATA size (B)",
        payload.data.len() as u64,
    );
    if keybags.is_empty() {
        c.children.push(Child::stored(label, offset, payload.data));
    } else {
        let bags = keybag_text(&keybags);
        c.notes.push(format!(
            "DATA is encrypted ({bags}); the key is wrapped with the device GID key; not decrypted"
        ));
        c.push_metadata("apple_img3_keybags", "Keybags", bags);
        c.children.push(Child::opaque(label, offset, payload.data));
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magics_are_little_endian_fourccs() {
        assert!(detect(b"3gmI"));
        assert!(!detect(b"Img3"));
        assert_eq!(code_text(TAG_DATA), "DATA");
        assert_eq!(&TAG_KBAG.to_le_bytes(), b"GABK");
    }

    #[test]
    fn keybag_sizes_follow_the_key_bits() {
        let mut data = vec![0u8; 8 + 16 + 32];
        data[0..4].copy_from_slice(&CRYPT_PRODUCTION.to_le_bytes());
        data[4..8].copy_from_slice(&256u32.to_le_bytes());
        let tag = Tag {
            code: TAG_KBAG,
            offset: 0,
            data: &data,
        };
        assert_eq!(keybag(&tag).unwrap().key_bits, 256);
        let short = Tag {
            data: &data[..40],
            ..tag
        };
        assert!(keybag(&short).is_err());
    }
}
