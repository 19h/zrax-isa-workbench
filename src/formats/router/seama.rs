//! D-Link SEAMA (`OpenWrt` firmware-utils `seama.h`, `seama.c` and
//! `oseama.c`).
//!
//! Header, network byte order: magic `0x5EA3A417` (0), reserved (4, 16
//! bits), metadata size (6, 16 bits), image size (8). An entity (image size
//! above zero) continues with the MD5 digest of the image (12, 16 bytes;
//! verified, as `seama.c` `parse_seama_header` does),
//! the metadata and the image. A seal (image size zero) has no digest; its
//! metadata is followed by entities, each a complete SEAMA file
//! (`seama -s` copies them in whole). Metadata is NUL-terminated
//! `key=value` text padded with NULs to four bytes.

use super::*;

/// `SEAMA_MAGIC` `0x5EA3A417`, big-endian.
pub(super) const MAGIC: [u8; 4] = [0x5e, 0xa3, 0xa4, 0x17];

/// Header fields.
const METADATA_SIZE: usize = 6;
const IMAGE_SIZE: usize = 8;

/// `struct seama_hdr`, and the MD5 digest that follows it in an entity.
const HEADER_SIZE: usize = 12;
const DIGEST_SIZE: usize = 16;

/// Metadata strings listed in a note, each cut after `MAX_METADATA_CHARS`.
const MAX_LISTED_METADATA: usize = 16;
const MAX_METADATA_CHARS: usize = 128;

/// The sizes one SEAMA header declares.
struct Header {
    metadata_size: usize,
    image_size: usize,
}

fn read_header(data: &[u8], at: usize) -> Result<Header> {
    let header = slice(data, at, HEADER_SIZE, "SEAMA header")?;
    if header[..4] != MAGIC {
        return Err(error(format!("Missing SEAMA magic at 0x{at:X}")));
    }
    Ok(Header {
        metadata_size: usize::from(be_u16(header, METADATA_SIZE)?),
        image_size: to_usize(be_u32(header, IMAGE_SIZE)?),
    })
}

/// A note listing the metadata strings, if there are any.
fn metadata_note(metadata: &[u8]) -> Option<String> {
    let entries: Vec<&[u8]> = metadata
        .split(|&b| b == 0)
        .filter(|entry| !entry.is_empty())
        .collect();
    if entries.is_empty() {
        return None;
    }
    let mut listed: Vec<String> = entries
        .iter()
        .take(MAX_LISTED_METADATA)
        .map(|entry| display_text(entry, MAX_METADATA_CHARS))
        .collect();
    if entries.len() > MAX_LISTED_METADATA {
        listed.push(format!(
            "{} more entries",
            entries.len() - MAX_LISTED_METADATA
        ));
    }
    Some(format!("Metadata: {}", listed.join("; ")))
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let first = read_header(data, 0)?;
    if first.image_size == 0 {
        seal(data, &first)
    } else {
        entity(data, &first)
    }
}

/// An entity: header, MD5 digest, metadata, image; only padding after it.
fn entity<'a>(data: &'a [u8], header: &Header) -> Result<Container<'a>> {
    let digest = slice(data, HEADER_SIZE, DIGEST_SIZE, "SEAMA MD5 digest")?;
    let metadata_offset = HEADER_SIZE + DIGEST_SIZE;
    let metadata = slice(
        data,
        metadata_offset,
        header.metadata_size,
        "SEAMA metadata",
    )?;
    let image_offset = metadata_offset + header.metadata_size;
    let image = slice(data, image_offset, header.image_size, "SEAMA image")?;
    let end = image_offset + header.image_size;
    let rest = &data[end..];
    if !is_padding(rest) {
        return Err(error(format!(
            "Unexpected {} after the SEAMA entity at 0x{end:X}",
            size_text(rest.len())
        )));
    }

    // `seama -x` rejects an entity whose digest does not match its image.
    let computed = checksum::md5(image);
    if computed[..] != *digest {
        return Err(error(format!(
            "Invalid SEAMA image MD5 {}, computed {}",
            hex_digest(digest),
            hex_digest(&computed)
        )));
    }
    let digest = hex_digest(digest);
    let mut c = Container::new(FileFormat::Seama, "D-Link SEAMA entity", "seama");
    c.consumed = end;
    c.notes.push(format!(
        "D-Link SEAMA entity; {} image; image MD5 {digest} verified (an integrity check, not authentication); the header names no architecture",
        size_text(header.image_size)
    ));
    if let Some(note) = metadata_note(metadata) {
        c.notes.push(note);
    }
    c.push_metadata("seama_md5", "Image MD5 (verified)", digest);
    c.push_metadata(
        "seama_metadata_size",
        "Metadata size (B)",
        header.metadata_size as u64,
    );
    let mut extractor = Extractor::default();
    c.children
        .push(extractor.component("Image".into(), image_offset, image, &mut c.notes));
    Ok(c)
}

/// A seal: header and metadata, then entities until the end of the file or
/// padding. Each entity is listed whole and classified as its own SEAMA
/// file; a nested seal has no length and holds everything after it.
fn seal<'a>(data: &'a [u8], header: &Header) -> Result<Container<'a>> {
    let metadata = slice(
        data,
        HEADER_SIZE,
        header.metadata_size,
        "SEAMA seal metadata",
    )?;
    let mut c = Container::new(FileFormat::Seama, "D-Link SEAMA seal", "seama");
    let mut pos = HEADER_SIZE + header.metadata_size;
    let mut entities = 0usize;
    while pos < data.len() && !is_padding(&data[pos..]) {
        let entity = read_header(data, pos)?;
        entities += 1;
        let label = format!("Entity {entities}");
        if entity.image_size == 0 {
            if c.children.len() < MAX_COMPONENTS {
                c.children
                    .push(Child::stored(format!("{label} (seal)"), pos, &data[pos..]));
            }
            pos = data.len();
            break;
        }
        let size = (HEADER_SIZE + DIGEST_SIZE + entity.metadata_size)
            .checked_add(entity.image_size)
            .ok_or_else(|| error(format!("Invalid SEAMA entity size at 0x{pos:X}")))?;
        let bytes = slice(data, pos, size, "SEAMA entity")?;
        if c.children.len() < MAX_COMPONENTS {
            c.children.push(Child::stored(label, pos, bytes));
        }
        pos += size;
    }
    c.consumed = pos;
    let count = if entities == 1 {
        "1 entity".to_string()
    } else {
        format!("{entities} entities")
    };
    c.notes.push(format!(
        "D-Link SEAMA seal with {count}; each entity is classified as its own SEAMA image; the header names no architecture"
    ));
    if entities > c.children.len() {
        c.notes.push(format!(
            "{} further entities were not listed (limit {MAX_COMPONENTS})",
            entities - c.children.len()
        ));
    }
    if let Some(note) = metadata_note(metadata) {
        c.notes.push(note);
    }
    c.push_metadata(
        "seama_metadata_size",
        "Metadata size (B)",
        header.metadata_size as u64,
    );
    c.push_metadata("seama_entities", "Entities", entities as u64);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_lists_nul_separated_strings() {
        let note = metadata_note(b"dev=/dev/mtdblock/1\0type=firmware\0\0\0").unwrap();
        assert_eq!(note, "Metadata: dev=/dev/mtdblock/1; type=firmware");
        assert!(metadata_note(&[0; 8]).is_none());
    }

    #[test]
    fn metadata_listing_is_bounded() {
        let many: Vec<u8> = (0..40).flat_map(|_| b"k=v\0".iter().copied()).collect();
        let note = metadata_note(&many).unwrap();
        assert!(note.ends_with("24 more entries"), "{note}");
    }
}
