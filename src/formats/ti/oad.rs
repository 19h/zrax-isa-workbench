//! `SimpleLink` over-the-air download (OAD) images and external-flash
//! metadata (`oad_image_header.h`). All fields are little-endian.
use super::*;

/// Image identifiers with the documented fixed header.
const IMAGE_IDS: [&[u8; 8]; 7] = [
    b"CC26x2R1",
    b"CC13x2R1",
    b"CC13x4  ",
    b"CC26x3  ",
    b"CC26x4  ",
    b"OAD IMG ",
    b"CC23x0R2",
];
/// Generic identifier that does not name a device family.
const GENERIC_ID: &[u8; 8] = b"OAD IMG ";
pub(super) const METADATA_ID: &[u8; 8] = b"OAD NVM1";

const HEADER_SIZE: usize = 44;
const METADATA_SIZE: usize = 52;

const SEGMENT_BOUNDARY: u8 = 0;
const SEGMENT_CONTIGUOUS: u8 = 1;
const SEGMENT_SECURITY: u8 = 3;

pub(super) fn is_image(data: &[u8]) -> bool {
    data.get(..8)
        .is_some_and(|id| IMAGE_IDS.iter().any(|known| known.as_slice() == id))
}

/// Fixed header: ID, CRC (8), BIM and metadata versions (12, 13), image
/// type (18), length (24), entry (28), header length (40). Variable-length
/// segments (type at +0, length at +4) follow up to the image length.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    if !is_image(data) {
        return Err(error("Unknown OAD image identifier"));
    }
    ensure(data, 0, HEADER_SIZE)?;
    let len = le_u32(data, 24)? as usize;
    let header = usize::from(le_u16(data, 40)?);
    if header < HEADER_SIZE || len < header {
        return Err(error("Invalid OAD length/header"));
    }
    ensure(data, 0, len)?;
    expect_padding(data, len)?;
    let image = &data[..len];
    let mut c = Container::new(Variant::Oad);
    let image_type = data[18];
    if image_type < 0x10 && &data[..8] != GENERIC_ID {
        // Image types below 0x10 run on the wireless MCU named by the ID.
        c.isa = Isa::Arm;
        c.bits = 32;
    } else if (0x10..0x20).contains(&image_type) || image_type >= 0x40 {
        c.opaque = true;
        c.notes
            .push("OAD user-data or reserved image type; payload ISA analysis was skipped".into());
    } else {
        c.notes.push("Generic or host-processor OAD image; header does not uniquely identify the payload ISA".into());
    }
    c.entry = Some(u64::from(le_u32(data, 28)?));
    let stored_crc = le_u32(data, 8)?;
    c.notes.push(format!(
        "Image identifier {}; BIM version {}; metadata version {}; image type {}",
        String::from_utf8_lossy(&data[..8]),
        data[12],
        data[13],
        data[18]
    ));
    c.notes.push(if stored_crc == u32::MAX {
        "OAD CRC is unset".into()
    } else if crc32(&image[12..]) == stored_crc {
        "OAD CRC32 verified over image bytes from offset 12".into()
    } else {
        "OAD CRC32 mismatch (image may be damaged or header status bytes modified)".into()
    });
    let mut pos = header;
    while pos < len {
        ensure(image, pos, 8)?;
        let kind = data[pos];
        let size = le_u32(data, pos + 4)? as usize;
        if size < 8 {
            return Err(error("OAD segment length is smaller than its header"));
        }
        ensure(image, pos, size)?;
        match kind {
            SEGMENT_BOUNDARY => {
                if size < 24 {
                    return Err(error("Truncated OAD image-boundary segment"));
                }
            }
            SEGMENT_CONTIGUOUS => {
                // 8-byte segment header, then the load address and the image.
                if size < 12 {
                    return Err(error("Truncated OAD contiguous-image segment"));
                }
                let address = u64::from(le_u32(data, pos + 8)?);
                let payload_size = size - 12;
                if address + payload_size as u64 > 1u64 << 32 {
                    return Err(error("OAD destination overflow"));
                }
                let payload = slice(data, pos + 12, payload_size)?;
                c.push_section(address, pos + 12, Cow::Borrowed(payload))?;
            }
            SEGMENT_SECURITY => {
                if size < 85 {
                    return Err(error("Truncated OAD security segment"));
                }
                c.notes.push(
                    "OAD security segment present; signature authenticity is not verified".into(),
                );
            }
            _ => c.notes.push(format!(
                "OAD segment type {kind} retained as metadata ({size} B)"
            )),
        }
        pos += size;
    }
    if c.sections.is_empty() {
        return Err(error("OAD image has no contiguous payload"));
    }
    c.consumed = len;
    Ok(c)
}

/// External-flash metadata describes an image stored elsewhere.
pub(super) fn parse_metadata(data: &[u8]) -> Result<Container<'_>> {
    if !data.starts_with(METADATA_ID) {
        return Err(error("Invalid OAD metadata identifier"));
    }
    ensure(data, 0, METADATA_SIZE)?;
    let mut c = Container::new(Variant::OadMetadata);
    c.opaque = true;
    c.consumed = METADATA_SIZE;
    c.notes.push(format!(
        "External-flash metadata entry; advertised image length {} B; image is stored separately",
        le_u32(data, 24)?
    ));
    Ok(c)
}
