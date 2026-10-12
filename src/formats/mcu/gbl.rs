//! Silicon Labs Gecko Bootloader files (GBL v3): a stream of tags, each a
//! little-endian `tagId` and `length` followed by `length` payload bytes,
//! from the header tag to the end tag.
//!
//! Sources: `gecko_sdk` v4.5.1
//! (`8a2efd2cb191cb250fd4c1e655b16b8a80be1997`)
//! `platform/bootloader/parser/gbl/btl_gbl_format.h` (tag IDs and payload
//! structures), `btl_gbl_format.c` (tag order and occurrence table) and
//! `btl_gbl_parser.c` (header, ordering, encryption and CRC rules);
//! `simplicity_sdk` v2025.6.3 for the delta tags; Silicon Labs "Gecko
//! Bootloader File Format" (docs.silabs.com, Wi-SUN 2.9.2 bootloader user
//! guide).
//!
//! The end tag's `gblCrc` makes the reflected IEEE CRC-32 register over the
//! file through `gblCrc` equal `0xDEBB20E3`, which is the same as `gblCrc`
//! being the zlib CRC-32 of the bytes before it.

use super::*;
use crate::formats::checksum;
use crate::formats::compressed::Codec;

/// Tag ID and length.
const TAG_HEADER_SIZE: usize = 8;

/// `GblHeader_t`: `version`, `type`.
const HEADER_LENGTH: usize = 8;

/// `GBL_COMPATIBILITY_MAJOR_VERSION` in the top byte of `version`.
const GBL_COMPATIBILITY_MAJOR_VERSION: u32 = 0x0300_0000;
const GBL_MAJOR_VERSION_MASK: u32 = 0xff00_0000;

/// Header `type` bits.
const GBL_TYPE_ENCRYPTION_AESCCM: u32 = 0x0000_0001;
const GBL_TYPE_SIGNATURE_ECDSA: u32 = 0x0000_0100;

/// Version dependency records: `imageType`, `statement`, reserved,
/// `version`.
const VERSION_DEPENDENCY_SIZE: usize = 8;

/// `GblSeUpgrade_t` and `GblBootloader_t`: two words before the image.
const IMAGE_TAG_FIELDS_SIZE: usize = 8;

/// `GblEncryptionInitAesCcm_t`: `msgLen` and a 12-byte nonce.
const ENCRYPTION_INIT_LENGTH: usize = 16;

/// `ApplicationData_t` is 28 bytes; the parser copies it from a 64-byte
/// buffer (`GBL_PARSER_BUFFER_SIZE`), so longer tags cannot be parsed.
const APPLICATION_DATA_SIZE: usize = 28;
const GBL_PARSER_BUFFER_SIZE: usize = 64;

/// Program tags start with `flashStartAddress`.
const FLASH_ADDRESS_SIZE: usize = 4;

/// `ApplicationCertificate_t`: version, flags, P-256 key, version,
/// signature.
const CERTIFICATE_LENGTH: usize = 136;
const CERTIFICATE_VERSION_OFFSET: usize = 68;

/// `GblSignatureEcdsaP256_t`: `r` and `s`.
const SIGNATURE_LENGTH: usize = 64;

/// `GblEnd_t`: `gblCrc`.
const END_LENGTH: usize = 4;

/// The order the SE upgrade tag takes in `BOOTLOADER_SE_UPGRADE_NO_STAGING`
/// builds, ahead of encryption init and application info.
const SE_UPGRADE_NO_STAGING_ORDER: u8 = 3;

/// `ApplicationData_t.type` bits (`application_properties.h`).
const APPLICATION_TYPES: &[(u32, &str)] = &[
    (0x01, "Zigbee"),
    (0x02, "Thread"),
    (0x04, "Flex"),
    (0x08, "Bluetooth"),
    (0x10, "MCU"),
    (0x20, "Bluetooth app"),
    (0x40, "Bootloader"),
    (0x80, "Z-Wave"),
];

/// What a tag carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Header,
    VersionDependency,
    SeUpgrade,
    EncryptionInit,
    Application,
    Bootloader,
    Metadata,
    Program,
    ProgramLz4,
    ProgramLzma,
    Delta,
    EncryptedData,
    Certificate,
    Signature,
    End,
}

/// One row of the parser's tag table.
struct TagInfo {
    id: u32,
    kind: Kind,
    name: &'static str,
    /// Position in the tag sequence.
    order: u8,
    /// May occur once.
    single: bool,
    /// Stays in plaintext in an encrypted file. The SE upgrade tag does so
    /// only in no-staging builds and is accepted either way.
    unencrypted: bool,
}

const fn tag(
    id: u32,
    kind: Kind,
    name: &'static str,
    order: u8,
    single: bool,
    unencrypted: bool,
) -> TagInfo {
    TagInfo {
        id,
        kind,
        name,
        order,
        single,
        unencrypted,
    }
}

/// `btl_gbl_format.c` tag table (`gecko_sdk` v4.5.1) plus the `simplicity_sdk`
/// delta tags. The encryption header tag `0xFB0505FB` is defined in
/// `btl_gbl_format.h` but absent from the table, so it is unknown here as
/// in the reference parser.
#[rustfmt::skip]
const TAGS: &[TagInfo] = &[
    //  tagId        kind                     name                          order  single unencrypted
    tag(0x03a6_17eb, Kind::Header,            "header",                     1,     true,  true),
    tag(0x76a6_17eb, Kind::VersionDependency, "version dependency",         2,     false, true),
    tag(0x5ea6_17eb, Kind::SeUpgrade,         "SE upgrade",                 6,     true,  true),
    tag(0xfa06_06fa, Kind::EncryptionInit,    "encryption init",            4,     true,  true),
    tag(0xf40a_0af4, Kind::Application,       "application info",           5,     true,  false),
    tag(0xf509_09f5, Kind::Bootloader,        "bootloader",                 7,     true,  false),
    tag(0xf608_08f6, Kind::Metadata,          "metadata",                   8,     false, false),
    tag(0xfe01_01fe, Kind::Program,           "program data",               8,     false, false),
    tag(0xfd03_03fd, Kind::Program,           "erase and program",          8,     false, false),
    tag(0xfd05_05fd, Kind::ProgramLz4,        "program LZ4",                8,     false, false),
    tag(0xfd07_07fd, Kind::ProgramLzma,       "program LZMA",               8,     false, false),
    tag(0xf80a_0af8, Kind::Delta,             "delta",                      8,     false, false),
    tag(0xf80b_0bf8, Kind::Delta,             "delta LZ4",                  8,     false, false),
    tag(0xf80c_0cf8, Kind::Delta,             "delta LZMA",                 8,     false, false),
    tag(0xf907_07f9, Kind::EncryptedData,     "encrypted data",             9,     false, true),
    tag(0xf30b_0bf3, Kind::Certificate,       "ECDSA P-256 certificate",    10,    true,  true),
    tag(0xf70a_0af7, Kind::Signature,         "ECDSA P-256 signature",      11,    true,  true),
    tag(0xfc04_04fc, Kind::End,               "end",                        12,    true,  true),
];

fn tag_info(id: u32) -> Option<&'static TagInfo> {
    TAGS.iter().find(|t| t.id == id)
}

/// The header tag ID, stored little-endian at offset 0.
const HEADER_TAG: u32 = TAGS[0].id;

/// Whether the file starts with the GBL v3 header tag ID.
pub(super) fn has_magic(data: &[u8]) -> bool {
    le_u32(data, 0).is_ok_and(|word| word == HEADER_TAG)
}

/// The order after `info`, or `None` when the tag comes too late. A
/// single-occurrence tag moves the order past itself, a repeatable tag to
/// itself, and encrypted data leaves it unchanged so the tags it decrypts
/// to continue the sequence.
fn next_order(current: u8, info: &TagInfo) -> Option<u8> {
    let order = if info.kind == Kind::SeUpgrade && current <= SE_UPGRADE_NO_STAGING_ORDER {
        SE_UPGRADE_NO_STAGING_ORDER
    } else {
        info.order
    };
    if order < current {
        return None;
    }
    Some(match info.kind {
        Kind::EncryptedData => current,
        _ if info.single => order + 1,
        _ => order,
    })
}

/// Walk state between tags.
struct Walk {
    /// Current tag order.
    order: u8,
    /// Header `type` has `GBL_TYPE_ENCRYPTION_AESCCM`.
    encrypted: bool,
    /// Bytes in load sections so far, against [`MAX_PAYLOAD`].
    section_bytes: usize,
    /// Load sections, capped at [`MAX_COMPONENTS`].
    sections: Sections,
    /// Children left out at [`MAX_COMPONENTS`].
    unlisted: usize,
    /// Encrypted data tags seen.
    encrypted_tags: usize,
    /// A signature tag was seen.
    signed: bool,
}

/// Parse a GBL file: plaintext program tags become load sections,
/// compressed ones are decoded, and the bootloader, SE upgrade, metadata,
/// delta and encrypted tags are separate (mostly opaque) children.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let mut c = Container::new(
        FileFormat::Gbl,
        Layout::Gbl.label(),
        Layout::Gbl.key_prefix(),
    );
    let gbl_type = parse_header(&mut c, data)?;
    let mut walk = Walk {
        order: TAGS[0].order + 1,
        encrypted: gbl_type & GBL_TYPE_ENCRYPTION_AESCCM != 0,
        section_bytes: 0,
        sections: Sections::new(),
        unlisted: 0,
        encrypted_tags: 0,
        signed: false,
    };
    let mut pos = TAG_HEADER_SIZE + HEADER_LENGTH;
    loop {
        if data.len() - pos < TAG_HEADER_SIZE {
            return Err(error(format!(
                "Missing GBL end tag: truncated tag at 0x{pos:X}"
            )));
        }
        let id = le_u32(data, pos)?;
        let length = le_u32(data, pos + 4)? as usize;
        let info = tag_info(id)
            .ok_or_else(|| error(format!("Unknown GBL tag 0x{id:08X} at 0x{pos:X}")))?;
        let payload_offset = pos + TAG_HEADER_SIZE;
        let payload = data
            .get(payload_offset..)
            .and_then(|rest| rest.get(..length))
            .ok_or_else(|| {
                error(format!(
                    "Truncated GBL {} tag at 0x{pos:X}: length {length} B",
                    info.name
                ))
            })?;
        walk.order = next_order(walk.order, info).ok_or_else(|| {
            error(format!(
                "Invalid GBL tag order: {} tag at 0x{pos:X}",
                info.name
            ))
        })?;
        if walk.encrypted && !info.unencrypted {
            return Err(error(format!(
                "Invalid GBL {} tag at 0x{pos:X}: plaintext in an encrypted file",
                info.name
            )));
        }
        if info.kind == Kind::End {
            finish(&mut c, data, pos, payload, walk, gbl_type)?;
            return Ok(c);
        }
        apply_tag(&mut c, &mut walk, info, pos, payload_offset, payload)?;
        pos = payload_offset + length;
    }
}

/// Header tag at offset 0: length 8, a v3 `version`, and `type`. Returns
/// `type`.
fn parse_header(c: &mut Container<'_>, data: &[u8]) -> Result<u32> {
    if le_u32(data, 0)? != HEADER_TAG {
        return Err(error("Missing GBL header tag at 0x0"));
    }
    let length = le_u32(data, 4)? as usize;
    if length != HEADER_LENGTH {
        return Err(error(format!(
            "Invalid GBL header tag length {length} B at 0x4"
        )));
    }
    let version = le_u32(data, 8)?;
    if version & GBL_MAJOR_VERSION_MASK != GBL_COMPATIBILITY_MAJOR_VERSION {
        return Err(error(format!(
            "Unsupported GBL version 0x{version:08X} at 0x8"
        )));
    }
    let gbl_type = le_u32(data, 12)?;
    c.push_metadata("gbl_version", "GBL version", format!("0x{version:08X}"));
    c.push_metadata("gbl_type", "GBL type", format!("0x{gbl_type:08X}"));
    Ok(gbl_type)
}

/// Record one tag between the header and the end tag.
fn apply_tag<'a>(
    c: &mut Container<'a>,
    walk: &mut Walk,
    info: &TagInfo,
    pos: usize,
    payload_offset: usize,
    payload: &'a [u8],
) -> Result<()> {
    match info.kind {
        // The header is single-occurrence and order 1, so the order check
        // rejects a second one before this point.
        Kind::Header | Kind::End => {}
        Kind::VersionDependency => version_dependencies(c, pos, payload)?,
        Kind::SeUpgrade => {
            let version = image_tag_version(info, pos, payload)?;
            c.notes.push(format!(
                "SE upgrade tag at 0x{pos:X}: version 0x{version:08X}; encrypted Secure Element image; opaque"
            ));
            push_child(
                c,
                walk,
                Child::opaque("SE upgrade", payload_offset, payload),
            );
        }
        Kind::EncryptionInit => {
            expect_length(info, pos, payload, ENCRYPTION_INIT_LENGTH)?;
            let message_length = le_u32(payload, 0)?;
            c.push_metadata(
                "gbl_encrypted_length",
                "Encrypted message length (B)",
                u64::from(message_length),
            );
        }
        Kind::Application => application_info(c, info, pos, payload)?,
        Kind::Bootloader => {
            let version = image_tag_version(info, pos, payload)?;
            let address = le_u32(payload, 4)?;
            c.notes.push(format!(
                "Bootloader tag at 0x{pos:X}: version 0x{version:08X}; address 0x{address:X}"
            ));
            let image = &payload[IMAGE_TAG_FIELDS_SIZE..];
            if !image.is_empty() {
                let offset = payload_offset + IMAGE_TAG_FIELDS_SIZE;
                push_child(c, walk, Child::stored("Bootloader", offset, image));
            }
        }
        Kind::Metadata => push_child(c, walk, Child::opaque("Metadata", payload_offset, payload)),
        Kind::Program | Kind::ProgramLz4 | Kind::ProgramLzma => {
            program_data(c, walk, info, pos, payload_offset, payload)?;
        }
        Kind::Delta => push_child(
            c,
            walk,
            Child::opaque(
                format!("Delta patch ({})", info.name),
                payload_offset,
                payload,
            ),
        ),
        Kind::EncryptedData => {
            walk.encrypted_tags += 1;
            push_child(
                c,
                walk,
                Child::opaque("Encrypted GBL data", payload_offset, payload),
            );
        }
        Kind::Certificate => {
            expect_length(info, pos, payload, CERTIFICATE_LENGTH)?;
            let version = le_u32(payload, CERTIFICATE_VERSION_OFFSET)?;
            c.push_metadata(
                "gbl_certificate_version",
                "Certificate version",
                format!("0x{version:08X}"),
            );
            c.notes
                .push("ECDSA P-256 certificate present; not verified".to_string());
        }
        Kind::Signature => {
            expect_length(info, pos, payload, SIGNATURE_LENGTH)?;
            walk.signed = true;
            c.notes
                .push("ECDSA P-256 signature present; not verified".to_string());
        }
    }
    Ok(())
}

/// A fixed-size tag must have exactly its structure's length.
fn expect_length(info: &TagInfo, pos: usize, payload: &[u8], expected: usize) -> Result<()> {
    if payload.len() == expected {
        return Ok(());
    }
    Err(error(format!(
        "Invalid GBL {} tag length {} B at 0x{:X}; expected {expected} B",
        info.name,
        payload.len(),
        pos + 4
    )))
}

/// List a child unless [`MAX_COMPONENTS`] is reached.
fn push_child<'a>(c: &mut Container<'a>, walk: &mut Walk, child: Child<'a>) {
    if c.children.len() < MAX_COMPONENTS {
        c.children.push(child);
    } else {
        walk.unlisted += 1;
    }
}

/// `version` of a bootloader or SE upgrade tag (its second word).
fn image_tag_version(info: &TagInfo, pos: usize, payload: &[u8]) -> Result<u32> {
    if payload.len() < IMAGE_TAG_FIELDS_SIZE {
        return Err(error(format!(
            "Truncated GBL {} tag at 0x{pos:X}: {} B",
            info.name,
            payload.len()
        )));
    }
    match info.kind {
        // GblBootloader_t: bootloaderVersion, address.
        Kind::Bootloader => le_u32(payload, 0),
        // GblSeUpgrade_t: blobSize, version.
        _ => le_u32(payload, 4),
    }
}

/// Version dependency records as metadata.
fn version_dependencies(c: &mut Container<'_>, pos: usize, payload: &[u8]) -> Result<()> {
    if payload.is_empty() || payload.len() % VERSION_DEPENDENCY_SIZE != 0 {
        return Err(error(format!(
            "Invalid GBL version dependency tag length {} B at 0x{:X}",
            payload.len(),
            pos + 4
        )));
    }
    for (i, record) in payload.chunks_exact(VERSION_DEPENDENCY_SIZE).enumerate() {
        let image = match record[0] {
            1 => "application".to_string(),
            2 => "bootloader".to_string(),
            3 => "SE".to_string(),
            other => format!("image type {other}"),
        };
        let statement = record[1];
        let version = le_u32(record, 4)?;
        c.push_metadata(
            format!("gbl_version_dependency_{i}"),
            format!("Version dependency {}", i + 1),
            format!("{image}; statement 0x{statement:02X}; version 0x{version:08X}"),
        );
    }
    Ok(())
}

/// `ApplicationData_t`: `type` bits, `version`, `capabilities`,
/// `productId[16]`.
fn application_info(
    c: &mut Container<'_>,
    info: &TagInfo,
    pos: usize,
    payload: &[u8],
) -> Result<()> {
    if !(APPLICATION_DATA_SIZE..=GBL_PARSER_BUFFER_SIZE).contains(&payload.len()) {
        return Err(error(format!(
            "Invalid GBL {} tag length {} B at 0x{:X}",
            info.name,
            payload.len(),
            pos + 4
        )));
    }
    let app_type = le_u32(payload, 0)?;
    let names: Vec<&str> = APPLICATION_TYPES
        .iter()
        .filter(|(bit, _)| app_type & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    let type_text = if names.is_empty() {
        format!("0x{app_type:08X}")
    } else {
        format!("0x{app_type:08X} ({})", names.join(", "))
    };
    c.push_metadata("gbl_application_type", "Application type", type_text);
    c.push_metadata(
        "gbl_application_version",
        "Application version",
        format!("0x{:08X}", le_u32(payload, 4)?),
    );
    c.push_metadata(
        "gbl_application_capabilities",
        "Application capabilities",
        format!("0x{:08X}", le_u32(payload, 8)?),
    );
    c.push_metadata(
        "gbl_product_id",
        "Product ID",
        hex_string(&payload[12..APPLICATION_DATA_SIZE]),
    );
    Ok(())
}

/// A program tag: `flashStartAddress`, then the bytes to write there,
/// stored, as a raw LZ4 block stream, or as an LZMA-alone stream
/// (properties, dictionary size, 8-byte size). A tag of four bytes or less
/// carries no data and sets no address. A compressed tag that does not
/// decode is listed as an opaque component and noted.
fn program_data<'a>(
    c: &mut Container<'a>,
    walk: &mut Walk,
    info: &TagInfo,
    pos: usize,
    payload_offset: usize,
    payload: &'a [u8],
) -> Result<()> {
    if payload.len() <= FLASH_ADDRESS_SIZE {
        return Ok(());
    }
    let address = u64::from(le_u32(payload, 0)?);
    let stored = &payload[FLASH_ADDRESS_SIZE..];
    let offset = payload_offset + FLASH_ADDRESS_SIZE;
    let label = format!("Load section {}", c.sections.len() + 1);
    let codec = match info.kind {
        Kind::ProgramLz4 => Codec::Lz4Block,
        Kind::ProgramLzma => Codec::Lzma,
        _ => {
            walk.section_bytes = walk.section_bytes.saturating_add(stored.len());
            walk.sections
                .push(c, stored_section(label, address, offset, stored));
            return Ok(());
        }
    };
    let budget = MAX_PAYLOAD.saturating_sub(walk.section_bytes);
    match compressed::decode_limited(codec, stored, budget) {
        Ok(decoded) => {
            walk.section_bytes = walk.section_bytes.saturating_add(decoded.data.len());
            walk.sections.push(
                c,
                transformed_section(
                    label,
                    address,
                    offset,
                    stored.len(),
                    decoded.data,
                    codec.name(),
                ),
            );
        }
        Err(e) => {
            c.notes.push(format!(
                "GBL {} tag at 0x{pos:X} does not decode ({e}); listed as opaque",
                info.name
            ));
            let child = Child::opaque(format!("Undecoded {}", info.name), offset, stored);
            push_child(c, walk, child);
        }
    }
    Ok(())
}

/// End tag: `gblCrc` over everything before it; only erased-flash padding
/// may follow.
fn finish(
    c: &mut Container<'_>,
    data: &[u8],
    pos: usize,
    payload: &[u8],
    walk: Walk,
    gbl_type: u32,
) -> Result<()> {
    if payload.len() != END_LENGTH {
        return Err(error(format!(
            "Invalid GBL end tag length {} B at 0x{:X}; expected {END_LENGTH} B",
            payload.len(),
            pos + 4
        )));
    }
    let crc_at = pos + TAG_HEADER_SIZE;
    let stored = le_u32(data, crc_at)?;
    let computed = checksum::crc32(&data[..crc_at]);
    if stored != computed {
        return Err(error(format!(
            "Invalid GBL end tag CRC-32 0x{stored:08X} at 0x{crc_at:X}; computed 0x{computed:08X}"
        )));
    }
    let end = crc_at + END_LENGTH;
    if !is_padding(&data[end..]) {
        return Err(error(format!(
            "Unexpected {} B after the GBL end tag at 0x{end:X}",
            data.len() - end
        )));
    }
    c.consumed = end;
    c.notes.insert(
        0,
        format!(
            "GBL v3: {}; end-tag CRC-32 verified; the format names no ISA",
            count(c.sections.len(), "program section", "program sections")
        ),
    );
    walk.sections.finish(c);
    if walk.encrypted {
        c.opaque = true;
        c.notes.push(format!(
            "Encrypted GBL (AES-CCM): {}; the key is not in the file",
            count(
                walk.encrypted_tags,
                "encrypted data tag",
                "encrypted data tags"
            )
        ));
    }
    if gbl_type & GBL_TYPE_SIGNATURE_ECDSA != 0 && !walk.signed {
        c.notes
            .push("Header type declares an ECDSA signature; no signature tag present".to_string());
    }
    if walk.unlisted > 0 {
        c.notes.push(format!(
            "{} not listed (limit {MAX_COMPONENTS})",
            count(walk.unlisted, "further tag", "further tags")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_table_ids_are_unique() {
        for (i, t) in TAGS.iter().enumerate() {
            assert!(TAGS[i + 1..].iter().all(|u| u.id != t.id), "{}", t.name);
        }
        assert_eq!(HEADER_TAG.to_le_bytes(), [0xeb, 0x17, 0xa6, 0x03]);
    }

    #[test]
    fn tag_order_follows_the_parser_table() {
        let info = |kind: Kind| TAGS.iter().find(|t| t.kind == kind).unwrap();
        // Application info (single, 5) moves the order to 6; program data
        // (repeatable, 8) keeps it at 8; encrypted data leaves it alone.
        assert_eq!(next_order(2, info(Kind::Application)), Some(6));
        assert_eq!(next_order(6, info(Kind::Program)), Some(8));
        assert_eq!(next_order(8, info(Kind::Program)), Some(8));
        assert_eq!(next_order(8, info(Kind::Application)), None);
        assert_eq!(next_order(6, info(Kind::EncryptedData)), Some(6));
        // SE upgrade: order 3 right after the header, else 6.
        assert_eq!(next_order(2, info(Kind::SeUpgrade)), Some(4));
        assert_eq!(next_order(6, info(Kind::SeUpgrade)), Some(7));
        assert_eq!(next_order(8, info(Kind::SeUpgrade)), None);
    }
}
