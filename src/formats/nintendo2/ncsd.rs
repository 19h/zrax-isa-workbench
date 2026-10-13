//! 3DS NCSD images (3dbrew "NCSD", oldid 22570; ctrtool `cci.h`; makerom
//! `ncsd.h`), all little-endian: an RSA-2048 signature (0x100), `NCSD` at
//! 0x100, the image size in media units (4) at 0x104, the media ID (8) at
//! 0x108, one FS type byte and one crypt type byte per partition at 0x110
//! and 0x118, and eight partition offset and size pairs in media units
//! (4 + 4) at 0x120.
//!
//! Two specializations share the header. A CTR cart image (CCI) has every
//! FS and crypt type 0 (ctrtool `CciFsSnapshotGenerator`), partition flags
//! at 0x188 (media platform at \[4\], media type at \[5\], media unit size
//! exponent at \[6\]: a unit is `0x200 << flags[6]` bytes) and partition IDs
//! at 0x190; its partitions are NCCH containers, classified on their own.
//! The card info header at 0x200 holds a CARD2 cart's writable address in
//! media units: from there on the dump holds save data, which is kept and
//! not parsed. A NAND image names FS types (1 normal, 3 FIRM, 4 `AGB_FIRM` save) and
//! crypt types (1 TWL, 2 CTR, 3 New 3DS); its partitions are AES-CTR
//! encrypted with a counter derived from the console's NAND CID (3dbrew
//! "Flash Filesystem", oldid 23624), so they are opaque, and its media unit
//! is 0x200 bytes.

use super::*;

/// Prefix of this layout's metadata keys.
const KEY_PREFIX: &str = "ncsd";

/// NCSD header size and magic.
const HEADER_SIZE: usize = 0x200;
const MAGIC_OFFSET: usize = 0x100;
const MAGIC: &[u8; 4] = b"NCSD";

/// Header fields.
const IMAGE_SIZE: usize = 0x104;
const MEDIA_ID: usize = 0x108;
const PARTITION_FS_TYPES: usize = 0x110;
const PARTITION_CRYPT_TYPES: usize = 0x118;
const PARTITION_TABLE: usize = 0x120;
const PARTITION_FLAGS: usize = 0x188;
const FLAGS_SIZE: usize = 8;
const PARTITION_IDS: usize = 0x190;
const PARTITION_ID_SIZE: usize = 8;

/// Eight partitions, each an offset and a size in media units.
const PARTITION_COUNT: usize = 8;
const PARTITION_ENTRY_SIZE: usize = 8;

/// CCI partition flag bytes (3dbrew; makerom `cci_flagindex`).
const FLAG_CARD_DEVICE: usize = 3;
const FLAG_MEDIA_PLATFORM: usize = 4;
const FLAG_MEDIA_TYPE: usize = 5;
const FLAG_MEDIA_UNIT_SIZE: usize = 6;
const FLAG_CARD_DEVICE_SDK2: usize = 7;

/// Media platform bit 0: CTR (ctrtool `MediaPlatform_CTR`; makerom
/// `cciplatform_CTR = 1`).
const MEDIA_PLATFORM_CTR: u8 = 0x01;

/// Media types of a cart image (makerom `mediatype_CARD1`, `CARD2`).
const MEDIA_TYPE_CARD1: u8 = 1;
const MEDIA_TYPE_CARD2: u8 = 2;

/// The card info header's writable address of a CARD2 cart, in media
/// units, and the value CARD1 carts store (3dbrew "NCSD").
const CARD_INFO_WRITABLE_ADDRESS: usize = 0x200;
const NO_WRITABLE_ADDRESS: u32 = u32::MAX;

/// One media unit at exponent 0 (0x200 bytes), as a power of two.
const MEDIA_UNIT_SHIFT: u32 = 9;

/// The NAND media unit (ctrtool: "the blocksize is always 0x200").
const NAND_MEDIA_UNIT: u64 = 0x200;

/// Partition FS types (3dbrew; ctrtool `PartitionFsType`).
const FS_TYPE_NORMAL: u8 = 1;
const FS_TYPE_FIRM: u8 = 3;
const FS_TYPE_AGB_FIRM_SAVE: u8 = 4;

/// Partition crypt types (ctrtool `PartitionCryptoType`).
const CRYPT_TYPE_TWL: u8 = 1;
const CRYPT_TYPE_CTR: u8 = 2;
const CRYPT_TYPE_SNAKE: u8 = 3;

/// Strong recognition: `NCSD` at 0x100 and the whole 0x200-byte header.
pub(super) fn detect(data: &[u8]) -> bool {
    data.len() >= HEADER_SIZE && &data[MAGIC_OFFSET..MAGIC_OFFSET + MAGIC.len()] == MAGIC
}

/// The NCSD specialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// CTR cart image: partitions are NCCH containers.
    Cci,
    /// NAND image: partitions are encrypted file systems and FIRM images.
    Nand,
}

/// One used partition, in bytes.
struct Partition {
    index: usize,
    region: Region,
}

/// The header fields this parser uses.
struct NcsdHeader {
    kind: Kind,
    media_id: u64,
    fs_types: [u8; PARTITION_COUNT],
    crypt_types: [u8; PARTITION_COUNT],
    /// CCI only; zero for NAND images.
    flags: [u8; FLAGS_SIZE],
    /// Bytes per media unit.
    media_unit: u64,
    /// The image size in bytes.
    image_size: u64,
}

fn ncsd_header(data: &[u8]) -> Result<NcsdHeader> {
    if data.len() < HEADER_SIZE {
        return Err(error(format!(
            "Truncated NCSD header: {} B of {HEADER_SIZE} B",
            data.len()
        )));
    }
    if !detect(data) {
        return Err(error("Missing NCSD magic at 0x100"));
    }
    let fs_types: [u8; PARTITION_COUNT] = array(data, PARTITION_FS_TYPES)?;
    let crypt_types: [u8; PARTITION_COUNT] = array(data, PARTITION_CRYPT_TYPES)?;
    let is_cci = fs_types.iter().chain(&crypt_types).all(|t| *t == 0);
    let (kind, flags, media_unit) = if is_cci {
        let flags: [u8; FLAGS_SIZE] = array(data, PARTITION_FLAGS)?;
        (Kind::Cci, flags, cci_media_unit(flags)?)
    } else {
        (Kind::Nand, [0; FLAGS_SIZE], NAND_MEDIA_UNIT)
    };
    Ok(NcsdHeader {
        kind,
        media_id: le_u64(data, MEDIA_ID)?,
        fs_types,
        crypt_types,
        flags,
        media_unit,
        image_size: u64::from(le_u32(data, IMAGE_SIZE)?) * media_unit,
    })
}

/// The CCI media unit, after the platform and media type checks of makerom
/// `IsCci` and ctrtool `CciFsSnapshotGenerator`.
fn cci_media_unit(flags: [u8; FLAGS_SIZE]) -> Result<u64> {
    let platform = flags[FLAG_MEDIA_PLATFORM];
    if platform & MEDIA_PLATFORM_CTR == 0 {
        return Err(error(format!(
            "Unsupported NCSD media platform 0x{platform:02X}: not CTR"
        )));
    }
    let media_type = flags[FLAG_MEDIA_TYPE];
    if !matches!(media_type, MEDIA_TYPE_CARD1 | MEDIA_TYPE_CARD2) {
        return Err(error(format!(
            "Unsupported NCSD media type {media_type}: not a Card1 or Card2 cart image"
        )));
    }
    let exponent = flags[FLAG_MEDIA_UNIT_SIZE];
    // A unit of 4 GiB already exceeds any cart; the bound keeps
    // `units * unit` inside u64.
    1u64.checked_shl(MEDIA_UNIT_SHIFT + u32::from(exponent))
        .filter(|unit| *unit <= 1 << 32)
        .ok_or_else(|| error(format!("Invalid NCSD media unit size exponent {exponent}")))
}

/// The used partitions: inside the image size and the file, and not
/// overlapping each other.
fn partitions(data: &[u8], header: &NcsdHeader) -> Result<Vec<Partition>> {
    let mut partitions: Vec<Partition> = Vec::new();
    for index in 0..PARTITION_COUNT {
        let entry = PARTITION_TABLE + index * PARTITION_ENTRY_SIZE;
        let units = u64::from(le_u32(data, entry + 4)?);
        if units == 0 {
            continue;
        }
        let offset = u64::from(le_u32(data, entry)?) * header.media_unit;
        let size = units * header.media_unit;
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= header.image_size)
            .ok_or_else(|| {
                error(format!(
                    "Invalid NCSD partition {index} 0x{offset:X} + {size} B: beyond the 0x{:X}-byte image",
                    header.image_size
                ))
            })?;
        let region = region_within(offset, size, data.len()).ok_or_else(|| {
            error(format!(
                "Truncated NCSD partition {index}: ends at 0x{end:X}, file {} B",
                data.len()
            ))
        })?;
        if let Some(other) = partitions
            .iter()
            .find(|p| p.region.offset < region.end() && region.offset < p.region.end())
        {
            return Err(error(format!(
                "Invalid NCSD partitions {} and {index}: they overlap",
                other.index
            )));
        }
        partitions.push(Partition { index, region });
    }
    Ok(partitions)
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = ncsd_header(data)?;
    let partitions = partitions(data, &header)?;
    let used_end = partitions
        .iter()
        .map(|p| p.region.end())
        .max()
        .unwrap_or(HEADER_SIZE)
        .max(HEADER_SIZE);
    let trailing = trailing_note(data, &header, used_end)?;
    let variant = match header.kind {
        Kind::Cci => "3DS CCI",
        Kind::Nand => "3DS NAND image",
    };
    let mut c = Container::new(FileFormat::Ncsd, variant, KEY_PREFIX);
    c.consumed = data.len();
    push_header_notes(&mut c, data, &header, partitions.len());
    let mut members = Members::new(data.len());
    for partition in &partitions {
        let bytes = partition.region.bytes(data);
        let label = partition_label(&header, partition.index);
        match header.kind {
            Kind::Cci => {
                let id = le_u64(data, PARTITION_IDS + PARTITION_ID_SIZE * partition.index)?;
                c.push_metadata(
                    format!("{KEY_PREFIX}_partition_{}_id", partition.index),
                    format!("Partition {} ID", partition.index),
                    format!("0x{id:016X}"),
                );
                members.offer(label, partition.region.offset, bytes);
            }
            Kind::Nand => members.push_opaque(label, partition.region.offset, bytes),
        }
    }
    c.notes.extend(trailing);
    members.finish(&mut c, "partition", "partitions");
    Ok(c)
}

/// Check what follows the last partition and return the note for bytes
/// that are kept but not parsed. A cart dump is trimmed after the last
/// partition or filled with erased flash up to the cart size, except for a
/// CARD2 cart's writable region, which holds save data; a NAND image
/// continues with NAND space that no partition covers.
fn trailing_note(data: &[u8], header: &NcsdHeader, used_end: usize) -> Result<Option<String>> {
    let trailing_size = data.len() - used_end;
    if trailing_size == 0 {
        return Ok(None);
    }
    if header.kind == Kind::Nand {
        return Ok(Some(format!(
            "{} after the last partition at 0x{used_end:X} are not parsed",
            size_text(trailing_size)
        )));
    }
    let save_start = writable_region(data, header)
        .filter(|start| *start >= used_end)
        .map_or(data.len(), |start| start.min(data.len()));
    let padding = &data[used_end..save_start];
    if !is_padding(padding) {
        return Err(error(format!(
            "Unexpected data in the {} after the last NCSD partition at 0x{used_end:X}",
            size_text(padding.len())
        )));
    }
    if save_start == data.len() {
        return Ok(None);
    }
    Ok(Some(format!(
        "CARD2 writable region (save data) at 0x{save_start:X}: {} not parsed",
        size_text(data.len() - save_start)
    )))
}

/// A CARD2 cart's writable address in bytes: the card info header at
/// 0x200 holds it in media units (3dbrew "NCSD"); CARD1 carts store
/// 0xFFFFFFFF there.
fn writable_region(data: &[u8], header: &NcsdHeader) -> Option<usize> {
    if header.flags[FLAG_MEDIA_TYPE] != MEDIA_TYPE_CARD2 {
        return None;
    }
    let units = le_u32(data, CARD_INFO_WRITABLE_ADDRESS)
        .ok()
        .filter(|units| *units != NO_WRITABLE_ADDRESS)?;
    usize::try_from(u64::from(units) * header.media_unit).ok()
}

fn push_header_notes(c: &mut Container<'_>, data: &[u8], header: &NcsdHeader, used: usize) {
    match header.kind {
        Kind::Cci => {
            c.notes.push(format!(
                "3DS CTR cart image; media ID 0x{:016X}; media type {}; card device {}; media unit {}; the container names no CPU",
                header.media_id,
                media_type_name(header.flags[FLAG_MEDIA_TYPE]),
                card_device_name(header.flags),
                size_unit(header.media_unit)
            ));
            c.notes
                .push("Partitions are NCCH containers, classified on their own".to_string());
        }
        Kind::Nand => c.notes.push(
            "3DS NAND image; partitions are AES-CTR encrypted with keyslots chosen by FS and crypt type and a counter from the NAND CID (3dbrew Flash Filesystem), so they are opaque; the container names no CPU"
                .to_string(),
        ),
    }
    let image_size = header.image_size;
    let file_size = data.len() as u64;
    if file_size < image_size {
        c.notes.push(format!(
            "Trimmed image: the file holds 0x{file_size:X} of 0x{image_size:X} B"
        ));
    }
    c.notes
        .push("The NCSD header RSA-2048 signature is not verified".to_string());
    c.push_metadata(
        format!("{KEY_PREFIX}_media_id"),
        "Media ID",
        format!("0x{:016X}", header.media_id),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_image_size"),
        "NCSD image size (B)",
        image_size,
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_media_unit"),
        "Media unit (B)",
        header.media_unit,
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_partitions"),
        "Partitions",
        used as u64,
    );
}

/// A size in bytes with a binary unit when it divides exactly.
fn size_unit(bytes: u64) -> String {
    usize::try_from(bytes).map_or_else(|_| format!("{bytes} B"), size_text)
}

fn media_type_name(media_type: u8) -> &'static str {
    match media_type {
        MEDIA_TYPE_CARD1 => "Card1",
        MEDIA_TYPE_CARD2 => "Card2",
        _ => "unknown",
    }
}

/// The card device: flags\[3\] since SDK 3, flags\[7\] in SDK 2 (makerom
/// `cciflag_CARD_DEVICE`, `cciflag_CARD_DEVICE_OLD`).
fn card_device_name(flags: [u8; FLAGS_SIZE]) -> String {
    match flags[FLAG_CARD_DEVICE] | flags[FLAG_CARD_DEVICE_SDK2] {
        0 => "not specified".to_string(),
        1 => "NOR flash".to_string(),
        2 => "none".to_string(),
        3 => "BT".to_string(),
        other => format!("unknown 0x{other:02X}"),
    }
}

/// `Partition <index> (<role>)`: the CCI partition roles of 3dbrew, or the
/// NAND FS and crypt types.
fn partition_label(header: &NcsdHeader, index: usize) -> String {
    let role = match header.kind {
        Kind::Cci => cci_role(index).map(str::to_string),
        Kind::Nand => Some(format!(
            "{}; {}",
            fs_type_name(header.fs_types[index]),
            crypt_type_name(header.crypt_types[index])
        )),
    };
    match role {
        Some(role) => format!("Partition {index} ({role})"),
        None => format!("Partition {index}"),
    }
}

/// CCI partition roles (3dbrew "NCSD"; ctrtool `PartitionIndex`).
fn cci_role(index: usize) -> Option<&'static str> {
    match index {
        0 => Some("executable content"),
        1 => Some("e-manual"),
        2 => Some("Download Play child"),
        6 => Some("New 3DS update data"),
        7 => Some("update data"),
        _ => None,
    }
}

fn fs_type_name(fs_type: u8) -> String {
    match fs_type {
        FS_TYPE_NORMAL => "normal FS".to_string(),
        FS_TYPE_FIRM => "FIRM".to_string(),
        FS_TYPE_AGB_FIRM_SAVE => "AGB_FIRM save".to_string(),
        other => format!("FS type {other}"),
    }
}

fn crypt_type_name(crypt_type: u8) -> String {
    match crypt_type {
        CRYPT_TYPE_TWL => "TWL crypt".to_string(),
        CRYPT_TYPE_CTR => "CTR crypt".to_string(),
        CRYPT_TYPE_SNAKE => "New 3DS crypt".to_string(),
        other => format!("crypt type {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cci_media_units_follow_the_exponent_and_are_bounded() {
        let mut flags = [0u8; FLAGS_SIZE];
        flags[FLAG_MEDIA_PLATFORM] = MEDIA_PLATFORM_CTR;
        flags[FLAG_MEDIA_TYPE] = MEDIA_TYPE_CARD2;
        assert_eq!(cci_media_unit(flags).unwrap(), 0x200);
        flags[FLAG_MEDIA_UNIT_SIZE] = 2;
        assert_eq!(cci_media_unit(flags).unwrap(), 0x800);
        flags[FLAG_MEDIA_UNIT_SIZE] = 24;
        assert!(cci_media_unit(flags).is_err());
        flags[FLAG_MEDIA_UNIT_SIZE] = 0;
        flags[FLAG_MEDIA_TYPE] = 0;
        assert!(cci_media_unit(flags).is_err());
    }

    #[test]
    fn cci_partition_roles_follow_3dbrew() {
        assert_eq!(cci_role(0), Some("executable content"));
        assert_eq!(cci_role(7), Some("update data"));
        assert_eq!(cci_role(3), None);
    }
}
