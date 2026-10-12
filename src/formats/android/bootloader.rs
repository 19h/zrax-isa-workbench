//! Pixel and Nexus bootloader packs (`bootloader-<device>-<version>.img`):
//! the Qualcomm `BOOTLDR!` pack, the ASUS fugu (Nexus Player) `BOOTLDR!`
//! variant, the Qualcomm meta image and FBPK versions 1 and 2.
//!
//! Sources:
//! - Qualcomm `BOOTLDR!`: AOSP `device/lge/hammerhead` `releasetools.py` at
//!   `e2e993442ed56db6a3743607a8dfd58f370d7b0a` (also `device/lge/bullhead`
//!   at `2994b6be` and `device/asus/flo` at `9d9fee95`), Python formats
//!   `"<8sIII"` and `"<64sI"`. That `bootldr_size` may equal the file size
//!   (Pixel and Pixel 2) is from Kaitai `android_bootldr_qcom.ksy` at
//!   `c35300d0`, a secondary source.
//! - ASUS fugu `BOOTLDR!`: AOSP `device/asus/fugu` `releasetools.py` at
//!   `25a29d70ff7d2042fc6a3ba8ae8838bc4df88a34` (`"<8sHHI"`, `"<8sIBBBB"`).
//! - Qualcomm meta image: CAF `device/qcom/common/meta_image/meta_format.h`
//!   (`OnePlusOSS` mirror at `018b5519`) and AOSP `device/huawei/angler`
//!   `releasetools.py` at `cf92cd8e` (`"<IHH64sHH"`, `"<72sLL"`).
//! - FBPK version 2: Google `fbpack.py` and `fbpacktool.py` (Pixel
//!   `fw_unpack` tools on source.android.com, 2021), `<IIII16s64sIIII` and
//!   `<I36s40sQQII`. The meanings of `platform`, `slot_type` and `crc32`
//!   are UNCONFIRMED.
//! - FBPK version 1: no Google source; `anestisb/qc_image_unpacker`
//!   `src/packed_image.h` at `28a783a9` and BANG `android_fbpk.ksy` at
//!   `96370e4f` agree on the layout. `pad1`, `pad2`, `checksum` and the
//!   alignment of `next_offset` are UNCONFIRMED.
//!
//! Every field is little-endian. No pack names a CPU: each member is an
//! independent image (bootloader stages, firmware, partition tables) and
//! is classified from its own bytes. FBPK partition tables (`FBPT`) and
//! fugu splash screens are data and stay opaque.

use super::*;
use crate::formats::checksum;

/// Qualcomm `BOOTLDR!` header (magic, `num_images`, `start_offset`,
/// `bootldr_size`) and image table entry (`name[64]`, `size`).
const BOOTLDR_HEADER_SIZE: usize = 20;
const BOOTLDR_ENTRY_SIZE: usize = 68;
const BOOTLDR_NAME_SIZE: usize = 64;

/// ASUS fugu header (magic, `revision`, two reserved fields) and chunk
/// header (`chunk_id[8]`, `size`, `flags`, three reserved bytes).
const FUGU_HEADER_SIZE: usize = 16;
const FUGU_CHUNK_HEADER_SIZE: usize = 16;

/// Revision 1 stores IFWI and droidboot sizes after the header and the
/// two images from 0x18; other revisions store chunks.
const FUGU_REVISION_SIZES: u16 = 1;
const FUGU_V1_IMAGES_OFFSET: usize = 0x18;

/// fugu chunk IDs and the labels used for them.
const FUGU_CHUNK_IFWI: &[u8; 8] = b"IFWI!!!!";
const FUGU_CHUNK_DROIDBOOT: &[u8; 8] = b"DROIDBT!";
const FUGU_CHUNK_SPLASH: &[u8; 8] = b"SPLASHS!";

/// fugu chunk flag bit 0: the updater writes the chunk only when it is set
/// (our name for the bit).
const FUGU_FLAG_FLASH: u8 = 0x01;

/// Qualcomm meta image header (`meta_header_t`) and entry
/// (`img_header_entry_t`, `ptn_name[MAX_GPT_NAME_SIZE]`).
const META_HEADER_SIZE: usize = 76;
const META_MAJOR_VERSION: u16 = 1;
const META_ENTRY_SIZE: usize = 80;
const META_NAME_SIZE: usize = 72;

/// FBPK versions (`FBPACK_VERSION` is 2).
const FBPK_V1: u32 = 1;
const FBPK_V2: u32 = 2;

/// FBPK version 1 header and entry header sizes.
const FBPK_V1_HEADER_SIZE: usize = 84;
const FBPK_V1_ENTRY_SIZE: usize = 56;

/// FBPK version 2 `PackHeader` and `PackEntry` sizes.
const FBPK_V2_HEADER_SIZE: usize = 112;
const FBPK_V2_ENTRY_SIZE: usize = 104;

/// FBPK entry types (`FBPACK_PARTITION_TABLE`, `FBPACK_PARTITION_DATA`,
/// `FBPACK_SIDELOAD_DATA`). Version 1 uses 0 for a partition table and
/// any other value for image data.
const FBPACK_PARTITION_TABLE: u32 = 0;
const FBPACK_PARTITION_DATA: u32 = 1;
const FBPACK_SIDELOAD_DATA: u32 = 2;

/// Partition table payload magic inside FBPK type-0 entries.
const FBPT_MAGIC: &[u8; 4] = b"FBPT";

/// A new bootloader-pack container of `variant`.
fn pack(variant: impl Into<String>, data: &[u8]) -> Container<'_> {
    let mut c = Container::new(FileFormat::AndroidBootloader, variant, KEY_PREFIX);
    c.consumed = data.len();
    c
}

/// The note every pack carries about ISA evidence.
const NO_CPU_NOTE: &str = "The pack names no CPU; members are classified from their own bytes";

/// A partition name: non-empty printable ASCII, terminated by a NUL inside
/// its field. `what` names the record in errors.
fn partition_name(field: &[u8], what: &str) -> Result<String> {
    let len = field
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| error(format!("Invalid {what} name: no NUL terminator")))?;
    let name = &field[..len];
    if name.is_empty() || !name.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        return Err(error(format!("Invalid {what} name")));
    }
    Ok(String::from_utf8_lossy(name).into_owned())
}

/// The message of an Android parse error, for errors that combine two.
fn reason(e: &ClassifierError) -> String {
    match e {
        ClassifierError::AndroidParseError { message } => message.clone(),
        other => other.to_string(),
    }
}

/// A note about the bytes after `end` when they are not padding.
fn push_trailing_note(c: &mut Container<'_>, data: &[u8], end: usize, what: &str) {
    let rest = data.get(end..).unwrap_or_default();
    if !is_padding(rest) {
        c.notes.push(format!(
            "{} after the {what} are not described by the header",
            size_text(rest.len())
        ));
    }
}

/// Per-entry checksum fields whose algorithm the sources do not establish:
/// a field that equals the IEEE CRC-32 of the entry data is reported as a
/// match, any other nonzero value as not verified.
#[derive(Default)]
struct Checksums {
    matched: usize,
    unverified: usize,
}

impl Checksums {
    fn check(&mut self, stored: u32, body: &[u8]) {
        if stored == 0 {
            return;
        }
        if checksum::crc32(body) == stored {
            self.matched += 1;
        } else {
            self.unverified += 1;
        }
    }

    fn push_note(&self, c: &mut Container<'_>, field: &str) {
        if self.matched > 0 {
            c.notes.push(format!(
                "{} {field} fields match the IEEE CRC-32 of their entry data",
                self.matched
            ));
        }
        if self.unverified > 0 {
            c.notes.push(format!(
                "{} {field} fields not verified (algorithm and coverage unconfirmed)",
                self.unverified
            ));
        }
    }
}

/// Parse a `BOOTLDR!` pack. The Qualcomm and ASUS layouts share the magic;
/// each is validated completely, and a pack that validates as both is
/// reported as ambiguous without extracting members.
pub(super) fn parse_bootldr(data: &[u8]) -> Result<Container<'_>> {
    slice(data, 0, FUGU_HEADER_SIZE, "BOOTLDR! header")?;
    if !data.starts_with(BOOTLDR_MAGIC) {
        return Err(error("Missing BOOTLDR! magic"));
    }
    match (qualcomm_bootldr(data), fugu_bootldr(data)) {
        (Ok(c), Err(_)) | (Err(_), Ok(c)) => Ok(c),
        (Ok(_), Ok(_)) => {
            let mut c = pack("Ambiguous BOOTLDR! pack", data);
            c.notes.push(
                "The pack validates as both the Qualcomm and the ASUS fugu BOOTLDR! layout; members were not extracted"
                    .into(),
            );
            Ok(c)
        }
        (Err(qualcomm), Err(fugu)) => Err(error(format!(
            "Invalid BOOTLDR! pack: as the Qualcomm layout, {}; as the ASUS layout, {}",
            reason(&qualcomm),
            reason(&fugu)
        ))),
    }
}

/// One Qualcomm `BOOTLDR!` image table entry.
struct BootldrEntry {
    name: String,
    size: u32,
}

/// Qualcomm `BOOTLDR!` pack: magic (8), `num_images` (u32) at 0x08,
/// `start_offset` (u32) at 0x0C, `bootldr_size` (u32) at 0x10, then
/// `num_images` 68-byte entries (`name[64]`, `size`). Image bodies follow
/// each other from `start_offset` without alignment.
fn qualcomm_bootldr(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, BOOTLDR_HEADER_SIZE, "BOOTLDR! header")?;
    let count = le_u32(header, 0x08)? as usize;
    let start = le_u32(header, 0x0c)? as usize;
    let declared = le_u32(header, 0x10)?;
    if count == 0 {
        return Err(error("Invalid BOOTLDR! num_images 0"));
    }
    let room = (data.len() - BOOTLDR_HEADER_SIZE) / BOOTLDR_ENTRY_SIZE;
    if count > room {
        return Err(error(format!(
            "Truncated BOOTLDR! image table: {count} entries declared, at most {room} fit in the file"
        )));
    }
    let table_end = BOOTLDR_HEADER_SIZE + count * BOOTLDR_ENTRY_SIZE;
    if start < table_end {
        return Err(error(format!(
            "Invalid BOOTLDR! start_offset 0x{start:X}: inside the image table ending at 0x{table_end:X}"
        )));
    }
    let entries = data[BOOTLDR_HEADER_SIZE..table_end]
        .chunks_exact(BOOTLDR_ENTRY_SIZE)
        .enumerate()
        .map(|(i, entry)| {
            Ok(BootldrEntry {
                name: partition_name(&entry[..BOOTLDR_NAME_SIZE], &format!("BOOTLDR! entry {i}"))?,
                size: le_u32(entry, BOOTLDR_NAME_SIZE)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut c = pack("Qualcomm BOOTLDR! pack", data);
    let mut pos = start;
    let mut bodies = Vec::with_capacity(entries.len());
    for entry in &entries {
        let body = slice(
            data,
            pos,
            entry.size as usize,
            &format!("BOOTLDR! image {}", entry.name),
        )?;
        bodies.push((pos, body));
        pos += body.len();
    }
    let total = pos - start;
    c.notes.push(format!(
        "Qualcomm BOOTLDR! pack: {count} images, {total} B of image data from 0x{start:X}"
    ));
    if declared as usize == total {
        c.notes
            .push("bootldr_size matches the sum of the image sizes".into());
    } else if declared as usize == data.len() {
        c.notes.push(
            "bootldr_size equals the file size rather than the sum of the image sizes (a variant known only from a secondary source)"
                .into(),
        );
    } else {
        return Err(error(format!(
            "Invalid BOOTLDR! bootldr_size {declared} B: the images add up to {total} B"
        )));
    }
    c.notes.push(NO_CPU_NOTE.into());
    c.push_metadata("android_bootloader_images", "Images", count as u64);
    let empty = entries.iter().filter(|e| e.size == 0).count();
    if empty > 0 {
        c.notes.push(format!("{empty} entries have no data"));
    }
    for (entry, (offset, body)) in entries.iter().zip(bodies) {
        if body.is_empty() {
            continue;
        }
        if is_component_limit(c.children.len(), count - empty, &mut c.notes) {
            break;
        }
        c.children
            .push(Child::stored(entry.name.clone(), offset, body));
    }
    push_trailing_note(&mut c, data, pos, "last image");
    Ok(c)
}

/// ASUS fugu `BOOTLDR!` pack: magic (8), `revision` (u16) at 0x08, a
/// reserved u16 and u32. Revision 1 then holds sizes; any other revision
/// holds chunks to the end of the file, as `releasetools.py` reads them.
fn fugu_bootldr(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, FUGU_HEADER_SIZE, "ASUS BOOTLDR! header")?;
    let revision = le_u16(header, 0x08)?;
    let mut c = pack(format!("ASUS BOOTLDR! pack revision {revision}"), data);
    if revision == FUGU_REVISION_SIZES {
        fugu_sized_images(data, &mut c)?;
    } else {
        fugu_chunks(data, &mut c)?;
    }
    c.notes.push(NO_CPU_NOTE.into());
    Ok(c)
}

/// Revision 1: IFWI size (u32) at 0x10 and droidboot size (u32) at 0x14;
/// the IFWI image from 0x18, then the droidboot image.
fn fugu_sized_images<'a>(data: &'a [u8], c: &mut Container<'a>) -> Result<()> {
    let ifwi_size = le_u32(data, 0x10)? as usize;
    let droidboot_size = le_u32(data, 0x14)? as usize;
    let ifwi = slice(
        data,
        FUGU_V1_IMAGES_OFFSET,
        ifwi_size,
        "ASUS BOOTLDR! IFWI image",
    )?;
    let droidboot_offset = FUGU_V1_IMAGES_OFFSET + ifwi.len();
    let droidboot = slice(
        data,
        droidboot_offset,
        droidboot_size,
        "ASUS BOOTLDR! droidboot image",
    )?;
    if ifwi.is_empty() && droidboot.is_empty() {
        return Err(error("Invalid ASUS BOOTLDR! pack: both images are empty"));
    }
    c.notes.push(format!(
        "ASUS BOOTLDR! pack revision 1: IFWI {ifwi_size} B, droidboot {droidboot_size} B"
    ));
    if !ifwi.is_empty() {
        c.children
            .push(Child::stored("IFWI", FUGU_V1_IMAGES_OFFSET, ifwi));
    }
    if !droidboot.is_empty() {
        c.children
            .push(Child::stored("droidboot", droidboot_offset, droidboot));
    }
    push_trailing_note(
        c,
        data,
        droidboot_offset + droidboot.len(),
        "droidboot image",
    );
    Ok(())
}

/// The display label of a fugu chunk ID, or `None` for an unknown ID.
fn fugu_chunk_label(id: &[u8]) -> Option<&'static str> {
    if id == FUGU_CHUNK_IFWI {
        Some("IFWI")
    } else if id == FUGU_CHUNK_DROIDBOOT {
        Some("droidboot")
    } else if id == FUGU_CHUNK_SPLASH {
        Some("splash")
    } else {
        None
    }
}

/// Chunks to the end of the file: `chunk_id[8]`, size (u32) at 0x08, flags
/// (u8) at 0x0C, three reserved bytes, then the data. The splash screen is
/// image data and stays opaque.
fn fugu_chunks<'a>(data: &'a [u8], c: &mut Container<'a>) -> Result<()> {
    let mut pos = FUGU_HEADER_SIZE;
    let mut count = 0usize;
    let mut skipped = Vec::new();
    let mut members = Vec::new();
    while pos < data.len() {
        let header = slice(
            data,
            pos,
            FUGU_CHUNK_HEADER_SIZE,
            "ASUS BOOTLDR! chunk header",
        )?;
        let id = &header[..8];
        let label = fugu_chunk_label(id).ok_or_else(|| {
            error(format!(
                "Unknown ASUS BOOTLDR! chunk ID \"{}\" at 0x{pos:X}",
                String::from_utf8_lossy(id).escape_default()
            ))
        })?;
        let size = le_u32(header, 0x08)? as usize;
        let flags = header[0x0c];
        let body_offset = pos + FUGU_CHUNK_HEADER_SIZE;
        let body = slice(data, body_offset, size, "ASUS BOOTLDR! chunk data")?;
        if flags & FUGU_FLAG_FLASH == 0 {
            skipped.push(format!(
                "{label}: chunk flag bit 0 is clear; the fugu updater skips the chunk"
            ));
        }
        if !body.is_empty() {
            members.push(if id == FUGU_CHUNK_SPLASH {
                Child::opaque(label, body_offset, body)
            } else {
                Child::stored(label, body_offset, body)
            });
        }
        count += 1;
        pos = body_offset + body.len();
    }
    if count == 0 {
        return Err(error("Invalid ASUS BOOTLDR! pack: no chunks"));
    }
    c.notes.push(format!(
        "ASUS BOOTLDR! pack: {count} chunks to the end of the file"
    ));
    c.notes.append(&mut skipped);
    let listed = members.len();
    for member in members {
        if is_component_limit(c.children.len(), listed, &mut c.notes) {
            break;
        }
        c.children.push(member);
    }
    Ok(())
}

/// Qualcomm meta image: magic (4), major and minor version (u16) at 0x04
/// and 0x06, image version (64) at 0x08, `meta_hdr_sz` (u16) at 0x48 and
/// `img_hdr_sz` (u16) at 0x4A, then `img_hdr_sz / 80` entries of a 72-byte
/// partition name, an absolute start offset (u32) and a size (u32). An
/// entry is in use when both offset and size are nonzero.
pub(super) fn parse_meta_image(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, META_HEADER_SIZE, "meta image header")?;
    if le_u32(header, 0)? != META_IMAGE_MAGIC {
        return Err(error("Missing meta image magic"));
    }
    let major = le_u16(header, 0x04)?;
    if major != META_MAJOR_VERSION {
        return Err(error(format!(
            "Unsupported meta image major version {major}"
        )));
    }
    let minor = le_u16(header, 0x06)?;
    let version = asciiz(&header[0x08..0x48]);
    let header_size = usize::from(le_u16(header, 0x48)?);
    let table_size = usize::from(le_u16(header, 0x4a)?);
    // The CAF reader reads the table right after the 76-byte header, while
    // Kaitai skips `meta_hdr_sz - 76` extension bytes; they agree only here.
    if header_size != META_HEADER_SIZE {
        return Err(error(format!(
            "Unsupported meta image header size {header_size} B: readers disagree where the entry table starts"
        )));
    }
    if table_size % META_ENTRY_SIZE != 0 {
        return Err(error(format!(
            "Invalid meta image entry table size {table_size} B: not a multiple of {META_ENTRY_SIZE} B"
        )));
    }
    let table = slice(data, META_HEADER_SIZE, table_size, "meta image entry table")?;
    let table_end = META_HEADER_SIZE + table_size;

    let mut c = pack(format!("Qualcomm meta image v{major}.{minor}"), data);
    let mut end = table_end;
    let mut members = Vec::new();
    for (i, entry) in table.chunks_exact(META_ENTRY_SIZE).enumerate() {
        let offset = le_u32(entry, 0x48)? as usize;
        let size = le_u32(entry, 0x4c)? as usize;
        if offset == 0 || size == 0 {
            continue;
        }
        let name = partition_name(&entry[..META_NAME_SIZE], &format!("meta image entry {i}"))?;
        if offset < table_end {
            return Err(error(format!(
                "Invalid meta image entry {name}: data at 0x{offset:X} overlaps the header"
            )));
        }
        let body = slice(data, offset, size, &format!("meta image partition {name}"))?;
        end = end.max(offset + size);
        members.push((name, offset, body));
    }
    if members.is_empty() {
        return Err(error("Invalid meta image: no entry is in use"));
    }
    c.notes.push(format!(
        "Qualcomm meta image v{major}.{minor}: {} of {} entries in use; image version \"{version}\"",
        members.len(),
        table_size / META_ENTRY_SIZE
    ));
    c.notes.push(NO_CPU_NOTE.into());
    c.push_metadata("android_bootloader_version", "Image version", version);
    for (name, offset, body) in members {
        c.children.push(Child::stored(name, offset, body));
    }
    push_trailing_note(&mut c, data, end, "last partition");
    Ok(c)
}

/// Parse an FBPK pack; the version at 0x04 selects the layout.
pub(super) fn parse_fbpk(data: &[u8]) -> Result<Container<'_>> {
    slice(data, 0, 8, "FBPK header")?;
    if !data.starts_with(FBPK_MAGIC) {
        return Err(error("Missing FBPK magic"));
    }
    match le_u32(data, 0x04)? {
        FBPK_V1 => fbpk_v1(data),
        FBPK_V2 => fbpk_v2(data),
        version => Err(error(format!("Unsupported FBPK version {version}"))),
    }
}

/// An FBPK member: a partition table is configuration data and stays
/// opaque; image data is classified from its own bytes.
fn fbpk_member(label: String, kind: u32, offset: usize, body: &[u8]) -> Child<'_> {
    if kind == FBPACK_PARTITION_TABLE {
        Child::opaque(label, offset, body)
    } else {
        Child::stored(label, offset, body)
    }
}

/// A note about the partition tables an FBPK pack holds.
fn push_partition_table_note(c: &mut Container<'_>, tables: usize, fbpt: usize) {
    if tables > 0 {
        c.notes.push(format!(
            "{tables} partition-table entries ({fbpt} with the FBPT magic) are configuration data; not analyzed"
        ));
    }
}

/// FBPK version 1 header: magic (4), version (4), image version (68) at
/// 0x08, entry count (u32) at 0x4C, total file size (u32) at 0x50. Entry
/// headers start at 0x54: type (4), partition name (32) at 0x04, `pad1`
/// (4) at 0x24, data size (4) at 0x28, `pad2` (4) at 0x2C, absolute offset
/// of the next entry header (4) at 0x30, checksum (4) at 0x34. The data
/// follows its entry header.
fn fbpk_v1(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, FBPK_V1_HEADER_SIZE, "FBPK v1 header")?;
    let version = asciiz(&header[0x08..0x4c]);
    let count = le_u32(header, 0x4c)? as usize;
    let total_size = le_u32(header, 0x50)?;
    let room = (data.len() - FBPK_V1_HEADER_SIZE) / FBPK_V1_ENTRY_SIZE;
    if count > room {
        return Err(error(format!(
            "Truncated FBPK v1 entry list: {count} entries declared, at most {room} fit in the file"
        )));
    }
    let mut c = pack("FBPK v1 pack", data);
    let mut pos = FBPK_V1_HEADER_SIZE;
    let mut end = pos;
    let mut checksums = Checksums::default();
    let mut tables = 0usize;
    let mut fbpt = 0usize;
    let mut members = Vec::with_capacity(count);
    for i in 0..count {
        let entry = slice(data, pos, FBPK_V1_ENTRY_SIZE, "FBPK v1 entry header")?;
        let kind = le_u32(entry, 0x00)?;
        let name = asciiz(&entry[0x04..0x24]);
        let pad1 = le_u32(entry, 0x24)?;
        let size = le_u32(entry, 0x28)? as usize;
        let pad2 = le_u32(entry, 0x2c)?;
        let next = le_u32(entry, 0x30)? as usize;
        // qc_image_unpacker reads pad1 and pad2 as high size and offset
        // words ("Most likely"); with no source, nonzero values are refused.
        if pad1 != 0 || pad2 != 0 {
            return Err(error(format!(
                "Unsupported FBPK v1 entry {i} at 0x{pos:X}: nonzero pad1 or pad2 (their meaning is unconfirmed)"
            )));
        }
        let body_offset = pos + FBPK_V1_ENTRY_SIZE;
        let body = slice(data, body_offset, size, "FBPK v1 entry data")?;
        checksums.check(le_u32(entry, 0x34)?, body);
        let body_end = body_offset + size;
        end = body_end;
        if kind == FBPACK_PARTITION_TABLE {
            tables += 1;
            fbpt += usize::from(body.starts_with(FBPT_MAGIC));
        }
        let label = if name.is_empty() {
            format!("Entry {i}")
        } else {
            name
        };
        if !body.is_empty() {
            members.push(fbpk_member(label, kind, body_offset, body));
        }
        if i + 1 < count {
            if next < body_end {
                return Err(error(format!(
                    "Invalid FBPK v1 next_offset 0x{next:X} in entry {i}: before the end of its data at 0x{body_end:X}"
                )));
            }
            pos = next;
        }
    }
    c.notes.push(format!(
        "FBPK v1 pack: {count} entries; image version \"{version}\"; layout from community unpackers (no Google source)"
    ));
    if total_size as usize != data.len() {
        c.notes.push(format!(
            "total_file_sz field is {total_size} B; the file is {} B",
            data.len()
        ));
    }
    checksums.push_note(&mut c, "checksum");
    push_partition_table_note(&mut c, tables, fbpt);
    c.notes.push(NO_CPU_NOTE.into());
    c.push_metadata("android_bootloader_version", "Image version", version);
    let listed = members.len();
    for member in members {
        if is_component_limit(c.children.len(), listed, &mut c.notes) {
            break;
        }
        c.children.push(member);
    }
    push_trailing_note(&mut c, data, end, "last entry");
    Ok(c)
}

/// FBPK version 2 `PackHeader`: magic (4), version (4), `header_size` (4)
/// at 0x08, `entry_header_size` (4) at 0x0C, platform (16) at 0x10, pack
/// version (64) at 0x20, `slot_type` (4) at 0x60, `data_align` (4) at
/// 0x64, entry count (4) at 0x68, `total_size` (4) at 0x6C. `PackEntry`
/// records start at `header_size` and step by `entry_header_size`: type
/// (4), name (36) at 0x04, product (40) at 0x28, absolute data offset (u64)
/// at 0x50, size (u64) at 0x58, `slotted` (4) at 0x60, `crc32` (4) at 0x64.
fn fbpk_v2(data: &[u8]) -> Result<Container<'_>> {
    let header = slice(data, 0, FBPK_V2_HEADER_SIZE, "FBPK v2 header")?;
    let header_size = le_u32(header, 0x08)? as usize;
    let entry_size = le_u32(header, 0x0c)? as usize;
    if header_size < FBPK_V2_HEADER_SIZE {
        return Err(error(format!(
            "Invalid FBPK v2 header_size {header_size} B"
        )));
    }
    slice(data, 0, header_size, "FBPK v2 header")?;
    if entry_size < FBPK_V2_ENTRY_SIZE {
        return Err(error(format!(
            "Invalid FBPK v2 entry_header_size {entry_size} B"
        )));
    }
    let platform = asciiz(&header[0x10..0x20]);
    let version = asciiz(&header[0x20..0x60]);
    let slot_type = le_u32(header, 0x60)?;
    let data_align = le_u32(header, 0x64)?;
    let count = le_u32(header, 0x68)? as usize;
    let total_size = le_u32(header, 0x6c)?;
    let room = data.len().saturating_sub(header_size) / entry_size;
    if count > room {
        return Err(error(format!(
            "Truncated FBPK v2 entry table: {count} entries declared, at most {room} fit in the file"
        )));
    }
    let table_end = header_size + count * entry_size;

    let mut c = pack("FBPK v2 pack", data);
    let mut end = table_end;
    let mut checksums = Checksums::default();
    let mut tables = 0usize;
    let mut fbpt = 0usize;
    let mut unknown_types = 0usize;
    let mut members = Vec::with_capacity(count);
    for i in 0..count {
        let entry = slice(
            data,
            header_size + i * entry_size,
            entry_size,
            "FBPK v2 entry",
        )?;
        let kind = le_u32(entry, 0x00)?;
        let name = asciiz(&entry[0x04..0x28]);
        let product = asciiz(&entry[0x28..0x50]);
        let offset = le_u64(entry, 0x50)?;
        let size = le_u64(entry, 0x58)?;
        let body = slice64(data, offset, size, &format!("FBPK v2 entry {i} data"))?;
        let body_offset = usize::try_from(offset).expect("entry data lies in the file");
        if !body.is_empty() && body_offset < table_end {
            return Err(error(format!(
                "Invalid FBPK v2 entry {i}: data at 0x{body_offset:X} overlaps the entry table"
            )));
        }
        end = end.max(body_offset + body.len());
        checksums.check(le_u32(entry, 0x64)?, body);
        match kind {
            FBPACK_PARTITION_TABLE => {
                tables += 1;
                fbpt += usize::from(body.starts_with(FBPT_MAGIC));
            }
            FBPACK_PARTITION_DATA | FBPACK_SIDELOAD_DATA => {}
            _ => unknown_types += 1,
        }
        let name = if name.is_empty() {
            format!("Entry {i}")
        } else {
            name
        };
        // Entries for different products may share a name.
        let label = if product.is_empty() {
            name
        } else {
            format!("{name} ({product})")
        };
        if !body.is_empty() {
            members.push(fbpk_member(label, kind, body_offset, body));
        }
    }
    c.notes.push(format!(
        "FBPK v2 pack: {count} entries; platform \"{platform}\"; pack version \"{version}\"; data alignment {data_align} B"
    ));
    if slot_type != 0 {
        c.notes
            .push(format!("slot_type {slot_type} (meaning unconfirmed)"));
    }
    if total_size as usize != data.len() {
        c.notes.push(format!(
            "total_size field is {total_size} B; the file is {} B",
            data.len()
        ));
    }
    if unknown_types > 0 {
        c.notes.push(format!(
            "{unknown_types} entries have an unknown type; classified from their own bytes"
        ));
    }
    checksums.push_note(&mut c, "crc32");
    push_partition_table_note(&mut c, tables, fbpt);
    c.notes.push(NO_CPU_NOTE.into());
    c.push_metadata("android_fbpk_platform", "Platform", platform);
    c.push_metadata("android_bootloader_version", "Pack version", version);
    let listed = members.len();
    for member in members {
        if is_component_limit(c.children.len(), listed, &mut c.notes) {
            break;
        }
        c.children.push(member);
    }
    push_trailing_note(&mut c, data, end, "last entry");
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_names_must_be_printable_and_terminated() {
        assert_eq!(partition_name(b"aboot\0\0\0", "entry").unwrap(), "aboot");
        assert!(partition_name(b"aboot", "entry").is_err(), "no NUL");
        assert!(partition_name(b"\0abc", "entry").is_err(), "empty");
        assert!(
            partition_name(b"a\x01b\0", "entry").is_err(),
            "control byte"
        );
    }

    #[test]
    fn fugu_chunk_ids_have_labels() {
        assert_eq!(fugu_chunk_label(FUGU_CHUNK_IFWI), Some("IFWI"));
        assert_eq!(fugu_chunk_label(FUGU_CHUNK_DROIDBOOT), Some("droidboot"));
        assert_eq!(fugu_chunk_label(FUGU_CHUNK_SPLASH), Some("splash"));
        assert_eq!(fugu_chunk_label(b"UNKNOWN!"), None);
    }

    #[test]
    fn checksum_fields_match_only_the_ieee_crc32() {
        let mut checksums = Checksums::default();
        checksums.check(0, b"data");
        checksums.check(checksum::crc32(b"data"), b"data");
        checksums.check(1, b"data");
        assert_eq!((checksums.matched, checksums.unverified), (1, 1));
    }
}
