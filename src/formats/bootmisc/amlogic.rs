//! Amlogic USB burning images (`aml_upgrade_package.img`), item table
//! versions 1 and 2.
//!
//! Layouts, from the vendor U-Boot `amlImage_if.h` (`AmlFirmwareImg_t`,
//! `ItemInfo_V1`, `ItemInfo_V2`) and `optimus_img_decoder.c`
//! (`image_open`, `image_item_open`, `get_item_name`), Amlogic's packer
//! `amlImage.cpp` (`image_pack`, `image_check`), `crc32.cpp`
//! (`calc_img_crc`) and `sha1.c` (`gen_sha1sum_verify`), and ampack
//! `src/image.rs` (`try_read_file`). All fields are little-endian.
//!
//! Header (64 bytes): CRC-32 (0), version (4), magic (8), image size (0x0C,
//! 64 bits), item alignment (0x14), item count (0x18), reserved. The item
//! table follows at 0x40. An item record holds its ID (0, equal to its
//! index), file type (4: 0 normal, `0xFE` Android sparse), reader offset
//! (8), data offset (0x10) and size (0x18, both 64 bits), the main and sub
//! type names (0x20, 32 bytes each in version 1 and 256 bytes in version
//! 2), a verify flag, the backup flag and the backup item ID.
//!
//! The CRC-32 is the reflected `0xEDB88320` polynomial with initial value
//! `0xFFFFFFFF` and no final XOR, over every byte after the CRC field
//! (`calc_img_crc` from offset 4; ampack hashes from offset 4 as well).
//! A `VERIFY` item holds `"sha1sum "` and the 40-digit SHA-1 of the item
//! with the same sub type just before it.

use super::*;
use crate::formats::checksum::{self, Sha1};
use crate::formats::container::MAX_COMPONENTS;

/// `IMAGE_MAGIC` at offset 8.
const IMAGE_MAGIC: u32 = 0x27b5_1956;
const MAGIC_OFFSET: usize = 8;

/// Header fields and size (`AmlFirmwareImg_t`).
const CRC_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 4;
const IMAGE_SIZE_OFFSET: usize = 0x0c;
const ITEM_ALIGN_OFFSET: usize = 0x14;
const ITEM_COUNT_OFFSET: usize = 0x18;
const HEADER_SIZE: usize = 0x40;

/// The CRC covers everything after its own four-byte field.
const CRC_START: usize = 4;

/// `AML_FRMWRM_VER_V1` and `AML_FRMWRM_VER_V2`.
const VERSION_1: u32 = 1;
const VERSION_2: u32 = 2;

/// Item record sizes and name field sizes (`ItemInfo_V1`, `ItemInfo_V2`).
const ITEM_SIZE_V1: usize = 128;
const ITEM_SIZE_V2: usize = 576;
const NAME_SIZE_V1: usize = 0x20;
const NAME_SIZE_V2: usize = 0x100;

/// Item record fields.
const ITEM_ID: usize = 0;
const ITEM_FILE_TYPE: usize = 4;
const ITEM_DATA_OFFSET: usize = 0x10;
const ITEM_DATA_SIZE: usize = 0x18;
const ITEM_MAIN_TYPE: usize = 0x20;

/// Offsets after the two name fields: verify flag (4 bytes), backup flag
/// and backup item ID (2 bytes each).
const ITEM_IS_BACKUP_AFTER_NAMES: usize = 4;
const ITEM_BACKUP_ID_AFTER_NAMES: usize = 6;

/// `IMAGE_ITEM_TYPE_NORMAL` and `IMAGE_ITEM_TYPE_SPARSE`.
const FILE_TYPE_NORMAL: u32 = 0;
const FILE_TYPE_SPARSE: u32 = 0xfe;

/// Main types with a documented role. `PARTITION` items are burned to the
/// partition their sub type names; `bootloader` is the boot loader
/// (`optimus_sdc_burn.c`). `USB` items (`DDR`, `UBOOT`) are the stages the
/// USB burning tool loads (ampack `find_essentials`). Other main types,
/// such as `UBOOT` for SD-card burning, have no documented role and are
/// treated as generic items.
const MAIN_PARTITION: &str = "PARTITION";
const MAIN_VERIFY: &str = "VERIFY";
const MAIN_USB: &str = "USB";
const SUB_BOOTLOADER: &str = "bootloader";

/// Main types of configuration items: verification records, the SD burning
/// `ini` and the platform `conf` (ampack `find_essentials`).
const CONFIG_MAIN_TYPES: &[&str] = &[MAIN_VERIFY, "ini", "conf"];

/// ampack names the encrypted USB stages `DDR_ENC` and `UBOOT_ENC`.
const ENCRYPTED_SUFFIX: &str = "_ENC";

/// A `VERIFY` item: `"sha1sum "` and 40 hex digits (`gen_sha1sum_verify`).
const VERIFY_PREFIX: &[u8] = b"sha1sum ";
const VERIFY_SIZE: usize = 48;
const SHA1_SIZE: usize = 20;

/// Names listed per note (our bound).
const MAX_LISTED: usize = 16;

pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    (le_u32(data, MAGIC_OFFSET).ok()? == IMAGE_MAGIC).then_some(Layout::Amlogic)
}

/// Record and name field sizes of an item table version.
struct TableLayout {
    record_size: usize,
    name_size: usize,
}

fn table_layout(version: u32) -> Result<TableLayout> {
    match version {
        VERSION_1 => Ok(TableLayout {
            record_size: ITEM_SIZE_V1,
            name_size: NAME_SIZE_V1,
        }),
        VERSION_2 => Ok(TableLayout {
            record_size: ITEM_SIZE_V2,
            name_size: NAME_SIZE_V2,
        }),
        other => Err(error(format!("Unsupported Amlogic image version {other}"))),
    }
}

/// One item record.
struct Item<'a> {
    main_type: String,
    sub_type: String,
    file_type: u32,
    offset: usize,
    bytes: &'a [u8],
    /// The item whose data this item shares, when it is a backup item.
    backup_of: Option<u16>,
}

impl Item<'_> {
    fn label(&self) -> String {
        format!("{}/{}", self.main_type, self.sub_type)
    }
}

fn item<'a>(
    image: &'a [u8],
    record: &[u8],
    index: usize,
    layout: &TableLayout,
) -> Result<Item<'a>> {
    let id = le_u32(record, ITEM_ID)?;
    if id as usize != index {
        return Err(error(format!(
            "Invalid Amlogic item ID {id} in record {index}"
        )));
    }
    let offset = to_usize(le_u64(record, ITEM_DATA_OFFSET)?, "Amlogic item offset")?;
    let size = to_usize(le_u64(record, ITEM_DATA_SIZE)?, "Amlogic item size")?;
    let main_type = text_field(range(
        record,
        ITEM_MAIN_TYPE,
        layout.name_size,
        "item name",
    )?);
    let sub_offset = ITEM_MAIN_TYPE + layout.name_size;
    let sub_type = text_field(range(record, sub_offset, layout.name_size, "item name")?);
    let after_names = sub_offset + layout.name_size;
    let is_backup = le_u16(record, after_names + ITEM_IS_BACKUP_AFTER_NAMES)? != 0;
    let backup_id = le_u16(record, after_names + ITEM_BACKUP_ID_AFTER_NAMES)?;
    let what = format!("Amlogic item {index} ({main_type}/{sub_type}) data");
    let bytes = range(image, offset, size, &what)?;
    Ok(Item {
        main_type,
        sub_type,
        file_type: le_u32(record, ITEM_FILE_TYPE)?,
        offset,
        bytes,
        backup_of: is_backup.then_some(backup_id),
    })
}

/// The SHA-1 a `VERIFY` item records, when its contents have the packer's
/// form.
fn verify_digest(bytes: &[u8]) -> Option<[u8; SHA1_SIZE]> {
    if bytes.len() != VERIFY_SIZE || !bytes.starts_with(VERIFY_PREFIX) {
        return None;
    }
    let digits = &bytes[VERIFY_PREFIX.len()..];
    let mut digest = [0u8; SHA1_SIZE];
    for (out, pair) in digest.iter_mut().zip(digits.chunks_exact(2)) {
        let text = std::str::from_utf8(pair).ok()?;
        *out = u8::from_str_radix(text, 16).ok()?;
    }
    Some(digest)
}

fn sha1(bytes: &[u8]) -> [u8; SHA1_SIZE] {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finish()
}

/// How an item is listed.
enum Role {
    /// A boot loader stage: always classified, by the code model if needed.
    BootLoader,
    /// Configuration or verification data; never analyzed.
    Config,
    /// A stage the item name marks as encrypted; never analyzed.
    Encrypted,
    /// Anything else: analyzed only when it is a recognized format.
    Generic,
}

fn role(item: &Item<'_>) -> Role {
    let main = item.main_type.as_str();
    let sub = item.sub_type.as_str();
    if CONFIG_MAIN_TYPES.contains(&main) {
        Role::Config
    } else if main == MAIN_USB && sub.ends_with(ENCRYPTED_SUFFIX) {
        Role::Encrypted
    } else if main == MAIN_USB || (main == MAIN_PARTITION && sub == SUB_BOOTLOADER) {
        Role::BootLoader
    } else {
        Role::Generic
    }
}

/// What the item walk found, for the notes.
#[derive(Default)]
struct Summary {
    verified: usize,
    /// Item bytes hashed so far, against [`hash_budget`].
    hashed: usize,
    over_budget: Vec<String>,
    mismatched: Vec<String>,
    unpaired_verify: Vec<String>,
    unrecognized: Vec<String>,
    encrypted: Vec<String>,
    backups: Vec<String>,
    unknown_file_types: Vec<String>,
    unlisted: usize,
}

/// Check a `VERIFY` item against the item before it. A record that is not
/// in the packer's form, or that follows an item with another sub type, is
/// counted. A digest mismatch is noted rather than rejected: the image
/// CRC-32 already holds, so the image parses, but the burning tool's own
/// verification of that partition would fail.
fn check_verify(
    item: &Item<'_>,
    previous: Option<&Item<'_>>,
    budget: usize,
    summary: &mut Summary,
) {
    let Some(previous) = previous.filter(|p| p.sub_type == item.sub_type) else {
        summary.unpaired_verify.push(item.sub_type.clone());
        return;
    };
    let Some(recorded) = verify_digest(item.bytes) else {
        summary.unpaired_verify.push(item.sub_type.clone());
        return;
    };
    let hashed = summary.hashed.saturating_add(previous.bytes.len());
    if hashed > budget {
        summary.over_budget.push(previous.label());
        return;
    }
    summary.hashed = hashed;
    let computed = sha1(previous.bytes);
    if recorded == computed {
        summary.verified += 1;
    } else {
        summary.mismatched.push(format!(
            "{} (recorded {}, computed {})",
            previous.label(),
            hex::encode_upper(recorded),
            hex::encode_upper(computed)
        ));
    }
}

/// Most item bytes hashed for `VERIFY` records: twice the image, which
/// covers every item and one backup copy of each (our bound). Items may
/// overlap, so without a budget a crafted table could hash the same range
/// many times.
fn hash_budget(image_size: usize) -> usize {
    image_size.saturating_mul(2)
}

/// The child for an item, by its role.
fn child<'a>(item: &Item<'a>, summary: &mut Summary) -> Child<'a> {
    let label = item.label();
    match role(item) {
        Role::BootLoader => Child::stored(label, item.offset, item.bytes),
        Role::Config => Child::opaque(label, item.offset, item.bytes),
        Role::Encrypted => {
            summary.encrypted.push(label.clone());
            Child::opaque(label, item.offset, item.bytes)
        }
        Role::Generic => {
            let (child, recognized) = recognized_or_opaque(label.clone(), item.offset, item.bytes);
            if !recognized {
                summary.unrecognized.push(label);
            }
            child
        }
    }
}

fn describe(c: &mut Container<'_>, summary: &Summary) {
    if summary.verified > 0 {
        c.notes.push(format!(
            "{} verified",
            counted(
                summary.verified,
                "VERIFY SHA-1 record",
                "VERIFY SHA-1 records"
            )
        ));
    }
    if !summary.over_budget.is_empty() {
        c.notes.push(format!(
            "VERIFY SHA-1 records beyond the hashing budget (twice the image size) were not checked: {}",
            name_list(&summary.over_budget, MAX_LISTED)
        ));
    }
    if !summary.mismatched.is_empty() {
        c.notes.push(format!(
            "VERIFY SHA-1 records that do not match their item: {}",
            name_list(&summary.mismatched, MAX_LISTED)
        ));
    }
    if !summary.unpaired_verify.is_empty() {
        c.notes.push(format!(
            "VERIFY items not in the packer's form or not after their item; not checked: {}",
            name_list(&summary.unpaired_verify, MAX_LISTED)
        ));
    }
    if !summary.unrecognized.is_empty() {
        c.notes.push(format!(
            "Items that are not a recognized format are listed as opaque data: {}",
            name_list(&summary.unrecognized, MAX_LISTED)
        ));
    }
    if !summary.encrypted.is_empty() {
        c.notes.push(format!(
            "Items named as encrypted (_ENC) are opaque: {}",
            name_list(&summary.encrypted, MAX_LISTED)
        ));
    }
    if !summary.backups.is_empty() {
        c.notes.push(format!(
            "Backup items share the data of an earlier item: {}",
            name_list(&summary.backups, MAX_LISTED)
        ));
    }
    if !summary.unknown_file_types.is_empty() {
        c.notes.push(format!(
            "Items with a file type other than normal (0) or sparse (0xFE): {}",
            name_list(&summary.unknown_file_types, MAX_LISTED)
        ));
    }
    if summary.unlisted > 0 {
        c.notes.push(format!(
            "{} further items were not listed (limit {MAX_COMPONENTS})",
            summary.unlisted
        ));
    }
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = range(data, 0, HEADER_SIZE, "Amlogic image header")?;
    if le_u32(header, MAGIC_OFFSET)? != IMAGE_MAGIC {
        return Err(error("Missing Amlogic image magic"));
    }
    let version = le_u32(header, VERSION_OFFSET)?;
    let layout = table_layout(version)?;
    let image_size = to_usize(le_u64(header, IMAGE_SIZE_OFFSET)?, "Amlogic image size")?;
    if image_size < HEADER_SIZE {
        return Err(error(format!(
            "Invalid Amlogic image size {image_size} B: shorter than the 64 B header"
        )));
    }
    let image = range(data, 0, image_size, "Amlogic image")?;
    let stored_crc = le_u32(header, CRC_OFFSET)?;
    let computed_crc = checksum::crc32_update(!0, &image[CRC_START..]);
    if stored_crc != computed_crc {
        return Err(error(format!(
            "Invalid Amlogic image CRC-32 0x{stored_crc:08X}, computed 0x{computed_crc:08X}"
        )));
    }
    expect_padding(data, image_size, "Amlogic image")?;
    let count = le_u32(header, ITEM_COUNT_OFFSET)? as usize;
    if count > (image_size - HEADER_SIZE) / layout.record_size {
        return Err(error(format!(
            "Invalid Amlogic item count {count}: the item table exceeds the {} image",
            size_text(image_size)
        )));
    }
    let align = le_u32(header, ITEM_ALIGN_OFFSET)?;

    let mut c = Container::new(
        FileFormat::AmlogicUpgrade,
        Layout::Amlogic.label(),
        "amlogic",
    );
    c.consumed = image_size;
    c.notes.push(format!(
        "Amlogic burning image version {version}: {}, {} B item names; CRC-32 0x{stored_crc:08X} verified over {}",
        counted(count, "item", "items"),
        layout.name_size,
        size_text(image_size - CRC_START)
    ));
    c.notes
        .push("No field names an ISA; items are classified on their own bytes".into());
    c.push_metadata("amlogic_version", "Image version", u64::from(version));
    c.push_metadata("amlogic_items", "Items", count as u64);
    c.push_metadata("amlogic_item_align", "Item alignment (B)", u64::from(align));
    c.push_metadata(
        "amlogic_crc32",
        "CRC-32",
        format!("0x{stored_crc:08X} (verified)"),
    );

    let table = &image[HEADER_SIZE..HEADER_SIZE + count * layout.record_size];
    let mut summary = Summary::default();
    let mut previous: Option<Item<'_>> = None;
    for (index, record) in table.chunks_exact(layout.record_size).enumerate() {
        let item = item(image, record, index, &layout)?;
        if item.main_type == MAIN_VERIFY {
            check_verify(
                &item,
                previous.as_ref(),
                hash_budget(image_size),
                &mut summary,
            );
        }
        if let Some(source) = item.backup_of {
            summary
                .backups
                .push(format!("{} (item {source})", item.label()));
        }
        if !matches!(item.file_type, FILE_TYPE_NORMAL | FILE_TYPE_SPARSE) {
            summary
                .unknown_file_types
                .push(format!("{} (0x{:X})", item.label(), item.file_type));
        }
        if c.children.len() < MAX_COMPONENTS {
            let child = child(&item, &mut summary);
            c.children.push(child);
        } else {
            summary.unlisted += 1;
        }
        previous = Some(item);
    }
    describe(&mut c, &summary);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_records_parse_only_in_the_packer_form() {
        let digest = sha1(b"abc");
        let mut record = b"sha1sum ".to_vec();
        record.extend_from_slice(hex::encode(digest).as_bytes());
        assert_eq!(verify_digest(&record), Some(digest));
        let upper = format!("sha1sum {}", hex::encode_upper(digest));
        assert_eq!(verify_digest(upper.as_bytes()), Some(digest));
        assert_eq!(verify_digest(&record[..47]), None);
        record[10] = b'g';
        assert_eq!(verify_digest(&record), None);
    }

    #[test]
    fn sha1_matches_the_fips_example() {
        assert_eq!(
            hex::encode(sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn unknown_versions_are_unsupported() {
        assert!(table_layout(VERSION_1).is_ok());
        assert!(table_layout(VERSION_2).is_ok());
        assert!(table_layout(3).is_err());
    }
}
