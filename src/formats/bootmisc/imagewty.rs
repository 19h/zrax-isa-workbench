//! Allwinner PhoenixSuit/LiveSuit images (`IMAGEWTY`).
//!
//! Layouts, from Allwinner's `imagefile_new.h` (`ImageHead_t`,
//! `ImageItem_t`) and `imgdecode.c` (`Img_Open`, `Img_GetItemSize`,
//! `Img_ReadItem`) for header version `0x0300`, and from awutils
//! `imagewty.h` (`struct imagewty_header` `v1`, `struct
//! imagewty_file_header` `v1`) for header version `0x0100`, which only that
//! reverse-engineered source describes. All fields are little-endian.
//!
//! The 1024-byte header is followed by one 1024-byte item record per file.
//! Version `0x0300` header: magic (0), version (8), header size (0x0C),
//! attributes (0x10), image version (0x14), image length (0x18, 64 bits),
//! alignment (0x20), USB PID (0x24) and VID (0x28), hardware ID (0x2C),
//! firmware ID (0x30), item attributes (0x34), item size (0x38), item
//! count (0x3C), item table offset (0x40). Version `0x0300` item: version
//! (0), size (4), main type (8, 8 bytes), sub type (0x10, 16 bytes),
//! attributes (0x20), file name (0x24, 256 bytes), stored length (0x124),
//! file length (0x12C), data offset (0x134, each 64 bits), encryption
//! plug-in ID (0x13C, 64 bytes, all NUL when the file is not encrypted),
//! checksum (0x17C).
//!
//! Version `0x0100` header (awutils): image size (0x18), PID (0x20), VID
//! (0x24), hardware ID (0x28), firmware ID (0x2C), file count (0x38).
//! Version `0x0100` item: main type (8), sub type (0x10), stored length
//! (0x24), original length (0x28), data offset (0x2C), file name (0x34).
//!
//! Encryption (awutils `crypto_init`, `decrypt_image`): when the image does
//! not start with `IMAGEWTY`, the header, the item table and the file data
//! are RC6-encrypted block by block with three fixed 256-bit keys: 31 bytes
//! `0x00`, `0x01` or `0x02` followed by `'i'`, `'m'` or `'g'`. Files whose
//! name does not end in `.fex` carry an additional Twofish layer that
//! awutils does not decrypt, so they stay opaque here.

use super::rc6::{self, Schedule};
use super::*;
use crate::formats::container::{MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;

/// `IMAGE_MAGIC`.
const MAGIC: &[u8; 8] = b"IMAGEWTY";

/// `IMAGE_HEAD_SIZE` and `IMAGE_ITEM_TABLE_SIZE`: the header and each item
/// record are 1024 bytes, the table starts right after the header.
const HEADER_SIZE: usize = 1024;
const ITEM_SIZE: usize = 1024;

/// Header versions: `IMAGE_HEAD_VERSION` and awutils' `0x0100`.
const HEADER_VERSION_1: u32 = 0x0100;
const HEADER_VERSION_3: u32 = 0x0300;
const HEADER_VERSION_OFFSET: usize = 8;

/// Version `0x0300` header fields (`ImageHead_t`).
const V3_IMAGE_VERSION: usize = 0x14;
const V3_LENGTH: usize = 0x18;
const V3_PID: usize = 0x24;
const V3_VID: usize = 0x28;
const V3_HARDWARE_ID: usize = 0x2c;
const V3_FIRMWARE_ID: usize = 0x30;
const V3_ITEM_COUNT: usize = 0x3c;

/// Version `0x0100` header fields (awutils `imagewty_header.v1`).
const V1_IMAGE_VERSION: usize = 0x14;
const V1_IMAGE_SIZE: usize = 0x18;
const V1_PID: usize = 0x20;
const V1_VID: usize = 0x24;
const V1_HARDWARE_ID: usize = 0x28;
const V1_FIRMWARE_ID: usize = 0x2c;
const V1_ITEM_COUNT: usize = 0x38;

/// Item fields both versions share.
const ITEM_MAIN_TYPE: usize = 0x08;
const MAIN_TYPE_SIZE: usize = 8;
const ITEM_SUB_TYPE: usize = 0x10;
const SUB_TYPE_SIZE: usize = 16;
const FILE_NAME_SIZE: usize = 256;

/// Version `0x0300` item fields (`ImageItem_t`).
const V3_ITEM_NAME: usize = 0x24;
const V3_ITEM_STORED_LENGTH: usize = 0x124;
const V3_ITEM_FILE_LENGTH: usize = 0x12c;
const V3_ITEM_OFFSET: usize = 0x134;
const V3_ITEM_ENCRYPT_ID: usize = 0x13c;
const ENCRYPT_ID_SIZE: usize = 64;

/// Version `0x0100` item fields (awutils `imagewty_file_header.v1`).
const V1_ITEM_STORED_LENGTH: usize = 0x24;
const V1_ITEM_ORIGINAL_LENGTH: usize = 0x28;
const V1_ITEM_OFFSET: usize = 0x2c;
const V1_ITEM_NAME: usize = 0x34;

/// awutils decrypts the content of `.fex` files with RC6 only.
const FEX_SUFFIX: &str = ".fex";

/// A 256-bit key of 31 `fill` bytes and a final `last` byte
/// (`crypto_init`).
const fn fixed_key(fill: u8, last: u8) -> [u8; rc6::KEY_SIZE] {
    let mut key = [fill; rc6::KEY_SIZE];
    key[rc6::KEY_SIZE - 1] = last;
    key
}

/// The three published keys, expanded at compile time.
const HEADER_KEY: Schedule = Schedule::new(&fixed_key(0x00, b'i'));
const TABLE_KEY: Schedule = Schedule::new(&fixed_key(0x01, b'm'));
const DATA_KEY: Schedule = Schedule::new(&fixed_key(0x02, b'g'));

/// Names listed per note (our bound).
const MAX_LISTED: usize = 16;

/// The plaintext magic, or the magic after decrypting the first block with
/// the header key.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let first = data.get(..rc6::BLOCK_SIZE)?;
    if first.starts_with(MAGIC) {
        return Some(Layout::ImageWty);
    }
    let mut block: [u8; rc6::BLOCK_SIZE] = first.try_into().ok()?;
    HEADER_KEY.decrypt_block(&mut block);
    block
        .starts_with(MAGIC)
        .then_some(Layout::ImageWtyEncrypted)
}

/// `len` bytes at `offset`, RC6-decrypted with `key` when `encrypted`.
fn read<'a>(
    data: &'a [u8],
    offset: usize,
    len: usize,
    what: &str,
    key: &Schedule,
    encrypted: bool,
) -> Result<Cow<'a, [u8]>> {
    let stored = range(data, offset, len, what)?;
    if !encrypted {
        return Ok(Cow::Borrowed(stored));
    }
    let mut plain = stored.to_vec();
    key.decrypt(&mut plain);
    Ok(Cow::Owned(plain))
}

/// The header fields this parser reports.
struct Header {
    version: u32,
    image_version: u32,
    /// Declared image length in bytes.
    length: u64,
    count: u32,
    pid: u32,
    vid: u32,
    hardware_id: u32,
    firmware_id: u32,
}

fn header(bytes: &[u8]) -> Result<Header> {
    if !bytes.starts_with(MAGIC) {
        return Err(error("Missing IMAGEWTY magic"));
    }
    let version = le_u32(bytes, HEADER_VERSION_OFFSET)?;
    let header = match version {
        HEADER_VERSION_3 => Header {
            version,
            image_version: le_u32(bytes, V3_IMAGE_VERSION)?,
            length: le_u64(bytes, V3_LENGTH)?,
            count: le_u32(bytes, V3_ITEM_COUNT)?,
            pid: le_u32(bytes, V3_PID)?,
            vid: le_u32(bytes, V3_VID)?,
            hardware_id: le_u32(bytes, V3_HARDWARE_ID)?,
            firmware_id: le_u32(bytes, V3_FIRMWARE_ID)?,
        },
        HEADER_VERSION_1 => Header {
            version,
            image_version: le_u32(bytes, V1_IMAGE_VERSION)?,
            length: le_u32(bytes, V1_IMAGE_SIZE)?.into(),
            count: le_u32(bytes, V1_ITEM_COUNT)?,
            pid: le_u32(bytes, V1_PID)?,
            vid: le_u32(bytes, V1_VID)?,
            hardware_id: le_u32(bytes, V1_HARDWARE_ID)?,
            firmware_id: le_u32(bytes, V1_FIRMWARE_ID)?,
        },
        other => {
            return Err(error(format!(
                "Unsupported IMAGEWTY header version 0x{other:04X}"
            )))
        }
    };
    Ok(header)
}

/// One item record.
struct Item {
    main_type: String,
    sub_type: String,
    name: String,
    /// Data offset from the image start, in bytes.
    offset: usize,
    /// Stored length in the image, in bytes.
    stored_length: usize,
    /// Length of the file itself, in bytes.
    file_length: usize,
    /// The encryption plug-in ID names a plug-in (version `0x0300` only).
    plugin_encrypted: bool,
}

impl Item {
    fn label(&self) -> String {
        let types = format!("{}/{}", self.main_type, self.sub_type);
        if self.name.is_empty() {
            types
        } else {
            format!("{} ({types})", self.name)
        }
    }
}

fn item(record: &[u8], version: u32, index: usize) -> Result<Item> {
    let main_type = text_field(range(record, ITEM_MAIN_TYPE, MAIN_TYPE_SIZE, "item type")?);
    let sub_type = text_field(range(record, ITEM_SUB_TYPE, SUB_TYPE_SIZE, "item type")?);
    let (name_at, stored, file, offset, plugin_encrypted) = if version == HEADER_VERSION_3 {
        let encrypt_id = range(record, V3_ITEM_ENCRYPT_ID, ENCRYPT_ID_SIZE, "item field")?;
        (
            V3_ITEM_NAME,
            le_u64(record, V3_ITEM_STORED_LENGTH)?,
            le_u64(record, V3_ITEM_FILE_LENGTH)?,
            le_u64(record, V3_ITEM_OFFSET)?,
            encrypt_id.iter().any(|&b| b != 0),
        )
    } else {
        (
            V1_ITEM_NAME,
            le_u32(record, V1_ITEM_STORED_LENGTH)?.into(),
            le_u32(record, V1_ITEM_ORIGINAL_LENGTH)?.into(),
            le_u32(record, V1_ITEM_OFFSET)?.into(),
            false,
        )
    };
    let name = text_field(range(record, name_at, FILE_NAME_SIZE, "item name")?);
    let item = Item {
        main_type,
        sub_type,
        name,
        offset: to_usize(offset, "IMAGEWTY item offset")?,
        stored_length: to_usize(stored, "IMAGEWTY item stored length")?,
        file_length: to_usize(file, "IMAGEWTY item file length")?,
        plugin_encrypted,
    };
    if item.file_length > item.stored_length {
        return Err(error(format!(
            "Invalid IMAGEWTY item {index} ({}): file length {} B exceeds the stored length {} B",
            item.label(),
            item.file_length,
            item.stored_length
        )));
    }
    Ok(item)
}

/// What the item walk found, for the notes.
#[derive(Default)]
struct Summary {
    unrecognized: Vec<String>,
    plugin_encrypted: Vec<String>,
    twofish: Vec<String>,
    beyond_limit: Vec<String>,
    /// File bytes decrypted so far.
    decrypted: usize,
    unlisted: usize,
}

/// The child for an item of a plaintext image: analyzed only when the file
/// is a recognized format and no encryption plug-in is named.
fn plain_child<'a>(item: &Item, stored: &'a [u8], summary: &mut Summary) -> Child<'a> {
    let label = item.label();
    let file = &stored[..item.file_length];
    if item.plugin_encrypted {
        summary.plugin_encrypted.push(label.clone());
        return Child::opaque(label, item.offset, stored);
    }
    let (child, recognized) = recognized_or_opaque(label.clone(), item.offset, file);
    if !recognized {
        summary.unrecognized.push(label);
    }
    child
}

/// The child for an item of an encrypted image. A `.fex` file without an
/// encryption plug-in ID is decrypted with the data key, within the
/// per-file limit and the total decryption budget (every decrypted byte
/// counts, so overlapping items cannot multiply the work); the stored range
/// stays in file coordinates.
fn encrypted_child<'a>(item: &Item, stored: &'a [u8], summary: &mut Summary) -> Child<'a> {
    let label = item.label();
    if item.plugin_encrypted {
        summary.plugin_encrypted.push(label.clone());
        return Child::opaque(label, item.offset, stored);
    }
    if !item.name.ends_with(FEX_SUFFIX) {
        summary.twofish.push(label.clone());
        return Child::opaque(label, item.offset, stored);
    }
    let within_limits = item.file_length <= MAX_PAYLOAD
        && summary.decrypted.saturating_add(item.file_length) <= MAX_EXTRACTED;
    if !within_limits {
        summary.beyond_limit.push(label.clone());
        return Child::opaque(label, item.offset, stored);
    }
    summary.decrypted += item.file_length;
    let blocks = whole_blocks(item.file_length);
    let mut plain = stored[..blocks.min(stored.len())].to_vec();
    DATA_KEY.decrypt(&mut plain);
    plain.truncate(item.file_length);
    if !container::is_recognized(&plain) {
        summary.unrecognized.push(label.clone());
        return Child::opaque(label, item.offset, stored);
    }
    Child::decoded(label, item.offset, stored.len(), Cow::Owned(plain), "RC6")
}

/// `len` rounded up to whole RC6 blocks, saturating.
fn whole_blocks(len: usize) -> usize {
    let partial = len % rc6::BLOCK_SIZE;
    if partial == 0 {
        len
    } else {
        len.saturating_add(rc6::BLOCK_SIZE - partial)
    }
}

fn describe(c: &mut Container<'_>, summary: &Summary) {
    let lists = [
        (
            &summary.unrecognized,
            "Files that are not a recognized format are listed as opaque data",
        ),
        (
            &summary.plugin_encrypted,
            "Files with an encryption plug-in ID are opaque",
        ),
        (
            &summary.twofish,
            "Files without a .fex name carry an additional Twofish layer that awutils does not decrypt; opaque",
        ),
        (
            &summary.beyond_limit,
            "Files beyond the extraction limits were not decrypted",
        ),
    ];
    for (names, text) in lists {
        if !names.is_empty() {
            c.notes
                .push(format!("{text}: {}", name_list(names, MAX_LISTED)));
        }
    }
    if summary.unlisted > 0 {
        c.notes.push(format!(
            "{} further files were not listed (limit {MAX_COMPONENTS})",
            summary.unlisted
        ));
    }
}

fn push_metadata(c: &mut Container<'_>, header: &Header) {
    c.push_metadata(
        "imagewty_header_version",
        "Header version",
        format!("0x{:04X}", header.version),
    );
    c.push_metadata(
        "imagewty_image_version",
        "Image version",
        format!("0x{:X}", header.image_version),
    );
    c.push_metadata("imagewty_files", "Files", u64::from(header.count));
    c.push_metadata(
        "imagewty_usb_id",
        "USB VID:PID",
        format!("0x{:04X}:0x{:04X}", header.vid, header.pid),
    );
    c.push_metadata(
        "imagewty_hardware_id",
        "Hardware ID",
        format!("0x{:X}", header.hardware_id),
    );
    c.push_metadata(
        "imagewty_firmware_id",
        "Firmware ID",
        format!("0x{:X}", header.firmware_id),
    );
}

pub(super) fn parse(data: &[u8], encrypted: bool) -> Result<Container<'_>> {
    let header_bytes = read(
        data,
        0,
        HEADER_SIZE,
        "IMAGEWTY header",
        &HEADER_KEY,
        encrypted,
    )?;
    let header = header(&header_bytes)?;
    let count = header.count as usize;
    if count > (data.len() - HEADER_SIZE) / ITEM_SIZE {
        return Err(error(format!(
            "Invalid IMAGEWTY item count {count}: the item table exceeds the {} file",
            size_text(data.len())
        )));
    }
    let declared = to_usize(header.length, "IMAGEWTY image length")?;
    if declared > data.len() {
        return Err(error(format!(
            "Truncated IMAGEWTY image: {declared} B declared, {} B present",
            data.len()
        )));
    }

    let layout = if encrypted {
        Layout::ImageWtyEncrypted
    } else {
        Layout::ImageWty
    };
    let mut c = Container::new(FileFormat::AllwinnerImage, layout.label(), "imagewty");
    c.notes.push(format!(
        "Allwinner IMAGEWTY image, header version 0x{:04X}: {}",
        header.version,
        counted(count, "file", "files")
    ));
    if encrypted {
        c.notes.push(
            "Header and item table decrypted with the fixed RC6 keys awutils publishes; .fex file data decrypted with the data key".into(),
        );
    }
    if header.version == HEADER_VERSION_1 {
        c.notes
            .push("Header version 0x0100 is read with awutils' reverse-engineered layout".into());
    }
    c.notes
        .push("No field names an ISA; files are classified on their own bytes".into());
    c.notes
        .push("Per-file checksums are not verified (algorithm not documented)".into());
    push_metadata(&mut c, &header);

    let mut summary = Summary::default();
    let mut end = HEADER_SIZE + count * ITEM_SIZE;
    for index in 0..count {
        let record = read(
            data,
            HEADER_SIZE + index * ITEM_SIZE,
            ITEM_SIZE,
            "IMAGEWTY item record",
            &TABLE_KEY,
            encrypted,
        )?;
        let item = item(&record, header.version, index)?;
        let what = format!("IMAGEWTY item {index} ({}) data", item.label());
        let stored = range(data, item.offset, item.stored_length, &what)?;
        end = end.max(item.offset + item.stored_length);
        if c.children.len() >= MAX_COMPONENTS {
            summary.unlisted += 1;
            continue;
        }
        let child = if encrypted {
            encrypted_child(&item, stored, &mut summary)
        } else {
            plain_child(&item, stored, &mut summary)
        };
        c.children.push(child);
    }
    if declared < end {
        c.notes.push(format!(
            "Declared image length 0x{declared:X} is shorter than the end of its files at 0x{end:X}"
        ));
    }
    let consumed = declared.max(end);
    expect_padding(data, consumed, "IMAGEWTY image")?;
    c.consumed = consumed;
    describe(&mut c, &summary);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_follow_crypto_init() {
        let key = fixed_key(0x01, b'm');
        assert_eq!(key[..31], [1; 31]);
        assert_eq!(key[31], b'm');
    }

    #[test]
    fn encrypted_magic_is_found_after_decryption() {
        let mut block = [0u8; rc6::BLOCK_SIZE];
        block[..8].copy_from_slice(MAGIC);
        HEADER_KEY.encrypt_block(&mut block);
        assert_eq!(detect(&block), Some(Layout::ImageWtyEncrypted));
        assert_eq!(
            detect(b"IMAGEWTY\0\x03\0\0\0\0\0\0\0\0"),
            Some(Layout::ImageWty)
        );
        assert_eq!(detect(&[0u8; 16]), None);
        assert_eq!(detect(MAGIC), None);
    }

    #[test]
    fn lengths_round_up_to_whole_blocks() {
        assert_eq!(whole_blocks(0), 0);
        assert_eq!(whole_blocks(1), 16);
        assert_eq!(whole_blocks(32), 32);
        assert_eq!(whole_blocks(usize::MAX), usize::MAX);
    }
}
