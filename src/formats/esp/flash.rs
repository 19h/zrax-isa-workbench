//! Flash dumps: the second-stage bootloader, the ESP-IDF partition table
//! at 0x8000 and the partitions it lists.
//!
//! Partition table: ESP-IDF v5.5.1 `esp_flash_partitions.h`
//! (`esp_partition_info_t`, `ESP_PARTITION_MAGIC`,
//! `ESP_PARTITION_MAGIC_MD5`, `ESP_PARTITION_TABLE_MAX_LEN`, the flags),
//! `flash_partitions.c` (`esp_partition_table_verify`: the record walk, one
//! MD5 record over the records before it, the terminator),
//! `gen_esp32part.py` (types and subtypes) and
//! `partition_table/Kconfig.projbuild` (default offset 0x8000).
//! Bootloader offsets: esptool `BOOTLOADER_FLASH_OFFSET`, ESP-IDF
//! `BOOTLOADER_OFFSET_IN_FLASH`.

use super::*;
use crate::formats::checksum::Md5;
use crate::formats::container::{self, Child};

/// Default partition table offset (`CONFIG_PARTITION_TABLE_OFFSET`); a
/// table moved elsewhere is not found.
const TABLE_OFFSET: usize = 0x8000;

/// `ESP_PARTITION_TABLE_MAX_LEN`: records, including the terminator.
const TABLE_MAX_LEN: usize = 0xC00;

/// `sizeof(esp_partition_info_t)`.
const RECORD_SIZE: usize = 32;

/// `ESP_PARTITION_MAGIC` (bytes `AA 50`).
const PARTITION_MAGIC: u16 = 0x50AA;

/// `ESP_PARTITION_MAGIC_MD5` (bytes `EB EB`).
const PARTITION_MAGIC_MD5: u16 = 0xEBEB;

/// Terminator magic; `esp_partition_table_verify` also requires
/// `PART_TYPE_END` and `PART_SUBTYPE_END`.
const END_MAGIC: u16 = 0xFFFF;

/// `PART_TYPE_END`.
const PART_TYPE_END: u8 = 0xFF;

/// `PART_SUBTYPE_END`.
const PART_SUBTYPE_END: u8 = 0xFF;

/// `ESP_PARTITION_MD5_OFFSET`: the digest's offset in the MD5 record.
const MD5_OFFSET: usize = 16;

/// `PART_FLAG_ENCRYPTED`.
const PART_FLAG_ENCRYPTED: u32 = 1 << 0;

/// `PART_FLAG_READONLY`.
const PART_FLAG_READONLY: u32 = 1 << 1;

/// `PART_TYPE_APP`.
const PART_TYPE_APP: u8 = 0x00;

/// `PART_TYPE_DATA`.
const PART_TYPE_DATA: u8 = 0x01;

/// `PART_TYPE_BOOTLOADER`.
const PART_TYPE_BOOTLOADER: u8 = 0x02;

/// `PART_TYPE_PARTITION_TABLE`.
const PART_TYPE_PARTITION_TABLE: u8 = 0x03;

/// `PART_SUBTYPE_FACTORY`.
const PART_SUBTYPE_FACTORY: u8 = 0x00;

/// `PART_SUBTYPE_OTA_FLAG`: application subtypes 0x10-0x1F are `ota_0` to
/// `ota_15` (`PART_SUBTYPE_OTA_MASK` 0x0F).
const PART_SUBTYPE_OTA_FLAG: u8 = 0x10;

/// The last OTA application subtype, `ota_15`.
const PART_SUBTYPE_OTA_LAST: u8 = 0x1F;

/// `PART_SUBTYPE_TEST`.
const PART_SUBTYPE_TEST: u8 = 0x20;

/// `PART_SUBTYPE_TEE_0`.
const PART_SUBTYPE_TEE_0: u8 = 0x30;

/// `PART_SUBTYPE_TEE_1`.
const PART_SUBTYPE_TEE_1: u8 = 0x31;

/// `PART_SUBTYPE_BOOTLOADER_PRIMARY` and
/// `PART_SUBTYPE_PARTITION_TABLE_PRIMARY`.
const PART_SUBTYPE_PRIMARY: u8 = 0x00;

/// `PART_SUBTYPE_BOOTLOADER_OTA` and `PART_SUBTYPE_PARTITION_TABLE_OTA`.
const PART_SUBTYPE_OTA: u8 = 0x01;

/// `PART_SUBTYPE_BOOTLOADER_RECOVERY`.
const PART_SUBTYPE_RECOVERY: u8 = 0x02;

/// Data subtypes (`esp_partition_subtype_t`).
#[rustfmt::skip]
const DATA_SUBTYPES: &[(u8, &str)] = &[
    (0x00, "ota"), (0x01, "phy"), (0x02, "nvs"), (0x03, "coredump"), (0x04, "nvs_keys"),
    (0x05, "efuse"), (0x06, "undefined"), (0x80, "esphttpd"), (0x81, "fat"),
    (0x82, "spiffs"), (0x83, "littlefs"), (0x90, "tee_ota"),
];

/// Bootloader offsets of every chip (esptool `BOOTLOADER_FLASH_OFFSET`):
/// 0x0, 0x1000 (ESP32, ESP32-S2) and 0x2000 (ESP32-C5, -H4, -P4, -S31).
const BOOTLOADER_OFFSETS: [usize; 3] = [0x0, 0x1000, 0x2000];

/// Bytes of a data partition checked for a recognized format before the
/// whole partition is.
const RECOGNITION_PREFIX: usize = 4 << 10;

/// One partition table record.
#[derive(Debug, Clone)]
struct Partition {
    kind: u8,
    subtype: u8,
    /// Flash offset in bytes.
    offset: u32,
    /// Size in bytes.
    size: u32,
    label: String,
    flags: u32,
}

/// The MD5 record and the digest of the records before it.
#[derive(Debug, Clone, Copy)]
struct Md5Record {
    offset: usize,
    stored: [u8; 16],
    computed: [u8; 16],
}

/// The partition table at 0x8000.
#[derive(Debug)]
struct Table {
    partitions: Vec<Partition>,
    md5: Option<Md5Record>,
    /// Offset after the terminator.
    end: usize,
}

/// Strong recognition: every record of the table at 0x8000 carries the
/// partition or MD5 magic up to a terminator, and at least one partition
/// is listed. The MD5 digest itself is checked by [`parse`], so a damaged
/// table is a parse error.
pub(super) fn detect(data: &[u8]) -> bool {
    read_table(data).is_ok_and(|table| !table.partitions.is_empty())
}

/// Parse a flash dump: the bootloader, the partition table and each
/// partition by label.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let table = read_table(data)?;
    if table.partitions.is_empty() {
        return Err(error(format!(
            "Missing partitions in the table at 0x{TABLE_OFFSET:X}"
        )));
    }
    if let Some(md5) = table.md5.filter(|md5| md5.stored != md5.computed) {
        return Err(error(format!(
            "Invalid partition table MD5 at 0x{:X}: stored {}, computed {}",
            md5.offset,
            hex(&md5.stored),
            hex(&md5.computed)
        )));
    }
    let mut c = Container::new(FileFormat::EspFlash, Layout::Flash.label(), KEY_PREFIX);
    c.consumed = data.len();
    push_bootloader(&mut c, data);
    c.notes.push(table_note(&table));
    c.children.push(Child::opaque(
        "Partition table",
        TABLE_OFFSET,
        &data[TABLE_OFFSET..table.end],
    ));
    for (index, partition) in table.partitions.iter().enumerate() {
        push_partition(&mut c, data, index, partition);
    }
    note_overlaps(&mut c, &table.partitions);
    Ok(c)
}

/// Walk the records as `esp_partition_table_verify` does: partitions, at
/// most one MD5 record, then a terminator that is not the first record.
fn read_table(data: &[u8]) -> Result<Table> {
    let mut partitions = Vec::new();
    let mut md5 = None;
    for index in 0..TABLE_MAX_LEN / RECORD_SIZE {
        let at = TABLE_OFFSET + index * RECORD_SIZE;
        let record = slice(
            data,
            &format!("partition table record {index}"),
            at,
            RECORD_SIZE,
        )?;
        let magic = le_u16(record, "partition magic", 0)?;
        match magic {
            PARTITION_MAGIC => partitions.push(partition(record)?),
            PARTITION_MAGIC_MD5 => {
                if md5.is_some() {
                    return Err(error(format!(
                        "Duplicate partition table MD5 record at 0x{at:X}"
                    )));
                }
                md5 = Some(md5_record(data, at, record)?);
            }
            END_MAGIC
                if index > 0 && record[2] == PART_TYPE_END && record[3] == PART_SUBTYPE_END =>
            {
                return Ok(Table {
                    partitions,
                    md5,
                    end: at + RECORD_SIZE,
                });
            }
            _ => {
                return Err(error(format!(
                    "Invalid partition table record {index} at 0x{at:X}: magic 0x{magic:04X}"
                )))
            }
        }
    }
    Err(error(format!(
        "Missing partition table terminator in the {} at 0x{TABLE_OFFSET:X}",
        size_text(TABLE_MAX_LEN as u64)
    )))
}

/// A partition record: magic, type (2), subtype (3), offset (4), size (8),
/// NUL-padded label (0x0C, 16 bytes), flags (0x1C).
fn partition(record: &[u8]) -> Result<Partition> {
    Ok(Partition {
        kind: record[2],
        subtype: record[3],
        offset: le_u32(record, "partition offset", 4)?,
        size: le_u32(record, "partition size", 8)?,
        label: c_string(&record[0x0C..0x1C]),
        flags: le_u32(record, "partition flags", 0x1C)?,
    })
}

/// The MD5 record at `at` and the MD5 of every record before it.
fn md5_record(data: &[u8], at: usize, record: &[u8]) -> Result<Md5Record> {
    let mut hasher = Md5::new();
    hasher.update(slice(
        data,
        "partition table",
        TABLE_OFFSET,
        at - TABLE_OFFSET,
    )?);
    Ok(Md5Record {
        offset: at,
        stored: array(record, "partition table MD5", MD5_OFFSET)?,
        computed: hasher.finish(),
    })
}

fn table_note(table: &Table) -> String {
    let md5 = if table.md5.is_some() {
        "MD5 verified"
    } else {
        "no MD5 record"
    };
    format!(
        "Partition table at 0x{TABLE_OFFSET:X}: {} partitions; {md5}",
        table.partitions.len()
    )
}

/// The bootloader image at the first offset where one validates, or the
/// bootloader region as opaque bytes when none does.
fn push_bootloader<'a>(c: &mut Container<'a>, data: &'a [u8]) {
    for offset in BOOTLOADER_OFFSETS {
        let Some(found) = data.get(offset..TABLE_OFFSET).and_then(image::validate) else {
            continue;
        };
        let before = &data[..offset];
        if !is_erased(before) {
            c.notes.push(format!(
                "0x0-0x{:X} before the bootloader is not parsed",
                offset - 1
            ));
            c.children
                .push(Child::opaque("Before the bootloader", 0, before));
        }
        c.notes.push(bootloader_note(data, offset, found));
        c.children.push(Child::stored(
            "Bootloader",
            offset,
            &data[offset..offset + found.size],
        ));
        return;
    }
    let region = &data[..TABLE_OFFSET];
    if is_blank(region) {
        c.notes.push(format!(
            "No bootloader: 0x0-0x{:X} is erased flash",
            TABLE_OFFSET - 1
        ));
        return;
    }
    c.notes.push(
        "No valid bootloader image at 0x0, 0x1000 or 0x2000; the region before the partition \
         table is listed as opaque (it may be encrypted)"
            .into(),
    );
    c.children
        .push(Child::opaque("Bootloader region", 0, region));
}

fn bootloader_note(data: &[u8], offset: usize, found: image::Found) -> String {
    let image = &data[offset..offset + found.size];
    let described = match (found.layout, image::chip(image, found.layout)) {
        (Layout::Image, Some(chip)) if chip.bootloader_offset != offset => format!(
            "{} image; the documented bootloader offset of the {} is 0x{:X}",
            chip.name, chip.name, chip.bootloader_offset
        ),
        (_, Some(chip)) => format!("{} image ({})", chip.name, found.layout.label()),
        (layout, None) => layout.label().to_string(),
    };
    format!(
        "Bootloader at 0x{offset:X}: {described}, {}",
        size_text(found.size as u64)
    )
}

/// One partition: its metadata entry, then a child by type, or a note when
/// it is erased, empty or outside the dump.
fn push_partition<'a>(c: &mut Container<'a>, data: &'a [u8], index: usize, partition: &Partition) {
    let label = if partition.label.is_empty() {
        format!("Partition {index}")
    } else {
        partition.label.clone()
    };
    c.push_metadata(
        format!("{KEY_PREFIX}_partition_{index}"),
        label.clone(),
        describe(partition),
    );
    let Some(bytes) = partition_bytes(c, data, &label, partition) else {
        return;
    };
    let offset = partition.offset as usize;
    if bytes.is_empty() {
        c.notes.push(format!("{label}: empty partition"));
    } else if partition.flags & PART_FLAG_ENCRYPTED != 0 {
        c.notes
            .push(format!("{label}: encrypted partition; listed as opaque"));
        c.children.push(Child::opaque(label, offset, bytes));
    } else if is_blank(bytes) {
        c.notes.push(format!("{label}: erased"));
    } else {
        match partition.kind {
            PART_TYPE_APP | PART_TYPE_BOOTLOADER => push_image(c, label, offset, bytes),
            PART_TYPE_PARTITION_TABLE => c.children.push(Child::opaque(label, offset, bytes)),
            _ => push_data(c, label, offset, bytes),
        }
    }
}

/// The stored bytes of `partition`, cut at the end of the dump, or `None`
/// (with a note) when it starts beyond the dump.
fn partition_bytes<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    label: &str,
    partition: &Partition,
) -> Option<&'a [u8]> {
    let start = u64::from(partition.offset);
    let end = start + u64::from(partition.size);
    let available = data.len() as u64;
    if start >= available {
        c.notes.push(format!(
            "{label}: 0x{start:X} lies outside the dump ({})",
            size_text(available)
        ));
        return None;
    }
    if end > available {
        c.notes.push(format!(
            "{label}: truncated; the dump ends 0x{:X} into the {} partition",
            available - start,
            size_text(u64::from(partition.size))
        ));
    }
    let start = usize::try_from(start).ok()?;
    let end = usize::try_from(end.min(available)).ok()?;
    data.get(start..end)
}

/// An application or bootloader partition: the image as a child, and any
/// data after it that is not erased as an opaque child.
fn push_image<'a>(c: &mut Container<'a>, label: String, offset: usize, bytes: &'a [u8]) {
    let Some(found) = image::validate(bytes) else {
        c.notes.push(format!(
            "{label}: not a valid ESP image (it may be encrypted); listed as opaque"
        ));
        c.children.push(Child::opaque(label, offset, bytes));
        return;
    };
    let (image, rest) = bytes.split_at(found.size);
    if !is_erased(rest) {
        c.children.push(Child::opaque(
            format!("{label} (data after the image)"),
            offset + found.size,
            rest,
        ));
    }
    c.children.push(Child::stored(label, offset, image));
}

/// A data partition: listed as its own format when the classifier
/// recognizes one, otherwise opaque.
fn push_data<'a>(c: &mut Container<'a>, label: String, offset: usize, bytes: &'a [u8]) {
    let prefix = &bytes[..bytes.len().min(RECOGNITION_PREFIX)];
    if container::is_recognized(prefix) && container::is_recognized(bytes) {
        c.children
            .push(Child::stored(label, offset, bytes).if_recognized());
    } else {
        c.children.push(Child::opaque(label, offset, bytes));
    }
}

/// `"app ota_0 at 0x10000, 1 MiB, readonly"`.
fn describe(partition: &Partition) -> String {
    let mut text = format!(
        "{} {} at 0x{:X}, {}",
        type_name(partition.kind),
        subtype_name(partition.kind, partition.subtype),
        partition.offset,
        size_text(u64::from(partition.size))
    );
    if partition.flags & PART_FLAG_ENCRYPTED != 0 {
        text.push_str(", encrypted");
    }
    if partition.flags & PART_FLAG_READONLY != 0 {
        text.push_str(", readonly");
    }
    let unknown = partition.flags & !(PART_FLAG_ENCRYPTED | PART_FLAG_READONLY);
    if unknown != 0 {
        write!(text, ", unknown flags 0x{unknown:X}").expect("writing to a String cannot fail");
    }
    text
}

fn type_name(kind: u8) -> String {
    match kind {
        PART_TYPE_APP => "app".into(),
        PART_TYPE_DATA => "data".into(),
        PART_TYPE_BOOTLOADER => "bootloader".into(),
        PART_TYPE_PARTITION_TABLE => "partition_table".into(),
        other => format!("type 0x{other:02X}"),
    }
}

fn subtype_name(kind: u8, subtype: u8) -> String {
    let named = match (kind, subtype) {
        (PART_TYPE_APP, PART_SUBTYPE_FACTORY) => Some("factory".to_string()),
        (PART_TYPE_APP, PART_SUBTYPE_OTA_FLAG..=PART_SUBTYPE_OTA_LAST) => {
            Some(format!("ota_{}", subtype - PART_SUBTYPE_OTA_FLAG))
        }
        (PART_TYPE_APP, PART_SUBTYPE_TEST) => Some("test".into()),
        (PART_TYPE_APP, PART_SUBTYPE_TEE_0..=PART_SUBTYPE_TEE_1) => {
            Some(format!("tee_{}", subtype - PART_SUBTYPE_TEE_0))
        }
        (PART_TYPE_DATA, _) => DATA_SUBTYPES
            .iter()
            .find(|(value, _)| *value == subtype)
            .map(|(_, name)| (*name).to_string()),
        (PART_TYPE_BOOTLOADER | PART_TYPE_PARTITION_TABLE, PART_SUBTYPE_PRIMARY) => {
            Some("primary".into())
        }
        (PART_TYPE_BOOTLOADER | PART_TYPE_PARTITION_TABLE, PART_SUBTYPE_OTA) => Some("ota".into()),
        (PART_TYPE_BOOTLOADER, PART_SUBTYPE_RECOVERY) => Some("recovery".into()),
        _ => None,
    };
    named.unwrap_or_else(|| format!("subtype 0x{subtype:02X}"))
}

/// Note partitions whose ranges overlap; `gen_esp32part.py` rejects them,
/// the dump still lists both.
fn note_overlaps(c: &mut Container<'_>, partitions: &[Partition]) {
    let mut ranges: Vec<(u64, u64, &str)> = partitions
        .iter()
        .map(|p| {
            let start = u64::from(p.offset);
            (start, start + u64::from(p.size), p.label.as_str())
        })
        .collect();
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        let (first, second) = (pair[0], pair[1]);
        if second.0 < first.1 {
            c.notes.push(format!(
                "Partitions {} and {} overlap at 0x{:X}",
                first.2, second.2, second.0
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtypes_follow_esp_partition_h() {
        assert_eq!(subtype_name(PART_TYPE_APP, 0x11), "ota_1");
        assert_eq!(subtype_name(PART_TYPE_APP, 0x31), "tee_1");
        assert_eq!(subtype_name(PART_TYPE_DATA, 0x82), "spiffs");
        assert_eq!(subtype_name(PART_TYPE_BOOTLOADER, 0x02), "recovery");
        assert_eq!(
            subtype_name(PART_TYPE_PARTITION_TABLE, 0x02),
            "subtype 0x02"
        );
        assert_eq!(type_name(0x40), "type 0x40");
    }

    #[test]
    fn descriptions_name_flags() {
        let partition = Partition {
            kind: PART_TYPE_DATA,
            subtype: 0x02,
            offset: 0x9000,
            size: 0x6000,
            label: "nvs".into(),
            flags: PART_FLAG_ENCRYPTED | PART_FLAG_READONLY | 0x10,
        };
        assert_eq!(
            describe(&partition),
            "data nvs at 0x9000, 24 KiB, encrypted, readonly, unknown flags 0x10"
        );
    }
}
