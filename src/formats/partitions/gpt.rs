//! The GUID Partition Table (UEFI 2.10, 5.3).
//!
//! LBA 0 holds a protective MBR (a type `0xEE` record from LBA 1) and LBA 1
//! the header, all fields little-endian: `EFI PART` (0), revision (8),
//! header size (12), header CRC-32 over the header size with this field
//! zeroed (16), reserved (20), `MyLBA` (24), `AlternateLBA` (32), first and
//! last usable LBA (40, 48; inclusive), disk GUID (56), partition entry LBA
//! (72), entry count (80), entry size (84; 128 B times a power of two) and
//! the entry array CRC-32 (88). Each entry holds the type GUID (0; zero when
//! unused), the unique GUID (16), the first and last LBA (32, 40;
//! inclusive), attributes (48) and a UTF-16LE name of 36 code units (56).
//! The backup header in the last LBA mirrors the primary, with its own
//! entry array between the usable range and itself. The CRC is the IEEE
//! 802.3 CRC-32 that Linux `efi_crc32` computes.

use super::*;

/// Header signature (`0x5452415020494645`).
const SIGNATURE: &[u8; 8] = b"EFI PART";

/// Logical block sizes tried for LBA 1: the two sizes UEFI 2.10, 5.3.1
/// names. The header does not record its block size.
const BLOCK_SIZES: [usize; 2] = [512, 4096];

/// `Revision` of the header this layout describes.
const REVISION_1_0: u32 = 0x0001_0000;

/// Header fields up to the entry array CRC (Table 5.5).
const MIN_HEADER_SIZE: usize = 92;

/// Offset of `HeaderCRC32`, zeroed while the header CRC is computed.
const HEADER_CRC: usize = 16;

/// Entry layout (Table 5.6): the fields up to the name.
const MIN_ENTRY_SIZE: usize = 128;
const NAME_OFFSET: usize = 56;
const NAME_SIZE: usize = 72;

/// Attribute bits (Table 5.8).
const ATTRIBUTE_NAMES: [(u64, &str); 3] = [
    (1 << 0, "required"),
    (1 << 1, "no block I/O"),
    (1 << 2, "legacy BIOS bootable"),
];

/// GRUB's BIOS boot partition (`GRUB_GPT_PARTITION_TYPE_BIOS_BOOT`), into
/// which GRUB embeds its core image (GRUB 2.12 manual, "BIOS
/// installation"). The manual names no ISA, so the code model classifies it.
const BIOS_BOOT: &str = "21686148-6449-6E6F-744E-656564454649";

/// Partition type GUIDs with names: UEFI 2.10 Table 5.7, GRUB 2.12
/// `gpt_partition.h` and util-linux v2.40.2 `include/pt-gpt-partnames.h`.
/// Names describe content only; they are never ISA evidence, though some
/// name an architecture.
const TYPE_NAMES: &[(&str, &str)] = &[
    ("C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "EFI System"),
    (
        "024DEE41-33E7-11D3-9D69-0008C781F39F",
        "MBR partition scheme",
    ),
    (BIOS_BOOT, "BIOS boot"),
    ("D3BFE2DE-3DAF-11DF-BA40-E3A556D89593", "Intel Fast Flash"),
    ("9E1A2D38-C612-4316-AA26-8B49521E5A8B", "PowerPC PReP boot"),
    ("E3C9E316-0B5C-4DB8-817D-F92DF00215AE", "Microsoft reserved"),
    (
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
        "Microsoft basic data",
    ),
    (
        "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3",
        "Microsoft LDM metadata",
    ),
    ("AF9B60A0-1431-4F62-BC68-3311714A69AD", "Microsoft LDM data"),
    (
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC",
        "Windows recovery environment",
    ),
    ("0657FD6D-A4AB-43C4-84E5-0933C84B4F4F", "Linux swap"),
    ("0FC63DAF-8483-4772-8E79-3D69D8477DE4", "Linux filesystem"),
    ("44479540-F297-41B2-9AF7-D131D5F0458A", "Linux root (x86)"),
    (
        "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709",
        "Linux root (x86-64)",
    ),
    ("69DAD710-2CE4-4E3C-B16C-21A1D49ABED3", "Linux root (ARM)"),
    (
        "B921B045-1DF0-41C3-AF44-4C6F280D3FAE",
        "Linux root (ARM-64)",
    ),
    (
        "72EC70A6-CF74-40E6-BD49-4BDA08E8F224",
        "Linux root (RISC-V-64)",
    ),
    ("933AC7E1-2EB4-4F13-B844-0E14E2AEF915", "Linux home"),
    ("A19D880F-05FC-4D3B-A006-743F0F84911E", "Linux RAID"),
    ("E6D6D379-F507-44C2-A23C-238F2A3DF928", "Linux LVM"),
    (
        "BC13C2FF-59E6-4262-A352-B275FD6F7172",
        "Linux extended boot",
    ),
    ("516E7CB4-6ECF-11D6-8FF8-00022D09712B", "FreeBSD data"),
    ("83BD6B9D-7F41-11DC-BE0B-001560B84F0F", "FreeBSD boot"),
    ("516E7CB6-6ECF-11D6-8FF8-00022D09712B", "FreeBSD UFS"),
    ("516E7CBA-6ECF-11D6-8FF8-00022D09712B", "FreeBSD ZFS"),
    ("48465300-0000-11AA-AA11-00306543ECAC", "Apple HFS/HFS+"),
    ("7C3457EF-0000-11AA-AA11-00306543ECAC", "Apple APFS"),
    ("426F6F74-0000-11AA-AA11-00306543ECAC", "Apple boot"),
    ("FE3A2A5D-4F32-41A7-B725-ACCC3285A309", "ChromeOS kernel"),
    ("3CB8E202-3B7E-47DD-8A3C-7FF2A13CFCEC", "ChromeOS root fs"),
    ("CAB6E88E-ABF3-4102-A07A-D4BB9BE3C1D3", "ChromeOS firmware"),
    ("3DE21764-95BD-54BD-A5C3-4ABE786F38A8", "U-Boot environment"),
];

/// Whether LBA 1 holds the header signature for one of [`BLOCK_SIZES`].
pub(super) fn has_header_signature(data: &[u8]) -> bool {
    BLOCK_SIZES
        .iter()
        .any(|&block_size| has_signature_at(data, block_size))
}

fn has_signature_at(data: &[u8], offset: usize) -> bool {
    data.get(offset..offset + SIGNATURE.len()) == Some(SIGNATURE.as_slice())
}

/// Which copy a header is. The entry arrays lie on opposite sides of the
/// usable range: after the primary header, and before the backup header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TableCopy {
    Primary,
    Backup,
}

/// The header fields, after the checks of [`parse_header`].
#[derive(Debug, Clone)]
struct Header {
    revision: u32,
    my_lba: u64,
    alternate_lba: u64,
    first_usable: u64,
    last_usable: u64,
    disk_guid: [u8; 16],
    entry_lba: u64,
    entry_count: u32,
    /// Bytes per entry.
    entry_size: usize,
    entry_crc: u32,
}

impl Header {
    /// Bytes of the entry array. Below 2^63: a 32-bit count times an entry
    /// size of at most 2^31.
    fn array_size(&self) -> u64 {
        u64::from(self.entry_count) * self.entry_size as u64
    }
}

/// A used partition entry.
#[derive(Debug, Clone)]
struct Entry {
    /// 1-based entry number.
    number: usize,
    type_guid: String,
    unique_guid: String,
    first_lba: u64,
    last_lba: u64,
    attributes: u64,
    name: String,
}

/// A header and entry array that validated, and where they came from.
struct Located<'a> {
    block_size: usize,
    header: Header,
    array: &'a [u8],
    /// Why the primary was not used, when the backup was.
    primary_failure: Option<String>,
}

/// A header and its partition entry array, both checked.
struct Table<'a> {
    header: Header,
    /// `entry_count` entries of `entry_size` bytes.
    array: &'a [u8],
}

/// `EFI_GUID` text: the first three fields are little-endian
/// (`UINT32, UINT16, UINT16, UINT8[8]`, as GRUB's `grub_cpu_to_le32` and
/// `le16` spell the BIOS boot GUID).
fn guid_text(guid: &[u8; 16]) -> String {
    let mut text = format!(
        "{:08X}-{:04X}-{:04X}-",
        u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]),
        u16::from_le_bytes([guid[4], guid[5]]),
        u16::from_le_bytes([guid[6], guid[7]])
    );
    for (i, b) in guid[8..].iter().enumerate() {
        if i == 2 {
            text.push('-');
        }
        let _ = write!(text, "{b:02X}");
    }
    text
}

fn type_name(guid: &str) -> Option<&'static str> {
    TYPE_NAMES
        .iter()
        .find(|&&(id, _)| id == guid)
        .map(|&(_, name)| name)
}

/// A partition name: UTF-16LE up to the first NUL, with invalid code units
/// and control characters replaced.
fn utf16_name(field: &[u8]) -> String {
    let units = field
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|&unit| unit != 0);
    char::decode_utf16(units)
        .map(|c| match c {
            Ok(c) if !c.is_control() => c,
            _ => char::REPLACEMENT_CHARACTER,
        })
        .collect()
}

/// Byte offset of `lba` blocks of `block_size`, when it fits.
fn lba_offset(lba: u64, block_size: usize) -> Option<u64> {
    lba.checked_mul(block_size as u64)
}

/// Parse the header at `lba` and check it as UEFI 2.10, 5.3.2 and Linux
/// `is_gpt_valid` do: signature, header size, header CRC-32, `MyLBA`, the
/// usable range (with the header outside it, as libblkid requires), a
/// nonzero entry count, the entry size, and an entry array on the header's
/// side of the usable range.
fn parse_header(data: &[u8], block_size: usize, lba: u64, copy: TableCopy) -> Result<Header> {
    let offset = lba_offset(lba, block_size)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or_else(|| error(format!("Invalid GPT header LBA {lba}")))?;
    let block = slice(data, offset, block_size, "GPT header")?;
    if !block.starts_with(SIGNATURE) {
        return Err(error(format!(
            "Missing GPT header signature \"EFI PART\" at LBA {lba} (0x{offset:X})"
        )));
    }
    let header_size = le_u32(block, 12)? as usize;
    if !(MIN_HEADER_SIZE..=block_size).contains(&header_size) {
        return Err(error(format!(
            "Invalid GPT header size {header_size} B at LBA {lba}: must be {MIN_HEADER_SIZE} B \
             to the block size, {block_size} B"
        )));
    }
    let stored_crc = le_u32(block, HEADER_CRC)?;
    let mut crc = checksum::crc32_update(!0, &block[..HEADER_CRC]);
    crc = checksum::crc32_update(crc, &[0; 4]);
    crc = !checksum::crc32_update(crc, &block[HEADER_CRC + 4..header_size]);
    if crc != stored_crc {
        return Err(error(format!(
            "Invalid GPT header CRC-32 at LBA {lba}: stored 0x{stored_crc:08X}, computed \
             0x{crc:08X}"
        )));
    }
    let my_lba = le_u64(block, 24)?;
    if my_lba != lba {
        return Err(error(format!(
            "Invalid GPT header at LBA {lba}: MyLBA is {my_lba}"
        )));
    }
    let first_usable = le_u64(block, 40)?;
    let last_usable = le_u64(block, 48)?;
    if first_usable > last_usable {
        return Err(error(format!(
            "Invalid GPT usable range: first usable LBA {first_usable} after last usable LBA \
             {last_usable}"
        )));
    }
    if last_usable
        .checked_add(1)
        .and_then(|end| lba_offset(end, block_size))
        .is_none()
    {
        return Err(error(format!(
            "Invalid GPT last usable LBA 0x{last_usable:X}: beyond 64-bit byte offsets"
        )));
    }
    if (first_usable..=last_usable).contains(&lba) {
        return Err(error(format!(
            "Invalid GPT header at LBA {lba}: inside the usable range {first_usable}-{last_usable}"
        )));
    }
    let entry_count = le_u32(block, 80)?;
    if entry_count == 0 {
        return Err(error(format!(
            "Invalid GPT header at LBA {lba}: no partition entries"
        )));
    }
    let entry_size = le_u32(block, 84)? as usize;
    if entry_size < MIN_ENTRY_SIZE || !entry_size.is_power_of_two() {
        return Err(error(format!(
            "Invalid GPT partition entry size {entry_size} B: must be 128 B times a power of two"
        )));
    }
    let header = Header {
        revision: le_u32(block, 8)?,
        my_lba,
        alternate_lba: le_u64(block, 32)?,
        first_usable,
        last_usable,
        disk_guid: array(block, 56)?,
        entry_lba: le_u64(block, 72)?,
        entry_count,
        entry_size,
        entry_crc: le_u32(block, 88)?,
    };
    check_array_position(&header, block_size, copy)?;
    Ok(header)
}

/// UEFI 2.10, 5.3.1: the primary entry array lies after the primary header
/// and ends before the first usable LBA; the backup array lies after the
/// last usable LBA and ends before the backup header.
fn check_array_position(header: &Header, block_size: usize, copy: TableCopy) -> Result<()> {
    let block = block_size as u64;
    let blocks = header.array_size() / block + u64::from(header.array_size() % block != 0);
    let end = header.entry_lba.checked_add(blocks);
    let placed = match copy {
        TableCopy::Primary => {
            header.entry_lba > header.my_lba && end.is_some_and(|end| end <= header.first_usable)
        }
        TableCopy::Backup => {
            header.entry_lba > header.last_usable && end.is_some_and(|end| end <= header.my_lba)
        }
    };
    if placed {
        return Ok(());
    }
    Err(error(format!(
        "Invalid GPT partition entry array at LBA {} ({blocks} blocks): it must lie between \
         the header at LBA {} and the usable range {}-{}",
        header.entry_lba, header.my_lba, header.first_usable, header.last_usable
    )))
}

/// The entry array of `header`, after its CRC-32 check.
fn entry_array<'a>(data: &'a [u8], header: &Header, block_size: usize) -> Result<&'a [u8]> {
    let size = header.array_size();
    let offset = lba_offset(header.entry_lba, block_size).unwrap_or(u64::MAX);
    let array = usize::try_from(offset)
        .ok()
        .zip(usize::try_from(size).ok())
        .and_then(|(offset, size)| data.get(offset..)?.get(..size));
    let Some(array) = array else {
        let present = data
            .len()
            .saturating_sub(usize::try_from(offset).unwrap_or(usize::MAX));
        return Err(error(format!(
            "Truncated GPT partition entry array: {size} B at 0x{offset:X}, {} B present",
            (present as u64).min(size)
        )));
    };
    let computed = checksum::crc32(array);
    if computed != header.entry_crc {
        return Err(error(format!(
            "Invalid GPT partition entry array CRC-32 at LBA {}: stored 0x{:08X}, computed \
             0x{computed:08X}",
            header.entry_lba, header.entry_crc
        )));
    }
    Ok(array)
}

/// The header and entry array at `lba`, both checked.
fn table(data: &[u8], block_size: usize, lba: u64, copy: TableCopy) -> Result<Table<'_>> {
    let header = parse_header(data, block_size, lba, copy)?;
    let array = entry_array(data, &header, block_size)?;
    Ok(Table { header, array })
}

/// Find a valid table: the primary at LBA 1 for each block size whose LBA 1
/// holds the signature, else the backup in the last block of the file
/// (UEFI 2.10, 5.3.2: when the primary is corrupt, software must check the
/// last LBA of the device).
fn locate(data: &[u8]) -> Result<Located<'_>> {
    let mut primary_error = None;
    for block_size in BLOCK_SIZES {
        if !has_signature_at(data, block_size) {
            continue;
        }
        match table(
            data,
            block_size,
            u64::from(GPT_HEADER_LBA),
            TableCopy::Primary,
        ) {
            Ok(Table { header, array }) => {
                return Ok(Located {
                    block_size,
                    header,
                    array,
                    primary_failure: None,
                })
            }
            Err(e) => {
                primary_error.get_or_insert(e);
            }
        }
    }
    for block_size in BLOCK_SIZES {
        let Some(last) = (data.len() / block_size).checked_sub(1) else {
            continue;
        };
        if last <= GPT_HEADER_LBA as usize || !has_signature_at(data, last * block_size) {
            continue;
        }
        let backup = table(data, block_size, last as u64, TableCopy::Backup);
        if let Ok(Table { header, array }) = backup {
            let failure = match primary_error.take() {
                Some(e) => error_message(e),
                None => "no \"EFI PART\" signature at LBA 1".to_string(),
            };
            return Ok(Located {
                block_size,
                header,
                array,
                primary_failure: Some(failure),
            });
        }
    }
    Err(primary_error.unwrap_or_else(|| {
        error(
            "Missing GPT header: no \"EFI PART\" signature at LBA 1 (0x200 or 0x1000) or in the \
             last block of the file",
        )
    }))
}

/// The used entries of the entry array `entry_bytes`, in table order. Each
/// must have its first LBA no later than its last and no earlier than the
/// first usable LBA, and no two may overlap (UEFI 2.10, 5.3.1). An entry
/// that ends after the last usable LBA is kept and noted by the caller.
fn entries(entry_bytes: &[u8], header: &Header) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    for (i, entry) in entry_bytes.chunks_exact(header.entry_size).enumerate() {
        let type_guid: [u8; 16] = array(entry, 0)?;
        if type_guid == [0; 16] {
            continue;
        }
        let number = i + 1;
        let first_lba = le_u64(entry, 32)?;
        let last_lba = le_u64(entry, 40)?;
        if first_lba > last_lba {
            return Err(error(format!(
                "Invalid GPT partition entry {number}: first LBA {first_lba} after last LBA \
                 {last_lba}"
            )));
        }
        if first_lba < header.first_usable {
            return Err(error(format!(
                "Invalid GPT partition entry {number}: LBA {first_lba}-{last_lba} starts before \
                 the first usable LBA {}",
                header.first_usable
            )));
        }
        entries.push(Entry {
            number,
            type_guid: guid_text(&type_guid),
            unique_guid: guid_text(&array(entry, 16)?),
            first_lba,
            last_lba,
            attributes: le_u64(entry, 48)?,
            name: utf16_name(slice(entry, NAME_OFFSET, NAME_SIZE, "GPT partition name")?),
        });
    }
    let mut order: Vec<&Entry> = entries.iter().collect();
    order.sort_by_key(|entry| entry.first_lba);
    for pair in order.windows(2) {
        if pair[0].last_lba >= pair[1].first_lba {
            return Err(error(format!(
                "Invalid GPT partition entries {} and {}: their LBA ranges overlap",
                pair[0].number, pair[1].number
            )));
        }
    }
    Ok(entries)
}

/// Parse a GPT disk image.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let located = locate(data)?;
    let header = &located.header;
    let block_size = located.block_size;
    let entries = entries(located.array, header)?;

    let mut c = Container::new(FileFormat::Gpt, Layout::Gpt.label(), KEY_PREFIX);
    let disk_end = header.my_lba.max(header.alternate_lba);
    c.consumed = disk_end
        .checked_add(1)
        .and_then(|blocks| lba_offset(blocks, block_size))
        .and_then(|size| usize::try_from(size).ok())
        .map_or(data.len(), |size| size.min(data.len()));
    let bootstrap = describe(&mut c, data, &located, &entries);

    let mut placement = Placement::default();
    let mut beyond_usable = Vec::new();
    for entry in &entries {
        let label = label(entry);
        if entry.last_lba > header.last_usable {
            beyond_usable.push(label.clone());
        }
        let content = if entry.type_guid == BIOS_BOOT {
            c.notes.push(format!(
                "{label}: a BIOS boot partition, which holds a boot loader's core image (GRUB); \
                 classified as code, its ISA from the code model"
            ));
            Content::Code
        } else {
            Content::Member
        };
        let blocks = (entry.last_lba - entry.first_lba).saturating_add(1);
        placement.place(
            &mut c,
            data,
            label,
            lba_offset(entry.first_lba, block_size).unwrap_or(u64::MAX),
            lba_offset(blocks, block_size).unwrap_or(u64::MAX),
            content,
        );
    }
    if !beyond_usable.is_empty() {
        c.notes.push(format!(
            "Partitions that end after the last usable LBA {}: {}",
            header.last_usable,
            name_list(&beyond_usable)
        ));
    }
    placement.push_notes(&mut c);
    c.children.extend(bootstrap);
    Ok(c)
}

/// The child label: entry number, name and type name (or type GUID).
fn label(entry: &Entry) -> String {
    let kind = type_name(&entry.type_guid).unwrap_or(&entry.type_guid);
    if entry.name.is_empty() {
        format!("Partition {} ({kind})", entry.number)
    } else {
        format!("Partition {} \"{}\" ({kind})", entry.number, entry.name)
    }
}

/// Summary notes, the protective MBR, the backup header and metadata.
/// Returns the protective MBR's bootstrap code child, for the caller to
/// push after the partitions.
fn describe<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    located: &Located<'_>,
    entries: &[Entry],
) -> Option<Child<'a>> {
    let header = &located.header;
    let block_size = located.block_size;
    c.notes.push(format!(
        "GPT: {} of {} entries of {} B in use, {} B logical blocks; header and entry array \
         CRC-32 verified",
        entries.len(),
        header.entry_count,
        header.entry_size,
        block_size
    ));
    match &located.primary_failure {
        Some(failure) => c.notes.push(format!(
            "The primary GPT header is not valid ({failure}); the partitions are read from the \
             backup header at LBA {}",
            header.my_lba
        )),
        None => c
            .notes
            .push(backup_note(data, header, located.array, block_size)),
    }
    if header.revision != REVISION_1_0 {
        c.notes.push(format!(
            "GPT header revision 0x{:08X}; this layout is revision 1.0 (0x00010000)",
            header.revision
        ));
    }
    let bootstrap = describe_protective_mbr(c, data);

    c.push_metadata(
        "partitions_gpt_disk_guid",
        "Disk GUID",
        guid_text(&header.disk_guid),
    );
    c.push_metadata(
        "partitions_gpt_block_size",
        "Logical block size (B)",
        block_size as u64,
    );
    c.push_metadata(
        "partitions_gpt_entry_count",
        "Partition entries",
        u64::from(header.entry_count),
    );
    c.push_metadata(
        "partitions_gpt_entry_size",
        "Partition entry size (B)",
        header.entry_size as u64,
    );
    c.push_metadata(
        "partitions_gpt_usable_lbas",
        "Usable LBAs",
        format!("{}-{}", header.first_usable, header.last_usable),
    );
    c.push_metadata(
        "partitions_gpt_alternate_lba",
        "Alternate header LBA",
        header.alternate_lba,
    );
    for entry in entries.iter().take(MAX_COMPONENTS) {
        let mut value = format!(
            "type {}; unique {}; LBA {}-{}",
            entry.type_guid, entry.unique_guid, entry.first_lba, entry.last_lba
        );
        let flags: Vec<&str> = ATTRIBUTE_NAMES
            .iter()
            .filter(|&&(bit, _)| entry.attributes & bit != 0)
            .map(|&(_, name)| name)
            .collect();
        if entry.attributes != 0 {
            let _ = write!(value, "; attributes 0x{:016X}", entry.attributes);
            if !flags.is_empty() {
                let _ = write!(value, " ({})", flags.join(", "));
            }
        }
        c.push_metadata(
            format!("partitions_gpt_entry_{}", entry.number),
            format!("Entry {}", entry.number),
            value,
        );
    }
    bootstrap
}

/// What the backup header says: verified, beyond the file, or invalid.
/// The backup is not required, since disk dumps are often cut short.
fn backup_note(data: &[u8], primary: &Header, primary_array: &[u8], block_size: usize) -> String {
    let lba = primary.alternate_lba;
    if lba <= u64::from(GPT_HEADER_LBA) {
        return format!(
            "The primary header names LBA {lba} as the backup header; no backup checked"
        );
    }
    let present = lba_offset(lba, block_size)
        .and_then(|offset| offset.checked_add(block_size as u64))
        .is_some_and(|end| end <= data.len() as u64);
    if !present {
        return format!(
            "Backup GPT header at LBA {lba} lies beyond the end of the file; not verified"
        );
    }
    let Table {
        header: backup,
        array,
    } = match table(data, block_size, lba, TableCopy::Backup) {
        Ok(table) => table,
        Err(e) => {
            return format!(
                "Backup GPT header at LBA {lba} is not valid: {}",
                error_message(e)
            )
        }
    };
    if backup.alternate_lba != primary.my_lba || backup.disk_guid != primary.disk_guid {
        return format!(
            "Backup GPT header at LBA {lba} is valid but does not match the primary (alternate \
             LBA {}, disk GUID {})",
            backup.alternate_lba,
            guid_text(&backup.disk_guid)
        );
    }
    if array != primary_array {
        return format!(
            "Backup GPT header at LBA {lba} verified (CRC-32); its entry array differs from the \
             primary's"
        );
    }
    format!(
        "Backup GPT header at LBA {lba} and its entry array verified (CRC-32); they match the \
         primary"
    )
}

/// The MBR at LBA 0 in front of the GPT: protective, hybrid or missing. A
/// protective MBR's bootstrap code is classified like an MBR's.
fn describe_protective_mbr<'a>(c: &mut Container<'a>, data: &'a [u8]) -> Option<Child<'a>> {
    let sector = data.get(..SECTOR_SIZE)?;
    let Some(records) = boot_records(sector) else {
        c.notes.push(
            "LBA 0 has no MBR boot signature, so no protective MBR (Linux and libblkid read such \
             a GPT only when forced)"
                .to_string(),
        );
        return None;
    };
    if !records.iter().any(|r| r.is_protective()) {
        c.notes.push(
            "LBA 0 holds an MBR without a protective record (type 0xEE from LBA 1)".to_string(),
        );
        return None;
    }
    let others = records
        .iter()
        .filter(|r| r.is_used() && r.os_type != OS_TYPE_GPT_PROTECTIVE)
        .count();
    if others == 0 {
        c.notes
            .push("Protective MBR at LBA 0 (type 0xEE)".to_string());
    } else {
        c.notes.push(format!(
            "Hybrid MBR at LBA 0: a protective record and {}, not listed (the GPT describes the \
             disk)",
            count(
                others,
                "further partition record",
                "further partition records"
            )
        ));
    }
    bootstrap(c, sector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_use_the_mixed_endian_text_form() {
        let bios_boot = *b"Hah!IdontNeedEFI";
        assert_eq!(guid_text(&bios_boot), BIOS_BOOT);
        let hfs = [
            0x00, 0x53, 0x46, 0x48, 0x00, 0x00, 0xaa, 0x11, 0xaa, 0x11, 0x00, 0x30, 0x65, 0x43,
            0xec, 0xac,
        ];
        assert_eq!(guid_text(&hfs), "48465300-0000-11AA-AA11-00306543ECAC");
        assert_eq!(type_name(&guid_text(&hfs)), Some("Apple HFS/HFS+"));
    }

    #[test]
    fn names_stop_at_the_first_nul_and_replace_bad_units() {
        let mut field = [0u8; NAME_SIZE];
        for (i, unit) in "boot\u{1}".encode_utf16().enumerate() {
            field[i * 2..i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(utf16_name(&field), "boot\u{FFFD}");
        field[12..14].copy_from_slice(&0xd800u16.to_le_bytes());
        assert_eq!(utf16_name(&field), "boot\u{FFFD}", "stops at the NUL at 10");
        assert_eq!(utf16_name(&[0; NAME_SIZE]), "");
    }

    #[test]
    fn entry_arrays_must_sit_on_their_side_of_the_usable_range() {
        let header = Header {
            revision: REVISION_1_0,
            my_lba: 1,
            alternate_lba: 2047,
            first_usable: 34,
            last_usable: 2014,
            disk_guid: [0; 16],
            entry_lba: 2,
            entry_count: 128,
            entry_size: 128,
            entry_crc: 0,
        };
        assert!(check_array_position(&header, 512, TableCopy::Primary).is_ok());
        let late = Header {
            entry_lba: 3,
            ..header.clone()
        };
        assert!(
            check_array_position(&late, 512, TableCopy::Primary).is_err(),
            "32 blocks from LBA 3 reach the first usable LBA"
        );
        let backup = Header {
            my_lba: 2047,
            alternate_lba: 1,
            entry_lba: 2015,
            ..header
        };
        assert!(check_array_position(&backup, 512, TableCopy::Backup).is_ok());
        assert!(check_array_position(&backup, 512, TableCopy::Primary).is_err());
    }
}
