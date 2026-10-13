//! Wii disc images: the disc header, the partition table at 0x40000 and
//! each partition's header (sources in the family module).
//!
//! Partition contents are AES-encrypted with the title key in the
//! partition's ticket (Dolphin `VolumeWii`). They are not decrypted: each
//! partition is listed as an opaque child with its type and offsets, and
//! no Wii code reaches the code model. Fields are big-endian; the
//! partition table and partition headers store offsets and sizes divided
//! by 4 (Dolphin `VolumeWii::GetOffsetShift`).

use super::*;

/// Disc magic at 0x18 (`WII_DISC_MAGIC`).
const WII_DISC_MAGIC: u32 = 0x5D1C_9EA3;
const MAGIC_OFFSET: usize = 0x18;

/// Header bytes that are 0 when partitions carry hashes and are encrypted
/// (Dolphin `VolumeWii` constructor, `m_has_hashes` and `m_has_encryption`).
const HASHES_DISABLED_OFFSET: usize = 0x60;
const ENCRYPTION_DISABLED_OFFSET: usize = 0x61;

/// Partition information: four groups of a partition count and a table
/// offset (divided by 4), each table entry a partition offset (divided by
/// 4) and a partition type.
const PARTITION_INFO_OFFSET: usize = 0x40000;
const PARTITION_GROUPS: usize = 4;
const PARTITION_GROUP_SIZE: usize = 8;
const PARTITION_ENTRY_SIZE: usize = 8;

/// Region code (`WII_REGION_DATA_ADDRESS`, `VolumeWii::GetRegion`).
const REGION_OFFSET: usize = 0x4E000;

/// The disc header area before the first partition (the
/// `disc_header_size` of Dolphin's `GetBiggestReferencedOffset`): it holds
/// the partition table and region data, so no partition starts in it.
const DISC_HEADER_AREA_SIZE: u64 = 0x50000;

/// Stored offsets and sizes are shifted right by 2.
const OFFSET_SHIFT: u32 = 2;

/// Partition header: the ticket (`WII_PARTITION_TICKET_SIZE`, 0x2A4 B),
/// TMD size and offset, certificate chain size and offset, H3 table
/// offset, then the data offset (0x2B8) and data size (0x2BC).
const PARTITION_HEADER_SIZE: usize = 0x2C0;
const DATA_OFFSET_FIELD: usize = 0x2B8;
const DATA_SIZE_FIELD: usize = 0x2BC;

/// Partition types (`PARTITION_DATA`, `PARTITION_UPDATE`,
/// `PARTITION_CHANNEL`, `PARTITION_INSTALL`).
const PARTITION_DATA: u32 = 0;
const PARTITION_UPDATE: u32 = 1;
const PARTITION_CHANNEL: u32 = 2;
const PARTITION_INSTALL: u32 = 3;

/// Strong recognition: the magic at 0x18.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let magic = data.get(MAGIC_OFFSET..MAGIC_OFFSET + 4)?;
    (magic == WII_DISC_MAGIC.to_be_bytes()).then_some(Layout::Wii)
}

/// A stored offset or size in bytes.
fn shifted(stored: u32) -> u64 {
    u64::from(stored) << OFFSET_SHIFT
}

/// The name Dolphin's `NameForPartitionType` gives a partition type
/// (without the `P-` prefix): a known name, the four characters when they
/// are all alphanumeric, or the number.
fn partition_type_name(kind: u32) -> String {
    match kind {
        PARTITION_DATA => "DATA".into(),
        PARTITION_UPDATE => "UPDATE".into(),
        PARTITION_CHANNEL => "CHANNEL".into(),
        PARTITION_INSTALL => "INSTALL".into(),
        _ => {
            let id = kind.to_be_bytes();
            if id.iter().all(u8::is_ascii_alphanumeric) {
                id.iter().map(|&b| char::from(b)).collect()
            } else {
                kind.to_string()
            }
        }
    }
}

/// Parse a Wii disc image: header notes and every partition the table
/// lists as an opaque child.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = disc_header(data)?;
    let magic = be_u32(data, MAGIC_OFFSET)?;
    if magic != WII_DISC_MAGIC {
        return Err(error(format!(
            "Invalid Wii disc magic 0x{magic:08X} at 0x{MAGIC_OFFSET:X}"
        )));
    }
    let info = slice(
        data,
        PARTITION_INFO_OFFSET,
        PARTITION_GROUPS * PARTITION_GROUP_SIZE,
    )
    .map_err(|_| {
        error(format!(
            "Truncated partition information at 0x{PARTITION_INFO_OFFSET:X}"
        ))
    })?;
    let region = be_u32(data, REGION_OFFSET)
        .map_err(|_| error(format!("Truncated region data at 0x{REGION_OFFSET:X}")))?;
    let mut c = Container::new(FileFormat::WiiDisc, Layout::Wii.label(), "wii");
    c.consumed = data.len();
    push_disc_header(&mut c, &header);
    push_region(&mut c, region);
    let mut partitions = 0usize;
    let mut unlisted = 0usize;
    for group in 0..PARTITION_GROUPS {
        let count = be_u32(info, group * PARTITION_GROUP_SIZE)?;
        let table_offset = shifted(be_u32(info, group * PARTITION_GROUP_SIZE + 4)?);
        if count == 0 {
            continue;
        }
        let table_size = u64::from(count) * PARTITION_ENTRY_SIZE as u64;
        let table = range(data, table_offset, table_size).ok_or_else(|| {
            error(format!(
                "Truncated partition table {group} at 0x{table_offset:X}: {count} entries"
            ))
        })?;
        for (index, entry) in table.chunks_exact(PARTITION_ENTRY_SIZE).enumerate() {
            partitions += 1;
            if c.children.len() >= MAX_COMPONENTS {
                unlisted += 1;
                continue;
            }
            let offset = shifted(be_u32(entry, 0)?);
            let kind = be_u32(entry, 4)?;
            let label = format!("Partition {group}.{index} ({})", partition_type_name(kind));
            let child = partition(data, label, offset, &mut c.notes)?;
            c.children.push(child);
        }
    }
    push_partition_notes(&mut c, data, partitions, unlisted);
    Ok(c)
}

/// The partition `label` at `offset`: its header must lie after the disc
/// header area and its data, at the header's data offset, in the image.
fn partition<'a>(
    data: &'a [u8],
    label: String,
    offset: u64,
    notes: &mut Vec<String>,
) -> Result<Child<'a>> {
    if offset < DISC_HEADER_AREA_SIZE {
        return Err(error(format!(
            "Invalid {label} offset 0x{offset:X}: inside the 0x{DISC_HEADER_AREA_SIZE:X} B disc header area"
        )));
    }
    let header = range(data, offset, PARTITION_HEADER_SIZE as u64)
        .ok_or_else(|| error(format!("Truncated {label} header at 0x{offset:X}")))?;
    let data_offset = shifted(be_u32(header, DATA_OFFSET_FIELD)?);
    let data_size = shifted(be_u32(header, DATA_SIZE_FIELD)?);
    if data_offset < PARTITION_HEADER_SIZE as u64 {
        return Err(error(format!(
            "Invalid {label} data offset 0x{data_offset:X}: inside the partition header"
        )));
    }
    // Each term is below 2^34, so the sum cannot overflow.
    let size = data_offset + data_size;
    let bytes = range(data, offset, size).ok_or_else(|| {
        error(format!(
            "Truncated {label} at 0x{offset:X}: its data ends at 0x{:X}",
            offset + size
        ))
    })?;
    notes.push(format!(
        "{label} at 0x{offset:X}: data at 0x{:X}, {data_size} B",
        offset + data_offset
    ));
    let offset = usize::try_from(offset).expect("the partition lies in the image");
    Ok(Child::opaque(label, offset, bytes))
}

/// Notes and metadata for the partition table as a whole and the header's
/// hash and encryption flags.
fn push_partition_notes(c: &mut Container<'_>, data: &[u8], partitions: usize, unlisted: usize) {
    let prefix = c.key_prefix;
    c.push_metadata(
        format!("{prefix}_partitions"),
        "Partitions",
        partitions as u64,
    );
    if partitions == 0 {
        c.notes
            .push("The partition table lists no partitions".into());
    }
    if unlisted > 0 {
        c.notes.push(format!(
            "Partition limit reached ({MAX_COMPONENTS}); not listed: {}",
            counted(unlisted, "further partition", "further partitions")
        ));
    }
    // `parse` read the disc header, so both flag bytes are in `data`.
    let encryption_disabled = data[ENCRYPTION_DISABLED_OFFSET];
    if encryption_disabled == 0 {
        c.notes.push(
            "Partition data is AES-encrypted with the title key in each partition's ticket; not decrypted".into(),
        );
    } else {
        c.notes.push(format!(
            "The disc header disables partition encryption (0x{ENCRYPTION_DISABLED_OFFSET:X} = 0x{encryption_disabled:02X}); partition data is not parsed"
        ));
    }
    let hashes_disabled = data[HASHES_DISABLED_OFFSET];
    if hashes_disabled != 0 {
        c.notes.push(format!(
            "The disc header disables hash verification (0x{HASHES_DISABLED_OFFSET:X} = 0x{hashes_disabled:02X})"
        ));
    }
    c.notes
        .push("Tickets, TMDs, certificate chains and H3 hash tables are not verified".into());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_types_are_named_like_dolphin() {
        assert_eq!(partition_type_name(0), "DATA");
        assert_eq!(partition_type_name(1), "UPDATE");
        assert_eq!(partition_type_name(2), "CHANNEL");
        assert_eq!(partition_type_name(3), "INSTALL");
        assert_eq!(partition_type_name(u32::from_be_bytes(*b"RSBJ")), "RSBJ");
        assert_eq!(partition_type_name(0xFF), "255");
    }

    #[test]
    fn stored_offsets_are_shifted_by_two() {
        assert_eq!(shifted(0x0003_E000), 0xF_8000);
        assert_eq!(shifted(u32::MAX), 0x3_FFFF_FFFC);
    }
}
