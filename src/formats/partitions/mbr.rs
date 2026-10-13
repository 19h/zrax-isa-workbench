//! The legacy MBR (UEFI 2.10, 5.2.1) and its extended boot record chains
//! (Linux v6.11 `parse_extended`, util-linux v2.40.2 `parse_dos_extended`).
//!
//! LBA 0 holds 440 B of bootstrap code, a 4-byte disk signature, two
//! unused bytes, four 16-byte partition records and the boot signature
//! `0x55AA` at 510. An extended partition (type `0x05`, `0x0F` or `0x85`)
//! holds a chain of EBRs: sectors with the same records and signature,
//! whose data records are logical partitions relative to that EBR and whose
//! first extended record links to the next EBR, relative to the start of
//! the extended partition. Logical partitions are numbered from 5, as Linux
//! numbers them.

use super::*;

/// Extended partition types (Linux `is_extended_partition`).
const DOS_EXTENDED: u8 = 0x05;
const W95_EXTENDED_LBA: u8 = 0x0f;
const LINUX_EXTENDED: u8 = 0x85;

/// Most EBRs read from one extended partition. Linux stops after 100 links
/// without a data partition and at its partition limit; this fixed bound
/// is our own and also ends a chain that never repeats an EBR.
const MAX_EBRS: usize = 256;

/// Number of the first logical partition (Linux and libblkid).
const FIRST_LOGICAL: usize = 5;

/// A partition's sectors on the disk, `start..end`.
#[derive(Debug, Clone, Copy)]
struct Extent {
    start: u64,
    end: u64,
}

impl Extent {
    fn of(start: u64, size: u32) -> Self {
        Self {
            start,
            end: start + u64::from(size),
        }
    }

    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// A partition listed from the MBR or an EBR, with its absolute first
/// sector.
#[derive(Debug, Clone, Copy)]
struct Partition {
    number: usize,
    record: Record,
    start: u64,
}

impl Record {
    fn is_extended(self) -> bool {
        matches!(
            self.os_type,
            DOS_EXTENDED | W95_EXTENDED_LBA | LINUX_EXTENDED
        )
    }
}

/// File offset of sector `sector`. Sector numbers come from 32-bit fields
/// and their sums, so the product fits.
fn sector_offset(sector: u64) -> u64 {
    sector * SECTOR_SIZE as u64
}

/// Weak recognition (see [`super::detect_weak`]).
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let sector = data.get(..SECTOR_SIZE)?;
    let records = boot_records(sector)?;
    if !records.iter().all(|r| r.has_valid_boot_indicator()) {
        return None;
    }
    if records.iter().any(|r| r.os_type == OS_TYPE_GPT_PROTECTIVE) {
        // libblkid and Linux leave a disk with a type 0xEE record to the GPT
        // prober. A protective MBR whose GPT header `detect` did not find
        // (damaged, or beyond the bytes examined) is a GPT, not an MBR.
        return records
            .iter()
            .any(|r| r.is_protective())
            .then_some(Layout::Gpt);
    }
    if is_volume_boot_record(sector) {
        return None;
    }
    check_primaries(&records, data.len()).ok()?;
    Some(Layout::Mbr)
}

/// Whether LBA 0 holds a legacy MBR with partitions and no type `0xEE`
/// record. A GPT header next to it is stale: legacy software that turns a
/// GPT disk into an MBR disk may leave the GPT in place (UEFI 2.10, 5.3.2),
/// and Linux (`is_pmbr_valid`) and libblkid read a GPT only behind a
/// protective record.
pub(super) fn has_legacy_partitions(data: &[u8]) -> bool {
    let Some(records) = data.get(..SECTOR_SIZE).and_then(boot_records) else {
        return false;
    };
    records.iter().all(|r| r.has_valid_boot_indicator())
        && records.iter().any(|r| r.is_used())
        && records.iter().all(|r| r.os_type != OS_TYPE_GPT_PROTECTIVE)
}

/// The rules for the primary records (UEFI 2.10, 5.2.1, plus the start
/// rules of weak detection): at least one record in use; each used record
/// starts after sector 0 (the MBR itself) and inside the file; no two used
/// records overlap.
fn check_primaries(records: &[Record; RECORD_COUNT], file_size: usize) -> Result<()> {
    let used: Vec<(usize, Record)> = records
        .iter()
        .enumerate()
        .filter(|(_, r)| r.is_used())
        .map(|(i, &r)| (i + 1, r))
        .collect();
    if used.is_empty() {
        return Err(error("Missing partitions: all four MBR records are empty"));
    }
    for &(number, r) in &used {
        if r.start == 0 {
            return Err(error(format!(
                "Invalid MBR partition {number}: starts at sector 0, the MBR itself"
            )));
        }
        let offset = sector_offset(u64::from(r.start));
        if offset >= file_size as u64 {
            return Err(error(format!(
                "Invalid MBR partition {number}: starts at sector {} (0x{offset:X}), beyond the \
                 end of the file",
                r.start
            )));
        }
    }
    for (i, &(first, a)) in used.iter().enumerate() {
        for &(second, b) in &used[i + 1..] {
            if Extent::of(u64::from(a.start), a.size)
                .overlaps(Extent::of(u64::from(b.start), b.size))
            {
                return Err(error(format!(
                    "Invalid MBR: partitions {first} and {second} overlap"
                )));
            }
        }
    }
    Ok(())
}

/// Parse an MBR disk image.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let sector = slice(data, 0, SECTOR_SIZE, "MBR")?;
    let records =
        boot_records(sector).ok_or_else(|| error("Missing MBR boot signature 0x55AA at 0x1FE"))?;
    if let Some((i, r)) = records
        .iter()
        .enumerate()
        .find(|(_, r)| !r.has_valid_boot_indicator())
    {
        return Err(error(format!(
            "Invalid MBR partition {}: boot indicator 0x{:02X} is neither 0x00 nor 0x80",
            i + 1,
            r.boot_indicator
        )));
    }
    if let Some(i) = records
        .iter()
        .position(|r| r.os_type == OS_TYPE_GPT_PROTECTIVE)
    {
        return Err(error(format!(
            "Invalid MBR: partition {} is a GPT protective record (type 0xEE)",
            i + 1
        )));
    }
    if is_volume_boot_record(sector) {
        return Err(error(
            "Invalid MBR: the sector is a FAT, exFAT or NTFS volume boot record",
        ));
    }
    check_primaries(&records, data.len())?;

    let primaries: Vec<Partition> = records
        .iter()
        .enumerate()
        .filter(|(_, r)| r.is_used())
        .map(|(i, &record)| Partition {
            number: i + 1,
            record,
            start: u64::from(record.start),
        })
        .collect();
    let extended: Vec<Partition> = primaries
        .iter()
        .copied()
        .filter(|p| p.record.is_extended())
        .collect();
    let mut partitions: Vec<Partition> = primaries
        .iter()
        .copied()
        .filter(|p| !p.record.is_extended())
        .collect();
    let mut listed: Vec<Extent> = partitions
        .iter()
        .map(|p| Extent::of(p.start, p.record.size))
        .collect();
    let mut next_number = FIRST_LOGICAL;
    let mut chain_notes = Vec::new();
    for container in &extended {
        let logical = walk_chain(
            data,
            container,
            &mut listed,
            &mut next_number,
            &mut chain_notes,
        );
        partitions.extend(logical);
    }

    let mut c = Container::new(FileFormat::Mbr, Layout::Mbr.label(), KEY_PREFIX);
    c.consumed = data.len();
    describe(&mut c, data, sector, &primaries, &partitions)?;
    push_bootstrap(&mut c, sector);
    c.notes.append(&mut chain_notes);
    let mut placement = Placement::default();
    for p in &partitions {
        placement.place(
            &mut c,
            data,
            label(p),
            sector_offset(p.start),
            sector_offset(u64::from(p.record.size)),
            Content::Member,
        );
    }
    placement.push_notes(&mut c);
    Ok(c)
}

/// Summary notes and metadata.
fn describe(
    c: &mut Container<'_>,
    data: &[u8],
    sector: &[u8],
    primaries: &[Partition],
    partitions: &[Partition],
) -> Result<()> {
    let extended = primaries.iter().filter(|p| p.record.is_extended()).count();
    let logical = partitions
        .iter()
        .filter(|p| p.number >= FIRST_LOGICAL)
        .count();
    let mut summary = format!(
        "MBR partition table: {} of 4 primary records in use",
        primaries.len()
    );
    if extended > 0 {
        let _ = write!(
            summary,
            " ({extended} extended), {}",
            count(logical, "logical partition", "logical partitions")
        );
    }
    summary.push_str("; sectors of 512 B assumed (the table does not record a sector size)");
    c.notes.push(summary);
    if gpt::has_header_signature(data) {
        c.notes.push(
            "A GPT header follows, but LBA 0 has no protective record: the GPT is treated as \
             stale and not read"
                .to_string(),
        );
    }
    let signature = le_u32(sector, DISK_SIGNATURE)?;
    if signature != 0 {
        c.push_metadata(
            "partitions_mbr_disk_signature",
            "Disk signature",
            format!("0x{signature:08X}"),
        );
    }
    for p in primaries
        .iter()
        .chain(partitions.iter().filter(|p| p.number >= FIRST_LOGICAL))
    {
        let end = p.start + u64::from(p.record.size) - 1;
        let mut value = format!("type 0x{:02X}; sectors {}-{end}", p.record.os_type, p.start);
        if p.record.boot_indicator == BOOT_ACTIVE {
            value.push_str("; active");
        }
        c.push_metadata(
            format!("partitions_mbr_partition_{}", p.number),
            format!("Partition {}", p.number),
            value,
        );
    }
    Ok(())
}

/// The child label of a partition: its number, type name and type.
fn label(p: &Partition) -> String {
    let os_type = p.record.os_type;
    let mut text = match mbr_type_name(os_type) {
        Some(name) => format!("Partition {} ({name}, type 0x{os_type:02X}", p.number),
        None => format!("Partition {} (type 0x{os_type:02X}", p.number),
    };
    if p.record.boot_indicator == BOOT_ACTIVE {
        text.push_str(", active");
    }
    text.push(')');
    text
}

/// Follow the EBR chain of the extended partition `container`, as Linux
/// `parse_extended` does, and return its logical partitions. Logical
/// partitions that overlap one already listed are skipped, which also keeps
/// the bytes classified within the file size. The walk ends at the last
/// link, at an EBR beyond the file or without a boot signature, at a
/// repeated EBR, or after [`MAX_EBRS`] EBRs; each end other than the last
/// link is noted.
fn walk_chain(
    data: &[u8],
    container: &Partition,
    listed: &mut Vec<Extent>,
    next_number: &mut usize,
    notes: &mut Vec<String>,
) -> Vec<Partition> {
    let base = Extent::of(container.start, container.record.size);
    let mut current = base;
    let mut visited: Vec<u64> = Vec::new();
    let mut logical = Vec::new();
    let prefix = format!(
        "Extended partition {} (type 0x{:02X})",
        container.number, container.record.os_type
    );
    loop {
        if visited.len() == MAX_EBRS {
            notes.push(format!(
                "{prefix}: more than {MAX_EBRS} EBRs; the walk stopped"
            ));
            break;
        }
        if visited.contains(&current.start) {
            notes.push(format!(
                "{prefix}: the EBR chain returns to sector {}; the walk stopped",
                current.start
            ));
            break;
        }
        visited.push(current.start);
        let ebr = usize::try_from(sector_offset(current.start))
            .ok()
            .and_then(|offset| data.get(offset..offset.checked_add(SECTOR_SIZE)?));
        let Some(ebr) = ebr else {
            notes.push(format!(
                "{prefix}: the EBR at sector {} lies beyond the end of the file; the chain is \
                 not followed further",
                current.start
            ));
            break;
        };
        let Some(records) = boot_records(ebr) else {
            notes.push(format!(
                "{prefix}: no boot signature in the EBR at sector {}; the chain ends there",
                current.start
            ));
            break;
        };
        for (i, &record) in records.iter().enumerate() {
            if !record.is_used() || record.is_extended() {
                continue;
            }
            let relative = Extent::of(u64::from(record.start), record.size);
            let absolute = Extent::of(current.start + relative.start, record.size);
            // Linux: the third and fourth records "sometimes contain random
            // garbage", so they count only when they fit the extended
            // partition.
            let fits = relative.end <= current.end - current.start
                && absolute.start >= base.start
                && absolute.end <= base.end;
            if i >= 2 && !fits {
                continue;
            }
            if record.start == 0 {
                notes.push(format!(
                    "{prefix}: a logical record in the EBR at sector {} starts at the EBR itself; \
                     skipped",
                    current.start
                ));
                continue;
            }
            if listed.iter().any(|e| e.overlaps(absolute)) {
                notes.push(format!(
                    "{prefix}: the logical partition at sectors {}-{} overlaps a listed partition; \
                     skipped",
                    absolute.start,
                    absolute.end - 1
                ));
                continue;
            }
            listed.push(absolute);
            logical.push(Partition {
                number: *next_number,
                record,
                start: absolute.start,
            });
            *next_number += 1;
        }
        // The first extended record links to the next EBR; libblkid ignores
        // a link with offset zero, which would point back at the chain's
        // first EBR.
        let Some(link) = records
            .iter()
            .find(|r| r.is_extended() && r.size != 0 && r.start != 0)
        else {
            break;
        };
        current = Extent::of(base.start + u64::from(link.start), link.size);
    }
    notes.push(format!(
        "{prefix} at sector {}: {} in {}",
        container.start,
        count(logical.len(), "logical partition", "logical partitions"),
        count(visited.len(), "EBR", "EBRs")
    ));
    logical
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(os_type: u8, start: u32, size: u32) -> Record {
        Record {
            boot_indicator: BOOT_INACTIVE,
            os_type,
            start,
            size,
        }
    }

    #[test]
    fn primary_records_must_start_inside_the_file_and_not_overlap() {
        let empty = Record::default();
        let one = [record(0x83, 1, 8), empty, empty, empty];
        assert!(check_primaries(&one, 1024).is_ok());
        assert!(
            check_primaries(&one, 512).is_err(),
            "sector 1 starts at the end of a 512 B file"
        );
        let at_zero = [record(0x83, 0, 8), empty, empty, empty];
        assert!(check_primaries(&at_zero, 4096).is_err());
        let overlapping = [record(0x83, 1, 8), record(0x83, 8, 8), empty, empty];
        assert!(check_primaries(&overlapping, 8192).is_err());
        let adjacent = [record(0x83, 1, 8), record(0x83, 9, 8), empty, empty];
        assert!(check_primaries(&adjacent, 8192).is_ok());
        assert!(check_primaries(&[empty; RECORD_COUNT], 8192).is_err());
    }

    #[test]
    fn extended_types_are_the_three_linux_names() {
        for os_type in [DOS_EXTENDED, W95_EXTENDED_LBA, LINUX_EXTENDED] {
            assert!(record(os_type, 1, 1).is_extended());
        }
        assert!(!record(0x83, 1, 1).is_extended());
    }

    #[test]
    fn labels_name_the_type_and_the_active_flag() {
        let mut p = Partition {
            number: 1,
            record: record(0x0c, 2048, 2048),
            start: 2048,
        };
        assert_eq!(label(&p), "Partition 1 (W95 FAT32 (LBA), type 0x0C)");
        p.record.boot_indicator = BOOT_ACTIVE;
        p.record.os_type = 0x42;
        assert_eq!(label(&p), "Partition 1 (SFS, type 0x42, active)");
        p.record.os_type = 0x99;
        assert_eq!(label(&p), "Partition 1 (type 0x99, active)");
    }
}
