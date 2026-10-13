//! The Apple Partition Map (Inside Macintosh: Devices, chapter 3).
//!
//! Block 0 holds the driver descriptor record, all fields big-endian:
//! `sbSig` `ER` (0), `sbBlkSize` (2), `sbBlkCount` (4), three reserved
//! fields (8, 10, 12), `sbDrvrCount` (16) and driver entries from 18, each
//! `ddBlock` (u32, a physical block), `ddSize` (u16, in 512-byte blocks) and
//! `ddType` (u16). The partition map begins at block 1 with one entry per
//! block of `sbBlkSize` bytes, the stride the Start Manager, Linux
//! `mac_partition` and libblkid read it at: `pmSig` `PM` (0), `pmSigPad`
//! (2), `pmMapBlkCnt` (4; the same in every entry), `pmPyPartStart` (8),
//! `pmPartBlkCnt` (12), `pmPartName` (16, 32 B), `pmParType` (48, 32 B),
//! `pmLgDataStart` (80), `pmDataCnt` (84), `pmPartStatus` (88),
//! `pmLgBootStart` (92), `pmBootSize` (96, bytes), `pmBootAddr` (100),
//! `pmBootEntry` (108), `pmBootCksum` (116) and `pmProcessor` (120, 16 B).
//! The map describes itself in an `Apple_partition_map` entry.

use super::*;

/// `sbSIGWord` (`$4552`).
const DDR_SIGNATURE: &[u8; 2] = b"ER";

/// `pMapSIG` (`$504D`).
const MAP_SIGNATURE: &[u8; 2] = b"PM";

/// "An earlier but still supported version uses the value $5453" (Inside
/// Macintosh); the book does not describe that map's layout.
const OLD_MAP_SIGNATURE: &[u8; 2] = b"TS";

/// A partition map entry record is 512 bytes, so a block holds at least
/// one.
const ENTRY_SIZE: usize = 512;

/// Driver entries of the driver descriptor record: 8 bytes each from
/// offset 18. Block 0 has room for 61 (the first entry plus `ddPad`, 243
/// 16-bit words, our arithmetic).
const DRIVER_ENTRIES: usize = 18;
const DRIVER_ENTRY_SIZE: usize = 8;
const MAX_DRIVERS: usize = 61;

/// `ddSize` counts 512-byte blocks.
const DRIVER_BLOCK: u64 = 512;

/// Partition types with a role in the map itself (Inside Macintosh's
/// standard types): the map and unused space.
const TYPE_PARTITION_MAP: &str = "Apple_partition_map";
const TYPE_FREE: &str = "Apple_Free";

/// `pmProcessor` values Inside Macintosh defines, all 680x0 processors.
const M68K_PROCESSORS: [&str; 4] = ["68000", "68020", "68030", "68040"];

/// The architecture those processors run.
const M68K_TARGET: Target = Target::new(Isa::M68k, 32, Endianness::Big);

/// A partition map entry's fields.
#[derive(Debug, Clone)]
struct Entry {
    /// 1-based block number of the entry, also its number in the map.
    number: usize,
    map_count: u32,
    /// `pmPyPartStart`, in blocks.
    start: u32,
    /// `pmPartBlkCnt`, in blocks.
    blocks: u32,
    name: String,
    kind: String,
    /// `pmLgDataStart`, in blocks from the partition start.
    data_start: u32,
    status: u32,
    /// `pmLgBootStart`, in blocks from the partition start.
    boot_start: u32,
    /// `pmBootSize`, in bytes.
    boot_size: u32,
    boot_address: u32,
    boot_entry_point: u32,
    boot_checksum: u32,
    processor: String,
}

/// A driver named by the driver descriptor record.
#[derive(Debug, Clone, Copy)]
struct Driver {
    /// `ddBlock`, a physical block.
    block: u32,
    /// `ddSize`, in 512-byte blocks.
    size: u16,
    /// `ddType`.
    kind: u16,
}

/// The text of a fixed-size, NUL-terminated field: printable ASCII as-is,
/// other bytes as `\xNN` (names may use Mac OS Roman).
fn c_string(field: &[u8]) -> String {
    let len = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let mut text = String::new();
    for &b in &field[..len] {
        if (0x20..0x7f).contains(&b) {
            text.push(char::from(b));
        } else {
            let _ = write!(text, "\\x{b:02X}");
        }
    }
    text
}

/// `sbBlkSize`: a power of two that holds a map entry. Linux requires a
/// power of two; libblkid a block that holds the fields it reads.
fn block_size(data: &[u8]) -> Result<usize> {
    let size = be_u16(data, 2)?;
    if size.is_power_of_two() && usize::from(size) >= ENTRY_SIZE {
        Ok(usize::from(size))
    } else {
        Err(error(format!(
            "Invalid driver descriptor block size {size} B: not a power of two of at least \
             {ENTRY_SIZE} B"
        )))
    }
}

/// Strong recognition (see [`super::detect`]): `ER`, a valid block size and
/// a `PM` (or old `TS`) entry at block 1; every `PM` entry present among
/// the first `pmMapBlkCnt` blocks must agree on that count.
pub(super) fn is_present(data: &[u8]) -> bool {
    if data.get(..DDR_SIGNATURE.len()) != Some(DDR_SIGNATURE.as_slice()) {
        return false;
    }
    let Ok(block_size) = block_size(data) else {
        return false;
    };
    let Some(first) = data.get(block_size..block_size + ENTRY_SIZE) else {
        return false;
    };
    if first.starts_with(OLD_MAP_SIGNATURE) {
        return true;
    }
    if !first.starts_with(MAP_SIGNATURE) {
        return false;
    }
    let Ok(map_count) = be_u32(first, 4) else {
        return false;
    };
    let present = data.len() / block_size - 1;
    let checked = present.min(usize::try_from(map_count).unwrap_or(usize::MAX));
    map_count >= 1
        && (2..=checked).all(|number| {
            let at = number * block_size;
            data.get(at..at + ENTRY_SIZE).is_some_and(|entry| {
                entry.starts_with(MAP_SIGNATURE) && be_u32(entry, 4).ok() == Some(map_count)
            })
        })
}

/// The map entry in block `number`.
fn entry(data: &[u8], block_size: usize, number: usize) -> Result<Entry> {
    let offset = number
        .checked_mul(block_size)
        .ok_or_else(|| error(format!("Invalid partition map entry {number}")))?;
    let record = slice(data, offset, ENTRY_SIZE, "partition map entry")?;
    if record.starts_with(OLD_MAP_SIGNATURE) {
        return Err(error(format!(
            "Unsupported old-format partition map (signature TS) at block {number}"
        )));
    }
    if !record.starts_with(MAP_SIGNATURE) {
        return Err(error(format!(
            "Missing partition map entry signature PM at block {number} (0x{offset:X})"
        )));
    }
    Ok(Entry {
        number,
        map_count: be_u32(record, 4)?,
        start: be_u32(record, 8)?,
        blocks: be_u32(record, 12)?,
        name: c_string(slice(record, 16, 32, "pmPartName")?),
        kind: c_string(slice(record, 48, 32, "pmParType")?),
        data_start: be_u32(record, 80)?,
        status: be_u32(record, 88)?,
        boot_start: be_u32(record, 92)?,
        boot_size: be_u32(record, 96)?,
        boot_address: be_u32(record, 100)?,
        boot_entry_point: be_u32(record, 108)?,
        boot_checksum: be_u32(record, 116)?,
        processor: c_string(slice(record, 120, 16, "pmProcessor")?),
    })
}

/// The driver entries of the driver descriptor record.
fn drivers(data: &[u8]) -> Result<Vec<Driver>> {
    let count = usize::from(be_u16(data, 16)?);
    if count > MAX_DRIVERS {
        return Err(error(format!(
            "Invalid driver descriptor: {count} drivers, at most {MAX_DRIVERS} fit in block 0"
        )));
    }
    (0..count)
        .map(|i| {
            let at = DRIVER_ENTRIES + i * DRIVER_ENTRY_SIZE;
            Ok(Driver {
                block: be_u32(data, at)?,
                size: be_u16(data, at + 4)?,
                kind: be_u16(data, at + 6)?,
            })
        })
        .collect()
}

/// All map entries: as many as entry 1's `pmMapBlkCnt`, each with the `PM`
/// signature and the same count (Inside Macintosh: "all entries in the
/// partition map must contain the same values for these fields").
fn map_entries(data: &[u8], block_size: usize) -> Result<Vec<Entry>> {
    let first = entry(data, block_size, 1)?;
    let count = first.map_count;
    if count == 0 {
        return Err(error("Invalid partition map: pmMapBlkCnt is 0"));
    }
    // Entry 1 was read, so the file holds more than one block; only whole
    // blocks count as present.
    let present = data.len() / block_size - 1;
    let Some(last) = usize::try_from(count)
        .ok()
        .filter(|&count| count <= present)
    else {
        return Err(error(format!(
            "Truncated partition map: {count} entries of {block_size} B from 0x{block_size:X}, \
             {present} present"
        )));
    };
    let mut entries = vec![first];
    for number in 2..=last {
        let entry = entry(data, block_size, number)?;
        if entry.map_count != count {
            return Err(error(format!(
                "Invalid partition map entry {number}: pmMapBlkCnt {} differs from entry 1's \
                 {count}",
                entry.map_count
            )));
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Block 0 belongs to no partition (Inside Macintosh: "With the exception
/// of the driver descriptor record in block 0, every block on a disk must
/// belong to a partition"), and no two partitions overlap.
fn check_extents(entries: &[Entry]) -> Result<()> {
    if let Some(entry) = entries.iter().find(|e| e.blocks != 0 && e.start == 0) {
        return Err(error(format!(
            "Invalid partition map entry {}: the partition starts at block 0, the driver \
             descriptor record",
            entry.number
        )));
    }
    let mut order: Vec<&Entry> = entries.iter().filter(|e| e.blocks != 0).collect();
    order.sort_by_key(|e| e.start);
    for pair in order.windows(2) {
        if u64::from(pair[0].start) + u64::from(pair[0].blocks) > u64::from(pair[1].start) {
            return Err(error(format!(
                "Invalid partition map: the partitions of entries {} and {} overlap",
                pair[0].number, pair[1].number
            )));
        }
    }
    Ok(())
}

/// Parse an Apple Partition Map disk image.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let signature = slice(data, 0, DDR_SIGNATURE.len(), "driver descriptor record")?;
    if signature != DDR_SIGNATURE {
        return Err(error("Missing driver descriptor signature ER at 0x0"));
    }
    let block_size = block_size(data)?;
    let block_count = be_u32(data, 4)?;
    let drivers = drivers(data)?;
    let entries = map_entries(data, block_size)?;
    check_extents(&entries)?;

    let mut c = Container::new(
        FileFormat::ApplePartitionMap,
        Layout::ApplePartitionMap.label(),
        KEY_PREFIX,
    );
    let device_size = u64::from(block_count) * block_size as u64;
    c.consumed = if block_count == 0 {
        data.len()
    } else {
        usize::try_from(device_size).map_or(data.len(), |size| size.min(data.len()))
    };
    c.notes.push(format!(
        "Apple Partition Map: {} in {block_size} B blocks; the driver descriptor gives \
         {block_count} blocks ({})",
        count(entries.len(), "entry", "entries"),
        size_text(device_size)
    ));
    describe_drivers(&mut c, &drivers);
    c.push_metadata(
        "partitions_apm_block_size",
        "Block size (B)",
        block_size as u64,
    );
    c.push_metadata(
        "partitions_apm_block_count",
        "Device blocks",
        u64::from(block_count),
    );

    let mut placement = Placement::default();
    for entry in &entries {
        let label = label(entry);
        c.push_metadata(
            format!("partitions_apm_entry_{}", entry.number),
            format!("Entry {}", entry.number),
            entry_summary(entry),
        );
        match entry.kind.as_str() {
            TYPE_PARTITION_MAP => continue,
            TYPE_FREE => {
                c.notes.push(format!("{label}: free space; not classified"));
                continue;
            }
            _ => {}
        }
        if entry.data_start != 0 {
            c.notes.push(format!(
                "{label}: the file system data starts at logical block {}; the whole partition \
                 is classified",
                entry.data_start
            ));
        }
        let offset = u64::from(entry.start) * block_size as u64;
        if entry.blocks != 0 {
            placement.place(
                &mut c,
                data,
                label.clone(),
                offset,
                u64::from(entry.blocks) * block_size as u64,
                Content::Member,
            );
        }
        let boot_code = BootCode {
            entry,
            label: &label,
            partition_offset: offset,
            block_size,
        };
        push_boot_code(&mut c, data, &boot_code, &mut placement);
    }
    placement.push_notes(&mut c);
    Ok(c)
}

/// The child label: entry number, name and type.
fn label(entry: &Entry) -> String {
    if entry.name.is_empty() {
        format!("Partition {} ({})", entry.number, entry.kind)
    } else {
        format!(
            "Partition {} \"{}\" ({})",
            entry.number, entry.name, entry.kind
        )
    }
}

/// The metadata value of an entry, in blocks.
fn entry_summary(entry: &Entry) -> String {
    let mut value = format!(
        "\"{}\"; {}; blocks {}+{}; status 0x{:08X}",
        entry.name, entry.kind, entry.start, entry.blocks, entry.status
    );
    if entry.boot_size != 0 {
        let _ = write!(
            value,
            "; boot code {} B at logical block {}",
            entry.boot_size, entry.boot_start
        );
    }
    if !entry.processor.is_empty() {
        let _ = write!(value, "; processor {}", entry.processor);
    }
    value
}

/// A note listing the drivers of the driver descriptor record.
fn describe_drivers(c: &mut Container<'_>, drivers: &[Driver]) {
    if drivers.is_empty() {
        return;
    }
    let list: Vec<String> = drivers
        .iter()
        .map(|d| {
            format!(
                "block {} ({}, type {})",
                d.block,
                size_text(u64::from(d.size) * DRIVER_BLOCK),
                d.kind
            )
        })
        .collect();
    c.notes.push(format!(
        "Driver descriptor lists {}: {}",
        count(drivers.len(), "driver", "drivers"),
        list.join(", ")
    ));
}

/// An entry whose boot code is listed, and where its partition lies.
struct BootCode<'e> {
    entry: &'e Entry,
    label: &'e str,
    /// File offset of the partition.
    partition_offset: u64,
    block_size: usize,
}

/// List an entry's boot code as code. Its `pmProcessor` names the processor
/// that runs it; Inside Macintosh defines 68000, 68020, 68030 and 68040.
/// Other processor strings leave the ISA to the code model. Logical blocks
/// are taken as `sbBlkSize` blocks from the partition start.
fn push_boot_code<'a>(
    c: &mut Container<'a>,
    data: &'a [u8],
    boot_code: &BootCode<'_>,
    placement: &mut Placement,
) {
    let BootCode {
        entry,
        label,
        partition_offset,
        block_size,
    } = *boot_code;
    if entry.boot_size == 0 {
        return;
    }
    let relative = u64::from(entry.boot_start) * block_size as u64;
    let size = u64::from(entry.boot_size);
    let partition_size = u64::from(entry.blocks) * block_size as u64;
    if relative + size > partition_size {
        c.notes.push(format!(
            "{label}: the boot code ({size} B at logical block {}) lies outside the partition; \
             not classified",
            entry.boot_start
        ));
        return;
    }
    let offset = partition_offset + relative;
    let located = usize::try_from(offset)
        .ok()
        .zip(usize::try_from(size).ok())
        .and_then(|(start, size)| Some((start, data.get(start..)?.get(..size)?)));
    let Some((start, code)) = located else {
        c.notes.push(format!(
            "{label}: the boot code at 0x{offset:X} lies beyond the end of the file; not \
             classified"
        ));
        return;
    };
    if c.children.len() >= MAX_COMPONENTS {
        placement.unlisted += 1;
        return;
    }
    let processor = M68K_PROCESSORS
        .iter()
        .copied()
        .find(|&name| name == entry.processor);
    let named = if entry.processor.is_empty() {
        "no processor named".to_string()
    } else {
        format!("pmProcessor {}", entry.processor)
    };
    c.notes.push(format!(
        "{label}: boot code {size} B at 0x{offset:X} ({named}), load address 0x{:08X}, entry \
         point 0x{:08X}; checksum 0x{:08X} not verified",
        entry.boot_address, entry.boot_entry_point, entry.boot_checksum
    ));
    let child = Child::stored(format!("{label} boot code"), start, code).as_code();
    c.children.push(match processor {
        Some(name) => child.with_target(M68K_TARGET).with_variant(name),
        None => child,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_stop_at_nul_and_escape_other_bytes() {
        assert_eq!(c_string(b"Apple_HFS\0junk"), "Apple_HFS");
        assert_eq!(c_string(b"Mac\xa5HD"), "Mac\\xA5HD");
        assert_eq!(c_string(&[0; 4]), "");
    }

    #[test]
    fn block_sizes_must_be_powers_of_two_that_hold_an_entry() {
        let mut ddr = b"ER\x02\x00".to_vec();
        assert_eq!(block_size(&ddr).ok(), Some(512));
        ddr[2..4].copy_from_slice(&2048u16.to_be_bytes());
        assert_eq!(block_size(&ddr).ok(), Some(2048));
        ddr[2..4].copy_from_slice(&256u16.to_be_bytes());
        assert!(block_size(&ddr).is_err());
        ddr[2..4].copy_from_slice(&1536u16.to_be_bytes());
        assert!(block_size(&ddr).is_err());
    }
}
