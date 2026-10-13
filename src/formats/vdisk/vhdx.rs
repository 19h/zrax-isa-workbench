//! Microsoft VHDX images ([MS-VHDX] protocol revision 8.0, 2024-04-23:
//! 2.2 header section, 2.4 blocks, 2.5 BAT, 2.6 metadata region; QEMU
//! `v11.1.1` `block/vhdx.c` for the BAT entry count and the choice between
//! two identical headers).
//!
//! Every integer is little-endian and every checksum is CRC-32C. The file
//! starts with a 1 MiB header section: the `vhdxfile` identifier, two
//! headers with sequence numbers, and two copies of the region table that
//! locates the BAT and the metadata region. The metadata region gives the
//! block size, virtual disk size and sector sizes; the BAT holds one entry
//! per payload block, with one sector bitmap entry after each chunk of
//! payload blocks. The log is not replayed: a non-empty log is noted.

use super::*;
use crate::formats::checksum;

/// File type identifier signature at offset 0.
const SIGNATURE: &[u8; 8] = b"vhdxfile";

/// The creator string after the signature: 512 bytes of UTF-16.
const CREATOR_OFFSET: usize = 8;
const CREATOR_SIZE: usize = 512;

/// The two headers: 4 KiB structures at 64 KiB and 128 KiB.
const HEADER_OFFSETS: [usize; 2] = [64 << 10, 128 << 10];
const HEADER_SIZE: usize = 4 << 10;
const HEADER_SIGNATURE: &[u8; 4] = b"head";

/// The two region tables: 64 KiB at 192 KiB and 256 KiB.
const REGION_TABLE_OFFSETS: [usize; 2] = [192 << 10, 256 << 10];
const REGION_TABLE_SIZE: usize = 64 << 10;
const REGION_SIGNATURE: &[u8; 4] = b"regi";
const REGION_ENTRY_OFFSET: usize = 16;
const REGION_ENTRY_SIZE: usize = 32;
const MAX_REGION_ENTRIES: u32 = 2047;

/// A region entry's `Required` value 1 (QEMU tests bit 0,
/// `VHDX_REGION_ENTRY_REQUIRED`).
const REGION_REQUIRED: u32 = 1;

/// Every checksum field is the second 32-bit word.
const CHECKSUM_OFFSET: usize = 4;

/// The format version a header must name.
const VERSION: u16 = 1;

/// Regions, objects and blocks are aligned to 1 MiB.
const MIB: u64 = 1 << 20;

/// Known region GUIDs in binary form.
const BAT_REGION: [u8; 16] = [
    0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a, 0x08,
];
const METADATA_REGION: [u8; 16] = [
    0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e,
];

/// The metadata table: a 32-byte header and 32-byte entries in the first
/// 64 KiB of the region.
const METADATA_SIGNATURE: &[u8; 8] = b"metadata";
const METADATA_TABLE_SIZE: u64 = 64 << 10;
const METADATA_ENTRY_SIZE: usize = 32;
const MAX_METADATA_ENTRIES: u16 = 2047;
const MAX_METADATA_ITEM: u32 = 1 << 20;

/// Metadata entry flags.
const META_IS_REQUIRED: u32 = 1 << 2;

/// Known metadata item GUIDs in binary form.
const FILE_PARAMETERS: [u8; 16] = [
    0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7, 0x6b,
];
const VIRTUAL_DISK_SIZE: [u8; 16] = [
    0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4, 0xb8,
];
const VIRTUAL_DISK_ID: [u8; 16] = [
    0xab, 0x12, 0xca, 0xbe, 0xe6, 0xb2, 0x23, 0x45, 0x93, 0xef, 0xc3, 0x09, 0xe0, 0x00, 0xc7, 0x46,
];
const LOGICAL_SECTOR_SIZE: [u8; 16] = [
    0x1d, 0xbf, 0x41, 0x81, 0x6f, 0xa9, 0x09, 0x47, 0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab, 0x5f,
];
const PHYSICAL_SECTOR_SIZE: [u8; 16] = [
    0xc7, 0x48, 0xa3, 0xcd, 0x5d, 0x44, 0x71, 0x44, 0x9c, 0xc9, 0xe9, 0x88, 0x52, 0x51, 0xc5, 0x56,
];
const PARENT_LOCATOR: [u8; 16] = [
    0x2d, 0x5f, 0xd3, 0xa8, 0x0b, 0xb3, 0x4d, 0x45, 0xab, 0xf7, 0xd3, 0xd8, 0x48, 0x34, 0xab, 0x0c,
];

/// File parameter flags.
const LEAVE_BLOCKS_ALLOCATED: u32 = 1 << 0;
const HAS_PARENT: u32 = 1 << 1;

/// Payload block sizes: a power of two from 1 MiB to 256 MiB.
const MIN_BLOCK_SIZE: u32 = 1 << 20;
const MAX_BLOCK_SIZE: u32 = 256 << 20;

/// Sector sizes and the largest virtual disk.
const SECTOR_512: u32 = 512;
const SECTOR_4096: u32 = 4096;
const MAX_VIRTUAL_SIZE: u64 = 64 << 40;

/// A sector bitmap block covers 2^23 sectors (a chunk).
const SECTORS_PER_CHUNK: u64 = 1 << 23;

/// BAT entries: 64 bits, the state in bits 0-2 and the 1 MiB file offset
/// in bits 20-63.
const BAT_ENTRY_SIZE: u64 = 8;
const BAT_STATE_MASK: u64 = 0x7;
const BAT_OFFSET_SHIFT: u32 = 20;

/// Payload BAT entry states (2.5.1.1). State 5 is the unmapped state of
/// the v0.95 draft, which QEMU still reads as unmapped.
const PAYLOAD_BLOCK_NOT_PRESENT: u64 = 0;
const PAYLOAD_BLOCK_UNDEFINED: u64 = 1;
const PAYLOAD_BLOCK_ZERO: u64 = 2;
const PAYLOAD_BLOCK_UNMAPPED: u64 = 3;
const PAYLOAD_BLOCK_UNMAPPED_V095: u64 = 5;
const PAYLOAD_BLOCK_FULLY_PRESENT: u64 = 6;
const PAYLOAD_BLOCK_PARTIALLY_PRESENT: u64 = 7;

/// Sector bitmap BAT entry state with a bitmap block in the file.
const SB_BLOCK_PRESENT: u64 = 6;

/// Parent locator: type GUID (16), reserved (2), key-value count (2), then
/// 12-byte entries.
const LOCATOR_HEADER_SIZE: usize = 20;
const LOCATOR_ENTRY_SIZE: usize = 12;

/// Locator keys shown for the parent, in the order the specification
/// says to evaluate the paths.
const PARENT_KEYS: [&str; 4] = [
    "parent_linkage",
    "relative_path",
    "volume_path",
    "absolute_win32_path",
];

const TRANSFORM: &str = "VHDX blocks";

/// Is this a VHDX file: the file type identifier at offset 0?
pub(super) fn is_present(data: &[u8]) -> bool {
    data.starts_with(SIGNATURE)
}

/// CRC-32C of a structure with its checksum field counted as zero.
fn crc32c(bytes: &[u8]) -> u32 {
    let head = checksum::crc32c_update(!0, &bytes[..CHECKSUM_OFFSET]);
    let field = checksum::crc32c_update(head, &[0; 4]);
    !checksum::crc32c_update(field, &bytes[CHECKSUM_OFFSET + 4..])
}

/// Whether a structure's stored CRC-32C matches.
fn is_sealed(bytes: &[u8]) -> bool {
    le_u32(bytes, CHECKSUM_OFFSET).is_ok_and(|stored| stored == crc32c(bytes))
}

/// The header fields this parser uses.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Header {
    /// File offset of the header.
    offset: usize,
    sequence: u64,
    log_guid: [u8; 16],
    log_length: u32,
    log_offset: u64,
}

/// A header (2.2.2): signature, CRC-32C over 4 KiB, sequence number (8),
/// file write, data write and log GUIDs (16 each), log version (2),
/// version (2), log length (4) and log offset (8). `None` unless the
/// signature, checksum and version 1 are all valid.
fn header(data: &[u8], offset: usize) -> Option<Header> {
    let bytes = data.get(offset..offset + HEADER_SIZE)?;
    if &bytes[..4] != HEADER_SIGNATURE || !is_sealed(bytes) || le_u16(bytes, 66).ok()? != VERSION {
        return None;
    }
    Some(Header {
        offset,
        sequence: le_u64(bytes, 8).ok()?,
        log_guid: array(bytes, 48).ok()?,
        log_length: le_u32(bytes, 68).ok()?,
        log_offset: le_u64(bytes, 72).ok()?,
    })
}

/// The current header: the only valid one, or the valid one with the
/// greater sequence number. Two valid headers with the same sequence
/// number are accepted when their bytes are identical, as QEMU accepts
/// those written by `Disk2VHD`.
fn current_header(data: &[u8]) -> Result<Header> {
    slice(
        data,
        0,
        REGION_TABLE_OFFSETS[1] + REGION_TABLE_SIZE,
        "VHDX header section",
    )?;
    let [first, second] = HEADER_OFFSETS.map(|offset| header(data, offset));
    match (first, second) {
        (Some(a), Some(b)) if a.sequence == b.sequence => {
            let same =
                data[a.offset..a.offset + HEADER_SIZE] == data[b.offset..b.offset + HEADER_SIZE];
            if same {
                Ok(a)
            } else {
                Err(error(format!(
                    "Invalid VHDX headers: both have sequence number {} but differ",
                    a.sequence
                )))
            }
        }
        (Some(a), Some(b)) => Ok(if a.sequence > b.sequence { a } else { b }),
        (Some(only), None) | (None, Some(only)) => Ok(only),
        (None, None) => Err(error(
            "Invalid VHDX headers: neither header at 0x10000 or 0x20000 is valid",
        )),
    }
}

/// A region table entry (2.2.3.2).
#[derive(Debug, Clone, Copy)]
struct Region {
    offset: u64,
    length: u32,
}

/// The BAT and metadata regions.
struct Regions {
    bat: Region,
    metadata: Region,
    /// File offset of the region table used.
    table_offset: usize,
}

/// The first region table copy with a valid signature and checksum:
/// signature, CRC-32C over 64 KiB, entry count (at most 2047), reserved,
/// then 32-byte entries of GUID (16), file offset (8), length (4) and
/// required flag (4). The BAT and metadata regions must each appear once;
/// an unknown region marked required cannot be read.
fn regions(data: &[u8]) -> Result<Regions> {
    let table_offset = REGION_TABLE_OFFSETS
        .into_iter()
        .find(|&offset| {
            data.get(offset..offset + REGION_TABLE_SIZE)
                .is_some_and(|table| table.starts_with(REGION_SIGNATURE) && is_sealed(table))
        })
        .ok_or_else(|| {
            error("Invalid VHDX region tables: neither copy at 0x30000 or 0x40000 is valid")
        })?;
    let table = slice(data, table_offset, REGION_TABLE_SIZE, "VHDX region table")?;
    let count = le_u32(table, 8)?;
    if count > MAX_REGION_ENTRIES {
        return Err(error(format!("Invalid VHDX region table: {count} entries")));
    }
    let mut bat = None;
    let mut metadata = None;
    for i in 0..count as usize {
        let entry = slice(
            table,
            REGION_ENTRY_OFFSET + i * REGION_ENTRY_SIZE,
            REGION_ENTRY_SIZE,
            "VHDX region entry",
        )?;
        let guid: [u8; 16] = array(entry, 0)?;
        let region = Region {
            offset: le_u64(entry, 16)?,
            length: le_u32(entry, 24)?,
        };
        let required = le_u32(entry, 28)? & REGION_REQUIRED != 0;
        let slot = match guid {
            BAT_REGION => &mut bat,
            METADATA_REGION => &mut metadata,
            _ if required => {
                return Err(error(format!(
                    "Unsupported VHDX region {} marked required",
                    guid_text(guid)
                )));
            }
            _ => continue,
        };
        if slot.is_some() {
            return Err(error(format!("Duplicate VHDX region {}", guid_text(guid))));
        }
        if region.offset < MIB || region.offset % MIB != 0 || u64::from(region.length) % MIB != 0 {
            return Err(error(format!(
                "Invalid VHDX region {} at 0x{:X} + {} B: not 1 MiB-aligned",
                guid_text(guid),
                region.offset,
                region.length
            )));
        }
        range(data, region.offset, u64::from(region.length), "VHDX region")?;
        *slot = Some(region);
    }
    match (bat, metadata) {
        (Some(bat), Some(metadata)) => Ok(Regions {
            bat,
            metadata,
            table_offset,
        }),
        (None, _) => Err(error("Missing VHDX BAT region")),
        (_, None) => Err(error("Missing VHDX metadata region")),
    }
}

/// What the metadata items say.
#[derive(Debug, Default)]
struct Metadata {
    block_size: u32,
    flags: u32,
    virtual_size: u64,
    logical_sector_size: u32,
    physical_sector_size: Option<u32>,
    disk_id: Option<String>,
    parent: Option<Vec<LocatorEntry>>,
}

/// One key-value pair of a parent locator.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LocatorEntry {
    key: String,
    value: String,
}

impl Metadata {
    fn has_parent(&self) -> bool {
        self.flags & HAS_PARENT != 0
    }
}

/// The items of the metadata table (2.6.1): signature, reserved (2), entry
/// count (2, at most 2047), reserved (20), then 32-byte entries of item ID
/// (16), offset (4, from the region start, at least 64 KiB), length (4, at
/// most 1 MiB), flags (4) and reserved (4). File parameters, virtual disk
/// size and logical sector size are required; an unknown item marked
/// required cannot be read.
fn metadata(data: &[u8], region: Region) -> Result<Metadata> {
    let base = region.offset;
    let region_bytes = range(data, base, u64::from(region.length), "VHDX metadata region")?;
    let table = range(region_bytes, 0, METADATA_TABLE_SIZE, "VHDX metadata table")?;
    if &table[..8] != METADATA_SIGNATURE {
        return Err(error(format!(
            "Missing VHDX metadata table signature at 0x{base:X}"
        )));
    }
    let count = le_u16(table, 10)?;
    if count > MAX_METADATA_ENTRIES {
        return Err(error(format!(
            "Invalid VHDX metadata table: {count} entries"
        )));
    }
    let mut found = Metadata::default();
    let mut seen: Vec<[u8; 16]> = Vec::new();
    for i in 0..usize::from(count) {
        let entry = slice(
            table,
            METADATA_ENTRY_SIZE * (i + 1),
            METADATA_ENTRY_SIZE,
            "VHDX metadata entry",
        )?;
        let id: [u8; 16] = array(entry, 0)?;
        let offset = le_u32(entry, 16)?;
        let length = le_u32(entry, 20)?;
        let flags = le_u32(entry, 24)?;
        if seen.contains(&id) {
            return Err(error(format!(
                "Duplicate VHDX metadata item {}",
                guid_text(id)
            )));
        }
        seen.push(id);
        if length > MAX_METADATA_ITEM || (length > 0 && u64::from(offset) < METADATA_TABLE_SIZE) {
            return Err(error(format!(
                "Invalid VHDX metadata item {} at offset 0x{offset:X} + {length} B",
                guid_text(id)
            )));
        }
        let item = range(
            region_bytes,
            u64::from(offset),
            u64::from(length),
            "VHDX metadata item",
        )?;
        match id {
            FILE_PARAMETERS => {
                found.block_size = le_u32(item, 0)?;
                found.flags = le_u32(item, 4)?;
            }
            VIRTUAL_DISK_SIZE => found.virtual_size = le_u64(item, 0)?,
            VIRTUAL_DISK_ID => found.disk_id = Some(guid_text(array(item, 0)?)),
            LOGICAL_SECTOR_SIZE => found.logical_sector_size = le_u32(item, 0)?,
            PHYSICAL_SECTOR_SIZE => found.physical_sector_size = Some(le_u32(item, 0)?),
            PARENT_LOCATOR => found.parent = Some(parent_locator(item)?),
            _ if flags & META_IS_REQUIRED != 0 => {
                return Err(error(format!(
                    "Unsupported VHDX metadata item {} marked required",
                    guid_text(id)
                )));
            }
            _ => {}
        }
    }
    for (id, name) in [
        (FILE_PARAMETERS, "file parameters"),
        (VIRTUAL_DISK_SIZE, "virtual disk size"),
        (LOGICAL_SECTOR_SIZE, "logical sector size"),
    ] {
        if !seen.contains(&id) {
            return Err(error(format!("Missing VHDX {name} metadata item")));
        }
    }
    check_metadata(&found)?;
    Ok(found)
}

/// The value ranges of 2.6.2: block size a power of two from 1 MiB to
/// 256 MiB, logical sector size 512 or 4096, virtual size a multiple of
/// it of at most 64 TiB, and a parent locator exactly when the file has a
/// parent.
fn check_metadata(found: &Metadata) -> Result<()> {
    if !found.block_size.is_power_of_two()
        || !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&found.block_size)
    {
        return Err(error(format!(
            "Invalid VHDX block size {} B",
            found.block_size
        )));
    }
    if !matches!(found.logical_sector_size, SECTOR_512 | SECTOR_4096) {
        return Err(error(format!(
            "Invalid VHDX logical sector size {} B",
            found.logical_sector_size
        )));
    }
    if found.virtual_size > MAX_VIRTUAL_SIZE
        || found.virtual_size % u64::from(found.logical_sector_size) != 0
    {
        return Err(error(format!(
            "Invalid VHDX virtual disk size {} B",
            found.virtual_size
        )));
    }
    match (found.has_parent(), found.parent.is_some()) {
        (true, false) => Err(error("Missing VHDX parent locator for a differencing disk")),
        _ => Ok(()),
    }
}

/// The parent locator's key-value pairs (2.6.2.6): UTF-16LE strings at
/// offsets within the item.
fn parent_locator(item: &[u8]) -> Result<Vec<LocatorEntry>> {
    let count = usize::from(le_u16(item, 18)?);
    slice(
        item,
        LOCATOR_HEADER_SIZE,
        count * LOCATOR_ENTRY_SIZE,
        "VHDX parent locator",
    )?;
    let mut pairs = Vec::with_capacity(count);
    for i in 0..count {
        let entry = slice(
            item,
            LOCATOR_HEADER_SIZE + i * LOCATOR_ENTRY_SIZE,
            LOCATOR_ENTRY_SIZE,
            "VHDX parent locator entry",
        )?;
        let key = slice(
            item,
            le_u32(entry, 0)? as usize,
            usize::from(le_u16(entry, 8)?),
            "VHDX parent locator key",
        )?;
        let value = slice(
            item,
            le_u32(entry, 4)? as usize,
            usize::from(le_u16(entry, 10)?),
            "VHDX parent locator value",
        )?;
        pairs.push(LocatorEntry {
            key: utf16_text(key, true),
            value: utf16_text(value, true),
        });
    }
    Ok(pairs)
}

/// Parse a VHDX image.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let creator = utf16_text(
        slice(
            data,
            CREATOR_OFFSET,
            CREATOR_SIZE,
            "VHDX file type identifier",
        )?,
        true,
    );
    let header = current_header(data)?;
    let regions = regions(data)?;
    let meta = metadata(data, regions.metadata)?;
    let kind = if meta.has_parent() {
        "differencing"
    } else if meta.flags & LEAVE_BLOCKS_ALLOCATED != 0 {
        "fixed"
    } else {
        "dynamic"
    };
    let mut c = container_for(data, Layout::Vhdx, format!("VHDX {kind}"));
    c.notes.push(format!(
        "VHDX {kind} disk; {} virtual disk; {} blocks; {} B logical sectors{}; current header at \
         0x{:X} (sequence number {}); region table at 0x{:X}",
        size_text(meta.virtual_size),
        size_text(u64::from(meta.block_size)),
        meta.logical_sector_size,
        meta.physical_sector_size
            .map(|size| format!(", {size} B physical sectors"))
            .unwrap_or_default(),
        header.offset,
        header.sequence,
        regions.table_offset
    ));
    if !creator.is_empty() {
        c.notes.push(format!("Creator: {creator}"));
        c.push_metadata("vdisk_vhdx_creator", "Creator", creator);
    }
    if header.log_guid != [0; 16] {
        c.notes.push(format!(
            "The log at 0x{:X} ({} B) may hold updates that were not replayed; metadata and \
             blocks are read as stored",
            header.log_offset, header.log_length
        ));
    }
    if let Some(id) = &meta.disk_id {
        c.push_metadata("vdisk_vhdx_disk_id", "Virtual disk ID", id.as_str());
    }
    c.push_metadata(
        "vdisk_vhdx_block_size",
        "Block size (B)",
        u64::from(meta.block_size),
    );
    let parent = meta.parent.as_deref().map(|entries| {
        let reference = parent_reference(entries);
        c.notes
            .push(format!("Differencing disk of the parent {reference}"));
        Parent {
            role: "parent disk",
            reference,
        }
    });
    let mut guest = Guest::new(data, meta.virtual_size);
    map_blocks(data, &meta, regions.bat, &mut guest)?;
    guest.finish(&mut c, TRANSFORM, parent.as_ref())?;
    Ok(c)
}

/// The parent's linkage GUID and paths, as the locator stores them.
fn parent_reference(entries: &[LocatorEntry]) -> String {
    let known: Vec<String> = PARENT_KEYS
        .iter()
        .filter_map(|&key| {
            entries
                .iter()
                .find(|entry| entry.key == key)
                .map(|entry| format!("{key} {}", entry.value))
        })
        .collect();
    if known.is_empty() {
        "named by an unknown locator".to_string()
    } else {
        format!("({})", known.join("; "))
    }
}

/// The BAT geometry of 2.4 and 2.5: payload blocks per chunk, and where a
/// payload block's entry and its chunk's sector bitmap entry are.
struct BatLayout {
    /// Payload blocks per chunk.
    chunk_ratio: u64,
    /// Payload bytes per block.
    block_size: u64,
    /// Logical sector size in bytes.
    sector_size: u64,
}

impl BatLayout {
    fn payload_index(&self, block: u64) -> u64 {
        block + block / self.chunk_ratio
    }

    fn bitmap_index(&self, block: u64) -> u64 {
        (block / self.chunk_ratio + 1) * (self.chunk_ratio + 1) - 1
    }

    /// BAT entries the disk needs (QEMU `vhdx_calc_bat_entries`).
    fn entries(&self, virtual_size: u64, has_parent: bool) -> u64 {
        let blocks = div_ceil(virtual_size, self.block_size);
        if has_parent {
            div_ceil(blocks, self.chunk_ratio) * (self.chunk_ratio + 1)
        } else if blocks == 0 {
            0
        } else {
            blocks + (blocks - 1) / self.chunk_ratio
        }
    }
}

/// One BAT entry, read from the BAT region.
fn bat_entry(data: &[u8], bat: Region, index: u64) -> Result<u64> {
    let at = bat.offset + index * BAT_ENTRY_SIZE;
    Ok(u64::from_le_bytes(
        range(data, at, BAT_ENTRY_SIZE, "VHDX BAT")?
            .try_into()
            .expect("8 bytes"),
    ))
}

/// The file offset of a block that a BAT entry locates, which must lie
/// after the 1 MiB header section.
fn block_offset(entry: u64, index: u64) -> Result<u64> {
    let offset = (entry >> BAT_OFFSET_SHIFT) << BAT_OFFSET_SHIFT;
    if offset < MIB {
        return Err(error(format!(
            "Invalid VHDX BAT entry {index}: block offset 0x{offset:X} is in the header section"
        )));
    }
    Ok(offset)
}

/// Map every payload block in the analyzed range from its BAT entry.
fn map_blocks<'a>(
    data: &'a [u8],
    meta: &Metadata,
    bat: Region,
    guest: &mut Guest<'a>,
) -> Result<()> {
    let layout = BatLayout {
        chunk_ratio: SECTORS_PER_CHUNK * u64::from(meta.logical_sector_size)
            / u64::from(meta.block_size),
        block_size: u64::from(meta.block_size),
        sector_size: u64::from(meta.logical_sector_size),
    };
    let entries = layout.entries(meta.virtual_size, meta.has_parent());
    if entries * BAT_ENTRY_SIZE > u64::from(bat.length) {
        return Err(error(format!(
            "Invalid VHDX BAT region: {} B hold fewer than the {entries} entries of the disk",
            bat.length
        )));
    }
    for block in 0..guest.block_count(layout.block_size) {
        let index = layout.payload_index(block);
        let entry = bat_entry(data, bat, index)?;
        match entry & BAT_STATE_MASK {
            PAYLOAD_BLOCK_NOT_PRESENT if meta.has_parent() => guest.parent(layout.block_size),
            PAYLOAD_BLOCK_NOT_PRESENT
            | PAYLOAD_BLOCK_UNDEFINED
            | PAYLOAD_BLOCK_ZERO
            | PAYLOAD_BLOCK_UNMAPPED
            | PAYLOAD_BLOCK_UNMAPPED_V095 => guest.zero(layout.block_size),
            PAYLOAD_BLOCK_FULLY_PRESENT => {
                let offset = block_offset(entry, index)?;
                guest.stored(offset, layout.block_size, "VHDX payload block")?;
            }
            PAYLOAD_BLOCK_PARTIALLY_PRESENT if meta.has_parent() => {
                let offset = block_offset(entry, index)?;
                let partial = PartialBlock { block, offset, bat };
                map_partial_block(data, &layout, &partial, guest)?;
            }
            PAYLOAD_BLOCK_PARTIALLY_PRESENT => {
                return Err(error(format!(
                    "Invalid VHDX BAT entry {index}: a partially present block in a disk \
                     without a parent"
                )));
            }
            state => {
                return Err(error(format!(
                    "Invalid VHDX BAT entry {index}: reserved payload block state {state}"
                )));
            }
        }
    }
    Ok(())
}

/// A partially present payload block.
struct PartialBlock {
    /// Payload block number.
    block: u64,
    /// File offset of its data.
    offset: u64,
    /// The BAT region that also holds its chunk's sector bitmap entry.
    bat: Region,
}

/// Map a partially present block sector by sector from its chunk's sector
/// bitmap block: bit 0 of byte 0 is the chunk's first sector, 1 means the
/// sector is in this file, 0 that the parent holds it.
fn map_partial_block<'a>(
    data: &'a [u8],
    layout: &BatLayout,
    partial: &PartialBlock,
    guest: &mut Guest<'a>,
) -> Result<()> {
    let index = layout.bitmap_index(partial.block);
    let entry = bat_entry(data, partial.bat, index)?;
    if entry & BAT_STATE_MASK != SB_BLOCK_PRESENT {
        return Err(error(format!(
            "Invalid VHDX BAT entry {index}: the sector bitmap of a partially present block is \
             not present"
        )));
    }
    let bitmap = range(
        data,
        block_offset(entry, index)?,
        MIB,
        "VHDX sector bitmap block",
    )?;
    let sectors_per_block = layout.block_size / layout.sector_size;
    let first = (partial.block % layout.chunk_ratio) * sectors_per_block;
    let remaining = guest.block_count(layout.sector_size) - partial.block * sectors_per_block;
    for sector in 0..sectors_per_block.min(remaining) {
        let bit = first + sector;
        let byte = bitmap[usize::try_from(bit / 8).expect("a chunk has 2^23 bits")];
        if byte & (1 << (bit % 8)) != 0 {
            let at = partial.offset + sector * layout.sector_size;
            guest.stored(at, layout.sector_size, "VHDX payload sector")?;
        } else {
            guest.parent(layout.sector_size);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bat_interleaves_one_bitmap_entry_per_chunk() {
        // 512-byte sectors and 1 MiB blocks: 4096 payload blocks per chunk.
        let layout = BatLayout {
            chunk_ratio: SECTORS_PER_CHUNK * 512 / (1 << 20),
            block_size: 1 << 20,
            sector_size: 512,
        };
        assert_eq!(layout.chunk_ratio, 4096);
        assert_eq!(layout.payload_index(0), 0);
        assert_eq!(layout.payload_index(4095), 4095);
        assert_eq!(layout.payload_index(4096), 4097);
        assert_eq!(layout.bitmap_index(0), 4096);
        assert_eq!(layout.bitmap_index(4096), 8193);
        assert_eq!(layout.entries(1 << 20, false), 1);
        assert_eq!(layout.entries(4097 << 20, false), 4098);
        assert_eq!(layout.entries(1 << 20, true), 4097);
        assert_eq!(layout.entries(0, false), 0);
    }

    #[test]
    fn crc32c_counts_the_checksum_field_as_zero() {
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(b"head");
        let crc = crc32c(&bytes);
        bytes[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        assert!(is_sealed(&bytes));
        assert_eq!(crc32c(&bytes), crc);
        bytes[10] ^= 1;
        assert!(!is_sealed(&bytes));
    }
}
