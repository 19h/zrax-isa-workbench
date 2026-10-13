//! Store headers (`STORE_HEADER` and its V2 fields), validation entries
//! (`VALIDATION_ENTRY`) and write descriptors (`BLOCK_DATA_ENTRY` with
//! `DISK_LOCATION`s), and where each store's payload lies (Microsoft "FFU
//! image format", "Store header region", "Validation Entries", "Block data
//! entries", "Image payload region").
//!
//! Store header: `dwUpdateType` (0), `MajorVersion` (4), `MinorVersion`
//! (6), `FullFlashMajorVersion` (8), `FullFlashMinorVersion` (10),
//! `szPlatformId` (12, 192 B), `dwBlockSizeInBytes` (204),
//! `dwWriteDescriptorCount` (208), `dwWriteDescriptorLength` (212),
//! `dwValidateDescriptorCount` (216), `dwValidateDescriptorLength` (220),
//! the initial, flash-only and final GPT table index and count pairs (224
//! to 247): 248 B (`STORE_HEADER_V1_0_SIZE`). V2 adds `NumOfStores` (248),
//! `StoreIndex` (250), `StorePayloadSize` (252, 8 B), `DevicePathLength`
//! (260) and the UTF-16 `DevicePath` (262) without alignment padding, as
//! img2ffu reads and writes them (Microsoft's declaration does not state the
//! packing). The validation entries follow the header, then the write
//! descriptors (`WPinternals`, img2ffu), then padding to a block boundary.
//! V2 store headers follow each other; the payloads follow the last one, in
//! store order.

use super::*;

/// `STORE_HEADER_V1_0_SIZE`.
const STORE_HEADER_SIZE: usize = 248;

/// The V2 fields before the device path: `NumOfStores`, `StoreIndex`,
/// `StorePayloadSize` and `DevicePathLength`.
const STORE_V2_FIELDS_SIZE: usize = 14;

/// `szPlatformId`.
const PLATFORM_ID_OFFSET: usize = 12;
const PLATFORM_ID_SIZE: usize = 192;

/// `MajorVersion` and `FullFlashMajorVersion` of the two documented
/// formats (Microsoft's version table: V1 is 1.0 with full flash 2.0, V2 is
/// 2.0 with full flash 2.0).
const STORE_VERSION_1: u16 = 1;
const STORE_VERSION_2: u16 = 2;
const FULL_FLASH_VERSION_2: u16 = 2;

/// `VALIDATION_ENTRY` before its compare data: sector index, sector offset
/// and byte count.
const VALIDATION_ENTRY_SIZE: usize = 12;

/// `BLOCK_DATA_ENTRY` before its locations: location count and block count.
const BLOCK_DATA_ENTRY_SIZE: usize = 8;

/// `DISK_LOCATION`: access method and block index.
const DISK_LOCATION_SIZE: usize = 8;

/// `DISK_ACCESS_METHOD` values.
const DISK_BEGIN: u32 = 0;
const DISK_END: u32 = 2;

/// Smallest block size accepted, one 512-byte sector: a bound of this
/// parser (Microsoft gives none; every block holds whole sectors).
const MIN_BLOCK_SIZE: u32 = 512;

/// Largest block size accepted: a bound of this parser, so that one block
/// fits in the analyzed range of a disk (64 MiB, `MAX_PAYLOAD`).
const MAX_BLOCK_SIZE: u32 = 64 << 20;

/// The store header and full flash versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StoreVersion {
    major: u16,
    minor: u16,
    full_flash_major: u16,
    full_flash_minor: u16,
}

impl StoreVersion {
    fn is_v2(self) -> bool {
        self.major == STORE_VERSION_2
    }
}

/// The V2 fields of a store header.
#[derive(Debug)]
struct StoreV2 {
    /// `NumOfStores`.
    store_count: u16,
    /// `StoreIndex`, 1-based.
    store_index: u16,
    /// `StorePayloadSize`, in bytes.
    payload_size: u64,
    /// `DevicePath`, the UEFI device path text of the target.
    device_path: String,
}

/// A GPT table's position in the payload: `dwInitialTableIndex` and
/// `dwInitialTableCount`, and the flash-only and final pairs.
#[derive(Debug, Clone, Copy)]
struct TableRange {
    index: u32,
    count: u32,
}

/// The blocks the write descriptors reach, for checks against the disk
/// size.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Extent {
    /// One past the highest block a `DISK_BEGIN` location writes.
    pub(super) begin_blocks: u64,
    /// The most blocks a `DISK_END` location reaches back from the end of
    /// the disk (`dwBlockIndex + 1`).
    pub(super) end_blocks: u64,
    /// Block writes at `DISK_END` locations.
    pub(super) end_writes: u64,
}

/// One store: its header fields and validated descriptor regions.
#[derive(Debug)]
pub(super) struct Store<'a> {
    /// Position in the file, from 1.
    pub(super) number: usize,
    /// File offset of the store header.
    offset: usize,
    version: StoreVersion,
    /// `dwUpdateType`.
    update_type: u32,
    /// `szPlatformId`, split at NULs.
    platform_ids: Vec<String>,
    /// `dwBlockSizeInBytes`.
    pub(super) block_size: u32,
    /// `dwValidateDescriptorCount`.
    validation_count: u32,
    /// The write descriptors, validated.
    pub(super) writes: WriteDescriptors<'a>,
    initial_table: TableRange,
    flash_only_table: TableRange,
    final_table: TableRange,
    v2: Option<StoreV2>,
    /// The blocks the write descriptors reach.
    pub(super) extent: Extent,
    /// Payload blocks: the sum of `dwBlockCount`.
    pub(super) payload_blocks: u64,
    /// File offset after the store's region and its padding: the next store
    /// header or the payload.
    end: usize,
    /// File offset and size of the store's payload, in bytes.
    pub(super) payload_offset: usize,
    pub(super) payload_size: usize,
}

/// The stores of an image and where their payloads lie.
#[derive(Debug)]
pub(super) struct Stores<'a> {
    pub(super) list: Vec<Store<'a>>,
    /// File offset of the first store's payload.
    pub(super) payload_offset: usize,
    /// File offset after the last store's payload.
    pub(super) payload_end: usize,
}

impl Stores<'_> {
    /// "FFU v1" or "FFU v2", from the first store header.
    pub(super) fn variant(&self) -> &'static str {
        match self.list.first() {
            Some(store) if store.version.is_v2() => "FFU v2",
            _ => "FFU v1",
        }
    }
}

/// Where a store header sits in the image's series of stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Position {
    /// The first store header, which says how many there are.
    First,
    /// Store `number` (from 2) of a V2 image of `count` stores.
    Next { number: usize, count: u16 },
}

impl Position {
    /// The store's position from 1.
    fn number(self) -> usize {
        match self {
            Self::First => 1,
            Self::Next { number, .. } => number,
        }
    }
}

/// Read every store header from `offset`: one for V1, `NumOfStores` for
/// V2, each at the end of the previous one's padding; then place the
/// payloads after the last, in store order, and check that the file holds
/// them.
pub(super) fn read_all(data: &[u8], offset: usize) -> Result<Stores<'_>> {
    let first = Store::read(data, offset, Position::First)?;
    let count = first.v2.as_ref().map_or(1, |v2| v2.store_count);
    let mut list = vec![first];
    while list.len() < usize::from(count) {
        let next_offset = list.last().map_or(offset, |store| store.end);
        let position = Position::Next {
            number: list.len() + 1,
            count,
        };
        list.push(Store::read(data, next_offset, position)?);
    }
    let payload_offset = list.last().map_or(offset, |store| store.end);
    let mut cursor = payload_offset;
    for store in &mut list {
        let size = store
            .payload_blocks
            .saturating_mul(u64::from(store.block_size));
        let end = (cursor as u64)
            .checked_add(size)
            .filter(|&end| end <= data.len() as u64)
            .ok_or_else(|| {
                error(format!(
                    "Truncated store {} payload at 0x{cursor:X}: {size} B, but the file ends at \
                     0x{:X}",
                    store.number,
                    data.len()
                ))
            })?;
        store.payload_offset = cursor;
        store.payload_size = to_usize(size, "store payload")?;
        cursor = to_usize(end, "store payload")?;
    }
    Ok(Stores {
        list,
        payload_offset,
        payload_end: cursor,
    })
}

/// Check the V2 fields of the store header at `offset` against its
/// position: at least one store, the count the first store gives, and a
/// `StoreIndex` that is the store's position.
fn check_series(v2: &StoreV2, offset: usize, position: Position) -> Result<()> {
    let count_at = offset + STORE_HEADER_SIZE;
    if v2.store_count == 0 {
        return Err(error(format!("Invalid store count 0 at 0x{count_at:X}")));
    }
    if let Position::Next { count, .. } = position {
        if v2.store_count != count {
            return Err(error(format!(
                "Invalid store count {} at 0x{count_at:X}: store 1 gives {count}",
                v2.store_count
            )));
        }
    }
    if usize::from(v2.store_index) != position.number() {
        return Err(error(format!(
            "Invalid store index {} at 0x{:X}: store {} expected",
            v2.store_index,
            count_at + 2,
            position.number()
        )));
    }
    Ok(())
}

impl<'a> Store<'a> {
    /// Read the store header at `offset`, check it against its position in
    /// the series, then validate its validation and write descriptor
    /// regions.
    fn read(data: &'a [u8], offset: usize, position: Position) -> Result<Self> {
        let number = position.number();
        let header = slice(data, offset, STORE_HEADER_SIZE, "store header")?;
        let version = StoreVersion {
            major: le_u16(header, 4)?,
            minor: le_u16(header, 6)?,
            full_flash_major: le_u16(header, 8)?,
            full_flash_minor: le_u16(header, 10)?,
        };
        let is_known = matches!(version.major, STORE_VERSION_1 | STORE_VERSION_2)
            && version.full_flash_major == FULL_FLASH_VERSION_2;
        if !is_known {
            return Err(error(format!(
                "Unsupported store {number} header version {}.{} (full flash {}.{}) at 0x{:X}",
                version.major,
                version.minor,
                version.full_flash_major,
                version.full_flash_minor,
                offset + 4
            )));
        }
        if position != Position::First && !version.is_v2() {
            return Err(error(format!(
                "Invalid store {number} header version {}.{} at 0x{:X}: it follows a V2 store",
                version.major,
                version.minor,
                offset + 4
            )));
        }
        let block_size = le_u32(header, 204)?;
        if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&block_size) {
            return Err(error(format!(
                "Invalid store {number} block size {block_size} B at 0x{:X}: this parser accepts \
                 {MIN_BLOCK_SIZE} B to {}",
                offset + 204,
                size_text(u64::from(MAX_BLOCK_SIZE))
            )));
        }
        let (v2, descriptors_offset) = if version.is_v2() {
            let v2 = read_v2_fields(data, offset + STORE_HEADER_SIZE)?;
            check_series(&v2.fields, offset, position)?;
            let path_size = 2 * v2.path_units;
            (
                Some(v2.fields),
                offset + STORE_HEADER_SIZE + STORE_V2_FIELDS_SIZE + path_size,
            )
        } else {
            (None, offset + STORE_HEADER_SIZE)
        };
        let validation_count = le_u32(header, 216)?;
        let validation = slice(
            data,
            descriptors_offset,
            le_u32(header, 220)? as usize,
            "validation entries",
        )?;
        check_validation_entries(validation, descriptors_offset, validation_count, number)?;
        let writes_offset = descriptors_offset + validation.len();
        let writes = WriteDescriptors {
            region: slice(
                data,
                writes_offset,
                le_u32(header, 212)? as usize,
                "write descriptors",
            )?,
            offset: writes_offset,
            count: le_u32(header, 208)?,
        };
        let summary = writes.validate(number)?;
        let writes_end = (writes_offset + writes.region.len()) as u64;
        let end = round_up(writes_end, u64::from(block_size))
            .ok_or_else(|| error("Invalid store region size"))?;
        let table = |at: usize| -> Result<TableRange> {
            Ok(TableRange {
                index: le_u32(header, at)?,
                count: le_u32(header, at + 4)?,
            })
        };
        Ok(Self {
            number,
            offset,
            version,
            update_type: le_u32(header, 0)?,
            platform_ids: platform_ids(slice(
                header,
                PLATFORM_ID_OFFSET,
                PLATFORM_ID_SIZE,
                "platform ID",
            )?),
            block_size,
            validation_count,
            writes,
            initial_table: table(224)?,
            flash_only_table: table(232)?,
            final_table: table(240)?,
            v2,
            extent: summary.extent,
            payload_blocks: summary.blocks,
            end: to_usize(end, "store padding")?,
            payload_offset: 0,
            payload_size: 0,
        })
    }

    /// The store's notes and metadata: versions, block size, descriptors,
    /// payload, platform IDs and the V2 fields.
    pub(super) fn push_notes(&self, c: &mut Container<'_>) {
        let n = self.number;
        let version = self.version;
        c.notes.push(format!(
            "Store {n} at 0x{:X}: store header {}.{}, full flash {}.{}; {} blocks; {} placing {} \
             ({} of payload at 0x{:X}); {}; update type {}",
            self.offset,
            version.major,
            version.minor,
            version.full_flash_major,
            version.full_flash_minor,
            size_text(u64::from(self.block_size)),
            counted(
                u64::from(self.writes.count),
                "write descriptor",
                "write descriptors"
            ),
            counted(self.payload_blocks, "block", "blocks"),
            size_text(self.payload_size as u64),
            self.payload_offset,
            counted(
                u64::from(self.validation_count),
                "validation entry",
                "validation entries"
            ),
            self.update_type
        ));
        if !self.platform_ids.is_empty() {
            let ids = self.platform_ids.join(", ");
            c.notes.push(format!("Store {n} platform ID: {ids}"));
            c.push_metadata(
                format!("ffu_store_{n}_platform_id"),
                format!("Store {n} platform ID"),
                ids,
            );
        }
        if let Some(v2) = &self.v2 {
            c.notes.push(format!(
                "Store {n} of {}: device path {}",
                v2.store_count,
                if v2.device_path.is_empty() {
                    "(empty)"
                } else {
                    &v2.device_path
                }
            ));
            if v2.payload_size != self.payload_size as u64 {
                c.notes.push(format!(
                    "Store {n} payload size field says {} B; its write descriptors place {} B",
                    v2.payload_size, self.payload_size
                ));
            }
            c.push_metadata(
                format!("ffu_store_{n}_device_path"),
                format!("Store {n} device path"),
                v2.device_path.clone(),
            );
        }
        c.push_metadata(
            format!("ffu_store_{n}_version"),
            format!("Store {n} header version"),
            format!("{}.{}", version.major, version.minor),
        );
        c.push_metadata(
            format!("ffu_store_{n}_block_size"),
            format!("Store {n} block size (B)"),
            u64::from(self.block_size),
        );
        c.push_metadata(
            format!("ffu_store_{n}_write_descriptors"),
            format!("Store {n} write descriptors"),
            u64::from(self.writes.count),
        );
        c.push_metadata(
            format!("ffu_store_{n}_payload_blocks"),
            format!("Store {n} payload blocks"),
            self.payload_blocks,
        );
        c.push_metadata(
            format!("ffu_store_{n}_gpt_tables"),
            format!("Store {n} GPT table blocks (index + count)"),
            format!(
                "initial {} + {}; flash-only {} + {}; final {} + {}",
                self.initial_table.index,
                self.initial_table.count,
                self.flash_only_table.index,
                self.flash_only_table.count,
                self.final_table.index,
                self.final_table.count
            ),
        );
    }
}

/// The V2 fields and the device path length in UTF-16 code units.
struct V2Fields {
    fields: StoreV2,
    path_units: usize,
}

/// Read the V2 fields at `offset` (after the 248-byte header) and the
/// device path after them.
fn read_v2_fields(data: &[u8], offset: usize) -> Result<V2Fields> {
    let fields = slice(data, offset, STORE_V2_FIELDS_SIZE, "V2 store header")?;
    let path_units = le_u16(fields, 12)? as usize;
    let path = slice(
        data,
        offset + STORE_V2_FIELDS_SIZE,
        2 * path_units,
        "store device path",
    )?;
    Ok(V2Fields {
        fields: StoreV2 {
            store_count: le_u16(fields, 0)?,
            store_index: le_u16(fields, 2)?,
            payload_size: le_u64(fields, 4)?,
            device_path: utf16le_text(path),
        },
        path_units,
    })
}

/// The NUL-separated, non-empty IDs in `szPlatformId` (img2ffu writes
/// several).
fn platform_ids(field: &[u8]) -> Vec<String> {
    field
        .split(|&b| b == 0)
        .filter(|id| !id.is_empty())
        .map(byte_text)
        .collect()
}

/// Check that `count` validation entries, each 12 bytes and its compare
/// data, fill `region` (at file offset `offset`) exactly.
fn check_validation_entries(region: &[u8], offset: usize, count: u32, store: usize) -> Result<()> {
    let mut at = 0usize;
    for i in 0..count {
        let entry = slice(region, at, VALIDATION_ENTRY_SIZE, "validation entry").map_err(|_| {
            error(format!(
                "Truncated store {store} validation entry {i} at 0x{:X}: the region holds {} B",
                offset + at,
                region.len()
            ))
        })?;
        let compare_size = le_u32(entry, 8)? as usize;
        let size = VALIDATION_ENTRY_SIZE
            .checked_add(compare_size)
            .filter(|&size| size <= region.len() - at)
            .ok_or_else(|| {
                error(format!(
                    "Invalid store {store} validation entry {i} at 0x{:X}: {compare_size} B of \
                     compare data overrun the {} B region",
                    offset + at,
                    region.len()
                ))
            })?;
        at += size;
    }
    if at != region.len() {
        return Err(error(format!(
            "Invalid store {store} validation entries at 0x{offset:X}: {} fill {at} of {} B",
            counted(u64::from(count), "entry", "entries"),
            region.len()
        )));
    }
    Ok(())
}

/// Where a disk location counts its block index from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Access {
    /// `DISK_BEGIN`: block index from the first block of the disk.
    Begin,
    /// `DISK_END`: block index back from the last block (0 is the last).
    End,
}

/// One `DISK_LOCATION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DiskLocation {
    pub(super) access: Access,
    /// `dwBlockIndex`.
    pub(super) block_index: u32,
}

/// One `BLOCK_DATA_ENTRY`: `block_count` payload blocks and the locations
/// they are written to.
#[derive(Debug, Clone, Copy)]
pub(super) struct WriteDescriptor<'a> {
    /// File offset of the entry.
    pub(super) offset: usize,
    /// `dwBlockCount`.
    pub(super) block_count: u32,
    /// The `DISK_LOCATION`s, 8 bytes each.
    locations: &'a [u8],
}

impl WriteDescriptor<'_> {
    /// The locations; an unknown access method (rejected by
    /// [`WriteDescriptors::validate`]) is skipped.
    pub(super) fn locations(&self) -> impl Iterator<Item = DiskLocation> + '_ {
        self.locations
            .chunks_exact(DISK_LOCATION_SIZE)
            .filter_map(|location| {
                let method =
                    u32::from_le_bytes([location[0], location[1], location[2], location[3]]);
                let block_index =
                    u32::from_le_bytes([location[4], location[5], location[6], location[7]]);
                let access = match method {
                    DISK_BEGIN => Access::Begin,
                    DISK_END => Access::End,
                    _ => return None,
                };
                Some(DiskLocation {
                    access,
                    block_index,
                })
            })
    }
}

/// The write descriptor region of a store.
#[derive(Debug, Clone, Copy)]
pub(super) struct WriteDescriptors<'a> {
    /// `dwWriteDescriptorLength` bytes.
    region: &'a [u8],
    /// File offset of the region.
    offset: usize,
    /// `dwWriteDescriptorCount`.
    count: u32,
}

/// What the write descriptors place, from [`WriteDescriptors::validate`].
struct WriteSummary {
    /// Payload blocks: the sum of `dwBlockCount`.
    blocks: u64,
    extent: Extent,
}

impl<'a> WriteDescriptors<'a> {
    /// The descriptors in order. After [`WriteDescriptors::validate`] this
    /// yields all `count` of them; it stops at the first one that does not
    /// fit.
    pub(super) fn iter(&self) -> impl Iterator<Item = WriteDescriptor<'a>> + 'a {
        let region = self.region;
        let offset = self.offset;
        let mut at = 0usize;
        (0..self.count).map_while(move |_| {
            let entry = region.get(at..at.checked_add(BLOCK_DATA_ENTRY_SIZE)?)?;
            let location_count = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let block_count = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
            let start = at + BLOCK_DATA_ENTRY_SIZE;
            let size = (location_count as usize).checked_mul(DISK_LOCATION_SIZE)?;
            let locations = region.get(start..start.checked_add(size)?)?;
            let descriptor = WriteDescriptor {
                offset: offset + at,
                block_count,
                locations,
            };
            at = start + size;
            Some(descriptor)
        })
    }

    /// Check that `count` descriptors fill the region exactly and use only
    /// `DISK_BEGIN` and `DISK_END`, that a `DISK_END` run does not pass the
    /// end of the disk, and sum the blocks they place.
    fn validate(&self, store: usize) -> Result<WriteSummary> {
        let mut at = 0usize;
        let mut blocks = 0u64;
        let mut extent = Extent::default();
        for i in 0..self.count {
            let file_offset = self.offset + at;
            let entry = slice(self.region, at, BLOCK_DATA_ENTRY_SIZE, "write descriptor").map_err(
                |_| {
                    error(format!(
                        "Truncated store {store} write descriptor {i} at 0x{file_offset:X}: the \
                         region holds {} B",
                        self.region.len()
                    ))
                },
            )?;
            let location_count = le_u32(entry, 0)?;
            let block_count = le_u32(entry, 4)?;
            let locations_size = (location_count as usize)
                .checked_mul(DISK_LOCATION_SIZE)
                .filter(|&size| size <= self.region.len() - at - BLOCK_DATA_ENTRY_SIZE)
                .ok_or_else(|| {
                    error(format!(
                        "Invalid store {store} write descriptor {i} at 0x{file_offset:X}: \
                         {location_count} locations overrun the {} B region",
                        self.region.len()
                    ))
                })?;
            let locations = &self.region[at + BLOCK_DATA_ENTRY_SIZE..][..locations_size];
            for location in locations.chunks_exact(DISK_LOCATION_SIZE) {
                let method = le_u32(location, 0)?;
                let block_index = u64::from(le_u32(location, 4)?);
                let count = u64::from(block_count);
                match method {
                    DISK_BEGIN => {
                        extent.begin_blocks = extent.begin_blocks.max(block_index + count);
                    }
                    // A run written from block `dwBlockIndex` before the end
                    // goes forward, so it may hold at most that many blocks
                    // plus one (the assumed reading of a multi-block
                    // `DISK_END` entry; every known writer uses one block).
                    DISK_END if count <= block_index + 1 => {
                        extent.end_blocks = extent.end_blocks.max(block_index + 1);
                        extent.end_writes += count;
                    }
                    DISK_END => {
                        return Err(error(format!(
                            "Invalid store {store} write descriptor {i} at 0x{file_offset:X}: \
                             {block_count} blocks from block {block_index} before the end run \
                             past the end of the disk"
                        )));
                    }
                    other => {
                        return Err(error(format!(
                            "Unsupported disk access method {other} in store {store} write \
                             descriptor {i} at 0x{file_offset:X}"
                        )));
                    }
                }
            }
            blocks += u64::from(block_count);
            at += BLOCK_DATA_ENTRY_SIZE + locations_size;
        }
        if at != self.region.len() {
            return Err(error(format!(
                "Invalid store {store} write descriptors at 0x{:X}: {} fill {at} of {} B",
                self.offset,
                counted(u64::from(self.count), "descriptor", "descriptors"),
                self.region.len()
            )));
        }
        Ok(WriteSummary { blocks, extent })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One `DISK_LOCATION` of a test entry.
    struct Location {
        method: u32,
        index: u32,
    }

    /// One `BLOCK_DATA_ENTRY` of a test region.
    struct Entry {
        blocks: u32,
        locations: Vec<Location>,
    }

    fn entry(blocks: u32, locations: &[[u32; 2]]) -> Entry {
        Entry {
            blocks,
            locations: locations
                .iter()
                .map(|&[method, index]| Location { method, index })
                .collect(),
        }
    }

    /// A write descriptor region: each entry's location count, block count
    /// and locations.
    fn region(entries: &[Entry]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for e in entries {
            let count = u32::try_from(e.locations.len()).expect("test entries are small");
            bytes.extend_from_slice(&count.to_le_bytes());
            bytes.extend_from_slice(&e.blocks.to_le_bytes());
            for location in &e.locations {
                bytes.extend_from_slice(&location.method.to_le_bytes());
                bytes.extend_from_slice(&location.index.to_le_bytes());
            }
        }
        bytes
    }

    fn descriptors(bytes: &[u8], count: u32) -> WriteDescriptors<'_> {
        WriteDescriptors {
            region: bytes,
            offset: 0x1000,
            count,
        }
    }

    #[test]
    fn write_descriptors_sum_blocks_and_extents() {
        let bytes = region(&[
            entry(1, &[[DISK_BEGIN, 0], [DISK_END, 0]]),
            entry(3, &[[DISK_BEGIN, 5]]),
            entry(2, &[[DISK_END, 4]]),
            entry(1, &[]),
        ]);
        let writes = descriptors(&bytes, 4);
        let summary = writes.validate(1).unwrap();
        assert_eq!(summary.blocks, 7);
        assert_eq!(summary.extent.begin_blocks, 8);
        assert_eq!(summary.extent.end_blocks, 5);
        assert_eq!(summary.extent.end_writes, 3);
        let listed: Vec<u32> = writes.iter().map(|d| d.block_count).collect();
        assert_eq!(listed, [1, 3, 2, 1]);
        let first: Vec<DiskLocation> = writes.iter().next().unwrap().locations().collect();
        assert_eq!(
            first,
            [
                DiskLocation {
                    access: Access::Begin,
                    block_index: 0
                },
                DiskLocation {
                    access: Access::End,
                    block_index: 0
                }
            ]
        );
    }

    #[test]
    fn write_descriptors_must_fill_their_region_with_known_methods() {
        let bytes = region(&[entry(1, &[[DISK_BEGIN, 0]])]);
        let message = |bytes: &[u8], count| {
            descriptors(bytes, count)
                .validate(2)
                .err()
                .map(|e| e.to_string())
        };
        assert_eq!(message(&bytes, 1), None);
        assert_eq!(
            message(&bytes, 2).unwrap(),
            "FFU image parse error: Truncated store 2 write descriptor 1 at 0x1010: the region \
             holds 16 B"
        );
        assert_eq!(
            message(&bytes, 0).unwrap(),
            "FFU image parse error: Invalid store 2 write descriptors at 0x1000: 0 descriptors \
             fill 0 of 16 B"
        );
        let sequential = region(&[entry(1, &[[1, 0]])]);
        assert_eq!(
            message(&sequential, 1).unwrap(),
            "FFU image parse error: Unsupported disk access method 1 in store 2 write \
             descriptor 0 at 0x1000"
        );
        let past_end = region(&[entry(2, &[[DISK_END, 0]])]);
        assert!(message(&past_end, 1)
            .unwrap()
            .contains("run past the end of the disk"));
        let mut overrun = bytes.clone();
        overrun[0] = 9;
        assert!(message(&overrun, 1)
            .unwrap()
            .contains("9 locations overrun"));
    }

    #[test]
    fn validation_entries_must_fill_their_region() {
        let mut entries = Vec::new();
        for (sector, data) in [(0u32, &b"EFI PART"[..]), (1, &b""[..])] {
            entries.extend_from_slice(&sector.to_le_bytes());
            entries.extend_from_slice(&0u32.to_le_bytes());
            let size = u32::try_from(data.len()).expect("test entries are small");
            entries.extend_from_slice(&size.to_le_bytes());
            entries.extend_from_slice(data);
        }
        assert!(check_validation_entries(&entries, 0x100, 2, 1).is_ok());
        assert!(check_validation_entries(&entries, 0x100, 1, 1).is_err());
        assert!(check_validation_entries(&entries, 0x100, 3, 1).is_err());
        assert!(check_validation_entries(&entries[..20], 0x100, 1, 1).is_ok());
        assert!(check_validation_entries(&entries[..19], 0x100, 1, 1).is_err());
    }

    #[test]
    fn platform_ids_split_at_nuls() {
        let mut field = [0u8; PLATFORM_ID_SIZE];
        field[..9].copy_from_slice(b"Zrax.A\0B\0");
        assert_eq!(platform_ids(&field), ["Zrax.A", "B"]);
        assert_eq!(platform_ids(&[0u8; 8]), Vec::<String>::new());
    }
}
