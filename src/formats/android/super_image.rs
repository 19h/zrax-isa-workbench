//! Dynamic-partition `super` images: the liblp logical partition metadata
//! of AOSP `platform/system/core` at `a3b721a3`
//! (`fs_mgr/liblp/include/liblp/metadata_format.h`; checks from
//! `fs_mgr/liblp/reader.cpp`, offsets from `utility.cpp`, file layouts
//! from `images.cpp` and `writer.cpp`).
//!
//! A full `super` image (`ImageBuilder`) is the first block device: 4096
//! reserved bytes, the geometry and its backup (4096 bytes each), then
//! `metadata_slot_count` primary and as many backup metadata copies of
//! `metadata_max_size` bytes, then partition data at 512-byte sectors. A
//! `super_empty` image (`WriteToImageFile`) holds the geometry at 0 and one
//! metadata copy at 4096, without partition data. The geometry and the
//! metadata header and tables carry SHA-256 checksums, which are verified.
//! Every field is little-endian.
//!
//! Partitions map logical sectors to dm-linear extents on a block device
//! or to dm-zero extents. Partitions whose extents lie in this file are
//! members, listed when they hold a recognized format: one linear extent
//! is borrowed from the file, several are assembled into one image. The
//! metadata names no CPU.

use super::*;
use crate::formats::container;
use sha2::{Digest, Sha256};

/// Backup geometry offset (`GetBackupGeometryOffset`).
const BACKUP_GEOMETRY_OFFSET: usize = LP_PARTITION_RESERVED_BYTES + LP_METADATA_GEOMETRY_SIZE;

/// First metadata slot in a full image (`GetPrimaryMetadataOffset`).
const METADATA_OFFSET: u64 = (LP_PARTITION_RESERVED_BYTES + 2 * LP_METADATA_GEOMETRY_SIZE) as u64;

/// `LpMetadataGeometry` size and the `checksum` field (SHA-256 at 8).
const GEOMETRY_STRUCT_SIZE: usize = 52;
const GEOMETRY_CHECKSUM: std::ops::Range<usize> = 8..40;

/// `LpMetadataHeader` magic and versions.
const LP_METADATA_HEADER_MAGIC: u32 = 0x414c_5030;
const LP_METADATA_MAJOR_VERSION: u16 = 10;
const LP_METADATA_MINOR_VERSION_MAX: u16 = 2;
const LP_METADATA_VERSION_FOR_UPDATED_ATTR: u16 = 1;
const LP_METADATA_VERSION_FOR_EXPANDED_HEADER: u16 = 2;

/// Header sizes of versions 10.0/10.1 (`LpMetadataHeaderV1_0`) and 10.2,
/// and the `header_checksum` field (SHA-256 at 12).
const HEADER_V1_0_SIZE: usize = 128;
const HEADER_V1_2_SIZE: usize = 256;
const HEADER_CHECKSUM: std::ops::Range<usize> = 12..44;

/// Table entry sizes: `LpMetadataPartition`, `LpMetadataExtent`,
/// `LpMetadataPartitionGroup`, `LpMetadataBlockDevice`.
const PARTITION_ENTRY_SIZE: u32 = 52;
const EXTENT_ENTRY_SIZE: u32 = 24;
const GROUP_ENTRY_SIZE: u32 = 48;
const BLOCK_DEVICE_ENTRY_SIZE: u32 = 64;

/// Partition, group and block device names (`char name[36]`).
const NAME_SIZE: usize = 36;

/// `LP_SECTOR_SIZE`: extents and `first_logical_sector` count 512-byte
/// sectors.
const LP_SECTOR_SIZE: u64 = 512;

/// Extent target types (`LP_TARGET_TYPE_*`).
const LP_TARGET_TYPE_LINEAR: u32 = 0;
const LP_TARGET_TYPE_ZERO: u32 = 1;

/// Partition attributes (`LP_PARTITION_ATTR_*`) and the masks for
/// metadata versions 10.0 and 10.1+.
const LP_PARTITION_ATTR_READONLY: u32 = 1 << 0;
const LP_PARTITION_ATTR_SLOT_SUFFIXED: u32 = 1 << 1;
const LP_PARTITION_ATTR_UPDATED: u32 = 1 << 2;
const LP_PARTITION_ATTR_DISABLED: u32 = 1 << 3;
const LP_PARTITION_ATTRIBUTE_MASK_V0: u32 =
    LP_PARTITION_ATTR_READONLY | LP_PARTITION_ATTR_SLOT_SUFFIXED;
const LP_PARTITION_ATTRIBUTE_MASK_V1: u32 = LP_PARTITION_ATTR_UPDATED | LP_PARTITION_ATTR_DISABLED;

/// Attribute names, in bit order.
const ATTRIBUTE_NAMES: [(u32, &str); 4] = [
    (LP_PARTITION_ATTR_READONLY, "readonly"),
    (LP_PARTITION_ATTR_SLOT_SUFFIXED, "slot-suffixed"),
    (LP_PARTITION_ATTR_UPDATED, "updated"),
    (LP_PARTITION_ATTR_DISABLED, "disabled"),
];

/// Header flags (`LP_HEADER_FLAG_*`, version 10.2).
const LP_HEADER_FLAG_VIRTUAL_AB_DEVICE: u32 = 0x1;
const LP_HEADER_FLAG_OVERLAYS_ACTIVE: u32 = 0x2;

/// Bytes at the start of an assembled partition read to decide whether it
/// is a recognized format.
const RECOGNITION_PREFIX: usize = 4096;

/// Transform name for partitions assembled from several extents.
const TRANSFORM: &str = "LP extents";

/// Most extent references followed across all partitions. liblp lets
/// partitions share extents, so without a bound a small table could make
/// the parser visit every extent once per partition.
const MAX_EXTENT_VISITS: u64 = 1 << 20;

/// Where the geometry and the metadata are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImageKind {
    /// A whole `super` block device (`ImageBuilder`).
    Full,
    /// Geometry at 0 and one metadata copy at 4096 (`super_empty.img`).
    Empty,
}

/// `LpMetadataGeometry` after `ParseGeometry`.
struct Geometry {
    /// Bytes reserved for one metadata copy.
    metadata_max_size: u32,
    metadata_slot_count: u32,
    logical_block_size: u32,
}

/// `LpMetadataTableDescriptor`: `offset` from the end of the header,
/// `num_entries` and `entry_size`.
#[derive(Debug, Clone, Copy)]
struct Table {
    offset: u32,
    num_entries: u32,
    entry_size: u32,
}

/// `LpMetadataHeader` fields the reader uses.
struct Header {
    minor_version: u16,
    /// `header_size`.
    size: usize,
    tables_size: u32,
    /// SHA-256 of the tables.
    tables_checksum: [u8; 32],
    partitions: Table,
    extents: Table,
    groups: Table,
    block_devices: Table,
    /// `flags`, version 10.2 only (0 before).
    flags: u32,
}

/// `LpMetadataPartition`.
struct Partition {
    name: String,
    attributes: u32,
    first_extent_index: u32,
    num_extents: u32,
    group_index: u32,
}

/// `LpMetadataExtent`: `num_sectors`, then the dm-linear sector and block
/// device index, or zeros for dm-zero.
#[derive(Debug, Clone, Copy)]
struct Extent {
    num_sectors: u64,
    target_type: u32,
    target_data: u64,
    target_source: u32,
}

/// `LpMetadataPartitionGroup`.
struct Group {
    name: String,
    /// Maximum size in bytes; 0 is unlimited.
    maximum_size: u64,
}

/// `LpMetadataBlockDevice`.
struct BlockDevice {
    first_logical_sector: u64,
    /// Size in bytes.
    size: u64,
    partition_name: String,
}

/// One metadata copy after `ParseMetadata`.
struct Metadata {
    header: Header,
    /// File offset of the header.
    offset: usize,
    partitions: Vec<Partition>,
    extents: Vec<Extent>,
    groups: Vec<Group>,
    block_devices: Vec<BlockDevice>,
}

impl Metadata {
    /// The leading partitions whose extents add up to at most
    /// [`MAX_EXTENT_VISITS`].
    fn examined_partitions(&self) -> &[Partition] {
        let mut visits = 0u64;
        let mut count = 0;
        for partition in &self.partitions {
            visits += u64::from(partition.num_extents);
            if visits > MAX_EXTENT_VISITS {
                break;
            }
            count += 1;
        }
        &self.partitions[..count]
    }

    /// Bytes from the header's start to the end of the tables.
    fn size(&self) -> usize {
        self.header.size + self.header.tables_size as usize
    }

    /// The extents of `partition`, which `parse_metadata` has bounded.
    fn extents_of(&self, partition: &Partition) -> &[Extent] {
        let first = partition.first_extent_index as usize;
        &self.extents[first..first + partition.num_extents as usize]
    }
}

fn sha256_matches(bytes: &[u8], stored: &[u8]) -> bool {
    Sha256::digest(bytes).as_slice() == stored
}

/// `ParseGeometry` on the 4096-byte geometry block at `at`: magic,
/// `struct_size` (4), SHA-256 `checksum` (8), `metadata_max_size` (40),
/// `metadata_slot_count` (44), `logical_block_size` (48).
fn parse_geometry(data: &[u8], at: usize) -> Result<Geometry> {
    let block = slice(data, at, LP_METADATA_GEOMETRY_SIZE, "LP geometry")?;
    if le_u32(block, 0)? != LP_METADATA_GEOMETRY_MAGIC {
        return Err(error(format!("Missing LP geometry magic at 0x{at:X}")));
    }
    // liblp checksums `struct_size` bytes, so a larger struct than it knows
    // is refused before the checksum and a smaller one after it.
    let struct_size = le_u32(block, 4)? as usize;
    if struct_size > GEOMETRY_STRUCT_SIZE {
        return Err(error(format!(
            "Unsupported LP geometry at 0x{at:X}: struct_size {struct_size} B"
        )));
    }
    let mut copy = block[..GEOMETRY_STRUCT_SIZE].to_vec();
    copy[GEOMETRY_CHECKSUM].fill(0);
    if !sha256_matches(&copy[..struct_size], &block[GEOMETRY_CHECKSUM]) {
        return Err(error(format!("Invalid LP geometry checksum at 0x{at:X}")));
    }
    if struct_size != GEOMETRY_STRUCT_SIZE {
        return Err(error(format!(
            "Invalid LP geometry at 0x{at:X}: struct_size {struct_size} B"
        )));
    }
    let geometry = Geometry {
        metadata_max_size: le_u32(block, 40)?,
        metadata_slot_count: le_u32(block, 44)?,
        logical_block_size: le_u32(block, 48)?,
    };
    if geometry.metadata_slot_count == 0 {
        return Err(error(format!(
            "Invalid LP geometry at 0x{at:X}: metadata_slot_count is 0"
        )));
    }
    if u64::from(geometry.metadata_max_size) % LP_SECTOR_SIZE != 0 {
        return Err(error(format!(
            "Invalid LP geometry at 0x{at:X}: metadata_max_size {} B is not a multiple of 512",
            geometry.metadata_max_size
        )));
    }
    Ok(geometry)
}

/// A table descriptor at `at`: offset, entry count, entry size.
fn table(header: &[u8], at: usize) -> Result<Table> {
    Ok(Table {
        offset: le_u32(header, at)?,
        num_entries: le_u32(header, at + 4)?,
        entry_size: le_u32(header, at + 8)?,
    })
}

/// `ValidateTableBounds`: the table lies inside `tables_size`.
fn is_in_tables(table: Table, tables_size: u32) -> bool {
    let size = u64::from(table.num_entries) * u64::from(table.entry_size);
    table.offset <= tables_size && u64::from(tables_size - table.offset) >= size
}

/// `ReadMetadataHeader`: magic, major and minor version (4, 6),
/// `header_size` (8), SHA-256 `header_checksum` (12), `tables_size` (44),
/// `tables_checksum` (48), four table descriptors (80, 92, 104, 116) and,
/// from version 10.2, `flags` (128).
fn parse_header(data: &[u8], at: usize) -> Result<Header> {
    let fixed = slice(data, at, HEADER_V1_0_SIZE, "LP metadata header")?;
    if le_u32(fixed, 0)? != LP_METADATA_HEADER_MAGIC {
        return Err(error(format!(
            "Missing LP metadata header magic at 0x{at:X}"
        )));
    }
    let major = le_u16(fixed, 4)?;
    let minor = le_u16(fixed, 6)?;
    if major != LP_METADATA_MAJOR_VERSION || minor > LP_METADATA_MINOR_VERSION_MAX {
        return Err(error(format!(
            "Unsupported LP metadata version {major}.{minor} at 0x{at:X}"
        )));
    }
    let expected_size = if minor < LP_METADATA_VERSION_FOR_EXPANDED_HEADER {
        HEADER_V1_0_SIZE
    } else {
        HEADER_V1_2_SIZE
    };
    let header_size = le_u32(fixed, 8)? as usize;
    if header_size != expected_size {
        return Err(error(format!(
            "Invalid LP metadata header size {header_size} B for version {major}.{minor} at 0x{at:X}"
        )));
    }
    let bytes = slice(data, at, header_size, "LP metadata header")?;
    let mut copy = bytes.to_vec();
    copy[HEADER_CHECKSUM].fill(0);
    if !sha256_matches(&copy, &bytes[HEADER_CHECKSUM]) {
        return Err(error(format!(
            "Invalid LP metadata header checksum at 0x{at:X}"
        )));
    }
    let header = Header {
        minor_version: minor,
        size: header_size,
        tables_size: le_u32(bytes, 44)?,
        tables_checksum: field(bytes, 48)?,
        partitions: table(bytes, 80)?,
        extents: table(bytes, 92)?,
        groups: table(bytes, 104)?,
        block_devices: table(bytes, 116)?,
        flags: if header_size == HEADER_V1_2_SIZE {
            le_u32(bytes, 128)?
        } else {
            0
        },
    };
    let tables = [
        header.partitions,
        header.extents,
        header.groups,
        header.block_devices,
    ];
    if !tables.iter().all(|&t| is_in_tables(t, header.tables_size)) {
        return Err(error(format!(
            "Invalid LP metadata at 0x{at:X}: a table exceeds tables_size {} B",
            header.tables_size
        )));
    }
    let entry_sizes = [
        (header.partitions, PARTITION_ENTRY_SIZE, "partition"),
        (header.extents, EXTENT_ENTRY_SIZE, "extent"),
        (header.groups, GROUP_ENTRY_SIZE, "group"),
    ];
    for (t, expected, what) in entry_sizes {
        if t.entry_size != expected {
            return Err(error(format!(
                "Invalid LP {what} table entry size {} B at 0x{at:X}",
                t.entry_size
            )));
        }
    }
    // liblp reads 64 bytes per block device at a stride of `entry_size`
    // and does not check it; a smaller stride would read past the entry.
    if header.block_devices.entry_size < BLOCK_DEVICE_ENTRY_SIZE {
        return Err(error(format!(
            "Invalid LP block device table entry size {} B at 0x{at:X}",
            header.block_devices.entry_size
        )));
    }
    Ok(header)
}

/// The entries of `table` in `tables`, which [`is_in_tables`] has bounded.
fn entries(tables: &[u8], table: Table) -> impl Iterator<Item = &[u8]> {
    let stride = table.entry_size as usize;
    let start = table.offset as usize;
    (0..table.num_entries as usize).map(move |i| &tables[start + i * stride..][..stride])
}

/// `ParseMetadata` for the copy at `at`: the header, the tables and their
/// SHA-256, then the partition, extent, group and block device entries.
fn parse_metadata(data: &[u8], at: usize, geometry: &Geometry) -> Result<Metadata> {
    let header = parse_header(data, at)?;
    if header.tables_size > geometry.metadata_max_size {
        return Err(error(format!(
            "Invalid LP metadata at 0x{at:X}: tables_size {} B exceeds metadata_max_size {} B",
            header.tables_size, geometry.metadata_max_size
        )));
    }
    let tables_at = at + header.size;
    let tables = slice(
        data,
        tables_at,
        header.tables_size as usize,
        "LP metadata tables",
    )?;
    if !sha256_matches(tables, &header.tables_checksum) {
        return Err(error(format!(
            "Invalid LP metadata tables checksum at 0x{tables_at:X}"
        )));
    }
    let mut valid_attributes = LP_PARTITION_ATTRIBUTE_MASK_V0;
    if header.minor_version >= LP_METADATA_VERSION_FOR_UPDATED_ATTR {
        valid_attributes |= LP_PARTITION_ATTRIBUTE_MASK_V1;
    }
    let mut partitions = Vec::with_capacity(header.partitions.num_entries as usize);
    for (i, entry) in entries(tables, header.partitions).enumerate() {
        let partition = Partition {
            name: asciiz(&entry[..NAME_SIZE]),
            attributes: le_u32(entry, 36)?,
            first_extent_index: le_u32(entry, 40)?,
            num_extents: le_u32(entry, 44)?,
            group_index: le_u32(entry, 48)?,
        };
        if partition.attributes & !valid_attributes != 0 {
            return Err(error(format!(
                "Invalid LP partition {i} attributes 0x{:X}",
                partition.attributes
            )));
        }
        let extents_end = partition
            .first_extent_index
            .checked_add(partition.num_extents)
            .ok_or_else(|| error(format!("Invalid LP partition {i}: extent range overflows")))?;
        if extents_end > header.extents.num_entries {
            return Err(error(format!(
                "Invalid LP partition {i}: extents {}..{extents_end} beyond the {} in the table",
                partition.first_extent_index, header.extents.num_entries
            )));
        }
        if partition.group_index >= header.groups.num_entries {
            return Err(error(format!(
                "Invalid LP partition {i}: group index {} beyond the {} groups",
                partition.group_index, header.groups.num_entries
            )));
        }
        partitions.push(partition);
    }
    let mut extents = Vec::with_capacity(header.extents.num_entries as usize);
    for (i, entry) in entries(tables, header.extents).enumerate() {
        let extent = Extent {
            num_sectors: le_u64(entry, 0)?,
            target_type: le_u32(entry, 8)?,
            target_data: le_u64(entry, 12)?,
            target_source: le_u32(entry, 20)?,
        };
        if extent.target_type == LP_TARGET_TYPE_LINEAR
            && extent.target_source >= header.block_devices.num_entries
        {
            return Err(error(format!(
                "Invalid LP extent {i}: block device {} beyond the {} in the table",
                extent.target_source, header.block_devices.num_entries
            )));
        }
        extents.push(extent);
    }
    let mut groups = Vec::with_capacity(header.groups.num_entries as usize);
    for entry in entries(tables, header.groups) {
        groups.push(Group {
            name: asciiz(&entry[..NAME_SIZE]),
            maximum_size: le_u64(entry, 40)?,
        });
    }
    let mut block_devices = Vec::with_capacity(header.block_devices.num_entries as usize);
    for entry in entries(tables, header.block_devices) {
        block_devices.push(BlockDevice {
            first_logical_sector: le_u64(entry, 0)?,
            size: le_u64(entry, 16)?,
            partition_name: asciiz(&entry[24..24 + NAME_SIZE]),
        });
    }
    let Some(super_device) = block_devices.first() else {
        return Err(error(format!(
            "Missing LP super block device in the metadata at 0x{at:X}"
        )));
    };
    // `GetTotalMetadataSize`: the reserved bytes, both geometries and every
    // metadata copy must end before the first logical sector. The product
    // of two u32 values fits in u64; the sums saturate.
    let copies = u64::from(geometry.metadata_max_size) * u64::from(geometry.metadata_slot_count);
    let metadata_region = (LP_METADATA_GEOMETRY_SIZE as u64)
        .saturating_add(copies)
        .saturating_mul(2)
        .saturating_add(LP_PARTITION_RESERVED_BYTES as u64);
    let first_logical_byte = super_device
        .first_logical_sector
        .saturating_mul(LP_SECTOR_SIZE);
    if metadata_region > first_logical_byte {
        return Err(error(format!(
            "Invalid LP metadata at 0x{at:X}: the metadata region ({metadata_region} B) overlaps the first logical sector {}",
            super_device.first_logical_sector
        )));
    }
    Ok(Metadata {
        header,
        offset: at,
        partitions,
        extents,
        groups,
        block_devices,
    })
}

/// What the parser read: the geometry, slot 0 of the metadata, and the
/// copies that were used instead of damaged primaries.
struct Read {
    geometry: Geometry,
    metadata: Metadata,
    notes: Vec<String>,
}

/// The geometry and metadata slot 0, falling back to the backup copies as
/// `ReadLogicalPartitionGeometry` and `ReadMetadata` do.
fn read_full(data: &[u8]) -> Result<Read> {
    let mut notes = Vec::new();
    let geometry = match parse_geometry(data, LP_PARTITION_RESERVED_BYTES) {
        Ok(geometry) => geometry,
        Err(primary) => match parse_geometry(data, BACKUP_GEOMETRY_OFFSET) {
            Ok(geometry) => {
                notes.push(format!(
                    "Primary LP geometry not used ({}); the backup geometry at 0x{BACKUP_GEOMETRY_OFFSET:X} was read",
                    reason(&primary)
                ));
                geometry
            }
            Err(_) => return Err(primary),
        },
    };
    let max_size = u64::from(geometry.metadata_max_size);
    let backup = METADATA_OFFSET.saturating_add(max_size * u64::from(geometry.metadata_slot_count));
    let primary_at = usize::try_from(METADATA_OFFSET).expect("a small constant");
    let metadata = match parse_metadata(data, primary_at, &geometry) {
        Ok(metadata) => metadata,
        Err(primary) => {
            let Ok(backup_at) = usize::try_from(backup) else {
                return Err(primary);
            };
            match parse_metadata(data, backup_at, &geometry) {
                Ok(metadata) => {
                    notes.push(format!(
                        "Primary LP metadata slot 0 not used ({}); the backup copy at 0x{backup:X} was read",
                        reason(&primary)
                    ));
                    metadata
                }
                Err(_) => return Err(primary),
            }
        }
    };
    Ok(Read {
        geometry,
        metadata,
        notes,
    })
}

/// Parse a full `super` image or a `super_empty` image.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let kind = if data.get(..4) == Some(&LP_METADATA_GEOMETRY_MAGIC.to_le_bytes()[..]) {
        ImageKind::Empty
    } else {
        ImageKind::Full
    };
    let read = match kind {
        ImageKind::Full => read_full(data)?,
        ImageKind::Empty => {
            let geometry = parse_geometry(data, 0)?;
            let metadata = parse_metadata(data, LP_METADATA_GEOMETRY_SIZE, &geometry)?;
            Read {
                geometry,
                metadata,
                notes: Vec::new(),
            }
        }
    };
    let metadata = &read.metadata;
    let header = &metadata.header;
    let version = format!("{LP_METADATA_MAJOR_VERSION}.{}", header.minor_version);
    let variant = match kind {
        ImageKind::Full => format!("super image (LP metadata v{version})"),
        ImageKind::Empty => format!("super_empty image (LP metadata v{version})"),
    };
    let mut c = Container::new(FileFormat::AndroidSuper, variant, KEY_PREFIX);
    let device = &metadata.block_devices[0];
    c.notes.push(format!(
        "Logical partition metadata v{version}: {} in {} on {}; geometry, header and table SHA-256 checksums verified",
        counted(metadata.partitions.len(), "partition", "partitions"),
        counted(metadata.groups.len(), "group", "groups"),
        counted(metadata.block_devices.len(), "block device", "block devices"),
    ));
    c.notes.extend(read.notes.iter().cloned());
    let unexamined = metadata.partitions.len() - metadata.examined_partitions().len();
    if unexamined > 0 {
        c.notes.push(format!(
            "{} not examined: the partitions refer to more than {MAX_EXTENT_VISITS} extents",
            counted(unexamined, "partition was", "partitions were")
        ));
    }
    describe(&mut c, &read, kind);
    match kind {
        ImageKind::Full => {
            c.consumed =
                usize::try_from(device.size).map_or(data.len(), |size| size.min(data.len()));
            push_partitions(&mut c, data, metadata);
            push_device_coverage(&mut c, data, device);
        }
        ImageKind::Empty => {
            let end = metadata.offset + metadata.size();
            c.consumed = end;
            c.notes.push(
                "super_empty image: metadata only; partition contents are not in the file".into(),
            );
            let rest = &data[end..];
            if !is_padding(rest) {
                c.notes.push(format!(
                    "{} after the metadata are not described by it",
                    size_text(rest.len())
                ));
            }
        }
    }
    c.notes.push(
        "The metadata names no CPU; partition images are classified from their own bytes".into(),
    );
    Ok(c)
}

/// Metadata entries for the geometry, the header, groups, block devices
/// and partitions.
fn describe(c: &mut Container<'_>, read: &Read, kind: ImageKind) {
    let geometry = &read.geometry;
    let metadata = &read.metadata;
    let header = &metadata.header;
    if header.flags & LP_HEADER_FLAG_VIRTUAL_AB_DEVICE != 0 {
        c.notes.push("Header flag: Virtual A/B device".into());
    }
    if header.flags & LP_HEADER_FLAG_OVERLAYS_ACTIVE != 0 {
        c.notes
            .push("Header flag: overlays active (adb remount)".into());
    }
    if kind == ImageKind::Full && geometry.metadata_slot_count > 1 {
        c.notes.push(format!(
            "{} metadata slots; slot 0 was read, the other slots were not compared",
            geometry.metadata_slot_count
        ));
    }
    c.push_metadata(
        "android_super_metadata_version",
        "LP metadata version",
        format!("{LP_METADATA_MAJOR_VERSION}.{}", header.minor_version),
    );
    c.push_metadata(
        "android_super_metadata_offset",
        "Metadata offset",
        MetadataValue::Address(metadata.offset as u64),
    );
    c.push_metadata(
        "android_super_metadata_max_size",
        "Metadata max size (B)",
        u64::from(geometry.metadata_max_size),
    );
    c.push_metadata(
        "android_super_metadata_slot_count",
        "Metadata slots",
        u64::from(geometry.metadata_slot_count),
    );
    c.push_metadata(
        "android_super_logical_block_size",
        "Logical block size (B)",
        u64::from(geometry.logical_block_size),
    );
    for (i, device) in metadata.block_devices.iter().enumerate() {
        c.push_metadata(
            format!("android_super_block_device_{i}"),
            format!("Block device {i}"),
            format!(
                "{}: {} B; first logical sector {}",
                device.partition_name, device.size, device.first_logical_sector
            ),
        );
    }
    for (i, group) in metadata.groups.iter().enumerate() {
        let limit = if group.maximum_size == 0 {
            "no maximum size".to_string()
        } else {
            format!("maximum size {} B", group.maximum_size)
        };
        c.push_metadata(
            format!("android_super_group_{i}"),
            format!("Group {i}"),
            format!("{}: {limit}", group.name),
        );
    }
    for (i, partition) in metadata.examined_partitions().iter().enumerate() {
        c.push_metadata(
            format!("android_super_partition_{i}"),
            format!("Partition {i}"),
            partition_summary(metadata, partition),
        );
    }
}

/// `name: group g; n extents (l linear, z zero); size B; attributes`.
fn partition_summary(metadata: &Metadata, partition: &Partition) -> String {
    let extents = metadata.extents_of(partition);
    let zero = extents
        .iter()
        .filter(|e| e.target_type == LP_TARGET_TYPE_ZERO)
        .count();
    let linear = extents
        .iter()
        .filter(|e| e.target_type == LP_TARGET_TYPE_LINEAR)
        .count();
    let size =
        partition_size(extents).map_or_else(|| "size overflows".to_string(), |s| format!("{s} B"));
    let group = &metadata.groups[partition.group_index as usize].name;
    let attributes: Vec<&str> = ATTRIBUTE_NAMES
        .iter()
        .filter(|(bit, _)| partition.attributes & bit != 0)
        .map(|&(_, name)| name)
        .collect();
    let attributes = if attributes.is_empty() {
        "no attributes".to_string()
    } else {
        attributes.join(", ")
    };
    format!(
        "{}: group {group}; {} ({linear} linear, {zero} zero); {size}; {attributes}",
        display_name(partition),
        counted(extents.len(), "extent", "extents")
    )
}

/// The partition name, or a placeholder for an empty one.
fn display_name(partition: &Partition) -> String {
    if partition.name.is_empty() {
        "(unnamed)".to_string()
    } else {
        partition.name.clone()
    }
}

/// Total size of `extents` in bytes.
fn partition_size(extents: &[Extent]) -> Option<u64> {
    extents.iter().try_fold(0u64, |size, e| {
        e.num_sectors
            .checked_mul(LP_SECTOR_SIZE)
            .and_then(|bytes| size.checked_add(bytes))
    })
}

/// Where one extent's bytes come from.
enum Source<'a> {
    /// Stored at a file offset.
    Stored { offset: usize, bytes: &'a [u8] },
    /// dm-zero.
    Zero { size: u64 },
}

/// Why a partition is not extracted.
enum Unmapped {
    /// An extent lies on another block device.
    OtherDevice(u32),
    /// A linear extent ends beyond the file.
    BeyondFile { end: u64 },
    /// An extent has a target type liblp does not define.
    UnknownTarget(u32),
    /// The size does not fit in 64 bits.
    Overflow,
}

/// The sources of `extents`, when every byte is in this file.
fn sources<'a>(
    data: &'a [u8],
    extents: &[Extent],
) -> std::result::Result<Vec<Source<'a>>, Unmapped> {
    let mut out = Vec::with_capacity(extents.len());
    for extent in extents {
        let size = extent
            .num_sectors
            .checked_mul(LP_SECTOR_SIZE)
            .ok_or(Unmapped::Overflow)?;
        match extent.target_type {
            LP_TARGET_TYPE_LINEAR => {
                if extent.target_source != 0 {
                    return Err(Unmapped::OtherDevice(extent.target_source));
                }
                let start = extent
                    .target_data
                    .checked_mul(LP_SECTOR_SIZE)
                    .ok_or(Unmapped::Overflow)?;
                let end = start.checked_add(size).ok_or(Unmapped::Overflow)?;
                let bytes = slice64(data, start, size, "LP extent")
                    .map_err(|_| Unmapped::BeyondFile { end })?;
                let offset = usize::try_from(start).expect("the extent lies in the file");
                out.push(Source::Stored { offset, bytes });
            }
            LP_TARGET_TYPE_ZERO => out.push(Source::Zero { size }),
            other => return Err(Unmapped::UnknownTarget(other)),
        }
    }
    Ok(out)
}

/// The first `limit` bytes of the concatenated `sources`.
fn assemble(sources: &[Source<'_>], limit: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(limit);
    for source in sources {
        let room = limit - out.len();
        if room == 0 {
            break;
        }
        match source {
            Source::Stored { bytes, .. } => out.extend_from_slice(&bytes[..bytes.len().min(room)]),
            Source::Zero { size } => {
                let zeros = usize::try_from(*size).map_or(room, |size| size.min(room));
                out.resize(out.len() + zeros, 0);
            }
        }
    }
    out
}

/// Members for the partitions whose extents are in the file and that hold
/// a recognized format.
fn push_partitions<'a>(c: &mut Container<'a>, data: &'a [u8], metadata: &Metadata) {
    let mut budget = Budget::new();
    let partitions = metadata.examined_partitions();
    let total = partitions.len();
    for partition in partitions {
        if is_component_limit(c.children.len(), total, &mut c.notes) {
            break;
        }
        let name = display_name(partition);
        let extents = metadata.extents_of(partition);
        if extents.is_empty() {
            c.notes
                .push(format!("{name}: no extents (empty partition)"));
            continue;
        }
        let sources = match sources(data, extents) {
            Ok(sources) => sources,
            Err(unmapped) => {
                c.notes
                    .push(unmapped_note(&name, &unmapped, metadata, data.len()));
                continue;
            }
        };
        let zero_extents = extents
            .iter()
            .filter(|e| e.target_type == LP_TARGET_TYPE_ZERO)
            .count();
        if zero_extents > 0 {
            c.notes.push(format!(
                "{name}: {} filled with zeros",
                counted(zero_extents, "zero extent", "zero extents")
            ));
        }
        if let [Source::Stored { offset, bytes }] = sources.as_slice() {
            c.children
                .push(Child::stored(name, *offset, bytes).if_recognized());
            continue;
        }
        push_assembled(c, &name, &sources, &mut budget);
    }
}

/// A partition of several extents (or a dm-zero one): assembled into one
/// image when it starts with a recognized format and the limits allow.
fn push_assembled<'a>(
    c: &mut Container<'a>,
    name: &str,
    sources: &[Source<'a>],
    budget: &mut Budget,
) {
    let size = sources.iter().fold(0u64, |size, source| match source {
        Source::Stored { bytes, .. } => size.saturating_add(bytes.len() as u64),
        Source::Zero { size: zeros } => size.saturating_add(*zeros),
    });
    let prefix_len = usize::try_from(size.min(RECOGNITION_PREFIX as u64))
        .expect("at most the recognition prefix");
    if !container::is_recognized(&assemble(sources, prefix_len)) {
        return;
    }
    let Some(size) = usize::try_from(size)
        .ok()
        .filter(|&size| size <= budget.limit())
    else {
        c.notes.push(format!(
            "{name}: {size} B in {} extents not assembled; the per-component limit is {} and {} of the {} extraction limit remain",
            sources.len(),
            size_text(MAX_PAYLOAD),
            size_text(budget.limit()),
            size_text(MAX_EXTRACTED)
        ));
        return;
    };
    let image = assemble(sources, size);
    budget.spend(size);
    // Stored coordinates are those of the first stored extent.
    let (offset, stored_size) = sources
        .iter()
        .find_map(|source| match source {
            Source::Stored { offset, bytes } => Some((*offset, bytes.len())),
            Source::Zero { .. } => None,
        })
        .unwrap_or((0, 0));
    c.notes.push(format!(
        "{name}: {} assembled into one {} image",
        counted(sources.len(), "extent", "extents"),
        size_text(size)
    ));
    c.children.push(
        Child::decoded(name, offset, stored_size, Cow::Owned(image), TRANSFORM).if_recognized(),
    );
}

/// Why a partition was not extracted.
fn unmapped_note(name: &str, unmapped: &Unmapped, metadata: &Metadata, file_size: usize) -> String {
    match unmapped {
        Unmapped::OtherDevice(index) => {
            let device = metadata
                .block_devices
                .get(*index as usize)
                .map_or("?", |d| d.partition_name.as_str());
            format!(
                "{name}: an extent lies on block device {index} ({device}), which is not in this file; not extracted"
            )
        }
        Unmapped::BeyondFile { end } => format!(
            "{name}: extents end at 0x{end:X}, beyond the {file_size} B in the file; not extracted"
        ),
        Unmapped::UnknownTarget(kind) => {
            format!("{name}: unknown extent target type {kind}; not extracted")
        }
        Unmapped::Overflow => format!("{name}: extent size overflows; not extracted"),
    }
}

/// Notes on how the file covers block device 0 (`ImageBuilder` writes the
/// whole device).
fn push_device_coverage(c: &mut Container<'_>, data: &[u8], device: &BlockDevice) {
    let file_size = data.len() as u64;
    if file_size < device.size {
        c.notes.push(format!(
            "The file holds {file_size} B of the {} B of block device {}",
            device.size, device.partition_name
        ));
        return;
    }
    let end = usize::try_from(device.size).expect("at most the file size");
    let rest = &data[end..];
    if !is_padding(rest) {
        c.notes.push(format!(
            "{} after block device {} are not described by the metadata",
            size_text(rest.len()),
            device.partition_name
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_bounds_use_64_bit_sizes() {
        let table = Table {
            offset: 8,
            num_entries: 0x1_0000,
            entry_size: 0x1_0000,
        };
        assert!(!is_in_tables(table, u32::MAX));
        let fits = Table {
            offset: 8,
            num_entries: 2,
            entry_size: 24,
        };
        assert!(is_in_tables(fits, 56));
        assert!(!is_in_tables(fits, 55));
        assert!(!is_in_tables(Table { offset: 57, ..fits }, 56));
    }

    #[test]
    fn assembly_concatenates_stored_and_zero_extents_up_to_the_limit() {
        let stored = [1u8, 2, 3, 4];
        let sources = [
            Source::Stored {
                offset: 0,
                bytes: &stored,
            },
            Source::Zero { size: 3 },
            Source::Stored {
                offset: 8,
                bytes: &stored[..2],
            },
        ];
        assert_eq!(assemble(&sources, 9), [1, 2, 3, 4, 0, 0, 0, 1, 2]);
        assert_eq!(assemble(&sources, 5), [1, 2, 3, 4, 0]);
        assert_eq!(partition_size(&[]), Some(0));
    }
}
