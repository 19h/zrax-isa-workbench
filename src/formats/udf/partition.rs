//! Partitions of the logical volume, by partition reference number, and the
//! mapping of their logical blocks to logical sectors of the volume:
//! physical (type 1) partitions (ECMA-167 3/10.7.2), sparable partitions
//! with their sparing table (UDF 2.60 2.2.9, 2.2.12), the metadata partition
//! read through the metadata file (2.2.10, 2.2.13) and virtual partitions
//! read through the virtual allocation table (2.2.8, 2.2.11; UDF 1.50
//! 2.2.10).

use super::entry::{DataSpace, Entry};
use super::text::{self, REGID_SIZE};
use super::volume::{Descriptors, MapRecord, PartitionDescriptor};
use super::*;

/// Partition type identifier of a sparing table (UDF 2.60 2.2.12).
const SPARING_TABLE_ID: &str = "*UDF Sparing Table";

/// Sparing table fields (UDF 2.60 2.2.12): sparing identifier (16, regid),
/// reallocation table length (48), sequence number (52), map entries (56,
/// 8 B each: original location, mapped location).
const SPARING_IDENTIFIER: usize = 16;
const SPARING_ENTRY_COUNT: usize = 48;
const SPARING_ENTRIES: usize = 56;
const SPARING_ENTRY_SIZE: usize = 8;

/// Original locations from this value up mark free, defective or reserved
/// entries (UDF 2.60 2.2.12).
const SPARING_UNUSED: u32 = 0xffff_fff0;

/// Largest sparing table read. Ours: Linux reads one block; UDF allows more
/// (2.2.12).
const MAX_SPARING_TABLE_SIZE: u32 = 1 << 20;

/// File types of the metadata file and its mirror (UDF 2.60 2.3.5.2).
const FILE_TYPE_METADATA: u8 = 250;
const FILE_TYPE_METADATA_MIRROR: u8 = 251;

/// File types of a 2.00 VAT (UDF 2.60 2.3.5.2) and of a 1.50 one, which is
/// "not specified" (UDF 1.50 2.2.10).
const FILE_TYPE_VAT: u8 = 248;
const FILE_TYPE_VAT_150: u8 = 0;

/// The UDF revision from which a virtual partition map names a 2.00 VAT
/// (Linux `udf_load_logicalvol`).
const VAT_200_REVISION: u16 = 0x0200;

/// The entity identifier that ends a 1.50 VAT, followed by the previous VAT
/// ICB location (UDF 1.50 2.2.10).
const VAT_150_ID: &str = "*UDF Virtual Alloc Tbl";
const VAT_150_TRAILER: usize = REGID_SIZE + 4;

/// Offset of the header length in a 2.00 VAT, and the header length
/// without implementation use (UDF 2.60 2.2.11).
const VAT_HEADER_LENGTH: usize = 0;
const VAT_MIN_HEADER: usize = 152;

/// A VAT entry for a virtual block that is not in use (UDF 2.60 2.2.11).
const VAT_UNUSED: u32 = 0xffff_ffff;

/// The VAT ICB is the last recorded sector; Linux also looks up to three
/// sectors before the last one (`udf_find_vat_block`).
const VAT_SEARCH_SECTORS: u64 = 4;

/// The bytes of one block and their file offset.
#[derive(Debug, Clone, Copy)]
pub(super) struct BlockBytes<'a> {
    pub(super) bytes: &'a [u8],
    /// File offset of the block.
    pub(super) offset: usize,
}

/// Consecutive logical sectors of the volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SectorRun {
    /// First logical sector.
    pub(super) sector: u64,
    /// Number of sectors.
    pub(super) count: u64,
}

/// A partition descriptor's extent: blocks are its sectors.
#[derive(Debug, Clone, Copy)]
struct Extent {
    /// First logical sector.
    start: u32,
    /// Length in blocks.
    length: u32,
}

impl Extent {
    fn of(descriptor: &PartitionDescriptor) -> Self {
        Self {
            start: descriptor.start,
            length: descriptor.length,
        }
    }
}

/// A remapped packet of a sparable partition (UDF 2.60 2.2.12).
#[derive(Debug, Clone, Copy)]
struct Spare {
    /// Partition block of the packet's first block.
    original: u32,
    /// Logical sector of its replacement.
    mapped: u32,
}

/// Blocks of the metadata partition recorded in one extent of the metadata
/// file.
#[derive(Debug, Clone, Copy)]
struct MetadataExtent {
    /// First metadata partition block of the extent.
    first: u64,
    /// Number of blocks.
    count: u64,
    /// Block of the physical partition that holds the first one.
    block: u32,
}

/// How a partition's blocks map to sectors.
#[derive(Debug, Clone)]
enum Mapping {
    /// Block b is sector start + b.
    Physical(Extent),
    /// As physical, unless the sparing table relocates b's packet.
    Sparable {
        extent: Extent,
        /// Blocks per packet, a power of two.
        packet_length: u32,
        /// Remapped packets, by original location.
        spares: Vec<Spare>,
        /// Logical sector of the sparing table used, if one verified.
        table: Option<u64>,
    },
    /// Block b is block b of the metadata file, in partition `physical`.
    Metadata {
        physical: u16,
        extents: Vec<MetadataExtent>,
        /// Metadata partition size in blocks.
        blocks: u64,
        /// Whether the mirror file was read because the metadata file
        /// could not be.
        from_mirror: bool,
    },
    /// Block b is VAT entry b, a block of partition `physical`.
    Virtual {
        physical: u16,
        entries: Vec<u32>,
        /// Logical sector of the VAT ICB.
        icb: u64,
    },
    /// A map this reader cannot use, and why.
    Unusable(String),
}

/// One partition map with its mapping.
#[derive(Debug, Clone)]
struct Map {
    record: MapRecord,
    mapping: Mapping,
}

/// The partitions of the logical volume, by partition reference number.
#[derive(Debug, Clone)]
pub(super) struct Partitions {
    maps: Vec<Map>,
}

impl Partitions {
    /// Set up every partition map: physical and sparable partitions first,
    /// then the metadata and virtual partitions that are read through them.
    pub(super) fn build(disc: &Disc<'_>, descriptors: &Descriptors) -> Result<Self> {
        let volume = descriptors.primary_sequence_number();
        let mut partitions = Self {
            maps: descriptors
                .logical
                .maps
                .iter()
                .map(|record| Map {
                    record: record.clone(),
                    mapping: physical_mapping(disc, descriptors, record, volume),
                })
                .collect(),
        };
        for reference in 0..partitions.maps.len() {
            let record = partitions.maps[reference].record.clone();
            let mapping = match record {
                MapRecord::Metadata {
                    partition,
                    file,
                    mirror,
                    ..
                } => metadata_mapping(disc, &partitions, partition, file, mirror)?,
                MapRecord::Virtual {
                    partition,
                    revision,
                    ..
                } => virtual_mapping(disc, &partitions, partition, revision)?,
                _ => continue,
            };
            partitions.maps[reference].mapping = mapping;
        }
        Ok(partitions)
    }

    /// The logical sector of `address`.
    pub(super) fn sector(&self, address: Address) -> ReadResult<u64> {
        let reference = address.reference;
        let Some(map) = self.maps.get(usize::from(reference)) else {
            return invalid(format!(
                "Invalid partition reference {reference}: the logical volume has {} partition \
                 maps",
                self.maps.len()
            ));
        };
        let block = address.block;
        match &map.mapping {
            Mapping::Physical(extent) => physical_sector(*extent, address),
            Mapping::Sparable {
                extent,
                packet_length,
                spares,
                ..
            } => {
                physical_sector(*extent, address)?;
                let packet = block & !(packet_length - 1);
                match spares.binary_search_by_key(&packet, |spare| spare.original) {
                    Ok(index) => Ok(u64::from(spares[index].mapped) + u64::from(block - packet)),
                    Err(_) => physical_sector(*extent, address),
                }
            }
            Mapping::Metadata {
                physical,
                extents,
                blocks,
                ..
            } => {
                let index = u64::from(block);
                if index >= *blocks {
                    return invalid(format!(
                        "Invalid {address}: the metadata partition has {blocks} blocks"
                    ));
                }
                // Extents are in metadata block order.
                let following = extents.partition_point(|e| e.first <= index);
                let found = following
                    .checked_sub(1)
                    .map(|i| extents[i])
                    .filter(|e| index < e.first + e.count);
                let block = found.and_then(|e| {
                    let offset = u32::try_from(index - e.first).ok()?;
                    e.block.checked_add(offset)
                });
                let Some(block) = block else {
                    return invalid(format!(
                        "Invalid {address}: the metadata file does not record it"
                    ));
                };
                self.sector(Address {
                    block,
                    reference: *physical,
                })
            }
            Mapping::Virtual {
                physical, entries, ..
            } => match entries.get(block as usize) {
                Some(&VAT_UNUSED) => invalid(format!("Invalid {address}: the VAT marks it unused")),
                Some(&entry) => self.sector(Address {
                    block: entry,
                    reference: *physical,
                }),
                None => invalid(format!(
                    "Invalid {address}: the VAT has {} entries",
                    entries.len()
                )),
            },
            Mapping::Unusable(reason) => {
                invalid(format!("Unsupported partition {reference}: {reason}"))
            }
        }
    }

    /// The block at `address`, with its file offset.
    pub(super) fn descriptor<'a>(
        &self,
        disc: &Disc<'a>,
        address: Address,
    ) -> ReadResult<BlockBytes<'a>> {
        let sector = self.sector(address)?;
        let bytes = disc.sector(sector)?;
        Ok(BlockBytes {
            bytes,
            offset: disc.offset(sector).expect("a present sector has an offset"),
        })
    }

    /// Append the sector runs that hold `count` blocks from `address` to
    /// `runs`, merging runs that continue each other.
    pub(super) fn runs(
        &self,
        address: Address,
        count: u32,
        runs: &mut Vec<SectorRun>,
    ) -> ReadResult<()> {
        if count == 0 {
            return Ok(());
        }
        let Some(last) = address.block.checked_add(count - 1) else {
            return invalid(format!("Invalid extent: {count} blocks from {address}"));
        };
        if let Some(Mapping::Physical(extent)) = self
            .maps
            .get(usize::from(address.reference))
            .map(|map| &map.mapping)
        {
            physical_sector(
                *extent,
                Address {
                    block: last,
                    ..address
                },
            )?;
            push_run(runs, physical_sector(*extent, address)?, u64::from(count));
            return Ok(());
        }
        // Other partitions may map every block elsewhere.
        for block in address.block..=last {
            let sector = self.sector(Address { block, ..address })?;
            push_run(runs, sector, 1);
        }
        Ok(())
    }

    /// Notes and metadata for the partition maps.
    pub(super) fn describe(&self, c: &mut Container<'_>) {
        let listed: Vec<String> = self
            .maps
            .iter()
            .enumerate()
            .map(|(reference, map)| format!("{reference}: {}", map.record.kind_text()))
            .collect();
        c.notes
            .push(format!("Partition maps: {}", listed.join("; ")));
        for (reference, map) in self.maps.iter().enumerate() {
            if let Some(note) = mapping_note(reference, &map.mapping) {
                c.notes.push(note);
            }
        }
        let kinds: Vec<&str> = self
            .maps
            .iter()
            .map(|map| match map.record {
                MapRecord::Physical { .. } => "type 1",
                MapRecord::Virtual { .. } => "virtual",
                MapRecord::Sparable { .. } => "sparable",
                MapRecord::Metadata { .. } => "metadata",
                MapRecord::Unknown { .. } => "unknown",
            })
            .collect();
        c.push_metadata("udf_partition_maps", "Partition maps", kinds.join(", "));
    }
}

/// The sector of `address` in a physical partition's extent.
fn physical_sector(extent: Extent, address: Address) -> ReadResult<u64> {
    if address.block >= extent.length {
        return invalid(format!(
            "Invalid {address}: the partition has {} blocks",
            extent.length
        ));
    }
    Ok(u64::from(extent.start) + u64::from(address.block))
}

/// Append `count` sectors from `sector`, extending the last run when they
/// continue it.
fn push_run(runs: &mut Vec<SectorRun>, sector: u64, count: u64) {
    match runs.last_mut() {
        Some(last) if last.sector + last.count == sector => last.count += count,
        _ => runs.push(SectorRun { sector, count }),
    }
}

/// The note for a mapping that is not plain physical.
fn mapping_note(reference: usize, mapping: &Mapping) -> Option<String> {
    let note = match mapping {
        Mapping::Physical(_) => return None,
        Mapping::Sparable {
            spares,
            table: Some(sector),
            ..
        } => format!(
            "Partition {reference}: sparing table at sector {sector} relocates {} packets",
            spares.len()
        ),
        Mapping::Sparable { table: None, .. } => format!(
            "Partition {reference}: no sparing table verifies; blocks are read where the \
             partition places them"
        ),
        Mapping::Metadata {
            blocks,
            extents,
            from_mirror,
            ..
        } => format!(
            "Partition {reference}: metadata partition of {blocks} blocks in {} extents of the \
             metadata {}",
            extents.len(),
            if *from_mirror {
                "mirror file (the metadata file could not be read)"
            } else {
                "file"
            }
        ),
        Mapping::Virtual { entries, icb, .. } => format!(
            "Partition {reference}: virtual partition of {} blocks; VAT ICB at sector {icb}",
            entries.len()
        ),
        Mapping::Unusable(reason) => format!("Partition {reference} is not read: {reason}"),
    };
    Some(note)
}

/// The mapping of a physical or sparable map, or a placeholder for the
/// maps set up afterwards.
fn physical_mapping(
    disc: &Disc<'_>,
    descriptors: &Descriptors,
    record: &MapRecord,
    volume: u16,
) -> Mapping {
    // On a single volume every map names it, whatever volume sequence
    // number it records; Linux does not compare the numbers at all.
    let other_volume = record
        .volume()
        .filter(|&v| descriptors.is_volume_set() && v != volume);
    if let Some(other) = other_volume {
        return Mapping::Unusable(format!(
            "its partition is on volume {other} of the set, not this volume ({volume})"
        ));
    }
    let partition = match record {
        MapRecord::Physical { partition, .. } | MapRecord::Sparable { partition, .. } => *partition,
        MapRecord::Metadata { .. } | MapRecord::Virtual { .. } => {
            return Mapping::Unusable("not set up".to_string())
        }
        MapRecord::Unknown { description } => {
            return Mapping::Unusable(format!("{description} is not interpreted"))
        }
    };
    let Some(descriptor) = descriptors.partition(partition) else {
        return Mapping::Unusable(format!("no partition descriptor has number {partition}"));
    };
    if !descriptor.holds_file_structure() {
        return Mapping::Unusable(format!(
            "partition contents \"{}\" are not ECMA-167 Part 4",
            descriptor.contents.escape_debug()
        ));
    }
    let extent = Extent::of(descriptor);
    match record {
        MapRecord::Sparable {
            packet_length,
            table_size,
            tables,
            ..
        } => sparable_mapping(disc, extent, *packet_length, *table_size, tables),
        _ => Mapping::Physical(extent),
    }
}

/// A sparable partition with the first sparing table that verifies (Linux
/// `udf_load_sparable_map`).
fn sparable_mapping(
    disc: &Disc<'_>,
    extent: Extent,
    packet_length: u16,
    table_size: u32,
    tables: &[u32],
) -> Mapping {
    if !packet_length.is_power_of_two() {
        return Mapping::Unusable(format!(
            "packet length {packet_length} is not a power of two"
        ));
    }
    if table_size > MAX_SPARING_TABLE_SIZE {
        return Mapping::Unusable(format!(
            "sparing tables of {table_size} B exceed the {} read",
            size_text(MAX_SPARING_TABLE_SIZE as usize)
        ));
    }
    for &sector in tables {
        if let Ok(mut spares) = sparing_table(disc, u64::from(sector), table_size) {
            spares.sort_by_key(|spare| spare.original);
            return Mapping::Sparable {
                extent,
                packet_length: u32::from(packet_length),
                spares,
                table: Some(u64::from(sector)),
            };
        }
    }
    Mapping::Sparable {
        extent,
        packet_length: u32::from(packet_length),
        spares: Vec::new(),
        table: None,
    }
}

/// The remapped packets of the sparing table at `sector`, `size` bytes
/// long.
fn sparing_table(disc: &Disc<'_>, sector: u64, size: u32) -> Result<Vec<Spare>> {
    let sectors = blocks_for(u64::from(size), disc.sector_size as u64).max(1);
    let bytes = match disc.sectors(sector, sectors) {
        Ok(bytes) => &bytes[..(size as usize).max(SPARING_ENTRIES).min(bytes.len())],
        Err(_) => return Err(error("absent sparing table")),
    };
    let offset = disc.offset(sector).expect("a present sector has an offset");
    let location = u32::try_from(sector).map_err(|_| error("sparing table sector"))?;
    let tag = read_tag(bytes, offset, Some(location))?;
    expect_identifier(tag, TAG_SPARING_TABLE, "sparing table", offset)?;
    let identifier = text::regid_identifier(slice(bytes, SPARING_IDENTIFIER, REGID_SIZE)?);
    if identifier != SPARING_TABLE_ID {
        return Err(error(format!(
            "Invalid sparing table at 0x{offset:X}: identifier \"{}\"",
            identifier.escape_debug()
        )));
    }
    let count = usize::from(le_u16(bytes, SPARING_ENTRY_COUNT)?);
    let entries = slice(bytes, SPARING_ENTRIES, count * SPARING_ENTRY_SIZE)?;
    let mut spares = Vec::with_capacity(count);
    for entry in entries.chunks_exact(SPARING_ENTRY_SIZE) {
        let original = le_u32(entry, 0)?;
        // Entries are sorted by original location; free, defective and
        // reserved entries sort last (UDF 2.60 2.2.12).
        if original >= SPARING_UNUSED {
            break;
        }
        spares.push(Spare {
            original,
            mapped: le_u32(entry, 4)?,
        });
    }
    Ok(spares)
}

/// The physical or sparable map that a metadata or virtual map is read
/// through.
#[derive(Debug, Clone, Copy)]
struct Underlying {
    /// Its partition reference number.
    reference: u16,
    /// Its partition descriptor's extent.
    extent: Extent,
}

/// The physical or sparable map of partition number `partition`.
fn underlying(partitions: &Partitions, partition: u16) -> Result<Underlying> {
    for (reference, map) in partitions.maps.iter().enumerate() {
        let (MapRecord::Physical {
            partition: number, ..
        }
        | MapRecord::Sparable {
            partition: number, ..
        }) = map.record
        else {
            continue;
        };
        let (Mapping::Physical(extent) | Mapping::Sparable { extent, .. }) = map.mapping else {
            continue;
        };
        if number == partition {
            return Ok(Underlying {
                reference: u16::try_from(reference).expect("partition maps fit the map table"),
                extent,
            });
        }
    }
    Err(error(format!(
        "Missing physical partition map for partition {partition}"
    )))
}

/// The metadata partition, read through the metadata file or, when that
/// cannot be read, its mirror (Linux `udf_load_metadata_files`).
fn metadata_mapping(
    disc: &Disc<'_>,
    partitions: &Partitions,
    partition: u16,
    file: u32,
    mirror: u32,
) -> Result<Mapping> {
    let physical = underlying(partitions, partition)?.reference;
    let main = metadata_extents(disc, partitions, physical, file, FILE_TYPE_METADATA);
    let (extents, from_mirror) = match main {
        Ok(extents) => (extents, false),
        Err(main_problem) => {
            match metadata_extents(
                disc,
                partitions,
                physical,
                mirror,
                FILE_TYPE_METADATA_MIRROR,
            ) {
                Ok(extents) => (extents, true),
                Err(mirror_problem) => {
                    let what = |fault: Fault, block: u32| match fault {
                        Fault::Invalid(e) => message(e),
                        Fault::Absent => format!(
                            "the file entry at block {block} lies past the end of the {} input \
                             (truncated volume)",
                            disc.present_text()
                        ),
                    };
                    return Err(error(format!(
                        "Invalid metadata partition: metadata file: {}; mirror file: {}",
                        what(main_problem, file),
                        what(mirror_problem, mirror)
                    )));
                }
            }
        }
    };
    Ok(Mapping::Metadata {
        physical,
        blocks: extents.blocks,
        extents: extents.extents,
        from_mirror,
    })
}

/// The extents of a metadata file and the metadata partition's size.
struct MetadataLayout {
    extents: Vec<MetadataExtent>,
    blocks: u64,
}

/// Read the metadata file (or mirror) entry at block `block` of the
/// physical partition and the extents its allocation descriptors record.
fn metadata_extents(
    disc: &Disc<'_>,
    partitions: &Partitions,
    physical: u16,
    block: u32,
    file_type: u8,
) -> ReadResult<MetadataLayout> {
    let address = Address {
        block,
        reference: physical,
    };
    let entry = Entry::read(disc, partitions, address)?;
    if entry.file_type != file_type {
        return invalid(format!(
            "file entry at {address} has file type {}, expected {file_type}",
            entry.file_type
        ));
    }
    let DataSpace::Extents(extents) = &entry.data else {
        return invalid(format!(
            "file entry at {address} records its data in the entry, not in extents"
        ));
    };
    let block_size = disc.sector_size as u64;
    let mut layout = MetadataLayout {
        extents: Vec::with_capacity(extents.len()),
        blocks: blocks_for(entry.information_length, block_size),
    };
    let mut first = 0u64;
    for extent in extents {
        let count = blocks_for(u64::from(extent.length), block_size);
        if extent.recorded {
            if extent.address.reference != physical {
                return invalid(format!(
                    "metadata file extent at {} is outside the physical partition",
                    extent.address
                ));
            }
            layout.extents.push(MetadataExtent {
                first,
                count,
                block: extent.address.block,
            });
        }
        first += count;
    }
    Ok(layout)
}

/// The virtual partition, read through the VAT in the last recorded sector
/// of partition number `partition` (UDF 2.60 2.2.11; Linux
/// `udf_find_vat_block`, `udf_load_vat`).
fn virtual_mapping(
    disc: &Disc<'_>,
    partitions: &Partitions,
    partition: u16,
    revision: u16,
) -> Result<Mapping> {
    let Underlying {
        reference: physical,
        extent,
    } = underlying(partitions, partition)?;
    let last = (disc.data.len() / disc.sector_size) as u64;
    let mut problem = None;
    for back in 1..=VAT_SEARCH_SECTORS {
        let Some(sector) = last.checked_sub(back) else {
            break;
        };
        let Some(block) = sector
            .checked_sub(u64::from(extent.start))
            .and_then(|block| u32::try_from(block).ok())
            .filter(|&block| block < extent.length)
        else {
            continue;
        };
        let address = Address {
            block,
            reference: physical,
        };
        match read_vat(disc, partitions, address, revision) {
            Ok(entries) => {
                return Ok(Mapping::Virtual {
                    physical,
                    entries,
                    icb: sector,
                })
            }
            Err(Fault::Invalid(e)) => {
                problem.get_or_insert_with(|| message(e));
            }
            Err(Fault::Absent) => {}
        }
    }
    let detail = problem.map_or_else(String::new, |problem| format!(" ({problem})"));
    Err(error(format!(
        "Missing virtual allocation table: no VAT ICB in the last {VAT_SEARCH_SECTORS} sectors of \
         partition {partition}{detail}; the input may end before the last recorded sector"
    )))
}

/// The entries of the VAT whose ICB is at `address`: a 2.00 VAT (file type
/// 248, a header of `L_HD` bytes before the entries) or, for maps of UDF
/// revisions below 2.00, a 1.50 VAT (the entries, then the entity
/// identifier `*UDF Virtual Alloc Tbl` and the previous VAT ICB).
fn read_vat(
    disc: &Disc<'_>,
    partitions: &Partitions,
    address: Address,
    revision: u16,
) -> ReadResult<Vec<u32>> {
    let entry = Entry::read(disc, partitions, address)?;
    let expected_type = if revision >= VAT_200_REVISION {
        FILE_TYPE_VAT
    } else {
        FILE_TYPE_VAT_150
    };
    if entry.file_type != expected_type {
        return invalid(format!(
            "the entry at {address} has file type {}, not a VAT",
            entry.file_type
        ));
    }
    // Every entry addresses a block of the partition, so the table cannot
    // need more than four bytes per partition block.
    let data = super::entry::read_data(disc, partitions, &entry, MAX_PAYLOAD_VAT)?;
    let table = if revision >= VAT_200_REVISION {
        let header = usize::from(le_u16(&data, VAT_HEADER_LENGTH)?);
        if header < VAT_MIN_HEADER || header > data.len() {
            return invalid(format!(
                "VAT at {address} has a header of {header} B in {} B",
                data.len()
            ));
        }
        &data[header..]
    } else {
        let Some(end) = data.len().checked_sub(VAT_150_TRAILER) else {
            return invalid(format!("VAT at {address} is shorter than its trailer"));
        };
        let identifier = text::regid_identifier(&data[end..end + REGID_SIZE]);
        if identifier != VAT_150_ID {
            return invalid(format!(
                "VAT at {address} ends without the \"{VAT_150_ID}\" identifier"
            ));
        }
        &data[..end]
    };
    Ok(table
        .chunks_exact(4)
        .map(|entry| u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]))
        .collect())
}

/// Largest VAT read (ours): 4 MiB holds a million virtual blocks, more than
/// a CD-R or DVD-R has directories and file entries.
const MAX_PAYLOAD_VAT: usize = 4 << 20;

#[cfg(test)]
mod tests {
    use super::*;

    fn physical(start: u32, length: u32) -> Map {
        Map {
            record: MapRecord::Physical {
                volume: 1,
                partition: 0,
            },
            mapping: Mapping::Physical(Extent { start, length }),
        }
    }

    fn address(block: u32, reference: u16) -> Address {
        Address { block, reference }
    }

    #[test]
    fn physical_blocks_follow_the_partition_start() {
        let partitions = Partitions {
            maps: vec![physical(100, 10)],
        };
        assert_eq!(partitions.sector(address(3, 0)).ok(), Some(103));
        assert!(partitions.sector(address(10, 0)).is_err());
        assert!(partitions.sector(address(0, 1)).is_err());
        let mut runs = Vec::new();
        partitions
            .runs(address(2, 0), 4, &mut runs)
            .expect("inside");
        assert_eq!(
            runs,
            [SectorRun {
                sector: 102,
                count: 4
            }]
        );
        assert!(partitions.runs(address(8, 0), 4, &mut runs).is_err());
    }

    #[test]
    fn sparing_relocates_whole_packets() {
        let partitions = Partitions {
            maps: vec![Map {
                record: MapRecord::Physical {
                    volume: 1,
                    partition: 0,
                },
                mapping: Mapping::Sparable {
                    extent: Extent {
                        start: 100,
                        length: 64,
                    },
                    packet_length: 16,
                    spares: vec![Spare {
                        original: 16,
                        mapped: 5000,
                    }],
                    table: Some(90),
                },
            }],
        };
        assert_eq!(partitions.sector(address(15, 0)).ok(), Some(115));
        assert_eq!(partitions.sector(address(19, 0)).ok(), Some(5003));
        let mut runs = Vec::new();
        partitions
            .runs(address(14, 0), 4, &mut runs)
            .expect("inside");
        assert_eq!(
            runs,
            [
                SectorRun {
                    sector: 114,
                    count: 2
                },
                SectorRun {
                    sector: 5000,
                    count: 2
                }
            ]
        );
    }

    #[test]
    fn metadata_and_virtual_blocks_map_through_their_files() {
        let partitions = Partitions {
            maps: vec![
                physical(100, 1000),
                Map {
                    record: MapRecord::Metadata {
                        volume: 1,
                        partition: 0,
                        file: 1,
                        mirror: 2,
                        duplicated: false,
                    },
                    mapping: Mapping::Metadata {
                        physical: 0,
                        extents: vec![
                            MetadataExtent {
                                first: 0,
                                count: 4,
                                block: 40,
                            },
                            MetadataExtent {
                                first: 6,
                                count: 2,
                                block: 80,
                            },
                        ],
                        blocks: 8,
                        from_mirror: false,
                    },
                },
                Map {
                    record: MapRecord::Virtual {
                        volume: 1,
                        partition: 0,
                        revision: 0x0200,
                    },
                    mapping: Mapping::Virtual {
                        physical: 0,
                        entries: vec![7, VAT_UNUSED, 9],
                        icb: 1099,
                    },
                },
            ],
        };
        assert_eq!(partitions.sector(address(3, 1)).ok(), Some(143));
        assert_eq!(partitions.sector(address(7, 1)).ok(), Some(181));
        assert!(partitions.sector(address(4, 1)).is_err());
        assert!(partitions.sector(address(8, 1)).is_err());
        assert_eq!(partitions.sector(address(2, 2)).ok(), Some(109));
        assert!(partitions.sector(address(1, 2)).is_err());
        assert!(partitions.sector(address(3, 2)).is_err());
    }
}
