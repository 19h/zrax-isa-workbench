//! The volume descriptor sequence (ECMA-167 3/8.4): the prevailing primary
//! volume, partition and logical volume descriptors with the partition maps
//! (3/10.1, 3/10.5-10.7; UDF 2.60 2.2.8-2.2.10), the logical volume
//! integrity sequence (3/10.10; UDF 2.60 2.2.6), and the file set
//! descriptor (4/14.1; UDF 2.60 2.3.2).

use super::partition::Partitions;
use super::recognition::Anchor;
use super::text::{self, REGID_SIZE, REGID_SUFFIX};
use super::*;

/// Most sectors of descriptor sequences read, across all extents and
/// volume descriptor pointers. Ours: UDF sequences have 16 sectors or a few
/// more (UDF 2.60 2.2.3.1).
const MAX_SEQUENCE_SECTORS: u64 = 4096;

/// Most volume descriptor pointers followed (Linux `UDF_MAX_TD_NESTING`).
const MAX_POINTERS: usize = 64;

/// Most logical volume integrity descriptors read (ours; Linux follows up
/// to 1000 extents, `UDF_MAX_LVID_NESTING`).
const MAX_INTEGRITY_DESCRIPTORS: usize = 256;

/// Most blocks of the file set descriptor extent read (ours; UDF records one
/// file set descriptor, several only on write-once media).
const MAX_FILE_SET_BLOCKS: u32 = 256;

/// Partition descriptor fields (3/10.5 figure 3/11).
const PARTITION_FLAGS: usize = 20;
const PARTITION_NUMBER: usize = 22;
const PARTITION_CONTENTS: usize = 24;
const PARTITION_ACCESS: usize = 184;
const PARTITION_START: usize = 188;
const PARTITION_LENGTH: usize = 192;

/// Partition flag bit 0: volume space has been allocated (3/10.5.3).
const PARTITION_ALLOCATED: u16 = 0x0001;

/// Partition contents that ECMA-167 Part 4 interprets (3/10.5.5; `+NSR02`
/// for the 2nd edition).
const PART4_CONTENTS: [&str; 2] = ["+NSR02", "+NSR03"];

/// Logical volume descriptor fields (3/10.6 figure 3/15).
const LV_IDENTIFIER: usize = 84;
const LV_BLOCK_SIZE: usize = 212;
const LV_DOMAIN: usize = 216;
const LV_CONTENTS_USE: usize = 248;
const LV_MAP_TABLE_LENGTH: usize = 264;
const LV_MAP_COUNT: usize = 268;
const LV_INTEGRITY: usize = 432;
const LV_MAPS: usize = 440;

/// The OSTA domain identifier (UDF 2.60 2.1.5.2, 6.2).
const UDF_DOMAIN: &str = "*OSTA UDF Compliant";

/// Partition map types and their recorded lengths (3/10.7.2, 3/10.7.3).
const MAP_TYPE_1: u8 = 1;
const MAP_TYPE_2: u8 = 2;
const MAP_TYPE_1_LENGTH: usize = 6;
const MAP_TYPE_2_LENGTH: usize = 64;

/// Type 2 partition type identifiers (UDF 2.60 6.2).
const VIRTUAL_PARTITION: &str = "*UDF Virtual Partition";
const SPARABLE_PARTITION: &str = "*UDF Sparable Partition";
const METADATA_PARTITION: &str = "*UDF Metadata Partition";

/// Offsets in a UDF type 2 map (UDF 2.60 2.2.8-2.2.10): partition type
/// identifier (4, 32), volume sequence number (36), partition number (38).
const MAP2_IDENTIFIER: usize = 4;
const MAP2_VOLUME: usize = 36;
const MAP2_PARTITION: usize = 38;

/// Most sparing tables a sparable map lists (UDF 2.60 2.2.9).
const MAX_SPARING_TABLES: usize = 4;

/// Bit 0 of the metadata map flags: the mirror file has its own copy of
/// the metadata (UDF 2.60 2.2.10).
const DUPLICATE_METADATA: u8 = 0x01;

/// Logical volume integrity types (3/10.10.3).
const INTEGRITY_OPEN: u32 = 0;
const INTEGRITY_CLOSE: u32 = 1;

/// File set descriptor fields (4/14.1 figure 4/9).
const FILE_SET_NUMBER: usize = 40;
const FILE_SET_IDENTIFIER: usize = 304;
const FILE_SET_ROOT: usize = 400;
const FILE_SET_STREAMS: usize = 464;

/// Access types of a partition (3/10.5.7; UDF 2.60 2.2.14.2 names 0).
fn access_text(access: u32) -> &'static str {
    match access {
        0 => "pseudo-overwritable",
        1 => "read-only",
        2 => "write-once",
        3 => "rewritable",
        4 => "overwritable",
        _ => "of a reserved access type",
    }
}

/// The prevailing primary volume descriptor (3/10.1 figure 3/6).
#[derive(Debug, Clone)]
pub(super) struct Primary {
    /// Volume identifier (24, dstring of 32 B).
    identifier: String,
    /// Volume sequence number (56) and maximum (58).
    sequence_number: u16,
    max_sequence_number: u16,
    /// Volume set identifier (72, dstring of 128 B).
    set_identifier: String,
    /// Application identifier (344, regid).
    application: String,
    /// Recording date and time (376, timestamp).
    recorded: Option<String>,
    /// Implementation identifier (388, regid).
    implementation: String,
}

impl Primary {
    fn parse(descriptor: &[u8]) -> Result<Self> {
        Ok(Self {
            identifier: text::dstring(slice(descriptor, 24, 32)?),
            sequence_number: le_u16(descriptor, 56)?,
            max_sequence_number: le_u16(descriptor, 58)?,
            set_identifier: text::dstring(slice(descriptor, 72, 128)?),
            application: text::regid_identifier(slice(descriptor, 344, REGID_SIZE)?),
            recorded: text::timestamp_text(slice(descriptor, 376, text::TIMESTAMP_SIZE)?),
            implementation: text::regid_identifier(slice(descriptor, 388, REGID_SIZE)?),
        })
    }
}

/// A prevailing partition descriptor (3/10.5).
#[derive(Debug, Clone)]
pub(super) struct PartitionDescriptor {
    /// Partition number (22).
    pub(super) number: u16,
    /// Partition contents identifier (24, regid): `+NSR02`, `+NSR03`.
    pub(super) contents: String,
    /// Access type (184).
    pub(super) access: u32,
    /// First logical sector (188).
    pub(super) start: u32,
    /// Length in logical sectors (192).
    pub(super) length: u32,
    /// Partition flags bit 0: space allocated.
    allocated: bool,
}

impl PartitionDescriptor {
    fn parse(descriptor: &[u8]) -> Result<Self> {
        Ok(Self {
            number: le_u16(descriptor, PARTITION_NUMBER)?,
            contents: text::regid_identifier(slice(descriptor, PARTITION_CONTENTS, REGID_SIZE)?),
            access: le_u32(descriptor, PARTITION_ACCESS)?,
            start: le_u32(descriptor, PARTITION_START)?,
            length: le_u32(descriptor, PARTITION_LENGTH)?,
            allocated: le_u16(descriptor, PARTITION_FLAGS)? & PARTITION_ALLOCATED != 0,
        })
    }

    /// Whether ECMA-167 Part 4 interprets the partition's contents.
    pub(super) fn holds_file_structure(&self) -> bool {
        PART4_CONTENTS.contains(&self.contents.as_str())
    }
}

/// A partition map of the logical volume descriptor (3/10.7; UDF 2.60
/// 2.2.8-2.2.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MapRecord {
    /// Type 1: a partition of a volume of the set.
    Physical { volume: u16, partition: u16 },
    /// `*UDF Virtual Partition`, read through a VAT of the UDF revision in
    /// the identifier suffix.
    Virtual {
        volume: u16,
        partition: u16,
        revision: u16,
    },
    /// `*UDF Sparable Partition`: packet length in blocks (40), sparing
    /// table size in bytes (44) and the absolute sectors of the tables (48).
    Sparable {
        volume: u16,
        partition: u16,
        packet_length: u16,
        table_size: u32,
        tables: Vec<u32>,
    },
    /// `*UDF Metadata Partition`: the blocks of the metadata, mirror and
    /// bitmap file entries in the physical partition (40, 44, 48) and the
    /// flags (58).
    Metadata {
        volume: u16,
        partition: u16,
        file: u32,
        mirror: u32,
        duplicated: bool,
    },
    /// A map this reader does not interpret.
    Unknown { description: String },
}

impl MapRecord {
    /// Parse the map at `at` in the map table `table`.
    fn parse(table: &[u8], at: usize, kind: u8) -> Result<Self> {
        if kind == MAP_TYPE_1 {
            return Ok(Self::Physical {
                volume: le_u16(table, at + 2)?,
                partition: le_u16(table, at + 4)?,
            });
        }
        if kind != MAP_TYPE_2 {
            return Ok(Self::Unknown {
                description: format!("partition map type {kind}"),
            });
        }
        let regid = slice(table, at + MAP2_IDENTIFIER, REGID_SIZE)?;
        let identifier = text::regid_identifier(regid);
        let volume = le_u16(table, at + MAP2_VOLUME)?;
        let partition = le_u16(table, at + MAP2_PARTITION)?;
        let record = match identifier.as_str() {
            VIRTUAL_PARTITION => Self::Virtual {
                volume,
                partition,
                revision: le_u16(regid, REGID_SUFFIX)?,
            },
            SPARABLE_PARTITION => {
                let count = usize::from(byte(table, at + 42)?);
                if !(1..=MAX_SPARING_TABLES).contains(&count) {
                    return Err(error(format!(
                        "Invalid sparable partition map: {count} sparing tables (1 to \
                         {MAX_SPARING_TABLES} allowed)"
                    )));
                }
                let tables = (0..count)
                    .map(|i| le_u32(table, at + 48 + 4 * i))
                    .collect::<Result<Vec<u32>>>()?;
                Self::Sparable {
                    volume,
                    partition,
                    packet_length: le_u16(table, at + 40)?,
                    table_size: le_u32(table, at + 44)?,
                    tables,
                }
            }
            METADATA_PARTITION => Self::Metadata {
                volume,
                partition,
                file: le_u32(table, at + 40)?,
                mirror: le_u32(table, at + 44)?,
                duplicated: byte(table, at + 58)? & DUPLICATE_METADATA != 0,
            },
            other => Self::Unknown {
                description: format!("type 2 partition map \"{}\"", other.escape_debug()),
            },
        };
        Ok(record)
    }

    /// Short description for notes and metadata.
    pub(super) fn kind_text(&self) -> String {
        match self {
            Self::Physical { partition, .. } => format!("type 1 (partition {partition})"),
            Self::Virtual {
                partition,
                revision,
                ..
            } => format!(
                "virtual (partition {partition}, VAT of UDF {})",
                text::revision_text(*revision)
            ),
            Self::Sparable {
                partition,
                packet_length,
                tables,
                ..
            } => format!(
                "sparable (partition {partition}, packets of {packet_length} blocks, {} sparing \
                 tables)",
                tables.len()
            ),
            Self::Metadata {
                partition,
                file,
                mirror,
                duplicated,
                ..
            } => format!(
                "metadata (partition {partition}; metadata file at block {file}, mirror at block \
                 {mirror}{})",
                if *duplicated { ", duplicated" } else { "" }
            ),
            Self::Unknown { description } => description.clone(),
        }
    }

    /// The volume sequence number the map names, if any.
    pub(super) fn volume(&self) -> Option<u16> {
        match self {
            Self::Physical { volume, .. }
            | Self::Virtual { volume, .. }
            | Self::Sparable { volume, .. }
            | Self::Metadata { volume, .. } => Some(*volume),
            Self::Unknown { .. } => None,
        }
    }
}

/// The prevailing logical volume descriptor (3/10.6).
#[derive(Debug, Clone)]
pub(super) struct LogicalVolume {
    /// Logical volume identifier (84, dstring of 128 B).
    pub(super) identifier: String,
    /// Logical block size in bytes (212).
    block_size: u32,
    /// Domain identifier (216, regid).
    domain: String,
    /// UDF revision from the domain identifier suffix (UDF 2.60 2.1.5.3).
    pub(super) revision: u16,
    /// The extent of the file set descriptors (248, `long_ad`).
    pub(super) file_set: LongAd,
    /// Partition maps (440), by partition reference number.
    pub(super) maps: Vec<MapRecord>,
    /// The first extent of the integrity sequence (432).
    integrity: SectorExtent,
}

impl LogicalVolume {
    /// Parse the descriptor at file offset `offset`. Linux
    /// `udf_load_logicalvol` rejects a map table longer than the block
    /// after the fixed fields.
    fn parse(descriptor: &[u8], offset: usize) -> Result<Self> {
        let table_length = le_u32(descriptor, LV_MAP_TABLE_LENGTH)? as usize;
        let count = le_u32(descriptor, LV_MAP_COUNT)?;
        let table = descriptor
            .get(LV_MAPS..)
            .and_then(|rest| rest.get(..table_length))
            .ok_or_else(|| {
                error(format!(
                    "Invalid logical volume descriptor at 0x{offset:X}: a map table of \
                     {table_length} B does not fit in the {} B descriptor",
                    descriptor.len()
                ))
            })?;
        let domain_regid = slice(descriptor, LV_DOMAIN, REGID_SIZE)?;
        Ok(Self {
            identifier: text::dstring(slice(descriptor, LV_IDENTIFIER, 128)?),
            block_size: le_u32(descriptor, LV_BLOCK_SIZE)?,
            domain: text::regid_identifier(domain_regid),
            revision: le_u16(domain_regid, REGID_SUFFIX)?,
            file_set: LongAd::read(descriptor, LV_CONTENTS_USE)?,
            maps: parse_maps(table, count, offset + LV_MAPS)?,
            integrity: SectorExtent::read(descriptor, LV_INTEGRITY)?,
        })
    }
}

/// Parse `count` partition maps from the map table at file offset `offset`.
fn parse_maps(table: &[u8], count: u32, offset: usize) -> Result<Vec<MapRecord>> {
    // Each map takes at least its type and length bytes, so a count that
    // the table cannot hold is invalid before anything is allocated.
    if count as usize > table.len() / 2 {
        return Err(error(format!(
            "Invalid logical volume descriptor: {count} partition maps in a {} B map table",
            table.len()
        )));
    }
    let mut maps = Vec::with_capacity(count as usize);
    let mut pos = 0;
    for index in 0..count {
        let kind = byte(table, pos)?;
        let length = usize::from(byte(table, pos + 1)?);
        let expected = match kind {
            MAP_TYPE_1 => Some(MAP_TYPE_1_LENGTH),
            MAP_TYPE_2 => Some(MAP_TYPE_2_LENGTH),
            _ => None,
        };
        let fits = pos + length <= table.len();
        if length < 2 || !fits || expected.is_some_and(|expected| expected != length) {
            return Err(error(format!(
                "Invalid partition map {index} at 0x{:X}: type {kind}, length {length}",
                offset + pos
            )));
        }
        maps.push(MapRecord::parse(&table[..pos + length], pos, kind)?);
        pos += length;
    }
    Ok(maps)
}

/// Which descriptor sequence supplied the volume descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Main,
    Reserve,
}

/// The prevailing descriptors of a volume descriptor sequence.
#[derive(Debug, Clone)]
pub(super) struct Descriptors {
    pub(super) primary: Primary,
    pub(super) logical: LogicalVolume,
    /// Prevailing partition descriptors, one per partition number, in
    /// sequence order.
    pub(super) partitions: Vec<PartitionDescriptor>,
    /// The sequence the descriptors came from.
    which: Which,
    /// The extent of that sequence.
    extent: SectorExtent,
    /// Why the main sequence was not used, when the reserve one was.
    main_problem: Option<String>,
    /// The prevailing integrity descriptor, or why it could not be read.
    integrity: std::result::Result<Integrity, String>,
}

/// A descriptor with its volume descriptor sequence number (3/10.1.2 and
/// the other descriptors' field at offset 16).
#[derive(Debug)]
struct Numbered<T> {
    sequence_number: u32,
    descriptor: T,
}

/// Keep `descriptor` in `slot` when it is the first one or its sequence
/// number is higher: the highest number prevails (3/8.4.3).
fn prevail<T>(slot: &mut Option<Numbered<T>>, sequence_number: u32, descriptor: T) {
    if slot
        .as_ref()
        .map_or(true, |current| sequence_number > current.sequence_number)
    {
        *slot = Some(Numbered {
            sequence_number,
            descriptor,
        });
    }
}

/// Prevailing descriptors as they are found in a sequence.
#[derive(Debug, Default)]
struct Collected {
    primary: Option<Numbered<Primary>>,
    logical: Option<Numbered<LogicalVolume>>,
    /// One per partition number, in sequence order.
    partitions: Vec<Numbered<PartitionDescriptor>>,
}

impl Collected {
    fn add_partition(&mut self, sequence_number: u32, partition: PartitionDescriptor) {
        let same = self
            .partitions
            .iter_mut()
            .find(|current| current.descriptor.number == partition.number);
        match same {
            Some(current) if sequence_number > current.sequence_number => {
                *current = Numbered {
                    sequence_number,
                    descriptor: partition,
                };
            }
            Some(_) => {}
            None => self.partitions.push(Numbered {
                sequence_number,
                descriptor: partition,
            }),
        }
    }
}

/// Read one volume descriptor sequence from `extent`, following volume
/// descriptor pointers. It ends at a terminating descriptor, at a sector
/// whose tag does not verify (an unrecorded sector, 3/8.4.2), or at the end
/// of an extent.
fn read_sequence(disc: &Disc<'_>, extent: SectorExtent) -> ReadResult<Collected> {
    let mut collected = Collected::default();
    let mut current = extent;
    let mut pointers = 0;
    let mut read = 0u64;
    let mut index = 0u64;
    loop {
        let sectors = u64::from(current.length) / disc.sector_size as u64;
        if index >= sectors {
            break;
        }
        if read >= MAX_SEQUENCE_SECTORS {
            return invalid(format!(
                "Invalid volume descriptor sequence: more than {MAX_SEQUENCE_SECTORS} sectors"
            ));
        }
        read += 1;
        let sector = u64::from(current.location) + index;
        index += 1;
        let Ok(location) = u32::try_from(sector) else {
            return invalid(format!(
                "Invalid volume descriptor sequence: sector {sector} is past the 32-bit sector \
                 numbers"
            ));
        };
        let descriptor = disc.sector(sector)?;
        let offset = disc.offset(sector).expect("a present sector has an offset");
        disc.charge(descriptor.len())?;
        let Ok(tag) = read_tag(descriptor, offset, Some(location)) else {
            break;
        };
        // The volume descriptor sequence number follows the tag (3/10.1.2
        // and the other descriptors).
        let number = le_u32(descriptor, 16)?;
        match tag.identifier {
            TAG_PRIMARY_VOLUME => {
                prevail(&mut collected.primary, number, Primary::parse(descriptor)?);
            }
            TAG_PARTITION => {
                collected.add_partition(number, PartitionDescriptor::parse(descriptor)?);
            }
            TAG_LOGICAL_VOLUME => {
                let logical = LogicalVolume::parse(descriptor, offset)?;
                prevail(&mut collected.logical, number, logical);
            }
            TAG_VOLUME_POINTER => {
                pointers += 1;
                if pointers > MAX_POINTERS {
                    return invalid(format!(
                        "Invalid volume descriptor sequence: more than {MAX_POINTERS} volume \
                         descriptor pointers"
                    ));
                }
                current = SectorExtent::read(descriptor, 20)?;
                index = 0;
            }
            TAG_TERMINATING => break,
            // Implementation use and unallocated space descriptors, and
            // descriptors of other types, do not describe the files.
            _ => {}
        }
    }
    Ok(collected)
}

impl Descriptors {
    /// Read the main volume descriptor sequence, or the reserve one when
    /// the main one lacks a primary volume, logical volume or partition
    /// descriptor (Linux `udf_load_sequence`), and the integrity sequence.
    pub(super) fn read(disc: &Disc<'_>, anchor: &Anchor) -> Result<Self> {
        let main = Self::from_sequence(disc, anchor.main, Which::Main);
        let (mut descriptors, main_problem) = match main {
            Ok(descriptors) => (descriptors, None),
            Err(problem) if anchor.reserve.length > 0 => {
                let reserve = Self::from_sequence(disc, anchor.reserve, Which::Reserve).map_err(
                    |reserve_problem| {
                        error(format!(
                            "Invalid volume descriptor sequences: main: {problem}; reserve: \
                             {reserve_problem}"
                        ))
                    },
                )?;
                (reserve, Some(problem))
            }
            Err(problem) => {
                return Err(error(format!(
                    "Invalid main volume descriptor sequence: {problem}; no reserve sequence is \
                     recorded"
                )))
            }
        };
        descriptors.main_problem = main_problem;
        descriptors.check_block_size(disc.sector_size)?;
        descriptors.integrity = read_integrity(disc, descriptors.logical.integrity);
        Ok(descriptors)
    }

    /// The descriptors of the sequence in `extent`, or why it cannot supply
    /// them.
    fn from_sequence(
        disc: &Disc<'_>,
        extent: SectorExtent,
        which: Which,
    ) -> std::result::Result<Self, String> {
        let collected = match read_sequence(disc, extent) {
            Ok(collected) => collected,
            Err(Fault::Invalid(e)) => return Err(message(e)),
            Err(Fault::Absent) => {
                return Err(format!(
                    "it lies past the end of the {} input (truncated volume)",
                    disc.present_text()
                ))
            }
        };
        let location = extent.location;
        let Some(primary) = collected.primary else {
            return Err(format!(
                "no primary volume descriptor from sector {location}"
            ));
        };
        let Some(logical) = collected.logical else {
            return Err(format!(
                "no logical volume descriptor from sector {location}"
            ));
        };
        if collected.partitions.is_empty() {
            return Err(format!("no partition descriptor from sector {location}"));
        }
        Ok(Self {
            primary: primary.descriptor,
            logical: logical.descriptor,
            partitions: collected
                .partitions
                .into_iter()
                .map(|numbered| numbered.descriptor)
                .collect(),
            which,
            extent,
            main_problem: None,
            integrity: Err(String::new()),
        })
    }

    /// UDF records the logical block size as the logical sector size (UDF
    /// 2.60 2.2.4.2); this reader addresses blocks as sectors.
    fn check_block_size(&self, sector_size: usize) -> Result<()> {
        let block_size = self.logical.block_size;
        if block_size as usize != sector_size {
            return Err(error(format!(
                "Unsupported logical block size {block_size} B: the anchor validates with {} \
                 sectors",
                size_text(sector_size)
            )));
        }
        Ok(())
    }

    /// The volume sequence number of the primary volume descriptor, which
    /// the partition maps name.
    pub(super) fn primary_sequence_number(&self) -> u16 {
        self.primary.sequence_number
    }

    /// Whether the volume belongs to a set of several volumes (3/10.1.6).
    pub(super) fn is_volume_set(&self) -> bool {
        self.primary.max_sequence_number > 1
    }

    /// The prevailing partition descriptor with partition number `number`.
    pub(super) fn partition(&self, number: u16) -> Option<&PartitionDescriptor> {
        self.partitions.iter().find(|p| p.number == number)
    }

    /// Notes and metadata for the volume descriptors.
    pub(super) fn describe(&self, sector_size: usize, c: &mut Container<'_>) {
        let primary = &self.primary;
        let sequence = match self.which {
            Which::Main => "main",
            Which::Reserve => "reserve",
        };
        c.notes.push(format!(
            "Primary volume \"{}\" of volume set \"{}\"; descriptors from the {sequence} volume \
             descriptor sequence at sector {} ({})",
            primary.identifier.escape_debug(),
            primary.set_identifier.escape_debug(),
            self.extent.location,
            size_text(self.extent.length as usize)
        ));
        if let Some(problem) = &self.main_problem {
            c.notes.push(format!(
                "Main volume descriptor sequence not used: {problem}"
            ));
        }
        for partition in &self.partitions {
            let size = u64::from(partition.length) * sector_size as u64;
            let allocated = if partition.allocated {
                ""
            } else {
                "; marked unallocated"
            };
            c.notes.push(format!(
                "Partition {} ({}): sector {}, {} blocks ({}), {}{allocated}",
                partition.number,
                partition.contents.escape_debug(),
                partition.start,
                partition.length,
                volume_size_text(size),
                access_text(partition.access)
            ));
        }
        if self.is_volume_set() {
            c.notes.push(format!(
                "Volume {} of a set of {}; partitions on other volumes are not read",
                primary.sequence_number, primary.max_sequence_number
            ));
        }
        if self.logical.domain != UDF_DOMAIN {
            c.notes.push(format!(
                "Domain identifier \"{}\" is not \"{UDF_DOMAIN}\"; the volume is read as ECMA-167",
                self.logical.domain.escape_debug()
            ));
        }
        match &self.integrity {
            Ok(integrity) => c.notes.push(integrity.text()),
            Err(problem) => c
                .notes
                .push(format!("Logical volume integrity not read: {problem}")),
        }
        self.metadata(c);
    }

    fn metadata(&self, c: &mut Container<'_>) {
        let primary = &self.primary;
        c.push_metadata(
            "udf_volume_id",
            "Volume identifier",
            primary.identifier.clone(),
        );
        if !primary.set_identifier.is_empty() {
            c.push_metadata(
                "udf_volume_set_id",
                "Volume set identifier",
                primary.set_identifier.clone(),
            );
        }
        for (key, label, value) in [
            ("udf_application", "Application", &primary.application),
            (
                "udf_implementation",
                "Implementation",
                &primary.implementation,
            ),
        ] {
            if !value.is_empty() {
                c.push_metadata(key, label, value.clone());
            }
        }
        if let Some(recorded) = &primary.recorded {
            c.push_metadata("udf_recorded", "Recording time", recorded.clone());
        }
        if let Some(partition) = self.partitions.first() {
            c.push_metadata(
                "udf_partition_start",
                "Partition start (sector)",
                u64::from(partition.start),
            );
            c.push_metadata(
                "udf_partition_blocks",
                "Partition length (blocks)",
                u64::from(partition.length),
            );
            c.push_metadata(
                "udf_access_type",
                "Partition access type",
                access_text(partition.access),
            );
        }
        if let Ok(integrity) = &self.integrity {
            c.push_metadata(
                "udf_integrity",
                "Logical volume integrity",
                integrity.state_text(),
            );
        }
    }
}

/// The prevailing logical volume integrity descriptor (3/10.10; UDF 2.60
/// 2.2.6).
#[derive(Debug, Clone)]
struct Integrity {
    /// Integrity type (28): 0 open, 1 close.
    kind: u32,
    /// The UDF implementation use fields (after the free space and size
    /// tables, UDF 2.60 2.2.6.4), when recorded.
    counts: Option<IntegrityCounts>,
}

/// The counts and revisions in the integrity descriptor's implementation
/// use (UDF 2.60 2.2.6.4): files (32), directories (36), minimum read
/// revision (40), minimum write revision (42), maximum write revision (44).
#[derive(Debug, Clone, Copy)]
struct IntegrityCounts {
    files: u32,
    directories: u32,
    min_read: u16,
    min_write: u16,
    max_write: u16,
}

/// Size of the UDF integrity implementation use fields (UDF 2.60 2.2.6.4).
const INTEGRITY_USE_SIZE: usize = 46;

impl Integrity {
    /// Parse the descriptor: integrity type (28), next extent (32), number
    /// of partitions `N_P` (72), implementation use length `L_IU` (76),
    /// tables (80) and implementation use (80 + 8 `N_P`).
    fn parse(descriptor: &[u8]) -> Result<Self> {
        let partitions = le_u32(descriptor, 72)? as usize;
        let use_length = le_u32(descriptor, 76)? as usize;
        let use_offset = partitions
            .checked_mul(8)
            .and_then(|tables| tables.checked_add(80));
        let counts = match use_offset {
            Some(at) if use_length >= INTEGRITY_USE_SIZE => match slice(descriptor, at, use_length)
            {
                Ok(area) => Some(IntegrityCounts {
                    files: le_u32(area, 32)?,
                    directories: le_u32(area, 36)?,
                    min_read: le_u16(area, 40)?,
                    min_write: le_u16(area, 42)?,
                    max_write: le_u16(area, 44)?,
                }),
                Err(_) => None,
            },
            _ => None,
        };
        Ok(Self {
            kind: le_u32(descriptor, 28)?,
            counts,
        })
    }

    fn state_text(&self) -> &'static str {
        match self.kind {
            INTEGRITY_OPEN => "open",
            INTEGRITY_CLOSE => "closed",
            _ => "of a reserved type",
        }
    }

    fn text(&self) -> String {
        let state = match self.kind {
            INTEGRITY_OPEN => "open (the volume was not closed after its last change)",
            INTEGRITY_CLOSE => "closed",
            _ => "of a reserved integrity type",
        };
        let Some(counts) = self.counts else {
            return format!("Logical volume integrity: {state}");
        };
        format!(
            "Logical volume integrity: {state}; {} files and {} directories recorded; UDF read \
             revision {} or later needed, written with {} to {}",
            counts.files,
            counts.directories,
            text::revision_text(counts.min_read),
            text::revision_text(counts.min_write),
            text::revision_text(counts.max_write)
        )
    }
}

/// Read the integrity sequence from `extent`: the last descriptor read
/// prevails (3/8.8.2). Descriptors follow each other in an extent until an
/// unrecorded sector or a terminating descriptor, and a descriptor may name
/// a next extent (32).
fn read_integrity(disc: &Disc<'_>, extent: SectorExtent) -> std::result::Result<Integrity, String> {
    if extent.length == 0 {
        return Err("no integrity sequence is recorded".to_string());
    }
    let mut prevailing = None;
    let mut current = extent;
    let mut index = 0u64;
    for _ in 0..MAX_INTEGRITY_DESCRIPTORS {
        if index >= u64::from(current.length) / disc.sector_size as u64 {
            break;
        }
        let sector = u64::from(current.location) + index;
        index += 1;
        let Ok(descriptor) = disc.sector(sector) else {
            if prevailing.is_none() {
                return Err(format!(
                    "the sequence at sector {sector} lies past the end of the {} input",
                    disc.present_text()
                ));
            }
            break;
        };
        let offset = disc.offset(sector).expect("a present sector has an offset");
        let location = u32::try_from(sector).ok();
        let Ok(tag) = read_tag(descriptor, offset, location) else {
            break;
        };
        if tag.identifier != TAG_INTEGRITY {
            break;
        }
        let integrity = Integrity::parse(descriptor).map_err(message)?;
        let next = SectorExtent::read(descriptor, 32).map_err(message)?;
        prevailing = Some(integrity);
        if next.length > 0 {
            current = next;
            index = 0;
        }
    }
    prevailing.ok_or_else(|| {
        format!(
            "no valid integrity descriptor at sector {}",
            extent.location
        )
    })
}

/// The file set descriptor (4/14.1) that prevails: the highest file set
/// number in the extent the logical volume descriptor names (UDF 2.60
/// 2.3.2).
#[derive(Debug, Clone)]
pub(super) struct FileSet {
    /// File set identifier (304, dstring of 32 B).
    pub(super) identifier: String,
    /// The root directory's ICB (400, `long_ad`).
    pub(super) root: Address,
    /// A system stream directory ICB is recorded (464, `long_ad`).
    has_streams: bool,
    /// File set number (40).
    number: u32,
    /// Further file set descriptors in the extent.
    others: usize,
}

impl FileSet {
    /// Read the file set descriptors in `extent`, up to a terminating
    /// descriptor, an unreadable block or the end of the extent.
    pub(super) fn read(
        disc: &Disc<'_>,
        partitions: &Partitions,
        extent: LongAd,
    ) -> ReadResult<Self> {
        let first = Self::read_one(disc, partitions, extent.location)?;
        let blocks = blocks_for(u64::from(extent.length), disc.sector_size as u64);
        let mut prevailing = first;
        for index in 1..blocks.min(u64::from(MAX_FILE_SET_BLOCKS)) {
            let address = Address {
                block: extent
                    .location
                    .block
                    .saturating_add(u32::try_from(index).expect("at most MAX_FILE_SET_BLOCKS")),
                reference: extent.location.reference,
            };
            // A terminating descriptor, an unrecorded block or anything
            // else ends the sequence of file set descriptors (4/8.3.1).
            let Ok(file_set) = Self::read_one(disc, partitions, address) else {
                break;
            };
            prevailing = if file_set.number > prevailing.number {
                Self {
                    others: prevailing.others + 1,
                    ..file_set
                }
            } else {
                Self {
                    others: prevailing.others + 1,
                    ..prevailing
                }
            };
        }
        Ok(prevailing)
    }

    /// The file set descriptor at `address`.
    fn read_one(disc: &Disc<'_>, partitions: &Partitions, address: Address) -> ReadResult<Self> {
        let block = partitions.descriptor(disc, address)?;
        disc.charge(block.bytes.len())?;
        let tag = read_tag(block.bytes, block.offset, Some(address.block)).map_err(|e| {
            error(format!(
                "Invalid file set descriptor at {address}: {}",
                message(e)
            ))
        })?;
        expect_identifier(tag, TAG_FILE_SET, "file set descriptor", block.offset)?;
        Ok(Self::parse(block.bytes)?)
    }

    fn parse(descriptor: &[u8]) -> Result<Self> {
        let root = LongAd::read(descriptor, FILE_SET_ROOT)?;
        if root.length == 0 {
            return Err(error(
                "Missing root directory ICB in the file set descriptor",
            ));
        }
        Ok(Self {
            identifier: text::dstring(slice(descriptor, FILE_SET_IDENTIFIER, 32)?),
            root: root.location,
            has_streams: LongAd::read(descriptor, FILE_SET_STREAMS)?.length > 0,
            number: le_u32(descriptor, FILE_SET_NUMBER)?,
            others: 0,
        })
    }

    /// Notes for the file set.
    pub(super) fn describe(&self, c: &mut Container<'_>) {
        if self.others > 0 {
            c.notes.push(format!(
                "{} further file set descriptors; file set {} (the highest number) is read",
                self.others, self.number
            ));
        }
        if self.has_streams {
            c.notes.push(
                "The file set records a system stream directory; streams are not read".to_string(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A type 2 map with partition type identifier `identifier`, volume 1
    /// and partition 0.
    fn type2_map(identifier: &str) -> Vec<u8> {
        let mut map = vec![0u8; MAP_TYPE_2_LENGTH];
        map[0] = MAP_TYPE_2;
        map[1] = u8::try_from(MAP_TYPE_2_LENGTH).expect("64");
        let id = identifier.as_bytes();
        map[MAP2_IDENTIFIER + 1..MAP2_IDENTIFIER + 1 + id.len()].copy_from_slice(id);
        map[MAP2_VOLUME..MAP2_VOLUME + 2].copy_from_slice(&1u16.to_le_bytes());
        map
    }

    #[test]
    fn partition_maps_parse_by_type_and_identifier() {
        let mut table = vec![MAP_TYPE_1, 6, 1, 0, 0, 0];
        let mut metadata = type2_map(METADATA_PARTITION);
        metadata[40..44].copy_from_slice(&7u32.to_le_bytes());
        metadata[44..48].copy_from_slice(&900u32.to_le_bytes());
        metadata[58] = DUPLICATE_METADATA;
        table.extend_from_slice(&metadata);
        let maps = parse_maps(&table, 2, 0).expect("valid maps");
        assert_eq!(
            maps[0],
            MapRecord::Physical {
                volume: 1,
                partition: 0
            }
        );
        assert_eq!(
            maps[1],
            MapRecord::Metadata {
                volume: 1,
                partition: 0,
                file: 7,
                mirror: 900,
                duplicated: true
            }
        );
        assert!(maps[1]
            .kind_text()
            .contains("mirror at block 900, duplicated"));
    }

    #[test]
    fn partition_map_lengths_and_counts_are_checked() {
        let table = [MAP_TYPE_1, 5, 1, 0, 0, 0];
        let wrong = parse_maps(&table, 1, 0x1B8).unwrap_err().to_string();
        assert!(
            wrong.contains("map 0 at 0x1B8: type 1, length 5"),
            "{wrong}"
        );
        assert!(parse_maps(&table, 4, 0).is_err());
        let mut sparable = type2_map(SPARABLE_PARTITION);
        sparable[42] = 5;
        assert!(parse_maps(&sparable, 1, 0).is_err());
        let unknown = parse_maps(&type2_map("*Vendor Partition"), 1, 0).expect("listed");
        assert!(matches!(unknown[0], MapRecord::Unknown { .. }));
    }

    #[test]
    fn later_sequence_numbers_prevail() {
        let mut collected = Collected::default();
        let partition = |number, start| PartitionDescriptor {
            number,
            contents: "+NSR03".to_string(),
            access: 1,
            start,
            length: 10,
            allocated: true,
        };
        collected.add_partition(1, partition(0, 100));
        collected.add_partition(3, partition(0, 200));
        collected.add_partition(2, partition(0, 300));
        collected.add_partition(1, partition(1, 400));
        let starts: Vec<u32> = collected
            .partitions
            .iter()
            .map(|numbered| numbered.descriptor.start)
            .collect();
        assert_eq!(starts, [200, 400]);
        let mut slot = None;
        prevail(&mut slot, 4, "first");
        prevail(&mut slot, 4, "same number");
        prevail(&mut slot, 5, "higher");
        assert_eq!(slot.map(|numbered| numbered.descriptor), Some("higher"));
    }
}
