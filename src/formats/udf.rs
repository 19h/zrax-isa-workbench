//! UDF volumes (the OSTA Universal Disk Format on ECMA-167): the volume
//! recognition sequence, the anchor volume descriptor pointer, the main and
//! reserve volume descriptor sequences, physical, sparable, metadata and
//! virtual partitions, the file set descriptor, file entries and extended
//! file entries with short, long, extended and embedded allocation, and a
//! directory walk that lists regular files in a recognized format as
//! members. DVD-Video, DVD-ROM and Blu-ray discs, packet-written CD and DVD
//! media and UDF hard disk volumes use it.
//!
//! Sources:
//! - [ECMA-167] ECMA-167 3rd edition (June 1997),
//!   <https://ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf>,
//!   SHA-256 `6efe0f591e21da2b17288076b2653dc616800bdc94f83e74acba9279c84c34b7`:
//!   1/7.2.12 (dstrings), 1/7.3 (timestamps), 1/7.4 (regids), 2/8.3 and
//!   2/9.1-9.3 (the volume recognition sequence), 3/7.1-7.2 (extents and
//!   the descriptor tag), 3/8.4 (volume descriptor sequences and anchor
//!   points), 3/10.1-10.10 (volume descriptors and partition maps), 4/7.1
//!   (`lb_addr`), 4/8.6 (directories), 4/12 (allocation descriptors), 4/14.1
//!   (file set descriptor), 4/14.4-14.9 (file identifier descriptor,
//!   allocation extent descriptor, ICB tag, indirect entry, file entry),
//!   4/14.14 (`short_ad`, `long_ad`, `ext_ad`) and 4/14.17 (extended file
//!   entry).
//! - [UDF260] OSTA UDF Specification revision 2.60 (2005-03-01),
//!   <https://web.archive.org/web/20240116224411/http://www.osta.org/specs/pdf/udf260.pdf>,
//!   SHA-256 `e338ef7f06cb4c8ef9511fef337b3b12bf3ba29a3a2de85ae84dfd316f5ae71b`:
//!   2 (basic restrictions), 2.1.1-2.1.5 (CS0, dstrings, entity
//!   identifiers), 2.2.1-2.2.14 (descriptor tags, the anchor, the logical
//!   volume descriptor, integrity, virtual, sparable and metadata partition
//!   maps, the VAT, sparing tables, the metadata partition), 2.3.1-2.3.11
//!   (file structure), 6.4 (OSTA Compressed Unicode), 6.9.2 (how a DVD
//!   player reads a disc) and 6.11.4 (UDF bridge discs).
//! - [UDF150] OSTA UDF Specification revision 1.50,
//!   <https://web.archive.org/web/20250101031426/http://www.osta.org/specs/pdf/udf150.pdf>,
//!   SHA-256 `f4ecee7ebc3f0132e5f846a7f8cadd3cee19d8246202e1643699ffe3ec8a3e8a`:
//!   2.2.10 (the 1.50 virtual allocation table).
//! - [Linux] torvalds/linux tag `v6.11`, `fs/udf/super.c` (`udf_check_vsd`,
//!   `udf_scan_anchors`, `udf_process_sequence`, `udf_load_logicalvol`,
//!   `udf_load_sparable_map`, `udf_load_metadata_files`, `udf_load_vat`,
//!   `udf_fill_super`), `misc.c` (`udf_read_tagged`), `inode.c`
//!   (`udf_read_inode`), `directory.c` (`udf_verify_fi`) and `partition.c`
//!   (sparable, virtual and metadata block mapping), cross-checking the
//!   documents.
//!
//! All numbers are little-endian. Part 3 structures address logical sectors
//! of the volume; Part 4 structures address logical blocks within a
//! partition, which UDF makes the size of a logical sector (2048 B on
//! optical media, 512 B or 4096 B on hard disks). The sector size is found
//! as Linux finds it: the sizes 512, 1024, 2048 and 4096 B are tried until
//! an anchor validates at sector 256. Offsets in notes, metadata and members
//! are file bytes. The format names no processor; members are classified
//! from their own bytes.
//!
//! A volume larger than the input (a partition that ends past the input;
//! containers hand on the first 64 MiB of a larger disc) is read as a
//! truncated volume when its descriptor sequence, file set descriptor and
//! root directory are present: directories and file entries past the end of
//! the input are skipped and counted, and files are listed only when all of
//! their data is present.

use crate::error::{ClassifierError, Result};
use crate::formats::checksum::crc16_ibm3740_update;
use crate::formats::compressed::size_text;
use crate::formats::container::Container;
use crate::types::FileFormat;
use std::cell::Cell;

mod entry;
mod partition;
mod recognition;
mod text;
mod volume;
mod walk;

use recognition::Recognized;

/// Tag identifiers (ECMA-167 3/7.2.1 figure 3/3, 4/7.2.1 figure 4/3; UDF
/// 2.60 2.2.12 for the sparing table).
const TAG_SPARING_TABLE: u16 = 0;
const TAG_PRIMARY_VOLUME: u16 = 1;
const TAG_ANCHOR: u16 = 2;
const TAG_VOLUME_POINTER: u16 = 3;
const TAG_PARTITION: u16 = 5;
const TAG_LOGICAL_VOLUME: u16 = 6;
const TAG_TERMINATING: u16 = 8;
const TAG_INTEGRITY: u16 = 9;
const TAG_FILE_SET: u16 = 256;
const TAG_FILE_IDENTIFIER: u16 = 257;
const TAG_ALLOCATION_EXTENT: u16 = 258;
const TAG_INDIRECT_ENTRY: u16 = 259;
const TAG_FILE_ENTRY: u16 = 261;
const TAG_EXTENDED_FILE_ENTRY: u16 = 266;

/// Size of a descriptor tag (ECMA-167 3/7.2 figure 3/2).
const TAG_SIZE: usize = 16;

/// Offset of the tag checksum in a descriptor tag (3/7.2.3).
const TAG_CHECKSUM_OFFSET: usize = 4;

/// Descriptor versions: 2 for ECMA-167 2nd edition (NSR02) structures, 3
/// for the 3rd edition (3/7.2.2; receivers allow both).
const DESCRIPTOR_VERSIONS: [u16; 2] = [2, 3];

/// Size of a `long_ad` (ECMA-167 4/14.14.2 figure 4/43).
const LONG_AD_SIZE: usize = 16;

/// The low 30 bits of an allocation descriptor's extent length are bytes;
/// the high 2 bits are the extent type (4/14.14.1.1).
const EXTENT_LENGTH_MASK: u32 = 0x3fff_ffff;
const EXTENT_TYPE_SHIFT: u32 = 30;

/// Descriptor bytes the reader may verify, as a multiple of the input size:
/// every file entry is read once and directory data is read once per
/// directory, so the factor only covers repeated descriptor sequences,
/// indirect entries and continuation extents. The factor is ours.
const METADATA_READ_FACTOR: u64 = 16;

/// Smallest descriptor read budget, for inputs smaller than their own
/// volume descriptor sequence would suggest. Ours.
const MIN_METADATA_BUDGET: u64 = 1 << 20;

/// A UDF layout recognized by its volume recognition sequence and anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// A UDF volume: `NSR02` or `NSR03` in the volume recognition sequence
    /// from 0x8000 and a valid anchor volume descriptor pointer at sector
    /// 256.
    Udf,
    /// A UDF bridge disc ([UDF260] 6.11.4): an ECMA-119 (ISO 9660) volume
    /// descriptor set precedes the UDF extended area, and the UDF volume
    /// opens through its root directory, so UDF rather than ISO 9660
    /// reports the disc.
    Bridge,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Udf | Self::Bridge => FileFormat::Udf,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Udf => "UDF",
            Self::Bridge => "UDF bridge (UDF and ISO 9660)",
        }
    }

    /// Recognized from complete structure rather than a magic value. Both
    /// layouts carry the recognition sequence identifiers and a checksummed
    /// anchor, so neither is weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Udf | Self::Bridge => false,
        }
    }
}

/// Strong recognition: `NSR02` or `NSR03` among the volume structure
/// descriptors from 0x8000 and an anchor volume descriptor pointer at
/// sector 256 whose tag checksum, descriptor CRC and tag location verify,
/// for one of the sector sizes 512, 1024, 2048 and 4096 B. The descriptor
/// sequence, partitions and directories are checked by [`parse_container`],
/// so a damaged volume is a parse error.
///
/// A bridge disc is also a valid ISO 9660 volume. It is claimed only when
/// the UDF volume opens through its root directory; otherwise ISO 9660
/// reports it, as it did before UDF was parsed.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let recognized = recognition::recognize(data).ok()?;
    if !recognized.sequence.is_bridge() {
        return Some(Layout::Udf);
    }
    let fs = Filesystem::open(data, &recognized).ok()?;
    walk::root_is_readable(&fs).then_some(Layout::Bridge)
}

/// Parse a UDF volume into the shared container model. Regular files whose
/// first bytes are a recognized format are its children, labeled by their
/// path, in walk order.
///
/// # Errors
///
/// [`ClassifierError::UdfParseError`] for a missing recognition sequence or
/// anchor, main and reserve volume descriptor sequences without a valid
/// primary volume, logical volume and partition descriptor, a logical block
/// size other than the sector size, an unusable partition map, metadata
/// file or virtual allocation table, an invalid file set descriptor or root
/// directory, and for a truncated volume whose descriptor sequence, file
/// set descriptor or root directory lies past the end of the input. Damage
/// below the root directory is reported in notes.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let recognized = recognition::recognize(data)?;
    let fs = Filesystem::open(data, &recognized)?;
    let mut c = Container::new(layout.format(), layout.label(), "udf");
    c.consumed = data.len();
    describe(&recognized, &fs, &mut c);
    walk::walk(&fs, &mut c);
    Ok(c)
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::UdfParseError {
        message: message.into(),
    }
}

/// Why a read of the volume failed.
#[derive(Debug)]
enum Fault {
    /// The volume is invalid; the error says how.
    Invalid(ClassifierError),
    /// The bytes lie past the end of the input, which may hold only the
    /// start of a larger volume.
    Absent,
}

impl From<ClassifierError> for Fault {
    fn from(e: ClassifierError) -> Self {
        Self::Invalid(e)
    }
}

/// The result of a read of the volume's bytes.
type ReadResult<T> = std::result::Result<T, Fault>;

/// A read that failed because the volume is invalid.
fn invalid<T>(message: impl Into<String>) -> ReadResult<T> {
    Err(Fault::Invalid(error(message)))
}

/// A read of a structure the volume cannot be listed without: bytes past
/// the end of the input are a truncation error naming `what`.
fn needed<T>(read: ReadResult<T>, what: &str, input_size: usize) -> Result<T> {
    match read {
        Ok(value) => Ok(value),
        Err(Fault::Invalid(e)) => Err(e),
        Err(Fault::Absent) => Err(error(format!(
            "Truncated UDF volume: {what} lies past the end of the {} input",
            size_text(input_size)
        ))),
    }
}

/// The text of a parse error without the family prefix.
fn message(e: ClassifierError) -> String {
    match e {
        ClassifierError::UdfParseError { message } => message,
        other => other.to_string(),
    }
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated descriptor at 0x{start:X} + {len} B")))
}

fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(data, at, N)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn byte(data: &[u8], at: usize) -> Result<u8> {
    Ok(slice(data, at, 1)?[0])
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(data, at)?))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(array(data, at)?))
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(array(data, at)?))
}

/// Whole blocks of `block_size` bytes covering `length` bytes.
fn blocks_for(length: u64, block_size: u64) -> u64 {
    length / block_size + u64::from(length % block_size != 0)
}

/// A size in bytes as text; a size past the address space in bytes.
fn volume_size_text(size: u64) -> String {
    usize::try_from(size).map_or_else(|_| format!("{size} B"), size_text)
}

/// A verified descriptor tag (ECMA-167 3/7.2, 4/7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tag {
    /// Tag identifier: `TAG_PRIMARY_VOLUME`, `TAG_FILE_ENTRY` and so on.
    identifier: u16,
}

/// Verify the tag at the start of `descriptor`, the descriptor's bytes at
/// file offset `offset`. Tag: identifier (0, 2), descriptor version (2, 2),
/// checksum (4, the sum of bytes 0-3 and 5-15 modulo 256), reserved (5),
/// serial number (6, 2), descriptor CRC (8, 2, CRC-ITU-T over the CRC length
/// bytes after the tag), CRC length (10, 2), tag location (12, 4). The tag
/// location must be `location` (a logical sector in Part 3, a block within
/// the partition in Part 4) unless it is `None`.
fn read_tag(descriptor: &[u8], offset: usize, location: Option<u32>) -> Result<Tag> {
    let tag = slice(descriptor, 0, TAG_SIZE)
        .map_err(|_| error(format!("Truncated descriptor tag at 0x{offset:X}")))?;
    let stored = tag[TAG_CHECKSUM_OFFSET];
    let computed = tag
        .iter()
        .enumerate()
        .filter(|&(i, _)| i != TAG_CHECKSUM_OFFSET)
        .fold(0u8, |sum, (_, &b)| sum.wrapping_add(b));
    if stored != computed {
        return Err(error(format!(
            "Invalid descriptor tag checksum at 0x{offset:X}: 0x{stored:02X} recorded, \
             0x{computed:02X} computed"
        )));
    }
    let identifier = le_u16(tag, 0)?;
    let version = le_u16(tag, 2)?;
    if !DESCRIPTOR_VERSIONS.contains(&version) {
        return Err(error(format!(
            "Unsupported descriptor version {version} at 0x{offset:X}"
        )));
    }
    let recorded_location = le_u32(tag, 12)?;
    if let Some(expected) = location.filter(|&expected| expected != recorded_location) {
        return Err(error(format!(
            "Invalid tag location at 0x{offset:X}: {recorded_location} recorded, {expected} \
             expected"
        )));
    }
    let crc_length = usize::from(le_u16(tag, 10)?);
    let Some(covered) = descriptor.get(TAG_SIZE..TAG_SIZE + crc_length) else {
        return Err(error(format!(
            "Invalid descriptor CRC length at 0x{offset:X}: {crc_length} B after the tag, {} B \
             in the descriptor",
            descriptor.len() - TAG_SIZE
        )));
    };
    let stored_crc = le_u16(tag, 8)?;
    let computed_crc = crc16_ibm3740_update(0, covered);
    if stored_crc != computed_crc {
        return Err(error(format!(
            "Invalid descriptor CRC at 0x{offset:X}: 0x{stored_crc:04X} recorded, \
             0x{computed_crc:04X} computed"
        )));
    }
    Ok(Tag { identifier })
}

/// Check that a verified tag names the descriptor `expected`; `what` names
/// it in the error.
fn expect_identifier(tag: Tag, expected: u16, what: &str, offset: usize) -> Result<()> {
    if tag.identifier != expected {
        return Err(error(format!(
            "Invalid {what} at 0x{offset:X}: tag identifier {}, expected {expected}",
            tag.identifier
        )));
    }
    Ok(())
}

/// An extent of logical sectors (`extent_ad`, ECMA-167 3/7.1): length in
/// bytes (0, 4), location in logical sectors (4, 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SectorExtent {
    /// Length in bytes.
    length: u32,
    /// First logical sector.
    location: u32,
}

impl SectorExtent {
    fn read(data: &[u8], at: usize) -> Result<Self> {
        Ok(Self {
            length: le_u32(data, at)?,
            location: le_u32(data, at + 4)?,
        })
    }
}

/// A logical block address (`lb_addr`, ECMA-167 4/7.1): block number (0,
/// 4) relative to the partition with the reference number (4, 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Address {
    /// Logical block number within the partition.
    block: u32,
    /// Partition reference number: the index of a partition map in the
    /// logical volume descriptor.
    reference: u16,
}

impl Address {
    fn read(data: &[u8], at: usize) -> Result<Self> {
        Ok(Self {
            block: le_u32(data, at)?,
            reference: le_u16(data, at + 4)?,
        })
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "block {} of partition {}", self.block, self.reference)
    }
}

/// A `long_ad` (ECMA-167 4/14.14.2): extent length (0, 4; low 30 bits in
/// bytes, high 2 bits the extent type), location (4, `lb_addr`),
/// implementation use (10, 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LongAd {
    /// Extent length in bytes.
    length: u32,
    /// Extent type: the high 2 bits of the recorded length.
    kind: u8,
    location: Address,
}

impl LongAd {
    fn read(data: &[u8], at: usize) -> Result<Self> {
        let raw = le_u32(data, at)?;
        Ok(Self {
            length: raw & EXTENT_LENGTH_MASK,
            kind: extent_type(raw),
            location: Address::read(data, at + 4)?,
        })
    }
}

/// The extent type in the high 2 bits of an allocation descriptor's extent
/// length (ECMA-167 4/14.14.1.1).
fn extent_type(raw_length: u32) -> u8 {
    u8::try_from(raw_length >> EXTENT_TYPE_SHIFT).expect("two bits")
}

/// The input read as logical sectors of the volume's sector size.
struct Disc<'a> {
    /// The whole input.
    data: &'a [u8],
    /// Logical sector size in bytes, which UDF makes the logical block size.
    sector_size: usize,
    /// Descriptor bytes the reader may still verify; see [`Disc::charge`].
    budget: Cell<u64>,
}

impl<'a> Disc<'a> {
    fn new(data: &'a [u8], sector_size: usize) -> Self {
        let budget = (data.len() as u64)
            .saturating_mul(METADATA_READ_FACTOR)
            .max(MIN_METADATA_BUDGET);
        Self {
            data,
            sector_size,
            budget: Cell::new(budget),
        }
    }

    /// File offset of logical sector `sector`, if it fits in `usize`.
    fn offset(&self, sector: u64) -> Option<usize> {
        usize::try_from(sector.checked_mul(self.sector_size as u64)?).ok()
    }

    /// The `count` sectors from `sector`; absent when they pass the end of
    /// the input.
    fn sectors(&self, sector: u64, count: u64) -> ReadResult<&'a [u8]> {
        let start = self.offset(sector);
        let len = count
            .checked_mul(self.sector_size as u64)
            .and_then(|len| usize::try_from(len).ok());
        let range = start.zip(len).and_then(|(start, len)| {
            let end = start.checked_add(len)?;
            Some(start..end)
        });
        match range.and_then(|range| self.data.get(range)) {
            Some(bytes) => Ok(bytes),
            None => Err(Fault::Absent),
        }
    }

    /// One logical sector.
    fn sector(&self, sector: u64) -> ReadResult<&'a [u8]> {
        self.sectors(sector, 1)
    }

    /// The input size as text for notes.
    fn present_text(&self) -> String {
        size_text(self.data.len())
    }

    /// Account for `size` bytes of descriptors about to be read.
    fn charge(&self, size: usize) -> Result<()> {
        let remaining = self.budget.get();
        let Some(left) = remaining.checked_sub(size as u64) else {
            self.budget.set(0);
            return Err(error(format!(
                "Invalid metadata: more than {METADATA_READ_FACTOR} times the {} input read in \
                 descriptors",
                self.present_text()
            )));
        };
        self.budget.set(left);
        Ok(())
    }

    /// The descriptor read limit was reached; the walk stops.
    fn is_exhausted(&self) -> bool {
        self.budget.get() == 0
    }
}

/// An opened volume: its descriptors, partitions, file set and root
/// directory.
struct Filesystem<'a> {
    disc: Disc<'a>,
    descriptors: volume::Descriptors,
    partitions: partition::Partitions,
    file_set: volume::FileSet,
    /// The root directory's file entry.
    root: entry::Entry,
}

impl<'a> Filesystem<'a> {
    /// Read the volume descriptor sequence, set up the partitions and read
    /// the file set descriptor and the root directory's file entry.
    fn open(data: &'a [u8], recognized: &Recognized) -> Result<Self> {
        let disc = Disc::new(data, recognized.sector_size);
        let descriptors = volume::Descriptors::read(&disc, &recognized.anchor)?;
        let partitions = partition::Partitions::build(&disc, &descriptors)?;
        let file_set = needed(
            volume::FileSet::read(&disc, &partitions, descriptors.logical.file_set),
            "the file set descriptor",
            data.len(),
        )?;
        let root = needed(
            entry::Entry::read(&disc, &partitions, file_set.root),
            "the root directory's file entry",
            data.len(),
        )?;
        if !root.is_directory() {
            return Err(error(format!(
                "Invalid root directory ICB at {}: file type {}, expected a directory",
                file_set.root, root.file_type
            )));
        }
        Ok(Self {
            disc,
            descriptors,
            partitions,
            file_set,
            root,
        })
    }

    /// Volume size in bytes as the partition descriptors declare it: the
    /// end of the last partition.
    fn declared_size(&self) -> u64 {
        self.descriptors
            .partitions
            .iter()
            .map(|p| (u64::from(p.start) + u64::from(p.length)) * self.disc.sector_size as u64)
            .max()
            .unwrap_or(0)
    }

    /// Whether the input ends before the last partition does.
    fn is_truncated(&self) -> bool {
        self.declared_size() > self.disc.data.len() as u64
    }
}

/// Summary notes and metadata from the recognition sequence and the volume
/// descriptors.
fn describe(recognized: &Recognized, fs: &Filesystem<'_>, c: &mut Container<'_>) {
    let descriptors = &fs.descriptors;
    let logical = &descriptors.logical;
    let revision = text::revision_text(logical.revision);
    c.notes.push(format!(
        "UDF volume \"{}\": UDF revision {revision} ({}), {} logical blocks; file set \"{}\"",
        logical.identifier.escape_debug(),
        recognized.sequence.nsr_identifier(),
        size_text(fs.disc.sector_size),
        fs.file_set.identifier.escape_debug()
    ));
    if fs.is_truncated() {
        c.notes.push(format!(
            "Volume truncated: {} of {} present; files are listed only when all of their data is \
             present",
            fs.disc.present_text(),
            volume_size_text(fs.declared_size())
        ));
    }
    recognized.describe(c);
    descriptors.describe(fs.disc.sector_size, c);
    fs.partitions.describe(c);
    fs.file_set.describe(c);
    c.notes.push(
        "No processor field: UDF names no ISA; members are classified from their own bytes"
            .to_string(),
    );
    c.push_metadata("udf_revision", "UDF revision", revision);
    c.push_metadata(
        "udf_nsr",
        "NSR descriptor",
        recognized.sequence.nsr_identifier(),
    );
    c.push_metadata(
        "udf_block_size",
        "Logical block size (B)",
        fs.disc.sector_size as u64,
    );
    c.push_metadata(
        "udf_logical_volume_id",
        "Logical volume identifier",
        logical.identifier.clone(),
    );
    c.push_metadata(
        "udf_file_set_id",
        "File set identifier",
        fs.file_set.identifier.clone(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tag with `identifier`, version 3 and location `location` before
    /// `body`, with its checksum and CRC set.
    fn tagged(identifier: u16, location: u32, body: &[u8]) -> Vec<u8> {
        let mut descriptor = vec![0u8; TAG_SIZE];
        descriptor[0..2].copy_from_slice(&identifier.to_le_bytes());
        descriptor[2..4].copy_from_slice(&3u16.to_le_bytes());
        descriptor[8..10].copy_from_slice(&crc16_ibm3740_update(0, body).to_le_bytes());
        let crc_length = u16::try_from(body.len()).expect("short body");
        descriptor[10..12].copy_from_slice(&crc_length.to_le_bytes());
        descriptor[12..16].copy_from_slice(&location.to_le_bytes());
        let sum = descriptor.iter().fold(0u8, |sum, &b| sum.wrapping_add(b));
        descriptor[TAG_CHECKSUM_OFFSET] = sum;
        descriptor.extend_from_slice(body);
        descriptor
    }

    #[test]
    fn descriptor_crc_is_crc_itu_t_with_a_zero_start() {
        // ECMA-167 3/7.2.6 note 4.
        assert_eq!(crc16_ibm3740_update(0, &[0x70, 0x6a, 0x77]), 0x3299);
    }

    #[test]
    fn tags_verify_checksum_version_location_and_crc() {
        let descriptor = tagged(TAG_ANCHOR, 256, &[1, 2, 3, 4]);
        let tag = read_tag(&descriptor, 0, Some(256)).expect("valid tag");
        assert_eq!(tag.identifier, TAG_ANCHOR);
        assert!(read_tag(&descriptor, 0, None).is_ok());
        let wrong_place = read_tag(&descriptor, 0, Some(257)).unwrap_err().to_string();
        assert!(
            wrong_place.contains("256 recorded, 257 expected"),
            "{wrong_place}"
        );

        let mut bad_crc = descriptor.clone();
        bad_crc[TAG_SIZE] ^= 1;
        let crc = read_tag(&bad_crc, 0, None).unwrap_err().to_string();
        assert!(crc.contains("Invalid descriptor CRC"), "{crc}");

        let mut bad_sum = descriptor.clone();
        bad_sum[TAG_CHECKSUM_OFFSET] ^= 1;
        assert!(read_tag(&bad_sum, 0, None).is_err());

        let short = read_tag(&descriptor[..TAG_SIZE + 2], 0, None)
            .unwrap_err()
            .to_string();
        assert!(short.contains("4 B after the tag, 2 B"), "{short}");

        // An unrecorded sector: checksum 0 holds, but version 0 does not.
        assert!(read_tag(&[0; 512], 0, None).is_err());
    }

    #[test]
    fn extent_types_are_the_high_two_bits() {
        assert_eq!(extent_type(0x4000_0800), 1);
        assert_eq!(extent_type(0xc000_0000), 3);
        let mut ad = [0u8; LONG_AD_SIZE];
        ad[0..4].copy_from_slice(&0x8000_1000u32.to_le_bytes());
        ad[4..8].copy_from_slice(&7u32.to_le_bytes());
        ad[8..10].copy_from_slice(&1u16.to_le_bytes());
        let long_ad = LongAd::read(&ad, 0).expect("16 bytes");
        assert_eq!(long_ad.length, 0x1000);
        assert_eq!(long_ad.kind, 2);
        assert_eq!(
            long_ad.location,
            Address {
                block: 7,
                reference: 1
            }
        );
    }

    #[test]
    fn block_counts_round_up() {
        assert_eq!(blocks_for(2048, 2048), 1);
        assert_eq!(blocks_for(2049, 2048), 2);
        assert_eq!(blocks_for(0, 512), 0);
    }

    #[test]
    fn layouts_name_their_format() {
        assert_eq!(Layout::Udf.format(), FileFormat::Udf);
        assert_eq!(Layout::Bridge.format(), FileFormat::Udf);
        assert!(!Layout::Bridge.is_weak());
        assert_eq!(detect(&[0; 4096]), None);
    }
}
