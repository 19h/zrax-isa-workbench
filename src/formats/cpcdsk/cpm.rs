//! The CP/M 2.2 filesystem that AMSDOS and +3DOS write on a disk image:
//! the format chosen from track 0, the directory, files reassembled from
//! their allocation blocks across extents, the AMSDOS and +3DOS headers in
//! their first records, and the boot sectors.
//!
//! Formats: the lowest sector ID on track 0 side 0 (iDSK `GetMinSect`) is
//! 0x41 for the AMSDOS system and vendor formats, 0xC1 for the data format
//! ([AMSROM] `SELECT FORMAT` and its XDPBs; [P3MAN]) and 0x01 for a PCW or
//! +3 disk, whose format is the disk specification in bytes 0-15 of sector
//! 1 ([P3MAN] "Disk specification"; all 0xE5 is the 173 KiB default,
//! [AMSFMT]), or else the AMSDOS IBM format of eight sectors per track.
//! Logical sector `s` of a track is the sector with ID `first + s`; logical
//! tracks are cylinders on one side, alternate between sides, or run up
//! side 0 and back down side 1 ([P3MAN]; [AMSFMT]).
//!
//! Directory entries ([DRI] Figure 5-2; [CPM22F]): user (0), name and type
//! (1, 11 B, bit 7 attributes), EX (12), S1 (13), S2 (14), RC (15) and 16
//! allocation bytes: 8-bit block numbers when DSM < 256, 16-bit
//! little-endian otherwise. An entry is extent `(32 × S2 + EX) / (EXM + 1)`
//! of its file and holds `(EX & EXM) × 128 + RC` records of 128 bytes. EXM
//! follows from the block size and DSM ([DRI] Table 6-9); the directory
//! occupies the first data blocks ([DRI] Figure 6-5).

use super::header::{first_record, FileHeader, HEADER_SIZE};
use super::image::{self, Disk, Sector, Track};
use super::*;
use crate::formats::container::{self, Child, MAX_COMPONENTS, MAX_EXTRACTED};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

/// Prefix of the disk image's metadata keys.
const KEY_PREFIX: &str = "cpcdsk";

/// Transform named for a file reassembled from several stored runs.
const FILE_TRANSFORM: &str = "CP/M allocation blocks";

/// The CP/M record: the unit of file lengths.
const RECORD_SIZE: usize = 128;

/// Size of a directory entry.
const DIRECTORY_ENTRY_SIZE: usize = 32;

/// User byte of an unused or deleted entry ([CPM22F]).
const UNUSED_ENTRY: u8 = 0xe5;

/// Highest user number of a file entry ([CPM22F]: 0-15). Other values are
/// CP/M 3 password, label and time-stamp entries, or damage.
const MAX_FILE_USER: u8 = 15;

/// EX ranges over 0-31 ([DRI] Table 5-2).
const MAX_EXTENT_LOW: u8 = 31;

/// A file has at most 65536 records ([DRI] chapter 5), 512 logical extents
/// of 16 KiB, so S2 is at most 15.
const MAX_EXTENT_HIGH: u8 = 15;

/// Logical extents counted by EX before S2 increments.
const EXTENTS_PER_S2: usize = 32;

/// An RC of 0x80 marks a full logical extent ([CPM22F]).
const FULL_RECORD_COUNT: u8 = 0x80;

/// Records in one logical extent of 16 KiB.
const RECORDS_PER_EXTENT: usize = 128;

/// One-byte block numbers serve while DSM < 256 ([DRI] Table 6-9;
/// [CPM22F]).
const MAX_NARROW_BLOCKS: usize = 256;

/// DSM is a 16-bit field ([DRI] Figure 6-4).
const MAX_BLOCKS: usize = 1 << 16;

/// Bytes at the start of a headerless file read to decide whether it is a
/// recognized format.
const RECOGNITION_PREFIX: usize = 4096;

/// Headered files described one by one in the notes, and problems; further
/// ones are counted.
const MAX_FILE_NOTES: usize = 32;
const MAX_PROBLEM_NOTES: usize = 16;

/// Sector size, block size and directory of all three AMSDOS formats: BSH
/// 3, DRM 63 and AL0 0xC0 in the XDPBs ([AMSROM] `0xCA43`).
const AMSDOS_SECTOR_SIZE: usize = 512;
const AMSDOS_BLOCK_SIZE: usize = 1024;
const AMSDOS_DIRECTORY_BLOCKS: usize = 2;
const AMSDOS_CYLINDERS: usize = 40;

/// Sector IDs that select a format: the AMSDOS system and data formats,
/// and the PCW/+3 disk specification sector (also the first IBM sector).
const SYSTEM_FIRST_SECTOR: u8 = 0x41;
const DATA_FIRST_SECTOR: u8 = 0xc1;
const SPEC_SECTOR: u8 = 0x01;

/// The IBM format's eight sectors per track ([AMSROM] `0xC5C0`).
const IBM_SECTORS: usize = 8;

/// Size of the PCW/+3 disk specification at the start of sector 1.
const SPEC_SIZE: usize = 16;

/// Fill of an unwritten specification: the 173 KiB default ([AMSFMT]).
const FORMAT_FILLER: u8 = 0xe5;

// Disk specification fields ([P3MAN]).
const SPEC_DISK_TYPE: usize = 0;
const SPEC_SIDEDNESS: usize = 1;
const SPEC_TRACKS: usize = 2;
const SPEC_SECTORS: usize = 3;
const SPEC_SECTOR_SHIFT: usize = 4;
const SPEC_RESERVED_TRACKS: usize = 5;
const SPEC_BLOCK_SHIFT: usize = 6;
const SPEC_DIRECTORY_BLOCKS: usize = 7;

/// Disk types with a disk specification: PCW single-sided (and the +3) and
/// PCW double-sided. Types 1 and 2 name the CPC formats, which have no
/// boot record ([AMSFMT]).
const DISK_TYPE_PCW_SS: u8 = 0;
const DISK_TYPE_PCW_DS: u8 = 3;

/// Sidedness bits 0-1 and the reserved bits 2-5 ([P3MAN]). Bit 6 marks a
/// high-density PCW16 disk ([AMSFMT]) and bit 7 a double-track disk.
const SIDEDNESS_MASK: u8 = 0x03;
const SIDEDNESS_RESERVED: u8 = 0x3c;
const SIDES_SINGLE: u8 = 0;
const SIDES_ALTERNATE: u8 = 1;
const SIDES_SUCCESSIVE: u8 = 2;

/// Block sizes of 1-16 KiB: block shifts 3-7 ([DRI] Table 6-8).
const MIN_BLOCK_SHIFT: u8 = 3;
const MAX_BLOCK_SHIFT: u8 = 7;

/// Sector shifts up to 7 (16 KiB), the largest a three-bit size code names.
const MAX_SECTOR_SHIFT: u8 = 7;

/// AL0 and AL1 reserve at most 16 directory blocks ([DRI] Figure 6-5).
const MAX_DIRECTORY_BLOCKS: u8 = 16;

/// The 173 KiB PCW/+3 format ([P3MAN] type 0 XDPB): 40 tracks of nine
/// 512-byte sectors, one reserved track, 1 KiB blocks, two directory
/// blocks.
const DEFAULT_SPEC: [u8; 8] = [DISK_TYPE_PCW_SS, SIDES_SINGLE, 40, 9, 2, 1, 3, 2];

/// `|CPM` loads track 0 sector 0x41 at 0x0100 and starts it there, unless
/// all its bytes are equal ([AMSROM] `0xC20A`-`0xC221`, `0xC2AC`).
const CPM_BOOT_ADDRESS: u16 = 0x0100;

/// `DOS BOOT` loads side 0, track 0, sector 1 at 0xFE00 and enters it at
/// 0xFE10 when the sum of its bytes is 3 modulo 256 ([P3MAN]). Sums of 1
/// and 255 mark PCW9512 and PCW8256 bootstraps ([AMSFMT]).
const BOOT_SECTOR_SIZE: usize = 512;
const PLUS3_BOOT_SUM: u8 = 3;
const PLUS3_BOOT_ADDRESS: u16 = 0xfe00;
const PLUS3_BOOT_ENTRY: usize = 0x10;
const PCW9512_BOOT_SUM: u8 = 1;
const PCW8256_BOOT_SUM: u8 = 0xff;

/// A defect inside the filesystem: it skips the file or the directory and
/// becomes a note.
type Walk<T> = std::result::Result<T, String>;

/// How logical tracks map to the sides ([P3MAN] "Logical tracks and
/// sectors").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sidedness {
    Single,
    /// Side 0 and side 1 of each cylinder in turn.
    Alternate,
    /// Up side 0, then back down side 1 ("up and over", [AMSFMT]).
    Successive,
}

/// A physical track.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Location {
    cylinder: usize,
    head: usize,
}

/// The filesystem's layout on the disk.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Geometry {
    /// The format's name, for the notes.
    name: String,
    /// ID of logical sector 0 on every track.
    first_sector: u8,
    sectors: usize,
    sector_size: usize,
    /// Tracks per side.
    cylinders: usize,
    sidedness: Sidedness,
    /// Reserved (system) tracks before the data area.
    reserved: usize,
    block_size: usize,
    directory_blocks: usize,
    /// Allocation blocks, DSM + 1.
    blocks: usize,
    /// The format comes from a PCW/+3 disk specification.
    from_spec: bool,
}

impl Geometry {
    fn track_size(&self) -> usize {
        self.sectors * self.sector_size
    }

    /// EXM ([DRI] Table 6-9): `BLS / 1024 - 1` while DSM < 256,
    /// `BLS / 2048 - 1` otherwise.
    fn extent_mask(&self) -> usize {
        let kib = self.block_size / 1024;
        if self.blocks <= MAX_NARROW_BLOCKS {
            kib - 1
        } else {
            (kib / 2).saturating_sub(1)
        }
    }

    fn wide_block_numbers(&self) -> bool {
        self.blocks > MAX_NARROW_BLOCKS
    }

    fn directory_entries(&self) -> usize {
        self.directory_blocks * self.block_size / DIRECTORY_ENTRY_SIZE
    }

    /// The physical track that holds logical track `track`.
    fn location(&self, track: usize) -> Location {
        match self.sidedness {
            Sidedness::Single => Location {
                cylinder: track,
                head: 0,
            },
            Sidedness::Alternate => Location {
                cylinder: track / 2,
                head: track % 2,
            },
            Sidedness::Successive if track < self.cylinders => Location {
                cylinder: track,
                head: 0,
            },
            // Past the last track this names no cylinder, so the read fails.
            Sidedness::Successive => Location {
                cylinder: (2 * self.cylinders)
                    .checked_sub(track + 1)
                    .unwrap_or(usize::MAX),
                head: 1,
            },
        }
    }

    fn description(&self) -> String {
        let reserved = match self.reserved {
            0 => "no reserved tracks".to_string(),
            n => counted(n, "reserved track", "reserved tracks"),
        };
        format!(
            "{}: {} sectors of {} B per track from ID 0x{:02X}, {reserved}, {} KiB blocks, \
             {} blocks, {} directory entries",
            self.name,
            self.sectors,
            self.sector_size,
            self.first_sector,
            self.block_size / 1024,
            self.blocks,
            self.directory_entries()
        )
    }
}

/// An AMSDOS format's XDPB values that differ between formats ([AMSROM]
/// `0xCA43` system, `0xC5C0` IBM, `0xC5CA` data).
struct AmsdosFormat {
    name: &'static str,
    first_sector: u8,
    sectors: usize,
    reserved: usize,
    /// DSM + 1.
    blocks: usize,
}

const SYSTEM_FORMAT: AmsdosFormat = AmsdosFormat {
    name: "AMSDOS system format",
    first_sector: SYSTEM_FIRST_SECTOR,
    sectors: 9,
    reserved: 2,
    blocks: 0xaa + 1,
};

const DATA_FORMAT: AmsdosFormat = AmsdosFormat {
    name: "AMSDOS data format",
    first_sector: DATA_FIRST_SECTOR,
    sectors: 9,
    reserved: 0,
    blocks: 0xb3 + 1,
};

const IBM_FORMAT: AmsdosFormat = AmsdosFormat {
    name: "AMSDOS IBM format",
    first_sector: SPEC_SECTOR,
    sectors: IBM_SECTORS,
    reserved: 1,
    blocks: 0x9b + 1,
};

impl AmsdosFormat {
    fn geometry(&self) -> Geometry {
        Geometry {
            name: self.name.to_string(),
            first_sector: self.first_sector,
            sectors: self.sectors,
            sector_size: AMSDOS_SECTOR_SIZE,
            cylinders: AMSDOS_CYLINDERS,
            sidedness: Sidedness::Single,
            reserved: self.reserved,
            block_size: AMSDOS_BLOCK_SIZE,
            directory_blocks: AMSDOS_DIRECTORY_BLOCKS,
            blocks: self.blocks,
            from_spec: false,
        }
    }
}

/// The geometry a PCW/+3 disk specification describes ([P3MAN]), with DSM
/// from the data area's size ([LIBDSK] `set_pcw_fs`).
fn spec_geometry(spec: &[u8], name: String) -> Walk<Geometry> {
    let field = |at: usize| spec.get(at).copied().unwrap_or(0);
    let disk_type = field(SPEC_DISK_TYPE);
    if disk_type != DISK_TYPE_PCW_SS && disk_type != DISK_TYPE_PCW_DS {
        return Err(format!("disk type {disk_type} is not a PCW or +3 type"));
    }
    let sidedness_byte = field(SPEC_SIDEDNESS);
    let sidedness = match sidedness_byte & SIDEDNESS_MASK {
        SIDES_SINGLE => Sidedness::Single,
        SIDES_ALTERNATE => Sidedness::Alternate,
        SIDES_SUCCESSIVE => Sidedness::Successive,
        _ => return Err("sidedness 3 is reserved".to_string()),
    };
    if sidedness_byte & SIDEDNESS_RESERVED != 0 {
        return Err(format!(
            "reserved sidedness bits are set (0x{sidedness_byte:02X})"
        ));
    }
    let cylinders = usize::from(field(SPEC_TRACKS));
    let sectors = usize::from(field(SPEC_SECTORS));
    if cylinders == 0 || sectors == 0 {
        return Err("no tracks or no sectors per track".to_string());
    }
    let sector_shift = field(SPEC_SECTOR_SHIFT);
    let block_shift = field(SPEC_BLOCK_SHIFT);
    let directory_blocks = field(SPEC_DIRECTORY_BLOCKS);
    if sector_shift > MAX_SECTOR_SHIFT {
        return Err(format!("sector size code {sector_shift} is too large"));
    }
    if !(MIN_BLOCK_SHIFT..=MAX_BLOCK_SHIFT).contains(&block_shift) {
        return Err(format!("block shift {block_shift} is not 3-7"));
    }
    if directory_blocks == 0 || directory_blocks > MAX_DIRECTORY_BLOCKS {
        return Err(format!("{directory_blocks} directory blocks"));
    }
    let heads = if sidedness == Sidedness::Single { 1 } else { 2 };
    let reserved = usize::from(field(SPEC_RESERVED_TRACKS));
    let data_tracks = (cylinders * heads)
        .checked_sub(reserved)
        .filter(|&n| n > 0)
        .ok_or_else(|| format!("all {} tracks are reserved", cylinders * heads))?;
    let sector_size = RECORD_SIZE << sector_shift;
    let block_size = RECORD_SIZE << block_shift;
    let blocks = data_tracks * sectors * sector_size / block_size;
    if blocks <= usize::from(directory_blocks) || blocks > MAX_BLOCKS {
        return Err(format!("{blocks} blocks do not fit a CP/M directory"));
    }
    if blocks > MAX_NARROW_BLOCKS && block_size == AMSDOS_BLOCK_SIZE {
        return Err(format!(
            "{blocks} blocks of 1 KiB have no extent mask ([DRI] Table 6-9)"
        ));
    }
    Ok(Geometry {
        name,
        first_sector: SPEC_SECTOR,
        sectors,
        sector_size,
        cylinders,
        sidedness,
        reserved,
        block_size,
        directory_blocks: usize::from(directory_blocks),
        blocks,
        from_spec: true,
    })
}

/// The filesystem geometry of `disk`, or why it has none.
fn select(disk: &Disk<'_>) -> Walk<Geometry> {
    let track = disk
        .track(0, 0)
        .filter(|t| !t.sectors.is_empty())
        .ok_or("track 0 side 0 is unformatted")?;
    match track.lowest_id() {
        Some(SYSTEM_FIRST_SECTOR) => Ok(SYSTEM_FORMAT.geometry()),
        Some(DATA_FIRST_SECTOR) => Ok(DATA_FORMAT.geometry()),
        Some(SPEC_SECTOR) => spec_or_ibm(track),
        lowest => Err(format!(
            "the lowest sector ID on track 0 is 0x{:02X}, not 0x41, 0xC1 or 0x01",
            lowest.unwrap_or_default()
        )),
    }
}

/// A track 0 whose lowest sector ID is 1: a PCW/+3 disk specification in
/// sector 1, the default format when the specification is unwritten, or
/// the AMSDOS IBM format.
fn spec_or_ibm(track: &Track<'_>) -> Walk<Geometry> {
    let spec = track
        .sector(u16::from(SPEC_SECTOR))
        .and_then(|s| s.data.get(..SPEC_SIZE))
        .ok_or("sector 1 of track 0 is shorter than a disk specification")?;
    let described = spec_geometry(
        spec,
        format!(
            "+3DOS/PCW disk specification (disk type {})",
            spec[SPEC_DISK_TYPE]
        ),
    );
    let unwritten = spec.iter().all(|&b| b == FORMAT_FILLER);
    let ibm = track.sectors.len() == IBM_SECTORS
        && (u16::from(SPEC_SECTOR)..)
            .take(IBM_SECTORS)
            .all(|id| track.sector(id).is_some());
    match described {
        Ok(geometry) => Ok(geometry),
        Err(_) if unwritten && !ibm => spec_geometry(
            &DEFAULT_SPEC,
            "+3DOS/PCW default format (the disk specification is unwritten)".to_string(),
        ),
        Err(_) if ibm => Ok(IBM_FORMAT.geometry()),
        Err(reason) => Err(format!(
            "sector 1 of track 0 holds no valid disk specification ({reason}) and the track is \
             not in the AMSDOS IBM format"
        )),
    }
}

/// Stored bytes in the input: a sector's data or part of it.
#[derive(Debug, Clone, Copy)]
struct Piece<'a> {
    /// File offset.
    offset: usize,
    bytes: &'a [u8],
}

/// Append `piece`, merging it into the last one when it continues it in
/// the file.
fn push_piece<'a>(pieces: &mut Vec<Piece<'a>>, data: &'a [u8], piece: Piece<'a>) {
    if let Some(last) = pieces.last_mut() {
        if last.offset + last.bytes.len() == piece.offset {
            // Both pieces are slices of `data` at their offsets, so the
            // merged range lies in `data`.
            let end = piece.offset + piece.bytes.len();
            last.bytes = &data[last.offset..end];
            return;
        }
    }
    pieces.push(piece);
}

fn concatenate(pieces: &[Piece<'_>]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(pieces.iter().map(|p| p.bytes.len()).sum());
    for piece in pieces {
        bytes.extend_from_slice(piece.bytes);
    }
    bytes
}

/// A block of a file and the bytes of it the file uses.
#[derive(Debug, Clone, Copy)]
struct UsedBlock {
    number: usize,
    len: usize,
}

/// Where a file's bytes are.
#[derive(Debug)]
struct FileLayout {
    blocks: Vec<UsedBlock>,
    /// File size in bytes (whole records).
    size: usize,
}

/// One directory entry of a file.
#[derive(Debug, Clone)]
struct Extent {
    /// Entry number within the file.
    number: usize,
    /// Records the entry holds.
    records: usize,
    /// Allocation block numbers, unallocated (0) ones included.
    blocks: Vec<usize>,
}

/// A file of the directory: its entries in directory order.
#[derive(Debug)]
struct FileEntry {
    user: u8,
    /// Name and type with attribute bits cleared.
    name: [u8; 11],
    extents: Vec<Extent>,
}

impl FileEntry {
    /// `user:NAME.EXT`.
    fn label(&self) -> String {
        format!("{}:{}", self.user, file_name(&self.name))
    }
}

/// What a directory entry is.
enum Entry {
    Unused,
    /// A user byte of 16 or more: CP/M 3 password, label or time-stamp
    /// entries, or damage.
    Other,
    Invalid,
    File {
        user: u8,
        name: [u8; 11],
        extent: Extent,
    },
}

/// Classify one 32-byte directory entry.
fn parse_entry(entry: &[u8], geometry: &Geometry) -> Entry {
    let user = entry[0];
    if user == UNUSED_ENTRY {
        return Entry::Unused;
    }
    if user > MAX_FILE_USER {
        return Entry::Other;
    }
    let mut name = [0u8; 11];
    for (character, &stored) in name.iter_mut().zip(&entry[1..12]) {
        *character = stored & !ATTRIBUTE_BIT;
    }
    let printable = name[0] != b' ' && name.iter().all(|&b| b == b' ' || b.is_ascii_graphic());
    let (low, high, record_count) = (entry[12], entry[14], entry[15]);
    if !printable
        || low > MAX_EXTENT_LOW
        || high > MAX_EXTENT_HIGH
        || record_count > FULL_RECORD_COUNT
    {
        return Entry::Invalid;
    }
    let mask = geometry.extent_mask();
    let logical = usize::from(high) * EXTENTS_PER_S2 + usize::from(low);
    let allocation = &entry[16..DIRECTORY_ENTRY_SIZE];
    let blocks = if geometry.wide_block_numbers() {
        allocation
            .chunks_exact(2)
            .map(|pair| usize::from(u16::from_le_bytes([pair[0], pair[1]])))
            .collect()
    } else {
        allocation.iter().map(|&b| usize::from(b)).collect()
    };
    Entry::File {
        user,
        name,
        extent: Extent {
            number: logical / (mask + 1),
            records: (usize::from(low) & mask) * RECORDS_PER_EXTENT + usize::from(record_count),
            blocks,
        },
    }
}

/// What the walk found and left out, for the notes.
#[derive(Debug, Default)]
struct Census {
    entries: usize,
    unused: usize,
    other: usize,
    invalid: usize,
    files: usize,
    extents: usize,
    amsdos: usize,
    plus3: usize,
    /// Headerless files in a recognized format, listed.
    members: usize,
    /// Headerless files not in a recognized format, not listed.
    unrecognized: usize,
    empty: usize,
    /// Files sharing a block with an earlier file.
    cross_linked: usize,
    unexamined: usize,
    over_budget: usize,
    file_notes: Vec<String>,
    unlisted_file_notes: usize,
    problems: Vec<String>,
    unlisted_problems: usize,
}

impl Census {
    fn problem(&mut self, text: String) {
        if self.problems.len() < MAX_PROBLEM_NOTES {
            self.problems.push(text);
        } else {
            self.unlisted_problems += 1;
        }
    }

    fn file_note(&mut self, text: String) {
        if self.file_notes.len() < MAX_FILE_NOTES {
            self.file_notes.push(text);
        } else {
            self.unlisted_file_notes += 1;
        }
    }

    fn report(self, c: &mut Container<'_>) {
        c.notes.push(format!(
            "CP/M directory: {} entries; {} in {}; {} unused",
            self.entries,
            counted(self.files, "file", "files"),
            counted(self.extents, "entry", "entries"),
            self.unused
        ));
        c.notes.push(format!(
            "Files: {} with an AMSDOS header, {} with a +3DOS header, {} headerless in a \
             recognized format, {} headerless in no recognized format (not listed), {} empty",
            self.amsdos, self.plus3, self.members, self.unrecognized, self.empty
        ));
        if self.other > 0 {
            c.notes.push(format!(
                "{} a user byte of 16 or more (CP/M 3 password, label or time-stamp entries); \
                 ignored",
                counted(self.other, "directory entry has", "directory entries have")
            ));
        }
        if self.invalid > 0 {
            c.notes.push(format!(
                "{} skipped: unprintable name or extent fields out of range",
                counted(
                    self.invalid,
                    "invalid directory entry",
                    "invalid directory entries"
                )
            ));
        }
        c.notes.extend(self.file_notes);
        if self.unlisted_file_notes > 0 {
            c.notes.push(format!(
                "{} not described",
                counted(
                    self.unlisted_file_notes,
                    "further headered file is",
                    "further headered files are"
                )
            ));
        }
        if self.cross_linked > 0 {
            c.notes.push(format!(
                "{} blocks with an earlier file (cross-linked)",
                counted(self.cross_linked, "file shares", "files share")
            ));
        }
        if self.unexamined > 0 {
            c.notes.push(format!(
                "{} not examined: at most {MAX_COMPONENTS} components are listed",
                counted(self.unexamined, "file was", "files were")
            ));
        }
        if self.over_budget > 0 {
            c.notes.push(format!(
                "{} not extracted: the {} MiB total extraction limit was reached",
                counted(self.over_budget, "file was", "files were"),
                MAX_EXTRACTED >> 20
            ));
        }
        c.notes.extend(self.problems);
        if self.unlisted_problems > 0 {
            c.notes.push(format!(
                "{} not listed",
                counted(
                    self.unlisted_problems,
                    "further problem was",
                    "further problems were"
                )
            ));
        }
        let prefix = KEY_PREFIX;
        c.push_metadata(
            format!("{prefix}_file_count"),
            "Files in the directory",
            self.files as u64,
        );
        c.push_metadata(
            format!("{prefix}_headered_file_count"),
            "Files with an AMSDOS or +3DOS header",
            (self.amsdos + self.plus3) as u64,
        );
    }
}

/// A disk's filesystem being walked.
struct Volume<'v, 'a> {
    data: &'a [u8],
    disk: &'v Disk<'a>,
    geometry: Geometry,
    census: Census,
    /// Bytes of all children so far, against [`MAX_EXTRACTED`].
    extracted: usize,
    /// Blocks used by the files examined so far.
    used: Vec<bool>,
}

impl<'v, 'a> Volume<'v, 'a> {
    fn new(data: &'a [u8], disk: &'v Disk<'a>, geometry: Geometry) -> Self {
        let blocks = geometry.blocks;
        Self {
            data,
            disk,
            geometry,
            census: Census::default(),
            extracted: 0,
            used: vec![false; blocks],
        }
    }

    /// The sector holding logical sector `index` of logical track `track`,
    /// with at least a sector's worth of stored data.
    fn sector(&self, track: usize, index: usize) -> Walk<&'v Sector<'a>> {
        let Location { cylinder, head } = self.geometry.location(track);
        // Sector IDs are 8-bit: a sum past 0xFF names no sector.
        let id = u16::from(self.geometry.first_sector)
            .saturating_add(u16::try_from(index).unwrap_or(u16::MAX));
        let track = self.disk.track(cylinder, head).ok_or_else(|| {
            format!("track {cylinder} side {head} is unformatted or not in the image")
        })?;
        let sector = track.sector(id).ok_or_else(|| {
            format!("sector 0x{id:02X} of track {cylinder} side {head} is missing")
        })?;
        if sector.data.len() < self.geometry.sector_size {
            return Err(format!(
                "sector 0x{id:02X} of track {cylinder} side {head} stores {} B of the format's \
                 {} B",
                sector.data.len(),
                self.geometry.sector_size
            ));
        }
        Ok(sector)
    }

    /// The stored pieces of data-area bytes `start..start + len`.
    fn read(&self, start: usize, len: usize, pieces: &mut Vec<Piece<'a>>) -> Walk<()> {
        let track_size = self.geometry.track_size();
        let sector_size = self.geometry.sector_size;
        let end = start + len;
        let mut address = start;
        while address < end {
            let track = self.geometry.reserved + address / track_size;
            let index = (address % track_size) / sector_size;
            let within = address % sector_size;
            let take = (sector_size - within).min(end - address);
            let sector = self.sector(track, index)?;
            push_piece(
                pieces,
                self.data,
                Piece {
                    offset: sector.offset + within,
                    bytes: &sector.data[within..within + take],
                },
            );
            address += take;
        }
        Ok(())
    }

    /// The directory's bytes: the first data blocks.
    fn directory(&self) -> Walk<Vec<u8>> {
        let mut pieces = Vec::new();
        self.read(
            0,
            self.geometry.directory_blocks * self.geometry.block_size,
            &mut pieces,
        )?;
        Ok(concatenate(&pieces))
    }

    /// Group the directory's file entries by user and name, in directory
    /// order.
    fn files(&mut self, directory: &[u8]) -> Vec<FileEntry> {
        let mut index: BTreeMap<(u8, [u8; 11]), usize> = BTreeMap::new();
        let mut files: Vec<FileEntry> = Vec::new();
        for entry in directory.chunks_exact(DIRECTORY_ENTRY_SIZE) {
            self.census.entries += 1;
            match parse_entry(entry, &self.geometry) {
                Entry::Unused => self.census.unused += 1,
                Entry::Other => self.census.other += 1,
                Entry::Invalid => self.census.invalid += 1,
                Entry::File { user, name, extent } => {
                    self.census.extents += 1;
                    let position = *index.entry((user, name)).or_insert_with(|| {
                        files.push(FileEntry {
                            user,
                            name,
                            extents: Vec::new(),
                        });
                        files.len() - 1
                    });
                    files[position].extents.push(extent);
                }
            }
        }
        self.census.files = files.len();
        files
    }

    /// The blocks of `file` in order: every extent present once, every
    /// extent but the last full, and every block a distinct data block.
    fn layout(&self, file: &FileEntry) -> Walk<FileLayout> {
        let geometry = &self.geometry;
        let mut extents = file.extents.clone();
        extents.sort_by_key(|e| e.number);
        let capacity = (geometry.extent_mask() + 1) * RECORDS_PER_EXTENT;
        let mut claimed = BTreeSet::new();
        let mut blocks = Vec::new();
        let mut size = 0;
        for (expected, extent) in extents.iter().enumerate() {
            if extent.number != expected {
                return Err(if extent.number < expected {
                    format!("extent {} appears twice", extent.number)
                } else {
                    format!("extent {expected} is missing")
                });
            }
            if expected + 1 < extents.len() && extent.records != capacity {
                return Err(format!(
                    "extent {expected} holds {} of {capacity} records (a sparse file)",
                    extent.records
                ));
            }
            let mut remaining = extent.records * RECORD_SIZE;
            let needed = div_round_up(remaining, geometry.block_size);
            let listed = extent.blocks.get(..needed).ok_or_else(|| {
                format!("extent {expected} needs {needed} blocks; its entry lists fewer")
            })?;
            for &number in listed {
                if number == 0 {
                    return Err(format!(
                        "extent {expected} leaves a block of its records unallocated"
                    ));
                }
                if number < geometry.directory_blocks {
                    return Err(format!("block {number} is a directory block"));
                }
                if number >= geometry.blocks {
                    return Err(format!(
                        "block {number} is beyond the format's {} blocks",
                        geometry.blocks
                    ));
                }
                if !claimed.insert(number) {
                    return Err(format!("block {number} appears twice"));
                }
                let len = remaining.min(geometry.block_size);
                blocks.push(UsedBlock { number, len });
                remaining -= len;
            }
            size += extent.records * RECORD_SIZE;
        }
        Ok(FileLayout { blocks, size })
    }

    /// The stored pieces of file bytes `start..start + len`.
    fn file_pieces(&self, layout: &FileLayout, start: usize, len: usize) -> Walk<Vec<Piece<'a>>> {
        let end = start + len;
        let mut pieces = Vec::new();
        let mut position = 0;
        for block in &layout.blocks {
            let block_end = position + block.len;
            if block_end > start && position < end {
                let from = start.max(position) - position;
                let to = end.min(block_end) - position;
                self.read(
                    block.number * self.geometry.block_size + from,
                    to - from,
                    &mut pieces,
                )?;
            }
            if block_end >= end {
                break;
            }
            position = block_end;
        }
        Ok(pieces)
    }

    /// Record the blocks of a file and count it when an earlier file uses
    /// one of them.
    fn claim(&mut self, layout: &FileLayout) {
        let mut shared = false;
        for block in &layout.blocks {
            shared |= self.used[block.number];
            self.used[block.number] = true;
        }
        self.census.cross_linked += usize::from(shared);
    }

    /// Whether `size` more bytes fit the extraction limit; charges them.
    fn charge(&mut self, size: usize) -> bool {
        if self.extracted + size > MAX_EXTRACTED {
            self.census.over_budget += 1;
            return false;
        }
        self.extracted += size;
        true
    }

    /// Examine one file: list it when it has a header or is a recognized
    /// format.
    fn file(&mut self, file: &FileEntry, c: &mut Container<'a>) {
        let label = file.label();
        let layout = match self.layout(file) {
            Ok(layout) => layout,
            Err(defect) => {
                self.census.problem(format!("Skipped {label}: {defect}"));
                return;
            }
        };
        self.claim(&layout);
        if layout.size == 0 {
            self.census.empty += 1;
            return;
        }
        if c.children.len() >= MAX_COMPONENTS {
            self.census.unexamined += 1;
            return;
        }
        let record = match self.file_pieces(&layout, 0, layout.size.min(HEADER_SIZE)) {
            Ok(pieces) => concatenate(&pieces),
            Err(defect) => {
                self.census.problem(format!("Skipped {label}: {defect}"));
                return;
            }
        };
        match first_record(&record).and_then(FileHeader::parse) {
            Some(header) => self.headered(label, &layout, &header, c),
            None => self.headerless(label, &layout, c),
        }
    }

    /// A file with an AMSDOS or +3DOS header: its body as Z80 code when the
    /// header says it is machine code, as opaque data otherwise.
    fn headered(
        &mut self,
        label: String,
        layout: &FileLayout,
        header: &FileHeader,
        c: &mut Container<'a>,
    ) {
        match header {
            FileHeader::Amsdos(_) => self.census.amsdos += 1,
            FileHeader::Plus3(_) => self.census.plus3 += 1,
        }
        let description = header.describe();
        let stored = layout.size - HEADER_SIZE;
        let declared = header.body_length();
        let length = declared.min(stored);
        let mismatch = if declared > stored {
            format!("; the header declares {declared} B, the directory {stored} B")
        } else {
            String::new()
        };
        self.census.file_note(format!(
            "{label}: {}; {length} B{mismatch}",
            description.summary
        ));
        if length == 0 || !self.charge(length) {
            return;
        }
        let pieces = match self.file_pieces(layout, HEADER_SIZE, length) {
            Ok(pieces) => pieces,
            Err(defect) => {
                self.census.problem(format!("Skipped {label}: {defect}"));
                return;
            }
        };
        let child = child_from(label, &pieces);
        c.children.push(if description.load.is_some() {
            child.with_target(Z80).with_variant(CPU_VARIANT).as_code()
        } else {
            Child {
                opaque: true,
                ..child
            }
        });
    }

    /// A headerless file: listed when its first bytes are a recognized
    /// format.
    fn headerless(&mut self, label: String, layout: &FileLayout, c: &mut Container<'a>) {
        let prefix = match self.file_pieces(layout, 0, layout.size.min(RECOGNITION_PREFIX)) {
            Ok(pieces) => concatenate(&pieces),
            Err(defect) => {
                self.census.problem(format!("Skipped {label}: {defect}"));
                return;
            }
        };
        if !container::is_recognized(&prefix) {
            self.census.unrecognized += 1;
            return;
        }
        if !self.charge(layout.size) {
            return;
        }
        match self.file_pieces(layout, 0, layout.size) {
            Ok(pieces) => {
                c.children.push(child_from(label, &pieces).if_recognized());
                self.census.members += 1;
            }
            Err(defect) => self.census.problem(format!("Skipped {label}: {defect}")),
        }
    }

    /// The boot sector the format's system executes, as a Z80 child after
    /// the files: the CP/M boot sector of the system format, or a +3
    /// bootstrap in the disk specification sector.
    fn boot_sector(&self, c: &mut Container<'a>) {
        let Some(track) = self.disk.track(0, 0) else {
            return;
        };
        if self.geometry.first_sector == SYSTEM_FIRST_SECTOR {
            cpm_boot_sector(track, c);
        } else if self.geometry.from_spec {
            plus3_boot_sector(track, c);
        }
    }
}

/// `value` divided by `divisor`, rounded up. `divisor` is not zero.
fn div_round_up(value: usize, divisor: usize) -> usize {
    value / divisor + usize::from(value % divisor != 0)
}

/// A child of `pieces`: borrowed when they are one stored run, reassembled
/// otherwise with the first run as its stored range.
fn child_from<'a>(label: String, pieces: &[Piece<'a>]) -> Child<'a> {
    if let [single] = pieces {
        return Child::stored(label, single.offset, single.bytes);
    }
    let first = pieces.first().copied().unwrap_or(Piece {
        offset: 0,
        bytes: &[],
    });
    Child::decoded(
        label,
        first.offset,
        first.bytes.len(),
        Cow::Owned(concatenate(pieces)),
        FILE_TRANSFORM,
    )
}

/// The first 512 bytes of sector `id` of `track`, if it stores them.
fn boot_sector_bytes<'a>(track: &Track<'a>, id: u8) -> Option<Piece<'a>> {
    let sector = track.sector(u16::from(id))?;
    Some(Piece {
        offset: sector.offset,
        bytes: sector.data.get(..BOOT_SECTOR_SIZE)?,
    })
}

/// The system format's CP/M boot sector, unless it holds one repeated byte
/// (a vendor-format disk, on which `|CPM` fails).
fn cpm_boot_sector<'a>(track: &Track<'a>, c: &mut Container<'a>) {
    let Some(Piece { offset, bytes }) = boot_sector_bytes(track, SYSTEM_FIRST_SECTOR) else {
        c.notes
            .push("Track 0 has no 512 B sector 0x41: no CP/M boot sector".to_string());
        return;
    };
    if bytes.iter().all(|&b| b == bytes[0]) {
        c.notes.push(format!(
            "Track 0 sector 0x41 is filled with 0x{:02X}: no CP/M boot sector",
            bytes[0]
        ));
        return;
    }
    c.notes.push(format!(
        "CP/M boot sector at 0x{offset:X} (512 B): AMSDOS |CPM loads it at \
         0x{CPM_BOOT_ADDRESS:04X} and starts it there"
    ));
    c.children.push(
        Child::stored("CP/M boot sector (track 0, sector 0x41)", offset, bytes)
            .with_target(Z80)
            .with_variant(CPU_VARIANT)
            .as_code(),
    );
}

/// A +3 bootstrap in the disk specification sector, recognized by its
/// checksum; PCW bootstraps are only noted.
fn plus3_boot_sector<'a>(track: &Track<'a>, c: &mut Container<'a>) {
    let Some(Piece { offset, bytes }) = boot_sector_bytes(track, SPEC_SECTOR) else {
        return;
    };
    let sum = bytes.iter().fold(0u8, |sum, &b| sum.wrapping_add(b));
    match sum {
        PLUS3_BOOT_SUM => {
            let entry = PLUS3_BOOT_ADDRESS + u16::try_from(PLUS3_BOOT_ENTRY).unwrap_or_default();
            c.notes.push(format!(
                "Spectrum +3 bootstrap at 0x{offset:X} (sector checksum 3): DOS BOOT loads the \
                 sector at 0x{PLUS3_BOOT_ADDRESS:04X} and enters it at 0x{entry:04X}"
            ));
            c.children.push(
                Child::stored(
                    "+3 bootstrap (track 0, sector 1)",
                    offset + PLUS3_BOOT_ENTRY,
                    &bytes[PLUS3_BOOT_ENTRY..],
                )
                .with_target(Z80)
                .with_variant(CPU_VARIANT)
                .as_code(),
            );
        }
        PCW9512_BOOT_SUM | PCW8256_BOOT_SUM => {
            let model = if sum == PCW9512_BOOT_SUM {
                "PCW9512"
            } else {
                "PCW8256"
            };
            c.notes.push(format!(
                "Sector 1 of track 0 holds a {model} bootstrap (sector checksum 0x{sum:02X}); not \
                 analyzed"
            ));
        }
        _ => {}
    }
}

/// Parse a disk image: its tracks, then the CP/M filesystem when track 0
/// selects a format.
pub(super) fn parse_disk(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let disk = image::parse(data, layout)?;
    let mut c = Container::new(FileFormat::CpcDsk, layout.label(), KEY_PREFIX);
    c.consumed = data.len();
    c.notes.push(disk.summary(layout));
    let filesystem = match select(&disk) {
        Ok(geometry) => {
            let name = geometry.name.clone();
            c.notes.push(geometry.description());
            walk(data, &disk, geometry, &mut c);
            name
        }
        Err(reason) => {
            c.notes.push(format!("No CP/M filesystem: {reason}"));
            "none".to_string()
        }
    };
    let census = disk.census();
    census.report(&mut c);
    c.notes.extend(disk.trailing_note(data));
    let prefix = KEY_PREFIX;
    c.push_metadata(format!("{prefix}_creator"), "Creator", disk.creator.clone());
    c.push_metadata(
        format!("{prefix}_tracks"),
        "Tracks per side",
        disk.cylinders as u64,
    );
    c.push_metadata(format!("{prefix}_sides"), "Sides", disk.sides as u64);
    c.push_metadata(
        format!("{prefix}_unformatted_tracks"),
        "Unformatted tracks",
        census.unformatted as u64,
    );
    c.push_metadata(format!("{prefix}_filesystem"), "Filesystem", filesystem);
    Ok(c)
}

/// Read the directory and list the files and the boot sector.
fn walk<'a>(data: &'a [u8], disk: &Disk<'a>, geometry: Geometry, c: &mut Container<'a>) {
    let mut volume = Volume::new(data, disk, geometry);
    let directory = match volume.directory() {
        Ok(directory) => directory,
        Err(defect) => {
            c.notes.push(format!(
                "CP/M directory unreadable: {defect}; no files listed"
            ));
            volume.boot_sector(c);
            return;
        }
    };
    let files = volume.files(&directory);
    for file in &files {
        volume.file(file, c);
    }
    volume.boot_sector(c);
    volume.census.report(c);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(bytes: [u8; 8]) -> Walk<Geometry> {
        spec_geometry(&bytes, "test".to_string())
    }

    #[test]
    fn amsdos_formats_match_their_xdpbs() {
        // DSM + 1 = (40 - OFF) tracks × SPT records × 128 / 1024 ([P3MAN]).
        for format in [&SYSTEM_FORMAT, &DATA_FORMAT, &IBM_FORMAT] {
            let geometry = format.geometry();
            let data_tracks = AMSDOS_CYLINDERS - geometry.reserved;
            assert_eq!(
                geometry.blocks,
                data_tracks * geometry.track_size() / AMSDOS_BLOCK_SIZE,
                "{}",
                geometry.name
            );
            assert_eq!(geometry.directory_entries(), 64);
            assert_eq!(geometry.extent_mask(), 0);
        }
    }

    #[test]
    fn the_default_specification_is_the_plus3_format() {
        let geometry = spec(DEFAULT_SPEC).unwrap();
        // [P3MAN] type 0 XDPB: DSM 174, DRM 63, OFF 1.
        assert_eq!(geometry.blocks, 175);
        assert_eq!(geometry.directory_entries(), 64);
        assert_eq!(geometry.reserved, 1);
    }

    #[test]
    fn specifications_reject_impossible_geometry() {
        // PCW 720 KiB ([AMSFMT]): double-sided, 80 tracks, 2 KiB blocks,
        // DSM 0x164, EXM 0, 16-bit block numbers.
        let pcw720 = spec([3, 0x81, 80, 9, 2, 1, 4, 4]).unwrap();
        assert_eq!(pcw720.blocks, 0x165);
        assert_eq!(pcw720.extent_mask(), 0);
        assert!(pcw720.wide_block_numbers());
        assert!(spec([1, 0, 40, 9, 2, 1, 3, 2]).is_err());
        assert!(spec([0, 3, 40, 9, 2, 1, 3, 2]).is_err());
        assert!(spec([0, 0, 40, 9, 2, 40, 3, 2]).is_err());
        assert!(spec([0, 0, 40, 9, 2, 1, 2, 2]).is_err());
        assert!(spec([0, 0, 40, 9, 2, 1, 3, 17]).is_err());
        // 1 KiB blocks on a disk of more than 256 blocks have no EXM.
        assert!(spec([3, 1, 80, 9, 2, 1, 3, 2]).is_err());
    }

    #[test]
    fn successive_sides_run_back_down_side_one() {
        let geometry = Geometry {
            sidedness: Sidedness::Successive,
            ..spec([3, 2, 40, 9, 2, 1, 4, 4]).unwrap()
        };
        assert_eq!(
            geometry.location(39),
            Location {
                cylinder: 39,
                head: 0
            }
        );
        assert_eq!(
            geometry.location(40),
            Location {
                cylinder: 39,
                head: 1
            }
        );
        assert_eq!(
            geometry.location(79),
            Location {
                cylinder: 0,
                head: 1
            }
        );
        assert_eq!(geometry.location(80).cylinder, usize::MAX);
        let alternate = Geometry {
            sidedness: Sidedness::Alternate,
            ..geometry
        };
        assert_eq!(
            alternate.location(3),
            Location {
                cylinder: 1,
                head: 1
            }
        );
    }

    #[test]
    fn entries_split_extents_by_the_extent_mask() {
        // 2 KiB blocks below 256 blocks: EXM 1, so EX 3 is entry 1 holding
        // 128 + RC records.
        let geometry = spec([0, 0, 40, 9, 2, 1, 4, 2]).unwrap();
        assert_eq!(geometry.extent_mask(), 1);
        let mut entry = [0u8; 32];
        entry[1..12].copy_from_slice(b"DATA    BIN");
        entry[12] = 3;
        entry[15] = 0x10;
        entry[16] = 5;
        let Entry::File { extent, .. } = parse_entry(&entry, &geometry) else {
            panic!("a file entry");
        };
        assert_eq!(extent.number, 1);
        assert_eq!(extent.records, 128 + 0x10);
        entry[15] = 0x81;
        assert!(matches!(parse_entry(&entry, &geometry), Entry::Invalid));
        entry[0] = 0x20;
        assert!(matches!(parse_entry(&entry, &geometry), Entry::Other));
        entry[0] = UNUSED_ENTRY;
        assert!(matches!(parse_entry(&entry, &geometry), Entry::Unused));
    }
}
