//! DOS 3.3 volumes ([BAD] chapter 4; [CP2] `DOS-notes.md`, `DOS.cs`,
//! `DOS_VTOC.cs`, `DOS_FileEntry.cs`). Multi-byte fields are little-endian.
//!
//! - VTOC, track 17 sector 0 ([BAD] p. 4-3): first catalog track and sector
//!   (0x01, 0x02), DOS release (0x03; 3 for DOS 3.3), volume number (0x06),
//!   track/sector pairs per list (0x27; 122), tracks (0x34), sectors per
//!   track (0x35; 16), bytes per sector (0x36, 2 bytes; 256).
//! - Catalog sector ([BAD] p. 4-6): next catalog track and sector (0x01,
//!   0x02; track 0 ends the chain), then seven 35-byte entries from 0x0B:
//!   track and sector of the first track/sector list (0x00, 0x01; track 0x00
//!   never used, 0xFF deleted), file type (0x02; 0x80 locked), name (0x03,
//!   30 high-bit ASCII bytes padded with spaces), sectors (0x21, 2 bytes).
//! - Track/sector list ([BAD] p. 4-8): next list track and sector (0x01,
//!   0x02), the sector offset in the file of its first pair (0x05, 2 bytes),
//!   122 data track/sector pairs from 0x0C (track 0: sparse or past the
//!   end).
//! - A binary (`B`) file starts with its load address and length, 2 bytes
//!   each, followed by "an exact copy of the memory involved" ([BAD]
//!   p. 4-12).

use super::*;
use std::fmt;

/// Where the VTOC is on every DOS disk ([BAD] p. 4-2).
const VTOC_TRACK: usize = 17;
const VTOC_SECTOR: usize = 0;

/// VTOC fields ([BAD] p. 4-3).
const VTOC_CATALOG: usize = 0x01;
const VTOC_RELEASE: usize = 0x03;
const VTOC_VOLUME: usize = 0x06;
const VTOC_PAIRS_PER_LIST: usize = 0x27;
const VTOC_TRACKS: usize = 0x34;
const VTOC_SECTORS: usize = 0x35;
const VTOC_SECTOR_SIZE: usize = 0x36;

/// The release number DOS 3.3 writes ([CP2] `DOS.Format`).
const DOS_33_RELEASE: u8 = 3;

/// Track/sector pairs in a list sector of 256 bytes ([BAD] p. 4-3).
const PAIRS_PER_LIST: usize = 122;

/// 35-track floppies and 40-track drives ([CP2] `DOS.sExpectedSizes`).
const SUPPORTED_TRACKS: [usize; 2] = [35, 40];

/// The next-sector link of catalog and track/sector list sectors.
const NEXT_LINK: usize = 0x01;

/// Catalog entries ([BAD] p. 4-6).
const FIRST_ENTRY: usize = 0x0b;
const ENTRY_SIZE: usize = 35;
const ENTRIES_PER_SECTOR: usize = 7;
const _: () = assert!(FIRST_ENTRY + ENTRIES_PER_SECTOR * ENTRY_SIZE == SECTOR_SIZE);

/// Entry fields.
const ENTRY_LIST: usize = 0x00;
const ENTRY_TYPE: usize = 0x02;
const ENTRY_NAME: usize = 0x03;
const NAME_SIZE: usize = 30;

/// List track values of entries that hold no file.
const NEVER_USED: u8 = 0x00;
const DELETED: u8 = 0xff;

/// File type flag and types ([BAD] p. 4-6).
const LOCKED: u8 = 0x80;
const TYPE_TEXT: u8 = 0x00;
const TYPE_INTEGER: u8 = 0x01;
const TYPE_APPLESOFT: u8 = 0x02;
const TYPE_BINARY: u8 = 0x04;
const TYPE_S: u8 = 0x08;
const TYPE_RELOCATABLE: u8 = 0x10;
const TYPE_NEW_A: u8 = 0x20;
const TYPE_NEW_B: u8 = 0x40;

/// The first track/sector pair of a list sector ([BAD] p. 4-8).
const FIRST_PAIR: usize = 0x0c;
const _: () = assert!(FIRST_PAIR + 2 * PAIRS_PER_LIST == SECTOR_SIZE);

/// Load address and length before a binary file's memory image.
const BINARY_HEADER_SIZE: usize = 4;

/// How a file's sectors are reassembled.
const TRANSFORM: &str = "DOS 3.3 track/sector list";

/// Whether `size` is a DOS 3.3 image of a supported track count.
pub(super) fn is_image_size(size: usize) -> bool {
    size % TRACK_SIZE == 0 && SUPPORTED_TRACKS.contains(&(size / TRACK_SIZE))
}

/// A track and sector, as catalog and list sectors store them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SectorAddress {
    track: usize,
    sector: usize,
}

impl SectorAddress {
    /// The pair at `at` of `record`.
    fn at(record: &[u8], at: usize) -> Self {
        Self {
            track: usize::from(record[at]),
            sector: usize::from(record[at + 1]),
        }
    }

    /// Track 0 ends a chain: it holds the DOS image, never catalog or list
    /// sectors ([BAD] p. 4-6).
    fn is_end(self) -> bool {
        self.track == 0
    }

    /// A sector of a disk of `tracks` tracks other than track 0.
    fn is_on_disk(self, tracks: usize) -> bool {
        (1..tracks).contains(&self.track) && self.sector < SECTORS_PER_TRACK
    }

    fn index(self) -> usize {
        self.track * SECTORS_PER_TRACK + self.sector
    }
}

impl fmt::Display for SectorAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "track {} sector {}", self.track, self.sector)
    }
}

/// An active catalog entry.
#[derive(Debug)]
struct Entry {
    list: SectorAddress,
    file_type: u8,
    name: String,
}

/// A validated VTOC and catalog chain.
#[derive(Debug)]
pub(super) struct Catalog {
    volume: u8,
    tracks: usize,
    sectors: usize,
    entries: Vec<Entry>,
    deleted: usize,
}

/// Validate the VTOC and walk the catalog chain of `disk`. Entries are
/// read up to the first never-used entry ([CP2] `DOS-notes.md`: "the
/// catalog scan can stop the first time an entry with T=0 is
/// encountered"); the chain is followed to its end.
pub(super) fn open(disk: Disk<'_>) -> Result<Catalog> {
    if !is_image_size(disk.size) {
        return Err(error(format!(
            "Unsupported DOS 3.3 image size {} B: 35 or 40 tracks of 16 sectors expected",
            disk.size
        )));
    }
    let tracks = disk.size / TRACK_SIZE;
    let vtoc_offset = disk
        .sector_offset(VTOC_TRACK, VTOC_SECTOR)
        .expect("track 17 is on a disk of 35 or 40 tracks");
    let vtoc = disk
        .sector(VTOC_TRACK, VTOC_SECTOR)
        .expect("track 17 is on a disk of 35 or 40 tracks");
    let first = check_vtoc(vtoc, tracks, vtoc_offset)?;
    let mut catalog = Catalog {
        volume: vtoc[VTOC_VOLUME],
        tracks,
        sectors: 0,
        entries: Vec::new(),
        deleted: 0,
    };
    let mut visited = vec![false; tracks * SECTORS_PER_TRACK];
    let mut entries_end = false;
    let mut address = first;
    while !address.is_end() {
        if !address.is_on_disk(tracks) || address.index() == VTOC_TRACK * SECTORS_PER_TRACK {
            return Err(error(format!(
                "Invalid catalog link to {address} after {}",
                counted(catalog.sectors, "catalog sector", "catalog sectors")
            )));
        }
        if visited[address.index()] {
            return Err(error(format!(
                "Invalid catalog chain: {address} is reached twice"
            )));
        }
        visited[address.index()] = true;
        catalog.sectors += 1;
        let sector = disk
            .sector(address.track, address.sector)
            .expect("the address is on the disk");
        if !entries_end {
            entries_end = read_entries(sector, address, &mut catalog)?;
        }
        address = SectorAddress::at(sector, NEXT_LINK);
    }
    Ok(catalog)
}

/// How many catalog sectors the chain from the VTOC's first catalog sector
/// links before it ends, leaves the disk, reaches the VTOC or repeats; the
/// other VTOC fields and the entries are not checked. 0 when the image is
/// not a DOS 3.3 size.
pub(super) fn chain_length(disk: Disk<'_>) -> usize {
    if !is_image_size(disk.size) {
        return 0;
    }
    let tracks = disk.size / TRACK_SIZE;
    let vtoc = disk
        .sector(VTOC_TRACK, VTOC_SECTOR)
        .expect("track 17 is on a disk of 35 or 40 tracks");
    let mut visited = vec![false; tracks * SECTORS_PER_TRACK];
    let mut length = 0;
    let mut address = SectorAddress::at(vtoc, VTOC_CATALOG);
    while address.is_on_disk(tracks)
        && address.index() != VTOC_TRACK * SECTORS_PER_TRACK
        && !visited[address.index()]
    {
        visited[address.index()] = true;
        length += 1;
        let sector = disk
            .sector(address.track, address.sector)
            .expect("the address is on the disk");
        address = SectorAddress::at(sector, NEXT_LINK);
    }
    length
}

/// The first catalog sector, after checking the VTOC fields DOS 3.3 writes
/// for a 16-sector disk of `tracks` tracks.
fn check_vtoc(vtoc: &[u8; SECTOR_SIZE], tracks: usize, offset: usize) -> Result<SectorAddress> {
    let invalid = |what: String| error(format!("Invalid VTOC at 0x{offset:X}: {what}"));
    if usize::from(vtoc[VTOC_PAIRS_PER_LIST]) != PAIRS_PER_LIST {
        return Err(invalid(format!(
            "{} track/sector pairs per list, {PAIRS_PER_LIST} expected",
            vtoc[VTOC_PAIRS_PER_LIST]
        )));
    }
    let sector_size = le_u16(vtoc, VTOC_SECTOR_SIZE);
    if usize::from(sector_size) != SECTOR_SIZE {
        return Err(invalid(format!(
            "{sector_size} B per sector, {SECTOR_SIZE} B expected"
        )));
    }
    if usize::from(vtoc[VTOC_SECTORS]) != SECTORS_PER_TRACK {
        return Err(invalid(format!(
            "{} sectors per track, {SECTORS_PER_TRACK} expected",
            vtoc[VTOC_SECTORS]
        )));
    }
    if usize::from(vtoc[VTOC_TRACKS]) != tracks {
        return Err(invalid(format!(
            "{} tracks, the image holds {tracks}",
            vtoc[VTOC_TRACKS]
        )));
    }
    if vtoc[VTOC_RELEASE] != DOS_33_RELEASE {
        return Err(error(format!(
            "Unsupported DOS release {} in the VTOC at 0x{offset:X}: DOS 3.3 writes \
             {DOS_33_RELEASE}",
            vtoc[VTOC_RELEASE]
        )));
    }
    let first = SectorAddress::at(vtoc, VTOC_CATALOG);
    if !first.is_on_disk(tracks) || first.index() == VTOC_TRACK * SECTORS_PER_TRACK {
        return Err(invalid(format!("first catalog sector at {first}")));
    }
    Ok(first)
}

/// Read the entries of the catalog sector at `address` into `catalog`;
/// returns whether a never-used entry ended them.
fn read_entries(
    sector: &[u8; SECTOR_SIZE],
    address: SectorAddress,
    catalog: &mut Catalog,
) -> Result<bool> {
    for number in 0..ENTRIES_PER_SECTOR {
        let start = FIRST_ENTRY + number * ENTRY_SIZE;
        let entry = &sector[start..start + ENTRY_SIZE];
        match entry[ENTRY_LIST] {
            NEVER_USED => return Ok(true),
            DELETED => catalog.deleted += 1,
            _ => {
                let list = SectorAddress::at(entry, ENTRY_LIST);
                if !list.is_on_disk(catalog.tracks) {
                    return Err(error(format!(
                        "Invalid catalog entry {} in {address}: its track/sector list is at \
                         {list}",
                        number + 1
                    )));
                }
                catalog.entries.push(Entry {
                    list,
                    file_type: entry[ENTRY_TYPE],
                    name: file_name(&entry[ENTRY_NAME..ENTRY_NAME + NAME_SIZE]),
                });
            }
        }
    }
    Ok(false)
}

/// A file name as [CP2] `DOS_FileEntry.GenerateCookedName` prints it:
/// trailing high-bit spaces removed; inverse and flashing characters shown
/// as normal ones; control characters as Unicode control pictures.
fn file_name(raw: &[u8]) -> String {
    const SPACE: u8 = b' ' | 0x80;
    const CONTROL_PICTURES: u32 = 0x2400;
    const DELETE_PICTURE: char = '\u{2421}';
    let end = raw
        .iter()
        .rposition(|&b| b != SPACE)
        .map_or(0, |last| last + 1);
    let name: String = raw[..end]
        .iter()
        .map(|&b| match b {
            0x00..=0x1f => char::from(b + 0x40),
            0x20..=0x5f => char::from(b),
            0x60..=0x7f => char::from(b - 0x40),
            0x80..=0x9f => char::from_u32(CONTROL_PICTURES + u32::from(b - 0x80))
                .expect("control pictures are characters"),
            0xa0..=0xfe => char::from(b - 0x80),
            0xff => DELETE_PICTURE,
        })
        .collect();
    if name.is_empty() {
        "(no name)".to_string()
    } else {
        name
    }
}

/// The type letter of a file type byte without the locked flag ([BAD]
/// p. 4-6).
fn type_name(file_type: u8) -> String {
    match file_type & !LOCKED {
        TYPE_TEXT => "T".to_string(),
        TYPE_INTEGER => "I".to_string(),
        TYPE_APPLESOFT => "A".to_string(),
        TYPE_BINARY => "B".to_string(),
        TYPE_S => "S".to_string(),
        TYPE_RELOCATABLE => "R".to_string(),
        TYPE_NEW_A => "new A".to_string(),
        TYPE_NEW_B => "new B".to_string(),
        other => format!("0x{other:02X}"),
    }
}

/// How many files of each type the catalog lists, in type order, with the
/// locked ones counted; `None` for an empty catalog.
fn type_census(entries: &[Entry]) -> Option<String> {
    let mut counts = std::collections::BTreeMap::<u8, usize>::new();
    for entry in entries {
        *counts.entry(entry.file_type & !LOCKED).or_default() += 1;
    }
    if counts.is_empty() {
        return None;
    }
    let locked = entries
        .iter()
        .filter(|entry| entry.file_type & LOCKED != 0)
        .count();
    let types: Vec<String> = counts
        .iter()
        .map(|(&file_type, count)| format!("{} {count}", type_name(file_type)))
        .collect();
    Some(format!("{}; {locked} locked", types.join(", ")))
}

/// List the files of a validated catalog, then the boot sector.
/// `order_note` says how a raw image's sector order was found.
pub(super) fn push_volume<'a>(
    disk: Disk<'a>,
    catalog: &Catalog,
    order_note: Option<String>,
    c: &mut Container<'a>,
) {
    c.notes.push(format!(
        "DOS 3.3 volume {}; {} tracks of 16 sectors; {}",
        catalog.volume,
        catalog.tracks,
        disk.order.name()
    ));
    c.notes.extend(order_note);
    c.notes.push(format!(
        "Catalog: {}, {}; {} ignored",
        counted(catalog.sectors, "sector", "sectors"),
        counted(catalog.entries.len(), "file", "files"),
        counted(catalog.deleted, "deleted entry", "deleted entries")
    ));
    if let Some(types) = type_census(&catalog.entries) {
        c.notes.push(format!("File types: {types}"));
    }
    c.push_metadata(
        format!("{KEY_PREFIX}_dos_volume"),
        "DOS volume number",
        u64::from(catalog.volume),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_tracks"),
        "Tracks",
        catalog.tracks as u64,
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_catalog_sectors"),
        "Catalog sectors",
        catalog.sectors as u64,
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_sector_order"),
        "Sector order",
        disk.order.name(),
    );
    let mut census = Census::default();
    // Track/sector list sectors already read, for all files.
    let mut claimed_lists = vec![false; catalog.tracks * SECTORS_PER_TRACK];
    for entry in &catalog.entries {
        let file = read_file(disk, &mut claimed_lists, entry, &mut census);
        if census.admit(c, file.contents.len) {
            census.push_file(c, disk.input, file);
        }
    }
    census.report(c, "B files after their 4-byte header");
    if prodos::open(disk, prodos::Fit::Within).is_ok() {
        c.notes.push(
            "The disk also holds a ProDOS volume directory that validates (a hybrid disk); its \
             files are not listed"
                .to_string(),
        );
    }
    let boot_offset = disk.sector_offset(0, 0).expect("track 0 is on the disk");
    let mut boot = Assembly::default();
    boot.push_stored(boot_offset, SECTOR_SIZE);
    push_boot(c, disk.input, &boot, "track 0 sector 0", TRANSFORM);
}

/// The data sectors of a file in file order, up to the last nonzero pair;
/// sparse pairs are `None`.
struct DataSectors {
    sectors: Vec<Option<SectorAddress>>,
    /// Why the lists were not followed to their end.
    damage: Option<String>,
}

/// Follow the track/sector lists from `first`. Each list sector is read at
/// most once per volume (`claimed`), so a chain that loops or is shared
/// with another file ends there, and the walk of all files reads each
/// sector at most once. A pair or link outside the disk ends the walk; the
/// sectors before it are kept ([CP2] `DOS_FileEntry.CalcFileLength`).
fn data_sectors(disk: Disk<'_>, claimed: &mut [bool], first: SectorAddress) -> DataSectors {
    let tracks = disk.size / TRACK_SIZE;
    let mut sectors = Vec::new();
    let mut stored_end = 0usize;
    let mut damage = None;
    let mut list = first;
    'lists: while !list.is_end() {
        if !list.is_on_disk(tracks) {
            damage = Some(format!("a track/sector list link leads to {list}"));
            break;
        }
        if claimed[list.index()] {
            damage = Some(format!(
                "the track/sector list at {list} was already read (a loop or a cross-link)"
            ));
            break;
        }
        claimed[list.index()] = true;
        let bytes = disk
            .sector(list.track, list.sector)
            .expect("the address is on the disk");
        for pair in 0..PAIRS_PER_LIST {
            let data = SectorAddress::at(bytes, FIRST_PAIR + 2 * pair);
            if data.is_end() {
                sectors.push(None);
            } else if data.is_on_disk(tracks) {
                sectors.push(Some(data));
                stored_end = sectors.len();
            } else {
                damage = Some(format!(
                    "pair {} of the track/sector list at {list} names {data}",
                    pair + 1
                ));
                break 'lists;
            }
        }
        list = SectorAddress::at(bytes, NEXT_LINK);
    }
    sectors.truncate(stored_end);
    DataSectors { sectors, damage }
}

/// A file's sectors as a file to list: the memory image of a binary file
/// as 6502 code, any other file's sectors as opaque data.
fn read_file(disk: Disk<'_>, claimed: &mut [bool], entry: &Entry, census: &mut Census) -> File {
    let DataSectors { sectors, damage } = data_sectors(disk, claimed, entry.list);
    if let Some(defect) = damage {
        census.problem(format!(
            "{}: {defect}; the sectors before it are listed",
            entry.name
        ));
    }
    let mut contents = Assembly::default();
    for sector in &sectors {
        match sector {
            Some(address) => {
                let offset = disk
                    .sector_offset(address.track, address.sector)
                    .expect("the address is on the disk");
                contents.push_stored(offset, SECTOR_SIZE);
            }
            None => contents.push_hole(SECTOR_SIZE),
        }
    }
    let fallback_offset = disk
        .sector_offset(entry.list.track, entry.list.sector)
        .expect("the catalog checked the address");
    let opaque = |contents| File {
        label: entry.name.clone(),
        contents,
        kind: FileKind::Opaque,
        transform: TRANSFORM,
        fallback_offset,
    };
    if entry.file_type & !LOCKED != TYPE_BINARY {
        return opaque(contents);
    }
    let Some(Some(first)) = sectors.first() else {
        census.problem(format!(
            "B file {}: the first data sector is missing; listed as opaque",
            entry.name
        ));
        return opaque(contents);
    };
    let header = disk
        .sector(first.track, first.sector)
        .expect("the address is on the disk");
    let load_address = le_u16(header, 0);
    let length = usize::from(le_u16(header, 2));
    let stored = contents.len.saturating_sub(BINARY_HEADER_SIZE);
    if length > stored {
        census.problem(format!(
            "B file {}: the header length {length} B exceeds the {stored} B stored after the \
             header",
            entry.name
        ));
    }
    let image = contents.range(BINARY_HEADER_SIZE, length);
    if image.len == 0 {
        census.problem(format!(
            "B file {}: the header length is 0 B; listed as opaque",
            entry.name
        ));
        return opaque(contents);
    }
    File {
        label: entry.name.clone(),
        contents: image,
        kind: FileKind::Code {
            load_address,
            file_type: "B",
        },
        transform: TRANSFORM,
        fallback_offset,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_trim_spaces_and_show_inverse_and_control_characters() {
        let mut raw = [0xa0u8; NAME_SIZE];
        raw[..5].copy_from_slice(b"\xc8\xc5\xcc\xcc\xcf");
        assert_eq!(file_name(&raw), "HELLO");
        raw[..5].copy_from_slice(&[0x08, 0x45, 0x6c, 0x87, 0xff]);
        assert_eq!(file_name(&raw), "HE,\u{2407}\u{2421}");
        assert_eq!(file_name(&[0xa0; NAME_SIZE]), "(no name)");
    }

    #[test]
    fn type_letters_ignore_the_locked_flag() {
        assert_eq!(type_name(0x84), "B");
        assert_eq!(type_name(0x00), "T");
        assert_eq!(type_name(0x20), "new A");
        assert_eq!(type_name(0x03), "0x03");
    }

    #[test]
    fn only_35_and_40_track_images_are_dos_sizes() {
        assert!(is_image_size(143_360));
        assert!(is_image_size(163_840));
        assert!(!is_image_size(143_360 + 256));
        assert!(!is_image_size(116_480));
    }
}
