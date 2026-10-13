//! CBM DOS disk images: D64 (1541, 35 or 40 tracks), D71 (1571) and D81
//! (1581).
//!
//! Geometry follows the VICE manual sections "The D64 disk image format",
//! "The D71 disk image format" and "The D81 disk image format", and VICE
//! `diskimage.c` (`sector_map_d64`): 256-byte sectors addressed by track
//! (from 1) and sector (from 0), stored in track order; the 1541 zones of
//! 21, 19, 18 and 17 sectors (tracks 1-17, 18-24, 25-30, 31-40), which the
//! 1571 repeats on its second side (tracks 36-70); 40 sectors on each of the
//! 1581's 80 tracks. An image may carry one error byte per sector after the
//! sectors.
//!
//! The BAM at 18/0 (1541, 1571), or the header at 40/0 with the BAM sectors
//! 40/1 and 40/2 (1581), names the disk. The directory is a sector chain
//! from 18/1 (40/3 on the 1581) of eight 32-byte entries per sector. A file
//! is a sector chain too: bytes 0-1 link to the next sector, bytes 2-255
//! are data, and the last sector has track 0 and, in its second byte, the
//! index of its last used byte (VICE `vdrive-iec.c` writes `length - 1`).

use super::*;
use crate::formats::container::{MAX_COMPONENTS, MAX_EXTRACTED};
use std::borrow::Cow;
use std::fmt;

/// Bytes per sector on every CBM DOS disk.
const SECTOR_SIZE: usize = 256;

/// The track and sector link at the start of every chained sector.
const LINK_SIZE: usize = 2;

/// Directory entries are 32 bytes, eight per sector.
const ENTRY_SIZE: usize = 32;

/// The little-endian load address at the start of a PRG file.
const LOAD_ADDRESS_SIZE: usize = 2;

/// The 6502 address space.
const ADDRESS_SPACE: usize = 0x1_0000;

/// Track counts (VICE manual; VICE `diskimage.h` sizes).
const D64_TRACKS: u8 = 35;
const D64_EXTENDED_TRACKS: u8 = 40;
const D71_TRACKS: u8 = 70;
const D81_TRACKS: u8 = 80;
const MAX_TRACKS: usize = 80;

/// The 1571's second side starts at track 36 with the zones of track 1.
const TRACKS_PER_SIDE_1571: u8 = 35;

/// Sectors on each 1581 track.
const SECTORS_PER_TRACK_1581: u16 = 40;

/// A 1541 speed zone: its last track and its sectors per track.
struct Zone {
    last_track: u8,
    sectors: u16,
}

/// The 1541 zones (VICE `sector_map_d64`); tracks 36-40 of 40-track images
/// have 17 sectors like tracks 31-35.
const ZONES_1541: [Zone; 4] = [
    Zone {
        last_track: 17,
        sectors: 21,
    },
    Zone {
        last_track: 24,
        sectors: 19,
    },
    Zone {
        last_track: 30,
        sectors: 18,
    },
    Zone {
        last_track: 40,
        sectors: 17,
    },
];

/// The 1541 and 1571 BAM sector and first directory sector.
const BAM_1541: Address = Address::new(18, 0);
const DIRECTORY_1541: Address = Address::new(18, 1);

/// The 1571 directory track's twin on side 1, excluded from the free count
/// like track 18 (VICE `vdrive_bam_free_block_count`).
const DIRECTORY_TRACK_SIDE_1_1571: u8 = 53;

/// The 1581 header, BAM sectors and first directory sector.
const HEADER_1581: Address = Address::new(40, 0);
const BAM_SIDE_0_1581: Address = Address::new(40, 1);
const BAM_SIDE_1_1581: Address = Address::new(40, 2);
const DIRECTORY_1581: Address = Address::new(40, 3);

/// DOS version bytes that formatting writes: `A` (1541, 1571) and `D`
/// (1581), and the 1581 BAM's one's complement of `D`.
const DOS_VERSION_1541: u8 = 0x41;
const DOS_VERSION_1581: u8 = 0x44;
const DOS_VERSION_COMPLEMENT_1581: u8 = !DOS_VERSION_1581;

/// The 1571 double-sided flag at BAM offset 3.
const DOUBLE_SIDED: u8 = 0x80;

/// 1541 and 1571 BAM (18/0) fields: directory link (2), DOS version (1),
/// sides flag (1), four bytes per track 1-35 (free count, then the bitmap),
/// disk name (16) at 0x90, disk ID (2) at 0xA2, DOS type (2) at 0xA5, and on
/// the 1571 the free counts of tracks 36-70 at 0xDD.
const BAM_DOS_VERSION: usize = 0x02;
const BAM_SIDES: usize = 0x03;
const BAM_ENTRIES_1541: usize = 0x04;
const BAM_ENTRY_SIZE_1541: usize = 4;
const BAM_DISK_NAME_1541: usize = 0x90;
const BAM_DISK_ID_1541: usize = 0xa2;
const BAM_DOS_TYPE_1541: usize = 0xa5;
const BAM_FREE_COUNTS_1571: usize = 0xdd;

/// 1581 header (40/0) fields: directory link (2), DOS version (1), zero (1),
/// disk name (16) at 0x04, disk ID (2) at 0x16, DOS version and disk
/// version (2) at 0x19.
const HEADER_SIGNATURE_1581: [u8; 4] = [40, 3, DOS_VERSION_1581, 0x00];
const HEADER_DISK_NAME_1581: usize = 0x04;
const HEADER_DISK_ID_1581: usize = 0x16;
const HEADER_DOS_TYPE_1581: usize = 0x19;

/// 1581 BAM sector fields: link (2), version (1), its complement (1), then
/// from 0x10 six bytes per track (free count, then the bitmap) for 40
/// tracks.
const BAM_VERSION_1581: usize = 0x02;
const BAM_VERSION_COMPLEMENT_1581: usize = 0x03;
const BAM_ENTRIES_1581: usize = 0x10;
const BAM_ENTRY_SIZE_1581: usize = 6;
const TRACKS_PER_BAM_1581: u8 = 40;

/// Directory entry fields: type (1) at 2, first track and sector (2) at 3,
/// name (16) at 5, size in sectors (2, little-endian) at 0x1E.
const ENTRY_TYPE: usize = 0x02;
const ENTRY_FIRST_SECTOR: usize = 0x03;
const ENTRY_NAME: usize = 0x05;
const NAME_SIZE: usize = 16;
const ENTRY_BLOCKS: usize = 0x1e;

/// Name and DOS-type fields are two bytes.
const ID_SIZE: usize = 2;

/// Error codes 0x01 (no error) and 0x00 (unused, "never occur") report no
/// drive error (VICE manual, D64 "Error codes").
const NO_ERROR_CODES: [u8; 2] = [0x00, 0x01];

/// The transform that reassembles a file from its sector chain.
const TRANSFORM: &str = "D64 sector chain";

/// Every disk layout, in the order sizes are matched.
const DISK_IMAGES: [DiskImage; 4] = [
    DiskImage::D64,
    DiskImage::D64Extended,
    DiskImage::D71,
    DiskImage::D81,
];

/// A disk block: track (from 1) and sector (from 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Address {
    track: u8,
    sector: u8,
}

impl Address {
    const fn new(track: u8, sector: u8) -> Self {
        Self { track, sector }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.track, self.sector)
    }
}

/// The track layout of a disk image.
#[derive(Debug, Clone, Copy)]
struct Geometry {
    image: DiskImage,
    tracks: u8,
    /// The index of each track's first sector, by track number; entry
    /// `tracks + 1` is the sector count.
    track_start: [u16; MAX_TRACKS + 2],
}

impl Geometry {
    fn of(image: DiskImage) -> Self {
        let tracks = match image {
            DiskImage::D64 => D64_TRACKS,
            DiskImage::D64Extended => D64_EXTENDED_TRACKS,
            DiskImage::D71 => D71_TRACKS,
            DiskImage::D81 => D81_TRACKS,
        };
        let mut track_start = [0u16; MAX_TRACKS + 2];
        for track in 1..=tracks {
            let t = usize::from(track);
            track_start[t + 1] = track_start[t] + sectors_per_track(image, track);
        }
        Self {
            image,
            tracks,
            track_start,
        }
    }

    /// Sectors on the disk.
    fn sectors(&self) -> usize {
        usize::from(self.track_start[usize::from(self.tracks) + 1])
    }

    /// Bytes of the sectors, without error bytes.
    fn image_size(&self) -> usize {
        self.sectors() * SECTOR_SIZE
    }

    /// The sector index of `address`, or `None` outside the disk.
    fn index(&self, address: Address) -> Option<usize> {
        if address.track == 0 || address.track > self.tracks {
            return None;
        }
        let track = usize::from(address.track);
        let first = usize::from(self.track_start[track]);
        let count = usize::from(self.track_start[track + 1]) - first;
        let sector = usize::from(address.sector);
        (sector < count).then_some(first + sector)
    }

    /// The address of sector index `index`.
    fn address(&self, index: usize) -> Option<Address> {
        (1..=self.tracks).find_map(|track| {
            let t = usize::from(track);
            let first = usize::from(self.track_start[t]);
            let end = usize::from(self.track_start[t + 1]);
            let sector = u8::try_from(index.checked_sub(first)?).ok()?;
            (index < end).then_some(Address::new(track, sector))
        })
    }
}

/// Sectors on `track` of a disk of `image`, which has the track.
fn sectors_per_track(image: DiskImage, track: u8) -> u16 {
    match image {
        DiskImage::D81 => SECTORS_PER_TRACK_1581,
        DiskImage::D71 if track > TRACKS_PER_SIDE_1571 => {
            zone_sectors(track - TRACKS_PER_SIDE_1571)
        }
        DiskImage::D64 | DiskImage::D64Extended | DiskImage::D71 => zone_sectors(track),
    }
}

/// Sectors per track in the 1541 zone of `track`.
fn zone_sectors(track: u8) -> u16 {
    ZONES_1541
        .iter()
        .find(|zone| track <= zone.last_track)
        .map_or(0, |zone| zone.sectors)
}

/// A sector of the image.
#[derive(Clone, Copy)]
struct Sector<'a> {
    /// Sector index on the disk.
    index: usize,
    /// File offset of the sector.
    offset: usize,
    bytes: &'a [u8; SECTOR_SIZE],
}

impl<'a> Sector<'a> {
    /// The sector a chain continues at, or `None` at the last sector
    /// (track 0).
    fn next(&self) -> Option<Address> {
        (self.bytes[0] != 0).then(|| Address::new(self.bytes[0], self.bytes[1]))
    }

    /// The file data this chained sector holds: bytes 2-255, or in the
    /// last sector bytes 2 to the index in byte 1.
    fn file_data(&self) -> &'a [u8] {
        let bytes: &'a [u8; SECTOR_SIZE] = self.bytes;
        let end = if self.next().is_some() {
            SECTOR_SIZE
        } else {
            (usize::from(bytes[1]) + 1).max(LINK_SIZE)
        };
        &bytes[LINK_SIZE..end]
    }
}

/// A disk image of the expected size.
struct Disk<'a> {
    data: &'a [u8],
    geometry: Geometry,
    /// One error byte per sector, when the image carries them.
    error_bytes: Option<&'a [u8]>,
}

impl<'a> Disk<'a> {
    /// `data` as an image of `image`: exactly the sectors, or the sectors
    /// and one error byte per sector.
    fn new(data: &'a [u8], image: DiskImage) -> Result<Self> {
        let geometry = Geometry::of(image);
        let size = geometry.image_size();
        let with_errors = size + geometry.sectors();
        let error_bytes = if data.len() == size {
            None
        } else if data.len() == with_errors {
            Some(&data[size..])
        } else {
            return Err(error(format!(
                "Invalid {} size {} B: expected {size} B, or {with_errors} B with error bytes",
                Layout::Disk(image).label(),
                data.len()
            )));
        };
        Ok(Self {
            data,
            geometry,
            error_bytes,
        })
    }

    fn sector(&self, address: Address) -> Option<Sector<'a>> {
        let index = self.geometry.index(address)?;
        let offset = index * SECTOR_SIZE;
        let bytes = self
            .data
            .get(offset..offset + SECTOR_SIZE)?
            .try_into()
            .ok()?;
        Some(Sector {
            index,
            offset,
            bytes,
        })
    }

    /// A sector that every image of the geometry has.
    fn fixed_sector(&self, address: Address) -> Result<Sector<'a>> {
        self.sector(address).ok_or_else(|| {
            error(format!(
                "Truncated image: sector {address} is missing from the {} B file",
                self.data.len()
            ))
        })
    }
}

/// The layout whose image size (with or without error bytes) `size` is.
fn image_for_size(size: usize) -> Option<DiskImage> {
    DISK_IMAGES.into_iter().find(|&image| {
        let geometry = Geometry::of(image);
        size == geometry.image_size() || size == geometry.image_size() + geometry.sectors()
    })
}

pub(super) fn detect(data: &[u8]) -> Option<DiskImage> {
    let image = image_for_size(data.len())?;
    let disk = Disk::new(data, image).ok()?;
    header(&disk).ok()?;
    directory(&disk).ok()?;
    Some(image)
}

/// What the BAM, or the 1581 header and BAM, say about the disk.
struct Header {
    name: String,
    id: String,
    dos_type: String,
    /// Free sectors outside the directory track, as a directory listing
    /// counts them.
    blocks_free: u64,
}

fn header(disk: &Disk<'_>) -> Result<Header> {
    match disk.geometry.image {
        DiskImage::D81 => header_1581(disk),
        DiskImage::D64 | DiskImage::D64Extended | DiskImage::D71 => header_1541(disk),
    }
}

/// The 1541 or 1571 BAM at 18/0: directory link 18/1 and DOS version `A`,
/// which formatting writes (VICE `vdrive_bam_create_empty_bam`) and file(1)
/// tests, and on a D71 the double-sided flag.
fn header_1541(disk: &Disk<'_>) -> Result<Header> {
    let bam = disk.fixed_sector(BAM_1541)?;
    let b = bam.bytes;
    let signature = [
        DIRECTORY_1541.track,
        DIRECTORY_1541.sector,
        DOS_VERSION_1541,
    ];
    if b[..signature.len()] != signature {
        return Err(error(format!(
            "Invalid BAM at 0x{:X} (sector {BAM_1541}): directory link {}/{} and DOS version \
                0x{:02X}; formatting writes 18/1 and 0x41",
            bam.offset, b[0], b[1], b[BAM_DOS_VERSION]
        )));
    }
    let image = disk.geometry.image;
    if image == DiskImage::D71 && b[BAM_SIDES] != DOUBLE_SIDED {
        return Err(error(format!(
            "Invalid D71 BAM at 0x{:X}: double-sided flag 0x{:02X}; a 1571 double-sided disk has \
                0x80",
            bam.offset, b[BAM_SIDES]
        )));
    }
    let mut blocks_free = 0u64;
    for track in 1..=TRACKS_PER_SIDE_1571 {
        if track != BAM_1541.track {
            let at = BAM_ENTRIES_1541 + BAM_ENTRY_SIZE_1541 * usize::from(track - 1);
            blocks_free += u64::from(b[at]);
        }
    }
    if image == DiskImage::D71 {
        for track in TRACKS_PER_SIDE_1571 + 1..=D71_TRACKS {
            if track != DIRECTORY_TRACK_SIDE_1_1571 {
                let at = BAM_FREE_COUNTS_1571 + usize::from(track - TRACKS_PER_SIDE_1571 - 1);
                blocks_free += u64::from(b[at]);
            }
        }
    }
    Ok(Header {
        name: padded_name(&b[BAM_DISK_NAME_1541..BAM_DISK_NAME_1541 + NAME_SIZE]),
        id: petscii_text(&b[BAM_DISK_ID_1541..BAM_DISK_ID_1541 + ID_SIZE]),
        dos_type: petscii_text(&b[BAM_DOS_TYPE_1541..BAM_DOS_TYPE_1541 + ID_SIZE]),
        blocks_free,
    })
}

/// The 1581 header at 40/0 (`28 03 44 00`, as formatting writes it and
/// file(1) tests) and the version byte `D` with its complement 0xBB in
/// both BAM sectors.
fn header_1581(disk: &Disk<'_>) -> Result<Header> {
    let header = disk.fixed_sector(HEADER_1581)?;
    let h = header.bytes;
    if h[..HEADER_SIGNATURE_1581.len()] != HEADER_SIGNATURE_1581 {
        return Err(error(format!(
            "Invalid D81 header at 0x{:X} (sector {HEADER_1581}): {:02X} {:02X} {:02X} {:02X}; \
                formatting writes 28 03 44 00",
            header.offset, h[0], h[1], h[2], h[3]
        )));
    }
    let mut blocks_free = 0u64;
    let sides = [
        (BAM_SIDE_0_1581, 1),
        (BAM_SIDE_1_1581, 1 + TRACKS_PER_BAM_1581),
    ];
    for (address, first_track) in sides {
        let bam = disk.fixed_sector(address)?;
        let b = bam.bytes;
        if b[BAM_VERSION_1581] != DOS_VERSION_1581
            || b[BAM_VERSION_COMPLEMENT_1581] != DOS_VERSION_COMPLEMENT_1581
        {
            return Err(error(format!(
                "Invalid D81 BAM at 0x{:X} (sector {address}): version 0x{:02X} and complement \
                    0x{:02X}; formatting writes 0x44 and 0xBB",
                bam.offset, b[BAM_VERSION_1581], b[BAM_VERSION_COMPLEMENT_1581]
            )));
        }
        for i in 0..TRACKS_PER_BAM_1581 {
            if first_track + i != HEADER_1581.track {
                let at = BAM_ENTRIES_1581 + BAM_ENTRY_SIZE_1581 * usize::from(i);
                blocks_free += u64::from(b[at]);
            }
        }
    }
    Ok(Header {
        name: padded_name(&h[HEADER_DISK_NAME_1581..HEADER_DISK_NAME_1581 + NAME_SIZE]),
        id: petscii_text(&h[HEADER_DISK_ID_1581..HEADER_DISK_ID_1581 + ID_SIZE]),
        dos_type: petscii_text(&h[HEADER_DOS_TYPE_1581..HEADER_DOS_TYPE_1581 + ID_SIZE]),
        blocks_free,
    })
}

/// The directory sectors in chain order. The drive starts at 18/1 (40/3)
/// whatever the BAM links to, and the chain may leave the directory track
/// (VICE manual: "Just follow the chain anyhow"); each sector may be
/// visited once, so the walk ends within the disk's sector count.
fn directory<'a>(disk: &Disk<'a>) -> Result<Vec<Sector<'a>>> {
    let first = match disk.geometry.image {
        DiskImage::D81 => DIRECTORY_1581,
        DiskImage::D64 | DiskImage::D64Extended | DiskImage::D71 => DIRECTORY_1541,
    };
    let mut visited = vec![false; disk.geometry.sectors()];
    let mut sectors: Vec<Sector<'a>> = Vec::new();
    let mut next = Some(first);
    while let Some(address) = next {
        let Some(sector) = disk.sector(address) else {
            let from = sectors.last().map_or(0, |s| s.offset);
            return Err(error(format!(
                "Invalid directory link at 0x{from:X}: sector {address} is outside the {}-track \
                    disk",
                disk.geometry.tracks
            )));
        };
        if visited[sector.index] {
            return Err(error(format!(
                "Invalid directory chain: sector {address} at 0x{:X} is linked twice",
                sector.offset
            )));
        }
        visited[sector.index] = true;
        next = sector.next();
        sectors.push(sector);
    }
    Ok(sectors)
}

/// A directory entry.
struct Entry<'a> {
    /// File offset of the 32-byte entry.
    offset: usize,
    type_byte: u8,
    first: Address,
    name: &'a [u8],
    /// File size in sectors, as the directory lists it.
    blocks: u16,
}

impl<'a> Entry<'a> {
    fn read(offset: usize, entry: &'a [u8; ENTRY_SIZE]) -> Self {
        Self {
            offset,
            type_byte: entry[ENTRY_TYPE],
            first: Address::new(entry[ENTRY_FIRST_SECTOR], entry[ENTRY_FIRST_SECTOR + 1]),
            name: &entry[ENTRY_NAME..ENTRY_NAME + NAME_SIZE],
            blocks: u16::from_le_bytes([entry[ENTRY_BLOCKS], entry[ENTRY_BLOCKS + 1]]),
        }
    }

    /// The flags a listing shows after the name.
    fn flags(&self) -> &'static str {
        match (
            self.type_byte & FILE_CLOSED != 0,
            self.type_byte & FILE_LOCKED != 0,
        ) {
            (true, false) => "",
            (true, true) => " (locked)",
            (false, false) => " (not closed)",
            (false, true) => " (locked, not closed)",
        }
    }
}

/// The entries of the directory sectors, in order.
fn entries<'a, 's>(sectors: &'s [Sector<'a>]) -> impl Iterator<Item = Entry<'a>> + 's {
    sectors.iter().flat_map(|sector| {
        let bytes: &'a [u8; SECTOR_SIZE] = sector.bytes;
        bytes
            .chunks_exact(ENTRY_SIZE)
            .enumerate()
            .map(move |(slot, entry)| {
                let entry: &'a [u8; ENTRY_SIZE] = entry
                    .try_into()
                    .expect("chunks_exact yields ENTRY_SIZE bytes");
                Entry::read(sector.offset + slot * ENTRY_SIZE, entry)
            })
    })
}

/// A file's sector chain, every link inside the disk.
struct Chain<'a> {
    /// File offset of the first sector.
    offset: usize,
    /// Stored bytes of the leading run of adjacent sectors.
    stored_size: usize,
    /// The data bytes of each sector, in chain order.
    pieces: Vec<&'a [u8]>,
    /// Total data bytes.
    size: usize,
}

impl Chain<'_> {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size);
        for piece in &self.pieces {
            bytes.extend_from_slice(piece);
        }
        bytes
    }
}

/// The sector chain of a file from `first`. A sector visited twice is a
/// loop, so the walk ends within the disk's sector count.
fn chain<'a>(disk: &Disk<'a>, first: Address) -> std::result::Result<Chain<'a>, String> {
    let mut visited = vec![false; disk.geometry.sectors()];
    let mut chain = Chain {
        offset: 0,
        stored_size: 0,
        pieces: Vec::new(),
        size: 0,
    };
    let mut adjacent = true;
    let mut next = Some(first);
    while let Some(address) = next {
        let Some(sector) = disk.sector(address) else {
            return Err(if chain.pieces.is_empty() {
                format!("its first sector {address} is outside the disk")
            } else {
                format!("its chain links to sector {address}, outside the disk")
            });
        };
        if visited[sector.index] {
            return Err(format!("its chain visits sector {address} twice"));
        }
        visited[sector.index] = true;
        if chain.pieces.is_empty() {
            chain.offset = sector.offset;
        }
        if adjacent && sector.offset == chain.offset + chain.stored_size {
            chain.stored_size += SECTOR_SIZE;
        } else {
            adjacent = false;
        }
        let piece = sector.file_data();
        chain.size += piece.len();
        chain.pieces.push(piece);
        next = sector.next();
    }
    Ok(chain)
}

/// A child of reassembled data that never reaches the code model.
fn opaque_file<'a>(label: String, chain: &Chain<'_>, bytes: Vec<u8>) -> Child<'a> {
    Child {
        opaque: true,
        ..Child::decoded(
            label,
            chain.offset,
            chain.stored_size,
            Cow::Owned(bytes),
            TRANSFORM,
        )
    }
}

/// Lists the files of the directory within the limits.
struct Listing<'d, 'a> {
    disk: &'d Disk<'a>,
    /// Decoded bytes so far.
    extracted: usize,
    /// Entries examined so far.
    examined: usize,
    /// Entries beyond [`MAX_COMPONENTS`].
    unexamined: usize,
    /// Files left out because of [`MAX_EXTRACTED`].
    over_budget: usize,
    /// Closed DEL entries.
    deleted: usize,
    problems: Problems,
}

impl<'a> Listing<'_, 'a> {
    fn entry(&mut self, entry: &Entry<'a>, c: &mut Container<'a>) {
        let file_type = FileType::of(entry.type_byte);
        if file_type == FileType::Del {
            // A scratched slot has type 0x00; a closed DEL entry is listed
            // by the drive but holds no file to classify.
            if entry.type_byte & FILE_CLOSED != 0 {
                self.deleted += 1;
            }
            return;
        }
        if self.examined >= MAX_COMPONENTS {
            self.unexamined += 1;
            return;
        }
        self.examined += 1;
        let name = padded_name(entry.name);
        match file_type {
            FileType::Seq | FileType::Prg | FileType::Usr | FileType::Rel => {
                self.file(entry, file_type, &name, c);
            }
            FileType::Partition if self.disk.geometry.image == DiskImage::D81 => {
                self.partition(entry, &name, c);
            }
            FileType::Partition | FileType::Other(_) | FileType::Del => {
                self.problems.push(format!(
                    "Skipped entry \"{name}\" at 0x{:X}: file type 0x{:02X} is not defined for \
                        this drive",
                    entry.offset, entry.type_byte
                ));
            }
        }
    }

    /// A chained file: PRG as code after its load address, the others as
    /// data.
    fn file(&mut self, entry: &Entry<'a>, file_type: FileType, name: &str, c: &mut Container<'a>) {
        let kind = file_type.name();
        let chain = match chain(self.disk, entry.first) {
            Ok(chain) => chain,
            Err(defect) => {
                self.problems.push(format!(
                    "Skipped {kind} \"{name}\" at 0x{:X}: {defect}",
                    entry.offset
                ));
                return;
            }
        };
        if usize::from(entry.blocks) != chain.pieces.len() {
            self.problems.push(format!(
                "{kind} \"{name}\": the directory lists {} blocks; its chain has {} sectors",
                entry.blocks,
                chain.pieces.len()
            ));
        }
        if self.extracted + chain.size > MAX_EXTRACTED {
            self.over_budget += 1;
            return;
        }
        self.extracted += chain.size;
        let mut bytes = chain.bytes();
        let flags = entry.flags();
        if file_type != FileType::Prg {
            let label = format!("{}{flags}", file_label(&kind, name, None));
            c.children.push(opaque_file(label, &chain, bytes));
            return;
        }
        if bytes.len() <= LOAD_ADDRESS_SIZE {
            self.problems.push(format!(
                "PRG \"{name}\": {} B hold no program after a load address",
                bytes.len()
            ));
            let label = format!("{}{flags}", file_label(&kind, name, None));
            c.children.push(opaque_file(label, &chain, bytes));
            return;
        }
        let load_address = u16::from_le_bytes([bytes[0], bytes[1]]);
        bytes.drain(..LOAD_ADDRESS_SIZE);
        if usize::from(load_address) + bytes.len() > ADDRESS_SPACE {
            self.problems.push(format!(
                "PRG \"{name}\": {} B from 0x{load_address:04X} extend past 0xFFFF",
                bytes.len()
            ));
        }
        let label = format!("{}{flags}", file_label(&kind, name, Some(load_address)));
        let child = Child::decoded(
            label,
            chain.offset,
            chain.stored_size,
            Cow::Owned(bytes),
            TRANSFORM,
        );
        c.children.push(program(child));
    }

    /// A 1581 partition: consecutive sectors from the entry's first sector
    /// for the entry's size, without a chain (VICE manual, "1581 Partitions
    /// and Sub-directories").
    fn partition(&mut self, entry: &Entry<'a>, name: &str, c: &mut Container<'a>) {
        let geometry = &self.disk.geometry;
        let blocks = usize::from(entry.blocks);
        let range = geometry
            .index(entry.first)
            .filter(|&start| blocks > 0 && start + blocks <= geometry.sectors());
        let Some(start) = range else {
            self.problems.push(format!(
                "Skipped CBM \"{name}\" at 0x{:X}: {blocks} sectors from {} do not fit the disk",
                entry.offset, entry.first
            ));
            return;
        };
        let offset = start * SECTOR_SIZE;
        let data: &'a [u8] = self.disk.data;
        let bytes = &data[offset..offset + blocks * SECTOR_SIZE];
        let label = format!("CBM \"{name}\" partition{}", entry.flags());
        c.children.push(Child::opaque(label, offset, bytes));
    }

    fn finish(self, notes: &mut Vec<String>) {
        if self.deleted > 0 {
            notes.push(format!(
                "{} skipped",
                counted(self.deleted, "DEL entry", "DEL entries")
            ));
        }
        if self.unexamined > 0 {
            notes.push(format!(
                "{} further directory entries were not examined (limit {MAX_COMPONENTS})",
                self.unexamined
            ));
        }
        if self.over_budget > 0 {
            notes.push(format!(
                "{} not extracted: the {} MiB extraction limit was reached",
                counted(self.over_budget, "file was", "files were"),
                MAX_EXTRACTED >> 20
            ));
        }
        self.problems.append_to(notes);
    }
}

/// The note on the error bytes: how many sectors report a drive error, and
/// the first of them.
fn error_bytes_note(geometry: &Geometry, error_bytes: &[u8]) -> String {
    let mut errors = error_bytes
        .iter()
        .enumerate()
        .filter(|(_, code)| !NO_ERROR_CODES.contains(code));
    let Some((first, code)) = errors.next() else {
        return format!(
            "{} error bytes follow the sectors; none reports a drive error",
            error_bytes.len()
        );
    };
    let count = 1 + errors.count();
    let at = geometry.address(first).map_or_else(String::new, |address| {
        format!(" (first: sector {address}, code 0x{code:02X})")
    });
    format!(
        "{} error bytes follow the sectors; {} a drive error{at}",
        error_bytes.len(),
        counted(count, "sector reports", "sectors report")
    )
}

pub(super) fn parse(data: &[u8], image: DiskImage) -> Result<Container<'_>> {
    let disk = Disk::new(data, image)?;
    let header = header(&disk)?;
    let directory = directory(&disk)?;
    let layout = Layout::Disk(image);
    let mut c = Container::new(layout.format(), layout.label(), KEY_PREFIX);
    c.consumed = data.len();
    let mut listing = Listing {
        disk: &disk,
        extracted: 0,
        examined: 0,
        unexamined: 0,
        over_budget: 0,
        deleted: 0,
        problems: Problems::default(),
    };
    for entry in entries(&directory) {
        listing.entry(&entry, &mut c);
    }
    let geometry = disk.geometry;
    c.notes.push(format!(
        "Disk \"{}\" ID \"{}\" DOS type \"{}\"; {} tracks, {} sectors of 256 B; {}; {} blocks \
            free",
        header.name,
        header.id,
        header.dos_type,
        geometry.tracks,
        geometry.sectors(),
        counted(c.children.len(), "file listed", "files listed"),
        header.blocks_free
    ));
    c.notes.push(
        "PRG files are 6502-family code after their two-byte load address (the CPU of the \
            Commodore 8-bit computers); SEQ, USR and REL files and partitions are data"
            .into(),
    );
    if image == DiskImage::D64Extended {
        c.notes.push(
            "Tracks 36-40 keep their BAM where the formatting DOS put it; blocks free counts \
                tracks 1-35"
                .into(),
        );
    }
    if let Some(error_bytes) = disk.error_bytes {
        c.notes.push(error_bytes_note(&geometry, error_bytes));
    }
    listing.finish(&mut c.notes);
    c.push_metadata("cbm_disk_name", "Disk name", header.name);
    c.push_metadata("cbm_disk_id", "Disk ID", header.id);
    c.push_metadata("cbm_dos_type", "DOS type", header.dos_type);
    c.push_metadata("cbm_blocks_free", "Blocks free", header.blocks_free);
    c.push_metadata(
        "cbm_directory_sectors",
        "Directory sectors",
        directory.len() as u64,
    );
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_matches_the_vice_offset_tables() {
        let d64 = Geometry::of(DiskImage::D64);
        assert_eq!(d64.sectors(), 683);
        assert_eq!(d64.image_size(), 174_848);
        assert_eq!(
            d64.index(Address::new(18, 0)).map(|i| i * 256),
            Some(0x16500)
        );
        assert_eq!(d64.index(Address::new(35, 16)), Some(682));
        assert_eq!(d64.index(Address::new(35, 17)), None);
        assert_eq!(d64.index(Address::new(36, 0)), None);
        assert_eq!(d64.index(Address::new(0, 0)), None);
        assert_eq!(d64.index(Address::new(17, 20)), Some(356));
        assert_eq!(d64.index(Address::new(17, 21)), None);
        let extended = Geometry::of(DiskImage::D64Extended);
        assert_eq!(extended.image_size(), 196_608);
        assert_eq!(
            extended.index(Address::new(40, 0)).map(|i| i * 256),
            Some(0x2ef00)
        );
        let d71 = Geometry::of(DiskImage::D71);
        assert_eq!(d71.image_size(), 349_696);
        assert_eq!(
            d71.index(Address::new(36, 0)).map(|i| i * 256),
            Some(0x2ab00)
        );
        assert_eq!(
            d71.index(Address::new(53, 0)).map(|i| i * 256),
            Some(0x41000)
        );
        assert_eq!(d71.index(Address::new(70, 16)), Some(1365));
        let d81 = Geometry::of(DiskImage::D81);
        assert_eq!(d81.image_size(), 819_200);
        assert_eq!(
            d81.index(Address::new(40, 0)).map(|i| i * 256),
            Some(0x61800)
        );
        assert_eq!(d81.index(Address::new(80, 39)), Some(3199));
        assert_eq!(d81.index(Address::new(80, 40)), None);
    }

    #[test]
    fn addresses_round_trip_through_sector_indexes() {
        for image in DISK_IMAGES {
            let geometry = Geometry::of(image);
            for index in 0..geometry.sectors() {
                let address = geometry.address(index).expect("address");
                assert_eq!(geometry.index(address), Some(index), "{image:?} {address}");
            }
            assert_eq!(geometry.address(geometry.sectors()), None);
        }
    }

    #[test]
    fn sizes_select_the_layout() {
        assert_eq!(image_for_size(174_848), Some(DiskImage::D64));
        assert_eq!(image_for_size(175_531), Some(DiskImage::D64));
        assert_eq!(image_for_size(196_608), Some(DiskImage::D64Extended));
        assert_eq!(image_for_size(197_376), Some(DiskImage::D64Extended));
        assert_eq!(image_for_size(349_696), Some(DiskImage::D71));
        assert_eq!(image_for_size(351_062), Some(DiskImage::D71));
        assert_eq!(image_for_size(819_200), Some(DiskImage::D81));
        assert_eq!(image_for_size(822_400), Some(DiskImage::D81));
        assert_eq!(image_for_size(174_847), None);
        assert_eq!(image_for_size(205_312), None);
    }

    #[test]
    fn the_last_sector_holds_bytes_up_to_its_index() {
        let mut bytes = [0u8; SECTOR_SIZE];
        let sector = |bytes: &[u8; SECTOR_SIZE]| {
            Sector {
                index: 0,
                offset: 0,
                bytes,
            }
            .file_data()
            .len()
        };
        bytes[1] = 0x34;
        assert_eq!(sector(&bytes), 0x33);
        bytes[1] = 0xff;
        assert_eq!(sector(&bytes), 254);
        bytes[1] = 1;
        assert_eq!(sector(&bytes), 0);
        bytes[1] = 0;
        assert_eq!(sector(&bytes), 0);
        bytes[0] = 1;
        assert_eq!(sector(&bytes), 254);
    }
}
