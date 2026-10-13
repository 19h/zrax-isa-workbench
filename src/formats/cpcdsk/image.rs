//! The disk image: the disk information block, one Track-Info block per
//! formatted track and side, and the stored sector data ([DSK], [EDSK]).
//!
//! Disk information block (offset 0, 256 B): signature (0, 34 B), creator
//! (0x22, 14 B), tracks (0x30), sides (0x31), track size including the
//! Track-Info block (0x32, little-endian, standard images), and the track
//! size table (0x34, one byte per track and side in 256-byte units,
//! extended images; 0 marks an unformatted track with no block in the
//! file). Track blocks follow from 0x100 in the order track 0 side 0,
//! track 0 side 1, track 1 side 0, and so on.
//!
//! Track-Info block: `Track-Info\r\n` (0), track number (0x10), side
//! number (0x11), data rate (0x12) and recording mode (0x13, both
//! extensions), sector size code N (0x14), sector count (0x15), gap 3
//! (0x16), filler byte (0x17), then 8 bytes per sector: C, H, R, N, ST1,
//! ST2 and, in extended images, the stored data length (little-endian).
//! Sector data starts 0x100 after the block, or at the next 256-byte
//! boundary after the sector list when more than 29 sectors extend the
//! block ([LIBDSK]), and follows in list order: `128 << N` bytes per sector
//! with N from 0x14 (0x1800 for N = 6) in standard images, the stored
//! length in extended ones.

use super::*;

/// Size of the disk information block; the first track block follows.
const INFO_SIZE: usize = 0x100;

/// The full signature texts ([DSK], [EDSK]). Detection needs only their
/// identifying prefixes; a different remainder is noted.
const STANDARD_TEXT: &[u8; 34] = b"MV - CPCEMU Disk-File\r\nDisk-Info\r\n";
const EXTENDED_TEXT: &[u8; 34] = b"EXTENDED CPC DSK File\r\nDisk-Info\r\n";

// Disk information block fields.
const CREATOR_OFFSET: usize = 0x22;
const CREATOR_SIZE: usize = 14;
const TRACKS_OFFSET: usize = 0x30;
const SIDES_OFFSET: usize = 0x31;
const TRACK_SIZE_OFFSET: usize = 0x32;
const TRACK_TABLE_OFFSET: usize = 0x34;

/// Entries of the extended track size table (0x34 to 0xFF).
const TRACK_TABLE_ENTRIES: usize = INFO_SIZE - TRACK_TABLE_OFFSET;

/// Extended track sizes are stored divided by 256 ([EDSK]).
const TRACK_SIZE_UNIT: usize = 0x100;

/// A floppy disk has one or two sides.
const MAX_SIDES: u8 = 2;

/// Start of a Track-Info block. [CAP32] compares these ten characters;
/// [DSK] follows them with `\r\n`.
const TRACK_INFO_MAGIC: &[u8; 10] = b"Track-Info";

/// Size of a Track-Info block of up to 29 sectors.
const TRACK_INFO_SIZE: usize = 0x100;

// Track-Info block fields.
const TRACK_NUMBER_OFFSET: usize = 0x10;
const SIDE_NUMBER_OFFSET: usize = 0x11;
const SIZE_CODE_OFFSET: usize = 0x14;
const SECTOR_COUNT_OFFSET: usize = 0x15;
const SECTOR_LIST_OFFSET: usize = 0x18;
const SECTOR_INFO_SIZE: usize = 8;

/// Standard images store `128 << N` bytes per sector, except 0x1800 for
/// N = 6 ([DSK]); larger codes are not described for them.
const SIZE_CODE_8K: u8 = 6;
const STORED_8K: usize = 0x1800;

/// Sector size codes are three bits: N = 8 is equivalent to N = 0 ([EDSK],
/// Simon Owen's extension).
const SIZE_CODE_MASK: u8 = 0x07;

/// [LIBDSK] (1.5.4 and later) appends an `Offset-Info` block after the last
/// track of an extended image.
const OFFSET_INFO_MAGIC: &[u8; 13] = b"Offset-Info\r\n";

/// A sector's ID field, its FDC status and its stored data.
#[derive(Debug, Clone, Copy)]
pub(super) struct Sector<'a> {
    /// ID field C: the cylinder the sector claims.
    pub(super) cylinder: u8,
    /// ID field H: the head the sector claims.
    pub(super) head: u8,
    /// ID field R: the sector ID.
    pub(super) id: u8,
    /// ID field N: the size code.
    pub(super) size_code: u8,
    /// FDC status registers 1 and 2 recorded by the dump.
    pub(super) st1: u8,
    pub(super) st2: u8,
    /// File offset of the stored data.
    pub(super) offset: usize,
    /// Stored data: the track's sector stride (standard) or the stored
    /// length (extended).
    pub(super) data: &'a [u8],
}

impl Sector<'_> {
    /// The size the ID field's N names, in bytes.
    pub(super) fn nominal_size(&self) -> usize {
        128 << (self.size_code & SIZE_CODE_MASK)
    }

    /// Stored data with several copies of a weak sector ([EDSK]).
    fn is_weak(&self) -> bool {
        let nominal = self.nominal_size();
        self.data.len() > nominal && self.data.len() % nominal == 0
    }

    /// Stored data shorter than the size code names, other than the
    /// documented 0x1800 bytes of an 8 KiB sector.
    fn is_short(&self) -> bool {
        let documented_8k =
            self.size_code & SIZE_CODE_MASK == SIZE_CODE_8K && self.data.len() == STORED_8K;
        self.data.len() < self.nominal_size() && !documented_8k
    }
}

/// A track block with its sectors.
#[derive(Debug)]
pub(super) struct Track<'a> {
    /// Track and side numbers recorded in the Track-Info block.
    pub(super) number: u8,
    pub(super) side: u8,
    /// Sectors in the order of the sector information list.
    pub(super) sectors: Vec<Sector<'a>>,
}

impl<'a> Track<'a> {
    /// The first sector whose ID field names sector `id`.
    pub(super) fn sector(&self, id: u16) -> Option<&Sector<'a>> {
        self.sectors.iter().find(|s| u16::from(s.id) == id)
    }

    /// The lowest sector ID on the track (iDSK `GetMinSect`).
    pub(super) fn lowest_id(&self) -> Option<u8> {
        self.sectors.iter().map(|s| s.id).min()
    }
}

/// A parsed disk image.
#[derive(Debug)]
pub(super) struct Disk<'a> {
    /// Creator name from the disk information block.
    pub(super) creator: String,
    /// The signature continues as documented after its identifying prefix.
    pub(super) documented_signature: bool,
    /// Tracks per side and sides, as the disk information block declares.
    pub(super) cylinders: usize,
    pub(super) sides: usize,
    /// Track blocks in image order, `None` for unformatted tracks.
    tracks: Vec<Option<Track<'a>>>,
    /// File offset just past the last track block.
    pub(super) end: usize,
}

impl<'a> Disk<'a> {
    /// The track at `cylinder` and `head`, if the image formats it.
    pub(super) fn track(&self, cylinder: usize, head: usize) -> Option<&Track<'a>> {
        if head >= self.sides {
            return None;
        }
        let index = cylinder.checked_mul(self.sides)?.checked_add(head)?;
        self.tracks.get(index)?.as_ref()
    }

    /// The image summary note.
    pub(super) fn summary(&self, layout: Layout) -> String {
        let mut parts = vec![format!(
            "{}: {}, {}",
            layout.label(),
            counted(self.cylinders, "track", "tracks"),
            counted(self.sides, "side", "sides")
        )];
        if !self.creator.is_empty() {
            parts.push(format!("creator \"{}\"", self.creator));
        }
        if !self.documented_signature {
            parts
                .push("the signature text differs from the documented one after its prefix".into());
        }
        parts.join("; ")
    }

    /// Count what the notes report about the tracks.
    pub(super) fn census(&self) -> Census {
        let mut census = Census::default();
        for (index, track) in self.tracks.iter().enumerate() {
            let Some(track) = track.as_ref().filter(|t| !t.sectors.is_empty()) else {
                census.unformatted += 1;
                continue;
            };
            census.formatted += 1;
            let (cylinder, side) = (index / self.sides, index % self.sides);
            if usize::from(track.number) != cylinder || usize::from(track.side) != side {
                census.misnumbered += 1;
            }
            for sector in &track.sectors {
                census.sectors += 1;
                census.foreign_ids += usize::from(
                    usize::from(sector.cylinder) != cylinder || usize::from(sector.head) != side,
                );
                census.flagged += usize::from(sector.st1 != 0 || sector.st2 != 0);
                census.weak += usize::from(sector.is_weak());
                census.short += usize::from(sector.is_short());
            }
        }
        census
    }

    /// What follows the last track block, if anything.
    pub(super) fn trailing_note(&self, data: &[u8]) -> Option<String> {
        let trailer = data.get(self.end..).filter(|t| !t.is_empty())?;
        let size = trailer.len();
        let at = self.end;
        Some(if trailer.starts_with(OFFSET_INFO_MAGIC) {
            format!(
                "{size} B after the last track at 0x{at:X} are a LibDsk Offset-Info block (not \
                 used)"
            )
        } else if is_padding(trailer) {
            format!("{size} B of padding after the last track at 0x{at:X}")
        } else {
            format!("{size} B after the last track at 0x{at:X} are not part of the image")
        })
    }
}

/// What the notes report about the tracks: copy protection and damage are
/// facts of the dump, not parse errors.
#[derive(Debug, Default)]
pub(super) struct Census {
    pub(super) formatted: usize,
    /// No track block (extended size 0) or a block without sectors.
    pub(super) unformatted: usize,
    pub(super) sectors: usize,
    /// Sectors with ST1 or ST2 bits set.
    pub(super) flagged: usize,
    /// Sectors stored as several copies.
    pub(super) weak: usize,
    /// Sectors stored shorter than their size code.
    pub(super) short: usize,
    /// Track-Info blocks whose track or side number is not their position.
    pub(super) misnumbered: usize,
    /// Sectors whose ID field names another cylinder or head.
    pub(super) foreign_ids: usize,
}

impl Census {
    /// Notes for the tracks.
    pub(super) fn report(&self, c: &mut Container<'_>) {
        c.notes.push(format!(
            "Tracks: {} formatted, {} unformatted; {}",
            self.formatted,
            self.unformatted,
            counted(self.sectors, "sector", "sectors")
        ));
        if self.flagged > 0 {
            c.notes.push(format!(
                "{} FDC status flags (ST1/ST2) recorded by the dump: copy protection or read \
                 errors",
                counted(self.flagged, "sector carries", "sectors carry")
            ));
        }
        if self.weak > 0 {
            c.notes.push(format!(
                "{} several copies of their data (weak sectors); the first copy is read",
                counted(self.weak, "sector stores", "sectors store")
            ));
        }
        if self.short > 0 {
            c.notes.push(format!(
                "{} less data than their size code names",
                counted(self.short, "sector stores", "sectors store")
            ));
        }
        if self.misnumbered > 0 {
            c.notes.push(format!(
                "{} a track or side number other than their position in the image",
                counted(
                    self.misnumbered,
                    "Track-Info block records",
                    "Track-Info blocks record"
                )
            ));
        }
        if self.foreign_ids > 0 {
            c.notes.push(format!(
                "{} another cylinder or head than the track holding them",
                counted(
                    self.foreign_ids,
                    "sector ID field names",
                    "sector ID fields name"
                )
            ));
        }
    }
}

/// Parse the disk information block and every track block.
pub(super) fn parse(data: &[u8], layout: Layout) -> Result<Disk<'_>> {
    let info = slice(data, 0, INFO_SIZE).map_err(|_| {
        error(format!(
            "Truncated disk information block: {} B of {INFO_SIZE} B",
            data.len()
        ))
    })?;
    let documented_text: &[u8] = match layout {
        Layout::Extended => EXTENDED_TEXT,
        _ => STANDARD_TEXT,
    };
    let cylinders = usize::from(info[TRACKS_OFFSET]);
    let sides_byte = info[SIDES_OFFSET];
    if sides_byte == 0 || sides_byte > MAX_SIDES {
        return Err(error(format!("Invalid side count {sides_byte}")));
    }
    let sides = usize::from(sides_byte);
    let sizes = track_sizes(info, layout, cylinders * sides)?;
    let mut tracks = Vec::with_capacity(sizes.len());
    let mut offset = INFO_SIZE;
    for (index, &size) in sizes.iter().enumerate() {
        let position = TrackPosition {
            cylinder: index / sides,
            side: index % sides,
            offset,
        };
        if size == 0 {
            tracks.push(None);
            continue;
        }
        tracks.push(Some(parse_track(data, position, size, layout)?));
        // `parse_track` read `size` bytes at `offset`, so this stays in the
        // file.
        offset += size;
    }
    Ok(Disk {
        creator: printable(&info[CREATOR_OFFSET..CREATOR_OFFSET + CREATOR_SIZE]),
        documented_signature: info.starts_with(documented_text),
        cylinders,
        sides,
        tracks,
        end: offset,
    })
}

/// The size of each of `count` track blocks in image order.
fn track_sizes(info: &[u8], layout: Layout, count: usize) -> Result<Vec<usize>> {
    if layout == Layout::Extended {
        let table = info
            .get(TRACK_TABLE_OFFSET..TRACK_TABLE_OFFSET + count)
            .ok_or_else(|| {
                error(format!(
                    "Invalid track count: {count} tracks and sides exceed the \
                     {TRACK_TABLE_ENTRIES}-entry track size table"
                ))
            })?;
        return Ok(table
            .iter()
            .map(|&size| usize::from(size) * TRACK_SIZE_UNIT)
            .collect());
    }
    let size = usize::from(le_u16(info, TRACK_SIZE_OFFSET)?);
    if count > 0 && size < TRACK_INFO_SIZE {
        return Err(error(format!(
            "Invalid track size 0x{size:X} B: smaller than the {TRACK_INFO_SIZE} B Track-Info block"
        )));
    }
    Ok(vec![size; count])
}

/// Where a track block is: its place in the image and its file offset.
#[derive(Debug, Clone, Copy)]
struct TrackPosition {
    cylinder: usize,
    side: usize,
    offset: usize,
}

/// Bytes stored per sector of a standard image whose Track-Info block
/// names size code `size_code`, or `None` for an undescribed code.
fn standard_stride(size_code: u8) -> Option<usize> {
    match size_code {
        0..=5 => Some(128 << size_code),
        SIZE_CODE_8K => Some(STORED_8K),
        _ => None,
    }
}

/// The track block of `size` bytes at `position`: the Track-Info block and
/// every sector's data inside the block.
fn parse_track(
    data: &[u8],
    position: TrackPosition,
    size: usize,
    layout: Layout,
) -> Result<Track<'_>> {
    let TrackPosition {
        cylinder,
        side,
        offset,
    } = position;
    let block = slice(data, offset, size).map_err(|_| {
        error(format!(
            "Truncated track {cylinder} side {side} at 0x{offset:X}: {size} B declared, {} B \
             present",
            data.len().saturating_sub(offset)
        ))
    })?;
    if !block.starts_with(TRACK_INFO_MAGIC) {
        return Err(error(format!(
            "Missing Track-Info block for track {cylinder} side {side} at 0x{offset:X}"
        )));
    }
    let count = usize::from(block[SECTOR_COUNT_OFFSET]);
    let list_end = SECTOR_LIST_OFFSET + count * SECTOR_INFO_SIZE;
    let data_start = round_up(list_end, TRACK_INFO_SIZE).max(TRACK_INFO_SIZE);
    if data_start > size {
        return Err(error(format!(
            "Invalid track {cylinder} side {side} at 0x{offset:X}: {count} sectors need a \
             0x{data_start:X} B Track-Info block in a 0x{size:X} B track"
        )));
    }
    let size_code = block[SIZE_CODE_OFFSET];
    let stride = match layout {
        Layout::Standard if count > 0 => Some(standard_stride(size_code).ok_or_else(|| {
            error(format!(
                "Unsupported sector size code {size_code} for track {cylinder} side {side} of a \
                 standard image"
            ))
        })?),
        _ => None,
    };
    let mut sectors = Vec::with_capacity(count);
    let mut start = data_start;
    for info in block[SECTOR_LIST_OFFSET..list_end].chunks_exact(SECTOR_INFO_SIZE) {
        let stored = stride.unwrap_or_else(|| usize::from(u16::from_le_bytes([info[6], info[7]])));
        let end = start + stored;
        if end > size {
            return Err(error(format!(
                "Invalid track {cylinder} side {side} at 0x{offset:X}: sector data ends 0x{end:X} \
                 B into a 0x{size:X} B track"
            )));
        }
        sectors.push(Sector {
            cylinder: info[0],
            head: info[1],
            id: info[2],
            size_code: info[3],
            st1: info[4],
            st2: info[5],
            offset: offset + start,
            data: &block[start..end],
        });
        start = end;
    }
    Ok(Track {
        number: block[TRACK_NUMBER_OFFSET],
        side: block[SIDE_NUMBER_OFFSET],
        sectors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_strides_follow_the_size_code() {
        assert_eq!(standard_stride(0), Some(128));
        assert_eq!(standard_stride(2), Some(512));
        assert_eq!(standard_stride(6), Some(0x1800));
        assert_eq!(standard_stride(7), None);
    }

    #[test]
    fn weak_and_short_sectors_compare_with_the_size_code() {
        let bytes = [0u8; 1024];
        let sector = |size_code: u8, len: usize| Sector {
            cylinder: 0,
            head: 0,
            id: 0xc1,
            size_code,
            st1: 0,
            st2: 0,
            offset: 0,
            data: &bytes[..len],
        };
        assert!(sector(2, 1024).is_weak());
        assert!(!sector(2, 512).is_weak());
        assert!(sector(2, 256).is_short());
        assert!(!sector(2, 512).is_short());
        // N = 8 reads as N = 0: 128 bytes.
        assert_eq!(sector(8, 128).nominal_size(), 128);
    }

    #[test]
    fn track_blocks_with_many_sectors_grow_in_256_byte_steps() {
        // 30 sectors: the list ends at 0x18 + 30 * 8 = 0x108, so data starts
        // at 0x200 ([LIBDSK]).
        let mut block = vec![0u8; 0x200 + 30 * 128];
        block[..10].copy_from_slice(TRACK_INFO_MAGIC);
        block[SECTOR_COUNT_OFFSET] = 30;
        for (i, info) in block[SECTOR_LIST_OFFSET..SECTOR_LIST_OFFSET + 30 * 8]
            .chunks_exact_mut(8)
            .enumerate()
        {
            info[2] = u8::try_from(i + 1).unwrap();
            info[6] = 0x80;
        }
        let position = TrackPosition {
            cylinder: 0,
            side: 0,
            offset: 0,
        };
        let track = parse_track(&block, position, block.len(), Layout::Extended).unwrap();
        assert_eq!(track.sectors.len(), 30);
        assert_eq!(track.sectors[0].offset, 0x200);
        assert_eq!(track.sector(30).unwrap().offset, 0x200 + 29 * 128);
        assert_eq!(track.lowest_id(), Some(1));
    }
}
