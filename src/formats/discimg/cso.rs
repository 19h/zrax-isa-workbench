//! PSP CSO and ZSO images (maxcso v1.13.0 `README_CSO.md`,
//! `README_ZSO.md`, `src/cso.h`, `src/input.cpp`; PPSSPP v1.17.1
//! `Core/FileSystems/BlockDevices.cpp`).
//!
//! A 0x18-byte little-endian header: the magic `CISO` or `ZISO` (0x00),
//! the header size (0x04, unreliable in version 1), the uncompressed size
//! (0x08, 8 B), the block size (0x10), the version (0x14), the index shift
//! (0x15) and two unused bytes. Then one 32-bit index entry per block and
//! one more from 0x18, `ceil(uncompressed size / block size) + 1` in all:
//! the low 31 bits shifted left by the index shift give a block's file
//! offset, and the next entry ends it,
//! so a stored length may include alignment padding. The last entry ends
//! the data. The high bit marks a block stored uncompressed in version 0,
//! version 1 and ZSO. In version 2 a block whose stored length is at least
//! the block size is uncompressed, and the high bit selects LZ4 over
//! DEFLATE for the others. CSO blocks are raw DEFLATE with a 15-bit window
//! (`inflateInit2(&z, -15)`), LZ4 blocks raw LZ4 blocks. Nothing is
//! checksummed.

use super::*;

/// The magics at 0 (`CSO_MAGIC`, `ZSO_MAGIC`).
const CSO_MAGIC: &[u8; 4] = b"CISO";
const ZSO_MAGIC: &[u8; 4] = b"ZISO";

/// `sizeof(CSOHeader)`, where the index starts.
const HEADER_SIZE: usize = 0x18;

/// Header field offsets.
const HEADER_SIZE_FIELD: usize = 0x04;
const UNCOMPRESSED_SIZE: usize = 0x08;
const BLOCK_SIZE: usize = 0x10;
const VERSION: usize = 0x14;
const INDEX_SHIFT: usize = 0x15;
const UNUSED: usize = 0x16;

/// `SECTOR_SIZE`: the smallest block size PPSSPP and maxcso accept.
const MIN_BLOCK_SIZE: u32 = 0x800;

/// maxcso rejects versions past 2 ("unsupported version").
const MAX_VERSION: u8 = 2;
const VERSION_2: u8 = 2;

/// The high index bit: `CSO_INDEX_UNCOMPRESSED` in version 1 and ZSO,
/// `CSO2_INDEX_LZ4` in version 2.
const INDEX_FLAG: u32 = 0x8000_0000;

/// The low 31 bits of an index entry: the block position before the shift.
const INDEX_POSITION_MASK: u32 = 0x7FFF_FFFF;

/// One index entry.
const INDEX_ENTRY_SIZE: usize = 4;

/// Largest index shift accepted. Our bound: a 31-bit position shifted
/// further would lie past 2^63.
const MAX_INDEX_SHIFT: u8 = 32;

/// The header fields after the magic.
struct Header {
    /// The header size field (0x04).
    stated_size: u32,
    uncompressed_size: u64,
    block_size: u32,
    version: u8,
    index_shift: u8,
    unused: [u8; 2],
}

/// One index entry.
struct Entry {
    /// File offset of the block: the low 31 bits shifted by the index
    /// shift.
    position: u64,
    /// The high bit.
    flag: bool,
}

/// How a block is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Storage {
    Uncompressed,
    Deflate,
    Lz4,
}

fn header(data: &[u8]) -> Result<Header> {
    let what = "CSO header";
    let header = slice(data, 0, HEADER_SIZE, what)?;
    Ok(Header {
        stated_size: le_u32(header, HEADER_SIZE_FIELD, what)?,
        uncompressed_size: le_u64(header, UNCOMPRESSED_SIZE, what)?,
        block_size: le_u32(header, BLOCK_SIZE, what)?,
        version: header[VERSION],
        index_shift: header[INDEX_SHIFT],
        unused: [header[UNUSED], header[UNUSED + 1]],
    })
}

/// Whether `block_size` is a power of two of at least 2 KiB, as PPSSPP's
/// `CISOFileBlockDevice` requires.
fn is_valid_block_size(block_size: u32) -> bool {
    block_size.is_power_of_two() && block_size >= MIN_BLOCK_SIZE
}

/// Strong recognition: `CISO` or `ZISO`, a power-of-two block size of at
/// least 2 KiB and a version maxcso reads (0 to 2), so the 32-bit magic
/// alone is not enough. `GameCube` CISO images are tested first.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    let zso = data.starts_with(ZSO_MAGIC);
    if !zso && !data.starts_with(CSO_MAGIC) {
        return None;
    }
    let header = header(data).ok()?;
    if !is_valid_block_size(header.block_size) || header.version > MAX_VERSION {
        return None;
    }
    Some(Layout::Cso(if zso {
        Cso::Zso
    } else if header.version == VERSION_2 {
        Cso::V2
    } else {
        Cso::V1
    }))
}

/// Name of the flavour in notes and errors.
fn name(version: Cso) -> &'static str {
    match version {
        Cso::V1 | Cso::V2 => "CSO",
        Cso::Zso => "ZSO",
    }
}

/// Parse a CSO or ZSO image: the header, the index, and the disc as one
/// child.
pub(super) fn parse(data: &[u8], version: Cso) -> Result<Container<'_>> {
    let what = name(version);
    let magic = if version == Cso::Zso {
        ZSO_MAGIC
    } else {
        CSO_MAGIC
    };
    if !data.starts_with(magic) {
        return Err(error(format!("Missing {what} magic at 0x0")));
    }
    let header = header(data)?;
    validate(&header, version)?;
    let block_size = u64::from(header.block_size);
    let blocks = div_ceil(header.uncompressed_size, block_size);
    let entries = index(data, &header, blocks, what)?;
    let storage: Vec<Storage> = entries
        .windows(2)
        .map(|pair| {
            storage_of(
                version,
                &pair[0],
                pair[1].position - pair[0].position,
                block_size,
            )
        })
        .collect();
    let count = |kind: Storage| storage.iter().filter(|s| **s == kind).count();

    let mut c = Container::new(FileFormat::Cso, Layout::Cso(version).label(), "cso");
    c.notes.push(format!(
        "{what} version {}: {} of {}; {} DEFLATE, {} LZ4, {} stored uncompressed; index shift {}; disc size {} B; header size field 0x{:X}",
        header.version,
        counted(blocks, "block", "blocks"),
        size_text(header.block_size as usize),
        count(Storage::Deflate),
        count(Storage::Lz4),
        count(Storage::Uncompressed),
        header.index_shift,
        header.uncompressed_size,
        header.stated_size
    ));
    let data_start = entries[0].position;
    let data_end = entries[entries.len() - 1].position;
    check_extent(&mut c, data, data_end, &format!("the {what} blocks"))?;
    push_metadata(&mut c, &header);
    let disc = decode(data, &header, &entries, &storage, what)?;
    if disc.size == 0 {
        c.notes.push(format!(
            "The {what} holds an empty disc (uncompressed size 0)"
        ));
    } else {
        let offset = usize::try_from(data_start).expect("the data start lies in the file");
        let stored = StoredSpan {
            offset,
            size: usize::try_from(data_end - data_start)
                .unwrap_or(usize::MAX)
                .min(data.len() - offset),
        };
        push_disc(&mut c, "Disc image".into(), disc, stored, what);
    }
    push_no_isa_note(&mut c, what);
    Ok(c)
}

/// The header checks that detection leaves to the parser, and the stricter
/// version 2 header (`README_CSO.md`: header size "Must always be 0x18",
/// unused bytes "Must be 0").
fn validate(header: &Header, version: Cso) -> Result<()> {
    let what = name(version);
    let block_size = header.block_size;
    if !is_valid_block_size(block_size) {
        return Err(error(format!(
            "Invalid {what} block size {block_size} B at 0x{BLOCK_SIZE:X}: not a power of two of at least 2 KiB"
        )));
    }
    if block_size as usize > MAX_PAYLOAD {
        return Err(error(format!(
            "Unsupported {what} block size {block_size} B (at most {})",
            size_text(MAX_PAYLOAD)
        )));
    }
    if header.version > MAX_VERSION {
        return Err(error(format!(
            "Unsupported {what} version {} at 0x{VERSION:X}",
            header.version
        )));
    }
    if header.index_shift > MAX_INDEX_SHIFT {
        return Err(error(format!(
            "Unsupported {what} index shift {} at 0x{INDEX_SHIFT:X} (at most {MAX_INDEX_SHIFT})",
            header.index_shift
        )));
    }
    if version == Cso::V2 && header.stated_size as usize != HEADER_SIZE {
        return Err(error(format!(
            "Invalid CSO v2 header size 0x{:X} at 0x{HEADER_SIZE_FIELD:X}: it must be 0x{HEADER_SIZE:X}",
            header.stated_size
        )));
    }
    if version == Cso::V2 && header.unused != [0, 0] {
        return Err(error(format!(
            "Invalid CSO v2 header: unused bytes at 0x{UNUSED:X} are {:02X} {:02X}, not 0",
            header.unused[0], header.unused[1]
        )));
    }
    Ok(())
}

/// The index: `blocks + 1` entries whose positions increase and start
/// after the index.
fn index(data: &[u8], header: &Header, blocks: u64, what: &str) -> Result<Vec<Entry>> {
    let entries = blocks + 1;
    let index_size = entries
        .checked_mul(INDEX_ENTRY_SIZE as u64)
        .filter(|size| *size <= data.len().saturating_sub(HEADER_SIZE) as u64)
        .ok_or_else(|| {
            error(format!(
                "Truncated {what} index: {entries} entries at 0x{HEADER_SIZE:X}; the file holds {} B",
                data.len()
            ))
        })?;
    let index_end = HEADER_SIZE as u64 + index_size;
    let count = usize::try_from(entries).expect("the index lies in the file");
    let mut entries: Vec<Entry> = Vec::with_capacity(count);
    for i in 0..count {
        let at = HEADER_SIZE + i * INDEX_ENTRY_SIZE;
        let raw = le_u32(data, at, "CSO index")?;
        let position = u64::from(raw & INDEX_POSITION_MASK) << header.index_shift;
        match entries.last().map(|entry| entry.position) {
            None if position < index_end => {
                return Err(error(format!(
                    "Invalid {what} index entry 0 at 0x{at:X}: block 0 at 0x{position:X} lies inside the index, which ends at 0x{index_end:X}"
                )));
            }
            Some(previous) if position < previous => {
                return Err(error(format!(
                    "Invalid {what} index entry {i} at 0x{at:X}: position 0x{position:X} is before the previous 0x{previous:X}"
                )));
            }
            _ => {}
        }
        let flag = raw & INDEX_FLAG != 0;
        if i + 1 == count && header.version == VERSION_2 && flag {
            return Err(error(format!(
                "Invalid CSO v2 index entry {i} at 0x{at:X}: the final entry has the high bit set"
            )));
        }
        entries.push(Entry { position, flag });
    }
    Ok(entries)
}

/// How the block of index entry `entry` with `stored_size` bytes is
/// stored (maxcso `Input::ReadSector`).
fn storage_of(version: Cso, entry: &Entry, stored_size: u64, block_size: u64) -> Storage {
    match version {
        Cso::V1 | Cso::Zso if entry.flag => Storage::Uncompressed,
        Cso::V1 => Storage::Deflate,
        Cso::Zso => Storage::Lz4,
        Cso::V2 if stored_size >= block_size => Storage::Uncompressed,
        Cso::V2 if entry.flag => Storage::Lz4,
        Cso::V2 => Storage::Deflate,
    }
}

fn push_metadata(c: &mut Container<'_>, header: &Header) {
    c.push_metadata("cso_version", "Version", u64::from(header.version));
    c.push_metadata(
        "cso_block_size",
        "Block size (B)",
        u64::from(header.block_size),
    );
    c.push_metadata(
        "cso_index_shift",
        "Index shift",
        u64::from(header.index_shift),
    );
    c.push_metadata("cso_disc_size", "Disc size (B)", header.uncompressed_size);
}

/// Decode the blocks the disc prefix covers. Each must lie in the file and
/// hold every disc byte of its block: the block size, or the rest of the
/// disc for the last block. PPSSPP wants the block size from every block;
/// maxcso trims the last block's output at the uncompressed size.
fn decode(
    data: &[u8],
    header: &Header,
    entries: &[Entry],
    storage: &[Storage],
    what: &str,
) -> Result<Disc> {
    let block_size = u64::from(header.block_size);
    let mut disc = Disc::new(header.uncompressed_size);
    let needed = usize::try_from(disc.blocks(block_size)).expect("at most one block per byte");
    for (i, kind) in storage.iter().enumerate().take(needed) {
        let at = entries[i].position;
        let stored_size = entries[i + 1].position - at;
        let holds = (header.uncompressed_size - i as u64 * block_size).min(block_size);
        let stored = range(data, at, stored_size).ok_or_else(|| {
            error(format!(
                "Truncated {what} block {i} at 0x{at:X} + {stored_size} B: it lies outside the file"
            ))
        })?;
        let block = format!("{what} block {i} at 0x{at:X}");
        let decoded = match kind {
            Storage::Uncompressed => Cow::Borrowed(stored),
            Storage::Deflate => Cow::Owned(decode_block(
                Codec::Deflate,
                stored,
                header.block_size as usize,
                &block,
            )?),
            Storage::Lz4 => Cow::Owned(decode_block(
                Codec::Lz4Block,
                stored,
                header.block_size as usize,
                &block,
            )?),
        };
        if (decoded.len() as u64) < holds {
            return Err(error(format!(
                "Invalid {block}: {} B {}, less than the {holds} B of the disc it holds",
                decoded.len(),
                if *kind == Storage::Uncompressed {
                    "stored"
                } else {
                    "decoded"
                }
            )));
        }
        let out = disc.block_mut(i as u64, block_size);
        let len = out.len();
        out.copy_from_slice(&decoded[..len]);
    }
    Ok(disc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes(magic: [u8; 4], block_size: u32, version: u8) -> Vec<u8> {
        let mut bytes = magic.to_vec();
        bytes.extend_from_slice(&0x18u32.to_le_bytes());
        bytes.extend_from_slice(&0x1000u64.to_le_bytes());
        bytes.extend_from_slice(&block_size.to_le_bytes());
        bytes.extend_from_slice(&[version, 0, 0, 0]);
        bytes
    }

    #[test]
    fn detection_reads_the_flavour_from_magic_and_version() {
        assert_eq!(
            detect(&header_bytes(*CSO_MAGIC, 0x800, 1)),
            Some(Layout::Cso(Cso::V1))
        );
        assert_eq!(
            detect(&header_bytes(*CSO_MAGIC, 0x800, 0)),
            Some(Layout::Cso(Cso::V1))
        );
        assert_eq!(
            detect(&header_bytes(*CSO_MAGIC, 0x4000, 2)),
            Some(Layout::Cso(Cso::V2))
        );
        assert_eq!(
            detect(&header_bytes(*ZSO_MAGIC, 0x800, 1)),
            Some(Layout::Cso(Cso::Zso))
        );
        assert_eq!(detect(&header_bytes(*CSO_MAGIC, 0x400, 1)), None);
        assert_eq!(detect(&header_bytes(*CSO_MAGIC, 0x1800, 1)), None);
        assert_eq!(detect(&header_bytes(*CSO_MAGIC, 0x800, 3)), None);
        assert_eq!(detect(&header_bytes(*CSO_MAGIC, 0x800, 1)[..0x17]), None);
    }

    #[test]
    fn version_2_storage_depends_on_the_stored_length() {
        let flagged = Entry {
            position: 0x40,
            flag: true,
        };
        let plain = Entry {
            position: 0x40,
            flag: false,
        };
        assert_eq!(
            storage_of(Cso::V1, &flagged, 10, 0x800),
            Storage::Uncompressed
        );
        assert_eq!(storage_of(Cso::V1, &plain, 10, 0x800), Storage::Deflate);
        assert_eq!(storage_of(Cso::Zso, &plain, 10, 0x800), Storage::Lz4);
        assert_eq!(
            storage_of(Cso::V2, &flagged, 0x800, 0x800),
            Storage::Uncompressed
        );
        assert_eq!(storage_of(Cso::V2, &flagged, 0x7FF, 0x800), Storage::Lz4);
        assert_eq!(storage_of(Cso::V2, &plain, 0x7FF, 0x800), Storage::Deflate);
    }
}
