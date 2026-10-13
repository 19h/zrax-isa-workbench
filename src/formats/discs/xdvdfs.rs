//! XDVDFS, the filesystem of Xbox and Xbox 360 game discs (sources in the
//! family module): a volume descriptor at sector 32 of the game partition,
//! and directory tables whose entries form a binary search tree linked by
//! offsets in 4-byte units.
//!
//! Every field is little-endian. Sector numbers count 2048-byte sectors
//! from the start of the game partition, which is 0 in an XISO image and
//! later in a full disc image. Neither extract-xiso nor xdvdfs guards
//! against links that form cycles; this walk visits each entry and each
//! directory table at most once and bounds the total work by the image
//! size.

use super::*;
use std::collections::BTreeSet;

/// Sector size (`XISO_SECTOR_SIZE`, xdvdfs `SECTOR_SIZE`).
const SECTOR_SIZE: u64 = 2048;

/// The volume descriptor: sector 32 of the game partition
/// (`XISO_HEADER_OFFSET`), one sector long.
const VOLUME_DESCRIPTOR_OFFSET: usize = 0x10000;
const VOLUME_DESCRIPTOR_SIZE: usize = 0x800;

/// Magic at the start and end (0x7EC) of the volume descriptor
/// (`XISO_HEADER_DATA`, xdvdfs `VOLUME_HEADER_MAGIC`).
const VOLUME_MAGIC: &[u8; 20] = b"MICROSOFT*XBOX*MEDIA";
const TRAILING_MAGIC_OFFSET: usize = 0x7EC;

/// Volume descriptor fields: root directory table sector and size in
/// bytes, then a Win32 `FILETIME`.
const ROOT_SECTOR_FIELD: usize = 0x14;
const ROOT_SIZE_FIELD: usize = 0x18;
const FILETIME_FIELD: usize = 0x1C;

/// A directory entry: left and right subtree links (0 and 2), start
/// sector (4), size in bytes (8), attributes (12), name length (13), then
/// the name (`XISO_FILENAME_OFFSET`).
const ENTRY_HEADER_SIZE: usize = 14;

/// Subtree links count 4-byte units from the start of the table
/// (`XISO_DWORD_SIZE`).
const LINK_UNIT: usize = 4;

/// Links that mean "no subtree": 0 (extract-xiso, xenia, xdvdfs) and
/// 0xFFFF (xdvdfs).
const NO_LINK: u16 = 0;
const PADDING_LINK: u16 = 0xFFFF;

/// Directory attribute (`XISO_ATTRIBUTE_DIR`).
const ATTRIBUTE_DIRECTORY: u8 = 0x10;

/// Most directory entries walked in one image. Every entry costs a
/// bounded amount of work and memory, and real discs hold far fewer.
const MAX_DIRECTORY_ENTRIES: usize = 1 << 20;

/// Windows-1252 code points of bytes 0x80-0x9F, which xdvdfs uses for
/// names; the five unassigned bytes map to C1 controls, as in the WHATWG
/// encoding. Bytes 0xA0-0xFF are Latin-1.
#[rustfmt::skip]
const WINDOWS_1252_80_9F: [char; 32] = [
    '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}',
    '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
];

/// Strong recognition: the volume descriptor magic at sector 32 of a
/// documented game partition start.
pub(super) fn detect(data: &[u8]) -> Option<Layout> {
    XdvdfsImage::ALL
        .into_iter()
        .find(|image| has_volume_magic(data, image.partition_offset()))
        .map(Layout::Xdvdfs)
}

fn has_volume_magic(data: &[u8], partition_offset: usize) -> bool {
    let at = partition_offset + VOLUME_DESCRIPTOR_OFFSET;
    data.get(at..at + VOLUME_MAGIC.len()) == Some(VOLUME_MAGIC.as_slice())
}

/// A name in Windows-1252.
fn windows_1252(raw: &[u8]) -> String {
    raw.iter()
        .map(|&b| match b {
            0x80..=0x9F => WINDOWS_1252_80_9F[usize::from(b - 0x80)],
            _ => char::from(b),
        })
        .collect()
}

/// Parse an XDVDFS image: the volume descriptor and every file in the
/// directory tree that is a recognized format.
pub(super) fn parse(data: &[u8], image: XdvdfsImage) -> Result<Container<'_>> {
    let partition_offset = image.partition_offset();
    let descriptor_offset = partition_offset + VOLUME_DESCRIPTOR_OFFSET;
    let descriptor = slice(data, descriptor_offset, VOLUME_DESCRIPTOR_SIZE).map_err(|_| {
        error(format!(
            "Truncated XDVDFS volume descriptor at 0x{descriptor_offset:X}"
        ))
    })?;
    if !descriptor.starts_with(VOLUME_MAGIC) {
        return Err(error(format!(
            "Invalid XDVDFS volume descriptor magic at 0x{descriptor_offset:X}"
        )));
    }
    if &descriptor[TRAILING_MAGIC_OFFSET..] != VOLUME_MAGIC.as_slice() {
        return Err(error(format!(
            "Invalid XDVDFS volume descriptor: missing trailing magic at 0x{:X}",
            descriptor_offset + TRAILING_MAGIC_OFFSET
        )));
    }
    let root = Table {
        sector: le_u32(descriptor, ROOT_SECTOR_FIELD)?,
        size: le_u32(descriptor, ROOT_SIZE_FIELD)?,
        path: String::new(),
        depth: 0,
    };
    let filetime = le_u64(descriptor, FILETIME_FIELD)?;
    let mut c = Container::new(FileFormat::XboxDvd, image.label(), "xdvdfs");
    c.consumed = data.len();
    c.notes.push(format!(
        "Game partition at 0x{partition_offset:X}; root directory table at sector {}, {} B",
        root.sector, root.size
    ));
    if partition_offset > 0 {
        c.notes.push(format!(
            "The 0x{partition_offset:X} B before the game partition are not parsed"
        ));
    }
    let prefix = c.key_prefix;
    c.push_metadata(
        format!("{prefix}_partition_offset"),
        "Game partition offset",
        partition_offset as u64,
    );
    c.push_metadata(
        format!("{prefix}_root_sector"),
        "Root directory table sector",
        u64::from(root.sector),
    );
    c.push_metadata(
        format!("{prefix}_root_size"),
        "Root directory table size (B)",
        u64::from(root.size),
    );
    c.push_metadata(
        format!("{prefix}_filetime"),
        "Volume timestamp (FILETIME)",
        filetime,
    );
    let mut walk = Walk {
        data,
        partition_offset: partition_offset as u64,
        members: Members::new(is_prefix_recognized),
        pending: Vec::new(),
        walked_sectors: BTreeSet::new(),
        walked_bytes: 0,
        entries: 0,
    };
    if root.size == 0 {
        c.notes.push("The image contains no files".into());
    } else {
        walk.pending.push(root);
    }
    while let Some(table) = walk.pending.pop() {
        walk.walk_table(&table)?;
    }
    walk.members.finish(&mut c);
    Ok(c)
}

/// A directory table waiting to be walked.
struct Table {
    /// First sector, from the game partition start.
    sector: u32,
    /// Size in bytes.
    size: u32,
    /// Path of the directory (empty for the root).
    path: String,
    /// Nesting depth (0 for the root).
    depth: usize,
}

/// A directory entry (extract-xiso `traverse_xiso`; xdvdfs
/// `DirectoryEntryDiskNode`), its name borrowed from its table.
#[derive(Clone, Copy)]
struct Entry<'t> {
    left: u16,
    right: u16,
    sector: u32,
    size: u32,
    attributes: u8,
    name: &'t [u8],
}

impl Entry<'_> {
    fn is_directory(&self) -> bool {
        self.attributes & ATTRIBUTE_DIRECTORY != 0
    }
}

/// Byte offset in the table that a subtree link names, or `None` for no
/// subtree.
fn link_offset(link: u16) -> Option<usize> {
    (link != NO_LINK && link != PADDING_LINK).then(|| usize::from(link) * LINK_UNIT)
}

/// The entry at `offset` of `table`, which is stored at `table_offset`, or
/// `None` for an empty slot (14 bytes of 0xFF or 0x00, xdvdfs
/// `DirectoryEntryNode::deserialize`). Names follow extract-xiso's rule
/// (no `.`, `..`, `/` or `\`) and must not be empty.
fn entry_at(table: &[u8], offset: usize, table_offset: u64) -> Result<Option<Entry<'_>>> {
    let position = table_offset + offset as u64;
    let header = slice(table, offset, ENTRY_HEADER_SIZE).map_err(|_| {
        error(format!(
            "Truncated XDVDFS directory entry at 0x{position:X}"
        ))
    })?;
    if header.iter().all(|&b| b == 0xFF) || header.iter().all(|&b| b == 0) {
        return Ok(None);
    }
    let name_len = usize::from(header[13]);
    let name = slice(table, offset + ENTRY_HEADER_SIZE, name_len).map_err(|_| {
        error(format!(
            "Truncated XDVDFS file name at 0x{:X}",
            position + ENTRY_HEADER_SIZE as u64
        ))
    })?;
    let is_invalid_name = name.is_empty()
        || name == b"."
        || name == b".."
        || name.iter().any(|&b| b == b'/' || b == b'\\');
    if is_invalid_name {
        return Err(error(format!("Invalid XDVDFS file name at 0x{position:X}")));
    }
    Ok(Some(Entry {
        left: le_u16(header, 0)?,
        right: le_u16(header, 2)?,
        sector: le_u32(header, 4)?,
        size: le_u32(header, 8)?,
        attributes: header[12],
        name,
    }))
}

/// The state of the directory walk over one image.
struct Walk<'a> {
    data: &'a [u8],
    /// File offset of the game partition.
    partition_offset: u64,
    members: Members<'a>,
    /// Directory tables still to walk, the next one last.
    pending: Vec<Table>,
    /// Sectors of the tables walked so far: a table reached twice means
    /// the directory links form a cycle.
    walked_sectors: BTreeSet<u32>,
    /// Bytes of the tables walked so far. Tables of a valid image do not
    /// overlap, so they cannot add up to more than the image.
    walked_bytes: u64,
    /// Directory entries walked so far, bounded by [`MAX_DIRECTORY_ENTRIES`].
    entries: usize,
}

impl<'a> Walk<'a> {
    /// File offset of `sector` of the game partition.
    fn sector_offset(&self, sector: u32) -> u64 {
        self.partition_offset + u64::from(sector) * SECTOR_SIZE
    }

    /// Walk one directory table in tree order (left subtree, entry, right
    /// subtree), so entries come sorted by name as the tools write them.
    /// Each entry offset is visited at most once.
    fn walk_table(&mut self, table: &Table) -> Result<()> {
        if !self.walked_sectors.insert(table.sector) {
            return Err(error(format!(
                "Invalid XDVDFS directory tree: the table at sector {} is reached twice",
                table.sector
            )));
        }
        self.walked_bytes += u64::from(table.size);
        if self.walked_bytes > self.data.len() as u64 {
            return Err(error(
                "Invalid XDVDFS directory tables: they span more bytes than the image",
            ));
        }
        let table_offset = self.sector_offset(table.sector);
        let data = self.data;
        let bytes = range(data, table_offset, u64::from(table.size)).ok_or_else(|| {
            error(format!(
                "Truncated XDVDFS directory table at 0x{table_offset:X} + {} B",
                table.size
            ))
        })?;
        // One bit per 4-byte slot that a link can name.
        let mut visited = vec![0u64; bytes.len() / LINK_UNIT / 64 + 1];
        let mut ancestors: Vec<Entry<'a>> = Vec::new();
        let mut subdirectories = Vec::new();
        let mut next = Some(0usize);
        loop {
            while let Some(offset) = next {
                let slot = offset / LINK_UNIT;
                let Some(word) = visited.get_mut(slot / 64) else {
                    return Err(error(format!(
                        "Truncated XDVDFS directory entry at 0x{:X}",
                        table_offset + offset as u64
                    )));
                };
                let bit = 1u64 << (slot % 64);
                if *word & bit != 0 {
                    return Err(error(format!(
                        "Invalid XDVDFS directory tree: the entry at 0x{:X} is reached twice",
                        table_offset + offset as u64
                    )));
                }
                *word |= bit;
                self.entries += 1;
                if self.entries > MAX_DIRECTORY_ENTRIES {
                    return Err(error(format!(
                        "Unsupported XDVDFS image: more than {MAX_DIRECTORY_ENTRIES} directory entries"
                    )));
                }
                next = match entry_at(bytes, offset, table_offset)? {
                    Some(entry) => {
                        ancestors.push(entry);
                        link_offset(entry.left)
                    }
                    None => None,
                };
            }
            let Some(entry) = ancestors.pop() else {
                break;
            };
            next = link_offset(entry.right);
            if let Some(subdirectory) = self.visit(&entry, table) {
                subdirectories.push(subdirectory);
            }
        }
        // Walk subdirectories in name order: the next one goes last.
        self.pending.extend(subdirectories.into_iter().rev());
        Ok(())
    }

    /// Offer a file to the member listing, or return a directory's table
    /// to walk.
    fn visit(&mut self, entry: &Entry<'_>, table: &Table) -> Option<Table> {
        let path = format!("{}/{}", table.path, windows_1252(entry.name));
        if !entry.is_directory() {
            let offset = self.sector_offset(entry.sector);
            self.members
                .offer(self.data, &path, offset, u64::from(entry.size));
            return None;
        }
        // A directory of size 0 has no table (extract-xiso, xenia).
        if entry.size == 0 {
            return None;
        }
        let depth = table.depth + 1;
        if !is_walkable(depth, &path) {
            self.members.unwalked_directories += 1;
            return None;
        }
        Some(Table {
            sector: entry.sector,
            size: entry.size,
            path,
            depth,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_decode_as_windows_1252() {
        assert_eq!(windows_1252(b"default.xbe"), "default.xbe");
        assert_eq!(
            windows_1252(&[b'A', 0x80, 0x9F, 0xE9]),
            "A\u{20AC}\u{0178}\u{E9}"
        );
    }

    #[test]
    fn links_of_zero_and_0xffff_name_no_subtree() {
        assert_eq!(link_offset(0), None);
        assert_eq!(link_offset(0xFFFF), None);
        assert_eq!(link_offset(3), Some(12));
    }

    #[test]
    fn empty_slots_and_bad_names_are_recognized() {
        assert!(entry_at(&[0xFF; 16], 0, 0).unwrap().is_none());
        assert!(entry_at(&[0x00; 16], 0, 0).unwrap().is_none());
        let mut entry = vec![0u8; ENTRY_HEADER_SIZE];
        entry[8] = 1;
        entry[13] = 2;
        entry.extend_from_slice(b"..");
        assert!(entry_at(&entry, 0, 0).is_err());
        entry[ENTRY_HEADER_SIZE..].copy_from_slice(b"ok");
        assert_eq!(entry_at(&entry, 0, 0).unwrap().unwrap().name, b"ok");
        assert!(entry_at(&entry[..15], 0, 0).is_err());
    }
}
