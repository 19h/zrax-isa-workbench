//! The STFS file table (sources in the family module): 64-byte entries,
//! 64 to a block, in blocks chained through their level-0 hash records.
//! Each entry names its parent by the position of a directory entry in the
//! table (0xFFFF for the root). A file is read from consecutive blocks
//! when its entry says so (as Velocity extracts it) and by following the
//! next-block numbers of the hash records otherwise; it is probed with its
//! first block and listed as a child labeled by its path when it is a
//! recognized format.

use super::blocks::{StoredBlock, Volume, VolumeDescriptor, Walk, BLOCK_SHIFT, END_OF_CHAIN};
use super::*;
use crate::formats::compressed::size_text;
use crate::formats::container::{self, Child, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;
use std::collections::BTreeSet;

/// File table entries (Free60 "File Listing"; xenia `StfsDirectoryEntry`).
const ENTRY_SIZE: usize = 0x40;
const ENTRIES_PER_BLOCK: usize = BLOCK_SIZE / ENTRY_SIZE;

/// Entry fields: the NUL-padded name, the name length and flags byte, the
/// starting block (24-bit little-endian), the parent directory index and
/// the file size (big-endian).
const NAME_SIZE: usize = 0x28;
const FLAGS_FIELD: usize = 0x28;
const START_BLOCK_FIELD: usize = 0x2F;
const DIRECTORY_INDEX_FIELD: usize = 0x32;
const SIZE_FIELD: usize = 0x34;

/// Flags byte: bits 0-5 the name length, bit 6 consecutive blocks, bit 7 a
/// directory.
const NAME_LENGTH_MASK: u8 = 0x3F;
const CONSECUTIVE: u8 = 0x40;
const DIRECTORY: u8 = 0x80;

/// The directory index of an entry in the root directory.
const ROOT_INDEX: u16 = 0xFFFF;

/// Most file table blocks read. Directory indices are 16 bits and 0xFFFF
/// names the root, so no more than 65,535 entries can be parents; 1024
/// blocks hold 65,536 entries. The rest of a longer table is counted.
const MAX_FILE_TABLE_BLOCKS: usize = 1024;

/// Deepest directory nesting followed when a path is built.
const MAX_DEPTH: usize = 64;

/// Bytes of a file probed for a recognized format: its first block.
const RECOGNITION_PREFIX: usize = BLOCK_SIZE;

/// Problems named in notes; the rest are counted.
const MAX_PROBLEM_NOTES: usize = 8;

/// Transform of a file reassembled from blocks that are not stored
/// contiguously (hash tables between them, or a fragmented chain).
const BLOCKS_TRANSFORM: &str = "STFS data blocks";

/// A file table entry, its name borrowed from the table block.
struct Entry<'a> {
    name: &'a [u8],
    is_directory: bool,
    /// The file occupies consecutive data blocks from `start_block`.
    is_consecutive: bool,
    start_block: u32,
    /// Index of the parent directory entry, or [`ROOT_INDEX`].
    parent: u16,
    /// File size in bytes.
    size: u32,
    /// File offset of the entry.
    offset: usize,
}

/// A run of stored bytes that belong to one file.
#[derive(Debug, Clone, Copy)]
struct Extent {
    offset: usize,
    len: usize,
}

/// What the listing found and left out, for the notes.
#[derive(Debug, Default)]
struct Census {
    files: usize,
    directories: usize,
    /// Entries with name length 0, which Velocity skips.
    unnamed: usize,
    /// File table blocks not read because of [`MAX_FILE_TABLE_BLOCKS`].
    unread_blocks: usize,
    over_component_limit: usize,
    over_extraction_limit: usize,
    too_large: usize,
    /// Bytes charged so far against [`MAX_EXTRACTED`].
    charged: usize,
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

    /// Charge `size` bytes of work, or return false once [`MAX_EXTRACTED`]
    /// would pass.
    fn charge(&mut self, size: usize) -> bool {
        match self.charged.checked_add(size) {
            Some(total) if total <= MAX_EXTRACTED => {
                self.charged = total;
                true
            }
            _ => false,
        }
    }
}

/// Read the file table and list every file that is a recognized format as
/// a child of `c`, in table order.
///
/// # Errors
///
/// [`ClassifierError::StfsParseError`] when a file table block is not
/// allocated, lies outside the file, is reached twice, or the chain ends
/// before the declared block count.
pub(super) fn list<'a>(
    volume: &mut Volume<'a>,
    descriptor: &VolumeDescriptor,
    data: &'a [u8],
    c: &mut Container<'a>,
) -> Result<()> {
    let mut census = Census::default();
    let entries = read_table(volume, descriptor, &mut census)?;
    for entry in entries.iter().flatten() {
        if entry.is_directory {
            census.directories += 1;
        } else {
            offer(volume, data, &entries, entry, &mut census, c);
        }
    }
    finish(&census, descriptor, c);
    Ok(())
}

/// The entries of the file table by position; `None` marks an empty or
/// skipped slot.
fn read_table<'a>(
    volume: &mut Volume<'a>,
    descriptor: &VolumeDescriptor,
    census: &mut Census,
) -> Result<Vec<Option<Entry<'a>>>> {
    let declared = usize::from(descriptor.file_table_blocks);
    let readable = declared.min(MAX_FILE_TABLE_BLOCKS);
    census.unread_blocks = declared - readable;
    let mut entries = Vec::new();
    let mut visited = BTreeSet::new();
    let mut block = descriptor.file_table_block;
    for position in 0..readable {
        if !visited.insert(block) {
            return Err(error(format!(
                "Invalid STFS file table chain: block {block} is reached twice"
            )));
        }
        let stored = volume
            .block(block)
            .map_err(|defect| error(format!("Invalid STFS file table block {block}: {defect}")))?;
        read_entries(stored, &mut entries, census)?;
        entries.resize_with((position + 1) * ENTRIES_PER_BLOCK, || None);
        if position + 1 == readable {
            break;
        }
        block = volume
            .record(block)
            .map_err(|defect| error(format!("Invalid STFS file table block {block}: {defect}")))?
            .next_block;
        if block == END_OF_CHAIN {
            return Err(error(format!(
                "Invalid STFS file table chain: it ends after {} of {declared} blocks",
                position + 1
            )));
        }
    }
    Ok(entries)
}

/// The entries of one file table block. The first entry whose name starts
/// with NUL ends the block (xenia; Free60 ends the listing with an all-zero
/// entry); an entry with name length 0 is skipped (Velocity).
fn read_entries<'a>(
    stored: StoredBlock<'a>,
    entries: &mut Vec<Option<Entry<'a>>>,
    census: &mut Census,
) -> Result<()> {
    for slot in 0..ENTRIES_PER_BLOCK {
        let raw = slice(stored.bytes, slot * ENTRY_SIZE, ENTRY_SIZE)?;
        let offset = stored.offset + slot * ENTRY_SIZE;
        if raw[0] == 0 {
            break;
        }
        let flags = raw[FLAGS_FIELD];
        let name_len = usize::from(flags & NAME_LENGTH_MASK);
        if name_len == 0 {
            census.unnamed += 1;
            entries.push(None);
            continue;
        }
        if name_len > NAME_SIZE {
            census.problem(format!(
                "Skipped the file table entry at 0x{offset:X}: name length {name_len} exceeds \
                 {NAME_SIZE} B"
            ));
            entries.push(None);
            continue;
        }
        entries.push(Some(Entry {
            name: &raw[..name_len],
            is_directory: flags & DIRECTORY != 0,
            is_consecutive: flags & CONSECUTIVE != 0,
            start_block: le_u24(raw, START_BLOCK_FIELD)?,
            parent: be_u16(raw, DIRECTORY_INDEX_FIELD)?,
            size: be_u32(raw, SIZE_FIELD)?,
            offset,
        }));
    }
    Ok(())
}

/// The path of `entry` from the root, through the directory entries its
/// directory indices name.
fn path(entries: &[Option<Entry<'_>>], entry: &Entry<'_>) -> Walk<String> {
    let mut parts = vec![entry_name(entry.name)];
    let mut parent = entry.parent;
    while parent != ROOT_INDEX {
        if parts.len() > MAX_DEPTH {
            return Err(format!(
                "it is nested deeper than {MAX_DEPTH} directories, or its directories form a loop"
            ));
        }
        let directory = entries
            .get(usize::from(parent))
            .and_then(Option::as_ref)
            .filter(|candidate| candidate.is_directory)
            .ok_or_else(|| format!("its directory index {parent} names no directory entry"))?;
        parts.push(entry_name(directory.name));
        parent = directory.parent;
    }
    parts.reverse();
    Ok(format!("/{}", parts.join("/")))
}

/// An entry name up to its first NUL: ASCII kept (Free60), every other
/// byte shown as U+FFFD.
fn entry_name(raw: &[u8]) -> String {
    raw.iter()
        .take_while(|&&b| b != 0)
        .map(|&b| {
            if b.is_ascii() {
                char::from(b)
            } else {
                char::REPLACEMENT_CHARACTER
            }
        })
        .collect()
}

/// Data blocks that hold `size` bytes: the full blocks, and one more for a
/// remainder.
fn blocks_for(size: u32) -> u32 {
    let full = size >> BLOCK_SHIFT;
    let has_remainder = size & ((1 << BLOCK_SHIFT) - 1) != 0;
    full + u32::from(has_remainder)
}

/// Examine one file and list it when its first block is a recognized
/// format and the limits allow reading it in full.
fn offer<'a>(
    volume: &mut Volume<'a>,
    data: &'a [u8],
    entries: &[Option<Entry<'a>>],
    entry: &Entry<'a>,
    census: &mut Census,
    c: &mut Container<'a>,
) {
    census.files += 1;
    if entry.size == 0 {
        return;
    }
    let path = match path(entries, entry) {
        Ok(path) => path,
        Err(defect) => {
            census.problem(format!(
                "Skipped the file entry at 0x{:X}: {defect}",
                entry.offset
            ));
            return;
        }
    };
    if c.children.len() >= MAX_COMPONENTS {
        census.over_component_limit += 1;
        return;
    }
    if !census.charge(RECOGNITION_PREFIX) {
        census.over_extraction_limit += 1;
        return;
    }
    let first = match volume.unchecked_block(entry.start_block) {
        Ok(first) => first,
        Err(defect) => {
            census.problem(format!("Skipped {path}: {defect}"));
            return;
        }
    };
    let size = entry.size as usize;
    if !container::is_recognized(&first.bytes[..size.min(BLOCK_SIZE)]) {
        return;
    }
    if size > MAX_PAYLOAD {
        census.too_large += 1;
        return;
    }
    if !census.charge(size) {
        census.over_extraction_limit += 1;
        return;
    }
    match read_file(volume, data, entry, path.clone()) {
        Ok(child) if container::is_recognized(&child.data) => {
            c.children.push(child.if_recognized());
        }
        Ok(_) => {}
        Err(defect) => census.problem(format!("Skipped {path}: {defect}")),
    }
}

/// The data block numbers of a file: consecutive from its first block, or
/// its chain of next-block numbers, which may not revisit a block.
fn file_blocks(volume: &mut Volume<'_>, entry: &Entry<'_>) -> Walk<Vec<u32>> {
    let needed = blocks_for(entry.size);
    if entry.is_consecutive {
        let last = entry
            .start_block
            .checked_add(needed - 1)
            .filter(|&last| last < volume.allocated_blocks())
            .ok_or_else(|| {
                format!(
                    "its {needed} consecutive blocks from block {} pass the {} allocated blocks",
                    entry.start_block,
                    volume.allocated_blocks()
                )
            })?;
        return Ok((entry.start_block..=last).collect());
    }
    let mut blocks = vec![entry.start_block];
    let mut visited = BTreeSet::from([entry.start_block]);
    let mut current = entry.start_block;
    while blocks.len() < needed as usize {
        let next = volume.record(current)?.next_block;
        if next == END_OF_CHAIN {
            return Err(format!(
                "the block chain ends after {} blocks; {} B need {needed}",
                blocks.len(),
                entry.size
            ));
        }
        if !visited.insert(next) {
            return Err(format!("the block chain reaches block {next} twice"));
        }
        blocks.push(next);
        current = next;
    }
    Ok(blocks)
}

/// The bytes of a file, borrowed when they are stored contiguously and
/// reassembled otherwise. Every block is checked against its hash record.
fn read_file<'a>(
    volume: &mut Volume<'a>,
    data: &'a [u8],
    entry: &Entry<'a>,
    path: String,
) -> Walk<Child<'a>> {
    let size = entry.size as usize;
    let mut extents: Vec<Extent> = Vec::new();
    let mut remaining = size;
    for block in file_blocks(volume, entry)? {
        let stored = volume.block(block)?;
        let len = remaining.min(BLOCK_SIZE);
        remaining -= len;
        match extents.last_mut() {
            Some(last) if last.offset + last.len == stored.offset => last.len += len,
            _ => extents.push(Extent {
                offset: stored.offset,
                len,
            }),
        }
    }
    let Some(&first) = extents.first() else {
        return Err("the file has no data blocks".into());
    };
    if extents.len() == 1 {
        return Ok(Child::stored(
            path,
            first.offset,
            &data[first.offset..first.offset + first.len],
        ));
    }
    let mut bytes = Vec::with_capacity(size);
    for extent in &extents {
        bytes.extend_from_slice(&data[extent.offset..extent.offset + extent.len]);
    }
    Ok(Child::decoded(
        path,
        first.offset,
        first.len,
        Cow::Owned(bytes),
        BLOCKS_TRANSFORM,
    ))
}

/// Notes and metadata for what the listing found and left out.
fn finish(census: &Census, descriptor: &VolumeDescriptor, c: &mut Container<'_>) {
    let prefix = c.key_prefix;
    let listed = c.children.len();
    c.notes.push(format!(
        "File table: {} from block {}; {}, {}; {listed} in a recognized format listed",
        counted(usize::from(descriptor.file_table_blocks), "block", "blocks"),
        descriptor.file_table_block,
        counted(census.files, "file", "files"),
        counted(census.directories, "directory", "directories")
    ));
    if census.unread_blocks > 0 {
        c.notes.push(format!(
            "File table limit reached ({MAX_FILE_TABLE_BLOCKS} blocks); not read: {}",
            counted(census.unread_blocks, "further block", "further blocks")
        ));
    }
    if census.unnamed > 0 {
        c.notes.push(format!(
            "Skipped: {} with name length 0",
            counted(census.unnamed, "file table entry", "file table entries")
        ));
    }
    if census.over_component_limit > 0 {
        c.notes.push(format!(
            "Member limit reached ({MAX_COMPONENTS} members); not examined: {}",
            counted(census.over_component_limit, "further file", "further files")
        ));
    }
    if census.over_extraction_limit > 0 {
        c.notes.push(format!(
            "Extraction limit reached ({}); not examined or not listed: {}",
            size_text(MAX_EXTRACTED),
            counted(census.over_extraction_limit, "file", "files")
        ));
    }
    if census.too_large > 0 {
        c.notes.push(format!(
            "Not examined: {} over the {} member limit",
            counted(census.too_large, "file", "files"),
            size_text(MAX_PAYLOAD)
        ));
    }
    c.notes.extend(census.problems.iter().cloned());
    if census.unlisted_problems > 0 {
        c.notes.push(format!(
            "Skipped: {} not named here",
            counted(census.unlisted_problems, "further entry", "further entries")
        ));
    }
    c.push_metadata(format!("{prefix}_files"), "Files", census.files as u64);
    c.push_metadata(
        format!("{prefix}_directories"),
        "Directories",
        census.directories as u64,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entry named `name`.
    fn entry(name: &'static [u8], is_directory: bool, parent: u16) -> Entry<'static> {
        Entry {
            name,
            is_directory,
            is_consecutive: false,
            start_block: 0,
            parent,
            size: 0,
            offset: 0,
        }
    }

    #[test]
    fn paths_follow_directory_indices_to_the_root() {
        let entries = vec![
            Some(entry(b"media", true, ROOT_INDEX)),
            Some(entry(b"maps", true, 0)),
            Some(entry(b"default.xex", false, ROOT_INDEX)),
            Some(entry(b"level1.xex", false, 1)),
            Some(entry(b"orphan.bin", false, 2)),
            Some(entry(b"lost.bin", false, 9)),
        ];
        let path_of = |i: usize| path(&entries, entries[i].as_ref().unwrap());
        assert_eq!(path_of(2).unwrap(), "/default.xex");
        assert_eq!(path_of(3).unwrap(), "/media/maps/level1.xex");
        assert!(path_of(4)
            .unwrap_err()
            .contains("index 2 names no directory"));
        assert!(path_of(5)
            .unwrap_err()
            .contains("index 9 names no directory"));
    }

    #[test]
    fn directory_loops_end_at_the_depth_limit() {
        let entries = vec![
            Some(entry(b"a", true, 1)),
            Some(entry(b"b", true, 0)),
            Some(entry(b"f", false, 0)),
        ];
        let defect = path(&entries, entries[2].as_ref().unwrap()).unwrap_err();
        assert!(defect.contains("form a loop"), "{defect}");
    }

    #[test]
    fn names_stop_at_nul_and_replace_non_ascii_bytes() {
        assert_eq!(entry_name(b"default.xex"), "default.xex");
        assert_eq!(entry_name(b"a\0b"), "a");
        assert_eq!(entry_name(&[b'x', 0xE9]), "x\u{FFFD}");
    }

    #[test]
    fn block_counts_round_up() {
        assert_eq!(blocks_for(1), 1);
        assert_eq!(blocks_for(4096), 1);
        assert_eq!(blocks_for(4097), 2);
        assert_eq!(blocks_for(u32::MAX), 0x10_0000);
    }

    #[test]
    fn census_names_eight_problems_and_counts_the_rest() {
        let mut census = Census::default();
        for i in 0..10 {
            census.problem(format!("problem {i}"));
        }
        assert_eq!(census.problems.len(), MAX_PROBLEM_NOTES);
        assert_eq!(census.unlisted_problems, 2);
        assert!(census.charge(MAX_EXTRACTED));
        assert!(!census.charge(1));
    }
}
