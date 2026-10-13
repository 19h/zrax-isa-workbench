//! The directory walk of an `AmigaDOS` volume: the hash tables of the root
//! and user directory blocks and their hash chains ([FAQ] 4.2.1, 4.2.2,
//! 4.5), entry blocks, and regular files reassembled from the data block
//! pointers of their file header and extension blocks ([FAQ] 4.4), listed
//! when they start with a recognized format. Every entry block is read at
//! most once per walk, which ends hash chain loops (disks that lock
//! `AmigaOS` this way exist: [ADFLIB] `adfGetRDirEntLimited`), directory
//! loops and cross-links.

use super::volume::{signed, Mounted, MAX_NAME_LEN};
use super::*;
use crate::formats::container::{self, Child, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;

/// Deepest directory level below the root that the walk enters.
const MAX_DEPTH: usize = 64;

/// Bytes at the start of a regular file read to decide whether it is a
/// recognized format.
const RECOGNITION_PREFIX: usize = 4096;

/// Most regular files examined in one image.
const MAX_FILES_EXAMINED: usize = 1 << 16;

/// Problems reported one by one; further ones are counted.
const MAX_PROBLEM_NOTES: usize = 16;

/// File header field: `byte_size` ([FAQ] 4.4).
const BYTE_SIZE: usize = 0x144;

/// OFS data block fields: `seq_num` (the first block is 1) and
/// `data_size`; the data follows the 24-byte header ([FAQ] 4.4).
const SEQ_NUM: usize = 0x008;
const DATA_SIZE: usize = 0x00c;
const OFS_HEADER_SIZE: usize = 24;

/// Long-name file systems (`DOS\6`, `DOS\7`) keep an entry's name and
/// comment as consecutive BCPL strings in the 112 bytes at 0x148; names
/// hold at most 110 characters ([AMITOOLS] `EntryBlock._read_nac_modts`,
/// `FileName.is_valid`).
const LONG_NAME: usize = 0x148;
const MAX_LONG_NAME_LEN: usize = 110;

/// The hash of a name ([FAQ] 4.2.1; [ADFLIB] `adfGetHashValue`): `hash =
/// (hash * 13 + upper(c)) & 0x7FF` over the characters, starting from the
/// length, then modulo the table size.
const HASH_MULTIPLIER: u32 = 13;
const HASH_MASK: u32 = 0x7ff;

/// International upper case ([FAQ] 5.4): 224-254 map to 192-222, except
/// 247 (the division sign).
const INTL_LOWER: std::ops::RangeInclusive<u8> = 224..=254;
const DIVISION_SIGN: u8 = 247;
const CASE_OFFSET: u8 = b'a' - b'A';

/// Transforms of files reassembled from their data blocks.
const OFS_TRANSFORM: &str = "AmigaDOS OFS data blocks";
const FFS_TRANSFORM: &str = "AmigaDOS FFS data blocks";

/// What the walks of an image found and left out.
#[derive(Debug, Default)]
pub(super) struct Census {
    directories: usize,
    files: usize,
    members: usize,
    /// Hard and soft links, which are not followed.
    links: usize,
    /// Entries whose name hashes to another slot than the chain they are
    /// in: `AmigaDOS` would not find them by name.
    misplaced: usize,
    too_deep: usize,
    unexamined: usize,
    too_large: usize,
    over_budget: usize,
    /// Bytes extracted, charged before a file is read.
    extracted: usize,
    problems: Vec<String>,
    unlisted_problems: usize,
}

/// A walked directory's name and parent, from which paths are built.
/// Node 0 is the root.
struct PathNode {
    parent: usize,
    name: String,
}

/// A directory waiting to be read.
struct Pending<'a> {
    block: Block<'a>,
    node: usize,
    depth: usize,
}

/// What an entry block describes ([ADFLIB] `adf_blk.h` secondary types).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    Directory,
    File,
    /// A hard link to a file or directory, or a soft link.
    Link,
}

/// A validated entry block.
struct Entry<'a> {
    block: Block<'a>,
    name: Vec<u8>,
    kind: EntryKind,
}

/// A regular file's data block pointers, as its file header gives them.
struct FileBlocks<'a> {
    header: Block<'a>,
    /// `byte_size`.
    size: usize,
    /// Data blocks that `size` needs.
    count: usize,
}

/// Bytes read from a file.
struct FileData<'a> {
    bytes: Cow<'a, [u8]>,
    /// File offset and size of the first stored run of file data.
    offset: usize,
    stored_size: usize,
}

struct Walker<'m, 'a> {
    mounted: &'m Mounted<'a>,
    /// Starts every member path: `""`, or `"DH0:"` on a partitioned disk.
    drive: &'m str,
    census: &'m mut Census,
    nodes: Vec<PathNode>,
    /// The blocks read as entries.
    claimed: BlockSet,
}

/// Walk the tree from the root block of `mounted` and append its members
/// to `c`. Problems are counted in `census`.
pub(super) fn walk_volume<'a>(
    mounted: &Mounted<'a>,
    drive: &str,
    census: &mut Census,
    c: &mut Container<'a>,
) {
    let blocks = mounted.volume.blocks_present();
    let mut walker = Walker {
        mounted,
        drive,
        census,
        nodes: vec![PathNode {
            parent: 0,
            name: String::new(),
        }],
        claimed: BlockSet::new(blocks),
    };
    // An entry that names the root block is a loop.
    walker.claimed.insert(mounted.root.number);
    let mut pending = vec![Pending {
        block: mounted.root,
        node: 0,
        depth: 0,
    }];
    while let Some(directory) = pending.pop() {
        walker.census.directories += 1;
        let subdirectories = walker.directory(&directory, c);
        // Reversed, so that subdirectories are walked in table order.
        pending.extend(subdirectories.into_iter().rev());
    }
}

impl<'a> Walker<'_, 'a> {
    /// The path of `name` in the directory at `node`.
    fn path(&self, node: usize, name: &str) -> String {
        let mut parts = Vec::new();
        if !name.is_empty() {
            parts.push(name.to_string());
        }
        let mut current = node;
        // Parents precede their children in `nodes`, so this ends at the
        // root.
        while current != 0 {
            parts.push(self.nodes[current].name.clone());
            current = self.nodes[current].parent;
        }
        parts.reverse();
        format!("{}/{}", self.drive, parts.join("/"))
    }

    /// Record a problem below the root.
    fn problem(&mut self, text: String) {
        if self.census.problems.len() < MAX_PROBLEM_NOTES {
            self.census.problems.push(text);
        } else {
            self.census.unlisted_problems += 1;
        }
    }

    /// Walk the hash table of one directory: list its members and return
    /// its subdirectories in table order.
    fn directory(&mut self, directory: &Pending<'a>, c: &mut Container<'a>) -> Vec<Pending<'a>> {
        let mut subdirectories = Vec::new();
        for slot in 0..TABLE_ENTRIES {
            let mut next = directory.block.long(TABLE + 4 * slot);
            while next != 0 {
                let entry = match self.entry(next) {
                    Ok(entry) => entry,
                    Err(defect) => {
                        let path = self.path(directory.node, "");
                        self.problem(format!("Skipped an entry of {path}: {defect}"));
                        break;
                    }
                };
                next = entry.block.long(HASH_CHAIN);
                if name_hash(&entry.name, self.mounted.volume.dos.is_international()) != slot {
                    self.census.misplaced += 1;
                }
                let name = latin1(&entry.name);
                match entry.kind {
                    EntryKind::Link => self.census.links += 1,
                    EntryKind::File => {
                        let path = self.path(directory.node, &name);
                        self.file(path, entry.block, c);
                    }
                    EntryKind::Directory if directory.depth >= MAX_DEPTH => {
                        self.census.too_deep += 1;
                    }
                    EntryKind::Directory => {
                        self.nodes.push(PathNode {
                            parent: directory.node,
                            name,
                        });
                        subdirectories.push(Pending {
                            block: entry.block,
                            node: self.nodes.len() - 1,
                            depth: directory.depth + 1,
                        });
                    }
                }
            }
        }
        subdirectories
    }

    /// Read and validate the entry block `number`: type `T_HEADER`, its own
    /// number in `header_key` ([AMITOOLS] `own_key == blk_num`), a valid
    /// checksum, a name without `/` or `:` ([FAQ] 4.2) and a directory,
    /// file or link secondary type.
    fn entry(&mut self, number: u32) -> Walk<Entry<'a>> {
        let block = self.mounted.volume.block(number)?;
        if !self.claimed.insert(number) {
            return Err(format!(
                "block {number} is reached a second time (a loop or a cross-link)"
            ));
        }
        let kind = block.long(TYPE);
        if kind != T_HEADER {
            return Err(format!(
                "block {number} is not an entry block (type {})",
                signed(kind)
            ));
        }
        if !block.is_checksum_valid() {
            return Err(format!(
                "block {number} fails its checksum (0x{:08X} stored, 0x{:08X} expected)",
                block.long(CHECKSUM),
                block.expected_checksum(CHECKSUM)
            ));
        }
        let key = block.long(HEADER_KEY);
        if key != number {
            return Err(format!("block {number} gives its own number as {key}"));
        }
        let name = if self.mounted.volume.dos.has_long_names() {
            block.bstr(LONG_NAME, MAX_LONG_NAME_LEN)
        } else {
            block.bstr(NAME, MAX_NAME_LEN)
        };
        let Some(name) = name.filter(|name| !name.is_empty()) else {
            return Err(format!("block {number} holds an invalid name length"));
        };
        if name.iter().any(|&b| b == b'/' || b == b':') {
            return Err(format!(
                "block {number} holds the name \"{}\", which contains / or :",
                latin1(name)
            ));
        }
        let kind = match block.long(SECONDARY_TYPE) {
            ST_USERDIR => EntryKind::Directory,
            ST_FILE => EntryKind::File,
            ST_LINKFILE | ST_LINKDIR | ST_SOFTLINK => EntryKind::Link,
            other => {
                return Err(format!(
                    "block {number} has the secondary type {}, not a directory, file or link",
                    signed(other)
                ))
            }
        };
        Ok(Entry {
            block,
            name: name.to_vec(),
            kind,
        })
    }

    /// List a regular file when its first bytes are a recognized format
    /// and the limits allow its extraction.
    fn file(&mut self, path: String, header: Block<'a>, c: &mut Container<'a>) {
        self.census.files += 1;
        if c.children.len() >= MAX_COMPONENTS || self.census.files > MAX_FILES_EXAMINED {
            self.census.unexamined += 1;
            return;
        }
        let file = match self.file_blocks(header) {
            Ok(file) => file,
            Err(defect) => {
                self.problem(format!("Skipped {path}: {defect}"));
                return;
            }
        };
        // An empty file is not a recognized format.
        if file.size == 0 {
            return;
        }
        let prefix_size = file.size.min(RECOGNITION_PREFIX);
        let data_size = self.mounted.volume.dos.data_size();
        let prefix = self
            .pointers(&file, div_round_up(prefix_size, data_size))
            .and_then(|pointers| self.read(&file, &pointers, prefix_size));
        let prefix = match prefix {
            Ok(prefix) => prefix,
            Err(defect) => {
                self.problem(format!("Skipped {path}: {defect}"));
                return;
            }
        };
        if !container::is_recognized(&prefix.bytes) {
            return;
        }
        if file.size > MAX_PAYLOAD {
            self.census.too_large += 1;
            return;
        }
        if self.census.extracted + file.size > MAX_EXTRACTED {
            self.census.over_budget += 1;
            return;
        }
        // Charged before reading, so that reads which fail late count too.
        self.census.extracted += file.size;
        let contents = if prefix_size == file.size {
            Ok(prefix)
        } else {
            self.pointers(&file, file.count)
                .and_then(|pointers| self.read(&file, &pointers, file.size))
        };
        let contents = match contents {
            Ok(contents) if contents.bytes.len() == file.size => contents,
            Ok(contents) => {
                self.problem(format!(
                    "Skipped {path}: its data blocks hold {} B, its file header gives {} B",
                    contents.bytes.len(),
                    file.size
                ));
                return;
            }
            Err(defect) => {
                self.problem(format!("Skipped {path}: {defect}"));
                return;
            }
        };
        let transform = if self.mounted.volume.dos.is_ffs() {
            FFS_TRANSFORM
        } else {
            OFS_TRANSFORM
        };
        let child = match contents.bytes {
            Cow::Borrowed(bytes) => Child::stored(path, contents.offset, bytes),
            Cow::Owned(bytes) => Child::decoded(
                path,
                contents.offset,
                contents.stored_size,
                Cow::Owned(bytes),
                transform,
            ),
        };
        c.children.push(child.if_recognized());
        self.census.members += 1;
    }

    /// The size and data block count of the file whose header is
    /// `header`. The header holds the first `min(count, 72)` pointers and
    /// `high_seq` must say so ([ADFLIB] `adfGetFileBlocks`); a file cannot
    /// have more data blocks than the input holds.
    fn file_blocks(&self, header: Block<'a>) -> Walk<FileBlocks<'a>> {
        let volume = &self.mounted.volume;
        let size = usize::try_from(header.long(BYTE_SIZE)).unwrap_or(usize::MAX);
        let count = div_round_up(size, volume.dos.data_size());
        if count > volume.blocks_present() {
            return Err(format!(
                "its size of {size} B needs {count} data blocks; the input holds {} blocks of \
                 the volume",
                volume.blocks_present()
            ));
        }
        let in_header = count.min(TABLE_ENTRIES);
        let high_seq = header.long(HIGH_SEQ);
        if usize::try_from(high_seq).ok() != Some(in_header) {
            return Err(format!(
                "its file header lists {high_seq} data blocks; {size} B need {in_header} there"
            ));
        }
        Ok(FileBlocks {
            header,
            size,
            count,
        })
    }

    /// The first `limit` data block pointers of `file` (at most its block
    /// count), in file order: from the end of the header's table backwards
    /// ([FAQ] 4.4: "the first is at datablock[71-0]"), then from each
    /// extension block in turn. Every extension block but the last is full
    /// ([ADFLIB] `adfFileRealSize` gives their number), names itself, the
    /// file header as its parent, and passes its checksum.
    fn pointers(&self, file: &FileBlocks<'a>, limit: usize) -> Walk<Vec<u32>> {
        let limit = limit.min(file.count);
        let mut pointers: Vec<u32> = table_pointers(&file.header, limit.min(TABLE_ENTRIES));
        let mut listed = file.count.min(TABLE_ENTRIES);
        let mut next = file.header.long(EXTENSION);
        let mut extensions = 0usize;
        while pointers.len() < limit {
            if next == 0 {
                return Err(format!(
                    "its extension block chain ends after {extensions} blocks; {} data blocks \
                     need {}",
                    file.count,
                    div_round_up(file.count - TABLE_ENTRIES, TABLE_ENTRIES)
                ));
            }
            let extension = self.extension(file, next)?;
            let expected = (file.count - listed).min(TABLE_ENTRIES);
            let high_seq = extension.long(HIGH_SEQ);
            if usize::try_from(high_seq).ok() != Some(expected) {
                return Err(format!(
                    "extension block {next} lists {high_seq} data blocks, not {expected}"
                ));
            }
            let wanted = (limit - pointers.len()).min(expected);
            pointers.extend(table_pointers(&extension, wanted));
            listed += expected;
            extensions += 1;
            next = extension.long(EXTENSION);
        }
        Ok(pointers)
    }

    /// The extension block `number` of `file` ([FAQ] 4.4; [ADFLIB]
    /// `adfReadFileExtBlock`): `T_LIST`, `ST_FILE`, its own number, the
    /// file header as parent, and a valid checksum.
    fn extension(&self, file: &FileBlocks<'a>, number: u32) -> Walk<Block<'a>> {
        let block = self.mounted.volume.block(number)?;
        if block.long(TYPE) != T_LIST || block.long(SECONDARY_TYPE) != ST_FILE {
            return Err(format!(
                "block {number} is not a file extension block (types {} and {})",
                signed(block.long(TYPE)),
                signed(block.long(SECONDARY_TYPE))
            ));
        }
        if !block.is_checksum_valid() {
            return Err(format!("extension block {number} fails its checksum"));
        }
        if block.long(HEADER_KEY) != number || block.long(PARENT) != file.header.number {
            return Err(format!(
                "extension block {number} names block {} and parent {}, not itself and the file \
                 header {}",
                block.long(HEADER_KEY),
                block.long(PARENT),
                file.header.number
            ));
        }
        Ok(block)
    }

    /// The first `len` bytes of `file` (at most its size) through
    /// `pointers`.
    fn read(&self, file: &FileBlocks<'a>, pointers: &[u32], len: usize) -> Walk<FileData<'a>> {
        if self.mounted.volume.dos.is_ffs() {
            self.read_ffs(pointers, len)
        } else {
            self.read_ofs(file, pointers, len)
        }
    }

    /// FFS data blocks hold raw file data, the last one cut to the size
    /// ([FAQ] 4.4; [AMITOOLS] `ADFSFile.read`). A file in consecutive
    /// blocks is borrowed where it is stored.
    fn read_ffs(&self, pointers: &[u32], len: usize) -> Walk<FileData<'a>> {
        let volume = &self.mounted.volume;
        let Some((&first, rest)) = pointers.split_first() else {
            return Err("it lists no data blocks".to_string());
        };
        let first_block = volume.block(first)?;
        // The longest run of consecutive blocks at the start.
        let run = 1 + pointers
            .windows(2)
            .take_while(|pair| pair[0].checked_add(1) == Some(pair[1]))
            .count();
        if run == pointers.len() {
            // The last block of the run lies in the input, so the blocks
            // before it do.
            let last = volume.block(*rest.last().unwrap_or(&first))?;
            let end = (first_block.offset + len).min(last.offset + BLOCK_SIZE);
            return Ok(FileData {
                bytes: Cow::Borrowed(&volume.data[first_block.offset..end]),
                offset: first_block.offset,
                stored_size: end - first_block.offset,
            });
        }
        let mut bytes = Vec::with_capacity(len);
        for &pointer in pointers {
            let block = volume.block(pointer)?;
            let take = (len - bytes.len()).min(BLOCK_SIZE);
            bytes.extend_from_slice(&block.bytes[..take]);
        }
        Ok(FileData {
            bytes: Cow::Owned(bytes),
            offset: first_block.offset,
            stored_size: (run * BLOCK_SIZE).min(len),
        })
    }

    /// OFS data blocks carry a 24-byte header ([FAQ] 4.4; [ADFLIB]
    /// `adfReadDataBlock`; [AMITOOLS] `ADFSFile.read`): `T_DATA`, the file
    /// header block in `header_key`, sequence numbers from 1, at most 488
    /// bytes of data each, and a valid checksum.
    fn read_ofs(&self, file: &FileBlocks<'a>, pointers: &[u32], len: usize) -> Walk<FileData<'a>> {
        let volume = &self.mounted.volume;
        let mut bytes = Vec::with_capacity(len);
        let mut first: Option<(usize, usize)> = None;
        for (sequence, &pointer) in (1u32..).zip(pointers) {
            let block = volume.block(pointer)?;
            if block.long(TYPE) != T_DATA {
                return Err(format!(
                    "block {pointer} is not an OFS data block (type {})",
                    signed(block.long(TYPE))
                ));
            }
            if !block.is_checksum_valid() {
                return Err(format!("data block {pointer} fails its checksum"));
            }
            if block.long(HEADER_KEY) != file.header.number || block.long(SEQ_NUM) != sequence {
                return Err(format!(
                    "data block {pointer} names file header {} and sequence number {}, not {} \
                     and {sequence}",
                    block.long(HEADER_KEY),
                    block.long(SEQ_NUM),
                    file.header.number
                ));
            }
            let data_size = usize::try_from(block.long(DATA_SIZE)).unwrap_or(usize::MAX);
            if data_size > BLOCK_SIZE - OFS_HEADER_SIZE {
                return Err(format!(
                    "data block {pointer} gives a data size of {data_size} B, more than 488 B"
                ));
            }
            let take = data_size.min(len - bytes.len());
            first.get_or_insert((block.offset + OFS_HEADER_SIZE, take));
            bytes.extend_from_slice(&block.bytes[OFS_HEADER_SIZE..OFS_HEADER_SIZE + take]);
            if bytes.len() == len {
                break;
            }
        }
        let (offset, stored_size) = first.ok_or_else(|| "it lists no data blocks".to_string())?;
        Ok(FileData {
            bytes: Cow::Owned(bytes),
            offset,
            stored_size,
        })
    }
}

/// The first `count` data block pointers of a file header or extension
/// block, which stores them from the end of its table backwards.
fn table_pointers(block: &Block<'_>, count: usize) -> Vec<u32> {
    (0..count.min(TABLE_ENTRIES))
        .map(|i| block.long(TABLE + 4 * (TABLE_ENTRIES - 1 - i)))
        .collect()
}

/// The hash table slot of `name` ([FAQ] 4.2.1 and 5.4; [ADFLIB]
/// `adfGetHashValue`).
fn name_hash(name: &[u8], international: bool) -> usize {
    let start = u32::try_from(name.len()).unwrap_or(u32::MAX) & HASH_MASK;
    let hash = name.iter().fold(start, |hash, &c| {
        (hash * HASH_MULTIPLIER + u32::from(upper(c, international))) & HASH_MASK
    });
    usize::try_from(hash).expect("masked to 11 bits") % TABLE_ENTRIES
}

/// The upper case `AmigaDOS` hashes names with: ASCII, and with the
/// international mode also the Latin-1 letters ([FAQ] 5.4).
fn upper(c: u8, international: bool) -> u8 {
    let is_lower =
        c.is_ascii_lowercase() || (international && INTL_LOWER.contains(&c) && c != DIVISION_SIGN);
    if is_lower {
        c - CASE_OFFSET
    } else {
        c
    }
}

impl Census {
    /// Notes and metadata: what was walked, then what was left out and why.
    pub(super) fn report(self, c: &mut Container<'_>) {
        c.notes.push(format!(
            "Directory walk: {}, {}; members in a recognized format: {}",
            counted(self.directories, "directory", "directories"),
            counted(self.files, "regular file", "regular files"),
            self.members
        ));
        if self.links > 0 {
            c.notes.push(format!(
                "{} not followed",
                counted(
                    self.links,
                    "hard or soft link was",
                    "hard or soft links were"
                )
            ));
        }
        if self.misplaced > 0 {
            c.notes.push(format!(
                "{} in the hash chain of another name; AmigaDOS does not find them by name",
                counted(self.misplaced, "entry is", "entries are")
            ));
        }
        self.limit_notes(c);
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
        let prefix = c.key_prefix;
        for (key, label, count) in [
            ("directory_count", "Directories walked", self.directories),
            ("regular_file_count", "Regular files", self.files),
            ("member_count", "Members", self.members),
            ("link_count", "Links", self.links),
        ] {
            c.push_metadata(format!("{prefix}_{key}"), label, count as u64);
        }
    }

    /// Notes for what the walk's limits left out.
    fn limit_notes(&self, c: &mut Container<'_>) {
        if self.too_deep > 0 {
            c.notes.push(format!(
                "{} not walked",
                counted(
                    self.too_deep,
                    &format!("directory deeper than {MAX_DEPTH} levels was"),
                    &format!("directories deeper than {MAX_DEPTH} levels were")
                )
            ));
        }
        if self.unexamined > 0 {
            c.notes.push(format!(
                "{} not examined: at most {MAX_COMPONENTS} members are listed and \
                 {MAX_FILES_EXAMINED} files examined",
                counted(self.unexamined, "regular file was", "regular files were")
            ));
        }
        if self.too_large > 0 {
            c.notes.push(format!(
                "{} the {} extraction limit; not extracted",
                counted(
                    self.too_large,
                    "recognized file exceeds",
                    "recognized files exceed"
                ),
                size_text(MAX_PAYLOAD as u64)
            ));
        }
        if self.over_budget > 0 {
            c.notes.push(format!(
                "{} not extracted: the {} total extraction limit was reached",
                counted(
                    self.over_budget,
                    "recognized file was",
                    "recognized files were"
                ),
                size_text(MAX_EXTRACTED as u64)
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_hash_case_insensitively() {
        // [FAQ] 4.2.1: "'file_1a', 'file_24' and 'file_5u' have the same
        // hash value".
        let slot = name_hash(b"file_1a", false);
        assert_eq!(name_hash(b"file_24", false), slot);
        assert_eq!(name_hash(b"file_5u", false), slot);
        assert_eq!(name_hash(b"FILE_1A", false), slot);
        // 3 * 13 + 'S' = 122, 122 * 13 + 'E' = 1655, 1655 * 13 + 'Q'
        // = 21596 & 0x7FF = 1116, mod 72 = 36 ("seq").
        assert_eq!(name_hash(b"seq", false), 36);
    }

    #[test]
    fn international_mode_upper_cases_latin1_letters() {
        assert_eq!(upper(0xe9, true), 0xc9);
        assert_eq!(upper(0xe9, false), 0xe9);
        assert_eq!(upper(DIVISION_SIGN, true), DIVISION_SIGN);
        assert_eq!(upper(0xff, true), 0xff);
        assert_eq!(upper(b'z', false), b'Z');
        assert_ne!(
            name_hash(b"\xe9t\xe9", true),
            name_hash(b"\xe9t\xe9", false)
        );
    }

    #[test]
    fn table_pointers_run_backwards_from_the_end_of_the_table() {
        let mut bytes = [0u8; BLOCK_SIZE];
        bytes[0x134..0x138].copy_from_slice(&100u32.to_be_bytes());
        bytes[0x130..0x134].copy_from_slice(&101u32.to_be_bytes());
        bytes[0x018..0x01c].copy_from_slice(&171u32.to_be_bytes());
        let block = Block::at(&bytes, 0, 0).unwrap();
        assert_eq!(table_pointers(&block, 2), [100, 101]);
        assert_eq!(table_pointers(&block, 72)[71], 171);
        assert_eq!(table_pointers(&block, 99).len(), 72);
    }
}
