//! `ProDOS` volumes ([TRM] Appendix B; [CP2] `ProDOS-notes.md`, `ProDOS.cs`,
//! `ProDOS_FileEntry.cs`, `ProDOS_FileDesc.cs`). Pointers, counts and
//! sizes are little-endian ([TRM] B.2.1); blocks are 512 bytes.
//!
//! - Directory block ([TRM] B.2.1): previous and next block (0x00, 0x02;
//!   0 ends), entries from 0x04. The key block's first entry is the header.
//! - Volume directory header, key block 2 ([TRM] B.2.2), relative to the
//!   entry: storage type 0xF and name length (0x00), name (0x01, 15),
//!   entry length (0x1F; 0x27), entries per block (0x20; 0x0D), file count
//!   (0x21, 2), bitmap pointer (0x23, 2), total blocks (0x25, 2).
//! - Subdirectory header ([TRM] B.2.3): storage type 0xE, a reserved byte
//!   0x75 at 0x10 (0x76 under GS/OS, [CP2]), the same entry length, entries
//!   per block and file count, then the parent pointer (0x23, 2), parent
//!   entry number (0x25) and parent entry length (0x26).
//! - File entry ([TRM] B.2.4): storage type and name length (0x00), name
//!   (0x01, 15), file type (0x10), key pointer (0x11, 2), blocks used (0x13,
//!   2), EOF (0x15, 3), aux type (0x1F, 2; the load address of a binary
//!   file), header pointer (0x25, 2).
//! - Storage ([TRM] B.3): a seedling's key block is its data; a sapling's
//!   is an index block of up to 256 pointers, a tree's a master index of up
//!   to 128 index-block pointers. Pointer `i` has its low byte at `i` and
//!   its high byte at `256 + i` ([CP2] `DiskBlock.GetBlockPtr`); pointer 0
//!   is a sparse block of zeros ([TRM] B.3.6). An extended file (storage
//!   type 5, GS/OS) points to a block with a data-fork entry at 0x000 and a
//!   resource-fork entry at 0x100: storage type, key block (2), blocks used
//!   (2), EOF (3) ([CP2] `ProDOS-notes.md`).

use super::*;

/// The key block of the volume directory ([TRM] B.2.2).
const VOLUME_DIRECTORY_BLOCK: usize = 2;

/// The smallest volume: two loader blocks, a directory block, a bitmap
/// block and a file ([CP2] `ProDOS.MIN_VOL_SIZE`).
const MIN_VOLUME_BLOCKS: usize = 5;

/// `total_blocks` is 16 bits; images of 65,536 blocks commonly hold a
/// volume of 65,535 ([CP2] `ProDOS.IsSizeAllowed`).
const MAX_VOLUME_BLOCKS: usize = 0xffff;
const MAX_IMAGE_BLOCKS: usize = 0x1_0000;

/// Directory block fields ([TRM] B.2.1).
const PREVIOUS_POINTER: usize = 0x00;
const NEXT_POINTER: usize = 0x02;
const FIRST_ENTRY: usize = 0x04;

/// Fields of entries and headers, relative to the entry.
const STORAGE_AND_NAME: usize = 0x00;
const NAME: usize = 0x01;
const FILE_TYPE: usize = 0x10;
const KEY_POINTER: usize = 0x11;
const EOF: usize = 0x15;
const AUX_TYPE: usize = 0x1f;
const SUBDIRECTORY_MARKER: usize = 0x10;
const ENTRY_LENGTH: usize = 0x1f;
const ENTRIES_PER_BLOCK: usize = 0x20;
const FILE_COUNT: usize = 0x21;
const BIT_MAP_POINTER: usize = 0x23;
const TOTAL_BLOCKS: usize = 0x25;
const PARENT_POINTER: usize = 0x23;
const PARENT_ENTRY_NUMBER: usize = 0x25;
const PARENT_ENTRY_LENGTH: usize = 0x26;

/// The fields every entry holds ([TRM] B.2.2: "`entry_length` = $27").
const MIN_ENTRY_LENGTH: usize = 0x27;

/// Storage types ([TRM] B.2.4; [CP2] `ProDOS-notes.md` for 5).
const STORAGE_DELETED: u8 = 0x0;
const STORAGE_SEEDLING: u8 = 0x1;
const STORAGE_SAPLING: u8 = 0x2;
const STORAGE_TREE: u8 = 0x3;
const STORAGE_PASCAL_AREA: u8 = 0x4;
const STORAGE_EXTENDED: u8 = 0x5;
const STORAGE_SUBDIRECTORY: u8 = 0xd;
const STORAGE_SUBDIRECTORY_HEADER: u8 = 0xe;
const STORAGE_VOLUME_HEADER: u8 = 0xf;

/// The reserved byte of a subdirectory header ([TRM] B.2.3: $75; [CP2]:
/// GS/OS writes $76).
const SUBDIRECTORY_MARKERS: [u8; 2] = [0x75, 0x76];

/// File types holding 6502 code ([TRM] B.4.2.4: $06 "General binary
/// file", $FF "`ProDOS` system file").
const FILE_TYPE_BIN: u8 = 0x06;
const FILE_TYPE_SYS: u8 = 0xff;

/// "System programs are always loaded into memory starting at location
/// $2000" ([TRM] "Writing a `ProDOS` System Program").
const SYSTEM_LOAD_ADDRESS: u16 = 0x2000;

/// Index block capacities ([TRM] B.3.3, B.3.4).
const POINTERS_PER_INDEX: usize = 256;
const POINTERS_PER_MASTER_INDEX: usize = 128;

/// The resource-fork entry of an extended key block, and the fields of a
/// fork entry ([CP2] `ProDOS-notes.md` "Extended Files").
const RESOURCE_FORK: usize = 0x100;
const FORK_STORAGE: usize = 0x00;
const FORK_KEY: usize = 0x01;
const FORK_EOF: usize = 0x05;

/// Deepest subdirectory level the walk enters. `ProDOS` pathnames are at most
/// 64 characters ([TRM] chapter 2), so a real volume stays far below.
const MAX_DEPTH: usize = 64;

/// How the blocks of a sapling or tree file are reassembled.
const INDEX_TRANSFORM: &str = "ProDOS index blocks";

/// How a block is reassembled from the two sectors of a DOS-order image.
const SECTOR_ORDER_TRANSFORM: &str = "DOS sector order";

/// How the volume must fit the disk data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fit {
    /// A raw image: exactly the volume (or a 65,535-block volume in 65,536
    /// blocks).
    Exact,
    /// Inside a 2IMG data chunk or beside a DOS 3.3 catalog: at most the
    /// disk data.
    Within,
}

/// Where an entry is: its directory block, its number in that block from
/// 1 for the first slot ([CP2] `ScanDir`), and the entry length of its
/// directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryLocation {
    block: usize,
    number: usize,
    entry_length: usize,
}

/// An active directory entry.
#[derive(Debug)]
struct Entry {
    storage_type: u8,
    name: String,
    file_type: u8,
    key_pointer: usize,
    /// Size in bytes.
    eof: usize,
    aux_type: u16,
    location: EntryLocation,
}

/// The entry layout a directory header declares.
#[derive(Debug, Clone, Copy)]
struct DirectoryFormat {
    entry_length: usize,
    entries_per_block: usize,
    file_count: usize,
}

/// A directory chain read from its key block.
#[derive(Debug, Default)]
struct Directory {
    entries: Vec<Entry>,
    /// Entries with a nonzero storage type, valid or not ([TRM]: the file
    /// count is of entries "whose `storage_type` is not 0").
    active: usize,
    /// Problems; each skipped the entry or the rest of the chain it names.
    defects: Vec<String>,
}

/// A validated volume header and volume directory.
#[derive(Debug)]
pub(super) struct Volume {
    name: String,
    total_blocks: usize,
    entries: Vec<Entry>,
    /// Blocks read as directories so far, one flag per block.
    claimed: Vec<bool>,
}

/// One fork of a file: its storage type, key block and size.
#[derive(Debug, Clone, Copy)]
struct Fork {
    storage_type: u8,
    key_pointer: usize,
    eof: usize,
}

/// The 24-bit field at `at` of a fixed-size record.
fn le_u24<const N: usize>(record: &[u8; N], at: usize) -> usize {
    usize::from(record[at]) | usize::from(le_u16(record, at + 1)) << 8
}

/// The fixed fields of the entry at `start` of a directory block; the
/// header checks keep every entry inside the block.
fn entry_at(block: &[u8; BLOCK_SIZE], start: usize) -> Option<&[u8; MIN_ENTRY_LENGTH]> {
    block.get(start..start + MIN_ENTRY_LENGTH)?.try_into().ok()
}

/// A volume or directory name as letters, digits and periods; other bytes
/// show as `?`.
fn name_text(raw: &[u8]) -> String {
    raw.iter()
        .map(|&b| {
            if b.is_ascii_graphic() {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect()
}

/// A volume name follows the file name syntax: a letter, then letters,
/// digits or periods ([TRM] B.2.2, chapter 2).
fn is_volume_name(raw: &[u8]) -> bool {
    raw.first().is_some_and(u8::is_ascii_uppercase)
        && raw
            .iter()
            .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'.')
}

/// The entry layout of a header, when every entry fits in a block.
fn directory_format(header: &[u8; MIN_ENTRY_LENGTH]) -> Walk<DirectoryFormat> {
    let entry_length = usize::from(header[ENTRY_LENGTH]);
    let entries_per_block = usize::from(header[ENTRIES_PER_BLOCK]);
    if entry_length < MIN_ENTRY_LENGTH
        || entries_per_block == 0
        || entries_per_block > (BLOCK_SIZE - FIRST_ENTRY) / entry_length
    {
        return Err(format!(
            "entry length 0x{entry_length:02X} and {entries_per_block} entries per block do not \
             fit a block"
        ));
    }
    Ok(DirectoryFormat {
        entry_length,
        entries_per_block,
        file_count: usize::from(le_u16(header, FILE_COUNT)),
    })
}

/// Validate the volume directory header in block 2 and walk the volume
/// directory: every block of the chain, every active entry and the file
/// count must be valid ([CP2] `ProDOS.TestImage`,
/// `ExtractVolDirHeader`, with the warnings of `ScanDir` made strict).
pub(super) fn open(disk: Disk<'_>, fit: Fit) -> Result<Volume> {
    let image_blocks = disk.blocks();
    if image_blocks < MIN_VOLUME_BLOCKS {
        return Err(error(format!(
            "Truncated ProDOS image: {} B, at least {MIN_VOLUME_BLOCKS} blocks of 512 B expected",
            disk.size
        )));
    }
    let offset = disk
        .block_offsets(VOLUME_DIRECTORY_BLOCK)
        .expect("block 2 is on the disk")[0];
    let key_block = disk
        .block(VOLUME_DIRECTORY_BLOCK)
        .expect("block 2 is on the disk");
    let key: &[u8; BLOCK_SIZE] = &key_block;
    let invalid = |what: String| {
        error(format!(
            "Invalid volume directory header in block 2 at 0x{offset:X}: {what}"
        ))
    };
    let previous = le_u16(key, PREVIOUS_POINTER);
    if previous != 0 {
        return Err(invalid(format!(
            "previous block pointer {previous}, 0 expected"
        )));
    }
    let header = entry_at(key, FIRST_ENTRY).expect("the header is at the start of the block");
    let storage_type = header[STORAGE_AND_NAME] >> 4;
    if storage_type != STORAGE_VOLUME_HEADER {
        return Err(invalid(format!(
            "storage type 0x{storage_type:X}, 0xF expected"
        )));
    }
    let name_length = usize::from(header[STORAGE_AND_NAME] & 0x0f);
    let raw_name = &header[NAME..NAME + name_length];
    if !is_volume_name(raw_name) {
        return Err(invalid(format!("volume name '{}'", name_text(raw_name))));
    }
    let format = directory_format(header).map_err(&invalid)?;
    let total_blocks = usize::from(le_u16(header, TOTAL_BLOCKS));
    let fits = match fit {
        Fit::Exact => {
            total_blocks == image_blocks
                || (total_blocks == MAX_VOLUME_BLOCKS && image_blocks == MAX_IMAGE_BLOCKS)
        }
        Fit::Within => total_blocks <= image_blocks,
    };
    if total_blocks < MIN_VOLUME_BLOCKS || !fits {
        return Err(invalid(format!(
            "{total_blocks} total blocks; the image holds {image_blocks}"
        )));
    }
    let bitmap = usize::from(le_u16(header, BIT_MAP_POINTER));
    if bitmap <= VOLUME_DIRECTORY_BLOCK || bitmap >= total_blocks {
        return Err(invalid(format!(
            "bitmap pointer {bitmap} outside blocks 3-{}",
            total_blocks - 1
        )));
    }
    let mut claimed = vec![false; total_blocks];
    let directory = walk_directory(
        disk,
        total_blocks,
        VOLUME_DIRECTORY_BLOCK,
        format,
        &mut claimed,
    );
    if let Some(defect) = directory.defects.first() {
        return Err(error(format!("Invalid volume directory: {defect}")));
    }
    if directory.active != format.file_count {
        return Err(error(format!(
            "Invalid volume directory: file count {}, {} active entries",
            format.file_count, directory.active
        )));
    }
    Ok(Volume {
        name: name_text(raw_name),
        total_blocks,
        entries: directory.entries,
        claimed,
    })
}

/// Read the directory chain from `key`: each block is claimed once per
/// volume, so loops and cross-links end the chain, and the entries of the
/// key block start after the header.
fn walk_directory(
    disk: Disk<'_>,
    total_blocks: usize,
    key: usize,
    format: DirectoryFormat,
    claimed: &mut [bool],
) -> Directory {
    let mut directory = Directory::default();
    let mut block = key;
    let mut previous = 0usize;
    while block != 0 {
        if !(VOLUME_DIRECTORY_BLOCK..total_blocks).contains(&block) {
            directory.defects.push(format!(
                "the chain leads to block {block}, outside the volume"
            ));
            break;
        }
        if claimed[block] {
            directory.defects.push(format!(
                "block {block} is already part of a directory (a loop or a cross-link)"
            ));
            break;
        }
        claimed[block] = true;
        let Some(bytes) = disk.block(block) else {
            directory
                .defects
                .push(format!("block {block} is not in the image"));
            break;
        };
        let stated = usize::from(le_u16(&bytes, PREVIOUS_POINTER));
        if stated != previous {
            directory.defects.push(format!(
                "block {block} names block {stated} as its predecessor, not {previous}"
            ));
        }
        // The key block's first slot is the header.
        let first_slot = usize::from(block == key);
        for slot in first_slot..format.entries_per_block {
            let start = FIRST_ENTRY + slot * format.entry_length;
            let fields = entry_at(&bytes, start).expect("the header keeps entries in the block");
            let location = EntryLocation {
                block,
                number: slot + 1,
                entry_length: format.entry_length,
            };
            read_entry(fields, location, total_blocks, &mut directory);
        }
        previous = block;
        block = usize::from(le_u16(&bytes, NEXT_POINTER));
    }
    directory
}

/// Add the entry `fields` at `location` to `directory`: unused and deleted
/// slots are skipped, an invalid storage type, name length or key pointer
/// is a defect.
fn read_entry(
    fields: &[u8; MIN_ENTRY_LENGTH],
    location: EntryLocation,
    total_blocks: usize,
    directory: &mut Directory,
) {
    let storage_type = fields[STORAGE_AND_NAME] >> 4;
    let name_length = usize::from(fields[STORAGE_AND_NAME] & 0x0f);
    // A zero storage type is a deleted entry, also when the name length
    // was left behind ([CP2] `ScanDir`: "incomplete deletion").
    if storage_type == STORAGE_DELETED {
        return;
    }
    directory.active += 1;
    let place = format!("entry {} of block {}", location.number, location.block);
    let is_known = matches!(
        storage_type,
        STORAGE_SEEDLING
            | STORAGE_SAPLING
            | STORAGE_TREE
            | STORAGE_PASCAL_AREA
            | STORAGE_EXTENDED
            | STORAGE_SUBDIRECTORY
    );
    if !is_known {
        directory
            .defects
            .push(format!("{place} has storage type 0x{storage_type:X}"));
        return;
    }
    let key_pointer = usize::from(le_u16(fields, KEY_POINTER));
    if name_length == 0 || !(VOLUME_DIRECTORY_BLOCK..total_blocks).contains(&key_pointer) {
        directory.defects.push(format!(
            "{place} has name length {name_length} and key block {key_pointer}"
        ));
        return;
    }
    directory.entries.push(Entry {
        storage_type,
        name: name_text(&fields[NAME..NAME + name_length]),
        file_type: fields[FILE_TYPE],
        key_pointer,
        eof: le_u24(fields, EOF),
        aux_type: le_u16(fields, AUX_TYPE),
        location,
    });
}

/// List the files of a validated volume in directory order, then the
/// loader blocks.
pub(super) fn push_volume<'a>(disk: Disk<'a>, volume: &Volume, c: &mut Container<'a>) {
    c.notes.push(format!(
        "ProDOS volume /{}; {} blocks of 512 B; {}",
        volume.name,
        volume.total_blocks,
        disk.order.name()
    ));
    if volume.total_blocks < disk.blocks() {
        c.notes.push(format!(
            "The volume spans {} blocks; the disk data holds {}",
            volume.total_blocks,
            disk.blocks()
        ));
    }
    c.push_metadata(
        format!("{KEY_PREFIX}_volume_name"),
        "Volume name",
        volume.name.clone(),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_total_blocks"),
        "Total blocks",
        volume.total_blocks as u64,
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_sector_order"),
        "Sector order",
        disk.order.name(),
    );
    let mut walker = Walker {
        disk,
        total_blocks: volume.total_blocks,
        claimed: volume.claimed.clone(),
        census: Census::default(),
        directories: 1,
        too_deep: 0,
        pascal_areas: Vec::new(),
    };
    let root = format!("/{}", volume.name);
    for entry in &volume.entries {
        walker.entry(c, &root, entry, 0);
    }
    walker.report(c);
    let mut boot = Assembly::default();
    for block in 0..2 {
        boot.push_block(
            disk.block_offsets(block)
                .expect("blocks 0 and 1 are on the disk"),
        );
    }
    push_boot(
        c,
        disk.input,
        &boot,
        "blocks 0 and 1",
        SECTOR_ORDER_TRANSFORM,
    );
}

/// The walk below the volume directory.
struct Walker<'a> {
    disk: Disk<'a>,
    total_blocks: usize,
    /// Blocks read as directories or index blocks, one flag per block: a
    /// block is read as structure once per volume, which bounds the walk
    /// and ends loops and cross-links.
    claimed: Vec<bool>,
    census: Census,
    directories: usize,
    too_deep: usize,
    pascal_areas: Vec<String>,
}

impl<'a> Walker<'a> {
    /// List the entry at `parent`/`entry.name`, `depth` levels below the
    /// volume directory.
    fn entry(&mut self, c: &mut Container<'a>, parent: &str, entry: &Entry, depth: usize) {
        let path = format!("{parent}/{}", entry.name);
        match entry.storage_type {
            STORAGE_SUBDIRECTORY => self.directory(c, &path, entry, depth + 1),
            STORAGE_PASCAL_AREA => self.pascal_areas.push(path),
            STORAGE_EXTENDED => self.extended(c, &path, entry),
            storage_type => {
                let fork = Fork {
                    storage_type,
                    key_pointer: entry.key_pointer,
                    eof: entry.eof,
                };
                self.file(c, path, fork, file_kind(entry));
            }
        }
    }

    /// Walk the subdirectory `entry` at `path`, `depth` levels down.
    fn directory(&mut self, c: &mut Container<'a>, path: &str, entry: &Entry, depth: usize) {
        if depth > MAX_DEPTH {
            self.too_deep += 1;
            return;
        }
        let key = entry.key_pointer;
        let Some(bytes) = self.disk.block(key) else {
            self.census
                .problem(format!("{path}: key block {key} is not in the image"));
            return;
        };
        let header =
            entry_at(&bytes, FIRST_ENTRY).expect("the header is at the start of the block");
        let storage_type = header[STORAGE_AND_NAME] >> 4;
        if storage_type != STORAGE_SUBDIRECTORY_HEADER {
            self.census.problem(format!(
                "{path}: the directory header has storage type 0x{storage_type:X}, 0xE \
                 expected; not walked"
            ));
            return;
        }
        let format = match directory_format(header) {
            Ok(format) => format,
            Err(defect) => {
                self.census.problem(format!(
                    "{path}: the directory header's {defect}; not walked"
                ));
                return;
            }
        };
        self.check_parent(path, header, entry.location);
        self.directories += 1;
        let directory =
            walk_directory(self.disk, self.total_blocks, key, format, &mut self.claimed);
        for defect in &directory.defects {
            self.census.problem(format!("{path}: {defect}"));
        }
        if directory.active != format.file_count {
            self.census.problem(format!(
                "{path}: file count {}, {} active entries",
                format.file_count, directory.active
            ));
        }
        for child in &directory.entries {
            self.entry(c, path, child, depth);
        }
    }

    /// Notes for a subdirectory header whose marker or parent fields
    /// disagree with the entry that leads to it ([CP2]
    /// `ExtractDirHeader` warns and continues).
    fn check_parent(
        &mut self,
        path: &str,
        header: &[u8; MIN_ENTRY_LENGTH],
        location: EntryLocation,
    ) {
        let marker = header[SUBDIRECTORY_MARKER];
        if !SUBDIRECTORY_MARKERS.contains(&marker) {
            self.census.problem(format!(
                "{path}: the directory header's reserved byte is 0x{marker:02X}, not 0x75 or 0x76"
            ));
        }
        let parent = usize::from(le_u16(header, PARENT_POINTER));
        let number = usize::from(header[PARENT_ENTRY_NUMBER]);
        if parent != location.block || number != location.number {
            self.census.problem(format!(
                "{path}: the directory header names entry {number} of block {parent} as its \
                 parent, not entry {} of block {}",
                location.number, location.block
            ));
        }
        let length = usize::from(header[PARENT_ENTRY_LENGTH]);
        if length != location.entry_length {
            self.census.problem(format!(
                "{path}: the directory header gives the parent entry length 0x{length:02X}, not \
                 0x{:02X}",
                location.entry_length
            ));
        }
    }

    /// List both forks of an extended file: the data fork by the file
    /// type, the resource fork as opaque data.
    fn extended(&mut self, c: &mut Container<'a>, path: &str, entry: &Entry) {
        let key = match self.structure_block(entry.key_pointer) {
            Ok(key) => key,
            Err(defect) => {
                self.census
                    .problem(format!("{path}: extended key block: {defect}"));
                return;
            }
        };
        let fork_at = |start: usize| Fork {
            storage_type: key[start + FORK_STORAGE],
            key_pointer: usize::from(le_u16(&key, start + FORK_KEY)),
            eof: le_u24(&key, start + FORK_EOF),
        };
        let data = fork_at(0);
        let resource = fork_at(RESOURCE_FORK);
        self.file(c, path.to_string(), data, file_kind(entry));
        self.file(
            c,
            format!("{path} (resource fork)"),
            resource,
            FileKind::Opaque,
        );
    }

    /// List one fork at `path` when the limits allow, reading its blocks.
    fn file(&mut self, c: &mut Container<'a>, path: String, fork: Fork, kind: FileKind) {
        if !self.census.admit(c, fork.eof) {
            return;
        }
        let contents = match self.fork_contents(fork) {
            Ok(contents) => contents,
            Err(defect) => {
                self.census.problem(format!("{path}: {defect}; not listed"));
                return;
            }
        };
        let kind = if contents.len == 0 {
            FileKind::Opaque
        } else {
            kind
        };
        let transform = if fork.storage_type == STORAGE_SEEDLING {
            SECTOR_ORDER_TRANSFORM
        } else {
            INDEX_TRANSFORM
        };
        let fallback_offset = self
            .disk
            .block_offsets(fork.key_pointer)
            .map_or(self.disk.start, |halves| halves[0]);
        let file = File {
            label: path,
            contents,
            kind,
            transform,
            fallback_offset,
        };
        self.census.push_file(c, self.disk.input, file);
    }

    /// The bytes of a fork: its data blocks in file order up to its EOF,
    /// with sparse blocks as holes.
    fn fork_contents(&mut self, fork: Fork) -> Walk<Assembly> {
        let blocks = div_round_up(fork.eof, BLOCK_SIZE);
        let mut contents = Assembly::default();
        match fork.storage_type {
            STORAGE_SEEDLING => {
                if blocks > 1 {
                    return Err(format!("EOF {} B exceeds a seedling's block", fork.eof));
                }
                self.push_data_block(&mut contents, fork.key_pointer)?;
            }
            STORAGE_SAPLING => {
                if blocks > POINTERS_PER_INDEX {
                    return Err(format!("EOF {} B exceeds a sapling's 128 KiB", fork.eof));
                }
                let index = self.structure_block(fork.key_pointer)?;
                for i in 0..blocks {
                    self.push_data_block(&mut contents, pointer(&index, i))?;
                }
            }
            STORAGE_TREE => {
                if blocks > POINTERS_PER_MASTER_INDEX * POINTERS_PER_INDEX {
                    return Err(format!("EOF {} B exceeds a tree's 16 MiB", fork.eof));
                }
                let master = self.structure_block(fork.key_pointer)?;
                for i in 0..div_round_up(blocks, POINTERS_PER_INDEX) {
                    let count = (blocks - i * POINTERS_PER_INDEX).min(POINTERS_PER_INDEX);
                    let index_pointer = pointer(&master, i);
                    if index_pointer == 0 {
                        contents.push_hole(count * BLOCK_SIZE);
                        continue;
                    }
                    let index = self.structure_block(index_pointer)?;
                    for j in 0..count {
                        self.push_data_block(&mut contents, pointer(&index, j))?;
                    }
                }
            }
            other => return Err(format!("storage type 0x{other:X} is not a file")),
        }
        Ok(contents.range(0, fork.eof))
    }

    /// Append data block `block`: a hole for pointer 0, otherwise its two
    /// halves.
    fn push_data_block(&self, contents: &mut Assembly, block: usize) -> Walk<()> {
        if block == 0 {
            contents.push_hole(BLOCK_SIZE);
            return Ok(());
        }
        contents.push_block(self.offsets(block)?);
        Ok(())
    }

    /// The halves of a block the volume may reference (blocks 0 and 1 hold
    /// the loader, [CP2] `IsBlockValid`).
    fn offsets(&self, block: usize) -> Walk<[usize; 2]> {
        if !(VOLUME_DIRECTORY_BLOCK..self.total_blocks).contains(&block) {
            return Err(format!("block pointer {block} is outside the volume"));
        }
        self.disk
            .block_offsets(block)
            .ok_or_else(|| format!("block {block} is not in the image"))
    }

    /// An index, master index or extended key block, claimed so that each
    /// is read once per volume.
    fn structure_block(&mut self, block: usize) -> Walk<Cow<'a, [u8; BLOCK_SIZE]>> {
        self.offsets(block)?;
        if self.claimed[block] {
            return Err(format!(
                "block {block} is already in use as a directory or index block (a loop or a \
                 cross-link)"
            ));
        }
        self.claimed[block] = true;
        self.disk
            .block(block)
            .ok_or_else(|| format!("block {block} is not in the image"))
    }

    /// Notes for the walk, then the files.
    fn report(self, c: &mut Container<'_>) {
        c.notes.push(format!(
            "Directory walk: {}, volume directory included",
            counted(self.directories, "directory", "directories")
        ));
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
        if !self.pascal_areas.is_empty() {
            c.notes.push(format!(
                "Pascal areas are not extracted: {}",
                self.pascal_areas.join(", ")
            ));
        }
        c.push_metadata(
            format!("{KEY_PREFIX}_directory_count"),
            "Directories walked",
            self.directories as u64,
        );
        self.census.report(
            c,
            "BIN files at their aux type address, SYS files at 0x2000",
        );
    }
}

/// Pointer `i` of an index block: low byte at `i`, high byte at `256 + i`.
fn pointer(index: &[u8; BLOCK_SIZE], i: usize) -> usize {
    usize::from(index[i]) | usize::from(index[POINTERS_PER_INDEX + i]) << 8
}

/// What an entry's file type says about its data fork.
fn file_kind(entry: &Entry) -> FileKind {
    match entry.file_type {
        FILE_TYPE_BIN => FileKind::Code {
            load_address: entry.aux_type,
            file_type: "BIN",
        },
        FILE_TYPE_SYS => FileKind::Code {
            load_address: SYSTEM_LOAD_ADDRESS,
            file_type: "SYS",
        },
        _ => FileKind::Opaque,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_pointers_split_low_and_high_bytes_by_block_half() {
        let mut index = [0u8; BLOCK_SIZE];
        index[3] = 0x34;
        index[256 + 3] = 0x12;
        index[255] = 0x01;
        index[511] = 0x02;
        assert_eq!(pointer(&index, 3), 0x1234);
        assert_eq!(pointer(&index, 255), 0x0201);
        assert_eq!(pointer(&index, 0), 0);
    }

    #[test]
    fn volume_names_start_with_a_letter() {
        assert!(is_volume_name(b"ZRAX.1"));
        assert!(!is_volume_name(b"1ZRAX"));
        assert!(!is_volume_name(b"ZR AX"));
        assert!(!is_volume_name(b""));
        assert_eq!(name_text(b"A\x01 B"), "A??B");
    }

    #[test]
    fn directory_formats_must_fit_a_block() {
        let mut header = [0u8; MIN_ENTRY_LENGTH];
        header[ENTRY_LENGTH] = 0x27;
        header[ENTRIES_PER_BLOCK] = 0x0d;
        header[FILE_COUNT] = 3;
        let format = directory_format(&header).unwrap();
        assert_eq!(
            (
                format.entry_length,
                format.entries_per_block,
                format.file_count
            ),
            (0x27, 13, 3)
        );
        header[ENTRIES_PER_BLOCK] = 14;
        assert!(directory_format(&header).is_err());
        header[ENTRY_LENGTH] = 0x26;
        header[ENTRIES_PER_BLOCK] = 1;
        assert!(directory_format(&header).is_err());
    }
}
