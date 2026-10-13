//! The directory walk from the root inode. Directory blocks are read as
//! linear arrays of `ext4_dir_entry_2` records (`ext4_readdir`). The index
//! blocks of an htree directory (`dx_root`, block 0, and `dx_node`, whose
//! first record spans the block) hold no entries besides "." and "..", so
//! they are skipped as `__ext4_read_dirblock` identifies them; the hash
//! tree itself is not needed to enumerate entries. Regular files that start
//! with a recognized format become members labeled by their path.

use super::inode::{EXT4_ENCRYPT_FL, EXT4_INDEX_FL, EXT4_INLINE_DATA_FL};
use super::*;
use crate::formats::checksum::crc32c_update;
use crate::formats::container::{self, Child, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use std::collections::HashSet;

/// Deepest directory level below the root that the walk enters.
const MAX_DEPTH: usize = 64;

/// Bytes at the start of a regular file read to decide whether it is a
/// recognized format.
const RECOGNITION_PREFIX: usize = 4096;

/// Most regular files examined in one image.
const MAX_FILES_EXAMINED: usize = 1 << 16;

/// Problems reported one by one; further ones are counted.
const MAX_PROBLEM_NOTES: usize = 16;

/// Directory entry header: `inode`, `rec_len` (4), `name_len` (6),
/// `file_type` (7), then the name.
const DIRENT_HEADER_SIZE: usize = 8;

/// The shortest record, `ext4_dir_rec_len(1)`.
const DIRENT_MIN_SIZE: usize = 12;

/// The checksum tail at the end of a leaf block with `metadata_csum`
/// (`struct ext4_dir_entry_tail`): a 12-byte record with inode 0,
/// `name_len` 0 and this file type, then the CRC32C of the block before it.
const DIRENT_TAIL_SIZE: usize = 12;
const EXT4_FT_DIR_CSUM: u8 = 0xde;

/// With 64 KiB blocks, an on-disk `rec_len` of 0 or `EXT4_MAX_REC_LEN`
/// means the whole block, and bits 0-1 hold bits 16-17
/// (`ext4_rec_len_from_disk`).
const EXT4_MAX_REC_LEN: u16 = 0xffff;
const LARGEST_BLOCK_SIZE: usize = 64 << 10;

/// A directory waiting to be read. Its inode is read again when it is
/// walked, so pending directories hold no inode copies.
struct Directory {
    number: u32,
    node: usize,
    depth: usize,
}

/// A walked directory's name and parent, from which paths are built when
/// they are needed. Node 0 is the root.
struct PathNode {
    parent: usize,
    name: String,
}

/// One directory record.
#[derive(Debug)]
struct Entry<'b> {
    /// `inode`; 0 marks an unused record.
    inode: u32,
    /// Decoded `rec_len`: bytes to the next record.
    rec_len: usize,
    /// The name, `name_len` bytes.
    name: &'b [u8],
}

/// What the walk found and left out, for the notes.
#[derive(Debug, Default)]
struct Census {
    directories: usize,
    files: usize,
    members: usize,
    repeated: usize,
    encrypted_files: usize,
    encrypted_directories: usize,
    inline_files: usize,
    inline_directories: usize,
    too_deep: usize,
    unexamined: usize,
    too_large: usize,
    over_budget: usize,
    unwalked: usize,
    /// Regular files not listed because their data, or the blocks that map
    /// it, lie past the end of a truncated filesystem's input.
    absent_files: usize,
    /// Directory blocks past the end of a truncated filesystem's input.
    absent_directory_blocks: u64,
    problems: Vec<String>,
    unlisted_problems: usize,
}

struct Walker<'f, 'a> {
    fs: &'f Filesystem<'a>,
    nodes: Vec<PathNode>,
    visited: HashSet<u32>,
    census: Census,
    extracted: usize,
}

/// Check that the root inode is a directory.
///
/// # Errors
///
/// An unreadable root inode, a root inode that is not a directory, or a
/// root inode past the end of a truncated filesystem's input.
pub(super) fn check_root(fs: &Filesystem<'_>) -> ReadResult<()> {
    let root = fs.inode(EXT4_ROOT_INO)?;
    if !root.is_dir() {
        return invalid(format!(
            "Invalid root inode: mode 0x{:04X} is not a directory",
            root.mode
        ));
    }
    Ok(())
}

/// Walk the directory tree from the root, which [`check_root`] checked,
/// and append the members to `c`. Damage below the root is reported in
/// notes, and what lies past the end of a truncated filesystem's input is
/// counted.
pub(super) fn walk<'a>(fs: &Filesystem<'a>, c: &mut Container<'a>) {
    let mut walker = Walker {
        fs,
        nodes: vec![PathNode {
            parent: 0,
            name: String::new(),
        }],
        visited: HashSet::from([EXT4_ROOT_INO]),
        census: Census::default(),
        extracted: 0,
    };
    let mut pending = vec![Directory {
        number: EXT4_ROOT_INO,
        node: 0,
        depth: 0,
    }];
    while let Some(directory) = pending.pop() {
        if fs.is_exhausted() {
            walker.census.unwalked = pending.len() + 1;
            break;
        }
        let subdirectories = walker.directory(&directory, c);
        // Reversed, so that subdirectories are walked in entry order.
        pending.extend(subdirectories.into_iter().rev());
    }
    walker.census.report(fs, c);
}

/// The text of a `ClassifierError` without the family prefix.
fn message(e: ClassifierError) -> String {
    match e {
        ClassifierError::ExtParseError { message } => message,
        other => other.to_string(),
    }
}

/// `rec_len` as stored, decoded for the block size.
fn rec_len_from_disk(stored: u16, block_size: usize) -> usize {
    if block_size < LARGEST_BLOCK_SIZE {
        return usize::from(stored);
    }
    if stored == 0 || stored == EXT4_MAX_REC_LEN {
        return block_size;
    }
    let stored = usize::from(stored);
    (stored & 0xfffc) | ((stored & 3) << 16)
}

/// `ext4_dir_rec_len`: the header and name rounded up to 4 bytes.
fn rec_len_for(name_len: usize) -> usize {
    (DIRENT_HEADER_SIZE + name_len + 3) & !3
}

/// The record at `pos` of the first `size` bytes of `block`, checked as
/// `__ext4_check_dir_entry` checks it.
fn parse_entry(
    block: &[u8],
    pos: usize,
    size: usize,
    inodes_count: u32,
) -> std::result::Result<Entry<'_>, String> {
    let header = block
        .get(pos..pos + DIRENT_HEADER_SIZE)
        .filter(|_| pos + DIRENT_HEADER_SIZE <= size)
        .ok_or_else(|| format!("truncated entry at 0x{pos:X}"))?;
    let inode = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let rec_len = rec_len_from_disk(u16::from_le_bytes([header[4], header[5]]), block.len());
    let name_len = usize::from(header[6]);
    let defect = if rec_len < DIRENT_MIN_SIZE {
        Some("rec_len is smaller than minimal")
    } else if rec_len % 4 != 0 {
        Some("rec_len is not a multiple of 4")
    } else if rec_len < rec_len_for(name_len) {
        Some("rec_len is too small for name_len")
    } else if pos + rec_len > size {
        Some("the entry overruns the block")
    } else if pos + rec_len > size - DIRENT_MIN_SIZE && pos + rec_len != size {
        Some("the entry ends too close to the block end")
    } else if inode > inodes_count {
        Some("the inode number is out of bounds")
    } else {
        None
    };
    if let Some(defect) = defect {
        return Err(format!(
            "invalid entry at 0x{pos:X} (inode {inode}, rec_len {rec_len}, name_len \
             {name_len}): {defect}"
        ));
    }
    let name_at = pos + DIRENT_HEADER_SIZE;
    Ok(Entry {
        inode,
        rec_len,
        name: &block[name_at..name_at + name_len],
    })
}

/// An htree directory's index block: block 0 (`dx_root`) or a block whose
/// first record spans it (`dx_node`). An empty leaf looks the same and
/// holds no entries either.
fn is_index_block(block: &[u8], logical: u64) -> bool {
    let first_rec_len = block
        .get(4..6)
        .map(|bytes| rec_len_from_disk(u16::from_le_bytes([bytes[0], bytes[1]]), block.len()));
    logical == 0 || first_rec_len == Some(block.len())
}

/// Verify a leaf block's checksum tail (`ext4_dirblock_csum_verify`).
fn verify_tail(block: &[u8], seed: u32) -> std::result::Result<(), String> {
    let tail_at = block.len() - DIRENT_TAIL_SIZE;
    let tail = &block[tail_at..];
    let is_tail = tail[..4] == [0; 4]
        && rec_len_from_disk(u16::from_le_bytes([tail[4], tail[5]]), block.len())
            == DIRENT_TAIL_SIZE
        && tail[6] == 0
        && tail[7] == EXT4_FT_DIR_CSUM;
    if !is_tail {
        return Err("missing checksum tail".to_string());
    }
    let stored = u32::from_le_bytes([tail[8], tail[9], tail[10], tail[11]]);
    let computed = crc32c_update(seed, &block[..tail_at]);
    if stored != computed {
        return Err(format!(
            "invalid checksum 0x{stored:08X} (computed 0x{computed:08X})"
        ));
    }
    Ok(())
}

impl<'a> Walker<'_, 'a> {
    /// The path of `name` in the directory at `node`, from the root.
    fn path(&self, node: usize, name: &[u8]) -> String {
        let mut parts = Vec::new();
        if !name.is_empty() {
            parts.push(String::from_utf8_lossy(name).into_owned());
        }
        let mut current = node;
        // Parents precede their children in `nodes`, so this ends at the root.
        while current != 0 {
            parts.push(self.nodes[current].name.clone());
            current = self.nodes[current].parent;
        }
        parts.reverse();
        format!("/{}", parts.join("/"))
    }

    /// Record a problem below the root, unless the metadata limit caused
    /// it (that is reported once).
    fn problem(&mut self, path: &str, e: ClassifierError) {
        if self.fs.is_exhausted() {
            return;
        }
        self.problem_text(format!("Skipped {path}: {}", message(e)));
    }

    fn problem_text(&mut self, text: String) {
        if self.census.problems.len() < MAX_PROBLEM_NOTES {
            self.census.problems.push(text);
        } else {
            self.census.unlisted_problems += 1;
        }
    }

    /// Metadata that could not be read: a problem, or blocks past the end
    /// of a truncated filesystem's input, which the filesystem counts.
    fn metadata_fault(&mut self, path: &str, fault: Fault) {
        if let Fault::Invalid(e) = fault {
            self.problem(path, e);
        }
    }

    /// A regular file that could not be read: a problem, or data or
    /// mapping blocks past the end of a truncated filesystem's input, which
    /// are counted.
    fn file_fault(&mut self, path: &str, fault: Fault) {
        match fault {
            Fault::Invalid(e) => self.problem(path, e),
            Fault::Absent => self.census.absent_files += 1,
        }
    }

    /// Read one directory and return its subdirectories in entry order.
    fn directory(&mut self, directory: &Directory, c: &mut Container<'a>) -> Vec<Directory> {
        let fs = self.fs;
        let mut subdirectories = Vec::new();
        let inode = match fs.inode(directory.number) {
            Ok(inode) => inode,
            Err(fault) => {
                self.metadata_fault(&self.path(directory.node, b""), fault);
                return subdirectories;
            }
        };
        self.census.directories += 1;
        if inode.has_flag(EXT4_ENCRYPT_FL) {
            self.census.encrypted_directories += 1;
            return subdirectories;
        }
        if inode.has_flag(EXT4_INLINE_DATA_FL) {
            self.census.inline_directories += 1;
            return subdirectories;
        }
        // Directories have no holes, so a directory has no more logical
        // blocks than the filesystem has blocks. The bound also limits the
        // runs collected for a directory whose `i_size` is inflated.
        let block_size = fs.sb.block_size as u64;
        let end = blocks_for(inode.size, block_size).min(fs.sb.blocks_count);
        let runs = match fs.runs(&inode, end) {
            Ok(runs) => runs,
            Err(fault) => {
                self.metadata_fault(&self.path(directory.node, b""), fault);
                return subdirectories;
            }
        };
        let indexed = fs.sb.has_compat(COMPAT_DIR_INDEX) && inode.has_flag(EXT4_INDEX_FL);
        for run in runs {
            for k in 0..run.blocks {
                let block = match fs.charged_block(run.physical + k) {
                    Ok(block) => block,
                    // The run's blocks from here on lie past the end of the
                    // input; the directory's other runs may be present.
                    Err(Fault::Absent) => {
                        self.census.absent_directory_blocks += run.blocks - k;
                        break;
                    }
                    Err(Fault::Invalid(e)) => {
                        self.problem(&self.path(directory.node, b""), e);
                        return subdirectories;
                    }
                };
                let logical = run.logical + k;
                if indexed && is_index_block(block, logical) {
                    continue;
                }
                self.directory_block(directory, &inode, block, logical, &mut subdirectories, c);
            }
        }
        subdirectories
    }

    /// The entries of one leaf block.
    fn directory_block(
        &mut self,
        directory: &Directory,
        inode: &Inode,
        block: &[u8],
        logical: u64,
        subdirectories: &mut Vec<Directory>,
        c: &mut Container<'a>,
    ) {
        let size = match inode.csum_seed {
            Some(seed) => {
                if let Err(defect) = verify_tail(block, seed) {
                    let path = self.path(directory.node, b"");
                    self.problem_text(format!(
                        "Skipped {path} directory block {logical}: {defect}"
                    ));
                    return;
                }
                block.len() - DIRENT_TAIL_SIZE
            }
            None => block.len(),
        };
        let mut pos = 0;
        while pos < size {
            let entry = match parse_entry(block, pos, size, self.fs.sb.inodes_count) {
                Ok(parsed) => parsed,
                Err(defect) => {
                    // The kernel skips the rest of a block after a bad record.
                    let path = self.path(directory.node, b"");
                    self.problem_text(format!(
                        "Skipped the rest of {path} directory block {logical}: {defect}"
                    ));
                    return;
                }
            };
            pos += entry.rec_len;
            if entry.inode == 0 || entry.name == b"." || entry.name == b".." {
                continue;
            }
            self.entry(directory, &entry, subdirectories, c);
        }
    }

    /// One entry in use: a subdirectory to walk, a regular file to examine,
    /// or anything else (symlinks, devices), which is ignored.
    fn entry(
        &mut self,
        directory: &Directory,
        entry: &Entry<'_>,
        subdirectories: &mut Vec<Directory>,
        c: &mut Container<'a>,
    ) {
        if self.visited.contains(&entry.inode) {
            self.census.repeated += 1;
            return;
        }
        let inode = match self.fs.inode(entry.inode) {
            Ok(inode) => inode,
            Err(fault) => {
                self.metadata_fault(&self.path(directory.node, entry.name), fault);
                return;
            }
        };
        self.visited.insert(entry.inode);
        if inode.is_dir() {
            if directory.depth >= MAX_DEPTH {
                self.census.too_deep += 1;
                return;
            }
            self.nodes.push(PathNode {
                parent: directory.node,
                name: String::from_utf8_lossy(entry.name).into_owned(),
            });
            subdirectories.push(Directory {
                number: entry.inode,
                node: self.nodes.len() - 1,
                depth: directory.depth + 1,
            });
        } else if inode.is_regular() {
            self.file(&inode, self.path(directory.node, entry.name), c);
        }
    }

    /// List a regular file when its first bytes are a recognized format and
    /// the limits allow its extraction.
    fn file(&mut self, inode: &Inode, path: String, c: &mut Container<'a>) {
        self.census.files += 1;
        if c.children.len() >= MAX_COMPONENTS || self.census.files > MAX_FILES_EXAMINED {
            self.census.unexamined += 1;
            return;
        }
        if inode.has_flag(EXT4_ENCRYPT_FL) {
            self.census.encrypted_files += 1;
            return;
        }
        if inode.has_flag(EXT4_INLINE_DATA_FL) {
            self.census.inline_files += 1;
            return;
        }
        if inode.size == 0 {
            return;
        }
        let prefix_len = usize::try_from(inode.size.min(RECOGNITION_PREFIX as u64))
            .expect("at most the recognition prefix");
        let prefix = match self.fs.read(inode, prefix_len) {
            Ok(prefix) => prefix,
            Err(fault) => {
                self.file_fault(&path, fault);
                return;
            }
        };
        if !container::is_recognized(&prefix.bytes) {
            return;
        }
        let Some(size) = usize::try_from(inode.size)
            .ok()
            .filter(|&size| size <= MAX_PAYLOAD)
        else {
            self.census.too_large += 1;
            return;
        };
        if self.extracted + size > MAX_EXTRACTED {
            self.census.over_budget += 1;
            return;
        }
        let contents = if size == prefix_len {
            prefix
        } else {
            match self.fs.read(inode, size) {
                Ok(contents) => contents,
                Err(fault) => {
                    self.file_fault(&path, fault);
                    return;
                }
            }
        };
        // A file without stored blocks is all zeros and not a recognized
        // format.
        let Some(first_run) = contents.first_run else {
            return;
        };
        let child = match contents.bytes {
            Cow::Borrowed(bytes) => Child::stored(path, first_run.offset, bytes),
            Cow::Owned(bytes) => Child::decoded(
                path,
                first_run.offset,
                first_run.size,
                Cow::Owned(bytes),
                contents.transform,
            ),
        };
        c.children.push(child.if_recognized());
        self.extracted += size;
        self.census.members += 1;
    }
}

/// `count` with the singular or plural form of the words after it.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

impl Census {
    /// Notes and metadata: what was walked, then what was left out and why.
    fn report(self, fs: &Filesystem<'_>, c: &mut Container<'_>) {
        c.notes.push(format!(
            "Directory walk: {}, {}; members in a recognized format: {}",
            counted(self.directories, "directory", "directories"),
            counted(self.files, "regular file", "regular files"),
            self.members
        ));
        let absent_blocks = fs.absent_blocks.borrow().len();
        if absent_blocks > 0 {
            let (verb, pronoun) = if absent_blocks == 1 {
                ("lies", "it was")
            } else {
                ("lie", "they were")
            };
            c.notes.push(format!(
                "{} that the walk needed (group descriptors, inode tables, extent or indirect \
                 blocks) {verb} past the {} present; {pronoun} not read",
                counted(absent_blocks, "metadata block", "metadata blocks"),
                fs.present_text()
            ));
        }
        if self.absent_directory_blocks > 0 {
            let blocks = usize::try_from(self.absent_directory_blocks).unwrap_or(usize::MAX);
            let (verb, pronoun) = if blocks == 1 {
                ("lies", "its")
            } else {
                ("lie", "their")
            };
            c.notes.push(format!(
                "{} {verb} past the {} present; {pronoun} entries were not read",
                counted(blocks, "directory block", "directory blocks"),
                fs.present_text()
            ));
        }
        if self.absent_files > 0 {
            c.notes.push(format!(
                "{} not listed: file data, or blocks that map it, lie partly or wholly past the \
                 {} present",
                counted(self.absent_files, "regular file was", "regular files were"),
                fs.present_text()
            ));
        }
        if self.repeated > 0 {
            c.notes.push(format!(
                "{} an inode already visited (hard links); each inode is examined once",
                counted(
                    self.repeated,
                    "directory entry names",
                    "directory entries name"
                )
            ));
        }
        if self.encrypted_files + self.encrypted_directories > 0 {
            c.notes.push(format!(
                "{} and {} are opaque and were not read",
                counted(self.encrypted_files, "encrypted file", "encrypted files"),
                counted(
                    self.encrypted_directories,
                    "encrypted directory",
                    "encrypted directories"
                )
            ));
        }
        if self.inline_files + self.inline_directories > 0 {
            c.notes.push(format!(
                "{} and {} store inline data, which is not implemented; they were not read",
                counted(self.inline_files, "file", "files"),
                counted(self.inline_directories, "directory", "directories")
            ));
        }
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
        if self.unwalked > 0 {
            c.notes.push(format!(
                "The walk stopped at the metadata read limit (twice {}); {} not walked",
                fs.budget_basis(),
                counted(self.unwalked, "directory was", "directories were")
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
        c.push_metadata(
            "ext_directory_count",
            "Directories walked",
            self.directories as u64,
        );
        c.push_metadata("ext_regular_file_count", "Regular files", self.files as u64);
        c.push_metadata("ext_member_count", "Members", self.members as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_block_rec_len_encodes_the_high_bits_in_the_low_bits() {
        assert_eq!(rec_len_from_disk(12, 4096), 12);
        assert_eq!(rec_len_from_disk(0, LARGEST_BLOCK_SIZE), LARGEST_BLOCK_SIZE);
        assert_eq!(
            rec_len_from_disk(EXT4_MAX_REC_LEN, LARGEST_BLOCK_SIZE),
            LARGEST_BLOCK_SIZE
        );
        // 0x1_0010 is stored as 0x0011.
        assert_eq!(rec_len_from_disk(0x0011, LARGEST_BLOCK_SIZE), 0x1_0010);
    }

    #[test]
    fn entries_are_checked_like_the_kernel_checks_them() {
        let mut block = vec![0u8; 1024];
        // inode 12, rec_len 1024, name_len 3, file type 1, "elf".
        block[..4].copy_from_slice(&12u32.to_le_bytes());
        block[4..6].copy_from_slice(&1024u16.to_le_bytes());
        block[6] = 3;
        block[7] = 1;
        block[8..11].copy_from_slice(b"elf");
        let entry = parse_entry(&block, 0, 1024, 32).unwrap();
        assert_eq!(
            (entry.inode, entry.name, entry.rec_len),
            (12, &b"elf"[..], 1024)
        );

        assert!(parse_entry(&block, 0, 1024, 11)
            .unwrap_err()
            .contains("out of bounds"));
        block[4..6].copy_from_slice(&1018u16.to_le_bytes());
        assert!(parse_entry(&block, 0, 1024, 32)
            .unwrap_err()
            .contains("multiple of 4"));
        block[4..6].copy_from_slice(&1016u16.to_le_bytes());
        assert!(parse_entry(&block, 0, 1024, 32)
            .unwrap_err()
            .contains("too close"));
        block[4..6].copy_from_slice(&8u16.to_le_bytes());
        assert!(parse_entry(&block, 0, 1024, 32)
            .unwrap_err()
            .contains("smaller than minimal"));
        assert!(parse_entry(&block, 1020, 1024, 32)
            .unwrap_err()
            .contains("truncated"));
    }

    #[test]
    fn htree_index_blocks_are_block_zero_or_span_the_block() {
        let mut block = vec![0u8; 1024];
        block[4..6].copy_from_slice(&1024u16.to_le_bytes());
        assert!(is_index_block(&block, 3));
        block[4..6].copy_from_slice(&12u16.to_le_bytes());
        assert!(!is_index_block(&block, 3));
        assert!(is_index_block(&block, 0));
    }
}
