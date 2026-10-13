//! The directory walk from the root inode. Directory data is read through
//! the directory's own data layout and split into blocks, each an array of
//! 12-byte `erofs_dirent` records followed by their names
//! (`erofs_readdir`, `erofs_fill_dentries`). Regular files that start with
//! a recognized format become members labeled by their path. Every
//! directory and file inode is examined once, which also breaks directory
//! cycles.

use super::inode::{FileData, Inode};
use super::*;
use crate::formats::container::{self, Child, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;
use std::collections::HashSet;

/// Deepest directory level below the root that the walk enters.
const MAX_DEPTH: usize = 64;

/// Bytes at the start of a regular file read to decide whether it is a
/// recognized format.
const RECOGNITION_PREFIX: u64 = 4096;

/// Most regular files examined in one image.
const MAX_FILES_EXAMINED: usize = 1 << 16;

/// Problems reported one by one; further ones are counted.
const MAX_PROBLEM_NOTES: usize = 16;

/// `struct erofs_dirent`: `nid` (u64), `nameoff` (u16), `file_type`,
/// reserved.
const DIRENT_SIZE: usize = 12;

/// `EROFS_NAME_LEN`.
const EROFS_NAME_LEN: usize = 255;

/// A directory waiting to be read.
struct Directory {
    nid: u64,
    node: usize,
    depth: usize,
}

/// A walked directory's name and parent, from which paths are built when
/// they are needed. Node 0 is the root.
struct PathNode {
    parent: usize,
    name: String,
}

/// One directory entry.
#[derive(Debug)]
struct Entry<'b> {
    nid: u64,
    name: &'b [u8],
}

/// What the walk found and left out, for the notes.
#[derive(Debug, Default)]
struct Census {
    directories: usize,
    files: usize,
    members: usize,
    compressed_files: usize,
    repeated: usize,
    too_deep: usize,
    unexamined: usize,
    too_large: usize,
    over_budget: usize,
    unwalked: usize,
    problems: Vec<String>,
    unlisted_problems: usize,
}

struct Walker<'f, 'a> {
    fs: &'f Filesystem<'a>,
    nodes: Vec<PathNode>,
    visited: HashSet<u64>,
    census: Census,
    extracted: usize,
}

/// Walk the directory tree from the root and append the members to `c`.
///
/// # Errors
///
/// An unreadable root inode, or a root inode that is not a directory.
/// Damage below it is reported in notes.
pub(super) fn walk<'a>(fs: &Filesystem<'a>, c: &mut Container<'a>) -> Result<()> {
    let root_nid = fs.sb.root_nid;
    let root = fs.inode(root_nid)?;
    if !root.is_dir() {
        return Err(error(format!(
            "Invalid root inode {root_nid}: mode 0o{:o} is not a directory",
            root.mode
        )));
    }
    let mut walker = Walker {
        fs,
        nodes: vec![PathNode {
            parent: 0,
            name: String::new(),
        }],
        visited: HashSet::from([root_nid]),
        census: Census::default(),
        extracted: 0,
    };
    let mut pending = vec![Directory {
        nid: root_nid,
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
    walker.census.report(c);
    Ok(())
}

/// The text of a `ClassifierError` without the family prefix.
fn message(e: ClassifierError) -> String {
    match e {
        ClassifierError::ErofsParseError { message } => message,
        other => other.to_string(),
    }
}

/// The entries of one directory block of `size` bytes (`maxsize`): the
/// first `nameoff` gives the entry count; each name runs to the next
/// entry's `nameoff`, the last to its first NUL within the block.
fn parse_block(block: &[u8]) -> std::result::Result<Vec<Entry<'_>>, String> {
    let size = block.len();
    let first_nameoff = block
        .get(8..10)
        .map(|bytes| usize::from(u16::from_le_bytes([bytes[0], bytes[1]])))
        .ok_or_else(|| "truncated block".to_string())?;
    if first_nameoff < DIRENT_SIZE || first_nameoff >= size {
        return Err(format!("invalid de[0].nameoff {first_nameoff}"));
    }
    let count = first_nameoff / DIRENT_SIZE;
    let mut entries = Vec::with_capacity(count);
    for k in 0..count {
        let record = &block[k * DIRENT_SIZE..(k + 1) * DIRENT_SIZE];
        let nid = u64::from_le_bytes(record[..8].try_into().expect("eight bytes"));
        let nameoff = usize::from(u16::from_le_bytes([record[8], record[9]]));
        let name_end = if k + 1 < count {
            let next = &block[(k + 1) * DIRENT_SIZE + 8..(k + 1) * DIRENT_SIZE + 10];
            usize::from(u16::from_le_bytes([next[0], next[1]]))
        } else {
            let rest = block.get(nameoff..).unwrap_or_default();
            nameoff + rest.iter().position(|&b| b == 0).unwrap_or(rest.len())
        };
        if nameoff > name_end || name_end > size || name_end - nameoff > EROFS_NAME_LEN {
            return Err(format!(
                "bogus dirent {k} (nameoff {nameoff}, name end {name_end})"
            ));
        }
        entries.push(Entry {
            nid,
            name: &block[nameoff..name_end],
        });
    }
    Ok(entries)
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

    /// Record a problem below the root, unless the read limit caused it
    /// (that is reported once).
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

    /// The data of a directory, charged to the read budget.
    fn directory_data(&self, inode: &Inode) -> Result<FileData<'a>> {
        if inode.size > MAX_PAYLOAD as u64 {
            return Err(error(format!(
                "Unsupported directory of {} B (limit {})",
                inode.size,
                size_text(MAX_PAYLOAD as u64)
            )));
        }
        self.fs.charge(inode.size)?;
        self.fs.read(inode, inode.size)
    }

    /// Read one directory and return its subdirectories in entry order.
    fn directory(&mut self, directory: &Directory, c: &mut Container<'a>) -> Vec<Directory> {
        let mut subdirectories = Vec::new();
        let inode = match self.fs.inode(directory.nid) {
            Ok(inode) => inode,
            Err(e) => {
                self.problem(&self.path(directory.node, b""), e);
                return subdirectories;
            }
        };
        self.census.directories += 1;
        let data = match self.directory_data(&inode) {
            Ok(data) => data,
            Err(e) => {
                self.problem(&self.path(directory.node, b""), e);
                return subdirectories;
            }
        };
        let block_size = self.fs.sb.block_size;
        for (index, block) in data.bytes.chunks(block_size).enumerate() {
            let entries = match parse_block(block) {
                Ok(entries) => entries,
                Err(defect) => {
                    // The kernel stops reading a directory at a bad block.
                    let path = self.path(directory.node, b"");
                    self.problem_text(format!(
                        "Skipped the rest of {path} from directory block {index}: {defect}"
                    ));
                    break;
                }
            };
            for entry in entries {
                if entry.name == b"." || entry.name == b".." {
                    continue;
                }
                self.entry(directory, &entry, &mut subdirectories, c);
            }
        }
        subdirectories
    }

    /// One entry: a subdirectory to walk, a regular file to examine, or
    /// anything else (symlinks, devices), which is ignored.
    fn entry(
        &mut self,
        directory: &Directory,
        entry: &Entry<'_>,
        subdirectories: &mut Vec<Directory>,
        c: &mut Container<'a>,
    ) {
        if self.visited.contains(&entry.nid) {
            self.census.repeated += 1;
            return;
        }
        let inode = match self.fs.inode(entry.nid) {
            Ok(inode) => inode,
            Err(e) => {
                self.problem(&self.path(directory.node, entry.name), e);
                return;
            }
        };
        self.visited.insert(entry.nid);
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
                nid: entry.nid,
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
        if inode.layout.is_compressed() {
            self.census.compressed_files += 1;
        }
        if c.children.len() >= MAX_COMPONENTS || self.census.files > MAX_FILES_EXAMINED {
            self.census.unexamined += 1;
            return;
        }
        if inode.size == 0 {
            return;
        }
        let prefix = match self.fs.read(inode, inode.size.min(RECOGNITION_PREFIX)) {
            Ok(prefix) => prefix,
            Err(e) => {
                self.problem(&path, e);
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
        let contents = if size == prefix.bytes.len() {
            prefix
        } else {
            match self.fs.read(inode, inode.size) {
                Ok(contents) => contents,
                Err(e) => {
                    self.problem(&path, e);
                    return;
                }
            }
        };
        // A file without stored bytes (only holes) is all zeros and not a
        // recognized format.
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

impl Census {
    /// Notes and metadata: what was walked, then what was left out and why.
    fn report(self, c: &mut Container<'_>) {
        c.notes.push(format!(
            "Directory walk: {}, {} ({} compressed); members in a recognized format: {}",
            counted(self.directories, "directory", "directories"),
            counted(self.files, "regular file", "regular files"),
            self.compressed_files,
            self.members
        ));
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
                "The walk stopped at the metadata read limit; {} not walked",
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
            "erofs_directory_count",
            "Directories walked",
            self.directories as u64,
        );
        c.push_metadata(
            "erofs_regular_file_count",
            "Regular files",
            self.files as u64,
        );
        c.push_metadata(
            "erofs_compressed_file_count",
            "Compressed files",
            self.compressed_files as u64,
        );
        c.push_metadata("erofs_member_count", "Members", self.members as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory block with `names`, each record pointing at its name.
    fn block(names: &[&[u8]], size: usize) -> Vec<u8> {
        let mut block = vec![0u8; size];
        let mut nameoff = names.len() * DIRENT_SIZE;
        for (k, name) in names.iter().enumerate() {
            let record = &mut block[k * DIRENT_SIZE..(k + 1) * DIRENT_SIZE];
            record[..8].copy_from_slice(&(k as u64 + 36).to_le_bytes());
            record[8..10].copy_from_slice(&u16::try_from(nameoff).unwrap().to_le_bytes());
            block[nameoff..nameoff + name.len()].copy_from_slice(name);
            nameoff += name.len();
        }
        block
    }

    #[test]
    fn names_run_to_the_next_nameoff_and_the_last_to_its_nul() {
        let data = block(&[b".", b"..", b"elf"], 64);
        let entries = parse_block(&data).unwrap();
        let names: Vec<&[u8]> = entries.iter().map(|e| e.name).collect();
        assert_eq!(names, [&b"."[..], b"..", b"elf"]);
        assert_eq!(entries[2].nid, 38);
        // A last name that fills the block has no NUL.
        let full = block(&[b"abc"], 15);
        assert_eq!(parse_block(&full).unwrap()[0].name, b"abc");
    }

    #[test]
    fn bad_name_offsets_are_defects() {
        let mut data = block(&[b"a", b"b"], 64);
        assert!(parse_block(&data[..8]).is_err());
        data[8..10].copy_from_slice(&4u16.to_le_bytes());
        assert!(parse_block(&data).is_err());
        let mut data = block(&[b"a", b"b"], 64);
        // The second name starts before the first.
        data[DIRENT_SIZE + 8..DIRENT_SIZE + 10].copy_from_slice(&20u16.to_le_bytes());
        assert!(parse_block(&data).unwrap_err().contains("bogus dirent"));
    }
}
