//! The catalog walk from the root folder. A folder's children are the
//! catalog records keyed with its CNID as parent, read in key order from
//! its thread record ([TN1150] "Catalog Tree Usage"). Hard links are
//! resolved to the indirect node files of the metadata folders ([TN1150]
//! "Hard Links"; [HFS] `cat_resolvelink`), symbolic links are counted, and
//! regular files that start with a recognized format become members
//! labeled by their path. decmpfs files are decoded first.

use super::catalog::{
    self, Children, Entry, File, Folder, HAS_LINK_CHAIN, S_IFLNK, S_IFREG, UF_COMPRESSED,
};
use super::decmpfs::{self, Header, Storage};
use super::fork::{self, ForkBytes};
use super::*;
use crate::formats::container::{self, Child, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Deepest folder level below the root that the walk enters.
const MAX_DEPTH: usize = 64;

/// Bytes at the start of a file read to decide whether it is a recognized
/// format.
const RECOGNITION_PREFIX: usize = 4096;

/// Most regular files examined in one volume.
const MAX_FILES_EXAMINED: usize = 1 << 16;

/// Most entries of a metadata folder indexed for link resolution.
const MAX_INDIRECT_NODES: usize = 1 << 16;

/// Problems reported one by one; further ones are counted.
const MAX_PROBLEM_NOTES: usize = 16;

/// The root's metadata folders, as exported: four U+0000 characters and
/// `HFS+ Private Data` for file hard links, and `.HFS+ Private Directory
/// Data` and a carriage return for directory hard links ([HFS]
/// `HFSPLUSMETADATAFOLDER`, `HFSPLUS_DIR_METADATA_FOLDER`).
const FILE_METADATA_FOLDER: &str = "\u{2400}\u{2400}\u{2400}\u{2400}HFS+ Private Data";
const DIRECTORY_METADATA_FOLDER: &str = ".HFS+ Private Directory Data\r";

/// Indirect node names: the prefix and the link reference in decimal
/// (`HFS_INODE_PREFIX`, `HFS_DIRINODE_PREFIX`).
const INODE_PREFIX: &str = "iNode";
const DIRECTORY_INODE_PREFIX: &str = "dir_";

/// File links: `kHardLinkFileType` (`hlnk`) and `kHFSPlusCreator`
/// (`hfs+`). Directory links: `kHFSAliasType` (`fdrp`) and
/// `kHFSAliasCreator` (`MACS`) with a link chain ([HFS] `hfs_catalog.h`).
const HARD_LINK_FILE_TYPE: u32 = 0x686c_6e6b;
const HFS_PLUS_CREATOR: u32 = 0x6866_732b;
const ALIAS_FILE_TYPE: u32 = 0x6664_7270;
const ALIAS_CREATOR: u32 = 0x4d41_4353;

/// The transform of a file reassembled from several extents.
const EXTENTS_TRANSFORM: &str = "HFS+ extents";

/// The label of the startup file's member.
const STARTUP_FILE_LABEL: &str = "Startup file";

/// A folder waiting to be read.
struct Directory {
    id: u32,
    node: usize,
    depth: usize,
}

/// A walked folder's name and parent, from which paths are built when they
/// are needed. Node 0 is the root.
struct PathNode {
    parent: usize,
    name: String,
}

/// The metadata folders and their indirect nodes, indexed on first use.
#[derive(Default)]
struct Private {
    /// CNID of the file hard-link metadata folder.
    file_folder: Option<u32>,
    /// CNID of the directory hard-link metadata folder.
    directory_folder: Option<u32>,
    /// Creation dates a link must carry to be resolved: the root's and the
    /// metadata folders' ([HFS] `cat_lookupbykey`; [TN1150] "Hard Links").
    link_dates: Vec<u32>,
    /// Indirect node files by name.
    inodes: Option<HashMap<String, File>>,
    /// Indirect node folders by name.
    directory_inodes: Option<HashMap<String, u32>>,
    /// The index of indirect node files stopped at catalog nodes past the
    /// end of a truncated volume's input, so a name it lacks may exist.
    inodes_cut: bool,
    /// The same for the index of indirect node folders.
    directory_inodes_cut: bool,
}

/// What the walk found and left out, for the notes.
#[derive(Debug, Default)]
struct Census {
    directories: usize,
    files: usize,
    members: usize,
    hard_links: usize,
    repeated_links: usize,
    broken_links: usize,
    directory_links: usize,
    repeated_folders: usize,
    symlinks: usize,
    special_files: usize,
    compressed: BTreeMap<&'static str, usize>,
    unsupported_compression: BTreeMap<u32, usize>,
    too_deep: usize,
    unexamined: usize,
    too_large: usize,
    over_budget: usize,
    unwalked: usize,
    /// Regular files not listed because their data, or the B-tree records
    /// that locate it, lie past the end of a truncated volume's input.
    absent_files: usize,
    problems: Vec<String>,
    unlisted_problems: usize,
}

struct Walker<'f, 'a> {
    fs: &'f Filesystem<'a>,
    nodes: Vec<PathNode>,
    visited_folders: HashSet<u32>,
    visited_files: HashSet<u32>,
    private: Private,
    census: Census,
    extracted: usize,
}

/// The text of a `ClassifierError` without the family prefix.
pub(super) fn message(e: ClassifierError) -> String {
    match e {
        ClassifierError::HfsPlusParseError { message } => message,
        other => other.to_string(),
    }
}

/// The root folder: its thread record, which names the volume, and its
/// folder record.
pub(super) struct Root {
    thread: catalog::Thread,
    folder: Folder,
}

/// Find the root folder's thread and folder records.
///
/// # Errors
///
/// A missing root folder thread or folder record, or catalog nodes past the
/// end of a truncated volume's input on the way to them.
pub(super) fn root(fs: &Filesystem<'_>) -> ReadResult<Root> {
    let thread = catalog::thread(fs, ROOT_FOLDER_ID)?
        .filter(|thread| thread.parent_id == ROOT_PARENT_ID)
        .ok_or_else(|| error("Missing root folder thread record"))?;
    let folder = root_folder(fs)?;
    Ok(Root { thread, folder })
}

/// Walk the catalog from the root folder and append the members to `c`.
/// Damage below the root is reported in notes, and what lies past the end
/// of a truncated volume's input is counted.
pub(super) fn walk<'a>(fs: &Filesystem<'a>, root: Root, c: &mut Container<'a>) {
    c.push_metadata("hfsplus_volume_name", "Volume name", root.thread.name);
    let root = root.folder;
    let mut walker = Walker {
        fs,
        nodes: vec![PathNode {
            parent: 0,
            name: String::new(),
        }],
        visited_folders: HashSet::from([ROOT_FOLDER_ID]),
        visited_files: HashSet::new(),
        private: Private::default(),
        census: Census::default(),
        extracted: 0,
    };
    walker.find_metadata_folders(root);
    let mut pending = vec![Directory {
        id: ROOT_FOLDER_ID,
        node: 0,
        depth: 0,
    }];
    while let Some(directory) = pending.pop() {
        if fs.vol.is_exhausted() {
            walker.census.unwalked = pending.len() + 1;
            break;
        }
        let subdirectories = walker.directory(&directory, c);
        // Reversed, so that subfolders are walked in key order.
        pending.extend(subdirectories.into_iter().rev());
    }
    walker.census.report(fs, c);
}

/// The root folder record, keyed (1, volume name).
fn root_folder(fs: &Filesystem<'_>) -> ReadResult<Folder> {
    let mut children = Children::new(fs, ROOT_PARENT_ID)?;
    while let Some(member) = children.next()? {
        if let Entry::Folder(folder) = member.entry {
            if folder.id == ROOT_FOLDER_ID {
                return Ok(folder);
            }
        }
    }
    invalid("Missing root folder record")
}

/// `count` with the singular or plural form of the words after it.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

impl<'a> Walker<'_, 'a> {
    /// The path of `name` in the folder at `node`, from the root.
    fn path(&self, node: usize, name: &str) -> String {
        let mut parts = Vec::new();
        if !name.is_empty() {
            parts.push(name.to_string());
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
        if self.fs.vol.is_exhausted() {
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

    /// A folder, or the metadata of one, that could not be read: a problem,
    /// or catalog nodes past the end of a truncated volume's input, which
    /// the B-tree counts.
    fn folder_fault(&mut self, path: &str, fault: Fault) {
        if let Fault::Invalid(e) = fault {
            self.problem(path, e);
        }
    }

    /// A regular file that could not be read: a problem, or data or records
    /// past the end of a truncated volume's input, which are counted.
    fn file_fault(&mut self, path: &str, fault: Fault) {
        match fault {
            Fault::Invalid(e) => self.problem(path, e),
            Fault::Absent => self.census.absent_files += 1,
        }
    }

    /// Find the metadata folders among the root's children and the dates a
    /// link must carry.
    fn find_metadata_folders(&mut self, root: Folder) {
        self.private.link_dates.push(root.create_date);
        let mut children = match Children::new(self.fs, ROOT_FOLDER_ID) {
            Ok(children) => children,
            Err(fault) => return self.folder_fault("/", fault),
        };
        loop {
            let member = match children.next() {
                Ok(Some(member)) => member,
                Ok(None) => break,
                Err(fault) => return self.folder_fault("/", fault),
            };
            let Entry::Folder(folder) = member.entry else {
                continue;
            };
            if member.name == FILE_METADATA_FOLDER {
                self.private.file_folder = Some(folder.id);
            } else if member.name == DIRECTORY_METADATA_FOLDER {
                self.private.directory_folder = Some(folder.id);
            } else {
                continue;
            }
            self.private.link_dates.push(folder.create_date);
        }
    }

    /// Read one folder and return its subfolders in key order.
    fn directory(&mut self, directory: &Directory, c: &mut Container<'a>) -> Vec<Directory> {
        let mut subdirectories = Vec::new();
        self.census.directories += 1;
        let mut children = match Children::new(self.fs, directory.id) {
            Ok(children) => children,
            Err(fault) => {
                self.folder_fault(&self.path(directory.node, ""), fault);
                return subdirectories;
            }
        };
        loop {
            let member = match children.next() {
                Ok(Some(member)) => member,
                Ok(None) => break,
                Err(fault) => {
                    self.folder_fault(&self.path(directory.node, ""), fault);
                    break;
                }
            };
            match member.entry {
                Entry::Folder(folder) => {
                    let is_metadata = Some(folder.id) == self.private.file_folder
                        || Some(folder.id) == self.private.directory_folder;
                    // Indirect nodes are reached through their links.
                    if !(directory.id == ROOT_FOLDER_ID && is_metadata) {
                        self.subdirectory(directory, member.name, folder.id, &mut subdirectories);
                    }
                }
                Entry::File(file) => {
                    self.file_entry(directory, &member.name, &file, &mut subdirectories, c);
                }
                // A thread record keyed with a name is not a child.
                Entry::Thread(_) => {}
            }
        }
        subdirectories
    }

    /// Queue a subfolder once; a folder reached again (through a directory
    /// link or a damaged catalog) is counted.
    fn subdirectory(
        &mut self,
        directory: &Directory,
        name: String,
        id: u32,
        subdirectories: &mut Vec<Directory>,
    ) {
        if directory.depth >= MAX_DEPTH {
            self.census.too_deep += 1;
            return;
        }
        if !self.visited_folders.insert(id) {
            self.census.repeated_folders += 1;
            return;
        }
        self.nodes.push(PathNode {
            parent: directory.node,
            name,
        });
        subdirectories.push(Directory {
            id,
            node: self.nodes.len() - 1,
            depth: directory.depth + 1,
        });
    }

    /// One file record: a hard link to resolve, a directory link to walk,
    /// a regular file to examine, or a symbolic link or special file to
    /// count.
    fn file_entry(
        &mut self,
        directory: &Directory,
        name: &str,
        file: &File,
        subdirectories: &mut Vec<Directory>,
        c: &mut Container<'a>,
    ) {
        let is_link_date = self.private.link_dates.contains(&file.create_date);
        if is_link_date
            && file.type_code == HARD_LINK_FILE_TYPE
            && file.creator_code == HFS_PLUS_CREATOR
        {
            self.census.hard_links += 1;
            return self.hard_link(directory, name, file, c);
        }
        let is_directory_link = file.flags & HAS_LINK_CHAIN != 0
            && file.type_code == ALIAS_FILE_TYPE
            && file.creator_code == ALIAS_CREATOR
            && file.special >= FIRST_USER_CATALOG_NODE_ID;
        if is_link_date && is_directory_link {
            self.census.directory_links += 1;
            return self.directory_link(directory, name, file, subdirectories);
        }
        if !self.visited_files.insert(file.id) {
            self.census.repeated_links += 1;
            return;
        }
        match file.file_mode_type() {
            S_IFLNK => self.census.symlinks += 1,
            S_IFREG | 0 => {
                let path = self.path(directory.node, name);
                self.file(file, &path, c);
            }
            _ => self.census.special_files += 1,
        }
    }

    /// Resolve a file hard link to its indirect node file `iNode<ref>` and
    /// examine that file once, under the first link's path.
    fn hard_link(&mut self, directory: &Directory, name: &str, link: &File, c: &mut Container<'a>) {
        let path = self.path(directory.node, name);
        let inode_name = format!("{INODE_PREFIX}{}", link.special);
        let inode = match self.inodes() {
            Ok(inodes) => inodes.get(&inode_name).cloned(),
            Err(fault) => return self.file_fault(&path, fault),
        };
        let Some(inode) = inode else {
            if self.private.inodes_cut {
                self.census.absent_files += 1;
                return;
            }
            self.census.broken_links += 1;
            return self.problem_text(format!(
                "Skipped {path}: hard link to the missing indirect node {inode_name}"
            ));
        };
        if !self.visited_files.insert(inode.id) {
            self.census.repeated_links += 1;
            return;
        }
        self.file(&inode, &path, c);
    }

    /// Resolve a directory hard link to its folder `dir_<ref>` and walk it
    /// once, under the link's path.
    fn directory_link(
        &mut self,
        directory: &Directory,
        name: &str,
        link: &File,
        subdirectories: &mut Vec<Directory>,
    ) {
        let folder_name = format!("{DIRECTORY_INODE_PREFIX}{}", link.special);
        let folder = match self.directory_inodes() {
            Ok(folders) => folders.get(&folder_name).copied(),
            Err(fault) => return self.folder_fault(&self.path(directory.node, name), fault),
        };
        if let Some(id) = folder {
            self.subdirectory(directory, name.to_string(), id, subdirectories);
        } else if !self.private.directory_inodes_cut {
            self.census.broken_links += 1;
            let path = self.path(directory.node, name);
            self.problem_text(format!(
                "Skipped {path}: directory link to the missing folder {folder_name}"
            ));
        }
    }

    /// The indirect node files of the file metadata folder, by name,
    /// indexed on first use. An error is returned once; later links use
    /// what was indexed before it.
    fn inodes(&mut self) -> ReadResult<&HashMap<String, File>> {
        if self.private.inodes.is_none() {
            let mut inodes = HashMap::new();
            let indexed =
                index_folder(
                    self.fs,
                    self.private.file_folder,
                    &mut inodes,
                    |entry| match entry {
                        Entry::File(file) => Some(*file),
                        _ => None,
                    },
                );
            self.private.inodes = Some(inodes);
            self.private.inodes_cut = matches!(indexed, Err(Fault::Absent));
            indexed?;
        }
        Ok(self.private.inodes.as_ref().expect("indexed above"))
    }

    /// The indirect node folders of the directory metadata folder, by name,
    /// indexed on first use as [`Self::inodes`] is.
    fn directory_inodes(&mut self) -> ReadResult<&HashMap<String, u32>> {
        if self.private.directory_inodes.is_none() {
            let mut folders = HashMap::new();
            let folder = self.private.directory_folder;
            let indexed = index_folder(self.fs, folder, &mut folders, |entry| match entry {
                Entry::Folder(folder) => Some(folder.id),
                _ => None,
            });
            self.private.directory_inodes = Some(folders);
            self.private.directory_inodes_cut = matches!(indexed, Err(Fault::Absent));
            indexed?;
        }
        Ok(self
            .private
            .directory_inodes
            .as_ref()
            .expect("indexed above"))
    }

    /// List a regular file when its first bytes are a recognized format and
    /// the limits allow its extraction.
    fn file(&mut self, file: &File, path: &str, c: &mut Container<'a>) {
        self.census.files += 1;
        if c.children.len() >= MAX_COMPONENTS || self.census.files > MAX_FILES_EXAMINED {
            self.census.unexamined += 1;
            return;
        }
        let member = if file.owner_flags & UF_COMPRESSED != 0 {
            self.compressed_file(file, path)
        } else {
            self.plain_file(file, path)
        };
        match member {
            Ok(Some(child)) => {
                self.extracted += child.data.len();
                self.census.members += 1;
                c.children.push(child.if_recognized());
            }
            Ok(None) => {}
            Err(fault) => self.file_fault(path, fault),
        }
    }

    /// Whether a recognized file of `size` decoded bytes may be extracted;
    /// counts the ones that may not.
    fn may_extract(&mut self, size: usize) -> bool {
        if size > MAX_PAYLOAD {
            self.census.too_large += 1;
            false
        } else if self.extracted + size > MAX_EXTRACTED {
            self.census.over_budget += 1;
            false
        } else {
            true
        }
    }

    /// A file whose data fork holds its bytes.
    fn plain_file(&mut self, file: &File, path: &str) -> ReadResult<Option<Child<'a>>> {
        let fs = self.fs;
        let size = file.data_fork.logical_size;
        if size == 0 {
            return Ok(None);
        }
        let prefix_len =
            usize::try_from(size.min(RECOGNITION_PREFIX as u64)).expect("at most the prefix");
        let prefix = read_data_fork(fs, file, prefix_len)?;
        if !container::is_recognized(&prefix.bytes) {
            return Ok(None);
        }
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        if !self.may_extract(size) {
            return Ok(None);
        }
        let contents = if size == prefix_len {
            prefix
        } else {
            read_data_fork(fs, file, size)?
        };
        let Some(run) = contents.first_run else {
            return Ok(None);
        };
        let child = match contents.bytes {
            Cow::Borrowed(bytes) => Child::stored(path, run.offset, bytes),
            Cow::Owned(bytes) => Child::decoded(
                path,
                run.offset,
                run.size,
                Cow::Owned(bytes),
                EXTENTS_TRANSFORM,
            ),
        };
        Ok(Some(child))
    }

    /// A decmpfs file: its header in the `com.apple.decmpfs` attribute, its
    /// data after the header or in the resource fork.
    fn compressed_file(&mut self, file: &File, path: &str) -> ReadResult<Option<Child<'a>>> {
        let fs = self.fs;
        let attribute = fs.decmpfs_attribute(file.id)?.ok_or_else(|| {
            error("Missing com.apple.decmpfs attribute of a compressed file (UF_COMPRESSED)")
        })?;
        let header = Header::parse(&attribute.bytes)?;
        let Some(method) = header.method() else {
            *self
                .census
                .unsupported_compression
                .entry(header.compression_type)
                .or_default() += 1;
            return Ok(None);
        };
        let member = self.decmpfs_member(file, path, &attribute, header, method);
        // A resource fork past the end of a truncated volume's input was
        // not decoded; the file is counted with the absent files.
        if !matches!(member, Err(Fault::Absent)) {
            *self
                .census
                .compressed
                .entry(method.compression.name())
                .or_default() += 1;
        }
        member
    }

    /// The member for a decmpfs file whose attribute and header were read:
    /// decoded from the attribute or from the resource fork.
    fn decmpfs_member(
        &mut self,
        file: &File,
        path: &str,
        attribute: &decmpfs::Attribute,
        header: Header,
        method: decmpfs::Method,
    ) -> ReadResult<Option<Child<'a>>> {
        let fs = self.fs;
        let size = usize::try_from(header.size).unwrap_or(usize::MAX);
        if size == 0 {
            return Ok(None);
        }
        let transform = method.compression.transform();
        match method.storage {
            Storage::Attribute => {
                if size > MAX_PAYLOAD {
                    self.census.too_large += 1;
                    return Ok(None);
                }
                let decoded =
                    decmpfs::decode_attribute(method.compression, &attribute.bytes, size)?;
                if !container::is_recognized(&decoded[..decoded.len().min(RECOGNITION_PREFIX)])
                    || !self.may_extract(size)
                {
                    return Ok(None);
                }
                let offset = attribute
                    .offset
                    .ok_or_else(|| error("Invalid attributes B-tree: unmapped node"))?;
                let stored_size = decmpfs::attribute_payload_size(&attribute.bytes);
                Ok(Some(Child::decoded(
                    path,
                    offset + decmpfs::DECMPFS_HEADER_SIZE,
                    stored_size,
                    Cow::Owned(decoded),
                    transform,
                )))
            }
            Storage::ResourceFork => {
                let fork_size = file.resource_fork.logical_size;
                let Some(fork_size) = usize::try_from(fork_size)
                    .ok()
                    .filter(|&fork_size| fork_size <= MAX_PAYLOAD && size <= MAX_PAYLOAD)
                else {
                    self.census.too_large += 1;
                    return Ok(None);
                };
                let fork = fork::resolve(
                    &fs.vol,
                    fs.extents.as_ref(),
                    &file.resource_fork,
                    file.id,
                    RESOURCE_FORK,
                    fork_size as u64,
                )?;
                let stored = fs.vol.read_fork(&fork, 0, fork_size)?;
                let prefix = decmpfs::decode_resource_fork(
                    method.compression,
                    &stored.bytes,
                    size,
                    RECOGNITION_PREFIX,
                )?;
                if !container::is_recognized(&prefix[..prefix.len().min(RECOGNITION_PREFIX)])
                    || !self.may_extract(size)
                {
                    return Ok(None);
                }
                let decoded =
                    decmpfs::decode_resource_fork(method.compression, &stored.bytes, size, size)?;
                let Some(run) = stored.first_run else {
                    return Ok(None);
                };
                Ok(Some(Child::decoded(
                    path,
                    run.offset,
                    run.size,
                    Cow::Owned(decoded),
                    transform,
                )))
            }
        }
    }
}

/// Add the children of metadata folder `folder` that `select` keeps to
/// `entries`, by name, up to [`MAX_INDIRECT_NODES`].
fn index_folder<T>(
    fs: &Filesystem<'_>,
    folder: Option<u32>,
    entries: &mut HashMap<String, T>,
    select: impl Fn(Entry) -> Option<T>,
) -> ReadResult<()> {
    let Some(folder) = folder else {
        return Ok(());
    };
    let mut children = Children::new(fs, folder)?;
    while let Some(member) = children.next()? {
        if entries.len() >= MAX_INDIRECT_NODES {
            break;
        }
        if let Some(value) = select(member.entry) {
            entries.insert(member.name, value);
        }
    }
    Ok(())
}

/// The first `len` bytes of a file's data fork.
fn read_data_fork<'a>(fs: &Filesystem<'a>, file: &File, len: usize) -> ReadResult<ForkBytes<'a>> {
    let fork = fork::resolve(
        &fs.vol,
        fs.extents.as_ref(),
        &file.data_fork,
        file.id,
        DATA_FORK,
        len as u64,
    )?;
    fs.vol.read_fork(&fork, 0, len)
}

/// List the startup file, a boot loader for systems without HFS Plus
/// support ([TN1150] "Startup File"), last, when it starts with a
/// recognized format.
pub(super) fn startup_file<'a>(fs: &Filesystem<'a>, c: &mut Container<'a>) {
    let data = fs.vol.header.startup_file;
    if data.logical_size == 0 {
        return;
    }
    match startup_member(fs, &data) {
        Ok(Some(child)) => {
            c.notes.push(format!(
                "Startup file of {} listed last",
                size_text(child.data.len())
            ));
            c.children.push(child.if_recognized());
        }
        Ok(None) => c.notes.push(format!(
            "Startup file of {} B is not a recognized format or exceeds the extraction limits; \
             not listed",
            data.logical_size
        )),
        Err(Fault::Invalid(e)) => c
            .notes
            .push(format!("Startup file not read: {}", message(e))),
        Err(Fault::Absent) => c.notes.push(format!(
            "Startup file of {} B not read: it lies partly or wholly past the {} present",
            data.logical_size,
            fs.vol.present_text()
        )),
    }
}

fn startup_member<'a>(fs: &Filesystem<'a>, data: &ForkData) -> ReadResult<Option<Child<'a>>> {
    let Some(size) = usize::try_from(data.logical_size)
        .ok()
        .filter(|&size| size <= MAX_PAYLOAD)
    else {
        return Ok(None);
    };
    let fork = fork::resolve(
        &fs.vol,
        fs.extents.as_ref(),
        data,
        STARTUP_FILE_ID,
        DATA_FORK,
        size as u64,
    )?;
    let contents = fs.vol.read_fork(&fork, 0, size)?;
    if !container::is_recognized(&contents.bytes[..size.min(RECOGNITION_PREFIX)]) {
        return Ok(None);
    }
    let Some(run) = contents.first_run else {
        return Ok(None);
    };
    Ok(Some(match contents.bytes {
        Cow::Borrowed(bytes) => Child::stored(STARTUP_FILE_LABEL, run.offset, bytes),
        Cow::Owned(bytes) => Child::decoded(
            STARTUP_FILE_LABEL,
            run.offset,
            run.size,
            Cow::Owned(bytes),
            EXTENTS_TRANSFORM,
        ),
    }))
}

impl Census {
    /// Notes and metadata: what was walked, then what was left out and why.
    fn report(self, fs: &Filesystem<'_>, c: &mut Container<'_>) {
        c.notes.push(format!(
            "Catalog walk: {}, {}; members in a recognized format: {}",
            counted(self.directories, "folder", "folders"),
            counted(self.files, "regular file", "regular files"),
            self.members
        ));
        absent_notes(fs, self.absent_files, c);
        if self.hard_links > 0 {
            c.notes.push(format!(
                "{} resolved to indirect node files; each file is examined once, under its first \
                 link's path",
                counted(self.hard_links, "hard link was", "hard links were")
            ));
        }
        if self.repeated_links > 0 {
            c.notes.push(format!(
                "{} to a file already examined",
                counted(
                    self.repeated_links,
                    "further link was skipped as it leads",
                    "further links were skipped as they lead"
                )
            ));
        }
        if self.repeated_folders > 0 {
            c.notes.push(format!(
                "{} not walked again",
                counted(
                    self.repeated_folders,
                    "folder reached a second time was",
                    "folders reached a second time were"
                )
            ));
        }
        if self.directory_links > 0 {
            c.notes.push(format!(
                "{} walked as folders",
                counted(
                    self.directory_links,
                    "directory hard link was",
                    "directory hard links were"
                )
            ));
        }
        if self.broken_links > 0 {
            c.notes.push(format!(
                "{} to a missing indirect node",
                counted(self.broken_links, "link points", "links point")
            ));
        }
        if self.symlinks > 0 {
            c.notes.push(format!(
                "{} counted, not followed",
                counted(self.symlinks, "symbolic link was", "symbolic links were")
            ));
        }
        if self.special_files > 0 {
            c.notes.push(format!(
                "{} not read",
                counted(
                    self.special_files,
                    "device, FIFO or socket file was",
                    "device, FIFO or socket files were"
                )
            ));
        }
        if !self.compressed.is_empty() {
            let total = self.compressed.values().sum();
            let methods: Vec<String> = self
                .compressed
                .iter()
                .map(|(method, count)| format!("{method}: {count}"))
                .collect();
            c.notes.push(format!(
                "{} decoded for examination ({})",
                counted(
                    total,
                    "decmpfs-compressed file was",
                    "decmpfs-compressed files were"
                ),
                methods.join(", ")
            ));
        }
        for (compression_type, count) in &self.unsupported_compression {
            c.notes.push(format!(
                "{} decmpfs compression type {compression_type}, which is not implemented; not \
                 read",
                counted(*count, "file uses", "files use")
            ));
        }
        if self.too_deep > 0 {
            c.notes.push(format!(
                "{} not walked",
                counted(
                    self.too_deep,
                    &format!("folder deeper than {MAX_DEPTH} levels was"),
                    &format!("folders deeper than {MAX_DEPTH} levels were")
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
                counted(self.too_large, "file exceeds", "files exceed"),
                size_text(MAX_PAYLOAD)
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
                size_text(MAX_EXTRACTED)
            ));
        }
        if self.unwalked > 0 {
            c.notes.push(format!(
                "The walk stopped at the metadata read limit ({METADATA_READ_FACTOR} times {}); {} \
                 not walked",
                fs.vol.budget_basis(),
                counted(self.unwalked, "folder was", "folders were")
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
            "hfsplus_directory_count",
            "Folders walked",
            self.directories as u64,
        );
        c.push_metadata(
            "hfsplus_regular_file_count",
            "Regular files",
            self.files as u64,
        );
        c.push_metadata("hfsplus_member_count", "Members", self.members as u64);
    }
}

/// Notes on what the walk skipped because it lies past the end of a
/// truncated volume's input: B-tree nodes, by tree, and regular files.
fn absent_notes(fs: &Filesystem<'_>, absent_files: usize, c: &mut Container<'_>) {
    let present = fs.vol.present_text();
    let trees = [
        Some(&fs.catalog),
        fs.extents.as_ref(),
        fs.attributes.as_ref(),
    ];
    for tree in trees.into_iter().flatten() {
        let count = tree.absent_node_count();
        if count == 0 {
            continue;
        }
        let (verb, pronoun) = if count == 1 {
            ("lies", "its")
        } else {
            ("lie", "their")
        };
        let nodes = counted(
            count,
            &format!("node of the {}", tree.name()),
            &format!("nodes of the {}", tree.name()),
        );
        c.notes.push(format!(
            "{nodes} B-tree that the walk needed {verb} past the {present} present; {pronoun} \
             records were not read"
        ));
    }
    if absent_files > 0 {
        c.notes.push(format!(
            "{} not listed: file data, or B-tree records that locate it, lie partly or wholly \
             past the {present} present",
            counted(absent_files, "regular file was", "regular files were")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_use_singular_and_plural_forms() {
        assert_eq!(counted(1, "folder", "folders"), "1 folder");
        assert_eq!(counted(3, "folder", "folders"), "3 folders");
    }
}
