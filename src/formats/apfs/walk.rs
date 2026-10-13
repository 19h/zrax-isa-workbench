//! The volume walk: each volume superblock is found through the container
//! object map, its file-system tree through the volume object map, and its
//! directories are read from the root (inode 2, [REF] "Inode Numbers").
//! A directory's entries are its `APFS_TYPE_DIR_REC` records; a regular
//! file's inode, attributes and extents are the records of its object
//! identifier (extents of its `private_id`). Regular files that start with
//! a recognized format become members labeled `/<volume>/<path>`; decmpfs
//! files are decoded first. Encrypted volumes are listed as opaque, sealed
//! volumes and snapshots noted.

use super::btree::{Lookup, Tree};
use super::decmpfs::{self, Header, Storage, DECMPFS_HEADER_SIZE, UF_COMPRESSED};
use super::omap::Omap;
use super::records::{
    is_before, DirEntry, Extent, Inode, KeyHeader, Xattr, XattrData, APFS_TYPE_DIR_REC,
    APFS_TYPE_FILE_EXTENT, APFS_TYPE_INODE, APFS_TYPE_XATTR, DT_DIR, DT_LNK, DT_REG, DT_UNKNOWN,
    S_IFDIR, S_IFLNK, S_IFREG,
};
use super::volume::VolumeSuperblock;
use super::*;
use crate::formats::container::{self, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};

/// `ROOT_DIR_INO_NUM`.
const ROOT_DIR_INO_NUM: u64 = 2;

/// Deepest directory level below the root that the walk enters.
const MAX_DEPTH: usize = 64;

/// Bytes at the start of a file read to decide whether it is a recognized
/// format.
const RECOGNITION_PREFIX: usize = 4096;

/// Most regular files examined in one container.
const MAX_FILES_EXAMINED: usize = 1 << 16;

/// Most entries read from one directory, and most extents of one stream.
/// The bounds are ours.
const MAX_DIRECTORY_ENTRIES: usize = 1 << 18;
const MAX_STREAM_EXTENTS: usize = 1 << 16;

/// Problems reported one by one per volume; further ones are counted.
const MAX_PROBLEM_NOTES: usize = 16;

/// The transform of a file reassembled from several extents or holes.
const EXTENTS_TRANSFORM: &str = "APFS extents";

/// Totals over all volumes, and the limits they share.
#[derive(Debug, Default)]
struct Totals {
    directories: usize,
    files: usize,
    members: usize,
    /// Decoded bytes of the members listed.
    extracted: usize,
}

/// What one volume's walk found and left out, for the notes.
#[derive(Debug, Default)]
struct Census {
    directories: usize,
    files: usize,
    members: usize,
    repeated_links: usize,
    repeated_directories: usize,
    symlinks: usize,
    special_files: usize,
    compressed: BTreeMap<&'static str, usize>,
    unsupported_compression: BTreeMap<u32, usize>,
    too_deep: usize,
    unexamined: usize,
    too_large: usize,
    over_budget: usize,
    truncated_directories: usize,
    unwalked: usize,
    problems: Vec<String>,
    unlisted_problems: usize,
}

/// A directory waiting to be read.
struct Directory {
    id: u64,
    node: usize,
    depth: usize,
}

/// A walked directory's name and parent, from which paths are built when
/// they are needed. Node 0 is the root.
struct PathNode {
    parent: usize,
    name: String,
}

/// A stream's bytes and where its first stored run is.
struct StreamBytes<'a> {
    bytes: Cow<'a, [u8]>,
    /// The first extent that is not a hole, as read.
    first_run: Option<Run>,
    /// Whether the bytes are one stored run of the input.
    is_stored: bool,
}

/// One extent of a stream as read: stored bytes, or a hole of zeros.
enum Piece<'a> {
    Stored(&'a [u8]),
    Hole(usize),
}

/// The records of a regular file that the walk needs.
#[derive(Default)]
struct FileRecords<'a> {
    inode: Option<Inode>,
    decmpfs: Option<Xattr<'a>>,
    resource_fork: Option<Xattr<'a>>,
    /// Extents keyed by the file's own identifier.
    extents: Vec<Extent>,
}

/// One volume's file-system tree and how to resolve its nodes.
struct Filesystem<'v> {
    tree: Tree,
    /// The volume object map as of the volume's transaction.
    lookup: Option<Lookup<'v>>,
    /// Directory entry keys are hashed.
    hashed_names: bool,
}

struct Walker<'v, 'a> {
    disk: &'v Disk<'a>,
    fs: &'v Filesystem<'v>,
    /// `/<volume label>`, the prefix of every member label.
    root: String,
    nodes: Vec<PathNode>,
    visited_directories: HashSet<u64>,
    visited_files: HashSet<u64>,
    census: Census,
}

/// Walk every volume of the container and append the members to `c`.
/// Problems are reported in notes.
pub(super) fn walk<'a>(disk: &Disk<'a>, sb: &NxSuperblock, c: &mut Container<'a>) {
    let mut totals = Totals::default();
    match Omap::open(disk, sb.omap_oid) {
        Ok(omap) => walk_volumes(disk, sb, &omap, &mut totals, c),
        Err(e) => c.notes.push(format!(
            "Container object map at block 0x{:X} not read; no volume was read: {}",
            sb.omap_oid,
            message(e)
        )),
    }
    c.push_metadata(
        "apfs_directory_count",
        "Directories walked",
        totals.directories as u64,
    );
    c.push_metadata(
        "apfs_regular_file_count",
        "Regular files",
        totals.files as u64,
    );
    c.push_metadata("apfs_member_count", "Members", totals.members as u64);
}

/// Find each volume through the container object map `omap`, describe it,
/// and walk the readable ones. Encrypted volumes are listed as opaque
/// children after every volume's files.
fn walk_volumes<'a>(
    disk: &Disk<'a>,
    sb: &NxSuperblock,
    omap: &Omap,
    totals: &mut Totals,
    c: &mut Container<'a>,
) {
    let mut opaque = Vec::new();
    let mut labels: Vec<String> = Vec::new();
    for (slot, &oid) in sb.fs_oids.iter().enumerate() {
        if oid == 0 {
            continue;
        }
        let volume = match omap
            .resolve(disk, oid, sb.xid)
            .and_then(|paddr| VolumeSuperblock::read(disk, paddr, oid))
        {
            Ok(volume) => volume,
            Err(e) => {
                c.notes.push(format!(
                    "Volume {slot} (object 0x{oid:X}) not read: {}",
                    message(e)
                ));
                continue;
            }
        };
        let label = volume_label(&volume, slot, &labels);
        labels.push(label.clone());
        describe_volume(&volume, slot, &label, c);
        if volume.is_encrypted() {
            c.notes.push(format!(
                "/{label}: encrypted (APFS_FS_UNENCRYPTED clear); its file-system tree and file \
                 contents are opaque and were not read"
            ));
            opaque.push(encrypted_volume(disk, &volume, &label));
            continue;
        }
        if let Some(reason) = unreadable_reason(&volume) {
            c.notes.push(format!("/{label}: {reason}"));
            continue;
        }
        if let Err(e) = walk_volume(disk, &volume, &label, totals, c) {
            c.notes.push(format!(
                "/{label}: file-system tree not read: {}",
                message(e)
            ));
        }
    }
    c.children.extend(opaque.into_iter().flatten());
}

/// The volume's path prefix: its name, or `volume <slot>` without one; a
/// name already used gains ` (volume <slot>)`.
fn volume_label(volume: &VolumeSuperblock, slot: usize, used: &[String]) -> String {
    let name = if volume.name.is_empty() {
        format!("volume {slot}")
    } else {
        volume.name.clone()
    };
    if used.contains(&name) {
        format!("{name} (volume {slot})")
    } else {
        name
    }
}

/// The note and metadata for the volume in `nx_fs_oid` slot `slot`.
fn describe_volume(volume: &VolumeSuperblock, slot: usize, label: &str, c: &mut Container<'_>) {
    c.notes.push(format!(
        "Volume /{label} (index {}): role {}, {} names, {}",
        volume.fs_index,
        volume.role_text(),
        volume.case_text(),
        volume.counts_text()
    ));
    if volume.snapshots() > 0 {
        c.notes.push(format!(
            "/{label}: {}; snapshot contents are not read",
            counted(
                usize::try_from(volume.snapshots()).unwrap_or(usize::MAX),
                "snapshot",
                "snapshots"
            )
        ));
    }
    let state = if volume.is_encrypted() {
        "encrypted"
    } else if volume.is_sealed() {
        "sealed"
    } else {
        "readable"
    };
    c.push_metadata(
        format!("apfs_volume_{slot}"),
        format!("Volume {slot}"),
        format!(
            "\"{}\"; role {}; {}; {}",
            volume.name,
            volume.role_text(),
            volume.case_text(),
            state
        ),
    );
}

/// Why the walk does not read `volume`, or `None` when it does.
fn unreadable_reason(volume: &VolumeSuperblock) -> Option<String> {
    if volume.is_sealed() {
        return Some(
            "sealed volume (APFS_INCOMPAT_SEALED_VOLUME): its integrity metadata and file \
             extent tree are not read, so its files are not listed"
                .into(),
        );
    }
    let unknown = volume.unknown_incompatible();
    (unknown != 0).then(|| format!("unknown incompatible volume features 0x{unknown:X}; not read"))
}

/// An encrypted volume as an opaque child: its superblock block.
fn encrypted_volume<'a>(
    disk: &Disk<'a>,
    volume: &VolumeSuperblock,
    label: &str,
) -> Option<Child<'a>> {
    let block = disk.blocks(volume.paddr, 1).ok()?;
    Some(Child::opaque(
        format!("/{label}"),
        disk.file_offset(volume.paddr),
        block,
    ))
}

/// Open the volume's object map and file-system tree and walk it.
fn walk_volume<'a>(
    disk: &Disk<'a>,
    volume: &VolumeSuperblock,
    label: &str,
    totals: &mut Totals,
    c: &mut Container<'a>,
) -> Result<()> {
    let omap = Omap::open(disk, volume.omap_oid)?;
    let root_lookup = Lookup {
        omap: &omap,
        xid: volume.xid,
    };
    let root = (!volume.has_physical_root()).then_some(root_lookup);
    let tree = Tree::open(disk, volume.root_tree_oid, OBJECT_TYPE_FSTREE, root)?;
    c.notes.push(format!(
        "/{label}: file-system tree of {} in {}, {}",
        counted(
            usize::try_from(tree.info.key_count).unwrap_or(usize::MAX),
            "record",
            "records"
        ),
        counted(
            usize::try_from(tree.info.node_count).unwrap_or(usize::MAX),
            "node",
            "nodes"
        ),
        counted(usize::from(tree.levels) + 1, "level", "levels")
    ));
    if omap.snapshot_count > 0 {
        c.notes.push(format!(
            "/{label}: the volume object map records {}; snapshot contents are not read",
            counted(omap.snapshot_count as usize, "snapshot", "snapshots")
        ));
    }
    let fs = Filesystem {
        tree,
        lookup: Some(root_lookup),
        hashed_names: volume.has_hashed_names(),
    };
    let mut walker = Walker {
        disk,
        fs: &fs,
        root: format!("/{label}"),
        nodes: vec![PathNode {
            parent: 0,
            name: String::new(),
        }],
        visited_directories: HashSet::from([ROOT_DIR_INO_NUM]),
        visited_files: HashSet::new(),
        census: Census::default(),
    };
    walker.run(totals, c);
    walker.census.report(&walker.root, c);
    Ok(())
}

impl<'a> Walker<'_, 'a> {
    /// Walk the directories depth first from the root.
    fn run(&mut self, totals: &mut Totals, c: &mut Container<'a>) {
        let mut pending = vec![Directory {
            id: ROOT_DIR_INO_NUM,
            node: 0,
            depth: 0,
        }];
        while let Some(directory) = pending.pop() {
            if self.disk.is_exhausted() {
                self.census.unwalked = pending.len() + 1;
                break;
            }
            let subdirectories = self.directory(&directory, totals, c);
            // Reversed, so that subdirectories are walked in name order.
            pending.extend(subdirectories.into_iter().rev());
        }
        totals.directories += self.census.directories;
        totals.files += self.census.files;
    }

    /// The path of `name` in the directory at `node`, from the volume root.
    fn path(&self, node: usize, name: &str) -> String {
        let mut parts = Vec::new();
        if !name.is_empty() {
            parts.push(name.to_string());
        }
        let mut current = node;
        // Parents precede their children in `nodes`, so this ends at 0.
        while current != 0 {
            parts.push(self.nodes[current].name.clone());
            current = self.nodes[current].parent;
        }
        parts.reverse();
        format!("{}/{}", self.root, parts.join("/"))
    }

    /// Record a problem, unless the read limit caused it (noted once).
    fn problem(&mut self, path: &str, e: ClassifierError) {
        if self.disk.is_exhausted() {
            return;
        }
        if self.census.problems.len() < MAX_PROBLEM_NOTES {
            self.census
                .problems
                .push(format!("Skipped {path}: {}", message(e)));
        } else {
            self.census.unlisted_problems += 1;
        }
    }

    /// Read one directory, list its regular files and return its
    /// subdirectories in name order.
    fn directory(
        &mut self,
        directory: &Directory,
        totals: &mut Totals,
        c: &mut Container<'a>,
    ) -> Vec<Directory> {
        self.census.directories += 1;
        let mut subdirectories = Vec::new();
        let mut entries = match self.directory_entries(directory.id) {
            Ok(entries) => entries,
            Err(e) => {
                let path = self.path(directory.node, "");
                self.problem(&path, e);
                return subdirectories;
            }
        };
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for entry in entries {
            match self.entry_type(&entry) {
                Ok(DT_DIR) => self.subdirectory(directory, entry, &mut subdirectories),
                Ok(DT_REG) => self.file_entry(directory, &entry, totals, c),
                Ok(DT_LNK) => self.census.symlinks += 1,
                Ok(_) => self.census.special_files += 1,
                Err(e) => {
                    let path = self.path(directory.node, &entry.name);
                    self.problem(&path, e);
                }
            }
        }
        subdirectories
    }

    /// The `DT_*` type of an entry; an entry of unknown type takes it from
    /// its inode's mode.
    fn entry_type(&self, entry: &DirEntry) -> Result<u8> {
        if entry.file_type != DT_UNKNOWN {
            return Ok(entry.file_type);
        }
        let inode = self
            .file_records(entry.file_id)?
            .inode
            .ok_or_else(|| error(format!("Missing inode 0x{:X}", entry.file_id)))?;
        Ok(match inode.file_type() {
            S_IFDIR => DT_DIR,
            S_IFREG => DT_REG,
            S_IFLNK => DT_LNK,
            _ => DT_UNKNOWN,
        })
    }

    /// The directory entries of directory `id`, up to
    /// [`MAX_DIRECTORY_ENTRIES`].
    fn directory_entries(&mut self, id: u64) -> Result<Vec<DirEntry>> {
        let fs = self.fs;
        let seek = |key: &[u8]| is_before(key, id, APFS_TYPE_DIR_REC);
        let mut cursor = fs.tree.seek(self.disk, fs.lookup, &seek)?;
        let mut entries = Vec::new();
        while let Some(record) = cursor.next(&fs.tree, self.disk, fs.lookup)? {
            let header = KeyHeader::parse(record.key)?;
            if header.oid != id || header.kind != APFS_TYPE_DIR_REC {
                break;
            }
            if entries.len() >= MAX_DIRECTORY_ENTRIES {
                self.census.truncated_directories += 1;
                break;
            }
            let value = record
                .value
                .ok_or_else(|| error("Invalid directory entry without a value"))?;
            entries.push(DirEntry::parse(record.key, value, fs.hashed_names)?);
        }
        Ok(entries)
    }

    /// Queue a subdirectory once; one reached again is counted.
    fn subdirectory(
        &mut self,
        directory: &Directory,
        entry: DirEntry,
        subdirectories: &mut Vec<Directory>,
    ) {
        if directory.depth >= MAX_DEPTH {
            self.census.too_deep += 1;
            return;
        }
        if !self.visited_directories.insert(entry.file_id) {
            self.census.repeated_directories += 1;
            return;
        }
        self.nodes.push(PathNode {
            parent: directory.node,
            name: entry.name,
        });
        subdirectories.push(Directory {
            id: entry.file_id,
            node: self.nodes.len() - 1,
            depth: directory.depth + 1,
        });
    }

    /// A regular file entry: examined once per inode (hard links share it).
    fn file_entry(
        &mut self,
        directory: &Directory,
        entry: &DirEntry,
        totals: &mut Totals,
        c: &mut Container<'a>,
    ) {
        if !self.visited_files.insert(entry.file_id) {
            self.census.repeated_links += 1;
            return;
        }
        self.census.files += 1;
        let examined = totals.files + self.census.files;
        if c.children.len() >= MAX_COMPONENTS || examined > MAX_FILES_EXAMINED {
            self.census.unexamined += 1;
            return;
        }
        let path = self.path(directory.node, &entry.name);
        match self.member(entry.file_id, &path, totals) {
            Ok(Some(child)) => {
                totals.extracted += child.data.len();
                totals.members += 1;
                self.census.members += 1;
                c.children.push(child.if_recognized());
            }
            Ok(None) => {}
            Err(e) => self.problem(&path, e),
        }
    }

    /// The records of object `id` from its inode to its file extents.
    fn file_records(&self, id: u64) -> Result<FileRecords<'a>> {
        let fs = self.fs;
        let seek = |key: &[u8]| is_before(key, id, APFS_TYPE_INODE);
        let mut cursor = fs.tree.seek(self.disk, fs.lookup, &seek)?;
        let mut found = FileRecords::default();
        while let Some(record) = cursor.next(&fs.tree, self.disk, fs.lookup)? {
            let header = KeyHeader::parse(record.key)?;
            if header.oid != id || header.kind > APFS_TYPE_FILE_EXTENT {
                break;
            }
            let Some(value) = record.value else {
                continue;
            };
            match header.kind {
                APFS_TYPE_INODE => found.inode = Some(Inode::parse(value)?),
                APFS_TYPE_XATTR => {
                    let xattr = Xattr::parse(record.key, value, record.value_offset)?;
                    if xattr.name == decmpfs::DECMPFS_XATTR_NAME {
                        found.decmpfs = Some(xattr);
                    } else if xattr.name == decmpfs::RESOURCE_FORK_XATTR_NAME {
                        found.resource_fork = Some(xattr);
                    }
                }
                APFS_TYPE_FILE_EXTENT => {
                    if found.extents.len() >= MAX_STREAM_EXTENTS {
                        return Err(error(format!(
                            "Unsupported data stream of more than {MAX_STREAM_EXTENTS} extents"
                        )));
                    }
                    found.extents.push(Extent::parse(record.key, value)?);
                }
                _ => {}
            }
        }
        Ok(found)
    }

    /// The extents of data stream `id` that start before `length`.
    fn stream_extents(&self, id: u64, length: usize) -> Result<Vec<Extent>> {
        let fs = self.fs;
        let seek = |key: &[u8]| is_before(key, id, APFS_TYPE_FILE_EXTENT);
        let mut cursor = fs.tree.seek(self.disk, fs.lookup, &seek)?;
        let mut extents = Vec::new();
        while let Some(record) = cursor.next(&fs.tree, self.disk, fs.lookup)? {
            let header = KeyHeader::parse(record.key)?;
            if header.oid != id || header.kind != APFS_TYPE_FILE_EXTENT {
                break;
            }
            let Some(value) = record.value else {
                continue;
            };
            let extent = Extent::parse(record.key, value)?;
            if extent.logical >= length as u64 {
                break;
            }
            if extents.len() >= MAX_STREAM_EXTENTS {
                return Err(error(format!(
                    "Unsupported data stream of more than {MAX_STREAM_EXTENTS} extents"
                )));
            }
            extents.push(extent);
        }
        Ok(extents)
    }

    /// The first `length` bytes of a stream with `extents` (in logical
    /// order). The extents must cover them without a gap; a hole extent
    /// (block 0) reads as zeros.
    fn read_stream(&self, extents: &[Extent], length: usize) -> Result<StreamBytes<'a>> {
        let disk = self.disk;
        let block_size = disk.block_size();
        if let Some(first) = extents.first() {
            if first.logical == 0 && first.block != 0 && first.length >= length as u64 {
                let stored = disk.blocks(first.block, blocks_for(length, block_size))?;
                return Ok(StreamBytes {
                    bytes: Cow::Borrowed(&stored[..length]),
                    first_run: Some(Run {
                        offset: disk.file_offset(first.block),
                        size: length,
                    }),
                    is_stored: true,
                });
            }
        }
        // Every extent is located (and its blocks found present) before
        // anything is allocated for the stream.
        let mut pieces = Vec::new();
        let mut covered = 0usize;
        let mut first_run = None;
        for extent in extents {
            if covered >= length {
                break;
            }
            if extent.logical != covered as u64 {
                return Err(error(format!(
                    "Invalid file extents: an extent at 0x{:X} where 0x{covered:X} was expected",
                    extent.logical
                )));
            }
            let take = usize::try_from(extent.length)
                .unwrap_or(usize::MAX)
                .min(length - covered);
            covered += take;
            if extent.block == 0 {
                pieces.push(Piece::Hole(take));
                continue;
            }
            let stored = disk.blocks(extent.block, blocks_for(take, block_size))?;
            if first_run.is_none() {
                first_run = Some(Run {
                    offset: disk.file_offset(extent.block),
                    size: take,
                });
            }
            pieces.push(Piece::Stored(&stored[..take]));
        }
        if covered < length {
            return Err(error(format!(
                "Invalid file extents: they cover {} of {}",
                size_text(covered),
                size_text(length)
            )));
        }
        let mut bytes = Vec::with_capacity(length);
        for piece in pieces {
            match piece {
                Piece::Stored(stored) => bytes.extend_from_slice(stored),
                Piece::Hole(size) => bytes.resize(bytes.len() + size, 0),
            }
        }
        Ok(StreamBytes {
            bytes: Cow::Owned(bytes),
            first_run,
            is_stored: false,
        })
    }

    /// The bytes of an attribute: embedded in its record, or the first
    /// `limit` bytes of its data stream (at most its size).
    fn attribute(&self, xattr: &Xattr<'a>, limit: usize) -> Result<StreamBytes<'a>> {
        match xattr.data {
            XattrData::Embedded { bytes, offset } => Ok(StreamBytes {
                bytes: Cow::Borrowed(bytes),
                first_run: Some(Run {
                    offset,
                    size: bytes.len(),
                }),
                is_stored: true,
            }),
            XattrData::Stream { id, size } => {
                let length = usize::try_from(size).unwrap_or(usize::MAX).min(limit);
                let extents = self.stream_extents(id, length)?;
                self.read_stream(&extents, length)
            }
        }
    }

    /// Whether a recognized file of `size` decoded bytes may be extracted;
    /// counts the ones that may not.
    fn may_extract(&mut self, size: usize, totals: &Totals) -> bool {
        if size > MAX_PAYLOAD {
            self.census.too_large += 1;
            false
        } else if totals.extracted + size > MAX_EXTRACTED {
            self.census.over_budget += 1;
            false
        } else {
            true
        }
    }

    /// The member for regular file `id`, when it is a recognized format and
    /// the limits allow its extraction.
    fn member(&mut self, id: u64, path: &str, totals: &Totals) -> Result<Option<Child<'a>>> {
        let records = self.file_records(id)?;
        let inode = records
            .inode
            .ok_or_else(|| error(format!("Missing inode 0x{id:X}")))?;
        if inode.bsd_flags & UF_COMPRESSED != 0 {
            return self.compressed_file(&records, path, totals);
        }
        let Some(size) = usize::try_from(inode.size).ok().filter(|&size| size > 0) else {
            return Ok(None);
        };
        let extents = if inode.private_id == id {
            records.extents
        } else {
            self.stream_extents(inode.private_id, size.min(MAX_PAYLOAD))?
        };
        let prefix = self.read_stream(&extents, size.min(RECOGNITION_PREFIX))?;
        if !container::is_recognized(&prefix.bytes) || !self.may_extract(size, totals) {
            return Ok(None);
        }
        let contents = if size == prefix.bytes.len() {
            prefix
        } else {
            self.read_stream(&extents, size)?
        };
        Ok(Some(stream_member(path, contents)))
    }

    /// A decmpfs file: its header in the `com.apple.decmpfs` attribute, its
    /// data after the header or in the `com.apple.ResourceFork` attribute.
    fn compressed_file(
        &mut self,
        records: &FileRecords<'a>,
        path: &str,
        totals: &Totals,
    ) -> Result<Option<Child<'a>>> {
        let xattr = records.decmpfs.ok_or_else(|| {
            error("Missing com.apple.decmpfs attribute of a compressed file (UF_COMPRESSED)")
        })?;
        let attribute = self.attribute(&xattr, MAX_PAYLOAD)?;
        let header = Header::parse(&attribute.bytes)?;
        let Some(method) = header.method() else {
            *self
                .census
                .unsupported_compression
                .entry(header.compression_type)
                .or_default() += 1;
            return Ok(None);
        };
        *self
            .census
            .compressed
            .entry(method.compression.name())
            .or_default() += 1;
        let Some(size) = usize::try_from(header.size).ok().filter(|&size| size > 0) else {
            return Ok(None);
        };
        if size > MAX_PAYLOAD {
            self.census.too_large += 1;
            return Ok(None);
        }
        let transform = method.compression.transform();
        match method.storage {
            Storage::Attribute => {
                let decoded =
                    decmpfs::decode_attribute(method.compression, &attribute.bytes, size)?;
                let prefix = &decoded[..decoded.len().min(RECOGNITION_PREFIX)];
                if !container::is_recognized(prefix) || !self.may_extract(size, totals) {
                    return Ok(None);
                }
                let run = attribute
                    .first_run
                    .filter(|run| run.size >= DECMPFS_HEADER_SIZE)
                    .ok_or_else(|| error("Invalid com.apple.decmpfs attribute location"))?;
                Ok(Some(Child::decoded(
                    path,
                    run.offset + DECMPFS_HEADER_SIZE,
                    attribute.bytes.len() - DECMPFS_HEADER_SIZE,
                    Cow::Owned(decoded),
                    transform,
                )))
            }
            Storage::ResourceFork => {
                let fork_xattr = records.resource_fork.ok_or_else(|| {
                    error(format!(
                        "Missing com.apple.ResourceFork attribute of a decmpfs type {} file",
                        header.compression_type
                    ))
                })?;
                let fork = self.attribute(&fork_xattr, MAX_PAYLOAD)?;
                let prefix = decmpfs::decode_resource_fork(
                    method.compression,
                    &fork.bytes,
                    size,
                    RECOGNITION_PREFIX,
                )?;
                let prefix = &prefix[..prefix.len().min(RECOGNITION_PREFIX)];
                if !container::is_recognized(prefix) || !self.may_extract(size, totals) {
                    return Ok(None);
                }
                let decoded =
                    decmpfs::decode_resource_fork(method.compression, &fork.bytes, size, size)?;
                let run = fork
                    .first_run
                    .ok_or_else(|| error("Invalid com.apple.ResourceFork attribute location"))?;
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

/// A member for a file's stream: stored when it is one run of the input,
/// otherwise decoded from the reassembled extents.
fn stream_member<'a>(path: &str, contents: StreamBytes<'a>) -> Child<'a> {
    let run = contents.first_run.unwrap_or(Run { offset: 0, size: 0 });
    match contents.bytes {
        Cow::Borrowed(bytes) if contents.is_stored => Child::stored(path, run.offset, bytes),
        bytes => Child::decoded(path, run.offset, run.size, bytes, EXTENTS_TRANSFORM),
    }
}

impl Census {
    /// Notes for one volume: what was walked, then what was left out and
    /// why. `root` is `/<volume label>`.
    fn report(&self, root: &str, c: &mut Container<'_>) {
        c.notes.push(format!(
            "{root}: walked {}, {}; members in a recognized format: {}",
            counted(self.directories, "directory", "directories"),
            counted(self.files, "regular file", "regular files"),
            self.members
        ));
        let mut left_out = Vec::new();
        if self.repeated_links > 0 {
            left_out.push(format!(
                "{} to a file already examined",
                counted(
                    self.repeated_links,
                    "further hard link was skipped as it leads",
                    "further hard links were skipped as they lead"
                )
            ));
        }
        if self.repeated_directories > 0 {
            left_out.push(format!(
                "{} not walked again",
                counted(
                    self.repeated_directories,
                    "directory reached a second time was",
                    "directories reached a second time were"
                )
            ));
        }
        if self.symlinks > 0 {
            left_out.push(format!(
                "{} counted, not followed",
                counted(self.symlinks, "symbolic link was", "symbolic links were")
            ));
        }
        if self.special_files > 0 {
            left_out.push(format!(
                "{} not read",
                counted(
                    self.special_files,
                    "device, FIFO, socket or whiteout entry was",
                    "device, FIFO, socket or whiteout entries were"
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
            left_out.push(format!(
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
            left_out.push(format!(
                "{} decmpfs compression type 0x{compression_type:X}, which is not implemented; \
                 not read",
                counted(*count, "file uses", "files use")
            ));
        }
        if self.too_deep > 0 {
            left_out.push(format!(
                "{} not walked",
                counted(
                    self.too_deep,
                    &format!("directory deeper than {MAX_DEPTH} levels was"),
                    &format!("directories deeper than {MAX_DEPTH} levels were")
                )
            ));
        }
        if self.truncated_directories > 0 {
            left_out.push(format!(
                "{} more than {MAX_DIRECTORY_ENTRIES} entries; the rest were not read",
                counted(
                    self.truncated_directories,
                    "directory has",
                    "directories have"
                )
            ));
        }
        if self.unexamined > 0 {
            left_out.push(format!(
                "{} not examined: at most {MAX_COMPONENTS} members are listed and \
                 {MAX_FILES_EXAMINED} files examined",
                counted(self.unexamined, "regular file was", "regular files were")
            ));
        }
        if self.too_large > 0 {
            left_out.push(format!(
                "{} the {} extraction limit; not extracted",
                counted(self.too_large, "file exceeds", "files exceed"),
                size_text(MAX_PAYLOAD)
            ));
        }
        if self.over_budget > 0 {
            left_out.push(format!(
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
            left_out.push(format!(
                "the walk stopped at the object read limit ({METADATA_READ_FACTOR} times the \
                 blocks present); {} not walked",
                counted(self.unwalked, "directory was", "directories were")
            ));
        }
        c.notes
            .extend(left_out.into_iter().map(|text| format!("{root}: {text}")));
        c.notes
            .extend(self.problems.iter().map(|text| format!("{root}: {text}")));
        if self.unlisted_problems > 0 {
            c.notes.push(format!(
                "{root}: {} not listed",
                counted(
                    self.unlisted_problems,
                    "further problem was",
                    "further problems were"
                )
            ));
        }
    }
}
