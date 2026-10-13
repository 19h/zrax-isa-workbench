//! The directory walk. The hierarchy that supplies the names is chosen as
//! Linux `isofs_fill_super` and libarchive `choose_volume` choose it: the
//! primary hierarchy with Rock Ridge names when the root carries Rock Ridge,
//! otherwise the Joliet hierarchy, otherwise the primary hierarchy with ISO
//! 9660 identifiers. Directories are visited once by their extent, so
//! repeated or cyclic records cannot loop; regular files that start with a
//! recognized format become members labeled by their path.

use super::descriptors::{DescriptorSet, Volume, ROOT_RECORD_OFFSET};
use super::directory::{self, Record};
use super::susp::{self, AlternateName, Attributes, Encoding, RockRidge};
use super::*;
use crate::formats::container::{self, Child, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

/// Most directories walked in one image.
const MAX_DIRECTORIES: usize = 1 << 16;

/// Problems reported one by one; further ones are counted.
const MAX_PROBLEM_NOTES: usize = 16;

/// Most file sections of one file. A file of [`MAX_PAYLOAD`] bytes needs
/// one; files of more than 4 GiB need two or more (each section holds less
/// than 4 GiB, ECMA-119 9.1.4).
const MAX_FILE_SECTIONS: usize = 1024;

/// Transform named for a file whose sections are not stored contiguously
/// and were reassembled.
const SECTIONS_TRANSFORM: &str = "ISO 9660 file sections";

/// Where the names of the walked hierarchy come from.
#[derive(Debug)]
pub(super) enum Names {
    /// ISO 9660 file identifiers of the primary hierarchy.
    Iso,
    /// The Joliet hierarchy, in UCS-2.
    Joliet,
    /// Rock Ridge `NM` entries of the primary hierarchy.
    RockRidge(RockRidge),
}

impl Names {
    /// Short name for the metadata.
    pub(super) fn label(&self) -> &'static str {
        match self {
            Self::Iso => "ISO 9660 identifiers",
            Self::Joliet => "Joliet",
            Self::RockRidge(_) => "Rock Ridge",
        }
    }

    /// Description for the notes.
    pub(super) fn description(&self) -> String {
        match self {
            Self::Iso => "ISO 9660 file identifiers (version numbers removed)".to_string(),
            Self::Joliet => "the Joliet hierarchy (UCS-2)".to_string(),
            Self::RockRidge(rock) => format!("Rock Ridge NM entries ({})", rock.evidence),
        }
    }
}

/// The hierarchy that is walked.
pub(super) struct Tree<'a> {
    image: Image<'a>,
    /// Logical block size in bytes.
    block_size: usize,
    /// File offset and size in bytes of the root directory.
    root: (usize, usize),
    pub(super) names: Names,
    /// Why a Joliet hierarchy was not used although Rock Ridge was absent.
    pub(super) joliet_unusable: Option<String>,
}

/// File offset and size of a directory's extent, checked against the
/// volume. A directory holds at least its `.` and `..` records.
fn directory_extent(
    image: Image<'_>,
    offset: Option<usize>,
    size: u32,
) -> std::result::Result<(usize, usize), String> {
    let size = size as usize;
    let Some(offset) = offset.filter(|&offset| image.holds(offset, size)) else {
        return Err(format!("extent of {size} B lies outside the volume"));
    };
    if size == 0 {
        return Err("empty directory extent".to_string());
    }
    Ok((offset, size))
}

/// Whether the first sector of a directory's extent, which holds its `.`
/// record, is present.
fn has_first_sector(image: Image<'_>, offset: usize, size: usize) -> bool {
    image.present(offset, size.min(SECTOR_SIZE)).is_some()
}

impl<'a> Tree<'a> {
    /// Choose the hierarchy and its name source. `None` when the root
    /// directory that supplies the names, or the continuation of the
    /// primary root's Rock Ridge entries, lies past the end of a truncated
    /// volume's input.
    ///
    /// # Errors
    ///
    /// The primary root directory lies outside the volume.
    pub(super) fn choose(image: Image<'a>, set: &DescriptorSet) -> Result<Option<Self>> {
        let primary = &set.primary;
        let root =
            directory_extent(image, primary.root_offset, primary.root_size).map_err(|reason| {
                error(format!(
                    "Invalid root directory record at 0x{:X}: {reason}",
                    primary.offset + ROOT_RECORD_OFFSET
                ))
            })?;
        if !has_first_sector(image, root.0, root.1) {
            return Ok(None);
        }
        let mut tree = Self {
            image,
            block_size: primary.block_size,
            root,
            names: Names::Iso,
            joliet_unusable: None,
        };
        // The root's `.` record carries the SUSP `SP` and `ER` entries.
        let dot = directory::records(image.bytes, root.0, root.1.min(SECTOR_SIZE))
            .next()
            .and_then(std::result::Result::ok)
            .filter(Record::is_self);
        let rock = match dot.map(|dot| susp::rock_ridge(image, primary.block_size, &dot)) {
            Some(Ok(rock)) => rock,
            // A continuation area past the end of the input: whether the
            // hierarchy carries Rock Ridge names is unknown.
            Some(Err(_)) => return Ok(None),
            None => None,
        };
        if let Some(rock) = rock {
            tree.names = Names::RockRidge(rock);
            return Ok(Some(tree));
        }
        if let Some(joliet) = &set.joliet {
            match joliet_root(image, &joliet.volume) {
                Ok(root) if !has_first_sector(image, root.0, root.1) => return Ok(None),
                Ok(root) => {
                    tree.root = root;
                    tree.names = Names::Joliet;
                }
                Err(reason) => tree.joliet_unusable = Some(reason),
            }
        }
        Ok(Some(tree))
    }

    /// The volume's bytes.
    pub(super) fn image(&self) -> Image<'a> {
        self.image
    }
}

/// The Joliet hierarchy's root directory.
fn joliet_root(image: Image<'_>, volume: &Volume) -> std::result::Result<(usize, usize), String> {
    directory_extent(image, volume.root_offset, volume.root_size).map_err(|reason| {
        format!(
            "its root directory record at 0x{:X}: {reason}",
            volume.offset + ROOT_RECORD_OFFSET
        )
    })
}

/// A regular file whose data an El Torito entry loads.
#[derive(Debug)]
pub(super) struct BootFile {
    pub(super) path: String,
    /// File size in bytes.
    pub(super) size: usize,
}

/// A directory waiting to be read.
struct PendingDirectory {
    offset: usize,
    size: usize,
    node: usize,
    depth: usize,
}

/// A walked directory's name and parent, from which paths are built. Node
/// 0 is the root.
struct PathNode {
    parent: usize,
    name: String,
}

/// What the walk found and left out, for the notes.
#[derive(Debug, Default)]
struct Census {
    directories: usize,
    files: usize,
    special: usize,
    associated: usize,
    interleaved: usize,
    compressed: usize,
    sparse: usize,
    relocated: usize,
    repeated: usize,
    unwalked: usize,
    over_walk_limit: usize,
    over_component_limit: usize,
    over_budget: usize,
    too_large: usize,
    byte_order_mismatches: usize,
    /// Entries of a Rock Ridge hierarchy without an `NM` entry.
    without_alternate_name: usize,
    /// Directories whose extent lies partly or wholly past the end of a
    /// truncated volume's input.
    absent_directories: usize,
    /// Directory records whose Rock Ridge entries continue past the end of
    /// a truncated volume's input.
    absent_records: usize,
    /// Regular files whose data lies partly or wholly past the end of a
    /// truncated volume's input.
    absent_files: usize,
    problems: Vec<String>,
    unlisted_problems: usize,
}

/// The result of a walk.
pub(super) struct Walked<'a> {
    members: Vec<Child<'a>>,
    /// Files whose data an El Torito entry loads, by file offset. They are
    /// listed as boot images, not as members.
    pub(super) boot_files: HashMap<usize, BootFile>,
    census: Census,
    /// The volume's bytes, for the notes on a truncated volume.
    image: Image<'a>,
}

struct Walker<'t, 'a> {
    tree: &'t Tree<'a>,
    /// File offsets of the El Torito boot images.
    boot_offsets: &'t [usize],
    nodes: Vec<PathNode>,
    /// File offsets of the directories walked or pending.
    visited: HashSet<usize>,
    census: Census,
    members: Vec<Child<'a>>,
    boot_files: HashMap<usize, BootFile>,
    /// Bytes probed and listed, bounded by [`MAX_EXTRACTED`].
    extracted: usize,
    /// Directory bytes the walk may still read: twice the volume size, so
    /// overlapping directory extents cannot make the walk quadratic.
    directory_budget: usize,
}

/// Walk the hierarchy from the root.
pub(super) fn walk<'a>(tree: &Tree<'a>, boot_offsets: &[usize]) -> Walked<'a> {
    let mut walker = Walker {
        tree,
        boot_offsets,
        nodes: vec![PathNode {
            parent: 0,
            name: String::new(),
        }],
        visited: HashSet::from([tree.root.0]),
        census: Census::default(),
        members: Vec::new(),
        boot_files: HashMap::new(),
        extracted: 0,
        directory_budget: tree.image.bytes.len().saturating_mul(2),
    };
    let mut pending = vec![PendingDirectory {
        offset: tree.root.0,
        size: tree.root.1,
        node: 0,
        depth: 0,
    }];
    while let Some(directory) = pending.pop() {
        let present = present_size(tree.image, &directory);
        if walker.census.directories >= MAX_DIRECTORIES || present > walker.directory_budget {
            walker.census.over_walk_limit = pending.len() + 1;
            break;
        }
        walker.directory_budget -= present;
        if present < directory.size {
            walker.census.absent_directories += 1;
        }
        let subdirectories = walker.directory(&directory, present);
        // Reversed, so that subdirectories are walked in record order.
        pending.extend(subdirectories.into_iter().rev());
    }
    Walked {
        members: walker.members,
        boot_files: walker.boot_files,
        census: walker.census,
        image: tree.image,
    }
}

/// The bytes of a directory's extent to read: all of them, or, when a
/// truncated volume's input ends inside the extent, its whole sectors
/// before the end. A record never crosses a sector (6.8.1.1), so no record
/// is cut.
fn present_size(image: Image<'_>, directory: &PendingDirectory) -> usize {
    let available = image.bytes.len().saturating_sub(directory.offset);
    if directory.size <= available {
        directory.size
    } else {
        available - available % SECTOR_SIZE
    }
}

impl<'a> Walker<'_, 'a> {
    /// The path of the directory at `node`, extended by `name`.
    fn path(&self, node: usize, name: Option<&str>) -> String {
        let mut parts: Vec<&str> = name.into_iter().collect();
        let mut current = node;
        // Parents precede their children in `nodes`, so this ends at the root.
        while current != 0 {
            parts.push(&self.nodes[current].name);
            current = self.nodes[current].parent;
        }
        parts.reverse();
        format!("/{}", parts.join("/"))
    }

    fn problem(&mut self, text: String) {
        if self.census.problems.len() < MAX_PROBLEM_NOTES {
            self.census.problems.push(text);
        } else {
            self.census.unlisted_problems += 1;
        }
    }

    /// Account for `size` more probed or listed bytes, or refuse once
    /// [`MAX_EXTRACTED`] would pass.
    fn charge(&mut self, size: usize) -> bool {
        match self.extracted.checked_add(size) {
            Some(total) if total <= MAX_EXTRACTED => {
                self.extracted = total;
                true
            }
            _ => false,
        }
    }

    /// Read the first `size` bytes of one directory's extent (see
    /// [`present_size`]) and return its subdirectories in record order.
    /// Consecutive records of a multi-extent file are collected into one
    /// file (ECMA-119 6.5.1, 9.1.6 bit 7).
    fn directory(&mut self, directory: &PendingDirectory, size: usize) -> Vec<PendingDirectory> {
        self.census.directories += 1;
        let mut subdirectories = Vec::new();
        let mut sections: Vec<Record<'a>> = Vec::new();
        for record in directory::records(self.tree.image.bytes, directory.offset, size) {
            let record = match record {
                Ok(record) => record,
                Err(defect) => {
                    let path = self.path(directory.node, None);
                    self.problem(format!(
                        "{path}: {defect}; the rest of the directory is not read"
                    ));
                    break;
                }
            };
            if record.is_self_or_parent() {
                continue;
            }
            self.census.byte_order_mismatches += usize::from(record.byte_orders_differ);
            if record.is_associated() {
                self.census.associated += 1;
                continue;
            }
            if sections
                .first()
                .is_some_and(|first| first.identifier != record.identifier)
            {
                self.interrupted_sections(directory, &sections);
                sections.clear();
            }
            if sections.len() == MAX_FILE_SECTIONS {
                self.too_many_sections(directory, &sections);
                sections.clear();
            }
            sections.push(record);
            let last = sections.last().expect("a section was pushed");
            if last.is_multi_extent() && !last.is_directory() {
                continue;
            }
            let file = std::mem::take(&mut sections);
            self.entry(directory, &file, &mut subdirectories);
        }
        if !sections.is_empty() {
            self.interrupted_sections(directory, &sections);
        }
        subdirectories
    }

    fn interrupted_sections(&mut self, directory: &PendingDirectory, sections: &[Record<'_>]) {
        let first = &sections[0];
        let path = self.path(directory.node, None);
        self.problem(format!(
            "{path}: multi-extent file at 0x{:X} has no final section record",
            first.offset
        ));
    }

    fn too_many_sections(&mut self, directory: &PendingDirectory, sections: &[Record<'_>]) {
        let first = &sections[0];
        let path = self.path(directory.node, None);
        self.problem(format!(
            "{path}: multi-extent file at 0x{:X} has more than {MAX_FILE_SECTIONS} sections and \
             is not read",
            first.offset
        ));
    }

    /// One directory entry: a subdirectory or a file of `sections`, whose
    /// last record carries the attributes (SUSP 4).
    fn entry(
        &mut self,
        directory: &PendingDirectory,
        sections: &[Record<'a>],
        subdirectories: &mut Vec<PendingDirectory>,
    ) {
        let record = sections.last().expect("an entry has a record");
        let Some(attributes) = self.attributes(directory, record) else {
            return;
        };
        if attributes.relocated {
            self.census.relocated += 1;
            return;
        }
        let is_directory = record.is_directory() || attributes.child_link.is_some();
        let name = match self.name(record, &attributes, is_directory) {
            Ok(name) => name,
            Err(reason) => {
                let path = self.path(directory.node, None);
                self.problem(format!(
                    "{path}: record at 0x{:X} skipped: {reason}",
                    record.offset
                ));
                return;
            }
        };
        let path = self.path(directory.node, Some(&name));
        if path.len() > MAX_PATH {
            self.census.unwalked += 1;
            return;
        }
        if is_directory {
            self.subdirectory(directory, record, &attributes, name, &path, subdirectories);
        } else {
            self.file(sections, &attributes, path);
        }
    }

    /// The Rock Ridge attributes of `record`, when the hierarchy has them.
    /// `None`, counted, when they continue past the end of a truncated
    /// volume's input: the record's name and type are then unknown.
    fn attributes(
        &mut self,
        directory: &PendingDirectory,
        record: &Record<'_>,
    ) -> Option<Attributes> {
        let Names::RockRidge(rock) = &self.tree.names else {
            return Some(Attributes::default());
        };
        match susp::attributes(self.tree.image, self.tree.block_size, rock, record) {
            Ok(attributes) => Some(attributes),
            Err(Fault::Defect(reason)) => {
                let path = self.path(directory.node, None);
                self.problem(format!(
                    "{path}: Rock Ridge entries of the record at 0x{:X} ignored: {reason}",
                    record.offset
                ));
                Some(Attributes::default())
            }
            Err(Fault::Absent) => {
                self.census.absent_records += 1;
                None
            }
        }
    }

    /// The entry's name from the hierarchy's name source. A Rock Ridge name
    /// that is too long falls back to the ISO 9660 identifier.
    fn name(
        &mut self,
        record: &Record<'_>,
        attributes: &Attributes,
        is_directory: bool,
    ) -> std::result::Result<String, String> {
        let name = match (&self.tree.names, &attributes.name) {
            (Names::Joliet, _) => directory::joliet_name(record.identifier, is_directory),
            (Names::RockRidge(_), Some(AlternateName::Recorded(name))) => {
                String::from_utf8_lossy(name).into_owned()
            }
            (Names::RockRidge(_), Some(AlternateName::TooLong)) => {
                self.problem(format!(
                    "Rock Ridge name of the record at 0x{:X} is longer than 255 B; the ISO 9660 \
                     identifier is used",
                    record.offset
                ));
                directory::iso_name(record.identifier, is_directory)
            }
            (Names::RockRidge(_), None) => {
                self.census.without_alternate_name += 1;
                directory::iso_name(record.identifier, is_directory)
            }
            (Names::Iso, _) => directory::iso_name(record.identifier, is_directory),
        };
        directory::checked_name(name)
    }

    /// Queue a subdirectory, or a directory moved by Rock Ridge relocation
    /// (`CL`), whose own `.` record gives its size (RRIP 4.1.5.1).
    fn subdirectory(
        &mut self,
        directory: &PendingDirectory,
        record: &Record<'_>,
        attributes: &Attributes,
        name: String,
        path: &str,
        subdirectories: &mut Vec<PendingDirectory>,
    ) {
        let image = self.tree.image;
        let block_size = self.tree.block_size;
        let extent = match attributes.child_link {
            Some(block) => match moved_directory(image, block, block_size) {
                Ok(Some(dot)) => Ok((Some(dot.offset), dot.data_len)),
                Ok(None) => {
                    self.census.absent_directories += 1;
                    return;
                }
                Err(reason) => Err(reason),
            },
            None => Ok((record.data_offset(block_size), record.data_len)),
        };
        let checked = extent.and_then(|(offset, size)| directory_extent(image, offset, size));
        let (offset, size) = match checked {
            Ok(extent) => extent,
            Err(reason) => {
                self.problem(format!("{path}: directory not walked: {reason}"));
                return;
            }
        };
        if !has_first_sector(image, offset, size) {
            self.census.absent_directories += 1;
            return;
        }
        if directory.depth + 1 > MAX_DEPTH {
            self.census.unwalked += 1;
            return;
        }
        if !self.visited.insert(offset) {
            self.census.repeated += 1;
            return;
        }
        let node = self.nodes.len();
        self.nodes.push(PathNode {
            parent: directory.node,
            name,
        });
        subdirectories.push(PendingDirectory {
            offset,
            size,
            node,
            depth: directory.depth + 1,
        });
    }

    /// A regular file: matched to an El Torito entry, or examined as a
    /// member.
    fn file(&mut self, sections: &[Record<'_>], attributes: &Attributes, path: String) {
        if attributes
            .file_type
            .is_some_and(|file_type| file_type != susp::S_IFREG)
        {
            self.census.special += 1;
            return;
        }
        match attributes.encoding {
            Encoding::Plain => {}
            Encoding::Zisofs => {
                self.census.compressed += 1;
                return;
            }
            Encoding::Sparse => {
                self.census.sparse += 1;
                return;
            }
        }
        if sections.iter().any(|section| section.interleaved) {
            self.census.interleaved += 1;
            return;
        }
        self.census.files += 1;
        let image = self.tree.image;
        let mut ranges = Vec::with_capacity(sections.len());
        let mut total = 0usize;
        for section in sections {
            let size = section.data_len as usize;
            let range = section
                .data_offset(self.tree.block_size)
                .filter(|&offset| image.holds(offset, size));
            let Some(offset) = range else {
                self.problem(format!(
                    "{path}: file section at block {} ({size} B) lies outside the volume",
                    section.extent
                ));
                return;
            };
            ranges.push((offset, size));
            // Sections lie in the volume, so their sum fits in usize.
            total = total.saturating_add(size);
        }
        let first = ranges[0].0;
        if total == 0 {
            return;
        }
        if self.boot_offsets.contains(&first) {
            self.boot_files
                .insert(first, BootFile { path, size: total });
            return;
        }
        let is_present = ranges
            .iter()
            .all(|&(offset, size)| image.present(offset, size).is_some());
        if !is_present {
            self.census.absent_files += 1;
            return;
        }
        self.examine(path, &ranges, total);
    }

    /// Probe a file's first bytes and, when they are a recognized format,
    /// list the whole file.
    fn examine(&mut self, path: String, ranges: &[(usize, usize)], total: usize) {
        if self.members.len() >= MAX_COMPONENTS {
            self.census.over_component_limit += 1;
            return;
        }
        let probe_size = total.min(PROBE_SIZE);
        if !self.charge(probe_size) {
            self.census.over_budget += 1;
            return;
        }
        let image = self.tree.image;
        if !container::is_recognized(&prefix(image.bytes, ranges, probe_size)) {
            return;
        }
        if total > MAX_PAYLOAD {
            self.census.too_large += 1;
            return;
        }
        if !self.charge(total - probe_size) {
            self.census.over_budget += 1;
            return;
        }
        self.members
            .push(member(image.bytes, path, ranges, total).if_recognized());
    }
}

/// The `.` record of the directory that a Rock Ridge `CL` entry moved to
/// logical block `block`; its data length is the directory's size (RRIP
/// 4.1.5.1). `None` when the record's sector lies past the end of a
/// truncated volume's input.
fn moved_directory(
    image: Image<'_>,
    block: u32,
    block_size: usize,
) -> std::result::Result<Option<Record<'_>>, String> {
    let offset = block_offset(block, block_size)
        .ok_or_else(|| format!("CL block {block} lies outside the volume"))?;
    // A record does not cross a logical sector (6.8.1.1).
    let sector = image.size.saturating_sub(offset).min(SECTOR_SIZE);
    if sector > 0 && image.present(offset, sector).is_none() {
        return Ok(None);
    }
    let available = image.bytes.len().saturating_sub(offset).min(SECTOR_SIZE);
    Record::parse(image.bytes, offset, available)
        .map(Some)
        .map_err(|e| format!("moved directory: {}", descriptors::message(e)))
}

/// The first `size` bytes of a file stored in `ranges`.
fn prefix<'a>(image: &'a [u8], ranges: &[(usize, usize)], size: usize) -> Cow<'a, [u8]> {
    let (offset, len) = ranges[0];
    if len >= size {
        return Cow::Borrowed(&image[offset..offset + size]);
    }
    let mut bytes = Vec::with_capacity(size);
    for &(offset, len) in ranges {
        let take = len.min(size - bytes.len());
        bytes.extend_from_slice(&image[offset..offset + take]);
        if bytes.len() == size {
            break;
        }
    }
    Cow::Owned(bytes)
}

/// A file as a member: borrowed when its sections are contiguous,
/// otherwise reassembled.
fn member<'a>(image: &'a [u8], path: String, ranges: &[(usize, usize)], total: usize) -> Child<'a> {
    let (first, first_size) = ranges[0];
    let contiguous = ranges.windows(2).all(|w| w[0].0 + w[0].1 == w[1].0);
    if contiguous {
        return Child::stored(path, first, &image[first..first + total]);
    }
    let mut bytes = Vec::with_capacity(total);
    for &(offset, len) in ranges {
        bytes.extend_from_slice(&image[offset..offset + len]);
    }
    Child::decoded(
        path,
        first,
        first_size,
        Cow::Owned(bytes),
        SECTIONS_TRANSFORM,
    )
}

impl<'a> Walked<'a> {
    /// Append the members to `c` and record what was found and left out.
    pub(super) fn finish(self, c: &mut Container<'a>) {
        let census = &self.census;
        c.notes.push(format!(
            "{} regular files in {} directories; {} recognized members listed; members are \
             recognized from their first {}",
            census.files,
            census.directories,
            self.members.len(),
            size_text(PROBE_SIZE as u64)
        ));
        let present = self.image.present_text();
        let counted = [
            (
                census.over_component_limit,
                format!("further regular files were not examined: member limit reached ({MAX_COMPONENTS} members)"),
            ),
            (
                census.over_budget,
                format!(
                    "regular files were not examined or extracted: extraction limit reached ({})",
                    size_text(MAX_EXTRACTED as u64)
                ),
            ),
            (
                census.too_large,
                format!(
                    "recognized regular files exceed the {} member limit and are not listed",
                    size_text(MAX_PAYLOAD as u64)
                ),
            ),
            (
                census.over_walk_limit,
                format!(
                    "directories were not walked: walk limit reached ({MAX_DIRECTORIES} \
                     directories or twice {} in directory data)",
                    if self.image.is_truncated() {
                        format!("the {present} present")
                    } else {
                        "the volume size".to_string()
                    }
                ),
            ),
            (
                census.absent_directories,
                format!(
                    "directories lie partly or wholly past the {present} present; their records \
                     past it were not read"
                ),
            ),
            (
                census.absent_records,
                format!(
                    "directory records carry Rock Ridge entries continued past the {present} \
                     present; they were not read"
                ),
            ),
            (
                census.absent_files,
                format!(
                    "regular files were not listed: file data lies partly or wholly past the \
                     {present} present"
                ),
            ),
            (
                census.unwalked,
                format!(
                    "directories or files nested deeper than {MAX_DEPTH} levels or with paths \
                     longer than {MAX_PATH} B were not walked"
                ),
            ),
            (
                census.repeated,
                "directory records point at a directory already walked; it is not walked again"
                    .to_string(),
            ),
            (
                census.relocated,
                "relocated directory records (Rock Ridge RE) are skipped; a relocated directory \
                 is walked only through a CL entry that names it"
                    .to_string(),
            ),
            (
                census.special,
                "Rock Ridge symbolic links, devices, FIFOs or sockets are not read".to_string(),
            ),
            (
                census.associated,
                "associated files (file flag bit 2) are not read".to_string(),
            ),
            (
                census.interleaved,
                "interleaved files (file unit or gap size set) are not read".to_string(),
            ),
            (
                census.compressed,
                "zisofs-compressed files (ZF) are not decompressed and not listed".to_string(),
            ),
            (
                census.sparse,
                "sparse files (Rock Ridge SF) are not read".to_string(),
            ),
            (
                census.without_alternate_name,
                "entries carry no Rock Ridge NM entry; their ISO 9660 identifiers are used"
                    .to_string(),
            ),
            (
                census.byte_order_mismatches,
                "directory records hold extent or length halves that disagree; the \
                 little-endian values are used, as Linux and libarchive read them"
                    .to_string(),
            ),
        ];
        for (count, text) in counted {
            if count > 0 {
                c.notes.push(format!("{count} {text}"));
            }
        }
        c.notes.extend(census.problems.iter().cloned());
        if census.unlisted_problems > 0 {
            c.notes.push(format!(
                "{} further problems are not listed",
                census.unlisted_problems
            ));
        }
        c.push_metadata(
            "iso9660_regular_files",
            "Regular files",
            census.files as u64,
        );
        c.push_metadata(
            "iso9660_directories",
            "Directories",
            census.directories as u64,
        );
        c.push_metadata(
            "iso9660_member_count",
            "Recognized members",
            self.members.len() as u64,
        );
        c.children.extend(self.members);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_span_sections() {
        let image: Vec<u8> = (0..32).collect();
        let ranges = [(0, 4), (10, 4), (20, 4)];
        assert_eq!(prefix(&image, &ranges, 3).as_ref(), &[0, 1, 2]);
        assert_eq!(prefix(&image, &ranges, 6).as_ref(), &[0, 1, 2, 3, 10, 11]);
    }

    #[test]
    fn members_borrow_contiguous_sections_and_reassemble_others() {
        let image: Vec<u8> = (0..32).collect();
        let contiguous = member(&image, "/a".to_string(), &[(4, 4), (8, 4)], 8);
        assert!(matches!(contiguous.data, Cow::Borrowed(_)));
        assert_eq!(contiguous.stored_size, 8);
        let split = member(&image, "/b".to_string(), &[(4, 2), (20, 2)], 4);
        assert_eq!(split.data.as_ref(), &[4, 5, 20, 21]);
        assert_eq!(split.transform, Some(SECTIONS_TRANSFORM));
        assert_eq!(split.stored_size, 2);
    }

    #[test]
    fn directory_extents_must_lie_in_the_volume() {
        let bytes = [0u8; 4096];
        let image = Image {
            bytes: &bytes,
            size: bytes.len(),
        };
        assert_eq!(directory_extent(image, Some(2048), 2048), Ok((2048, 2048)));
        assert!(directory_extent(image, Some(2048), 2049).is_err());
        assert!(directory_extent(image, None, 1).is_err());
        assert!(directory_extent(image, Some(0), 0).is_err());
        // In a truncated volume, an extent inside the volume may lie past
        // the bytes present.
        let truncated = Image {
            bytes: &bytes[..2048],
            size: bytes.len(),
        };
        assert_eq!(
            directory_extent(truncated, Some(2048), 2048),
            Ok((2048, 2048))
        );
        assert!(!has_first_sector(truncated, 2048, 2048));
        assert!(has_first_sector(truncated, 0, 4096));
    }
}
