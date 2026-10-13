//! The MFT walk. Every record in use is read in record order. Directories
//! are indexed with their name and parent; a file's path is built from the
//! parent directory reference of its first `$FILE_NAME` that is not a DOS
//! alias, up to the root directory (record 5), with cycle detection and a
//! depth limit. Files whose parents do not lead to the root are listed
//! under `/$OrphanFiles`, as [TSK] names that directory. Regular files and
//! named data streams (`path:name`) whose first bytes are a recognized
//! format become members; system files (records below 16 and the `$Extend`
//! tree) are not read.

use super::data::Stream;
use super::mft::{File, METADATA_READ_FACTOR, MIN_METADATA_BASIS};
use super::record::FileName;
use super::*;
use crate::formats::container::{self, Child, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};

/// Most MFT records read; the bound is ours (4 GiB of 1 KiB records).
const MAX_RECORDS: u64 = 1 << 22;

/// Deepest directory level below the root that a path is built through.
const MAX_DEPTH: usize = 64;

/// Bytes at the start of a stream read to decide whether it is a
/// recognized format.
const RECOGNITION_PREFIX: usize = 4096;

/// Most data streams examined in one volume.
const MAX_STREAMS_EXAMINED: usize = 1 << 16;

/// Problems reported one by one; further ones are counted.
const MAX_PROBLEM_NOTES: usize = 16;

/// Where files that the root does not reach are listed ([TSK]
/// `tsk/fs/fs_dir.c`).
const ORPHAN_DIRECTORY: &str = "/$OrphanFiles";

/// The sequence number of the root directory: a system file's sequence
/// number equals its record number and never changes ([LAYOUT]
/// `NTFS_SYSTEM_FILES`).
const ROOT_SEQUENCE: u16 = 5;

/// Reparse tags of links to other files, which are not followed ([LAYOUT]
/// `PREDEFINED_REPARSE_TAGS`).
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xa000_0003;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xa000_000c;
const IO_REPARSE_TAG_LX_SYMLINK: u32 = 0xa000_001d;

/// Windows Overlay Filter files keep their data compressed (XPRESS or LZX)
/// in a named stream, which is not implemented ([LAYOUT]
/// `IO_REPARSE_TAG_WOF`).
const IO_REPARSE_TAG_WOF: u32 = 0x8000_0017;

/// An Interix symbolic link: a system file whose data starts with
/// `IntxLNK\1` ([LAYOUT] `INTX_FILE_TYPES`; [NTFS-3G] `ntfs_interix_types`,
/// read only for files with the system attribute).
const INTERIX_SYMLINK_MAGIC: &[u8; 8] = b"IntxLNK\x01";

/// A directory's name and parent, from which paths are built.
struct Directory {
    sequence: u16,
    parent: Reference,
    name: String,
}

/// Where a directory lies.
#[derive(Clone)]
enum Place {
    /// Its path from the root, `""` for the root itself, and its depth
    /// below the root.
    Path { path: String, depth: usize },
    /// Its parents do not lead to the root: a parent is missing, not a
    /// directory, reused (a stale sequence number), or one of its own
    /// ancestors.
    Orphan,
    /// More than [`MAX_DEPTH`] levels below the root.
    TooDeep,
    /// A system directory: `$Extend` or below it.
    System,
    /// A parent's MFT record lies past the end of a truncated volume's
    /// input, so the path is not known.
    Absent,
}

/// How a stream that is not read is compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Compression {
    /// The compression method in the attribute flags.
    method: u16,
    /// `compression_unit`: log2 of the clusters in a unit.
    unit: u8,
}

/// What the walk found and left out, for the notes.
#[derive(Debug, Default)]
struct Census {
    records_in_use: usize,
    directories: usize,
    files: usize,
    members: usize,
    absent_records: u64,
    unread_records: u64,
    unread_at_limit: u64,
    unexamined_at_limit: usize,
    linked_files: usize,
    named_streams: usize,
    resident_members: usize,
    sparse_members: usize,
    decoded_lznt1: usize,
    unsupported_compression: BTreeMap<Compression, usize>,
    encrypted: usize,
    links: BTreeMap<u32, usize>,
    wof: usize,
    other_reparse: BTreeMap<u32, usize>,
    interix_links: usize,
    orphans: usize,
    too_deep: usize,
    unexamined: usize,
    too_large: usize,
    over_budget: usize,
    absent_files: usize,
    absent_parents: usize,
    problems: Vec<String>,
    unlisted_problems: usize,
}

struct Walker<'v, 'a> {
    vol: &'v Volume<'a>,
    mft: &'v Mft,
    directories: HashMap<u64, Directory>,
    places: HashMap<u64, Place>,
    census: Census,
    extracted: usize,
    examined: usize,
}

/// `count` with the singular or plural form of the words after it.
fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

/// Walk the MFT and append the members to `c`.
pub(super) fn walk<'a>(vol: &Volume<'a>, mft: &Mft, c: &mut Container<'a>) {
    let mut walker = Walker {
        vol,
        mft,
        directories: HashMap::new(),
        places: HashMap::from([(
            ROOT_RECORD,
            Place::Path {
                path: String::new(),
                depth: 0,
            },
        )]),
        census: Census::default(),
        extracted: 0,
        examined: 0,
    };
    let candidates = walker.index();
    let total = candidates.len();
    for (done, number) in candidates.into_iter().enumerate() {
        if mft.is_exhausted() {
            walker.census.unexamined_at_limit = total - done;
            break;
        }
        walker.examine(number, c);
    }
    walker.census.report(vol, c);
}

impl<'a> Walker<'_, 'a> {
    fn problem(&mut self, text: String) {
        if self.census.problems.len() < MAX_PROBLEM_NOTES {
            self.census.problems.push(text);
        } else {
            self.census.unlisted_problems += 1;
        }
    }

    /// A record that could not be read: a problem, or bytes past the end of
    /// a truncated volume's input.
    fn record_fault(&mut self, number: u64, fault: Fault) {
        match fault {
            // The metadata read limit is reported once, in its own note.
            Fault::Invalid(_) if self.mft.is_exhausted() => {}
            Fault::Invalid(e) => {
                self.problem(format!("Skipped MFT record {number}: {}", message(e)));
            }
            Fault::Absent => self.census.absent_records += 1,
        }
    }

    /// Base record `number`, if it is in use.
    fn base_record(&mut self, number: u64) -> Option<Record> {
        match self.mft.record(self.vol, number) {
            Ok(Some(record)) if record.is_in_use() && record.is_base() => Some(record),
            Ok(_) => None,
            Err(fault) => {
                self.record_fault(number, fault);
                None
            }
        }
    }

    /// The attributes of the file whose base record is `record`. When its
    /// attribute list or an extension record lies past the end of a
    /// truncated volume's input, the file is counted as absent; a directory
    /// is still returned with the names its base record holds, so that the
    /// paths below it can be built.
    fn file(&mut self, record: Record) -> Option<File> {
        let number = record.number;
        let sequence = record.sequence;
        let is_directory = record.is_directory();
        let names = base_names(&record);
        match self.mft.file(self.vol, record) {
            Ok(file) => Some(file),
            Err(Fault::Absent) => {
                self.census.absent_files += 1;
                is_directory.then(|| File {
                    number,
                    sequence,
                    is_directory,
                    names,
                    attribute_flags: 0,
                    streams: Vec::new(),
                    reparse_point: None,
                    has_efs: false,
                })
            }
            Err(fault) => {
                self.record_fault(number, fault);
                None
            }
        }
    }

    /// The first pass: index the directories and return the records to
    /// examine (regular files, and directories with named streams), in
    /// record order. The system records are not read.
    fn index(&mut self) -> Vec<u64> {
        let last = self.mft.record_count().min(MAX_RECORDS);
        self.census.unread_records = self.mft.record_count() - last;
        let mut candidates = Vec::new();
        for number in FIRST_USER_RECORD..last {
            if self.mft.is_exhausted() {
                self.census.unread_at_limit = last - number;
                break;
            }
            let Some(record) = self.base_record(number) else {
                continue;
            };
            self.census.records_in_use += 1;
            let Some(file) = self.file(record) else {
                continue;
            };
            if file.is_directory {
                if let Some(name) = file.primary_name() {
                    self.directories.insert(
                        number,
                        Directory {
                            sequence: file.sequence,
                            parent: name.parent,
                            name: name.name.clone(),
                        },
                    );
                }
                if file.streams.iter().any(|stream| !stream.name.is_empty()) {
                    candidates.push(number);
                }
            } else {
                candidates.push(number);
            }
        }
        let numbers: Vec<u64> = self.directories.keys().copied().collect();
        for number in numbers {
            let reference = Reference {
                record: number,
                sequence: self.directories[&number].sequence,
            };
            if !matches!(self.place(reference), Place::System) {
                self.census.directories += 1;
            }
        }
        candidates
    }

    /// Where the directory that `reference` names lies, building and
    /// remembering the paths of it and its ancestors.
    fn place(&mut self, reference: Reference) -> Place {
        let mut chain: Vec<u64> = Vec::new();
        let mut current = reference;
        let base = loop {
            if current.record == ROOT_RECORD {
                break if current.names(ROOT_SEQUENCE) {
                    self.places[&ROOT_RECORD].clone()
                } else {
                    Place::Orphan
                };
            }
            if current.record < FIRST_USER_RECORD {
                break Place::System;
            }
            let Some(directory) = self.directories.get(&current.record) else {
                let absent = matches!(
                    self.mft.record(self.vol, current.record),
                    Err(Fault::Absent)
                );
                break if absent { Place::Absent } else { Place::Orphan };
            };
            // A reference with another sequence number names a record
            // that was reused since: the parent it named is gone.
            if !current.names(directory.sequence) {
                break Place::Orphan;
            }
            if let Some(place) = self.places.get(&current.record) {
                break place.clone();
            }
            if chain.contains(&current.record) {
                break Place::Orphan;
            }
            // A chain longer than the limit is too deep wherever it ends.
            if chain.len() > MAX_DEPTH {
                return Place::TooDeep;
            }
            chain.push(current.record);
            current = directory.parent;
        };
        // A chain past the depth limit says nothing about the directories in
        // it, which may lie fewer levels down; it is not remembered.
        if let Place::Path { depth, .. } = &base {
            if depth + chain.len() > MAX_DEPTH {
                return Place::TooDeep;
            }
        }
        // Name the chain from the root outward.
        let mut place = base;
        for &number in chain.iter().rev() {
            if let Place::Path { path, depth } = &place {
                let name = &self.directories[&number].name;
                place = Place::Path {
                    path: format!("{path}/{name}"),
                    depth: depth + 1,
                };
            }
            self.places.insert(number, place.clone());
        }
        place
    }

    /// The second pass over one record: its data streams.
    fn examine(&mut self, number: u64, c: &mut Container<'a>) {
        let Some(file) = self
            .base_record(number)
            .and_then(|record| self.file(record))
        else {
            return;
        };
        let Some(name) = file.primary_name().cloned() else {
            self.problem(format!("Skipped MFT record {number}: no $FILE_NAME"));
            return;
        };
        let path = if file.is_directory {
            self.place(Reference {
                record: number,
                sequence: file.sequence,
            })
        } else {
            match self.place(name.parent) {
                Place::Path { path, depth } => Place::Path {
                    path: format!("{path}/{}", name.name),
                    depth,
                },
                other => other,
            }
        };
        let path = match path {
            Place::Path { path, .. } => path,
            Place::System => return,
            Place::Orphan => {
                self.census.orphans += 1;
                format!("{ORPHAN_DIRECTORY}/{}", name.name)
            }
            Place::TooDeep => {
                self.census.too_deep += 1;
                return;
            }
            Place::Absent => {
                self.census.absent_parents += 1;
                return;
            }
        };
        if !file.is_directory {
            self.census.files += 1;
            if file.link_count() > 1 {
                self.census.linked_files += 1;
            }
        }
        if !self.is_readable(&file) {
            return;
        }
        let base = if path.is_empty() { "/" } else { &path };
        for stream in &file.streams {
            if file.is_directory && stream.name.is_empty() {
                continue;
            }
            let label = if stream.name.is_empty() {
                base.to_string()
            } else {
                self.census.named_streams += 1;
                format!("{base}:{}", stream.name)
            };
            self.stream(&file, stream, &label, c);
        }
    }

    /// Whether the file's data may be read: encrypted files, links and WOF
    /// files are counted instead.
    fn is_readable(&mut self, file: &File) -> bool {
        if file.has_efs
            || file.attribute_flags & FILE_ATTR_ENCRYPTED != 0
            || file.streams.iter().any(Stream::is_encrypted)
        {
            self.census.encrypted += 1;
            return false;
        }
        if file.attribute_flags & FILE_ATTR_REPARSE_POINT == 0 && file.reparse_point.is_none() {
            return true;
        }
        let tag = file
            .reparse_point
            .as_ref()
            .and_then(|point| point.read(self.vol, 4).ok())
            .and_then(|bytes| le_u32(&bytes.bytes, 0).ok());
        match tag {
            Some(
                tag @ (IO_REPARSE_TAG_SYMLINK
                | IO_REPARSE_TAG_MOUNT_POINT
                | IO_REPARSE_TAG_LX_SYMLINK),
            ) => {
                *self.census.links.entry(tag).or_default() += 1;
                false
            }
            Some(IO_REPARSE_TAG_WOF) => {
                self.census.wof += 1;
                false
            }
            Some(tag) => {
                *self.census.other_reparse.entry(tag).or_default() += 1;
                true
            }
            None => true,
        }
    }

    /// List a stream when its first bytes are a recognized format and the
    /// limits allow its extraction.
    fn stream(&mut self, file: &File, stream: &Stream, label: &str, c: &mut Container<'a>) {
        if stream.size() == 0 {
            return;
        }
        if c.children.len() >= MAX_COMPONENTS || self.examined >= MAX_STREAMS_EXAMINED {
            self.census.unexamined += 1;
            return;
        }
        self.examined += 1;
        let method = stream.compression_method();
        if method != 0 && !is_lznt1(self.vol, stream) {
            let unit = match &stream.body {
                data::Body::NonResident(extents) => extents.compression_unit,
                data::Body::Resident { .. } => 0,
            };
            *self
                .census
                .unsupported_compression
                .entry(Compression { method, unit })
                .or_default() += 1;
            return;
        }
        match self.member(file, stream, label) {
            Ok(Some(child)) => {
                self.extracted += child.data.len();
                self.census.members += 1;
                if stream.is_resident() {
                    self.census.resident_members += 1;
                }
                if stream.is_sparse() && method == 0 {
                    self.census.sparse_members += 1;
                }
                if method != 0 {
                    self.census.decoded_lznt1 += 1;
                }
                c.children.push(child.if_recognized());
            }
            Ok(None) => {}
            Err(Fault::Invalid(e)) => self.problem(format!("Skipped {label}: {}", message(e))),
            Err(Fault::Absent) => self.census.absent_files += 1,
        }
    }

    /// The member for a stream in a recognized format, if the limits allow.
    fn member(
        &mut self,
        file: &File,
        stream: &Stream,
        label: &str,
    ) -> ReadResult<Option<Child<'a>>> {
        let size = usize::try_from(stream.size()).unwrap_or(usize::MAX);
        let prefix = stream.read(self.vol, size.min(RECOGNITION_PREFIX))?;
        if stream.name.is_empty()
            && file.attribute_flags & FILE_ATTR_SYSTEM != 0
            && prefix.bytes.starts_with(INTERIX_SYMLINK_MAGIC)
        {
            self.census.interix_links += 1;
            return Ok(None);
        }
        if !container::is_recognized(&prefix.bytes) {
            return Ok(None);
        }
        if size > MAX_PAYLOAD {
            self.census.too_large += 1;
            return Ok(None);
        }
        if self.extracted + size > MAX_EXTRACTED {
            self.census.over_budget += 1;
            return Ok(None);
        }
        let contents = if prefix.bytes.len() == size {
            prefix
        } else {
            stream.read(self.vol, size)?
        };
        let Some(run) = contents.first_run else {
            return Ok(None);
        };
        let child = match contents.bytes {
            Cow::Borrowed(bytes) => Child::stored(label, run.offset, bytes),
            Cow::Owned(bytes) => Child::decoded(
                label,
                run.offset,
                run.size,
                Cow::Owned(bytes),
                contents
                    .transform
                    .expect("stream reads name the transform of owned bytes"),
            ),
        };
        Ok(Some(child))
    }
}

/// The `$FILE_NAME` values in a base record, in record order.
fn base_names(record: &Record) -> Vec<FileName> {
    record
        .attributes
        .iter()
        .filter(|attribute| attribute.kind == AT_FILE_NAME)
        .filter_map(|attribute| record.resident_value(attribute).and_then(FileName::read))
        .collect()
}

/// Whether a compressed stream uses the method this reader decodes: LZNT1
/// in units of 16 clusters of at most 4 KiB ([NTFS-3G] `ntfs_attr_open`).
fn is_lznt1(vol: &Volume<'_>, stream: &Stream) -> bool {
    let unit = match &stream.body {
        data::Body::NonResident(extents) => extents.compression_unit,
        data::Body::Resident { .. } => return false,
    };
    stream.compression_method() == ATTR_IS_COMPRESSED
        && unit == data::STANDARD_COMPRESSION_UNIT
        && vol.boot.cluster_size <= data::MAX_COMPRESSION_CLUSTER_SIZE
}

impl Census {
    /// Notes and metadata: what was walked, then what was left out and why.
    fn report(self, vol: &Volume<'_>, c: &mut Container<'_>) {
        let present = vol.present_text();
        c.notes.push(format!(
            "MFT walk: {} in use after the 16 system records, {}, {}; members in a recognized \
             format: {}; paths come from $FILE_NAME parent references (the $I30 directory \
             indexes are not read)",
            counted(self.records_in_use, "base record", "base records"),
            counted(self.directories, "directory", "directories"),
            counted(self.files, "regular file", "regular files"),
            self.members
        ));
        if self.absent_records > 0 {
            c.notes.push(format!(
                "{} past the {present} present and {} not read",
                counted(
                    usize::try_from(self.absent_records).unwrap_or(usize::MAX),
                    "MFT record lies",
                    "MFT records lie"
                ),
                if self.absent_records == 1 {
                    "was"
                } else {
                    "were"
                }
            ));
        }
        if self.unread_records > 0 {
            c.notes.push(format!(
                "The walk stopped after {MAX_RECORDS} MFT records; {} records were not read",
                self.unread_records
            ));
        }
        if self.unread_at_limit > 0 || self.unexamined_at_limit > 0 {
            c.notes.push(format!(
                "The walk stopped at the metadata read limit ({METADATA_READ_FACTOR} times the \
                 {present} present, at least {}): {} MFT records were not indexed and {} files \
                 not examined",
                size_text(MIN_METADATA_BASIS),
                self.unread_at_limit,
                self.unexamined_at_limit
            ));
        }
        if self.absent_files > 0 {
            c.notes.push(format!(
                "{} not read: data, or the attribute lists and extension records that locate \
                 it, lie partly or wholly past the {present} present",
                counted(
                    self.absent_files,
                    "data stream or file was",
                    "data streams or files were"
                )
            ));
        }
        if self.absent_parents > 0 {
            c.notes.push(format!(
                "{} not read: the MFT record of a parent directory lies past the {present} \
                 present, so the path is not known",
                counted(
                    self.absent_parents,
                    "file or directory was",
                    "files or directories were"
                )
            ));
        }
        if self.linked_files > 0 {
            c.notes.push(format!(
                "{} more than one name (hard links); each is examined once, under its first name",
                counted(self.linked_files, "file has", "files have")
            ));
        }
        if self.named_streams > 0 {
            c.notes.push(format!(
                "{} examined; streams are listed as path:name",
                counted(
                    self.named_streams,
                    "named data stream was",
                    "named data streams were"
                )
            ));
        }
        if self.resident_members > 0 {
            c.notes.push(counted(
                self.resident_members,
                "member is resident: stored in its MFT record",
                "members are resident: stored in their MFT records",
            ));
        }
        if self.sparse_members > 0 {
            c.notes.push(format!(
                "{} sparse runs, read as zeros",
                counted(self.sparse_members, "member has", "members have")
            ));
        }
        if self.decoded_lznt1 > 0 {
            c.notes.push(format!(
                "{} decoded from LZNT1 compression units",
                counted(self.decoded_lznt1, "member was", "members were")
            ));
        }
        for (compression, count) in &self.unsupported_compression {
            c.notes.push(format!(
                "{} compression method {} in units of 2^{} clusters of {}, which is not \
                 implemented; not read",
                counted(*count, "stream uses", "streams use"),
                compression.method,
                compression.unit,
                size_text(vol.boot.cluster_size as usize)
            ));
        }
        if self.encrypted > 0 {
            c.notes.push(format!(
                "{} not read: EFS-encrypted data is opaque without the file's key",
                counted(self.encrypted, "encrypted file was", "encrypted files were")
            ));
        }
        for (tag, count) in &self.links {
            c.notes.push(format!(
                "{} with reparse tag 0x{tag:08X} counted, not followed",
                counted(*count, "link", "links")
            ));
        }
        if self.wof > 0 {
            c.notes.push(format!(
                "{} not read: WOF compression (reparse tag 0x{IO_REPARSE_TAG_WOF:08X}, XPRESS or \
                 LZX in the WofCompressedData stream) is not implemented",
                counted(
                    self.wof,
                    "WOF-compressed file was",
                    "WOF-compressed files were"
                )
            ));
        }
        for (tag, count) in &self.other_reparse {
            c.notes.push(format!(
                "{} reparse tag 0x{tag:08X}; their data streams were examined as stored",
                counted(*count, "file carries", "files carry")
            ));
        }
        if self.interix_links > 0 {
            c.notes.push(format!(
                "{} counted, not followed",
                counted(
                    self.interix_links,
                    "Interix symbolic link (IntxLNK) was",
                    "Interix symbolic links (IntxLNK) were"
                )
            ));
        }
        if self.orphans > 0 {
            c.notes.push(format!(
                "{} not reachable from the root directory; recognized ones are listed under \
                 {ORPHAN_DIRECTORY}",
                counted(
                    self.orphans,
                    "file or directory is",
                    "files or directories are"
                )
            ));
        }
        if self.too_deep > 0 {
            c.notes.push(format!(
                "{} not read",
                counted(
                    self.too_deep,
                    &format!("file deeper than {MAX_DEPTH} directory levels was"),
                    &format!("files deeper than {MAX_DEPTH} directory levels were")
                )
            ));
        }
        if self.unexamined > 0 {
            c.notes.push(format!(
                "{} not examined: at most {MAX_COMPONENTS} members are listed and \
                 {MAX_STREAMS_EXAMINED} data streams examined",
                counted(self.unexamined, "data stream was", "data streams were")
            ));
        }
        if self.too_large > 0 {
            c.notes.push(format!(
                "{} the {} extraction limit; not extracted",
                counted(self.too_large, "stream exceeds", "streams exceed"),
                size_text(MAX_PAYLOAD)
            ));
        }
        if self.over_budget > 0 {
            c.notes.push(format!(
                "{} not extracted: the {} total extraction limit was reached",
                counted(
                    self.over_budget,
                    "recognized stream was",
                    "recognized streams were"
                ),
                size_text(MAX_EXTRACTED)
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
            "ntfs_records_in_use",
            "Base records in use (from record 16)",
            self.records_in_use as u64,
        );
        c.push_metadata(
            "ntfs_directory_count",
            "Directories",
            self.directories as u64,
        );
        c.push_metadata(
            "ntfs_regular_file_count",
            "Regular files",
            self.files as u64,
        );
        c.push_metadata("ntfs_member_count", "Members", self.members as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_use_singular_and_plural_forms() {
        assert_eq!(counted(1, "file", "files"), "1 file");
        assert_eq!(counted(0, "file", "files"), "0 files");
    }
}
