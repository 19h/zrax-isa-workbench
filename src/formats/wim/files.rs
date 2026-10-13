//! The files of a WIM as children. For each image, in lookup table order,
//! the metadata resource is decoded whole and its SHA-1 verified, its
//! directory tree is walked in pre-order, and every data stream in a
//! recognized format is listed, labeled `/<image>/<path>` (a named stream
//! `/<image>/<path>:<name>`). Parts of a split WIM other than the first
//! hold no metadata; their resources are listed by SHA-1, in table order.
//!
//! A first walk of the images collects the resources that data streams
//! name. Each of them is then examined once, in the order the resources
//! are stored, so that the chunks of a solid resource are decoded in order:
//! its first 4 KiB decide whether it is a recognized format, and only then
//! is it decoded whole, its SHA-1 verified against the lookup table and its
//! whole contents checked again. The second walk lists the recognized
//! resources under their paths; a hash under several paths (hard links,
//! files that several images share) is listed under each from that one
//! decode. Reparse point data and encrypted files are never examined.
//!
//! Limits: resources over [`MAX_PAYLOAD`] are not decoded; the bytes of
//! recognized resources and of their further listings are charged against
//! [`MAX_EXTRACTED`]; at most [`MAX_FILES_EXAMINED`] resources are
//! examined and [`MAX_COMPONENTS`] children listed; a metadata resource may
//! decode to [`MAX_METADATA`] bytes and all of them together, in each walk,
//! to [`MAX_METADATA_TOTAL`]; all chunk decoding stops at the reader's
//! limit (see [`Reader`]). What a limit leaves out is counted in notes.

use super::lookup::{Blob, Location, Table};
use super::metadata::{self, Dentry, StreamKind, WalkCensus};
use super::resource::{self, Bytes, Reader};
use super::xml::{ImageInfo, XmlInfo};
use super::*;
use crate::formats::checksum::Sha1;
use crate::formats::container::{self, Child, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

/// Bytes at the start of a resource that are checked for a recognized
/// format before the whole resource is decoded.
const RECOGNITION_PREFIX: usize = 4096;

/// Most resources examined in one WIM.
const MAX_FILES_EXAMINED: usize = 1 << 16;

/// Largest metadata resource decoded, and most metadata decoded for one
/// WIM. A metadata resource holds about 100 B per file; the bounds are
/// ours.
const MAX_METADATA: usize = MAX_EXTRACTED;
const MAX_METADATA_TOTAL: usize = 4 * MAX_EXTRACTED;

/// Problems reported one by one; further ones are counted.
const MAX_PROBLEM_NOTES: usize = 16;

/// Longest label in bytes; a longer path keeps its end.
const MAX_LABEL: usize = 1024;

/// The transform of bytes assembled from stored chunks. Stored chunks are
/// contiguous, so it is not expected; it keeps child construction total.
const STORED_CHUNKS: &str = "WIM chunks";

/// Why a stream was not listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    /// Larger than [`MAX_PAYLOAD`].
    TooLarge,
    /// [`MAX_FILES_EXAMINED`] resources were examined already.
    Unexamined,
    /// The reader's decoding limit was reached.
    DecodeLimit,
    /// The resource did not decode or failed its SHA-1.
    Failed,
    /// [`MAX_EXTRACTED`] would be exceeded.
    OverBudget,
}

/// What examining a resource found, kept by hash.
#[derive(Debug, Clone, Copy)]
enum Outcome {
    /// Not in a recognized format.
    Unrecognized,
    /// A recognized format, decoded and verified, waiting in
    /// [`Lister::pending`] for its first path.
    Recognized,
    /// Listed as child `0` of the container.
    Listed(usize),
    NotListed(Reason),
}

/// What the listing found and left out.
#[derive(Debug, Default)]
struct Census {
    /// Data streams met in the directory trees (or resources of a later
    /// part).
    streams: usize,
    listed: usize,
    empty: usize,
    /// Streams whose hash the lookup table does not hold.
    missing: usize,
    in_other_parts: usize,
    reparse_points: usize,
    encrypted: usize,
    examined: usize,
    recognized: usize,
    /// Resources whose SHA-1 was verified: metadata and recognized files.
    verified: usize,
    too_large: usize,
    unexamined: usize,
    decode_limit: usize,
    failed: usize,
    over_budget: usize,
    /// Streams not examined because [`MAX_COMPONENTS`] were listed.
    unlisted: usize,
    /// Bytes of recognized resources and of listed copies.
    extracted: usize,
    metadata_decoded: usize,
    problems: Vec<String>,
    more_problems: usize,
}

impl Census {
    fn skip(&mut self, reason: Reason) {
        match reason {
            Reason::TooLarge => self.too_large += 1,
            Reason::Unexamined => self.unexamined += 1,
            Reason::DecodeLimit => self.decode_limit += 1,
            Reason::Failed => self.failed += 1,
            Reason::OverBudget => self.over_budget += 1,
        }
    }

    fn problem(&mut self, what: &str, message: &str) {
        if self.problems.len() < MAX_PROBLEM_NOTES {
            self.problems.push(format!("`{what}`: {message}"));
        } else {
            self.more_problems += 1;
        }
    }
}

/// Examines the resources and lists the images' files.
struct Lister<'a, 'h> {
    reader: Reader<'a, 'h>,
    table: &'h Table,
    seen: HashMap<Hash, Outcome>,
    /// Bytes of recognized resources not listed yet.
    pending: HashMap<Hash, Bytes<'a>>,
    /// Why resources failed, noted under the first path that names them.
    failures: HashMap<Hash, String>,
    census: Census,
}

/// Examine the resources of this part in the order they are stored, which
/// decodes the chunks of a solid resource in order, then list the files of
/// every image (part 1) or the resources (later parts of a split WIM). In
/// part 1, a first walk of the images finds the resources that data
/// streams name, so that reparse point data and encrypted files are not
/// examined.
pub(super) fn list<'a>(
    data: &'a [u8],
    header: &Header,
    table: &Table,
    xml: Option<&XmlInfo>,
    c: &mut Container<'a>,
) {
    let mut lister = Lister {
        reader: Reader::new(data, header, &table.solid),
        table,
        seen: HashMap::new(),
        pending: HashMap::new(),
        failures: HashMap::new(),
        census: Census::default(),
    };
    if header.part_number == 1 {
        let wanted = lister.data_streams();
        lister.examine_all(Some(&wanted));
        for (i, blob) in table.metadata.iter().enumerate() {
            let index = u32::try_from(i + 1).unwrap_or(u32::MAX);
            let info = xml.and_then(|xml| xml.image(index));
            lister.image(index, blob, info, c);
        }
    } else {
        lister.examine_all(None);
        c.notes.push(format!(
            "File names are in part 1; the {} of this part are listed by SHA-1",
            count(table.order.len(), "resource", "resources")
        ));
        for hash in &table.order {
            lister.stream(format!("resource {}", hex(hash)), *hash, c);
        }
    }
    lister.census.report(c);
}

impl<'a> Lister<'a, '_> {
    /// The resources that the images' data streams name, from a first walk
    /// of every image whose metadata resource reads.
    fn data_streams(&mut self) -> HashSet<Hash> {
        let mut wanted = HashSet::new();
        let mut decoded = 0;
        for blob in &self.table.metadata {
            let Ok(metadata) = read_metadata(&mut self.reader, blob, &mut decoded) else {
                continue;
            };
            // A walk that stops early still names the streams it reached.
            let _ = metadata::walk(&metadata.data, |_, entry| {
                for stream in &entry.streams {
                    if is_data_stream(entry, stream) {
                        wanted.insert(stream.hash);
                    }
                }
            });
        }
        wanted
    }

    /// Examine the resources of the lookup table, those in `wanted` when it
    /// is given, in stored order: by the offset of their resource, then by
    /// their offset in a solid resource.
    fn examine_all(&mut self, wanted: Option<&HashSet<Hash>>) {
        let table = self.table;
        let mut order: Vec<StoredPosition> = table
            .order
            .iter()
            .filter(|hash| wanted.map_or(true, |wanted| wanted.contains(*hash)))
            .map(|hash| StoredPosition::of(table, *hash))
            .collect();
        order.sort_unstable();
        for position in order {
            let blob = table.blobs[&position.hash];
            let outcome = self.examine(&blob);
            self.seen.insert(position.hash, outcome);
        }
    }

    /// Walk one image's directory tree and list its streams.
    fn image(&mut self, index: u32, blob: &Blob, info: Option<&ImageInfo>, c: &mut Container<'a>) {
        let name = info
            .and_then(|info| info.name.as_deref())
            .map_or_else(String::new, |name| format!(" (`{name}`)"));
        let metadata =
            match read_metadata(&mut self.reader, blob, &mut self.census.metadata_decoded) {
                Ok(metadata) => {
                    self.census.verified += 1;
                    metadata
                }
                Err(problem) => {
                    c.notes.push(format!(
                        "Image {index}{name}: {problem}; its files are not listed"
                    ));
                    return;
                }
            };
        let prefix = format!("/{index}");
        let walk = metadata::walk(&metadata.data, |path, entry| {
            self.entry(&prefix, path, entry, c);
        });
        match walk {
            Ok(walk) => c.notes.push(image_note(index, &name, &walk)),
            Err(e) => c.notes.push(format!(
                "Image {index}{name}: directory tree not read: {}",
                resource::message(&e)
            )),
        }
    }

    /// List the streams of one directory entry at `path` in an image.
    fn entry(&mut self, prefix: &str, path: &str, entry: &Dentry, c: &mut Container<'a>) {
        for stream in &entry.streams {
            let label = match &stream.kind {
                // A directory's unnamed stream holds no file contents.
                StreamKind::Data if entry.is_directory() => continue,
                StreamKind::Data => stream_label(prefix, path, None),
                StreamKind::Named(name) => stream_label(prefix, path, Some(name)),
                StreamKind::Reparse => {
                    self.census.reparse_points += 1;
                    continue;
                }
                StreamKind::Encrypted => {
                    self.census.encrypted += 1;
                    continue;
                }
            };
            self.stream(label, stream.hash, c);
        }
    }

    /// List one data stream under `label`: its recognized resource the
    /// first time, a copy of that child after.
    fn stream(&mut self, label: String, hash: Hash, c: &mut Container<'a>) {
        self.census.streams += 1;
        if c.children.len() >= MAX_COMPONENTS {
            self.census.unlisted += 1;
            return;
        }
        if hash == [0; HASH_SIZE] {
            self.census.empty += 1;
            return;
        }
        let Some(outcome) = self.seen.get(&hash).copied() else {
            if self.table.other_parts.contains(&hash) {
                self.census.in_other_parts += 1;
            } else {
                self.census.missing += 1;
            }
            return;
        };
        match outcome {
            Outcome::Unrecognized => {}
            Outcome::NotListed(reason) => {
                self.census.skip(reason);
                if let Some(problem) = self.failures.remove(&hash) {
                    self.census.problem(&label, &problem);
                }
            }
            Outcome::Recognized => {
                let bytes = self
                    .pending
                    .remove(&hash)
                    .expect("a recognized resource waits for its first path");
                self.census.listed += 1;
                c.children.push(child(label, bytes).if_recognized());
                self.seen
                    .insert(hash, Outcome::Listed(c.children.len() - 1));
            }
            Outcome::Listed(child) => self.repeat(child, label, c),
        }
    }

    /// Examine one resource: its first bytes, then, for a recognized
    /// format, all of them, which must match the SHA-1 and still be
    /// recognized; they wait in [`Self::pending`] for the first path.
    fn examine(&mut self, blob: &Blob) -> Outcome {
        let Some(size) = usize::try_from(blob.size)
            .ok()
            .filter(|&size| size <= MAX_PAYLOAD)
        else {
            return Outcome::NotListed(Reason::TooLarge);
        };
        if self.census.examined >= MAX_FILES_EXAMINED {
            return Outcome::NotListed(Reason::Unexamined);
        }
        if self.reader.is_exhausted() {
            return Outcome::NotListed(Reason::DecodeLimit);
        }
        self.census.examined += 1;
        let prefix_len = size.min(RECOGNITION_PREFIX);
        let prefix = match self.reader.read(&blob.location, blob.size, prefix_len) {
            Ok(prefix) => prefix,
            Err(e) => return self.read_failure(blob, &e),
        };
        if !container::is_recognized(&prefix.data) {
            return Outcome::Unrecognized;
        }
        self.census.recognized += 1;
        if self.census.extracted + size > MAX_EXTRACTED {
            return Outcome::NotListed(Reason::OverBudget);
        }
        let whole = if prefix_len == size {
            prefix
        } else {
            match self.reader.read(&blob.location, blob.size, size) {
                Ok(whole) => whole,
                Err(e) => return self.read_failure(blob, &e),
            }
        };
        if sha1(&whole.data) != blob.hash {
            self.failures
                .insert(blob.hash, "the data does not match its SHA-1".to_string());
            return Outcome::NotListed(Reason::Failed);
        }
        self.census.verified += 1;
        if !container::is_recognized(&whole.data) {
            return Outcome::Unrecognized;
        }
        self.census.extracted += size;
        self.pending.insert(blob.hash, whole);
        Outcome::Recognized
    }

    /// The outcome of a read that failed: the decoding limit, or a problem
    /// kept for the resource's first path.
    fn read_failure(&mut self, blob: &Blob, e: &ClassifierError) -> Outcome {
        if self.reader.is_exhausted() {
            return Outcome::NotListed(Reason::DecodeLimit);
        }
        self.failures.insert(blob.hash, resource::message(e));
        Outcome::NotListed(Reason::Failed)
    }

    /// List the resource of child `child` again under `label`.
    fn repeat(&mut self, child: usize, label: String, c: &mut Container<'a>) {
        let first = &c.children[child];
        let size = first.data.len();
        if self.census.extracted + size > MAX_EXTRACTED {
            self.census.over_budget += 1;
            return;
        }
        let copy = Child {
            label,
            offset: first.offset,
            stored_size: first.stored_size,
            data: first.data.clone(),
            transform: first.transform,
            opaque: first.opaque,
            target: first.target,
            variant: first.variant,
            classify: first.classify,
        };
        self.census.extracted += size;
        self.census.listed += 1;
        c.children.push(copy.if_recognized());
    }
}

/// Where a blob is stored, for examining blobs in stored order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct StoredPosition {
    /// File offset of the blob's resource.
    resource: u64,
    /// Offset in a solid resource's uncompressed data; 0 otherwise.
    offset: u64,
    hash: Hash,
}

impl StoredPosition {
    fn of(table: &Table, hash: Hash) -> Self {
        let (resource, offset) = match table.blobs[&hash].location {
            Location::Resource(resource) => (resource.offset, 0),
            Location::Solid { resource, offset } => (table.solid[resource].header.offset, offset),
        };
        Self {
            resource,
            offset,
            hash,
        }
    }
}

/// An image's metadata resource, decoded whole and verified, or why not;
/// `decoded` counts the metadata bytes decoded against
/// [`MAX_METADATA_TOTAL`].
fn read_metadata<'a>(
    reader: &mut Reader<'a, '_>,
    blob: &Blob,
    decoded: &mut usize,
) -> std::result::Result<Bytes<'a>, String> {
    let size = usize::try_from(blob.size)
        .ok()
        .filter(|&size| size <= MAX_METADATA)
        .ok_or_else(|| {
            format!(
                "metadata resource of {} B exceeds the {} limit",
                blob.size,
                size_text(MAX_METADATA)
            )
        })?;
    if *decoded + size > MAX_METADATA_TOTAL {
        return Err(format!(
            "the {} metadata read limit was reached",
            size_text(MAX_METADATA_TOTAL)
        ));
    }
    let bytes = reader
        .read(&blob.location, blob.size, size)
        .map_err(|e| format!("metadata resource not read: {}", resource::message(&e)))?;
    *decoded += size;
    if sha1(&bytes.data) != blob.hash {
        return Err("metadata resource does not match its SHA-1".into());
    }
    Ok(bytes)
}

/// Whether a stream holds file contents worth examining: an unnamed data
/// stream of a file or a named data stream.
fn is_data_stream(entry: &Dentry, stream: &metadata::Stream) -> bool {
    match stream.kind {
        StreamKind::Data => !entry.is_directory(),
        StreamKind::Named(_) => true,
        StreamKind::Reparse | StreamKind::Encrypted => false,
    }
}

/// The SHA-1 of `bytes`.
fn sha1(bytes: &[u8]) -> Hash {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finish()
}

/// A child for read bytes: stored at their own offset when borrowed,
/// decoded from the stored extent otherwise.
fn child(label: String, bytes: Bytes<'_>) -> Child<'_> {
    let Bytes {
        data,
        offset,
        stored_size,
        transform,
    } = bytes;
    match (data, transform) {
        (Cow::Borrowed(stored), None) => Child::stored(label, offset, stored),
        (data, transform) => Child::decoded(
            label,
            offset,
            stored_size,
            data,
            transform.unwrap_or(STORED_CHUNKS),
        ),
    }
}

/// `/<image>/<path>` or `/<image>/<path>:<stream>`, keeping the end of a
/// label over [`MAX_LABEL`] bytes.
fn stream_label(prefix: &str, path: &str, stream: Option<&str>) -> String {
    let full = match stream {
        Some(stream) => format!("{prefix}{path}:{stream}"),
        None => format!("{prefix}{path}"),
    };
    if full.len() <= MAX_LABEL {
        return full;
    }
    let keep = MAX_LABEL - prefix.len() - "/…".len();
    let mut start = full.len() - keep;
    while !full.is_char_boundary(start) {
        start += 1;
    }
    format!("{prefix}/…{}", &full[start..])
}

/// The note on one image's walk.
fn image_note(index: u32, name: &str, walk: &WalkCensus) -> String {
    let mut note = format!(
        "Image {index}{name}: {} and {} in the directory tree",
        count(walk.directories, "directory", "directories"),
        count(walk.files, "file", "files")
    );
    let skipped = [
        (
            walk.invalid_names,
            "entries with an empty, `.`, `..` or NUL-holding name skipped",
        ),
        (
            walk.too_deep,
            "directories deeper than 64 levels not walked",
        ),
        (
            walk.children_of_files,
            "entry lists of non-directories ignored",
        ),
    ];
    for (n, what) in skipped {
        if n > 0 {
            write!(note, "; {n} {what}").expect("writing to a String succeeds");
        }
    }
    if let Some(stopped) = &walk.stopped {
        write!(note, "; the walk stopped early: {stopped}").expect("writing to a String succeeds");
    }
    note
}

impl Census {
    /// Notes and metadata: what was listed, then what was left out and why.
    fn report(self, c: &mut Container<'_>) {
        c.notes.push(format!(
            "{} of {} listed; {} of {} examined resources are in a recognized format",
            self.listed,
            count(self.streams, "data stream", "data streams"),
            self.recognized,
            self.examined
        ));
        if self.verified > 0 {
            c.notes.push(format!(
                "SHA-1 verified for {}",
                count(self.verified, "decoded resource", "decoded resources")
            ));
        }
        let left_out = [
            (self.empty, "empty"),
            (self.missing, "not in the lookup table"),
            (
                self.in_other_parts,
                "stored in other parts of the split WIM",
            ),
            (
                self.decode_limit,
                "not examined: the 2 GiB decoding limit was reached",
            ),
            (self.failed, "not decoded or failed their SHA-1"),
            (self.too_large, "over the 64 MiB extraction limit"),
            (self.over_budget, "over the 256 MiB total extraction limit"),
            (
                self.unexamined,
                "not examined: 65536 resources were examined",
            ),
            (self.unlisted, "not examined: 4096 children were listed"),
        ];
        let reasons: Vec<String> = left_out
            .iter()
            .filter(|(n, _)| *n > 0)
            .map(|(n, why)| format!("{n} {why}"))
            .collect();
        if !reasons.is_empty() {
            c.notes
                .push(format!("Data streams left out: {}", reasons.join(", ")));
        }
        if self.reparse_points > 0 {
            c.notes.push(format!(
                "{} not listed",
                count(
                    self.reparse_points,
                    "reparse point's data is",
                    "reparse points' data are"
                )
            ));
        }
        if self.encrypted > 0 {
            c.notes.push(format!(
                "{} not decoded",
                count(self.encrypted, "encrypted file is", "encrypted files are")
            ));
        }
        c.notes.extend(self.problems);
        if self.more_problems > 0 {
            c.notes.push(format!(
                "{} not listed",
                count(
                    self.more_problems,
                    "further problem was",
                    "further problems were"
                )
            ));
        }
        c.push_metadata(
            "wim_streams_listed",
            "Data streams listed",
            self.listed as u64,
        );
        c.push_metadata("wim_listed_size", "Listed bytes (B)", self.extracted as u64);
        c.push_metadata(
            "wim_resources_verified",
            "Resources with a verified SHA-1",
            self.verified as u64,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_labels_keep_their_end() {
        assert_eq!(stream_label("/1", "/a/b", None), "/1/a/b");
        assert_eq!(stream_label("/1", "/a", Some("ads")), "/1/a:ads");
        let deep = format!("/{}/{}", "é".repeat(600), "file.dll");
        let shortened = stream_label("/2", &deep, None);
        assert!(shortened.len() <= MAX_LABEL);
        assert!(shortened.starts_with("/2/…"));
        assert!(shortened.ends_with("/file.dll"));
    }
}
