//! The directory walk: file identifier descriptors (ECMA-167 4/14.4; UDF
//! 2.60 2.3.4) read from each directory's data space, from the root
//! directory down. Every ICB is examined once, so repeated or cyclic
//! references cannot loop; regular files that start with a recognized
//! format become members labeled by their path.

use super::entry::{self, Entry, Piece};
use super::text;
use super::*;
use crate::formats::container::{self, Child, MAX_COMPONENTS, MAX_EXTRACTED};
use crate::formats::MAX_PAYLOAD;
use std::borrow::Cow;
use std::collections::HashSet;

/// Bytes of a regular file read to decide whether it is a recognized
/// format.
const PROBE_SIZE: usize = 4096;

/// Deepest directory level below the root that the walk enters (ours).
const MAX_DEPTH: usize = 64;

/// Longest member path that is walked (Linux `PATH_MAX`).
const MAX_PATH: usize = 4096;

/// Most directories walked in one volume (ours).
const MAX_DIRECTORIES: usize = 1 << 16;

/// Largest directory read (ours).
const MAX_DIRECTORY_SIZE: usize = 64 << 20;

/// Problems reported one by one; further ones are counted.
const MAX_PROBLEM_NOTES: usize = 16;

/// Transform named for a file whose extents are not stored contiguously,
/// or hold unrecorded (zero) extents, and were reassembled.
const EXTENTS_TRANSFORM: &str = "UDF extents";

/// File identifier descriptor fields (4/14.4 figure 4/12): characteristics
/// (18), identifier length `L_FI` (19), ICB (20, `long_ad`), implementation
/// use length `L_IU` (36), implementation use (38), identifier (38 +
/// `L_IU`).
const FID_CHARACTERISTICS: usize = 18;
const FID_IDENTIFIER_LENGTH: usize = 19;
const FID_ICB: usize = 20;
const FID_USE_LENGTH: usize = 36;
const FID_HEADER: usize = 38;

/// File characteristics (4/14.4.3 figure 4/13).
const CHARACTERISTIC_DELETED: u8 = 0x04;
const CHARACTERISTIC_PARENT: u8 = 0x08;

/// File types that are not walked (4/14.6.6 figure 4/17; UDF 2.60
/// 2.3.5.2).
const FILE_TYPE_SYMLINK: u8 = 12;
const FILE_TYPE_REAL_TIME: u8 = 249;

/// One file identifier descriptor.
#[derive(Debug)]
struct Fid<'d> {
    /// Total length, padded to a multiple of 4 (4/14.4.9).
    length: usize,
    characteristics: u8,
    /// The ICB of the file it identifies.
    icb: LongAd,
    /// The file identifier in OSTA CS0.
    identifier: &'d [u8],
}

/// Parse the descriptor at the start of `bytes`, at file offset `offset`,
/// with the checks of Linux `udf_verify_fi`: tag 257, an implementation use
/// length that is a multiple of 4, and a length within the directory and
/// within one block (UDF 2.60 2.3.4).
fn parse_fid(bytes: &[u8], offset: u64, block_size: usize) -> Result<Fid<'_>> {
    let at = offset_text(offset);
    if bytes.len() < FID_HEADER {
        return Err(error(format!(
            "Truncated file identifier descriptor at {at}: {} B left in the directory",
            bytes.len()
        )));
    }
    let identifier_length = usize::from(byte(bytes, FID_IDENTIFIER_LENGTH)?);
    let use_length = usize::from(le_u16(bytes, FID_USE_LENGTH)?);
    if use_length % 4 != 0 {
        return Err(error(format!(
            "Invalid file identifier descriptor at {at}: implementation use of {use_length} B is \
             not a multiple of 4"
        )));
    }
    let unpadded = FID_HEADER + use_length + identifier_length;
    let length = unpadded + (4 - unpadded % 4) % 4;
    if length > block_size || length > bytes.len() {
        return Err(error(format!(
            "Invalid file identifier descriptor at {at}: {length} B with {} B left in the \
             directory and {block_size} B blocks",
            bytes.len()
        )));
    }
    let descriptor = &bytes[..length];
    let tag = read_tag(
        descriptor,
        usize::try_from(offset).unwrap_or(usize::MAX),
        None,
    )?;
    if tag.identifier != TAG_FILE_IDENTIFIER {
        return Err(error(format!(
            "Invalid file identifier descriptor at {at}: tag identifier {}",
            tag.identifier
        )));
    }
    let name_start = FID_HEADER + use_length;
    Ok(Fid {
        length,
        characteristics: descriptor[FID_CHARACTERISTICS],
        icb: LongAd::read(descriptor, FID_ICB)?,
        identifier: &descriptor[name_start..name_start + identifier_length],
    })
}

/// A file offset for messages.
fn offset_text(offset: u64) -> String {
    format!("0x{offset:X}")
}

/// A path component from a file identifier: OSTA CS0 text that names a
/// file, not `.`, `..` or a string with `/` or NUL.
fn component(identifier: &[u8]) -> std::result::Result<String, String> {
    let Some(name) = text::cs0(identifier) else {
        let compression = identifier.first().copied().unwrap_or(0);
        return Err(format!(
            "file identifier with compression ID {compression} is not OSTA CS0 text"
        ));
    };
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(format!("name {name:?} is not a path component"));
    }
    Ok(name)
}

/// A directory's bytes: all of its data space, or the part before the end
/// of the input of a truncated volume.
struct DirectoryData<'a> {
    bytes: Cow<'a, [u8]>,
    /// The pieces the bytes came from, to map positions to file offsets.
    pieces: Vec<Piece>,
    /// The data space passes the end of the input.
    cut: bool,
}

impl DirectoryData<'_> {
    /// The file offset of directory byte `position`, if it is stored.
    fn file_offset(&self, position: usize) -> Option<u64> {
        let mut start = 0u64;
        let position = position as u64;
        for piece in &self.pieces {
            let end = start + piece.length();
            if position < end {
                return match *piece {
                    Piece::Stored { offset, .. } => Some(offset + (position - start)),
                    Piece::Zeros { .. } => None,
                };
            }
            start = end;
        }
        None
    }
}

/// The present bytes of the directory `entry`. The bytes it can map are
/// charged to the descriptor read budget first: no more of a directory than
/// the input holds can be present.
fn directory_data<'a>(fs: &Filesystem<'a>, entry: &Entry) -> ReadResult<DirectoryData<'a>> {
    if entry.information_length > MAX_DIRECTORY_SIZE as u64 {
        return invalid(format!(
            "directory of {} B exceeds the {} read",
            entry.information_length,
            size_text(MAX_DIRECTORY_SIZE)
        ));
    }
    let data = fs.disc.data;
    let readable = entry.information_length.min(data.len() as u64);
    fs.disc
        .charge(usize::try_from(readable).expect("at most the input size"))?;
    let all = entry::pieces(&fs.disc, &fs.partitions, entry, readable)?;
    let mut present = Vec::with_capacity(all.len());
    let mut cut = readable < entry.information_length;
    for piece in all {
        if entry::is_present(data, std::slice::from_ref(&piece)) {
            present.push(piece);
            continue;
        }
        // The input ends inside the directory: keep the stored bytes before
        // the end.
        cut = true;
        if let Piece::Stored { offset, .. } = piece {
            if let Some(length) = (data.len() as u64).checked_sub(offset).filter(|&n| n > 0) {
                present.push(Piece::Stored { offset, length });
            }
        }
        break;
    }
    let bytes = match present.as_slice() {
        [Piece::Stored { offset, length }] => {
            Cow::Borrowed(entry::stored(fs.disc.data, *offset, *length)?)
        }
        pieces => Cow::Owned(entry::assemble(fs.disc.data, pieces)?),
    };
    Ok(DirectoryData {
        bytes,
        pieces: present,
        cut,
    })
}

/// Whether the root directory's data is present and its first file
/// identifier descriptor verifies, for the detection of bridge discs.
pub(super) fn root_is_readable(fs: &Filesystem<'_>) -> bool {
    let Ok(directory) = directory_data(fs, &fs.root) else {
        return false;
    };
    if directory.cut {
        return false;
    }
    directory.bytes.is_empty()
        || parse_fid(
            &directory.bytes,
            directory.file_offset(0).unwrap_or(0),
            fs.disc.sector_size,
        )
        .is_ok()
}

/// A directory waiting to be read.
struct PendingDirectory {
    entry: Entry,
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
    symlinks: usize,
    special: usize,
    real_time: usize,
    transformed: usize,
    with_streams: usize,
    deleted: usize,
    repeated: usize,
    unwalked: usize,
    over_walk_limit: usize,
    over_component_limit: usize,
    over_budget: usize,
    too_large: usize,
    /// Directories whose data lies partly or wholly past the end of the
    /// input.
    absent_directories: usize,
    /// File entries past the end of the input.
    absent_entries: usize,
    /// Regular files whose data lies partly or wholly past the end of the
    /// input.
    absent_files: usize,
    problems: Vec<String>,
    unlisted_problems: usize,
}

struct Walker<'f, 'a> {
    fs: &'f Filesystem<'a>,
    nodes: Vec<PathNode>,
    /// ICBs examined, so each file entry is read once.
    visited: HashSet<Address>,
    census: Census,
    members: Vec<Child<'a>>,
    /// Bytes probed and listed, bounded by [`MAX_EXTRACTED`].
    extracted: usize,
}

/// Walk the directory hierarchy from the root and append the members and
/// notes to `c`.
pub(super) fn walk<'a>(fs: &Filesystem<'a>, c: &mut Container<'a>) {
    let mut walker = Walker {
        fs,
        nodes: vec![PathNode {
            parent: 0,
            name: String::new(),
        }],
        visited: HashSet::from([fs.file_set.root, fs.root.address]),
        census: Census::default(),
        members: Vec::new(),
        extracted: 0,
    };
    let mut pending = vec![PendingDirectory {
        entry: fs.root.clone(),
        node: 0,
        depth: 0,
    }];
    while let Some(directory) = pending.pop() {
        if walker.census.directories >= MAX_DIRECTORIES || fs.disc.is_exhausted() {
            walker.census.over_walk_limit = pending.len() + 1;
            break;
        }
        let subdirectories = walker.directory(&directory);
        // Reversed, so that subdirectories are walked in identifier order.
        pending.extend(subdirectories.into_iter().rev());
    }
    walker.finish(c);
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

    /// Read one directory's file identifier descriptors and return its
    /// subdirectories in identifier order.
    fn directory(&mut self, directory: &PendingDirectory) -> Vec<PendingDirectory> {
        self.census.directories += 1;
        let path = self.path(directory.node, None);
        let data = match directory_data(self.fs, &directory.entry) {
            Ok(data) => data,
            Err(Fault::Absent) => {
                self.census.absent_directories += 1;
                return Vec::new();
            }
            Err(Fault::Invalid(_)) if self.fs.disc.is_exhausted() => {
                self.census.over_walk_limit += 1;
                return Vec::new();
            }
            Err(Fault::Invalid(e)) => {
                self.problem(format!("{path}: directory not read: {}", message(e)));
                return Vec::new();
            }
        };
        if data.cut {
            self.census.absent_directories += 1;
        }
        let mut subdirectories = Vec::new();
        let mut position = 0;
        while position < data.bytes.len() {
            let rest = &data.bytes[position..];
            let offset = data.file_offset(position).unwrap_or(0);
            let fid = match parse_fid(rest, offset, self.fs.disc.sector_size) {
                Ok(fid) => fid,
                // The input ends inside the directory: the last
                // descriptor is cut, not damaged.
                Err(_) if data.cut => break,
                Err(e) => {
                    self.problem(format!(
                        "{path}: {}; the rest of the directory is not read",
                        message(e)
                    ));
                    break;
                }
            };
            position += fid.length;
            self.identifier(directory, &fid, &mut subdirectories);
        }
        subdirectories
    }

    /// One file identifier descriptor: a subdirectory, a file, or an entry
    /// that is skipped and counted.
    fn identifier(
        &mut self,
        directory: &PendingDirectory,
        fid: &Fid<'_>,
        subdirectories: &mut Vec<PendingDirectory>,
    ) {
        if fid.characteristics & CHARACTERISTIC_PARENT != 0 {
            return;
        }
        if fid.characteristics & CHARACTERISTIC_DELETED != 0 {
            self.census.deleted += 1;
            return;
        }
        let name = match component(fid.identifier) {
            Ok(name) => name,
            Err(reason) => {
                let path = self.path(directory.node, None);
                self.problem(format!("{path}: entry skipped: {reason}"));
                return;
            }
        };
        let path = self.path(directory.node, Some(&name));
        if path.len() > MAX_PATH {
            self.census.unwalked += 1;
            return;
        }
        if fid.icb.length == 0 {
            self.problem(format!("{path}: no ICB is recorded"));
            return;
        }
        if !self.visited.insert(fid.icb.location) {
            self.census.repeated += 1;
            return;
        }
        let entry = match Entry::read(&self.fs.disc, &self.fs.partitions, fid.icb.location) {
            Ok(entry) => entry,
            Err(Fault::Absent) => {
                self.census.absent_entries += 1;
                return;
            }
            Err(Fault::Invalid(e)) => {
                self.problem(format!("{path}: file entry not read: {}", message(e)));
                return;
            }
        };
        self.census.with_streams += usize::from(entry.has_streams);
        if entry.is_directory() {
            if directory.depth + 1 > MAX_DEPTH {
                self.census.unwalked += 1;
                return;
            }
            let node = self.nodes.len();
            self.nodes.push(PathNode {
                parent: directory.node,
                name,
            });
            subdirectories.push(PendingDirectory {
                entry,
                node,
                depth: directory.depth + 1,
            });
        } else if entry.is_regular() {
            self.file(&entry, path);
        } else if entry.file_type == FILE_TYPE_SYMLINK {
            self.census.symlinks += 1;
        } else if entry.file_type == FILE_TYPE_REAL_TIME {
            self.census.real_time += 1;
        } else {
            self.census.special += 1;
        }
    }

    /// A regular file: probe its first bytes and, when they are a
    /// recognized format, list the whole file.
    fn file(&mut self, entry: &Entry, path: String) {
        self.census.files += 1;
        if entry.transformed {
            self.census.transformed += 1;
            return;
        }
        if entry.information_length == 0 {
            return;
        }
        if self.members.len() >= MAX_COMPONENTS {
            self.census.over_component_limit += 1;
            return;
        }
        let probe_size =
            PROBE_SIZE.min(usize::try_from(entry.information_length).unwrap_or(PROBE_SIZE));
        if !self.charge(probe_size) {
            self.census.over_budget += 1;
            return;
        }
        let Some(prefix) = self.present_data(entry, probe_size as u64, &path) else {
            return;
        };
        // `present_data` checked that the pieces lie in the input.
        let Ok(prefix) = entry::assemble(self.fs.disc.data, &prefix) else {
            return;
        };
        if !container::is_recognized(&prefix) {
            return;
        }
        if entry.information_length > MAX_PAYLOAD as u64 {
            self.census.too_large += 1;
            return;
        }
        // The whole file is charged before its extents are mapped, so the
        // mapping is bounded by the extraction limit too.
        let total = usize::try_from(entry.information_length).expect("at most MAX_PAYLOAD");
        if !self.charge(total - probe_size) {
            self.census.over_budget += 1;
            return;
        }
        let Some(pieces) = self.present_data(entry, entry.information_length, &path) else {
            return;
        };
        if let Some(member) = member(self.fs.disc.data, path, &pieces) {
            self.members.push(member.if_recognized());
        }
    }

    /// The pieces of the first `length` bytes of `entry`'s data, when all
    /// of them lie in the input; otherwise `None`, counted or reported.
    fn present_data(&mut self, entry: &Entry, length: u64, path: &str) -> Option<Vec<Piece>> {
        let fs = self.fs;
        match entry::pieces(&fs.disc, &fs.partitions, entry, length) {
            Ok(pieces) if entry::is_present(fs.disc.data, &pieces) => Some(pieces),
            Ok(_) | Err(Fault::Absent) => {
                self.census.absent_files += 1;
                None
            }
            Err(Fault::Invalid(e)) => {
                self.problem(format!("{path}: data not read: {}", message(e)));
                None
            }
        }
    }

    /// Append the members to `c` and record what was found and left out.
    fn finish(self, c: &mut Container<'a>) {
        let census = &self.census;
        let present = self.fs.disc.present_text();
        c.notes.push(format!(
            "{} regular files in {} directories; {} recognized members listed; members are \
             recognized from their first {}",
            census.files,
            census.directories,
            self.members.len(),
            size_text(PROBE_SIZE)
        ));
        let counted = [
            (
                census.over_component_limit,
                format!(
                    "further regular files were not examined: member limit reached \
                     ({MAX_COMPONENTS} members)"
                ),
            ),
            (
                census.over_budget,
                format!(
                    "regular files were not examined or extracted: extraction limit reached ({})",
                    size_text(MAX_EXTRACTED)
                ),
            ),
            (
                census.too_large,
                format!(
                    "recognized regular files exceed the {} member limit and are not listed",
                    size_text(MAX_PAYLOAD)
                ),
            ),
            (
                census.over_walk_limit,
                format!(
                    "directories were not walked: walk limit reached ({MAX_DIRECTORIES} \
                     directories or {METADATA_READ_FACTOR} times the {present} input in \
                     descriptors)"
                ),
            ),
            (
                census.absent_directories,
                format!(
                    "directories lie partly or wholly past the end of the {present} input; their \
                     descriptors past it were not read"
                ),
            ),
            (
                census.absent_entries,
                format!("file entries lie past the end of the {present} input and were not read"),
            ),
            (
                census.absent_files,
                format!(
                    "regular files were not listed: file data lies partly or wholly past the end \
                     of the {present} input"
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
                "directory entries name an ICB already examined; it is not read again".to_string(),
            ),
            (
                census.deleted,
                "deleted directory entries are skipped".to_string(),
            ),
            (
                census.symlinks,
                "symbolic links are not followed".to_string(),
            ),
            (
                census.special,
                "devices, FIFOs, sockets and other special files are not read".to_string(),
            ),
            (
                census.real_time,
                "real-time files (file type 249) are not read, as UDF 2.60 2.3.5.2.1 requires"
                    .to_string(),
            ),
            (
                census.transformed,
                "files with transformed data (ICB flag bit 11 or partly recorded extended \
                 allocation descriptors) are not read"
                    .to_string(),
            ),
            (
                census.with_streams,
                "entries carry named streams (a stream directory); streams are not read"
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
        c.push_metadata("udf_regular_files", "Regular files", census.files as u64);
        c.push_metadata("udf_directories", "Directories", census.directories as u64);
        c.push_metadata(
            "udf_member_count",
            "Recognized members",
            self.members.len() as u64,
        );
        c.children.extend(self.members);
    }
}

/// A file as a member: borrowed when its data is stored in one piece,
/// otherwise reassembled with its stored size that of the first stored
/// piece. `None` for data without a stored piece.
fn member<'a>(data: &'a [u8], path: String, pieces: &[Piece]) -> Option<Child<'a>> {
    let (first_offset, first_length) = pieces.iter().find_map(|piece| match *piece {
        Piece::Stored { offset, length } => Some((offset, length)),
        Piece::Zeros { .. } => None,
    })?;
    let offset = usize::try_from(first_offset).ok()?;
    if let [Piece::Stored { length, .. }] = pieces {
        let bytes = entry::stored(data, first_offset, *length).ok()?;
        return Some(Child::stored(path, offset, bytes));
    }
    let bytes = entry::assemble(data, pieces).ok()?;
    let stored_size = usize::try_from(first_length).ok()?;
    Some(Child::decoded(
        path,
        offset,
        stored_size,
        Cow::Owned(bytes),
        EXTENTS_TRANSFORM,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components_are_cs0_names_without_separators() {
        assert_eq!(
            component(b"\x08kernel.macho").as_deref(),
            Ok("kernel.macho")
        );
        assert!(component(b"\x08a/b").is_err());
        assert!(component(b"\x08..").is_err());
        assert!(component(&[254, b'x']).is_err());
        assert!(component(&[]).is_err());
    }

    #[test]
    fn members_borrow_one_piece_and_reassemble_others() {
        let data: Vec<u8> = (0..64).collect();
        let one = member(
            &data,
            "/a".into(),
            &[Piece::Stored {
                offset: 8,
                length: 4,
            }],
        )
        .expect("stored");
        assert!(matches!(one.data, Cow::Borrowed(_)));
        assert_eq!((one.offset, one.stored_size), (8, 4));
        let split = member(
            &data,
            "/b".into(),
            &[
                Piece::Stored {
                    offset: 8,
                    length: 2,
                },
                Piece::Zeros { length: 2 },
                Piece::Stored {
                    offset: 40,
                    length: 1,
                },
            ],
        )
        .expect("reassembled");
        assert_eq!(split.data.as_ref(), &[8, 9, 0, 0, 40]);
        assert_eq!(split.transform, Some(EXTENTS_TRANSFORM));
        assert_eq!((split.offset, split.stored_size), (8, 2));
        assert!(member(&data, "/c".into(), &[Piece::Zeros { length: 4 }]).is_none());
    }
}
