//! An image's metadata resource (MSWIM "WIM Metadata Resource", "Directory
//! Entry", "Alternate Stream Entry"; wimlib `src/metadata_resource.c`,
//! `src/security.c` `read_wim_security_data`, `src/dentry.c` `read_dentry`
//! and `read_dentry_tree`; 7-Zip `WimIn.cpp` `ParseImageDirs` and
//! `ParseDirItem`):
//! - The security data: total length (4, rounded up to 8; 0 means 8),
//!   descriptor count (4), the descriptors' 8-byte sizes and the
//!   descriptors. The root directory entry follows it.
//! - A directory entry: length (8, rounded up to 8; 8 or less ends the
//!   list of a directory), attributes (4), security ID (4), the offset of
//!   the directory's entries in the resource (8; 0 for none), 16 reserved
//!   bytes, three timestamps (24), the SHA-1 of the unnamed stream (20), 4
//!   unknown bytes, the reparse tag or hard link group (8), the number of
//!   stream entries (2), the short name size (2) and the name size (2):
//!   102 bytes, then the UTF-16LE name and short name, each with a NUL
//!   when not empty.
//! - Stream entries follow the entry, outside its length: length (8,
//!   rounded up to 8), 8 reserved bytes, SHA-1 (20), name size (2) and the
//!   UTF-16LE name.
//!
//! Stream types are not stored; wimlib's `assign_stream_types_unencrypted`
//! reads named entries as named data streams and the main hash (when not
//! zero) and unnamed entries, in order, as the reparse point stream of a
//! reparse point and the unnamed data stream. An encrypted file's first
//! unnamed nonzero stream is its encrypted raw data
//! (`assign_stream_types_encrypted`).

use super::*;

/// File attributes (Windows `FILE_ATTRIBUTE_*`; wimlib `inode.h`).
pub(super) const ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub(super) const ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
pub(super) const ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;

/// Directory entry fields (wimlib `struct wim_dentry_on_disk`).
const DENTRY_SIZE: usize = 102;
const ATTRIBUTES_FIELD: usize = 0x08;
const SUBDIR_FIELD: usize = 0x10;
const MAIN_HASH_FIELD: usize = 0x40;
const STREAM_COUNT_FIELD: usize = 0x60;
const SHORT_NAME_SIZE_FIELD: usize = 0x62;
const NAME_SIZE_FIELD: usize = 0x64;

/// Stream entry fields (wimlib `struct wim_extra_stream_entry_on_disk`).
const STREAM_ENTRY_SIZE: usize = 38;
const STREAM_HASH_FIELD: usize = 16;
const STREAM_NAME_SIZE_FIELD: usize = 36;

/// Security data fields.
const SECURITY_LENGTH_FIELD: usize = 0;
const SECURITY_COUNT_FIELD: usize = 4;
const SECURITY_FIXED_SIZE: u64 = 8;
const SECURITY_SIZE_ENTRY: u64 = 8;

/// Entries and their lengths are aligned to 8 bytes.
const ALIGNMENT: u64 = 8;

/// A list's end: a length of 8 or less, which occupies 8 bytes.
const END_OF_LIST_SIZE: usize = 8;

/// The terminating NUL after a name.
const NAME_TERMINATOR: usize = 2;

/// Deepest directory level below the root that the walk enters.
const MAX_DEPTH: usize = 64;

/// What a stream holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum StreamKind {
    /// The unnamed data stream: the file's contents.
    Data,
    /// A named data stream.
    Named(String),
    /// The reparse point data of a reparse point.
    Reparse,
    /// An encrypted file's raw encrypted data.
    Encrypted,
}

/// A stream of a directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Stream {
    pub(super) kind: StreamKind,
    pub(super) hash: Hash,
}

/// A directory entry.
#[derive(Debug)]
pub(super) struct Dentry {
    pub(super) attributes: u32,
    /// Offset of the directory's entries in the resource; 0 for none.
    pub(super) subdir_offset: u64,
    /// The long name; empty for the root.
    pub(super) name: String,
    /// The name has no UTF-16 unit of 0.
    name_has_nul: bool,
    pub(super) streams: Vec<Stream>,
    /// Bytes of the entry and its stream entries.
    size: usize,
}

impl Dentry {
    /// A directory that is not a reparse point (wimlib
    /// `inode_is_directory`).
    pub(super) fn is_directory(&self) -> bool {
        self.attributes & (ATTRIBUTE_DIRECTORY | ATTRIBUTE_REPARSE_POINT) == ATTRIBUTE_DIRECTORY
    }

    /// A name that wimlib keeps: not empty, `.`, `..` or with a NUL
    /// (wimlib `should_ignore_dentry`).
    fn has_valid_name(&self) -> bool {
        !self.name.is_empty() && self.name != "." && self.name != ".." && !self.name_has_nul
    }
}

/// `value` rounded up to a multiple of 8.
fn align(value: u64) -> Option<u64> {
    value
        .checked_add(ALIGNMENT - 1)
        .map(|v| v & !(ALIGNMENT - 1))
}

/// Where the root directory entry starts: after the security data, whose
/// sizes must fit its stated length (wimlib `read_wim_security_data`).
pub(super) fn root_offset(metadata: &[u8]) -> Result<usize> {
    let stated = u64::from(le_u32(metadata, SECURITY_LENGTH_FIELD)?);
    let entries = u64::from(le_u32(metadata, SECURITY_COUNT_FIELD)?);
    let total = match align(stated).expect("32-bit values do not overflow") {
        0 => SECURITY_FIXED_SIZE,
        total => total,
    };
    let sizes_end = SECURITY_FIXED_SIZE + entries * SECURITY_SIZE_ENTRY;
    if total > metadata.len() as u64 || sizes_end > total {
        return Err(error(format!(
            "Invalid WIM security data: {entries} descriptors in a length of {stated} B"
        )));
    }
    let mut used = sizes_end;
    for i in 0..entries {
        let size = le_u64(
            metadata,
            to_usize(SECURITY_FIXED_SIZE + i * SECURITY_SIZE_ENTRY, "WIM offset")?,
        )?;
        used = used
            .checked_add(size)
            .filter(|&used| used <= total)
            .ok_or_else(|| {
                error(format!(
                    "Invalid WIM security data: descriptor {i} of {size} B runs past the length of \
                     {stated} B"
                ))
            })?;
    }
    to_usize(total, "WIM security data length")
}

/// The directory entry at `offset`, or `None` for the end of a directory's
/// list (a length of 8 or less, which occupies 8 bytes).
pub(super) fn read_dentry(metadata: &[u8], offset: usize) -> Result<Option<Dentry>> {
    let length = align(le_u64(metadata, offset)?).ok_or_else(|| {
        error(format!(
            "Invalid WIM directory entry length at 0x{offset:X}"
        ))
    })?;
    if length <= ALIGNMENT {
        return Ok(None);
    }
    let length = to_usize(length, "WIM directory entry length")?;
    if length < DENTRY_SIZE {
        return Err(error(format!(
            "Invalid WIM directory entry at 0x{offset:X}: {length} B is shorter than {DENTRY_SIZE} B"
        )));
    }
    let entry = slice(metadata, offset, length, "WIM directory entry")?;
    let short_name_size = usize::from(le_u16(entry, SHORT_NAME_SIZE_FIELD)?);
    let name_size = usize::from(le_u16(entry, NAME_SIZE_FIELD)?);
    if short_name_size % 2 != 0 || name_size % 2 != 0 {
        return Err(error(format!(
            "Invalid WIM directory entry at 0x{offset:X}: odd name sizes {name_size} and \
             {short_name_size}"
        )));
    }
    let names = name_field(name_size) + name_field(short_name_size);
    if length < DENTRY_SIZE + names {
        return Err(error(format!(
            "Invalid WIM directory entry at 0x{offset:X}: {length} B cannot hold names of \
             {names} B"
        )));
    }
    let name_units = &entry[DENTRY_SIZE..DENTRY_SIZE + name_size];
    let attributes = le_u32(entry, ATTRIBUTES_FIELD)?;
    let main_hash = hash_at(entry, MAIN_HASH_FIELD)?;
    let stream_count = usize::from(le_u16(entry, STREAM_COUNT_FIELD)?);
    let mut extra = Vec::new();
    let mut next = offset + length;
    for _ in 0..stream_count {
        let stream = read_stream_entry(metadata, next)?;
        next += stream.size;
        extra.push(stream);
    }
    Ok(Some(Dentry {
        attributes,
        subdir_offset: le_u64(entry, SUBDIR_FIELD)?,
        name: utf16_name(name_units),
        name_has_nul: name_units.chunks_exact(2).any(|unit| unit == [0, 0]),
        streams: assign_streams(attributes, main_hash, extra),
        size: next - offset,
    }))
}

/// Bytes a name of `size` bytes occupies: the name and its NUL, or nothing.
fn name_field(size: usize) -> usize {
    if size == 0 {
        0
    } else {
        size + NAME_TERMINATOR
    }
}

/// A stream entry as stored: its name (if any), hash and size on disk.
struct StreamEntry {
    name: Option<String>,
    hash: Hash,
    size: usize,
}

/// The stream entry at `offset`.
fn read_stream_entry(metadata: &[u8], offset: usize) -> Result<StreamEntry> {
    let length = align(le_u64(metadata, offset)?)
        .ok_or_else(|| error(format!("Invalid WIM stream entry length at 0x{offset:X}")))?;
    let length = to_usize(length, "WIM stream entry length")?;
    if length < STREAM_ENTRY_SIZE {
        return Err(error(format!(
            "Invalid WIM stream entry at 0x{offset:X}: {length} B is shorter than \
             {STREAM_ENTRY_SIZE} B"
        )));
    }
    let entry = slice(metadata, offset, length, "WIM stream entry")?;
    let name_size = usize::from(le_u16(entry, STREAM_NAME_SIZE_FIELD)?);
    if name_size % 2 != 0 || STREAM_ENTRY_SIZE + name_size > length {
        return Err(error(format!(
            "Invalid WIM stream entry at 0x{offset:X}: a name of {name_size} B in {length} B"
        )));
    }
    let name = (name_size > 0)
        .then(|| utf16_name(&entry[STREAM_ENTRY_SIZE..STREAM_ENTRY_SIZE + name_size]));
    Ok(StreamEntry {
        name,
        hash: hash_at(entry, STREAM_HASH_FIELD)?,
        size: length,
    })
}

/// The streams of an entry, typed as wimlib types them.
fn assign_streams(attributes: u32, main_hash: Hash, extra: Vec<StreamEntry>) -> Vec<Stream> {
    let zero = [0u8; HASH_SIZE];
    let mut all =
        std::iter::once((None, main_hash)).chain(extra.into_iter().map(|e| (e.name, e.hash)));
    let mut streams = Vec::new();
    if attributes & ATTRIBUTE_ENCRYPTED != 0 {
        if let Some((_, hash)) = all.find(|(name, hash)| name.is_none() && *hash != zero) {
            streams.push(Stream {
                kind: StreamKind::Encrypted,
                hash,
            });
        }
        return streams;
    }
    let reparse_point = attributes & ATTRIBUTE_REPARSE_POINT != 0;
    let mut found_reparse = false;
    let mut found_data = false;
    for (i, (name, hash)) in all.enumerate() {
        let kind = match name {
            Some(name) => StreamKind::Named(name),
            // A zero main hash stands for nothing when an unnamed stream
            // entry follows.
            None if i == 0 && hash == zero => continue,
            None if reparse_point && !found_reparse => {
                found_reparse = true;
                StreamKind::Reparse
            }
            None if !found_data => {
                found_data = true;
                StreamKind::Data
            }
            None => continue,
        };
        streams.push(Stream { kind, hash });
    }
    streams
}

/// UTF-16LE name text; unpaired surrogates become replacement characters.
fn utf16_name(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// What a walk saw and skipped.
#[derive(Debug, Default)]
pub(super) struct WalkCensus {
    pub(super) directories: usize,
    pub(super) files: usize,
    /// Entries skipped for their names, with their subtrees.
    pub(super) invalid_names: usize,
    /// Directories not entered because they are too deep.
    pub(super) too_deep: usize,
    /// Non-directories whose entry list was ignored.
    pub(super) children_of_files: usize,
    /// Why the walk stopped early, if it did.
    pub(super) stopped: Option<String>,
}

/// One directory list being walked.
struct Frame {
    /// Offset of the next entry in the list.
    cursor: usize,
    /// Length of the directory's path in the path buffer.
    path_len: usize,
    depth: usize,
}

/// Walk the directory tree of a metadata resource in pre-order, giving
/// `visit` each entry below the root with its path (`/dir/name`). Entries
/// are read at most once per byte of the resource: a walk that would read
/// more has met a loop or overlapping lists and stops (7-Zip
/// `DirProcessed`).
pub(super) fn walk(metadata: &[u8], mut visit: impl FnMut(&str, &Dentry)) -> Result<WalkCensus> {
    let mut census = WalkCensus::default();
    let root_at = root_offset(metadata)?;
    let Some(root) = read_dentry(metadata, root_at)? else {
        return Ok(census);
    };
    if !root.is_directory() {
        return Err(error(format!(
            "Invalid WIM root at 0x{root_at:X}: not a directory (attributes 0x{:08X})",
            root.attributes
        )));
    }
    let mut processed = root.size;
    let mut path = String::new();
    let mut stack = Vec::new();
    if root.subdir_offset != 0 {
        census.directories += 1;
        stack.push(Frame {
            cursor: to_usize(root.subdir_offset, "WIM directory offset")?,
            path_len: 0,
            depth: 0,
        });
    }
    while let Some(frame) = stack.last_mut() {
        let entry = match read_dentry(metadata, frame.cursor) {
            Ok(entry) => entry,
            Err(e) => {
                census.stopped = Some(resource::message(&e));
                break;
            }
        };
        let used = entry.as_ref().map_or(END_OF_LIST_SIZE, |entry| entry.size);
        processed = processed.saturating_add(used);
        if processed > metadata.len() {
            census.stopped = Some(
                "the directory lists would read more than the resource holds (a loop or \
                 overlapping lists)"
                    .to_string(),
            );
            break;
        }
        let Some(entry) = entry else {
            stack.pop();
            continue;
        };
        frame.cursor += used;
        let (path_len, depth) = (frame.path_len, frame.depth);
        if !entry.has_valid_name() {
            census.invalid_names += 1;
            continue;
        }
        path.truncate(path_len);
        path.push('/');
        path.push_str(&entry.name);
        if entry.is_directory() {
            census.directories += 1;
        } else {
            census.files += 1;
        }
        visit(&path, &entry);
        if entry.subdir_offset == 0 {
            continue;
        }
        if !entry.is_directory() {
            census.children_of_files += 1;
        } else if depth + 1 > MAX_DEPTH {
            census.too_deep += 1;
        } else {
            stack.push(Frame {
                cursor: to_usize(entry.subdir_offset, "WIM directory offset")?,
                path_len: path.len(),
                depth: depth + 1,
            });
        }
    }
    Ok(census)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash {
        [byte; HASH_SIZE]
    }

    fn entry(name: Option<&str>, byte: u8) -> StreamEntry {
        StreamEntry {
            name: name.map(str::to_string),
            hash: hash(byte),
            size: 40,
        }
    }

    #[test]
    fn streams_are_typed_as_wimlib_types_them() {
        let plain = assign_streams(0, hash(1), vec![entry(Some("ads"), 2)]);
        assert_eq!(
            plain,
            vec![
                Stream {
                    kind: StreamKind::Data,
                    hash: hash(1)
                },
                Stream {
                    kind: StreamKind::Named("ads".to_string()),
                    hash: hash(2)
                },
            ]
        );
        // A zero main hash and an unnamed entry: the entry is the data.
        let unnamed = assign_streams(0, hash(0), vec![entry(None, 3)]);
        assert_eq!(unnamed[0].kind, StreamKind::Data);
        assert_eq!(unnamed[0].hash, hash(3));
        // A reparse point: the first unnamed stream is the reparse data.
        let reparse = assign_streams(ATTRIBUTE_REPARSE_POINT, hash(4), vec![entry(None, 5)]);
        assert_eq!(reparse[0].kind, StreamKind::Reparse);
        assert_eq!(reparse[1].kind, StreamKind::Data);
        // An encrypted file has one raw stream.
        let encrypted = assign_streams(ATTRIBUTE_ENCRYPTED, hash(6), vec![entry(Some("x"), 7)]);
        assert_eq!(
            encrypted,
            vec![Stream {
                kind: StreamKind::Encrypted,
                hash: hash(6)
            }]
        );
    }

    #[test]
    fn security_data_must_fit_its_length() {
        let mut data = vec![0u8; 64];
        data[0] = 24;
        data[4] = 1;
        data[8] = 8;
        assert_eq!(root_offset(&data).unwrap(), 24);
        data[8] = 9;
        assert!(root_offset(&data).is_err());
        data[0] = 0;
        data[4] = 0;
        assert_eq!(root_offset(&data).unwrap(), 8);
        data[4] = 9;
        assert!(root_offset(&data).is_err());
    }

    #[test]
    fn lengths_of_eight_or_less_end_a_list() {
        let mut data = vec![0u8; 16];
        assert!(read_dentry(&data, 0).unwrap().is_none());
        data[0] = 7;
        assert!(read_dentry(&data, 0).unwrap().is_none());
        data[0] = 9;
        assert!(read_dentry(&data, 0).is_err());
        assert!(read_dentry(&data, 12).is_err());
    }
}
