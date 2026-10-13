//! Electron ASAR archives.
//!
//! Layout (asar v4.3.1 `README.md` "Format", `src/disk.ts`
//! `createFilesystemWriteStream` and `readArchiveHeaderSync`,
//! `src/pickle.ts`), all integers little-endian as Chromium's `Pickle`
//! writes them:
//!
//! - 0: the size pickle's payload size, 4 (the pickle holds one `uint32`).
//! - 4: `header_size`, the size of the header pickle.
//! - 8: the header pickle's payload size, `header_size - 4`.
//! - 12: the JSON string's length in bytes (`writeString`).
//! - 16: the UTF-8 JSON header, zero-padded to a 4-byte boundary, so
//!   `header_size = 8 + align4(length)`.
//! - `8 + header_size`: the file data; each file's `offset` counts from
//!   here.
//!
//! The JSON header is a directory tree (`validateHeader`): the root and
//! every directory are `{"files": {name: entry}}`; a file has `offset` (a
//! decimal string), `size`, optional `executable` and `unpacked` (stored in
//! `<archive>.asar.unpacked`, not in the archive) and optional `integrity`
//! (`algorithm` `SHA256`, the hex `hash` of the whole file, `blockSize`
//! and the hex hashes of its `blocks`); a link is `{"link": path}`.
//! Electron reads `size` as an integer (`archive.cc`
//! `FillFileInfoWithNode`).

use super::*;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Size of the size pickle: its payload size and `header_size`.
const SIZE_PICKLE_SIZE: usize = 8;

/// The size pickle's payload: one `uint32`.
const SIZE_PICKLE_PAYLOAD: u32 = 4;

/// Header fields: the header pickle's payload size and the string length.
const HEADER_PAYLOAD_SIZE: usize = 8;
const STRING_LENGTH: usize = 12;

/// File offset of the JSON string.
const JSON_START: usize = 16;

/// Bytes of the header pickle before its string: its payload size and the
/// string length.
const HEADER_PICKLE_OVERHEAD: usize = 8;

/// Pickle payloads are aligned to `uint32` (`pickle.ts` `alignInt`).
const PICKLE_ALIGNMENT: usize = 4;

/// The integrity algorithm asar writes (`integrity.ts`).
const SHA256_ALGORITHM: &str = "SHA256";

/// Most nested directories walked. The JSON parser already stops at 128
/// levels of nesting, two per directory.
const MAX_DEPTH: usize = 64;

/// Most file bytes hashed to check integrity.
const MAX_HASHED: usize = MAX_EXTRACTED;

/// The header pickle and the JSON string.
#[derive(Debug)]
struct Header<'a> {
    /// `header_size`: bytes of the header pickle.
    header_size: usize,
    /// The JSON string's bytes.
    json: &'a [u8],
}

impl Header<'_> {
    /// File offset where file data starts.
    fn data_start(&self) -> usize {
        SIZE_PICKLE_SIZE + self.header_size
    }
}

/// Whether `length` bytes of string, padded, make a header pickle of
/// `header_size` bytes.
fn is_padded_string(length: u32, header_size: u32) -> bool {
    let length = to_usize(length);
    let padding = (PICKLE_ALIGNMENT - length % PICKLE_ALIGNMENT) % PICKLE_ALIGNMENT;
    length
        .checked_add(HEADER_PICKLE_OVERHEAD + padding)
        .is_some_and(|size| size == to_usize(header_size))
}

/// The size pickle's payload size, 4; a header pickle payload size of
/// `header_size - 4`; a string length that, padded to four bytes, fills
/// the header pickle; and JSON that starts with the root `files` object.
/// Runs on every input, so it reads the fixed fields without building
/// errors.
pub(super) fn detect(data: &[u8]) -> bool {
    let Some(fixed) = data.get(..JSON_START) else {
        return false;
    };
    let field = |at: usize| {
        u32::from_le_bytes(
            fixed[at..at + 4]
                .try_into()
                .expect("a field of the 16-byte header"),
        )
    };
    let header_size = field(4);
    field(0) == SIZE_PICKLE_PAYLOAD
        && field(HEADER_PAYLOAD_SIZE).checked_add(SIZE_PICKLE_PAYLOAD) == Some(header_size)
        && is_padded_string(field(STRING_LENGTH), header_size)
        && starts_with_files_object(&data[JSON_START..])
}

/// JSON whitespace (RFC 8259, section 2).
fn is_json_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// Whether `json` starts `{"files":{`, with optional whitespace between
/// the tokens.
fn starts_with_files_object(json: &[u8]) -> bool {
    let mut rest = json;
    for token in [&b"{"[..], b"\"files\"", b":", b"{"] {
        let start = rest
            .iter()
            .position(|&b| !is_json_space(b))
            .unwrap_or(rest.len());
        rest = &rest[start..];
        let Some(after) = rest.strip_prefix(token) else {
            return false;
        };
        rest = after;
    }
    true
}

/// Read and check the two pickles.
fn read_header(data: &[u8]) -> Result<Header<'_>> {
    let fixed = slice(data, 0, JSON_START, "ASAR header")?;
    let size_payload = le_u32(fixed, 0, "ASAR header")?;
    if size_payload != SIZE_PICKLE_PAYLOAD {
        return Err(error(format!(
            "Invalid ASAR size pickle payload size {size_payload} (expected 4)"
        )));
    }
    let header_size = le_u32(fixed, 4, "ASAR header")?;
    let header_payload = le_u32(fixed, HEADER_PAYLOAD_SIZE, "ASAR header")?;
    if header_payload.checked_add(SIZE_PICKLE_PAYLOAD) != Some(header_size) {
        return Err(error(format!(
            "Invalid ASAR header pickle payload size {header_payload} B for a {header_size} B \
             header pickle"
        )));
    }
    let length = le_u32(fixed, STRING_LENGTH, "ASAR header")?;
    if !is_padded_string(length, header_size) {
        return Err(error(format!(
            "Invalid ASAR header string length {length} B for a {header_size} B header pickle"
        )));
    }
    let header_size = to_usize(header_size);
    let available = data.len() - SIZE_PICKLE_SIZE;
    if header_size > available {
        return Err(error(format!(
            "Truncated ASAR header: {header_size} B declared, {available} B present"
        )));
    }
    // The padded string fills the header pickle, which ends inside `data`.
    Ok(Header {
        header_size,
        json: &data[JSON_START..JSON_START + to_usize(length)],
    })
}

/// A file stored in the archive.
#[derive(Debug)]
struct File {
    /// Path from the archive root, `/`-separated.
    path: String,
    /// Offset from the start of the file data.
    offset: u64,
    /// Size in bytes.
    size: u64,
    /// `integrity.algorithm` and `integrity.hash`, when present.
    integrity: Option<Integrity>,
}

/// A file's declared integrity.
#[derive(Debug)]
struct Integrity {
    algorithm: String,
    hash: String,
}

/// What the header's directory tree holds.
#[derive(Debug, Default)]
struct Tree {
    /// Files stored in the archive.
    files: Vec<File>,
    /// Files stored next to the archive, in `<archive>.asar.unpacked`.
    unpacked: usize,
    /// Symbolic links.
    links: usize,
    /// Directories below the root.
    directories: usize,
    /// Files marked executable.
    executables: usize,
}

/// Walk the directory `files` at `path` (empty for the root), `depth`
/// levels down.
fn walk(files: &Map<String, Value>, path: &str, depth: usize, tree: &mut Tree) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(error(format!(
            "Invalid ASAR header: directories nested deeper than {MAX_DEPTH} levels at /{path}"
        )));
    }
    for (name, entry) in files {
        if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
            return Err(error(format!(
                "Invalid ASAR entry name {} in /{path}",
                display_name(name.as_bytes())
            )));
        }
        let entry_path = if path.is_empty() {
            name.clone()
        } else {
            format!("{path}/{name}")
        };
        let Some(entry) = entry.as_object() else {
            return Err(entry_error(&entry_path, "entry is not an object"));
        };
        if entry.contains_key("link") {
            expect_link(entry, &entry_path)?;
            tree.links += 1;
        } else if let Some(children) = entry.get("files") {
            let Some(children) = children.as_object() else {
                return Err(entry_error(&entry_path, "files is not an object"));
            };
            tree.directories += 1;
            walk(children, &entry_path, depth + 1, tree)?;
        } else {
            read_file(entry, entry_path, tree)?;
        }
    }
    Ok(())
}

fn entry_error(path: &str, what: &str) -> ClassifierError {
    error(format!(
        "Invalid ASAR entry /{}: {what}",
        display_name(path.as_bytes())
    ))
}

/// A link names a non-empty target path.
fn expect_link(entry: &Map<String, Value>, path: &str) -> Result<()> {
    match entry.get("link").and_then(Value::as_str) {
        Some(target) if !target.is_empty() => Ok(()),
        _ => Err(entry_error(path, "link is not a non-empty string")),
    }
}

/// A file entry: `size`, then either `unpacked: true` or a decimal
/// `offset`, and optional `executable` and `integrity` (`disk.ts`
/// `validateFileEntry`, `validateUnpackedFileEntry`).
fn read_file(entry: &Map<String, Value>, path: String, tree: &mut Tree) -> Result<()> {
    let size = entry
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| entry_error(&path, "size is not a non-negative integer"))?;
    let unpacked = optional_bool(entry, "unpacked", &path)?;
    if optional_bool(entry, "executable", &path)? {
        tree.executables += 1;
    }
    let integrity = read_integrity(entry, &path)?;
    if unpacked {
        tree.unpacked += 1;
        return Ok(());
    }
    let offset = match entry.get("offset") {
        Some(Value::String(text))
            if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) =>
        {
            text.parse::<u64>()
                .map_err(|_| entry_error(&path, "offset does not fit in 64 bits"))?
        }
        Some(_) => return Err(entry_error(&path, "offset is not a decimal string")),
        None => {
            return Err(entry_error(
                &path,
                "neither a directory, a file with an offset, an unpacked file nor a link",
            ))
        }
    };
    tree.files.push(File {
        path,
        offset,
        size,
        integrity,
    });
    Ok(())
}

/// An optional boolean field; absent is false.
fn optional_bool(entry: &Map<String, Value>, key: &str, path: &str) -> Result<bool> {
    match entry.get(key) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(entry_error(path, &format!("{key} is not a boolean"))),
    }
}

/// `integrity`, when present: `algorithm` and `hash` strings, a positive
/// `blockSize` and a `blocks` array of strings (`disk.ts`
/// `validateIntegrity`).
fn read_integrity(entry: &Map<String, Value>, path: &str) -> Result<Option<Integrity>> {
    let Some(integrity) = entry.get("integrity") else {
        return Ok(None);
    };
    let integrity = integrity
        .as_object()
        .ok_or_else(|| entry_error(path, "integrity is not an object"))?;
    let text = |key: &str| {
        integrity
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| entry_error(path, &format!("integrity.{key} is not a string")))
    };
    let algorithm = text("algorithm")?;
    let hash = text("hash")?;
    let block_size_ok = integrity
        .get("blockSize")
        .and_then(Value::as_f64)
        .is_some_and(|size| size > 0.0);
    if !block_size_ok {
        return Err(entry_error(
            path,
            "integrity.blockSize is not a positive number",
        ));
    }
    let blocks_ok = integrity
        .get("blocks")
        .and_then(Value::as_array)
        .is_some_and(|blocks| blocks.iter().all(Value::is_string));
    if !blocks_ok {
        return Err(entry_error(
            path,
            "integrity.blocks is not an array of strings",
        ));
    }
    Ok(Some(Integrity { algorithm, hash }))
}

/// A stored file's bytes, located in the file.
#[derive(Debug)]
struct Located<'f, 'd> {
    file: &'f File,
    /// File offset of the bytes.
    start: usize,
    bytes: &'d [u8],
}

/// Place every stored file in the input: its range must end inside it.
fn locate<'f, 'd>(
    data: &'d [u8],
    header: &Header<'_>,
    files: &'f [File],
) -> Result<Vec<Located<'f, 'd>>> {
    let base = header.data_start() as u64;
    files
        .iter()
        .map(|file| {
            let start = base.checked_add(file.offset);
            let end = start.and_then(|start| start.checked_add(file.size));
            match (start, end) {
                (Some(start), Some(end)) if end <= data.len() as u64 => {
                    let start = usize::try_from(start).expect("below the input length");
                    let end = usize::try_from(end).expect("below the input length");
                    Ok(Located {
                        file,
                        start,
                        bytes: &data[start..end],
                    })
                }
                _ => Err(error(format!(
                    "Invalid ASAR file range for /{}: offset {} + {} B from 0x{:X} ends past the \
                     end of the archive at 0x{:X}",
                    display_name(file.path.as_bytes()),
                    file.offset,
                    file.size,
                    header.data_start(),
                    data.len()
                ))),
            }
        })
        .collect()
}

/// Outcome of checking the declared SHA-256 hashes.
#[derive(Debug, Default)]
struct IntegrityCheck {
    verified: usize,
    mismatched: Vec<String>,
    /// Not hashed because [`MAX_HASHED`] bytes were hashed.
    unchecked: usize,
    unsupported: usize,
    absent: usize,
}

/// Hash each stored file whose integrity names SHA-256, up to
/// [`MAX_HASHED`] bytes in all.
fn check_integrity(files: &[Located<'_, '_>]) -> IntegrityCheck {
    let mut check = IntegrityCheck::default();
    let mut hashed = 0usize;
    for located in files {
        let Some(integrity) = &located.file.integrity else {
            check.absent += 1;
            continue;
        };
        if integrity.algorithm != SHA256_ALGORITHM {
            check.unsupported += 1;
            continue;
        }
        match hashed.checked_add(located.bytes.len()) {
            Some(total) if total <= MAX_HASHED => hashed = total,
            _ => {
                check.unchecked += 1;
                continue;
            }
        }
        let digest = hex::encode(Sha256::digest(located.bytes));
        if digest.eq_ignore_ascii_case(&integrity.hash) {
            check.verified += 1;
        } else {
            check
                .mismatched
                .push(display_name(located.file.path.as_bytes()));
        }
    }
    check
}

/// Parse an ASAR archive: the header pickle, the JSON tree, every stored
/// file's range and integrity, and the files in a recognized format as
/// members.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = read_header(data)?;
    let root: Value = serde_json::from_slice(header.json)
        .map_err(|e| error(format!("Invalid ASAR header JSON ({e})")))?;
    let Some(files) = root.get("files").and_then(Value::as_object) else {
        return Err(error("Invalid ASAR header: the root has no files object"));
    };
    let mut tree = Tree::default();
    walk(files, "", 0, &mut tree)?;
    let mut located = locate(data, &header, &tree.files)?;
    located.sort_by(|a, b| (a.start, &a.file.path).cmp(&(b.start, &b.file.path)));

    let mut c = Container::new(FileFormat::Asar, Layout::Asar.label(), "asar");
    let end = located
        .iter()
        .map(|l| l.start + l.bytes.len())
        .max()
        .unwrap_or(0)
        .max(header.data_start());
    c.consumed = end;
    push_tree_notes(&mut c, &header, &tree);
    push_integrity_notes(&mut c, &check_integrity(&located));
    if end < data.len() {
        c.notes.push(format!(
            "{} after the last file are not part of the archive",
            size_text(data.len() - end)
        ));
    }
    c.push_metadata(
        "asar_header_size",
        "Header pickle size (B)",
        header.header_size as u64,
    );
    c.push_metadata(
        "asar_files",
        "Files in the archive",
        tree.files.len() as u64,
    );
    c.push_metadata(
        "asar_unpacked_files",
        "Unpacked files",
        tree.unpacked as u64,
    );
    c.push_metadata("asar_links", "Links", tree.links as u64);

    let mut members = Members::default();
    for l in &located {
        if l.bytes.is_empty() {
            continue;
        }
        members.offer(
            &mut c,
            Member {
                label: display_name(l.file.path.as_bytes()),
                offset: l.start,
                contents: Contents::Stored(l.bytes),
                recognition: Recognition::Prefix,
            },
        );
    }
    members.push_notes(&mut c, "file", "files");
    Ok(c)
}

/// What the header's tree holds.
fn push_tree_notes(c: &mut Container<'_>, header: &Header<'_>, tree: &Tree) {
    c.notes.push(format!(
        "ASAR header: {} ({} B of JSON); {} in the archive, {} in the .unpacked directory, {}, \
         {}",
        size_text(header.header_size),
        header.json.len(),
        counted(tree.files.len(), "file", "files"),
        counted(tree.unpacked, "file", "files"),
        counted(tree.directories, "directory", "directories"),
        counted(tree.links, "link", "links"),
    ));
    if tree.executables > 0 {
        c.notes.push(format!(
            "{} marked executable",
            counted(tree.executables, "file", "files")
        ));
    }
}

/// Which declared hashes were verified.
fn push_integrity_notes(c: &mut Container<'_>, check: &IntegrityCheck) {
    let declared = check.verified + check.mismatched.len() + check.unchecked;
    if declared > 0 {
        c.notes.push(format!(
            "Integrity: {} of {declared} declared SHA-256 file hashes verified; block hashes not \
             verified",
            check.verified
        ));
    }
    if !check.mismatched.is_empty() {
        c.notes.push(format!(
            "SHA-256 mismatch for {}: {}",
            counted(check.mismatched.len(), "file", "files"),
            bounded_list(&check.mismatched)
        ));
    }
    if check.unchecked > 0 {
        c.notes.push(format!(
            "Hashing stopped at {}; {} not verified",
            size_text(MAX_HASHED),
            counted(check.unchecked, "file", "files")
        ));
    }
    if check.unsupported > 0 {
        c.notes.push(format!(
            "{} with an integrity algorithm other than SHA256, not verified",
            counted(check.unsupported, "file", "files")
        ));
    }
    if check.absent > 0 && declared + check.unsupported > 0 {
        c.notes.push(format!(
            "{} without integrity data",
            counted(check.absent, "file", "files")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_files_object_may_have_whitespace() {
        assert!(starts_with_files_object(br#"{"files":{"a":{}}}"#));
        assert!(starts_with_files_object(b"{ \"files\" :\n {"));
        assert!(!starts_with_files_object(br#"{"file":{"#));
        assert!(!starts_with_files_object(br#"{"files":["#));
        assert!(!starts_with_files_object(b"{\"files\""));
        assert!(!starts_with_files_object(b""));
    }

    #[test]
    fn the_string_fills_the_header_pickle_with_at_most_three_padding_bytes() {
        assert!(is_padded_string(787, 796));
        assert!(is_padded_string(788, 796));
        assert!(!is_padded_string(784, 796));
        assert!(!is_padded_string(789, 796));
        assert!(!is_padded_string(u32::MAX, 0));
    }
}
