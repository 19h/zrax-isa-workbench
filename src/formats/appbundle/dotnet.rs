//! .NET single-file bundles.
//!
//! Layout (.NET runtime v10.0.0 `src/native/corehost/bundle/header.h`,
//! `file_entry.h`, `reader.cpp`; `Microsoft.NET.HostModel/Bundle/Manifest.cs`
//! and `FileEntry.cs`), all integers little-endian:
//!
//! - The apphost holds a 40-byte bundle marker (`bundle_marker.cpp`): the
//!   bundle header offset (8, `int64`, 0 in an apphost that is not a
//!   bundle), then a 32-byte signature, the SHA-256 of `.net core bundle\n`.
//!   The SDK writes the offset into the first occurrence of the signature
//!   (`Bundler.cs` `BundleHeaderPlaceholder`, `IsBundle`).
//! - The files follow the apphost, then the header at that offset: major
//!   version (4), minor version (4), file count (4, `int32`), bundle ID (a
//!   string); from version 2 the `deps.json` and `runtimeconfig.json`
//!   locations (offset 8 and size 8 each, 0 when absent) and flags (8; bit
//!   0 is .NET Core 3 compatibility mode).
//! - Then one entry per file: offset (8, from the start of the file), size
//!   (8), from version 6 a compressed size (8, 0 when stored; raw DEFLATE),
//!   type (1: 0 unknown, 1 assembly, 2 native binary, 3 `deps.json`, 4
//!   `runtimeconfig.json`, 5 symbols), relative path (a string).
//! - A string is a 7-bit-encoded length of one or two bytes, then UTF-8
//!   (`reader_t::read_path_length`: never more than two length bytes, never
//!   empty).
//!
//! .NET 6 and later write version 6.0, .NET 5 writes 2.0 and .NET Core 3
//! writes 1.0 (`TargetInfo.cs`); the runtime's reader accepts 6.0 and 2.0
//! (`header.cpp`). The bundle ID is the first 12 characters of the base64url
//! SHA-256 over the SHA-256 digests of the files' contents in manifest order
//! (`Manifest.GenerateDeterministicId`).

use super::*;
use crate::formats::compressed::Codec;
use sha2::{Digest, Sha256};

/// The bundle signature after the header offset (`bundle_marker.cpp`).
#[rustfmt::skip]
const BUNDLE_SIGNATURE: [u8; 32] = [
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
    0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
    0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
    0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
];

/// The header offset field before the signature.
const HEADER_OFFSET_SIZE: usize = 8;

/// Size of the whole marker: offset and signature.
const MARKER_SIZE: usize = HEADER_OFFSET_SIZE + BUNDLE_SIGNATURE.len();

/// Bundle major versions (`TargetInfo.cs` `BundleMajorVersion`).
const VERSION_NETCOREAPP3: u32 = 1;
const VERSION_NET5: u32 = 2;
const VERSION_NET6: u32 = 6;

/// Fixed header fields: major and minor version and file count.
const FIXED_HEADER_SIZE: usize = 12;

/// Version 2 header fields: two locations and the flags.
const V2_HEADER_SIZE: usize = 40;

/// `header_flags_t::netcoreapp3_compat_mode`.
const FLAG_NETCOREAPP3_COMPAT_MODE: u64 = 1;

/// `file_type_t` values; types from [`TYPE_COUNT`] on are invalid.
const TYPE_UNKNOWN: u8 = 0;
const TYPE_ASSEMBLY: u8 = 1;
const TYPE_NATIVE_BINARY: u8 = 2;
const TYPE_DEPS_JSON: u8 = 3;
const TYPE_RUNTIME_CONFIG_JSON: u8 = 4;
const TYPE_SYMBOLS: u8 = 5;
const TYPE_COUNT: u8 = 6;

/// Entry fields before the path: offset, size and (from version 6) the
/// compressed size, then the type byte.
const ENTRY_FIXED_SIZE: usize = 17;
const ENTRY_FIXED_SIZE_V6: usize = 25;

/// The shortest path string: one length byte and one byte of path.
const MIN_STRING_SIZE: usize = 2;

/// A string length takes at most two 7-bit groups (`read_path_length`).
const LENGTH_CONTINUATION: u8 = 0x80;
const LENGTH_BITS: u8 = 0x7f;

/// The deterministic bundle ID: 12 base64url characters (`Manifest.cs`
/// `BundleIdLength`), which encode the digest's first 9 bytes.
const BUNDLE_ID_LENGTH: usize = 12;
const BUNDLE_ID_DIGEST_BYTES: usize = 9;

/// RFC 4648, section 5 (base64url) alphabet.
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The apphost's bundle marker.
#[derive(Debug)]
struct Marker {
    /// File offset of the 40-byte marker.
    offset: usize,
    /// The bundle header offset it holds.
    header_offset: i64,
}

/// The first bundle marker, as the SDK finds it.
fn find_marker(data: &[u8]) -> Option<Marker> {
    let signature = memchr::memmem::find(data, &BUNDLE_SIGNATURE)?;
    let offset = signature.checked_sub(HEADER_OFFSET_SIZE)?;
    let header_offset = le_i64(data, offset, "bundle marker").ok()?;
    Some(Marker {
        offset,
        header_offset,
    })
}

/// A file's location named by the version 2 header; `None` when absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Location {
    offset: i64,
    size: i64,
}

/// A length-prefixed string and the file offset after it.
#[derive(Debug)]
struct Text<'a> {
    bytes: &'a [u8],
    end: usize,
}

/// The string at `at`: a 7-bit-encoded length of one or two bytes, never
/// zero, then the bytes.
fn read_text<'a>(data: &'a [u8], at: usize, what: &str) -> Result<Text<'a>> {
    let first = slice(data, at, 1, what)?[0];
    let (length, start) = if first & LENGTH_CONTINUATION == 0 {
        (usize::from(first), at + 1)
    } else {
        let second = slice(data, at + 1, 1, what)?[0];
        if second & LENGTH_CONTINUATION != 0 {
            return Err(error(format!(
                "Invalid {what} length at 0x{at:X}: more than two length bytes"
            )));
        }
        (
            usize::from(second) << 7 | usize::from(first & LENGTH_BITS),
            at + 2,
        )
    };
    if length == 0 {
        return Err(error(format!("Invalid {what} at 0x{at:X}: empty string")));
    }
    let bytes = slice(data, start, length, what)?;
    Ok(Text {
        bytes,
        end: start + length,
    })
}

/// The bundle header.
#[derive(Debug)]
struct Header<'a> {
    /// File offset of the header.
    offset: usize,
    major: u32,
    minor: u32,
    file_count: usize,
    bundle_id: &'a [u8],
    deps_json: Option<Location>,
    runtime_config: Option<Location>,
    flags: u64,
    /// File offset of the first file entry.
    entries_start: usize,
}

impl Header<'_> {
    /// Bytes of an entry before its path.
    fn entry_fixed_size(&self) -> usize {
        if self.major >= VERSION_NET6 {
            ENTRY_FIXED_SIZE_V6
        } else {
            ENTRY_FIXED_SIZE
        }
    }

    /// The SDK generation that writes this version.
    fn writer(&self) -> &'static str {
        match self.major {
            VERSION_NETCOREAPP3 => ".NET Core 3",
            VERSION_NET5 => ".NET 5",
            _ => ".NET 6 and later",
        }
    }
}

/// A version 2 location, `None` when its offset is 0.
fn read_location(data: &[u8], at: usize) -> Result<Option<Location>> {
    let offset = le_i64(data, at, "bundle header")?;
    let size = le_i64(data, at + 8, "bundle header")?;
    Ok((offset != 0).then_some(Location { offset, size }))
}

/// Read the header at `offset`: a supported version, a file count that the
/// rest of the file can hold, and the bundle ID.
fn read_header(data: &[u8], offset: usize) -> Result<Header<'_>> {
    let fixed = slice(data, offset, FIXED_HEADER_SIZE, "bundle header")?;
    let major = le_u32(fixed, 0, "bundle header")?;
    let minor = le_u32(fixed, 4, "bundle header")?;
    let supported = matches!(major, VERSION_NETCOREAPP3 | VERSION_NET5 | VERSION_NET6);
    if !supported || minor != 0 {
        return Err(error(format!(
            "Unsupported bundle version {major}.{minor} at 0x{offset:X}"
        )));
    }
    let count = le_i32(fixed, 8, "bundle header")?;
    let id = read_text(data, offset + FIXED_HEADER_SIZE, "bundle ID")?;
    let mut header = Header {
        offset,
        major,
        minor,
        file_count: 0,
        bundle_id: id.bytes,
        deps_json: None,
        runtime_config: None,
        flags: 0,
        entries_start: id.end,
    };
    if major >= VERSION_NET5 {
        let v2 = id.end;
        slice(data, v2, V2_HEADER_SIZE, "bundle header")?;
        header.deps_json = read_location(data, v2)?;
        header.runtime_config = read_location(data, v2 + 16)?;
        header.flags = le_u64(data, v2 + 32, "bundle header")?;
        header.entries_start = v2 + V2_HEADER_SIZE;
    }
    let min_entry = header.entry_fixed_size() + MIN_STRING_SIZE;
    let room = (data.len() - header.entries_start) / min_entry;
    match usize::try_from(count) {
        Ok(count) if count > 0 && count <= room => header.file_count = count,
        _ => {
            return Err(error(format!(
                "Invalid file count {count} in the bundle header at 0x{offset:X}: the manifest \
                 holds at most {room} entries"
            )))
        }
    }
    Ok(header)
}

/// A marker with a nonzero header offset that leads to a valid header.
pub(super) fn detect(data: &[u8]) -> bool {
    let Some(marker) = find_marker(data) else {
        return false;
    };
    usize::try_from(marker.header_offset)
        .ok()
        .filter(|&offset| offset > 0)
        .is_some_and(|offset| read_header(data, offset).is_ok())
}

/// One manifest entry.
#[derive(Debug)]
struct Entry<'a> {
    /// File offset of the stored bytes.
    offset: usize,
    /// Decoded size.
    size: usize,
    /// Compressed size, 0 when stored.
    compressed_size: usize,
    kind: u8,
    path: &'a [u8],
}

impl Entry<'_> {
    /// Bytes the entry occupies in the file.
    fn stored_size(&self) -> usize {
        if self.compressed_size > 0 {
            self.compressed_size
        } else {
            self.size
        }
    }

    fn label(&self) -> String {
        display_name(self.path)
    }

    /// The location the version 2 header records for this entry.
    fn location(&self) -> Location {
        Location {
            offset: i64::try_from(self.offset).unwrap_or(i64::MAX),
            size: i64::try_from(self.size).unwrap_or(i64::MAX),
        }
    }
}

/// The entries and the file offset where the manifest ends.
#[derive(Debug)]
struct Manifest<'a> {
    entries: Vec<Entry<'a>>,
    end: usize,
}

/// A non-negative 64-bit field as a size, or an error naming it.
fn to_size(value: i64, field: &str, at: usize) -> Result<usize> {
    usize::try_from(value).map_err(|_| {
        error(format!(
            "Invalid {field} {value} in the file entry at 0x{at:X}"
        ))
    })
}

/// Read the file entries after the header. Every file must lie after the
/// bundle marker (in the bytes appended to the apphost) and end before the
/// header, where the writer puts the manifest.
fn read_manifest<'a>(data: &'a [u8], header: &Header<'_>, marker: &Marker) -> Result<Manifest<'a>> {
    let fixed_size = header.entry_fixed_size();
    let files_start = marker.offset + MARKER_SIZE;
    let mut entries = Vec::with_capacity(header.file_count);
    let mut at = header.entries_start;
    for _ in 0..header.file_count {
        let fixed = slice(data, at, fixed_size, "file entry")?;
        let offset = le_i64(fixed, 0, "file entry")?;
        let size = to_size(le_i64(fixed, 8, "file entry")?, "size", at)?;
        let compressed_size = if header.major >= VERSION_NET6 {
            to_size(le_i64(fixed, 16, "file entry")?, "compressed size", at)?
        } else {
            0
        };
        let kind = fixed[fixed_size - 1];
        if offset <= 0 {
            return Err(error(format!(
                "Invalid offset {offset} in the file entry at 0x{at:X}"
            )));
        }
        if kind >= TYPE_COUNT {
            return Err(error(format!(
                "Unknown file type {kind} in the file entry at 0x{at:X}"
            )));
        }
        let path = read_text(data, at + fixed_size, "file path")?;
        let entry = Entry {
            offset: to_size(offset, "offset", at)?,
            size,
            compressed_size,
            kind,
            path: path.bytes,
        };
        let in_bundle = entry.offset >= files_start
            && entry
                .offset
                .checked_add(entry.stored_size())
                .is_some_and(|end| end <= header.offset);
        if !in_bundle {
            return Err(error(format!(
                "Invalid range 0x{:X} + {} B for {}: bundled files lie between the bundle marker \
                 end at 0x{files_start:X} and the header at 0x{:X}",
                entry.offset,
                entry.stored_size(),
                entry.label(),
                header.offset
            )));
        }
        entries.push(entry);
        at = path.end;
    }
    Ok(Manifest { entries, end: at })
}

/// The first 12 base64url characters of `digest`.
fn bundle_id(digest: &[u8]) -> String {
    let mut id = String::with_capacity(BUNDLE_ID_LENGTH);
    for group in digest[..BUNDLE_ID_DIGEST_BYTES].chunks(3) {
        let bits = u32::from(group[0]) << 16 | u32::from(group[1]) << 8 | u32::from(group[2]);
        for shift in [18, 12, 6, 0] {
            let index = usize::try_from(bits >> shift & 0x3f).expect("six bits");
            id.push(char::from(BASE64URL[index]));
        }
    }
    id
}

/// Parse a .NET single-file bundle in its apphost: the marker, the
/// header, the manifest, and the managed and native files in a recognized
/// format as members.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let marker = find_marker(data)
        .ok_or_else(|| error("Missing .NET bundle marker (the 32-byte bundle signature)"))?;
    let header_offset = match usize::try_from(marker.header_offset) {
        Ok(0) => {
            return Err(error(format!(
                "Missing bundle: the bundle marker at 0x{:X} holds header offset 0",
                marker.offset
            )))
        }
        Ok(offset) => offset,
        Err(_) => {
            return Err(error(format!(
                "Invalid bundle header offset {} in the bundle marker at 0x{:X}",
                marker.header_offset, marker.offset
            )))
        }
    };
    let header = read_header(data, header_offset)?;
    let manifest = read_manifest(data, &header, &marker)?;

    let mut c = Container::new(
        FileFormat::DotnetBundle,
        Layout::DotnetBundle.label(),
        "dotnetbundle",
    );
    let bundle_start = manifest
        .entries
        .iter()
        .map(|e| e.offset)
        .min()
        .unwrap_or(header.offset);
    c.consumed = manifest.end - bundle_start;
    push_header_notes(&mut c, &header, &manifest, &marker, data.len());
    check_locations(&mut c, &header, &manifest);

    let mut members = Members::default();
    let mut ids = Some(Sha256::new());
    let mut compressed = 0usize;
    for entry in &manifest.entries {
        // `read_manifest` placed every entry before the header.
        let stored = &data[entry.offset..entry.offset + entry.stored_size()];
        let contents = if entry.compressed_size > 0 {
            compressed += 1;
            let Some(decoded) = decode(&mut members, entry, stored) else {
                ids = None;
                continue;
            };
            add_digest(&mut ids, &decoded);
            Contents::Decoded {
                stored_size: stored.len(),
                data: decoded,
                codec: Codec::Deflate,
            }
        } else {
            add_digest(&mut ids, stored);
            Contents::Stored(stored)
        };
        let listable = !matches!(entry.kind, TYPE_DEPS_JSON | TYPE_RUNTIME_CONFIG_JSON);
        if listable && entry.size > 0 {
            members.offer(
                &mut c,
                Member {
                    label: entry.label(),
                    offset: entry.offset,
                    contents,
                    recognition: Recognition::Prefix,
                },
            );
        }
    }
    push_id_note(&mut c, &header, ids);
    if compressed > 0 {
        c.notes.push(format!(
            "{} compressed with raw DEFLATE",
            counted(compressed, "file", "files")
        ));
    }
    members.push_notes(&mut c, "file", "files");
    Ok(c)
}

/// Decode a compressed entry within the extraction budget.
fn decode(members: &mut Members, entry: &Entry<'_>, stored: &[u8]) -> Option<Vec<u8>> {
    if !members.charge(entry.size) {
        return None;
    }
    members.decode(&entry.label(), stored, Codec::Deflate, entry.size)
}

/// Add one file's SHA-256 to the bundle ID hash, while every file so far
/// was available.
fn add_digest(ids: &mut Option<Sha256>, contents: &[u8]) {
    if let Some(hasher) = ids.as_mut() {
        hasher.update(Sha256::digest(contents));
    }
}

/// Version, ID, file counts by type, extent and flags.
fn push_header_notes(
    c: &mut Container<'_>,
    header: &Header<'_>,
    manifest: &Manifest<'_>,
    marker: &Marker,
    input_len: usize,
) {
    let id = display_name(header.bundle_id);
    let count = |kind: u8| manifest.entries.iter().filter(|e| e.kind == kind).count();
    c.notes.push(format!(
        "Bundle version {}.{} (written for {}); bundle ID {id}; {}: {}, {}, {}, {} and {}",
        header.major,
        header.minor,
        header.writer(),
        counted(manifest.entries.len(), "file", "files"),
        counted(count(TYPE_ASSEMBLY), "assembly", "assemblies"),
        counted(
            count(TYPE_NATIVE_BINARY),
            "native binary",
            "native binaries"
        ),
        counted(count(TYPE_SYMBOLS), "symbol file", "symbol files"),
        counted(
            count(TYPE_DEPS_JSON) + count(TYPE_RUNTIME_CONFIG_JSON),
            "configuration file",
            "configuration files"
        ),
        counted(count(TYPE_UNKNOWN), "other file", "other files"),
    ));
    c.notes.push(format!(
        "Bundle marker at 0x{:X} in the apphost; manifest at 0x{:X}-0x{:X}",
        marker.offset, header.offset, manifest.end
    ));
    if manifest.end < input_len {
        c.notes.push(format!(
            "{} after the manifest (a code signature or other data) are not part of the bundle",
            size_text(input_len - manifest.end)
        ));
    }
    if header.flags & FLAG_NETCOREAPP3_COMPAT_MODE != 0 {
        c.notes
            .push(".NET Core 3 compatibility mode: all files are extracted at run time".into());
    }
    let unknown_flags = header.flags & !FLAG_NETCOREAPP3_COMPAT_MODE;
    if unknown_flags != 0 {
        c.notes
            .push(format!("Unknown header flags 0x{unknown_flags:X}"));
    }
    c.push_metadata(
        "dotnetbundle_version",
        "Bundle version",
        format!("{}.{}", header.major, header.minor),
    );
    c.push_metadata("dotnetbundle_id", "Bundle ID", id);
    c.push_metadata(
        "dotnetbundle_marker_offset",
        "Bundle marker offset (B)",
        marker.offset as u64,
    );
    c.push_metadata(
        "dotnetbundle_header_offset",
        "Bundle header offset (B)",
        header.offset as u64,
    );
    c.push_metadata("dotnetbundle_files", "Files", manifest.entries.len() as u64);
}

/// The version 2 header repeats where `deps.json` and
/// `runtimeconfig.json` are, for the host to read them without the
/// manifest; both copies should agree.
fn check_locations(c: &mut Container<'_>, header: &Header<'_>, manifest: &Manifest<'_>) {
    if header.major < VERSION_NET5 {
        return;
    }
    let pairs = [
        (TYPE_DEPS_JSON, header.deps_json, "deps.json"),
        (
            TYPE_RUNTIME_CONFIG_JSON,
            header.runtime_config,
            "runtimeconfig.json",
        ),
    ];
    for (kind, recorded, name) in pairs {
        let entry = manifest.entries.iter().find(|e| e.kind == kind);
        match (entry, recorded) {
            (Some(entry), Some(location)) if entry.location() == location => {
                c.notes.push(format!(
                    "{name}: {} ({})",
                    entry.label(),
                    size_text(entry.size)
                ));
            }
            (None, None) => {}
            _ => c.notes.push(format!(
                "The header's {name} location does not match the manifest's {name} entry"
            )),
        }
    }
}

/// Whether the bundle ID is the content-derived ID.
fn push_id_note(c: &mut Container<'_>, header: &Header<'_>, ids: Option<Sha256>) {
    let id = display_name(header.bundle_id);
    let Some(hasher) = ids else {
        c.notes.push(format!(
            "Bundle ID {id} not checked: not every file was decoded"
        ));
        return;
    };
    let expected = bundle_id(&hasher.finalize());
    if header.bundle_id == expected.as_bytes() {
        c.notes.push(format!(
            "Bundle ID {id} matches the SHA-256 of the files' contents"
        ));
    } else {
        c.notes.push(format!(
            "Bundle ID {id} is not the SHA-256 of the files' contents ({expected}); the ID may \
             have been chosen another way, so the contents are not verified"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_ids_are_twelve_base64url_characters() {
        let digest = [0xfb, 0xff, 0xbf, 0, 0, 0, 0x14, 0xfb, 0x9c, 0xaa];
        assert_eq!(bundle_id(&digest), "-_-_AAAAFPuc");
    }

    #[test]
    fn strings_take_one_or_two_length_bytes() {
        let short = [3, b'a', b'b', b'c'];
        let text = read_text(&short, 0, "path").unwrap();
        assert_eq!((text.bytes, text.end), (&b"abc"[..], 4));
        let mut long = vec![0x80 | 1, 1];
        long.extend(std::iter::repeat(b'x').take(129));
        assert_eq!(read_text(&long, 0, "path").unwrap().bytes.len(), 129);
        assert!(read_text(&[0x80, 0x80, 1], 0, "path").is_err());
        assert!(read_text(&[0], 0, "path").is_err());
        assert!(read_text(&[5, b'a'], 0, "path").is_err());
    }
}
