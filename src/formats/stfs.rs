//! Xbox 360 STFS packages: `XContent` packages signed by a console (`CON `)
//! or by Microsoft (`LIVE`, `PIRS`) whose volume is the Secure Transacted
//! File System, with files reassembled from 4 KiB data blocks between
//! interleaved SHA-1 hash tables. `XContent` headers that describe an SVOD
//! volume (data in separate files) are recognized and reported.
//!
//! Primary sources (pins and hashes in `docs/stfs.md`):
//! - Free60 wiki "STFS" (`docs/System-Software/Formats/STFS.md` at commit
//!   `32eb31bc`): magics, signature areas, metadata offsets, the volume
//!   descriptor, the file listing, hash records and block statuses.
//! - Velocity at `cf0b84cc`: `XboxInternals/Stfs/XContentHeader.cpp`
//!   (header reader, header hash range), `StfsDefinitions.cpp` (volume
//!   descriptor byte order), `StfsPackage.cpp` (block and hash table
//!   addressing, active table copies, file table, consecutive and chained
//!   extraction, rehashing), `StfsConstants.h` (magics, content types) and
//!   `STFS Notes.txt` (the kernel's header size bounds).
//! - xenia at `95a5c3ee`: `src/xenia/vfs/devices/stfs_xbox.h` (structure
//!   layouts and the block separation flags), `stfs_container_device.cc`
//!   and `.h` (block addressing, hash table selection, end of chain).
//!
//! An `XContent` package names no CPU: the platform byte says Xbox 360 or
//! PC, not an instruction set. The container target is always unknown, and
//! the ISA comes from the files, which are classified by their own parsers
//! (XEX executables by `console.rs`). The RSA signatures are not verified;
//! the header SHA-1 and the SHA-1 of every hash table and data block that
//! is read are.

use crate::error::{ClassifierError, Result};
use crate::formats::checksum::Sha1;
use crate::formats::container::Container;
use crate::types::{FileFormat, MetadataValue};

mod blocks;
mod files;

use blocks::{Volume, VolumeDescriptor, BLOCK_SIZE};

/// Package magics at offset 0 (Free60 "Magic"; Velocity `Magic`).
const MAGIC_CON: &[u8; 4] = b"CON ";
const MAGIC_LIVE: &[u8; 4] = b"LIVE";
const MAGIC_PIRS: &[u8; 4] = b"PIRS";

/// Header SHA-1 (the content ID) and header size fields.
const CONTENT_ID_FIELD: usize = 0x32C;
const HEADER_SIZE_FIELD: usize = 0x340;

/// Start of the metadata, which is also where the header SHA-1 starts.
const METADATA_OFFSET: usize = 0x344;

/// Metadata fields (Free60 "Metadata", xenia `XContentMetadata`).
const CONTENT_TYPE_FIELD: usize = 0x344;
const METADATA_VERSION_FIELD: usize = 0x348;
const CONTENT_SIZE_FIELD: usize = 0x34C;
const MEDIA_ID_FIELD: usize = 0x354;
const VERSION_FIELD: usize = 0x358;
const BASE_VERSION_FIELD: usize = 0x35C;
const TITLE_ID_FIELD: usize = 0x360;
const PLATFORM_FIELD: usize = 0x364;
const DATA_FILE_COUNT_FIELD: usize = 0x39D;
const DATA_FILE_SIZE_FIELD: usize = 0x3A1;
const VOLUME_TYPE_FIELD: usize = 0x3A9;

/// The volume descriptor: 0x24 bytes at 0x379, whose first byte is its
/// size (xenia `StfsVolumeDescriptor::is_valid`).
const VOLUME_DESCRIPTOR_OFFSET: usize = 0x379;
const VOLUME_DESCRIPTOR_SIZE: u8 = 0x24;

/// Volume types (Free60 "Descriptor type"; xenia `XContentVolumeType`).
const VOLUME_STFS: u32 = 0;
const VOLUME_SVOD: u32 = 1;

/// The display name (9 locales of 128 UTF-16BE characters; locale 0 is
/// English), the publisher and the title name (64 characters each).
const DISPLAY_NAME_FIELD: usize = 0x411;
const DISPLAY_NAME_SIZE: usize = 0x100;
const PUBLISHER_FIELD: usize = 0x1611;
const TITLE_NAME_FIELD: usize = 0x1691;
const SHORT_NAME_SIZE: usize = 0x80;

/// Header size bounds the kernel enforces (Velocity `STFS Notes.txt`,
/// `XCONTENT_MOUNTED_PACKAGE`); 0x971A is also the size of the header and
/// metadata together (xenia `StfsHeader`).
const MIN_HEADER_SIZE: u32 = 0x971A;
const MAX_HEADER_SIZE: u32 = 0x1000_0000;

/// Platform values (Free60 "Platform").
const PLATFORM_XBOX_360: u8 = 2;
const PLATFORM_PC: u8 = 4;

/// Content types that Free60 and Velocity both list, with Free60's names.
#[rustfmt::skip]
const CONTENT_TYPES: [(u32, &str); 30] = [
    (0x0000_0001, "Saved Game"),
    (0x0000_0002, "Marketplace Content"),
    (0x0000_0003, "Publisher"),
    (0x0000_1000, "Xbox 360 Title"),
    (0x0000_2000, "IPTV Pause Buffer"),
    (0x0000_4000, "Installed Game"),
    (0x0000_5000, "Xbox Original Game"),
    (0x0000_7000, "Game on Demand"),
    (0x0000_9000, "Avatar Item"),
    (0x0001_0000, "Profile"),
    (0x0002_0000, "Gamer Picture"),
    (0x0003_0000, "Theme"),
    (0x0004_0000, "Cache File"),
    (0x0005_0000, "Storage Download"),
    (0x0006_0000, "Xbox Saved Game"),
    (0x0007_0000, "Xbox Download"),
    (0x0008_0000, "Game Demo"),
    (0x000A_0000, "Game Title"),
    (0x000B_0000, "Installer"),
    (0x000C_0000, "Game Trailer"),
    (0x000D_0000, "Arcade Title"),
    (0x000E_0000, "XNA"),
    (0x000F_0000, "License Store"),
    (0x0010_0000, "Movie"),
    (0x0020_0000, "TV"),
    (0x0030_0000, "Music Video"),
    (0x0040_0000, "Game Video"),
    (0x0050_0000, "Podcast Video"),
    (0x0060_0000, "Viral Video"),
    (0x0200_0000, "Community Game"),
];

/// An `XContent` package layout, named by its magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `CON `: signed by a console (saved games, profiles, caches).
    Con,
    /// `LIVE`: signed by Microsoft, delivered over Xbox Live.
    Live,
    /// `PIRS`: signed by Microsoft, delivered by other means (system
    /// updates).
    Pirs,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Con | Self::Live | Self::Pirs => FileFormat::XboxStfs,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Con => "Xbox 360 CON package",
            Self::Live => "Xbox 360 LIVE package",
            Self::Pirs => "Xbox 360 PIRS package",
        }
    }

    /// Recognized from complete structure rather than a magic value. Every
    /// layout carries a 4-byte magic, and detection also requires the
    /// header size, volume descriptor size and volume type, so none is
    /// weak.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Con | Self::Live | Self::Pirs => false,
        }
    }

    fn from_magic(magic: &[u8]) -> Option<Self> {
        if magic == MAGIC_CON {
            Some(Self::Con)
        } else if magic == MAGIC_LIVE {
            Some(Self::Live)
        } else if magic == MAGIC_PIRS {
            Some(Self::Pirs)
        } else {
            None
        }
    }

    /// The signature the layout carries (Free60 "Signatures").
    fn signature_note(self) -> &'static str {
        match self {
            Self::Con => "Console certificate and signature present (console-signed); not verified",
            Self::Live | Self::Pirs => "Package signature present (Microsoft-signed); not verified",
        }
    }
}

/// Strong recognition: `CON `, `LIVE` or `PIRS` at offset 0, a header size
/// within the kernel's bounds, a volume descriptor whose size byte is 0x24
/// and a volume type of STFS or SVOD. All of it lies in the first 0x3AD
/// bytes, so a damaged package is still recognized and becomes a parse
/// error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    let layout = Layout::from_magic(data.get(..4)?)?;
    let header_size = be_u32(data, HEADER_SIZE_FIELD).ok()?;
    let descriptor_size = *data.get(VOLUME_DESCRIPTOR_OFFSET)?;
    let volume_type = be_u32(data, VOLUME_TYPE_FIELD).ok()?;
    let is_package = is_header_size_valid(header_size)
        && descriptor_size == VOLUME_DESCRIPTOR_SIZE
        && matches!(volume_type, VOLUME_STFS | VOLUME_SVOD);
    is_package.then_some(layout)
}

/// Parse an `XContent` package into the shared container model: the header
/// and metadata in notes and metadata, and for an STFS volume every file
/// that is a recognized format as a child labeled by its path.
///
/// # Errors
///
/// [`ClassifierError::StfsParseError`] for a missing magic, a header size
/// outside 0x971A-0x10000000, a truncated header, an invalid volume
/// descriptor or volume type, a block count above 4,913,000, a top hash
/// table outside the file, or a file table whose blocks are missing,
/// unallocated or chained in a loop. A file whose blocks lie outside a
/// truncated package or whose chain is broken is not an error; it is left
/// out and named in a note.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    if data.get(..4) != Some(magic(layout).as_slice()) {
        return Err(error("Invalid XContent magic at 0x0"));
    }
    let header = read_header(data)?;
    let mut c = Container::new(FileFormat::XboxStfs, layout.label(), "stfs");
    c.consumed = data.len();
    push_header(&mut c, layout, &header, data);
    match header.volume_type {
        VOLUME_STFS => {
            let descriptor = VolumeDescriptor::read(data, VOLUME_DESCRIPTOR_OFFSET)?;
            let mut volume = Volume::new(data, header.header_size, &descriptor)?;
            volume.push_notes(&descriptor, &mut c);
            if descriptor.file_table_blocks == 0 {
                c.notes
                    .push("The package contains no files (empty file table)".into());
            } else {
                files::list(&mut volume, &descriptor, data, &mut c)?;
            }
            volume.push_check_notes(&mut c);
        }
        VOLUME_SVOD => push_svod(&mut c, &header),
        other => {
            return Err(error(format!(
                "Unsupported XContent volume type {other} at 0x{VOLUME_TYPE_FIELD:X}"
            )))
        }
    }
    Ok(c)
}

fn magic(layout: Layout) -> &'static [u8; 4] {
    match layout {
        Layout::Con => MAGIC_CON,
        Layout::Live => MAGIC_LIVE,
        Layout::Pirs => MAGIC_PIRS,
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::StfsParseError {
        message: message.into(),
    }
}

fn is_header_size_valid(header_size: u32) -> bool {
    (MIN_HEADER_SIZE..=MAX_HEADER_SIZE).contains(&header_size)
}

/// The `XContent` header and metadata fields that are reported.
struct PackageHeader {
    /// Header size in bytes; the first hash table follows at the next
    /// 4 KiB boundary.
    header_size: u32,
    /// SHA-1 of the bytes from 0x344 to the first hash table.
    content_id: [u8; 20],
    content_type: u32,
    metadata_version: u32,
    /// Content size in bytes, as the header states it.
    content_size: u64,
    media_id: u32,
    version: u32,
    base_version: u32,
    title_id: u32,
    platform: u8,
    volume_type: u32,
    /// SVOD data files and their combined size in bytes.
    data_file_count: u32,
    data_file_size: u64,
    display_name: String,
    publisher: String,
    title_name: String,
}

/// The header fields; the header size must lie within the kernel's bounds
/// and the file must hold the whole header.
fn read_header(data: &[u8]) -> Result<PackageHeader> {
    let header_size = be_u32(data, HEADER_SIZE_FIELD)?;
    if !is_header_size_valid(header_size) {
        return Err(error(format!(
            "Invalid XContent header size 0x{header_size:X} at 0x{HEADER_SIZE_FIELD:X}"
        )));
    }
    let header_len = header_size as usize;
    if data.len() < header_len {
        return Err(error(format!(
            "Truncated XContent header: {} B of {header_len} B",
            data.len()
        )));
    }
    let descriptor_size = data[VOLUME_DESCRIPTOR_OFFSET];
    if descriptor_size != VOLUME_DESCRIPTOR_SIZE {
        return Err(error(format!(
            "Invalid XContent volume descriptor size 0x{descriptor_size:X} at \
             0x{VOLUME_DESCRIPTOR_OFFSET:X}"
        )));
    }
    Ok(PackageHeader {
        header_size,
        content_id: array(data, CONTENT_ID_FIELD)?,
        content_type: be_u32(data, CONTENT_TYPE_FIELD)?,
        metadata_version: be_u32(data, METADATA_VERSION_FIELD)?,
        content_size: be_u64(data, CONTENT_SIZE_FIELD)?,
        media_id: be_u32(data, MEDIA_ID_FIELD)?,
        version: be_u32(data, VERSION_FIELD)?,
        base_version: be_u32(data, BASE_VERSION_FIELD)?,
        title_id: be_u32(data, TITLE_ID_FIELD)?,
        platform: data[PLATFORM_FIELD],
        volume_type: be_u32(data, VOLUME_TYPE_FIELD)?,
        data_file_count: be_u32(data, DATA_FILE_COUNT_FIELD)?,
        data_file_size: be_u64(data, DATA_FILE_SIZE_FIELD)?,
        display_name: utf16be_text(slice(data, DISPLAY_NAME_FIELD, DISPLAY_NAME_SIZE)?),
        publisher: utf16be_text(slice(data, PUBLISHER_FIELD, SHORT_NAME_SIZE)?),
        title_name: utf16be_text(slice(data, TITLE_NAME_FIELD, SHORT_NAME_SIZE)?),
    })
}

/// Notes and metadata for the header, the signature and the header SHA-1.
fn push_header(c: &mut Container<'_>, layout: Layout, header: &PackageHeader, data: &[u8]) {
    let prefix = c.key_prefix;
    c.notes.push(format!(
        "Content type 0x{:08X} ({}); metadata version {}",
        header.content_type,
        content_type_name(header.content_type),
        header.metadata_version
    ));
    c.notes.push(format!(
        "Title ID 0x{:08X}; media ID 0x{:08X}; version 0x{:X}; base version 0x{:X}; \
         platform {} ({})",
        header.title_id,
        header.media_id,
        header.version,
        header.base_version,
        header.platform,
        platform_name(header.platform)
    ));
    let names: Vec<String> = [
        ("display name", &header.display_name),
        ("title", &header.title_name),
        ("publisher", &header.publisher),
    ]
    .into_iter()
    .filter(|(_, text)| !text.is_empty())
    .map(|(what, text)| format!("{what} \"{text}\""))
    .collect();
    if !names.is_empty() {
        c.notes.push(capitalized(&names.join("; ")));
    }
    c.notes.push(layout.signature_note().into());
    push_content_id_note(c, header, data);
    c.push_metadata(
        format!("{prefix}_content_type"),
        "Content type",
        MetadataValue::Hex(header.content_type),
    );
    c.push_metadata(
        format!("{prefix}_metadata_version"),
        "Metadata version",
        u64::from(header.metadata_version),
    );
    c.push_metadata(
        format!("{prefix}_title_id"),
        "Title ID",
        MetadataValue::Hex(header.title_id),
    );
    c.push_metadata(
        format!("{prefix}_media_id"),
        "Media ID",
        MetadataValue::Hex(header.media_id),
    );
    c.push_metadata(
        format!("{prefix}_content_size"),
        "Content size (B)",
        header.content_size,
    );
    c.push_metadata(
        format!("{prefix}_header_size"),
        "Header size (B)",
        u64::from(header.header_size),
    );
    c.push_metadata(
        format!("{prefix}_content_id"),
        "Content ID (header SHA-1)",
        hex::encode(header.content_id),
    );
    for (key, label, text) in [
        ("display_name", "Display name", &header.display_name),
        ("title_name", "Title name", &header.title_name),
        ("publisher", "Publisher", &header.publisher),
    ] {
        if !text.is_empty() {
            c.push_metadata(format!("{prefix}_{key}"), label, text.clone());
        }
    }
}

/// Note whether the header SHA-1 matches the bytes from 0x344 to the first
/// hash table (Free60), or to the end of a file that ends before it
/// (Velocity `FixHeaderHash`).
fn push_content_id_note(c: &mut Container<'_>, header: &PackageHeader, data: &[u8]) {
    let first_table = round_up_to_block(header.header_size);
    let end = first_table.min(data.len());
    let mut sha1 = Sha1::new();
    sha1.update(&data[METADATA_OFFSET..end]);
    let verdict = if sha1.finish() == header.content_id {
        "matches"
    } else {
        "does not match"
    };
    c.notes.push(format!(
        "Header SHA-1 (content ID) over 0x{METADATA_OFFSET:X}-0x{:X} {verdict}",
        end - 1
    ));
}

/// An SVOD volume keeps its data in the separate files of a `.data`
/// directory (xenia `OpenFiles`), so the header file holds nothing to list.
fn push_svod(c: &mut Container<'_>, header: &PackageHeader) {
    let prefix = c.key_prefix;
    c.notes.push(format!(
        "SVOD volume: the data is in {} separate data files of {} B together; not parsed",
        header.data_file_count, header.data_file_size
    ));
    c.push_metadata(format!("{prefix}_volume_type"), "Volume type", "SVOD");
    c.push_metadata(
        format!("{prefix}_data_files"),
        "SVOD data files",
        u64::from(header.data_file_count),
    );
}

/// The Free60 name of a content type, or "unknown".
fn content_type_name(content_type: u32) -> &'static str {
    CONTENT_TYPES
        .iter()
        .find(|(value, _)| *value == content_type)
        .map_or("unknown", |(_, name)| name)
}

fn platform_name(platform: u8) -> &'static str {
    match platform {
        PLATFORM_XBOX_360 => "Xbox 360",
        PLATFORM_PC => "PC",
        _ => "unknown",
    }
}

/// `header_size` rounded up to the 4 KiB block size: the file offset of the
/// first hash table. The header size is at most 0x10000000, so this cannot
/// overflow.
fn round_up_to_block(header_size: u32) -> usize {
    let size = header_size as usize;
    match size % BLOCK_SIZE {
        0 => size,
        remainder => size + (BLOCK_SIZE - remainder),
    }
}

/// Text up to the first NUL of UTF-16BE `raw`; unpaired surrogates become
/// U+FFFD.
fn utf16be_text(raw: &[u8]) -> String {
    let units = raw
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .take_while(|&unit| unit != 0);
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>()
        .trim()
        .to_string()
}

/// `text` with its first letter in upper case: a note that starts with a
/// lower-case phrase.
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// `n` with the singular or plural noun.
fn counted(n: usize, singular: &str, plural: &str) -> String {
    format!("{n} {}", if n == 1 { singular } else { plural })
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error("File range overflow"))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated file range 0x{start:X} + {len} B")))
}

fn array<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    Ok(slice(data, at, N)?
        .try_into()
        .expect("slice has exactly N bytes"))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(array(data, at)?))
}

fn be_u64(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(array(data, at)?))
}

fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(array(data, at)?))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(array(data, at)?))
}

/// A 24-bit big-endian value (hash record next blocks).
fn be_u24(data: &[u8], at: usize) -> Result<u32> {
    let [high, middle, low] = array(data, at)?;
    Ok(u32::from_be_bytes([0, high, middle, low]))
}

/// A 24-bit little-endian value (file table block numbers).
fn le_u24(data: &[u8], at: usize) -> Result<u32> {
    let [low, middle, high] = array(data, at)?;
    Ok(u32::from_le_bytes([low, middle, high, 0]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_names_come_from_the_shared_table() {
        assert_eq!(content_type_name(1), "Saved Game");
        assert_eq!(content_type_name(0x1000), "Xbox 360 Title");
        assert_eq!(content_type_name(0x0200_0000), "Community Game");
        // Listed by only one source.
        assert_eq!(content_type_name(0x8000), "unknown");
        assert_eq!(content_type_name(0x9_0000), "unknown");
    }

    #[test]
    fn utf16be_text_stops_at_nul_and_replaces_unpaired_surrogates() {
        assert_eq!(utf16be_text(b"\0H\0i\0\0\0X"), "Hi");
        assert_eq!(utf16be_text(&[0xD8, 0x00, 0x00, 0x41]), "\u{FFFD}A");
        assert_eq!(utf16be_text(&[0x00, 0xE9, 0x00]), "\u{E9}");
        assert_eq!(utf16be_text(b""), "");
    }

    #[test]
    fn header_sizes_round_up_to_the_first_hash_table() {
        assert_eq!(round_up_to_block(0x971A), 0xA000);
        assert_eq!(round_up_to_block(0xAD0E), 0xB000);
        assert_eq!(round_up_to_block(0xA000), 0xA000);
        assert_eq!(round_up_to_block(MAX_HEADER_SIZE), 0x1000_0000);
    }

    #[test]
    fn header_size_bounds_are_the_kernel_bounds() {
        assert!(!is_header_size_valid(0x9719));
        assert!(is_header_size_valid(0x971A));
        assert!(is_header_size_valid(0x1000_0000));
        assert!(!is_header_size_valid(0x1000_0001));
    }

    #[test]
    fn detection_needs_the_magic_and_the_header_structure() {
        let mut header = vec![0u8; 0x3B0];
        header[..4].copy_from_slice(b"LIVE");
        header[HEADER_SIZE_FIELD..HEADER_SIZE_FIELD + 4].copy_from_slice(&0x971Au32.to_be_bytes());
        header[VOLUME_DESCRIPTOR_OFFSET] = VOLUME_DESCRIPTOR_SIZE;
        assert_eq!(detect(&header), Some(Layout::Live));
        header[VOLUME_TYPE_FIELD + 3] = 2;
        assert_eq!(detect(&header), None);
        header[VOLUME_TYPE_FIELD + 3] = 1;
        assert_eq!(detect(&header), Some(Layout::Live));
        header[VOLUME_DESCRIPTOR_OFFSET] = 0x23;
        assert_eq!(detect(&header), None);
        header[VOLUME_DESCRIPTOR_OFFSET] = VOLUME_DESCRIPTOR_SIZE;
        header[..4].copy_from_slice(b"CON\0");
        assert_eq!(detect(&header), None);
        assert_eq!(detect(&header[..0x3A0]), None);
    }
}
