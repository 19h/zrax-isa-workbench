//! `StuffIt` 5 archives (`.sit`, written by `StuffIt` 5.0 and later).
//!
//! Aladdin Systems did not publish the format. The layout is the reading of
//! The Unarchiver's `XADMaster` at revision `7cb9ee0a`
//! (`XADStuffIt5Parser.m`: archive header and entries; `XADStuffItParser.m`
//! and `XADCRCHandle.m`: fork CRCs), and fields that source leaves unnamed
//! are not used.
//!
//! An archive starts with an 80-byte text, `StuffIt (c)1997-` and a year,
//! ` Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/` and CR LF,
//! followed by `1A 00`, the archive version (5) and flags, then the archive
//! size (4), a field of unknown meaning (4), the number of root entries (2)
//! and the offset of the first entry (4). All numbers are big-endian.
//!
//! Entries follow one another. Each starts with the magic `A5 A5 A5 A5`, a
//! version, its header size (2), flags (0x40 folder, 0x20 encrypted), two
//! dates, the offsets of the previous, next and parent entries (4 each),
//! the name length (2) and a CRC-16/ARC of the header with that CRC field
//! zeroed. A file then holds its data fork's length, stored length and
//! CRC-16/ARC, the data fork's compression method and the length of its
//! password data; a folder holds where its entries start, its size and
//! its entry count. The name and an optional comment follow, then a second
//! block with the Finder information and, when bit 0 of its first field is
//! set, the resource fork's lengths, CRC and method. A file's stored
//! resource fork and then its stored data fork come next. Every folder is
//! followed by a 48-byte entry whose data length is `0xFFFFFFFF`; the
//! source skips these without naming them, and so does this parser.
//!
//! Data forks stored without compression (method 0) are the members, with
//! their CRC verified. Compressed forks (methods 13 and 15 in `StuffIt` 5
//! archives) are not decoded, and encrypted entries are opaque. Resource
//! forks are counted, not classified. The archive header's own CRC is not
//! verified: what it covers is not known.

use super::*;
use std::collections::BTreeMap;

/// The archive's signature text, around the four digits of a year.
const SIGNATURE_PREFIX: &[u8] = b"StuffIt (c)1997-";
const SIGNATURE_SUFFIX: &[u8] = b" Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/\r\n";
const YEAR_LEN: usize = 4;
const SIGNATURE_LEN: usize = SIGNATURE_PREFIX.len() + YEAR_LEN + SIGNATURE_SUFFIX.len();

/// Archive header fields after the signature and `1A 00`.
const ARCHIVE_VERSION_OFFSET: usize = 82;
const ARCHIVE_FLAGS_OFFSET: usize = 83;
const ARCHIVE_SIZE_OFFSET: usize = 84;
const ROOT_ENTRIES_OFFSET: usize = 92;
const FIRST_ENTRY_OFFSET: usize = 94;

/// Size of the archive header up to and including its CRC.
const ARCHIVE_HEADER_SIZE: usize = 100;

/// The archive version of `StuffIt` 5 archives.
const ARCHIVE_VERSION: u8 = 5;

/// Archive flag: every entry is encrypted.
const ARCHIVE_ENCRYPTED: u8 = 0x80;

/// Magic at the start of every entry (`SIT5_ID`).
const ENTRY_MAGIC: u32 = 0xA5A5_A5A5;

/// Entry fields (offsets in the entry).
const ENTRY_VERSION: usize = 4;
const ENTRY_HEADER_SIZE: usize = 6;
const ENTRY_FLAGS: usize = 9;
const ENTRY_PARENT: usize = 26;
const ENTRY_NAME_LEN: usize = 30;
const ENTRY_HEADER_CRC: usize = 32;
const ENTRY_DATA_LEN: usize = 34;
const ENTRY_DATA_STORED_LEN: usize = 38;
const ENTRY_DATA_CRC: usize = 42;
const ENTRY_FOLDER_ENTRIES: usize = 46;
const ENTRY_DATA_METHOD: usize = 46;
const ENTRY_PASSWORD_LEN: usize = 47;

/// Bytes of an entry before its password data and name.
const ENTRY_FIXED_SIZE: usize = 48;

/// Entry flags (`SIT5FLAGS_DIRECTORY`, `SIT5FLAGS_CRYPTED`).
const ENTRY_FOLDER: u8 = 0x40;
const ENTRY_ENCRYPTED: u8 = 0x20;

/// Data length of the unnamed entry that follows each folder.
const FOLDER_MARKER: u32 = 0xFFFF_FFFF;

/// Compression method of a fork stored as-is.
const METHOD_STORED: u8 = 0;

/// Second block: fork flags (2), a field of unknown meaning (2), file type
/// (4), creator (4) and Finder flags (2), then 22 B in entries of version 1
/// and 18 B in the others.
const FINDER_INFO_SIZE: usize = 14;
const FINDER_PADDING_V1: usize = 22;
const FINDER_PADDING: usize = 18;

/// Fork flag of the second block: a resource fork follows.
const HAS_RESOURCE_FORK: u16 = 0x0001;

/// Resource fork fields: length (4), stored length (4), CRC (2), a field of
/// unknown meaning (2), method (1) and password data length (1).
const RESOURCE_STORED_LEN: usize = 4;
const RESOURCE_PASSWORD_LEN: usize = 13;
const RESOURCE_FIELDS_SIZE: usize = 14;

/// Folders above a member that are named in its label; deeper ones are
/// shown as `…`.
const MAX_LABEL_DEPTH: usize = 32;

/// Bytes of each name used in a label.
const MAX_LABEL_NAME: usize = 255;

/// Whether `data` starts with the `StuffIt` 5 signature text.
pub(super) fn is_stuffit5(data: &[u8]) -> bool {
    data.get(..SIGNATURE_LEN).is_some_and(|signature| {
        signature.starts_with(SIGNATURE_PREFIX) && signature.ends_with(SIGNATURE_SUFFIX)
    })
}

/// Big-endian 16-bit field at `at`.
fn be_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2, "StuffIt field")?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_be_bytes(bytes))
}

/// Big-endian 32-bit field at `at`.
fn be_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4, "StuffIt field")?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_be_bytes(bytes))
}

/// A 32-bit length or offset as `usize`.
fn to_usize(value: u32) -> usize {
    usize::try_from(value).expect("usize holds 32 bits")
}

/// The fields of the archive header that the parser uses.
struct ArchiveHeader {
    encrypted: bool,
    size: usize,
    root_entries: usize,
    first_entry: usize,
}

/// Archive header: signature, `1A 00`, version (1), flags (1), archive
/// size (4), unknown (4), root entries (2), first entry offset (4), CRC (2).
fn archive_header(data: &[u8]) -> Result<ArchiveHeader> {
    slice(data, 0, ARCHIVE_HEADER_SIZE, "StuffIt archive header")?;
    let version = data[ARCHIVE_VERSION_OFFSET];
    if version != ARCHIVE_VERSION {
        return Err(error(format!(
            "Unsupported StuffIt archive version {version}"
        )));
    }
    let header = ArchiveHeader {
        encrypted: data[ARCHIVE_FLAGS_OFFSET] & ARCHIVE_ENCRYPTED != 0,
        size: to_usize(be_u32(data, ARCHIVE_SIZE_OFFSET)?),
        root_entries: usize::from(be_u16(data, ROOT_ENTRIES_OFFSET)?),
        first_entry: to_usize(be_u32(data, FIRST_ENTRY_OFFSET)?),
    };
    if header.first_entry < ARCHIVE_HEADER_SIZE {
        return Err(error(format!(
            "Invalid StuffIt first entry offset 0x{:X}",
            header.first_entry
        )));
    }
    if header.size > data.len() {
        return Err(error(format!(
            "Truncated StuffIt archive: {} B declared, {} B present",
            header.size,
            data.len()
        )));
    }
    Ok(header)
}

/// What an entry is.
enum EntryKind<'a> {
    /// The unnamed entry after a folder.
    FolderMarker,
    /// A folder and the number of entries in it.
    Folder { entries: usize },
    /// A file.
    File(File<'a>),
}

/// A file entry's forks.
struct File<'a> {
    encrypted: bool,
    method: u8,
    size: u32,
    crc: u16,
    /// File offset of the stored data fork.
    data_offset: usize,
    /// The stored data fork.
    stored: &'a [u8],
    has_resource_fork: bool,
}

/// One entry: its kind, name, parent folder offset and the offset of the
/// next entry.
struct Entry<'a> {
    kind: EntryKind<'a>,
    name: &'a [u8],
    parent: usize,
    next: usize,
}

/// The entry header at `pos`: magic, a header size that holds the fixed
/// fields, and a CRC-16/ARC of the header with its CRC field zeroed.
fn verified_header(data: &[u8], pos: usize) -> Result<&[u8]> {
    slice(data, pos, ENTRY_FIXED_SIZE, "StuffIt entry header")?;
    if be_u32(data, pos)? != ENTRY_MAGIC {
        return Err(error(format!("Invalid StuffIt entry magic at 0x{pos:X}")));
    }
    let header_size = usize::from(be_u16(data, pos + ENTRY_HEADER_SIZE)?);
    if header_size < ENTRY_FIXED_SIZE {
        return Err(error(format!(
            "Invalid StuffIt entry header size {header_size} B at 0x{pos:X}"
        )));
    }
    let header = slice(data, pos, header_size, "StuffIt entry header")?;
    let stored_crc = be_u16(data, pos + ENTRY_HEADER_CRC)?;
    let mut zeroed = header.to_vec();
    zeroed[ENTRY_HEADER_CRC..ENTRY_HEADER_CRC + 2].fill(0);
    if checksum::crc16_arc(&zeroed) != stored_crc {
        return Err(error(format!(
            "Invalid StuffIt entry header CRC 0x{stored_crc:04X} at 0x{pos:X}"
        )));
    }
    Ok(header)
}

/// What the second block says about the resource fork, and where the
/// block ends.
struct SecondBlock {
    has_resource_fork: bool,
    /// Stored length of the resource fork, which comes first after the
    /// block.
    resource_stored_len: usize,
    end: usize,
}

/// The second block at `at`: Finder information (fork flags, type,
/// creator, Finder flags and 22 or 18 B more), then the resource fork's
/// fields when fork flag bit 0 is set.
fn second_block(data: &[u8], at: usize, version: u8, encrypted: bool) -> Result<SecondBlock> {
    let fork_flags = be_u16(data, at)?;
    let padding = if version == 1 {
        FINDER_PADDING_V1
    } else {
        FINDER_PADDING
    };
    let mut end = at + FINDER_INFO_SIZE + padding;
    let has_resource_fork = fork_flags & HAS_RESOURCE_FORK != 0;
    let mut resource_stored_len = 0;
    if has_resource_fork {
        let fields = slice(
            data,
            end,
            RESOURCE_FIELDS_SIZE,
            "StuffIt resource fork fields",
        )?;
        resource_stored_len = to_usize(be_u32(data, end + RESOURCE_STORED_LEN)?);
        let password_len = usize::from(fields[RESOURCE_PASSWORD_LEN]);
        if password_len > 0 && !encrypted {
            return Err(error(format!(
                "Unsupported StuffIt resource fork password data at 0x{end:X}"
            )));
        }
        end += RESOURCE_FIELDS_SIZE + password_len;
    }
    slice(data, at, end - at, "StuffIt second block")?;
    Ok(SecondBlock {
        has_resource_fork,
        resource_stored_len,
        end,
    })
}

/// The entry at `pos`, its header CRC verified.
fn read_entry(data: &[u8], pos: usize) -> Result<Entry<'_>> {
    let header = verified_header(data, pos)?;
    let field = |offset: usize| pos + offset;
    let flags = header[ENTRY_FLAGS];
    let parent = to_usize(be_u32(data, field(ENTRY_PARENT))?);
    let data_len = be_u32(data, field(ENTRY_DATA_LEN))?;
    let is_folder = flags & ENTRY_FOLDER != 0;
    if is_folder && data_len == FOLDER_MARKER {
        return Ok(Entry {
            kind: EntryKind::FolderMarker,
            name: &[],
            parent,
            next: pos + ENTRY_FIXED_SIZE,
        });
    }
    let password_len = if is_folder {
        0
    } else {
        usize::from(header[ENTRY_PASSWORD_LEN])
    };
    let encrypted = flags & ENTRY_ENCRYPTED != 0;
    if password_len > 0 && !encrypted {
        return Err(error(format!(
            "Unsupported StuffIt password data in an unencrypted entry at 0x{pos:X}"
        )));
    }
    let name_len = usize::from(be_u16(data, field(ENTRY_NAME_LEN))?);
    let name_at = pos + ENTRY_FIXED_SIZE + password_len;
    let name = slice(data, name_at, name_len, "StuffIt entry name")?;
    let header_end = pos + header.len();
    let mut cursor = name_at + name_len;
    if cursor > header_end {
        return Err(error(format!(
            "Invalid StuffIt entry header size {} B at 0x{pos:X}: the name ends at 0x{cursor:X}",
            header.len()
        )));
    }
    if cursor < header_end {
        // Comment size (2), a field of unknown meaning (2), comment.
        let comment_len = usize::from(be_u16(data, cursor)?);
        cursor += 4 + comment_len;
    }
    let block = second_block(data, cursor, header[ENTRY_VERSION], encrypted)?;
    if is_folder {
        let entries = usize::from(be_u16(data, field(ENTRY_FOLDER_ENTRIES))?);
        return Ok(Entry {
            kind: EntryKind::Folder { entries },
            name,
            parent,
            next: block.end,
        });
    }
    let data_offset = block
        .end
        .checked_add(block.resource_stored_len)
        .ok_or_else(|| {
            error(format!(
                "Invalid StuffIt resource fork size at 0x{:X}",
                block.end
            ))
        })?;
    let data_stored_len = to_usize(be_u32(data, field(ENTRY_DATA_STORED_LEN))?);
    let stored = slice(data, data_offset, data_stored_len, "StuffIt data fork")?;
    let file = File {
        encrypted,
        method: header[ENTRY_DATA_METHOD],
        size: data_len,
        crc: be_u16(data, field(ENTRY_DATA_CRC))?,
        data_offset,
        stored,
        has_resource_fork: block.has_resource_fork,
    };
    Ok(Entry {
        kind: EntryKind::File(file),
        name,
        parent,
        next: data_offset + data_stored_len,
    })
}

/// A folder seen so far: its name and the offset of its parent folder.
struct Folder<'a> {
    name: &'a [u8],
    parent: Option<usize>,
}

/// Folders by entry offset. A parent must be a folder that came earlier,
/// so following parents always ends.
#[derive(Default)]
struct Folders<'a> {
    by_offset: BTreeMap<usize, Folder<'a>>,
}

impl<'a> Folders<'a> {
    /// The folder `offset` names, if it is a folder seen before `pos`.
    fn parent_of(&self, offset: usize, pos: usize) -> Option<usize> {
        (offset < pos && self.by_offset.contains_key(&offset)).then_some(offset)
    }

    fn insert(&mut self, offset: usize, name: &'a [u8], parent: Option<usize>) {
        self.by_offset.insert(offset, Folder { name, parent });
    }

    /// `name` with the folders above it, for labels and notes.
    fn path(&self, parent: Option<usize>, name: &[u8]) -> String {
        let mut parts = vec![label_name(name)];
        let mut folder = parent;
        while let Some(offset) = folder {
            if parts.len() > MAX_LABEL_DEPTH {
                parts.push("…".to_string());
                break;
            }
            let Some(entry) = self.by_offset.get(&offset) else {
                break;
            };
            parts.push(label_name(entry.name));
            folder = entry.parent;
        }
        parts.reverse();
        parts.join("/")
    }
}

/// A name for a label: at most [`MAX_LABEL_NAME`] bytes of it.
fn label_name(name: &[u8]) -> String {
    display_name(&name[..name.len().min(MAX_LABEL_NAME)])
}

/// Entries counted for the notes and metadata.
#[derive(Default)]
struct Tally {
    entries: usize,
    files: usize,
    folders: usize,
    resource_forks: usize,
    crc_verified: usize,
    stored: usize,
    compressed: NameList,
    encrypted: NameList,
    failed: NameList,
}

/// Parse a `StuffIt` 5 archive: one child per stored data fork in a
/// recognized format, in archive order.
pub(super) fn parse(data: &[u8], mode: MemberMode) -> Result<Container<'_>> {
    let header = archive_header(data)?;
    let mut c = Container::new(FileFormat::StuffIt, Layout::StuffIt5.label(), "stuffit");
    let mut members = Members {
        mode,
        ..Members::default()
    };
    let mut tally = Tally::default();
    let mut folders = Folders::default();
    let mut pending = header.root_entries;
    let mut pos = header.first_entry;
    while pending > 0 {
        let entry = read_entry(data, pos)?;
        let parent = folders.parent_of(entry.parent, pos);
        match entry.kind {
            EntryKind::FolderMarker => {
                pos = entry.next;
                continue;
            }
            EntryKind::Folder { entries } => {
                tally.folders += 1;
                folders.insert(pos, entry.name, parent);
                pending = pending.checked_add(entries).ok_or_else(|| {
                    error(format!("Invalid StuffIt folder entry count at 0x{pos:X}"))
                })?;
            }
            EntryKind::File(file) => {
                let name = folders.path(parent, entry.name);
                member(
                    &mut c,
                    &mut members,
                    &mut tally,
                    header.encrypted,
                    name,
                    &file,
                );
            }
        }
        tally.entries += 1;
        pending -= 1;
        pos = entry.next;
    }
    if pos > header.size {
        return Err(error(format!(
            "Invalid StuffIt archive size {} B: entries end at 0x{pos:X}",
            header.size
        )));
    }
    if !is_padding(&data[pos..header.size]) {
        return Err(error(format!(
            "Unexpected data after the last StuffIt entry at 0x{pos:X}"
        )));
    }
    c.consumed = header.size;
    push_notes(&tally, &mut c);
    push_trailing(data, c.consumed, "StuffIt", &mut c)?;
    members.push_notes(&mut c);
    c.push_metadata("stuffit_entries", "Entries", tally.entries as u64);
    c.push_metadata("stuffit_files", "Files", tally.files as u64);
    c.push_metadata("stuffit_folders", "Folders", tally.folders as u64);
    Ok(c)
}

/// Offer a file's data fork as a member: stored forks whose CRC matches are
/// offered, compressed and encrypted forks are counted (and listed as
/// opaque stored bytes when every member is wanted).
fn member<'a>(
    c: &mut Container<'a>,
    members: &mut Members,
    tally: &mut Tally,
    archive_encrypted: bool,
    name: String,
    file: &File<'a>,
) {
    tally.files += 1;
    if file.has_resource_fork {
        tally.resource_forks += 1;
    }
    let opaque = if archive_encrypted || file.encrypted {
        tally.encrypted.push(name.as_str());
        true
    } else if file.method != METHOD_STORED {
        tally
            .compressed
            .push(format!("{name} (method {})", file.method));
        true
    } else {
        false
    };
    if !members.has_room(c) {
        return;
    }
    if opaque {
        if members.mode == MemberMode::All {
            members.list(c, Child::opaque(name, file.data_offset, file.stored));
        }
        return;
    }
    tally.stored += 1;
    if file.stored.len() != to_usize(file.size) {
        tally.failed.push(format!(
            "{name}: {} B stored, {} B declared",
            file.stored.len(),
            file.size
        ));
        return;
    }
    let crc = checksum::crc16_arc(file.stored);
    if crc != file.crc {
        tally.failed.push(format!(
            "{name}: CRC-16 0x{crc:04X}, the entry declares 0x{:04X}",
            file.crc
        ));
        return;
    }
    tally.crc_verified += 1;
    members.offer(c, Child::stored(name, file.data_offset, file.stored));
}

fn push_notes(tally: &Tally, c: &mut Container<'_>) {
    c.notes
        .push("Entry header CRC-16s verified; the archive header CRC is not verified".to_string());
    if tally.stored > 0 {
        c.notes.push(format!(
            "Data fork CRC-16 verified for {} of {} stored files",
            tally.crc_verified, tally.stored
        ));
    }
    if !tally.compressed.is_empty() {
        c.notes.push(format!(
            "Compressed data forks are not decoded and are opaque: {}",
            tally.compressed
        ));
    }
    if !tally.encrypted.is_empty() {
        c.notes.push(format!(
            "Encrypted files are opaque and were not analyzed: {}",
            tally.encrypted
        ));
    }
    if tally.resource_forks > 0 {
        c.notes.push(format!(
            "{} not classified",
            count(
                tally.resource_forks,
                "resource fork is",
                "resource forks are"
            )
        ));
    }
    if !tally.failed.is_empty() {
        c.notes.push(format!(
            "Files that failed to verify were not classified: {}",
            tally.failed
        ));
    }
}
