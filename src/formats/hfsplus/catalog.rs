//! Catalog keys and records ([TN1150] "Catalog File"; [HFS]
//! `HFSPlusCatalogKey`, `HFSPlusCatalogFolder`, `HFSPlusCatalogFile`,
//! `HFSPlusCatalogThread`), and the enumeration of a folder's children.

use super::btree::Cursor;
use super::*;
use std::cmp::Ordering;

/// Catalog record types (`recordType`).
const FOLDER_RECORD: u16 = 1;
const FILE_RECORD: u16 = 2;
const FOLDER_THREAD_RECORD: u16 = 3;
const FILE_THREAD_RECORD: u16 = 4;

/// Record sizes: `HFSPlusCatalogFolder` 88 B, `HFSPlusCatalogFile` 248 B,
/// and the fixed part of `HFSPlusCatalogThread` (type, reserved,
/// `parentID`, name length).
const FOLDER_RECORD_SIZE: usize = 88;
const FILE_RECORD_SIZE: usize = 248;
const THREAD_RECORD_FIXED_SIZE: usize = 10;

/// Catalog key: `parentID` (4) and the name length (2) before the name;
/// `kHFSPlusCatalogKeyMinimumLength`.
const CATALOG_KEY_MIN_LENGTH: usize = 6;

/// Longest node name (`kHFSPlusMaxFileNameChars`).
const MAX_NAME_CHARS: usize = 255;

/// `fileMode` file types (octal, [TN1150] "HFS Plus Permissions").
pub(super) const S_IFMT: u16 = 0o170_000;
pub(super) const S_IFREG: u16 = 0o100_000;
pub(super) const S_IFLNK: u16 = 0o120_000;

/// File record `flags`: the file has a hard link chain
/// (`kHFSHasLinkChainMask`).
pub(super) const HAS_LINK_CHAIN: u16 = 0x0020;

/// `UF_COMPRESSED` in `ownerFlags` (bits 0-7 of `st_flags`; macOS SDK
/// `sys/stat.h`).
pub(super) const UF_COMPRESSED: u8 = 0x20;

/// U+0000 is exported as U+2400 SYMBOL FOR NULL ([XNU] `UCS_ALT_NULL`) and
/// `/` as `:` ([HFS] `cat_lookupbykey` passes `':'` to `utf8_encodestr`).
const ALT_NULL: char = '\u{2400}';
const ALT_SLASH: char = ':';

/// A folder record's fields the reader uses.
#[derive(Debug, Clone, Copy)]
pub(super) struct Folder {
    /// `folderID`.
    pub(super) id: u32,
    /// `createDate`, seconds since 1904.
    pub(super) create_date: u32,
}

/// A file record's fields the reader uses.
#[derive(Debug, Clone)]
pub(super) struct File {
    /// `fileID`.
    pub(super) id: u32,
    /// `flags`.
    pub(super) flags: u16,
    /// `createDate`, seconds since 1904.
    pub(super) create_date: u32,
    /// `bsdInfo.ownerFlags`.
    pub(super) owner_flags: u8,
    /// `bsdInfo.fileMode`.
    pub(super) mode: u16,
    /// `bsdInfo.special`: the link reference of a hard link.
    pub(super) special: u32,
    /// `userInfo.fdType`.
    pub(super) type_code: u32,
    /// `userInfo.fdCreator`.
    pub(super) creator_code: u32,
    /// `dataFork`.
    pub(super) data_fork: ForkData,
    /// `resourceFork`.
    pub(super) resource_fork: ForkData,
}

impl File {
    /// The file type bits of `fileMode`. Zero means the permissions were
    /// never initialized (Mac OS 8 and 9), which Mac OS X treats as a
    /// regular file with default permissions ([TN1150]).
    pub(super) fn file_mode_type(&self) -> u16 {
        self.mode & S_IFMT
    }
}

/// A thread record: the parent and name of the CNID in its key.
#[derive(Debug, Clone)]
pub(super) struct Thread {
    /// `parentID`.
    pub(super) parent_id: u32,
    /// `nodeName`, as exported.
    pub(super) name: String,
}

/// A catalog leaf record.
#[derive(Debug, Clone)]
pub(super) enum Entry {
    Folder(Folder),
    File(Box<File>),
    Thread(Thread),
}

/// A catalog key: `parentID` (0), name length (4), UTF-16BE name (6).
pub(super) struct Key<'k> {
    pub(super) parent_id: u32,
    /// The name's UTF-16 code units, big-endian.
    pub(super) name: &'k [u8],
}

impl<'k> Key<'k> {
    pub(super) fn parse(key: &'k [u8]) -> Result<Self> {
        if key.len() < CATALOG_KEY_MIN_LENGTH {
            return Err(error(format!("Invalid catalog key of {} B", key.len())));
        }
        let length = usize::from(be_u16(key, 4)?);
        if length > MAX_NAME_CHARS || CATALOG_KEY_MIN_LENGTH + 2 * length > key.len() {
            return Err(error(format!(
                "Invalid catalog key: name of {length} characters in {} B",
                key.len()
            )));
        }
        Ok(Self {
            parent_id: be_u32(key, 0)?,
            name: &key[CATALOG_KEY_MIN_LENGTH..CATALOG_KEY_MIN_LENGTH + 2 * length],
        })
    }
}

/// How `key` compares with the first key of folder `parent`'s records,
/// (`parent`, empty name). An empty name sorts before every other, so no
/// Unicode comparison is needed.
pub(super) fn order_by_parent(key: &[u8], parent: u32) -> Result<Ordering> {
    let key = Key::parse(key)?;
    Ok(key.parent_id.cmp(&parent).then(if key.name.is_empty() {
        Ordering::Equal
    } else {
        Ordering::Greater
    }))
}

/// A name as Mac OS X exports it, from UTF-16BE code units. Unpaired
/// surrogates become U+FFFD.
pub(super) fn name_text(units: &[u8]) -> String {
    let units = units
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]));
    char::decode_utf16(units)
        .map(|unit| match unit {
            Ok('\0') => ALT_NULL,
            Ok('/') => ALT_SLASH,
            Ok(c) => c,
            Err(_) => char::REPLACEMENT_CHARACTER,
        })
        .collect()
}

/// Parse a leaf record's data. Layouts ([TN1150]): folder `recordType`
/// (0), `flags` (2), `valence` (4), `folderID` (8), `createDate` (12);
/// file `flags` (2), `fileID` (8), `createDate` (12), `bsdInfo` (32:
/// `ownerFlags` at 41, `fileMode` at 42, `special` at 44), `userInfo` (48:
/// `fdType`, `fdCreator`), `dataFork` (88), `resourceFork` (168); thread
/// `parentID` (4), `nodeName` (8).
pub(super) fn parse_entry(data: &[u8]) -> Result<Entry> {
    let record_type = be_u16(data, 0)?;
    match record_type {
        FOLDER_RECORD => {
            let record = slice(data, 0, FOLDER_RECORD_SIZE)
                .map_err(|_| error(format!("Truncated folder record of {} B", data.len())))?;
            Ok(Entry::Folder(Folder {
                id: be_u32(record, 8)?,
                create_date: be_u32(record, 12)?,
            }))
        }
        FILE_RECORD => {
            let record = slice(data, 0, FILE_RECORD_SIZE)
                .map_err(|_| error(format!("Truncated file record of {} B", data.len())))?;
            Ok(Entry::File(Box::new(File {
                id: be_u32(record, 8)?,
                flags: be_u16(record, 2)?,
                create_date: be_u32(record, 12)?,
                owner_flags: record[41],
                mode: be_u16(record, 42)?,
                special: be_u32(record, 44)?,
                type_code: be_u32(record, 48)?,
                creator_code: be_u32(record, 52)?,
                data_fork: ForkData::parse(record, 88)?,
                resource_fork: ForkData::parse(record, 168)?,
            })))
        }
        FOLDER_THREAD_RECORD | FILE_THREAD_RECORD => {
            let length = usize::from(be_u16(data, 8)?);
            let name = slice(data, THREAD_RECORD_FIXED_SIZE, 2 * length)
                .map_err(|_| error(format!("Truncated thread record of {} B", data.len())))?;
            Ok(Entry::Thread(Thread {
                parent_id: be_u32(data, 4)?,
                name: name_text(name),
            }))
        }
        other => Err(error(format!("Unknown catalog record type {other}"))),
    }
}

/// A child of a folder: its name and record.
pub(super) struct Member {
    /// `nodeName`, as exported.
    pub(super) name: String,
    pub(super) entry: Entry,
}

/// The children of a folder, read from the catalog in key order.
pub(super) struct Children<'f, 'a> {
    fs: &'f Filesystem<'a>,
    parent: u32,
    cursor: Option<Cursor<'a>>,
}

impl<'f, 'a> Children<'f, 'a> {
    /// Start at the first record of folder `parent`: its thread record,
    /// keyed (`parent`, empty name).
    pub(super) fn new(fs: &'f Filesystem<'a>, parent: u32) -> ReadResult<Self> {
        let order = |key: &[u8]| order_by_parent(key, parent);
        let cursor = fs.catalog.lower_bound(&fs.vol, &order)?;
        Ok(Self { fs, parent, cursor })
    }

    /// The next file or folder of the folder, skipping its thread record.
    /// `None` at the first record of another folder or at the end.
    pub(super) fn next(&mut self) -> ReadResult<Option<Member>> {
        let Some(cursor) = self.cursor.as_mut() else {
            return Ok(None);
        };
        loop {
            let Some(record) = cursor.next(&self.fs.catalog, &self.fs.vol)? else {
                return Ok(None);
            };
            let key = Key::parse(record.key)?;
            if key.parent_id != self.parent {
                return Ok(None);
            }
            if key.name.is_empty() {
                // The folder's own thread record.
                continue;
            }
            let name = name_text(key.name);
            let entry = parse_entry(record.data)?;
            return Ok(Some(Member { name, entry }));
        }
    }
}

/// The thread record of `id`, keyed (`id`, empty name), if the catalog
/// holds one.
pub(super) fn thread(fs: &Filesystem<'_>, id: u32) -> ReadResult<Option<Thread>> {
    let order = |key: &[u8]| order_by_parent(key, id);
    let Some(mut cursor) = fs.catalog.lower_bound(&fs.vol, &order)? else {
        return Ok(None);
    };
    let Some(record) = cursor.next(&fs.catalog, &fs.vol)? else {
        return Ok(None);
    };
    let key = Key::parse(record.key)?;
    if key.parent_id != id || !key.name.is_empty() {
        return Ok(None);
    }
    match parse_entry(record.data)? {
        Entry::Thread(thread) => Ok(Some(thread)),
        _ => invalid(format!("Invalid catalog: CNID {id} has no thread record")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_be_bytes).collect()
    }

    #[test]
    fn names_export_nul_and_slash_as_macos_does() {
        let mut private = vec![0u8; 8];
        private.extend(units("HFS+ Private Data"));
        assert_eq!(
            name_text(&private),
            "\u{2400}\u{2400}\u{2400}\u{2400}HFS+ Private Data"
        );
        assert_eq!(name_text(&units("a/b")), "a:b");
        // An unpaired high surrogate.
        assert_eq!(name_text(&[0xd8, 0x00, 0x00, 0x41]), "\u{fffd}A");
    }

    #[test]
    fn keys_order_by_parent_with_the_empty_name_first() {
        let key = |parent: u32, name: &str| {
            let mut key = parent.to_be_bytes().to_vec();
            let name = units(name);
            key.extend(u16::try_from(name.len() / 2).unwrap().to_be_bytes());
            key.extend(name);
            key
        };
        assert_eq!(order_by_parent(&key(2, ""), 2).unwrap(), Ordering::Equal);
        assert_eq!(order_by_parent(&key(2, "a"), 2).unwrap(), Ordering::Greater);
        assert_eq!(order_by_parent(&key(1, "ZRAX"), 2).unwrap(), Ordering::Less);
        assert_eq!(order_by_parent(&key(3, ""), 2).unwrap(), Ordering::Greater);
        assert!(order_by_parent(&[0, 0, 0, 2, 0, 9, 0, 0x41], 2).is_err());
    }
}
