//! CFHEADER, CFFOLDER and CFFILE (SDK "CFHEADER", "CFFOLDER", "CFFILE").
//!
//! CFHEADER: signature (0), `reserved1` (4), `cbCabinet` (8), `reserved2`
//! (0x0C), `coffFiles` (0x10), `reserved3` (0x14), `versionMinor` (0x18),
//! `versionMajor` (0x19), `cFolders` (0x1A), `cFiles` (0x1C), `flags`
//! (0x1E), `setID` (0x20), `iCabinet` (0x22); with `cfhdrRESERVE_PRESENT`
//! then `cbCFHeader` (0x24, 16 bits), `cbCFFolder` (0x26) and `cbCFData`
//! (0x27) and the per-cabinet reserve; with `cfhdrPREV_CABINET` the
//! previous cabinet's and disk's names, with `cfhdrNEXT_CABINET` the next
//! ones, each NUL-terminated and at most 255 bytes long. The CFFOLDER
//! entries follow; the CFFILE entries start at `coffFiles`.

use super::*;
use crate::types::MetadataValue;

/// `flags` bits (SDK "CFHEADER").
const PREV_CABINET: u16 = 0x0001;
const NEXT_CABINET: u16 = 0x0002;
const RESERVE_PRESENT: u16 = 0x0004;
const KNOWN_FLAGS: u16 = PREV_CABINET | NEXT_CABINET | RESERVE_PRESENT;

/// Field offsets in the fixed CFHEADER fields.
const VERSION_MINOR_FIELD: usize = 0x18;
const VERSION_MAJOR_FIELD: usize = 0x19;
const FILE_COUNT_FIELD: usize = 0x1C;
const FLAGS_FIELD: usize = 0x1E;
const SET_ID_FIELD: usize = 0x20;
const INDEX_FIELD: usize = 0x22;

/// The reserve sizes that follow the fixed fields when
/// `cfhdrRESERVE_PRESENT` is set: `cbCFHeader` (2 bytes), `cbCFFolder` and
/// `cbCFData` (1 byte each).
const RESERVE_SIZES_SIZE: usize = 4;

/// "Values for cbCFHeader range from 0 to 60,000" (SDK).
const MAX_HEADER_RESERVE: usize = 60_000;

/// Cabinet and disk names hold "up to 255 bytes plus the NUL byte" (SDK);
/// libmspack reads them into a 256-byte buffer.
const MAX_NAME: usize = 256;

/// The format version the SDK describes: "Currently, versionMajor = 1 and
/// versionMinor = 3".
const VERSION_MAJOR: u8 = 1;
const VERSION_MINOR: u8 = 3;

/// Fixed size of a CFFILE entry, before its name, and the offsets of its
/// `iFolder` and `attribs` fields.
const CFFILE_SIZE: usize = 16;
const CFFILE_FOLDER_FIELD: usize = 8;
const CFFILE_ATTRIBUTES_FIELD: usize = 0x0E;

/// `iFolder` values for files that span cabinets (SDK "CFFILE").
const CONTINUED_FROM_PREV: u16 = 0xFFFD;
const CONTINUED_TO_NEXT: u16 = 0xFFFE;
const CONTINUED_PREV_AND_NEXT: u16 = 0xFFFF;

/// `attribs` bits (SDK "CFFILE"): run after extraction, and a name in the
/// SDK's UTF encoding (UTF-8 for UCS-2).
pub(super) const ATTRIBUTE_EXEC: u16 = 0x40;
const ATTRIBUTE_NAME_IS_UTF: u16 = 0x80;

/// `typeCompress` fields (Wine `include/fdi.h`, matching libmspack
/// `cab.h`): the type in bits 0-3; the LZX window and Quantum memory in
/// bits 8-12, the Quantum level in bits 4-7.
const COMPRESSION_TYPE_MASK: u16 = 0x000F;
const TYPE_NONE: u16 = 0;
const TYPE_MSZIP: u16 = 1;
const TYPE_QUANTUM: u16 = 2;
const TYPE_LZX: u16 = 3;
const WINDOW_SHIFT: u32 = 8;
const WINDOW_MASK: u16 = 0x1F;
const QUANTUM_LEVEL_SHIFT: u32 = 4;
const QUANTUM_LEVEL_MASK: u16 = 0x0F;

/// The Authenticode reserve of a signed cabinet (osslsigncode `cab.c`,
/// `cab_ctx_get`): 20 bytes whose first word is 0x00100000 (a value
/// osslsigncode checks and writes; its meaning is not documented), then the
/// signature's file offset and size.
const SIGNATURE_RESERVE_SIZE: usize = 20;
const SIGNATURE_RESERVE_TAG: u32 = 0x0010_0000;
const SIGNATURE_OFFSET_FIELD: usize = 4;
const SIGNATURE_SIZE_FIELD: usize = 8;

/// The names of a neighboring cabinet in a set.
#[derive(Debug)]
pub(super) struct Neighbor {
    /// The cabinet's file name.
    pub cabinet: String,
    /// A description of its medium, such as a disk label; may be empty.
    pub disk: String,
}

/// The CFHEADER fields the parser uses.
#[derive(Debug)]
pub(super) struct Header<'a> {
    /// `cbCabinet`, at most the input's size.
    pub cabinet_size: usize,
    /// `coffFiles`.
    pub files_offset: usize,
    pub version_major: u8,
    pub version_minor: u8,
    pub folder_count: usize,
    pub file_count: usize,
    pub flags: u16,
    pub set_id: u16,
    /// `iCabinet`: the cabinet's index in its set, from 0.
    pub index: u16,
    /// The per-cabinet reserve area.
    pub reserve: &'a [u8],
    /// Reserve bytes in each CFFOLDER and CFDATA (`cbCFFolder`,
    /// `cbCFData`).
    pub folder_reserve: usize,
    pub data_reserve: usize,
    pub previous: Option<Neighbor>,
    pub next: Option<Neighbor>,
    /// File offset of the first CFFOLDER.
    pub folders_offset: usize,
}

impl<'a> Header<'a> {
    /// Read and check the CFHEADER of `data`; the whole cabinet must be
    /// present.
    pub fn read(data: &'a [u8]) -> Result<Self> {
        let fixed = slice(data, 0, CFHEADER_SIZE, "CFHEADER")?;
        if &fixed[..4] != SIGNATURE {
            return Err(error("Missing cabinet signature MSCF at 0x0"));
        }
        for (name, at) in [
            ("reserved1", RESERVED1_FIELD),
            ("reserved2", RESERVED2_FIELD),
            ("reserved3", RESERVED3_FIELD),
        ] {
            let value = le_u32(fixed, at)?;
            if value != 0 {
                return Err(error(format!(
                    "Invalid CFHEADER {name} 0x{value:X} at 0x{at:X}: it must be zero"
                )));
            }
        }
        let cabinet_size = to_usize(le_u32(fixed, CABINET_SIZE_FIELD)?);
        if cabinet_size < CFHEADER_SIZE {
            return Err(error(format!(
                "Invalid cbCabinet {cabinet_size} B at 0x{CABINET_SIZE_FIELD:X}: shorter than the \
                 CFHEADER"
            )));
        }
        if data.len() < cabinet_size {
            return Err(error(format!(
                "Truncated cabinet: {} B of the {cabinet_size} B that cbCabinet declares",
                data.len()
            )));
        }
        let cabinet = &data[..cabinet_size];
        let folder_count = usize::from(le_u16(fixed, FOLDER_COUNT_FIELD)?);
        let file_count = usize::from(le_u16(fixed, FILE_COUNT_FIELD)?);
        if folder_count == 0 {
            return Err(error(
                "Invalid CFHEADER: the cabinet has no folders (cFolders 0)",
            ));
        }
        if file_count == 0 {
            return Err(error(
                "Invalid CFHEADER: the cabinet has no files (cFiles 0)",
            ));
        }
        let flags = le_u16(fixed, FLAGS_FIELD)?;
        let mut pos = CFHEADER_SIZE;
        let (reserve_size, folder_reserve, data_reserve) = if flags & RESERVE_PRESENT != 0 {
            let sizes = slice(cabinet, pos, RESERVE_SIZES_SIZE, "CFHEADER reserve sizes")?;
            pos += RESERVE_SIZES_SIZE;
            (
                usize::from(u16::from_le_bytes([sizes[0], sizes[1]])),
                usize::from(sizes[2]),
                usize::from(sizes[3]),
            )
        } else {
            (0, 0, 0)
        };
        let reserve = slice(cabinet, pos, reserve_size, "CFHEADER reserve area")?;
        pos += reserve_size;
        let previous = if flags & PREV_CABINET != 0 {
            Some(read_neighbor(cabinet, &mut pos, "previous")?)
        } else {
            None
        };
        let next = if flags & NEXT_CABINET != 0 {
            Some(read_neighbor(cabinet, &mut pos, "next")?)
        } else {
            None
        };
        let files_offset = to_usize(le_u32(fixed, FILES_OFFSET_FIELD)?);
        let folders_end = folder_count
            .checked_mul(CFFOLDER_SIZE + folder_reserve)
            .and_then(|size| size.checked_add(pos))
            .ok_or_else(|| error("Invalid CFFOLDER table size"))?;
        if files_offset < folders_end {
            return Err(error(format!(
                "Invalid coffFiles 0x{files_offset:X} at 0x{FILES_OFFSET_FIELD:X}: the CFFOLDER \
                 table ends at 0x{folders_end:X}"
            )));
        }
        Ok(Self {
            cabinet_size,
            files_offset,
            version_major: fixed[VERSION_MAJOR_FIELD],
            version_minor: fixed[VERSION_MINOR_FIELD],
            folder_count,
            file_count,
            flags,
            set_id: le_u16(fixed, SET_ID_FIELD)?,
            index: le_u16(fixed, INDEX_FIELD)?,
            reserve,
            folder_reserve,
            data_reserve,
            previous,
            next,
            folders_offset: pos,
        })
    }

    /// End of the CFFOLDER table, which [`Header::read`] checked against
    /// `coffFiles`.
    fn folders_end(&self) -> usize {
        self.folders_offset + self.folder_count * (CFFOLDER_SIZE + self.folder_reserve)
    }

    /// The Authenticode signature the reserve area names, when it has the
    /// layout osslsigncode reads and the signature lies right after the
    /// cabinet, inside the input.
    pub fn signature(&self, data: &[u8]) -> Option<Signature> {
        if self.reserve.len() != SIGNATURE_RESERVE_SIZE
            || self.folder_reserve != 0
            || self.data_reserve != 0
            || le_u32(self.reserve, 0).ok()? != SIGNATURE_RESERVE_TAG
        {
            return None;
        }
        let offset = to_usize(le_u32(self.reserve, SIGNATURE_OFFSET_FIELD).ok()?);
        let size = to_usize(le_u32(self.reserve, SIGNATURE_SIZE_FIELD).ok()?);
        let end = offset.checked_add(size)?;
        (offset == self.cabinet_size && size > 0 && end <= data.len()).then_some(Signature {
            offset,
            size,
            end,
        })
    }

    /// Notes and metadata for the header.
    pub fn push_notes(&self, folders: &[Folder], files: usize, c: &mut Container<'_>) {
        let version = format!("{}.{}", self.version_major, self.version_minor);
        let mut kinds: Vec<(String, usize)> = Vec::new();
        for folder in folders {
            let name = folder.compression.to_string();
            match kinds.iter_mut().find(|(kind, _)| *kind == name) {
                Some((_, n)) => *n += 1,
                None => kinds.push((name, 1)),
            }
        }
        let kinds: Vec<String> = kinds
            .into_iter()
            .map(|(kind, n)| {
                if folders.len() == 1 {
                    kind
                } else {
                    format!("{n} {kind}")
                }
            })
            .collect();
        c.notes.push(format!(
            "Cabinet format {version}; {}: {}; {}",
            count(folders.len(), "folder", "folders"),
            kinds.join(", "),
            count(files, "file", "files")
        ));
        if (self.version_major, self.version_minor) != (VERSION_MAJOR, VERSION_MINOR) {
            c.notes.push(format!(
                "The cabinet declares format version {version}; the specification describes 1.3"
            ));
        }
        let unknown_flags = self.flags & !KNOWN_FLAGS;
        if unknown_flags != 0 {
            c.notes.push(format!(
                "Reserved CFHEADER flag bits 0x{unknown_flags:04X} are set"
            ));
        }
        if self.reserve.len() > MAX_HEADER_RESERVE {
            c.notes.push(format!(
                "The per-cabinet reserve area holds {} B; the specification allows at most 60,000 B",
                self.reserve.len()
            ));
        }
        if self.previous.is_some() || self.next.is_some() {
            let mut set = vec![format!(
                "Cabinet {} of set 0x{:04X}",
                self.index, self.set_id
            )];
            if let Some(previous) = &self.previous {
                set.push(format!("previous cabinet {}", neighbor_text(previous)));
            }
            if let Some(next) = &self.next {
                set.push(format!("next cabinet {}", neighbor_text(next)));
            }
            c.notes.push(set.join("; "));
        }
        if self.files_offset != self.folders_end() {
            c.notes.push(format!(
                "{} B between the CFFOLDER table and the CFFILE table at 0x{:X}",
                self.files_offset - self.folders_end(),
                self.files_offset
            ));
        }
        c.push_metadata("cab_version", "Cabinet format version", version);
        c.push_metadata("cab_folders", "Folders", folders.len() as u64);
        c.push_metadata("cab_files", "Files", files as u64);
        c.push_metadata("cab_flags", "Header flags", format!("0x{:04X}", self.flags));
        c.push_metadata("cab_set_id", "Set ID", format!("0x{:04X}", self.set_id));
        c.push_metadata(
            "cab_index",
            "Cabinet index in its set",
            u64::from(self.index),
        );
        if !self.reserve.is_empty() {
            c.push_metadata(
                "cab_header_reserve",
                "Per-cabinet reserve (B)",
                self.reserve.len() as u64,
            );
        }
        for (key, label, neighbor) in [
            ("cab_previous_cabinet", "Previous cabinet", &self.previous),
            ("cab_next_cabinet", "Next cabinet", &self.next),
        ] {
            if let Some(neighbor) = neighbor {
                c.push_metadata(key, label, MetadataValue::String(neighbor.cabinet.clone()));
            }
        }
    }
}

/// `name` (on `disk`) for notes.
fn neighbor_text(neighbor: &Neighbor) -> String {
    if neighbor.disk.is_empty() {
        format!("`{}`", neighbor.cabinet)
    } else {
        format!("`{}` (disk `{}`)", neighbor.cabinet, neighbor.disk)
    }
}

/// The signature of an Authenticode-signed cabinet.
#[derive(Debug)]
pub(super) struct Signature {
    /// File offset and size in bytes.
    pub offset: usize,
    pub size: usize,
    /// End of the signature, which is where the file's content ends.
    pub end: usize,
}

impl Signature {
    pub fn push_notes(&self, c: &mut Container<'_>) {
        c.notes.push(format!(
            "Authenticode signature present ({} B at 0x{:X}); not verified",
            self.size, self.offset
        ));
        c.push_metadata(
            "cab_signature_offset",
            "Signature offset",
            self.offset as u64,
        );
        c.push_metadata("cab_signature_size", "Signature size (B)", self.size as u64);
    }
}

/// A NUL-terminated name of at most 255 bytes at `pos`; `pos` moves past
/// the NUL.
fn read_name(cabinet: &[u8], pos: &mut usize, what: &str) -> Result<Vec<u8>> {
    let rest = cabinet.get(*pos..).unwrap_or_default();
    let window = &rest[..rest.len().min(MAX_NAME)];
    let Some(len) = memchr::memchr(0, window) else {
        return Err(error(format!(
            "Invalid {what} at 0x{:X}: no NUL within {MAX_NAME} B or the cabinet",
            *pos
        )));
    };
    let name = window[..len].to_vec();
    *pos += len + 1;
    Ok(name)
}

/// The cabinet and disk names of a neighbor; the cabinet name may not be
/// empty (libmspack `cabd_read_string`).
fn read_neighbor(cabinet: &[u8], pos: &mut usize, which: &str) -> Result<Neighbor> {
    let at = *pos;
    let name = read_name(cabinet, pos, &format!("{which} cabinet name"))?;
    if name.is_empty() {
        return Err(error(format!(
            "Invalid {which} cabinet name at 0x{at:X}: empty"
        )));
    }
    let disk = read_name(cabinet, pos, &format!("{which} disk name"))?;
    Ok(Neighbor {
        cabinet: String::from_utf8_lossy(&name).into_owned(),
        disk: String::from_utf8_lossy(&disk).into_owned(),
    })
}

/// A folder's compression (`typeCompress`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Compression {
    /// Stored blocks.
    None,
    MsZip,
    /// Quantum, which is not decoded.
    Quantum {
        level: u8,
        window_bits: u8,
    },
    Lzx {
        window_bits: u8,
    },
    /// A type the specification does not define (4-15).
    Unknown(u16),
}

impl Compression {
    fn from_field(value: u16) -> Self {
        let window_bits = u8::try_from((value >> WINDOW_SHIFT) & WINDOW_MASK).expect("5-bit field");
        match value & COMPRESSION_TYPE_MASK {
            TYPE_NONE => Self::None,
            TYPE_MSZIP => Self::MsZip,
            TYPE_QUANTUM => Self::Quantum {
                level: u8::try_from((value >> QUANTUM_LEVEL_SHIFT) & QUANTUM_LEVEL_MASK)
                    .expect("4-bit field"),
                window_bits,
            },
            TYPE_LZX => Self::Lzx { window_bits },
            other => Self::Unknown(other),
        }
    }
}

impl std::fmt::Display for Compression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("stored"),
            Self::MsZip => f.write_str("MSZIP"),
            Self::Quantum { level, window_bits } => {
                write!(f, "Quantum (level {level}, 2^{window_bits} B window)")
            }
            Self::Lzx { window_bits } => write!(f, "LZX (2^{window_bits} B window)"),
            Self::Unknown(kind) => write!(f, "unknown compression type {kind}"),
        }
    }
}

/// One CFFOLDER entry.
#[derive(Debug)]
pub(super) struct Folder {
    /// File offset of the entry.
    pub entry_offset: usize,
    /// `coffCabStart`: file offset of the first CFDATA block.
    pub data_offset: usize,
    /// `cCFData`: blocks at least partly in this cabinet.
    pub block_count: usize,
    pub compression: Compression,
    /// The raw `typeCompress` value.
    pub type_compress: u16,
}

/// The CFFOLDER entries: `coffCabStart` (0), `cCFData` (4),
/// `typeCompress` (6), then `cbCFFolder` reserve bytes. [`Header::read`]
/// checked that they end before `coffFiles`.
pub(super) fn read_folders(cabinet: &[u8], header: &Header<'_>) -> Result<Vec<Folder>> {
    let entry_size = CFFOLDER_SIZE + header.folder_reserve;
    let mut folders = Vec::with_capacity(header.folder_count);
    for i in 0..header.folder_count {
        let at = header.folders_offset + i * entry_size;
        let entry = slice(cabinet, at, entry_size, "CFFOLDER")?;
        let type_compress = le_u16(entry, 6)?;
        folders.push(Folder {
            entry_offset: at,
            data_offset: to_usize(le_u32(entry, 0)?),
            block_count: usize::from(le_u16(entry, 4)?),
            compression: Compression::from_field(type_compress),
            type_compress,
        });
    }
    Ok(folders)
}

/// The folder a CFFILE entry names (`iFolder`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FolderIndex {
    /// A folder of this cabinet.
    Folder(usize),
    /// Begins in the previous cabinet; the folder is the first one here.
    FromPrevious,
    /// Continues in the next cabinet; the folder is the last one here.
    ToNext,
    /// Both.
    PreviousAndNext,
}

/// One CFFILE entry: `cbFile` (0), `uoffFolderStart` (4), `iFolder` (8),
/// `date` (0x0A), `time` (0x0C), `attribs` (0x0E), `szName` (0x10).
#[derive(Debug)]
pub(super) struct FileEntry {
    /// File offset of the entry.
    pub entry_offset: usize,
    /// `cbFile`: size in bytes.
    pub size: usize,
    /// `uoffFolderStart`: offset in the folder's uncompressed bytes.
    pub folder_offset: usize,
    pub folder: FolderIndex,
    pub attributes: u16,
    /// The name, as UTF-8 when `_A_NAME_IS_UTF` is set; other names are in
    /// an unspecified code page and shown with replacement characters for
    /// bytes that are not UTF-8.
    pub name: String,
    /// The name has bytes above 0x7F without `_A_NAME_IS_UTF`, so its code
    /// page is unknown.
    pub name_in_code_page: bool,
}

impl FileEntry {
    /// Ends after the uncompressed bytes of its folder that it needs.
    pub fn end(&self) -> usize {
        self.folder_offset.saturating_add(self.size)
    }
}

/// The CFFILE entries at `coffFiles`: `cbFile` (0), `uoffFolderStart` (4),
/// `iFolder` (8), `date` (0x0A), `time` (0x0C), `attribs` (0x0E), then the
/// NUL-terminated `szName`.
pub(super) fn read_files(cabinet: &[u8], header: &Header<'_>) -> Result<Vec<FileEntry>> {
    let mut pos = header.files_offset;
    // Each entry takes at least its fixed fields, a name byte and the NUL.
    let room = cabinet.len().saturating_sub(pos) / (CFFILE_SIZE + 2);
    if header.file_count > room {
        return Err(error(format!(
            "Truncated CFFILE table at 0x{pos:X}: {} entries need more than the {} B left",
            header.file_count,
            cabinet.len().saturating_sub(pos)
        )));
    }
    let mut files = Vec::with_capacity(header.file_count);
    for _ in 0..header.file_count {
        let at = pos;
        let fixed = slice(cabinet, at, CFFILE_SIZE, "CFFILE")?;
        pos += CFFILE_SIZE;
        let raw_folder = le_u16(fixed, CFFILE_FOLDER_FIELD)?;
        let folder = match raw_folder {
            CONTINUED_FROM_PREV => FolderIndex::FromPrevious,
            CONTINUED_TO_NEXT => FolderIndex::ToNext,
            CONTINUED_PREV_AND_NEXT => FolderIndex::PreviousAndNext,
            index if usize::from(index) < header.folder_count => {
                FolderIndex::Folder(usize::from(index))
            }
            index => {
                return Err(error(format!(
                    "Invalid CFFILE iFolder {index} at 0x{:X}: the cabinet has {}",
                    at + CFFILE_FOLDER_FIELD,
                    count(header.folder_count, "folder", "folders")
                )))
            }
        };
        let attributes = le_u16(fixed, CFFILE_ATTRIBUTES_FIELD)?;
        let name_at = pos;
        let name = read_name(cabinet, &mut pos, "CFFILE szName")?;
        if name.is_empty() {
            return Err(error(format!(
                "Invalid CFFILE szName at 0x{name_at:X}: empty"
            )));
        }
        // Names flagged `_A_NAME_IS_UTF` are UTF-8 (SDK "UTF Encoding
        // Method"); others use a locale's code page, which the cabinet does
        // not name.
        let name_in_code_page =
            attributes & ATTRIBUTE_NAME_IS_UTF == 0 && name.iter().any(|&b| b > 0x7F);
        files.push(FileEntry {
            entry_offset: at,
            size: to_usize(le_u32(fixed, 0)?),
            folder_offset: to_usize(le_u32(fixed, 4)?),
            folder,
            attributes,
            name: String::from_utf8_lossy(&name).into_owned(),
            name_in_code_page,
        });
    }
    Ok(files)
}

/// Which folders of this cabinet continue into its neighbors, from the
/// files that say so (SDK "CFFOLDER": a folder is the beginning of a
/// folder unless its first file is continued from the previous cabinet).
#[derive(Debug, Default)]
pub(super) struct Continuation {
    /// The first folder began in the previous cabinet.
    pub first_from_previous: bool,
    /// The last folder continues in the next cabinet.
    pub last_to_next: bool,
}

impl Continuation {
    /// Derive the continuation from the file entries; a continued file in
    /// a cabinet whose header names no neighbor in that direction is an
    /// error.
    pub fn of(header: &Header<'_>, files: &[FileEntry]) -> Result<Self> {
        let mut continuation = Self::default();
        for file in files {
            let (from_previous, to_next) = match file.folder {
                FolderIndex::Folder(_) => continue,
                FolderIndex::FromPrevious => (true, false),
                FolderIndex::ToNext => (false, true),
                FolderIndex::PreviousAndNext => (true, true),
            };
            if from_previous && header.previous.is_none() {
                return Err(error(format!(
                    "Invalid CFFILE iFolder at 0x{:X}: `{}` continues from a previous cabinet \
                     that the header does not name",
                    file.entry_offset + CFFILE_FOLDER_FIELD,
                    file.name
                )));
            }
            if to_next && header.next.is_none() {
                return Err(error(format!(
                    "Invalid CFFILE iFolder at 0x{:X}: `{}` continues in a next cabinet that the \
                     header does not name",
                    file.entry_offset + CFFILE_FOLDER_FIELD,
                    file.name
                )));
            }
            continuation.first_from_previous |= from_previous;
            continuation.last_to_next |= to_next;
        }
        Ok(continuation)
    }

    /// Whether folder `index` began in the previous cabinet.
    pub fn starts_before(&self, index: usize) -> bool {
        self.first_from_previous && index == 0
    }

    /// Whether folder `index` of `folder_count` continues in the next
    /// cabinet.
    pub fn continues_after(&self, index: usize, folder_count: usize) -> bool {
        self.last_to_next && index + 1 == folder_count
    }
}
