//! Switch `PartitionFs` tables: `PFS0` (switchbrew "NCA", oldid 14983,
//! section `PFS0`; hactool `pfs0.h`) and its hashed form `HFS0` (switchbrew
//! "XCI", oldid 13628; hactool `hfs0.h`), all little-endian.
//!
//! Header: magic (4), entry count (4), string table size (4), reserved (4);
//! then the entry table, the string table of NUL-terminated names, and the
//! file data. A `PFS0` entry (0x18 B) holds the data offset (8), size (8),
//! name offset (4) and a reserved word; an `HFS0` entry (0x40 B) adds the
//! size of its hashed region (4), 8 reserved bytes and the SHA-256 of the
//! first hashed-region bytes of the file. Data offsets count from the end
//! of the string table (hactool `pfs0_save_file`, `hfs0_save_file`).

use super::*;

/// The header before the entry table.
const HEADER_SIZE: usize = 0x10;
const ENTRY_COUNT: usize = 4;
const STRING_TABLE_SIZE: usize = 8;

/// Entry fields shared by both variants.
const ENTRY_DATA_OFFSET: usize = 0;
const ENTRY_DATA_SIZE: usize = 8;
const ENTRY_NAME_OFFSET: usize = 0x10;

/// Longest file name read, in bytes (Linux `PATH_MAX`, as for the other
/// filesystem families; the sources set no limit).
const MAX_NAME_SIZE: usize = 4096;

/// `HFS0` entry fields.
const HFS0_HASHED_SIZE: usize = 0x14;
const HFS0_HASH: usize = 0x20;

/// A `PartitionFs` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// `PFS0`: entries without hashes.
    Pfs0,
    /// `HFS0`: entries with the SHA-256 of a hashed region.
    Hfs0,
}

impl Kind {
    fn magic(self) -> &'static [u8; 4] {
        match self {
            Self::Pfs0 => b"PFS0",
            Self::Hfs0 => b"HFS0",
        }
    }

    fn entry_size(self) -> usize {
        match self {
            Self::Pfs0 => 0x18,
            Self::Hfs0 => 0x40,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Pfs0 => "PFS0",
            Self::Hfs0 => "HFS0",
        }
    }
}

/// The hashed region of an `HFS0` file: its first `size` bytes.
#[derive(Debug, Clone, Copy)]
pub(super) struct HashedRegion {
    pub(super) size: usize,
    pub(super) sha256: [u8; SHA256_SIZE],
}

/// One file of a `PartitionFs`, in file coordinates.
#[derive(Debug)]
pub(super) struct File {
    pub(super) name: String,
    pub(super) region: Region,
    /// `HFS0` only.
    pub(super) hashed: Option<HashedRegion>,
}

impl File {
    /// Whether the hashed region lies in the file and its SHA-256 matches.
    /// `PFS0` files have no hash and never verify.
    pub(super) fn hash_matches(&self, data: &[u8]) -> bool {
        let Some(hashed) = self.hashed else {
            return false;
        };
        hashed.size <= self.region.size
            && sha256_matches(&self.region.bytes(data)[..hashed.size], &hashed.sha256)
    }
}

/// A parsed `PartitionFs`.
#[derive(Debug)]
pub(super) struct PartitionFs {
    /// Header, entry table and string table, in bytes.
    pub(super) header_size: usize,
    /// Entries in the table, listed or not.
    pub(super) entry_count: usize,
    /// The first [`MAX_COMPONENTS`] files, in table order.
    pub(super) files: Vec<File>,
    /// One past the end of the header and of every file.
    pub(super) end: usize,
}

/// The entry count and string table size of a header whose magic matches
/// and whose tables fit.
struct Tables {
    entry_count: usize,
    string_table_size: usize,
}

fn tables(data: &[u8], offset: usize, limit: usize, kind: Kind) -> Result<Tables> {
    let fs = kind.name();
    let available = limit.saturating_sub(offset);
    let header = data
        .get(..limit)
        .and_then(|bounded| slice(bounded, offset, HEADER_SIZE).ok())
        .ok_or_else(|| error(format!("Truncated {fs} header at 0x{offset:X}")))?;
    if &header[..4] != kind.magic() {
        return Err(error(format!("Missing {fs} magic at 0x{offset:X}")));
    }
    let entry_count = le_u32(header, ENTRY_COUNT)? as usize;
    let string_table_size = le_u32(header, STRING_TABLE_SIZE)? as usize;
    if entry_count > (available - HEADER_SIZE) / kind.entry_size() {
        return Err(error(format!(
            "Truncated {fs} entry table at 0x{offset:X}: {entry_count} entries in {}",
            size_text(available)
        )));
    }
    let entry_table_end = HEADER_SIZE + entry_count * kind.entry_size();
    if string_table_size > available - entry_table_end {
        return Err(error(format!(
            "Truncated {fs} string table at 0x{:X}: {string_table_size} B",
            offset + entry_table_end
        )));
    }
    Ok(Tables {
        entry_count,
        string_table_size,
    })
}

/// Whether a `PartitionFs` header of `kind` starts at `offset` and its
/// entry and string tables fit in `data`.
pub(super) fn has_header(data: &[u8], offset: usize, kind: Kind) -> bool {
    offset < data.len() && tables(data, offset, data.len(), kind).is_ok()
}

/// Parse the `PartitionFs` at `offset` whose files must end before `limit`
/// (at most `data.len()`).
pub(super) fn parse(data: &[u8], offset: usize, limit: usize, kind: Kind) -> Result<PartitionFs> {
    let fs = kind.name();
    let Tables {
        entry_count,
        string_table_size,
    } = tables(data, offset, limit, kind)?;
    let entry_table = offset + HEADER_SIZE;
    let string_table_offset = entry_table + entry_count * kind.entry_size();
    let string_table = &data[string_table_offset..string_table_offset + string_table_size];
    let data_start = string_table_offset + string_table_size;
    let mut files = Vec::new();
    let mut end = data_start;
    let mut previous_end = 0u64;
    for index in 0..entry_count {
        let entry = &data[entry_table + index * kind.entry_size()..][..kind.entry_size()];
        let name = entry_name(entry, string_table, index, kind)?;
        let data_offset = le_u64(entry, ENTRY_DATA_OFFSET)?;
        let size = le_u64(entry, ENTRY_DATA_SIZE)?;
        // hactool's `hfs0_process` rejects an entry that starts before the
        // previous entries end; PFS0 readers check nothing of the kind.
        if kind == Kind::Hfs0 && data_offset < previous_end {
            return Err(error(format!(
                "Invalid HFS0 entry {name} in the HFS0 at 0x{offset:X}: data offset 0x{data_offset:X} overlaps the previous entry"
            )));
        }
        previous_end = data_offset.saturating_add(size);
        let region = u64::try_from(data_start)
            .ok()
            .and_then(|start| start.checked_add(data_offset))
            .and_then(|start| region_within(start, size, limit))
            .ok_or_else(|| {
                error(format!(
                    "Invalid {fs} entry {name} in the {fs} at 0x{offset:X}: data 0x{data_offset:X} + {size} B beyond the {} {fs}",
                    size_text(limit - offset)
                ))
            })?;
        end = end.max(region.end());
        if files.len() < MAX_COMPONENTS {
            files.push(File {
                name,
                region,
                hashed: hashed_region(entry, kind)?,
            });
        }
    }
    Ok(PartitionFs {
        header_size: data_start - offset,
        entry_count,
        files,
        end,
    })
}

/// The name of entry `index`: NUL-terminated inside the string table within
/// [`MAX_NAME_SIZE`] bytes, so every entry scans a bounded part of the
/// table.
fn entry_name(entry: &[u8], string_table: &[u8], index: usize, kind: Kind) -> Result<String> {
    let name_offset = le_u32(entry, ENTRY_NAME_OFFSET)? as usize;
    let name = string_table.get(name_offset..).and_then(|rest| {
        let window = &rest[..rest.len().min(MAX_NAME_SIZE + 1)];
        window
            .iter()
            .position(|b| *b == 0)
            .map(|end| &window[..end])
    });
    let Some(name) = name else {
        return Err(error(format!(
            "Invalid {} entry {index}: name offset 0x{name_offset:X} has no name terminated within {MAX_NAME_SIZE} B in the {} B string table",
            kind.name(),
            string_table.len()
        )));
    };
    Ok(name_text(name))
}

fn hashed_region(entry: &[u8], kind: Kind) -> Result<Option<HashedRegion>> {
    if kind != Kind::Hfs0 {
        return Ok(None);
    }
    Ok(Some(HashedRegion {
        size: le_u32(entry, HFS0_HASHED_SIZE)? as usize,
        sha256: array(entry, HFS0_HASH)?,
    }))
}

/// The files of `fs` whose hashed region verifies, and the names of those
/// that do not.
pub(super) struct HashCheck {
    pub(super) verified: usize,
    pub(super) mismatched: Vec<String>,
}

/// Check the hashed region of every listed `HFS0` file.
pub(super) fn check_hashes(data: &[u8], fs: &PartitionFs) -> HashCheck {
    let mut check = HashCheck {
        verified: 0,
        mismatched: Vec::new(),
    };
    for file in &fs.files {
        if file.hash_matches(data) {
            check.verified += 1;
        } else {
            check.mismatched.push(file.name.clone());
        }
    }
    check
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PFS0 with one file `a` of 4 bytes, name table padded to 8 bytes.
    fn pfs0() -> Vec<u8> {
        let mut data = b"PFS0".to_vec();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&4u64.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(b"a\0\0\0\0\0\0\0");
        data.extend_from_slice(b"wxyz");
        data
    }

    #[test]
    fn pfs0_entries_count_from_the_end_of_the_string_table() {
        let data = pfs0();
        let fs = parse(&data, 0, data.len(), Kind::Pfs0).unwrap();
        assert_eq!(fs.header_size, 0x30);
        assert_eq!(fs.files[0].name, "a");
        assert_eq!(fs.files[0].region.bytes(&data), b"wxyz");
        assert_eq!(fs.end, data.len());
        assert!(!fs.files[0].hash_matches(&data));
    }

    #[test]
    fn counts_and_tables_are_checked_against_the_bytes() {
        let data = pfs0();
        assert!(has_header(&data, 0, Kind::Pfs0));
        assert!(!has_header(&data, 0, Kind::Hfs0));
        assert!(!has_header(&data, data.len(), Kind::Pfs0));
        let mut huge = data.clone();
        huge[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!has_header(&huge, 0, Kind::Pfs0));
        let mut beyond = data.clone();
        beyond[0x18..0x20].copy_from_slice(&5u64.to_le_bytes());
        assert!(parse(&beyond, 0, beyond.len(), Kind::Pfs0).is_err());
        let mut unterminated = data;
        unterminated[0x20..0x24].copy_from_slice(&8u32.to_le_bytes());
        assert!(parse(&unterminated, 0, unterminated.len(), Kind::Pfs0).is_err());
    }

    #[test]
    fn names_must_end_within_the_name_limit() {
        let mut entry = [0u8; 0x18];
        let mut table = vec![b'n'; MAX_NAME_SIZE];
        table.push(0);
        assert_eq!(
            entry_name(&entry, &table, 0, Kind::Pfs0).unwrap().len(),
            MAX_NAME_SIZE
        );
        table.insert(0, b'n');
        assert!(entry_name(&entry, &table, 0, Kind::Pfs0).is_err());
        entry[ENTRY_NAME_OFFSET] = 1;
        assert!(entry_name(&entry, &table, 0, Kind::Pfs0).is_ok());
    }
}
