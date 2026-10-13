//! Switch gamecard images (XCI): the card header (switchbrew "XCI", oldid
//! 13628, `CardHeader`; hactool `xci_header_t`), little-endian, then the
//! root `HFS0` whose entries are the `update`, `normal`, `secure` and `logo`
//! partitions, each an `HFS0` of NCAs ([`partition_fs`]).
//!
//! Card header: RSA-2048 signature (0x100), `HEAD` at 0x100, ROM area start
//! page (4) at 0x104, backup area start page (4), key indexes (1) at 0x10C,
//! ROM size code (1), header version (1), flags (1), package ID (8) at
//! 0x110, valid data end page (4) at 0x118, the reversed IV (0x10) at
//! 0x120, the root `HFS0` offset (8) at 0x130, its header size (8) and the
//! header's SHA-256 at 0x140, the initial data hash at 0x160, `SelSec` (4)
//! at 0x180 and 0x70 encrypted bytes at 0x190. Pages are 0x200 bytes. The
//! file starts with the card header; dumps that keep the 0x1000-byte key
//! area in front of it are not recognized.
//!
//! The root header hash covers the header-size bytes at the root offset,
//! with the compatibility type appended as a salt byte when it is not
//! global (hactool `check_memory_hash_table_with_suffix`, nstool
//! `processRootPfs`). The compatibility type is in the encrypted header
//! data, so, as hactool does without the header key, the hash is tried
//! without a salt and with salt 0x01 (China).

use super::partition_fs::{self, Kind, PartitionFs};
use super::*;

/// Prefix of this layout's metadata keys.
const KEY_PREFIX: &str = "xci";

/// Card header size and magic.
const HEADER_SIZE: usize = 0x200;
const MAGIC_OFFSET: usize = 0x100;
const MAGIC: &[u8; 4] = b"HEAD";

/// Card header fields.
const ROM_AREA_START_PAGE: usize = 0x104;
const KEY_INDEX: usize = 0x10c;
const ROM_SIZE: usize = 0x10d;
const HEADER_VERSION: usize = 0x10e;
const FLAGS: usize = 0x10f;
const PACKAGE_ID: usize = 0x110;
const VALID_DATA_END_PAGE: usize = 0x118;
const PARTITION_FS_HEADER_ADDRESS: usize = 0x130;
const PARTITION_FS_HEADER_SIZE: usize = 0x138;
const PARTITION_FS_HEADER_HASH: usize = 0x140;
const SEL_SEC: usize = 0x180;

/// Card pages are 0x200 bytes.
const PAGE_SIZE: u64 = 0x200;

/// Compatibility type salt of a China-region card (hactool `COMPAT_CHINA`).
const COMPAT_CHINA: u8 = 1;

/// The root partitions and the order their files are listed in: the game
/// (`secure`) first, the system update last, so update NCAs never decide
/// the ISA of a game card.
const PARTITIONS: [&str; 4] = ["secure", "normal", "logo", "update"];

/// Strong recognition: `HEAD` at 0x100 and an `HFS0` header, with its
/// tables, at the root partition offset the card header names.
pub(super) fn detect(data: &[u8]) -> bool {
    let has_magic = data
        .get(MAGIC_OFFSET..MAGIC_OFFSET + MAGIC.len())
        .is_some_and(|magic| magic == MAGIC);
    has_magic
        && le_u64(data, PARTITION_FS_HEADER_ADDRESS)
            .ok()
            .and_then(|offset| usize::try_from(offset).ok())
            .is_some_and(|offset| partition_fs::has_header(data, offset, Kind::Hfs0))
}

/// The card header fields this parser uses.
struct CardHeader {
    rom_area_start_page: u32,
    key_index: u8,
    rom_size: u8,
    version: u8,
    flags: u8,
    package_id: u64,
    /// One past the last valid byte: `(valid data end page + 1) * 0x200`.
    valid_data_end: u64,
    root_offset: u64,
    root_header_size: u64,
    root_header_hash: [u8; SHA256_SIZE],
    sel_sec: u32,
}

fn card_header(data: &[u8]) -> Result<CardHeader> {
    if data.len() < HEADER_SIZE {
        return Err(error(format!(
            "Truncated XCI card header: {} B of {HEADER_SIZE} B",
            data.len()
        )));
    }
    if &data[MAGIC_OFFSET..MAGIC_OFFSET + MAGIC.len()] != MAGIC {
        return Err(error("Missing XCI magic HEAD at 0x100"));
    }
    let valid_data_end_page = le_u32(data, VALID_DATA_END_PAGE)?;
    Ok(CardHeader {
        rom_area_start_page: le_u32(data, ROM_AREA_START_PAGE)?,
        key_index: data[KEY_INDEX],
        rom_size: data[ROM_SIZE],
        version: data[HEADER_VERSION],
        flags: data[FLAGS],
        package_id: le_u64(data, PACKAGE_ID)?,
        valid_data_end: (u64::from(valid_data_end_page) + 1) * PAGE_SIZE,
        root_offset: le_u64(data, PARTITION_FS_HEADER_ADDRESS)?,
        root_header_size: le_u64(data, PARTITION_FS_HEADER_SIZE)?,
        root_header_hash: array(data, PARTITION_FS_HEADER_HASH)?,
        sel_sec: le_u32(data, SEL_SEC)?,
    })
}

/// ROM size codes (switchbrew `RomSize`; hactool `cartridge_type_t`).
fn rom_size_name(code: u8) -> String {
    match code {
        0xfa => "1 GB".to_string(),
        0xf8 => "2 GB".to_string(),
        0xf0 => "4 GB".to_string(),
        0xe0 => "8 GB".to_string(),
        0xe1 => "16 GB".to_string(),
        0xe2 => "32 GB".to_string(),
        other => format!("unknown code 0x{other:02X}"),
    }
}

/// One root partition and its own `HFS0`.
struct Partition {
    name: &'static str,
    region: Region,
    /// Whether the root entry's hash of the partition header verifies.
    header_hash_matches: bool,
    fs: PartitionFs,
}

pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let header = card_header(data)?;
    let valid_end = usize::try_from(header.valid_data_end)
        .ok()
        .filter(|end| *end <= data.len())
        .ok_or_else(|| {
            error(format!(
                "Truncated XCI: valid data ends at 0x{:X}, file {} B",
                header.valid_data_end,
                data.len()
            ))
        })?;
    let root_offset = usize::try_from(header.root_offset)
        .ok()
        .filter(|offset| *offset >= HEADER_SIZE && *offset < valid_end)
        .ok_or_else(|| {
            error(format!(
                "Invalid XCI root partition offset 0x{:X}",
                header.root_offset
            ))
        })?;
    let root = partition_fs::parse(data, root_offset, valid_end, Kind::Hfs0)?;
    let partitions = root_partitions(data, &root)?;
    let trailing = &data[valid_end..];
    if !is_padding(trailing) {
        return Err(error(format!(
            "Unexpected data in the {} after the XCI valid data end 0x{valid_end:X}",
            size_text(trailing.len())
        )));
    }

    let mut c = Container::new(FileFormat::Xci, Layout::Xci.label(), KEY_PREFIX);
    c.consumed = data.len();
    push_header_notes(&mut c, &header, root_header_hash(data, &header));
    let mut members = Members::new(data.len());
    for name in PARTITIONS {
        let Some(partition) = partitions.iter().find(|p| p.name == name) else {
            continue;
        };
        push_partition_notes(&mut c, data, partition);
        for file in &partition.fs.files {
            members.offer(
                format!("{name}/{}", file.name),
                file.region.offset,
                file.region.bytes(data),
            );
        }
    }
    members.finish(&mut c, "partition file", "partition files");
    Ok(c)
}

/// The root entries as partitions: at most four, each named once from
/// [`PARTITIONS`] (hactool `xci_process`), each an `HFS0` inside its entry.
fn root_partitions(data: &[u8], root: &PartitionFs) -> Result<Vec<Partition>> {
    if root.entry_count > PARTITIONS.len() {
        return Err(error(format!(
            "Invalid XCI root partition count {} (at most {})",
            root.entry_count,
            PARTITIONS.len()
        )));
    }
    let mut partitions: Vec<Partition> = Vec::new();
    for file in &root.files {
        let name = PARTITIONS
            .iter()
            .find(|name| **name == file.name)
            .ok_or_else(|| error(format!("Unknown XCI partition {}", file.name)))?;
        if partitions.iter().any(|p| p.name == *name) {
            return Err(error(format!("Duplicate XCI partition {name}")));
        }
        let fs = partition_fs::parse(data, file.region.offset, file.region.end(), Kind::Hfs0)?;
        partitions.push(Partition {
            name,
            region: file.region,
            header_hash_matches: file.hash_matches(data),
            fs,
        });
    }
    Ok(partitions)
}

/// How the root `HFS0` header hash compares.
#[derive(Debug, Clone, Copy)]
enum RootHash {
    /// Matches without a salt (global card).
    Global,
    /// Matches with the China compatibility salt.
    China,
    /// Matches neither.
    Mismatch,
    /// The declared header range lies outside the file.
    OutOfRange,
}

fn root_header_hash(data: &[u8], header: &CardHeader) -> RootHash {
    let Some(region) = region_within(header.root_offset, header.root_header_size, data.len())
    else {
        return RootHash::OutOfRange;
    };
    let bytes = region.bytes(data);
    if sha256_matches(bytes, &header.root_header_hash) {
        return RootHash::Global;
    }
    let mut salted = Sha256::new();
    salted.update(bytes);
    salted.update([COMPAT_CHINA]);
    if salted.finalize().as_slice() == header.root_header_hash {
        RootHash::China
    } else {
        RootHash::Mismatch
    }
}

fn push_header_notes(c: &mut Container<'_>, header: &CardHeader, root_hash: RootHash) {
    c.notes.push(format!(
        "Switch gamecard image; ROM size {}; header version {}; flags 0x{:02X}; package ID 0x{:016X}; valid data ends at 0x{:X}; the container names no CPU",
        rom_size_name(header.rom_size),
        header.version,
        header.flags,
        header.package_id,
        header.valid_data_end
    ));
    let root_hash = match root_hash {
        RootHash::Global => "verified",
        RootHash::China => "verified with the China compatibility salt",
        RootHash::Mismatch => "does not match",
        RootHash::OutOfRange => "not verified: the declared header lies outside the file",
    };
    c.notes.push(format!(
        "Root HFS0 at 0x{:X}; header SHA-256 {root_hash}",
        header.root_offset
    ));
    c.notes.push(format!(
        "The card header RSA-2048 signature is not verified and its encrypted data (key index 0x{:02X}, SelSec {}) is not decrypted",
        header.key_index, header.sel_sec
    ));
    c.push_metadata(
        format!("{KEY_PREFIX}_rom_size"),
        "ROM size",
        rom_size_name(header.rom_size),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_package_id"),
        "Package ID",
        format!("0x{:016X}", header.package_id),
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_rom_area_start"),
        "ROM area start (B)",
        u64::from(header.rom_area_start_page) * PAGE_SIZE,
    );
    c.push_metadata(
        format!("{KEY_PREFIX}_valid_data_end"),
        "Valid data end (B)",
        header.valid_data_end,
    );
}

fn push_partition_notes(c: &mut Container<'_>, data: &[u8], partition: &Partition) {
    let hashes = partition_fs::check_hashes(data, &partition.fs);
    let mismatch = if hashes.mismatched.is_empty() {
        String::new()
    } else {
        format!("; mismatch for {}", bounded_list(&hashes.mismatched))
    };
    let header_hash = if partition.header_hash_matches {
        "verified"
    } else {
        "does not match"
    };
    c.notes.push(format!(
        "Partition {} at 0x{:X} ({}): {}; header SHA-256 {header_hash}; hashed regions verified for {} of {}{mismatch}",
        partition.name,
        partition.region.offset,
        size_text(partition.region.size),
        counted(partition.fs.entry_count, "file", "files"),
        hashes.verified,
        partition.fs.files.len()
    ));
    c.push_metadata(
        format!("{KEY_PREFIX}_partition_{}", partition.name),
        format!("Partition {}", partition.name),
        format!(
            "file 0x{:X}; {} B; {}",
            partition.region.offset,
            partition.region.size,
            counted(partition.fs.entry_count, "file", "files")
        ),
    );
    if partition.fs.entry_count > partition.fs.files.len() {
        c.notes.push(format!(
            "Partition {}: member limit reached ({MAX_COMPONENTS} members); not listed: {}",
            partition.name,
            counted(
                partition.fs.entry_count - partition.fs.files.len(),
                "further file",
                "further files"
            )
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rom_size_codes_follow_switchbrew() {
        assert_eq!(rom_size_name(0xfa), "1 GB");
        assert_eq!(rom_size_name(0xe2), "32 GB");
        assert_eq!(rom_size_name(0x00), "unknown code 0x00");
    }

    #[test]
    fn partitions_list_the_game_first_and_the_update_last() {
        assert_eq!(PARTITIONS.first(), Some(&"secure"));
        assert_eq!(PARTITIONS.last(), Some(&"update"));
    }
}
