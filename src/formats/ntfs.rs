//! NTFS volumes: the boot sector, the master file table (`$MFT`) located
//! through its own runlist, MFT records with their update sequence fixups,
//! resident and non-resident attributes, attribute lists, named data
//! streams, sparse and LZNT1-compressed data, and a walk of the MFT that
//! lists regular files in a recognized format as members labelled by path.
//!
//! Sources:
//! - [LAYOUT] tuxera/ntfs-3g tag `2022.10.3` (commit
//!   `78414d93613532fd82f3a82aba5d4a1c32898781`), `include/ntfs-3g/layout.h`
//!   (on-disk structures and constants) and `include/ntfs-3g/param.h`
//!   (`NTFS_MAX_CLUSTER_SIZE`, `STANDARD_COMPRESSION_UNIT`,
//!   `MAX_COMPRESSION_CLUSTER_SIZE`).
//! - [NTFS-3G] the same tag: `libntfs-3g/bootsect.c`
//!   (`ntfs_boot_sector_is_ntfs`, `ntfs_boot_sector_parse`),
//!   `libntfs-3g/mst.c` (update sequence fixups), `libntfs-3g/mft.c`
//!   (`ntfs_mft_record_check`), `libntfs-3g/attrib.c`
//!   (`ntfs_attr_inconsistent`, the compression unit checks of
//!   `ntfs_attr_open`), `libntfs-3g/runlist.c`
//!   (`ntfs_mapping_pairs_decompress_i`), `libntfs-3g/volume.c`
//!   (`ntfs_mft_load`), `libntfs-3g/compress.c`
//!   (`ntfs_compressed_attr_pread`, `ntfs_is_cb_compressed`) and
//!   `libntfs-3g/dir.c` (`ntfs_interix_types`).
//! - [DOCS] Richard Russon and Yuval Fledel, "NTFS Documentation"
//!   (linux-ntfs project), flatcap/ntfs-docs commit
//!   `641edd36dc5f6b62c2aae6658c5a60a4d6d3fe29`: `files/boot.html`,
//!   `files/mftmirr.html`, `concepts/file_record.html`,
//!   `concepts/fixup.html`, `concepts/attribute_header.html`,
//!   `concepts/data_runs.html`, `concepts/compression.html`,
//!   `attributes/file_name.html` and `attributes/attribute_list.html`.
//! - [MS-XCA] v20240423, section 2.5, for the LZNT1 codec (see
//!   `compressed::Codec::Lznt1`).
//! - [TSK] The Sleuth Kit `sleuthkit-4.12.1`, `tsk/fs/fs_dir.c`, for the
//!   `$OrphanFiles` directory under which files unreachable from the root
//!   are listed.
//!
//! All fields are little-endian. Cluster numbers count clusters of
//! `bytes_per_sector * sectors_per_cluster` bytes from the boot sector, which
//! starts the input; offsets in notes, metadata and members are file bytes.
//! The volume names no processor, so members are classified from their own
//! bytes.
//!
//! Directory tree: every MFT record in use is read in record order, and a
//! file's path is built from the parent directory references of its
//! `$FILE_NAME` attributes up to the root directory (record 5), with cycle
//! detection and a depth limit. The `$I30` index B+ trees are not read: the
//! parent references name the same directories, and reading the records in
//! order needs no index nodes.
//!
//! A volume larger than the input (`number_of_sectors` times
//! `bytes_per_sector`) is read as a truncated volume when its boot sector,
//! the records that locate the MFT and the root directory's record are
//! present: MFT records past the end of the input are counted, and files are
//! listed only when all of their data is present.

use crate::error::{ClassifierError, Result};
use crate::formats::compressed::size_text;
use crate::formats::container::Container;
use crate::types::FileFormat;

mod boot;
mod data;
mod mft;
mod record;
mod runlist;
mod walk;

use boot::BootSector;
use mft::Mft;
use record::{Record, Reference};

/// Size of the boot sector ([LAYOUT] `NTFS_BOOT_SECTOR`: "`sizeof()` = 512").
const BOOT_SECTOR_SIZE: usize = 512;

/// System files ([LAYOUT] `NTFS_SYSTEM_FILES`).
const MFT_RECORD: u64 = 0;
const VOLUME_RECORD: u64 = 3;
const ROOT_RECORD: u64 = 5;
const FIRST_USER_RECORD: u64 = 16;

/// Attribute types ([LAYOUT] `ATTR_TYPES`).
const AT_STANDARD_INFORMATION: u32 = 0x10;
const AT_ATTRIBUTE_LIST: u32 = 0x20;
const AT_FILE_NAME: u32 = 0x30;
const AT_VOLUME_NAME: u32 = 0x60;
const AT_VOLUME_INFORMATION: u32 = 0x70;
const AT_DATA: u32 = 0x80;
const AT_INDEX_ALLOCATION: u32 = 0xa0;
const AT_REPARSE_POINT: u32 = 0xc0;
const AT_LOGGED_UTILITY_STREAM: u32 = 0x100;
const AT_END: u32 = 0xffff_ffff;

/// Attribute flags ([LAYOUT] `ATTR_FLAGS`): the compression method in the
/// low byte (1 is LZNT1), encryption and sparseness.
const ATTR_COMPRESSION_MASK: u16 = 0x00ff;
const ATTR_IS_COMPRESSED: u16 = 0x0001;
const ATTR_IS_ENCRYPTED: u16 = 0x4000;
const ATTR_IS_SPARSE: u16 = 0x8000;

/// `$STANDARD_INFORMATION` file attribute flags ([LAYOUT]
/// `FILE_ATTR_FLAGS`).
const FILE_ATTR_SYSTEM: u32 = 0x0000_0004;
const FILE_ATTR_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_ATTR_ENCRYPTED: u32 = 0x0000_4000;

/// `$VOLUME_INFORMATION` flags ([LAYOUT] `VOLUME_FLAGS`).
const VOLUME_IS_DIRTY: u16 = 0x0001;
const VOLUME_CHKDSK_UNDERWAY: u16 = 0x4000;
const VOLUME_MODIFIED_BY_CHKDSK: u16 = 0x8000;

/// The `$MFTMirr` copy holds the first four records, or one cluster of
/// records when a cluster holds more ([LAYOUT] `FILE_MFTMirr`; [NTFS-3G]
/// `ntfs_boot_sector_parse`).
const MIRRORED_RECORDS: usize = 4;

/// An NTFS volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Boot sector with the OEM ID `NTFS    ` at offset 3, starting the
    /// input.
    Ntfs,
}

impl Layout {
    /// The reported file format.
    pub fn format(self) -> FileFormat {
        match self {
            Self::Ntfs => FileFormat::Ntfs,
        }
    }

    /// Human-readable layout name, used as the format variant.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ntfs => "NTFS",
        }
    }

    /// The layout is strong: the OEM ID, the boot sector signature and a
    /// consistent BIOS parameter block.
    pub fn is_weak(self) -> bool {
        match self {
            Self::Ntfs => false,
        }
    }
}

fn error(message: impl Into<String>) -> ClassifierError {
    ClassifierError::NtfsParseError {
        message: message.into(),
    }
}

/// Why a read of the volume failed.
#[derive(Debug)]
enum Fault {
    /// The volume is invalid; the error says how.
    Invalid(ClassifierError),
    /// The bytes lie inside the volume but past the end of the input, which
    /// holds only the start of a truncated volume.
    Absent,
}

impl From<ClassifierError> for Fault {
    fn from(e: ClassifierError) -> Self {
        Self::Invalid(e)
    }
}

/// The result of a read of the volume's bytes.
type ReadResult<T> = std::result::Result<T, Fault>;

/// A read that failed because the volume is invalid.
fn invalid<T>(message: impl Into<String>) -> ReadResult<T> {
    Err(Fault::Invalid(error(message)))
}

/// A size in bytes as text; a size past the address space in bytes.
fn volume_size_text(size: u64) -> String {
    usize::try_from(size).map_or_else(|_| format!("{size} B"), size_text)
}

/// The `len` bytes at `start`.
fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| error(format!("Invalid range 0x{start:X} + {len} B")))?;
    data.get(start..end)
        .ok_or_else(|| error(format!("Truncated structure at 0x{start:X} + {len} B")))
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, at, 2)?
        .try_into()
        .expect("slice has exactly 2 bytes");
    Ok(u16::from_le_bytes(bytes))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, at, 4)?
        .try_into()
        .expect("slice has exactly 4 bytes");
    Ok(u32::from_le_bytes(bytes))
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    let bytes: [u8; 8] = slice(data, at, 8)?
        .try_into()
        .expect("slice has exactly 8 bytes");
    Ok(u64::from_le_bytes(bytes))
}

fn le_i64(data: &[u8], at: usize) -> Result<i64> {
    let bytes: [u8; 8] = slice(data, at, 8)?
        .try_into()
        .expect("slice has exactly 8 bytes");
    Ok(i64::from_le_bytes(bytes))
}

/// UTF-16LE code units as text; unpaired surrogates become U+FFFD.
fn utf16_text(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Erased flash or zero fill.
fn is_padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| matches!(b, 0x00 | 0xff))
}

/// The text of a `ClassifierError` without the family prefix.
fn message(e: ClassifierError) -> String {
    match e {
        ClassifierError::NtfsParseError { message } => message,
        other => other.to_string(),
    }
}

/// Detect an NTFS volume: the OEM ID `NTFS    ` at offset 3, the signature
/// `55 AA` at 510, and a BIOS parameter block that ntfs-3g accepts (sector
/// size 256 to 4096 B, a power of two; a cluster of at most 2 MiB; zero FAT
/// fields; documented MFT and index record size encodings; `$MFT` and
/// `$MFTMirr` at distinct clusters inside the volume). The MFT and the files
/// are checked by [`parse_container`], so a damaged volume with a consistent
/// boot sector is a parse error.
pub fn detect(data: &[u8]) -> Option<Layout> {
    BootSector::read(data).ok().map(|_| Layout::Ntfs)
}

/// The volume's bytes and geometry.
struct Volume<'a> {
    /// The volume's bytes, or those present when the input ends inside the
    /// volume.
    data: &'a [u8],
    boot: BootSector,
}

impl<'a> Volume<'a> {
    fn cluster_size(&self) -> u64 {
        u64::from(self.boot.cluster_size)
    }

    /// Whether the input ends before the volume does.
    fn is_truncated(&self) -> bool {
        (self.data.len() as u64) < self.boot.volume_size()
    }

    /// The bytes of the volume present, as text for notes.
    fn present_text(&self) -> String {
        size_text(self.data.len())
    }

    /// The bytes of `count` clusters from cluster `lcn`, which must lie
    /// inside the volume; absent when they pass the end of the input.
    fn clusters(&self, lcn: u64, count: u64) -> ReadResult<&'a [u8]> {
        let end = lcn.checked_add(count);
        if end.map_or(true, |end| end > self.boot.cluster_count) {
            return invalid(format!(
                "Invalid cluster range 0x{lcn:X} + {count} beyond the {} clusters of the volume",
                self.boot.cluster_count
            ));
        }
        self.present(lcn * self.cluster_size(), count * self.cluster_size())
    }

    /// The `len` bytes at volume offset `at`, a range inside the volume;
    /// absent when they pass the end of the input.
    fn present(&self, at: u64, len: u64) -> ReadResult<&'a [u8]> {
        let range = at
            .checked_add(len)
            .filter(|&end| end <= self.data.len() as u64)
            .and_then(|end| Some(usize::try_from(at).ok()?..usize::try_from(end).ok()?));
        match range {
            Some(range) => Ok(&self.data[range]),
            None => Err(Fault::Absent),
        }
    }
}

/// A read of a structure the volume cannot be listed without: bytes past
/// the end of the input are the error `truncation`.
fn needed<T>(read: ReadResult<T>, truncation: impl FnOnce() -> ClassifierError) -> Result<T> {
    match read {
        Ok(value) => Ok(value),
        Err(Fault::Invalid(e)) => Err(e),
        Err(Fault::Absent) => Err(truncation()),
    }
}

/// The error for a volume whose structures needed before anything can be
/// listed lie past the end of the input.
fn truncated_volume(boot: &BootSector, present: usize) -> ClassifierError {
    error(format!(
        "Truncated volume: {} sectors of {} need {} B, {present} B present",
        boot.total_sectors,
        size_text(boot.bytes_per_sector as usize),
        boot.volume_size()
    ))
}

/// The NTFS version in `$VOLUME_INFORMATION` (3.1 for Windows XP and
/// later).
#[derive(Debug, Clone, Copy)]
struct Version {
    major: u8,
    minor: u8,
}

/// What `$Volume` (record 3) says about the volume.
#[derive(Debug, Default)]
struct VolumeInfo {
    /// `$VOLUME_NAME`, the volume label.
    name: Option<String>,
    /// `$VOLUME_INFORMATION` version.
    version: Option<Version>,
    /// `$VOLUME_INFORMATION` flags.
    flags: u16,
}

/// What follows a complete volume in the input.
struct Trailer {
    /// Bytes of the input that belong to the volume: the volume and its
    /// backup boot sector.
    consumed: usize,
    /// The backup boot sector after the volume, if there is one.
    backup: Option<BackupBootSector>,
}

/// A backup boot sector in the sector after the volume.
struct BackupBootSector {
    /// File offset.
    offset: usize,
    /// Bytes of it in the input.
    size: usize,
    /// How it compares with the boot sector.
    state: Backup,
}

/// How a backup boot sector compares with the boot sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backup {
    /// A whole sector equal to the boot sector.
    Matches,
    /// A whole sector that is a valid boot sector but differs.
    Differs,
    /// The input ends inside it, after bytes equal to the boot sector's.
    CutShort,
}

/// Parse an NTFS volume into the shared container model. Regular files
/// whose first bytes are a recognized format, and named data streams that
/// are, are its children, labelled by their path; LZNT1-compressed data is
/// decoded first.
///
/// # Errors
///
/// [`ClassifierError::NtfsParseError`] for an invalid boot sector, a
/// complete volume followed by data other than the backup boot sector or
/// padding, an invalid `$MFT` record or runlist, a missing or invalid root
/// directory, and for a volume larger than the input whose `$MFT` record or
/// root directory record lies past the end of the input. Damage in other
/// records is reported in notes instead.
pub fn parse_container(data: &[u8], layout: Layout) -> Result<Container<'_>> {
    let boot = BootSector::read(data)?;
    let volume_size = boot.volume_size();
    let trailer = match usize::try_from(volume_size)
        .ok()
        .filter(|&size| size <= data.len())
    {
        Some(size) => trailer(data, size, &boot)?,
        // The input ends inside the volume: all of it belongs to the volume.
        None => Trailer {
            consumed: data.len(),
            backup: None,
        },
    };
    let present = usize::try_from(volume_size).map_or(data.len(), |size| size.min(data.len()));
    let truncation = || truncated_volume(&boot, data.len());
    let vol = Volume {
        data: &data[..present],
        boot: boot.clone(),
    };
    // The MFT's own record and the root directory must be present; without
    // them nothing can be listed.
    let mft = needed(Mft::open(&vol), truncation)?;
    let root = needed(mft.record(&vol, ROOT_RECORD), truncation)?;
    check_root(root.as_ref())?;
    let mut c = Container::new(layout.format(), layout.label(), "ntfs");
    c.consumed = trailer.consumed;
    let info = volume_info(&vol, &mft, &mut c);
    describe(&vol, &mft, &info, trailer.backup.as_ref(), &mut c);
    mirror_note(&vol, &mft, &mut c);
    walk::walk(&vol, &mft, &mut c);
    Ok(c)
}

/// What follows a complete volume of `size` bytes: its backup boot sector
/// in the sector after it (NT 4 and later; [LAYOUT] "Location of bootsector
/// on partition"), then only padding.
fn trailer(data: &[u8], size: usize, boot: &BootSector) -> Result<Trailer> {
    let sector = (boot.bytes_per_sector as usize).max(BOOT_SECTOR_SIZE);
    let trailing = &data[size..];
    let backup = match trailing.get(..sector) {
        Some(copy) if BootSector::read(copy).is_ok() => Some(BackupBootSector {
            offset: size,
            size: sector,
            state: if data.get(..sector) == Some(copy) {
                Backup::Matches
            } else {
                Backup::Differs
            },
        }),
        // An input cut inside the backup boot sector ends with the start
        // of a copy of the boot sector.
        None if !trailing.is_empty() && data.starts_with(trailing) => Some(BackupBootSector {
            offset: size,
            size: trailing.len(),
            state: Backup::CutShort,
        }),
        _ => None,
    };
    let consumed = backup.as_ref().map_or(size, |backup| size + backup.size);
    if !is_padding(&data[consumed..]) {
        return Err(error(format!(
            "Invalid trailing data: {} B after the volume at 0x{size:X} are neither the backup \
             boot sector nor padding",
            trailing.len()
        )));
    }
    Ok(Trailer { consumed, backup })
}

/// The root directory (record 5) must be a directory record in use.
fn check_root(root: Option<&Record>) -> Result<()> {
    match root {
        Some(record) if record.is_in_use() && record.is_directory() => Ok(()),
        _ => Err(error(
            "Missing root directory: MFT record 5 is not a directory in use",
        )),
    }
}

/// Read the label, version and flags from `$Volume`; a damaged or absent
/// record is noted.
fn volume_info(vol: &Volume<'_>, mft: &Mft, c: &mut Container<'_>) -> VolumeInfo {
    let mut info = VolumeInfo::default();
    let record = match mft.record(vol, VOLUME_RECORD) {
        Ok(Some(record)) => record,
        Ok(None) => {
            c.notes
                .push("$Volume (MFT record 3) is empty; no label or version".into());
            return info;
        }
        Err(Fault::Invalid(e)) => {
            c.notes
                .push(format!("$Volume (MFT record 3) not read: {}", message(e)));
            return info;
        }
        Err(Fault::Absent) => {
            c.notes.push(format!(
                "$Volume (MFT record 3) lies past the {} present and was not read",
                vol.present_text()
            ));
            return info;
        }
    };
    for attribute in &record.attributes {
        let Some(value) = record.resident_value(attribute) else {
            continue;
        };
        match attribute.kind {
            AT_VOLUME_NAME => info.name = Some(utf16_text(value)),
            // Reserved (8), major and minor version, flags (2).
            AT_VOLUME_INFORMATION if value.len() >= 12 => {
                info.version = Some(Version {
                    major: value[8],
                    minor: value[9],
                });
                info.flags = u16::from_le_bytes([value[10], value[11]]);
            }
            _ => {}
        }
    }
    info
}

/// Summary notes and metadata from the boot sector, the MFT and `$Volume`.
fn describe(
    vol: &Volume<'_>,
    mft: &Mft,
    info: &VolumeInfo,
    backup: Option<&BackupBootSector>,
    c: &mut Container<'_>,
) {
    let boot = &vol.boot;
    let version = info.version.map_or_else(String::new, |version| {
        format!(" {}.{}", version.major, version.minor)
    });
    c.notes.push(format!(
        "NTFS{version} volume: {} clusters of {}, {} sectors; {} MFT records, {} index records; \
         $MFT at cluster 0x{:X} with {} records",
        boot.cluster_count,
        size_text(boot.cluster_size as usize),
        size_text(boot.bytes_per_sector as usize),
        size_text(boot.record_size),
        size_text(boot.index_record_size),
        boot.mft_lcn,
        mft.record_count()
    ));
    if vol.is_truncated() {
        c.notes.push(format!(
            "Volume truncated: {} of {} present; files are listed only when all of their data is \
             present",
            vol.present_text(),
            volume_size_text(boot.volume_size())
        ));
    }
    if info.flags & VOLUME_IS_DIRTY != 0 {
        c.notes.push(
            "The volume is marked dirty (VOLUME_IS_DIRTY): it was not unmounted cleanly, and \
             $LogFile was not replayed, so metadata may be stale"
                .into(),
        );
    }
    if info.flags & (VOLUME_CHKDSK_UNDERWAY | VOLUME_MODIFIED_BY_CHKDSK) != 0 {
        c.notes
            .push("The volume flags record a chkdsk run (underway or modified)".into());
    }
    if let Some(backup) = backup {
        let comparison = match backup.state {
            Backup::Matches => "matches the boot sector".to_string(),
            Backup::Differs => "differs from the boot sector".to_string(),
            Backup::CutShort => format!(
                "is cut short: {} B present, equal to the boot sector's",
                backup.size
            ),
        };
        c.notes.push(format!(
            "Backup boot sector at 0x{:X} {comparison}",
            backup.offset
        ));
    }
    c.notes.push(
        "No processor field: the boot sector and the MFT name no CPU; members are classified \
         from their own bytes"
            .into(),
    );

    if let Some(name) = &info.name {
        c.push_metadata("ntfs_volume_name", "Volume name", name.clone());
    }
    if let Some(version) = info.version {
        c.push_metadata(
            "ntfs_version",
            "NTFS version",
            format!("{}.{}", version.major, version.minor),
        );
    }
    c.push_metadata(
        "ntfs_serial_number",
        "Volume serial number",
        format!("0x{:016X}", boot.serial_number),
    );
    c.push_metadata(
        "ntfs_bytes_per_sector",
        "Bytes per sector",
        u64::from(boot.bytes_per_sector),
    );
    c.push_metadata(
        "ntfs_cluster_size",
        "Cluster size (B)",
        u64::from(boot.cluster_size),
    );
    c.push_metadata("ntfs_total_sectors", "Sectors", boot.total_sectors);
    c.push_metadata(
        "ntfs_mft_record_size",
        "MFT record size (B)",
        boot.record_size as u64,
    );
    c.push_metadata(
        "ntfs_index_record_size",
        "Index record size (B)",
        boot.index_record_size as u64,
    );
    c.push_metadata("ntfs_mft_cluster", "$MFT cluster", boot.mft_lcn);
    c.push_metadata(
        "ntfs_mft_mirror_cluster",
        "$MFTMirr cluster",
        boot.mft_mirror_lcn,
    );
    c.push_metadata("ntfs_mft_record_count", "MFT records", mft.record_count());
}

/// Compare the first records with their `$MFTMirr` copy, which the boot
/// sector locates ([DOCS] `files/mftmirr.html`): a difference is noted, a
/// copy past the end of the input is not compared.
fn mirror_note(vol: &Volume<'_>, mft: &Mft, c: &mut Container<'_>) {
    let boot = &vol.boot;
    let count = MIRRORED_RECORDS
        .max(boot.cluster_size as usize / boot.record_size)
        .min(usize::try_from(mft.record_count()).unwrap_or(usize::MAX));
    let size = (count * boot.record_size) as u64;
    let clusters = div_ceil(size, vol.cluster_size());
    let copy = match vol.clusters(boot.mft_mirror_lcn, clusters) {
        Ok(copy) => copy,
        Err(Fault::Absent) => {
            c.notes.push(format!(
                "$MFTMirr lies past the {} present and was not compared",
                vol.present_text()
            ));
            return;
        }
        Err(Fault::Invalid(e)) => {
            c.notes
                .push(format!("$MFTMirr not compared: {}", message(e)));
            return;
        }
    };
    let differing: Vec<String> = (0..count)
        .filter(|&number| {
            let start = number * boot.record_size;
            let mirrored = copy[start..start + boot.record_size].to_vec();
            let original = mft.fixed_up_record(vol, number as u64);
            let mirror = Record::fixed_up(number as u64, mirrored);
            !matches!((original, mirror), (Ok(a), Ok(b)) if a == b)
        })
        .map(|number| number.to_string())
        .collect();
    if differing.is_empty() {
        c.notes.push(format!(
            "$MFTMirr at cluster 0x{:X} matches the first {count} MFT records",
            boot.mft_mirror_lcn
        ));
    } else {
        c.notes.push(format!(
            "$MFTMirr at cluster 0x{:X} differs from MFT records {}; $MFT was read",
            boot.mft_mirror_lcn,
            differing.join(", ")
        ));
    }
}

/// `value / divisor`, rounded up, for cluster and unit counts.
fn div_ceil(value: u64, divisor: u64) -> u64 {
    value / divisor + u64::from(value % divisor != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_names_decode_and_replace_unpaired_surrogates() {
        assert_eq!(utf16_text(&[b'Z', 0, b'r', 0]), "Zr");
        assert_eq!(utf16_text(&[0x00, 0xd8, b'a', 0]), "\u{FFFD}a");
    }

    #[test]
    fn layouts_name_their_format() {
        assert_eq!(Layout::Ntfs.format(), FileFormat::Ntfs);
        assert_eq!(Layout::Ntfs.label(), "NTFS");
        assert!(!Layout::Ntfs.is_weak());
    }

    #[test]
    fn counts_round_up() {
        assert_eq!(div_ceil(0, 4096), 0);
        assert_eq!(div_ceil(1, 4096), 1);
        assert_eq!(div_ceil(8192, 4096), 2);
        assert_eq!(div_ceil(8193, 4096), 3);
    }
}
