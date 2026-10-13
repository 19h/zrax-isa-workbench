//! exFAT volumes ([EXFAT]): the main and backup boot regions and their
//! checksums (sections 3.1-3.4), the FAT (4.1), the cluster heap (5.1),
//! and the directory tree of entry sets (6, 7): allocation bitmaps, the
//! up-case table and the volume label in the root directory, and File
//! entries with their Stream Extension and File Name entries everywhere.

use super::table::{EntryKind, Heap, Table};
use super::walk::{self, DirectoryData, FileRef, Span, Walker, MAX_DEPTH};
use super::*;

/// `FileSystemName` at offset 3, with three trailing spaces.
const FILE_SYSTEM_NAME: &[u8; 8] = b"EXFAT   ";
const FILE_SYSTEM_NAME_OFFSET: usize = 3;

/// `JumpBoot`: a short jump to `BootCode`.
const JUMP_BOOT: [u8; 3] = [0xeb, 0x76, 0x90];

/// `MustBeZero` covers the bytes the packed BPB of FAT volumes uses.
const MUST_BE_ZERO_OFFSET: usize = 11;
const MUST_BE_ZERO_SIZE: usize = 53;

/// `BootCode` follows the boot sector fields.
const BOOT_CODE_OFFSET: usize = 120;

/// `VolumeFlags` and `PercentInUse`, which the boot checksum skips.
const VOLUME_FLAGS_OFFSET: usize = 106;
const PERCENT_IN_USE_OFFSET: usize = 112;

/// A boot region is 12 sectors: the boot sector, eight extended boot
/// sectors, the OEM parameters, a reserved sector and the checksum sector,
/// which repeats the checksum of the first 11. The backup region follows.
const BOOT_REGION_SECTORS: usize = 12;
const CHECKSUMMED_SECTORS: usize = 11;
const EXTENDED_BOOT_SECTORS: std::ops::RangeInclusive<usize> = 1..=8;

/// `ExtendedBootSignature` in the last four bytes of an extended boot
/// sector.
const EXTENDED_BOOT_SIGNATURE: u32 = 0xaa55_0000;

/// `FatOffset` is at least 24: both boot regions precede the FAT.
const MIN_FAT_OFFSET: u32 = 24;

/// `BytesPerSectorShift` range (512 B to 4 KiB sectors) and the largest
/// cluster, 32 MiB (`SectorsPerClusterShift` at most 25 minus it).
const MIN_SECTOR_SHIFT: u8 = 9;
const MAX_SECTOR_SHIFT: u8 = 12;
const MAX_CLUSTER_SIZE_SHIFT: u8 = 25;

/// Most clusters a FAT describes: 2^32 - 11.
const MAX_CLUSTER_COUNT: u32 = u32::MAX - 10;

/// The smallest volume, 1 MiB.
const MIN_VOLUME_SIZE: u64 = 1 << 20;

/// `FileSystemRevision`: major revision 1, minor revision 0-99.
const REVISION_MAJOR: u16 = 1;
const MAX_REVISION_MINOR: u16 = 99;

/// `VolumeFlags` bits.
const ACTIVE_FAT: u16 = 0x0001;
const VOLUME_DIRTY: u16 = 0x0002;
const MEDIA_FAILURE: u16 = 0x0004;

/// `PercentInUse` when the percentage is not available.
const PERCENT_UNKNOWN: u8 = 0xff;

/// `FatEntry[0]`: the media type (F8) and three bytes of FF; `FatEntry[1]`:
/// all ones.
const FAT_ENTRY_0: u32 = 0xffff_fff8;
const FAT_ENTRY_1: u32 = u32::MAX;

/// `EntryType` bits: `TypeImportance` (benign), `TypeCategory`
/// (secondary) and `InUse`; 0x00 ends the directory, 0x80 is invalid.
const TYPE_BENIGN: u8 = 0x20;
const TYPE_SECONDARY: u8 = 0x40;
const TYPE_IN_USE: u8 = 0x80;
const END_OF_DIRECTORY: u8 = 0x00;

/// Entry types of revision 1.00.
const ENTRY_ALLOCATION_BITMAP: u8 = 0x81;
const ENTRY_UPCASE_TABLE: u8 = 0x82;
const ENTRY_VOLUME_LABEL: u8 = 0x83;
const ENTRY_FILE: u8 = 0x85;
const ENTRY_STREAM_EXTENSION: u8 = 0xc0;
const ENTRY_FILE_NAME: u8 = 0xc1;

/// A File entry with `InUse` 0: a deleted file.
const ENTRY_DELETED_FILE: u8 = ENTRY_FILE & !TYPE_IN_USE;

/// `GeneralSecondaryFlags` bits.
const ALLOCATION_POSSIBLE: u8 = 0x01;
const NO_FAT_CHAIN: u8 = 0x02;

/// `FileAttributes` bit of a directory.
const ATTRIBUTE_DIRECTORY: u16 = 0x0010;

/// `BitmapFlags` bit 0: the second allocation bitmap.
const BITMAP_SECOND: u8 = 0x01;

/// A File Name entry holds 15 UTF-16 characters from offset 2.
const NAME_CHARS_PER_ENTRY: usize = 15;
const NAME_OFFSET: usize = 2;

/// A volume label has at most 11 characters.
const MAX_LABEL_CHARS: usize = 11;

/// A directory holds at most 256 MiB ([EXFAT] 7.6.7).
const MAX_DIRECTORY_SIZE: u64 = 256 << 20;

/// The up-case table maps at most 65,536 characters of 2 bytes.
const MAX_UPCASE_TABLE_SIZE: u64 = 2 << 16;

/// Characters that are illegal in a file name besides control codes
/// ([EXFAT] 7.7.3, Table 35).
const ILLEGAL_NAME_CHARS: [char; 9] = ['"', '*', '/', ':', '<', '>', '?', '\\', '|'];

/// Transform of a file whose clusters are not contiguous.
const CHAIN_TRANSFORM: &str = "exFAT cluster chain";

/// The exFAT file system name at offset 3.
pub(super) fn detect(data: &[u8]) -> bool {
    data.get(FILE_SYSTEM_NAME_OFFSET..FILE_SYSTEM_NAME_OFFSET + FILE_SYSTEM_NAME.len())
        == Some(FILE_SYSTEM_NAME.as_slice())
}

/// The boot sector fields that the reader uses, after
/// [`BootSector::parse`]. Sector numbers count `1 << sector_shift` bytes
/// from the start of the volume.
#[derive(Debug, Clone, Copy)]
struct BootSector {
    /// `PartitionOffset`: media-relative sector of the volume.
    partition_offset: u64,
    /// `VolumeLength` in sectors.
    volume_length: u64,
    /// `FatOffset` and `FatLength` in sectors.
    fat_offset: u32,
    fat_length: u32,
    /// `ClusterHeapOffset` in sectors.
    cluster_heap_offset: u32,
    cluster_count: u32,
    /// `FirstClusterOfRootDirectory`.
    root_cluster: u32,
    serial: u32,
    /// `FileSystemRevision`: major in the high byte.
    revision: u16,
    volume_flags: u16,
    sector_shift: u8,
    cluster_shift: u8,
    fat_count: u8,
    percent_in_use: u8,
}

impl BootSector {
    /// Read and validate a boot sector: offsets 64 (`PartitionOffset`, 8),
    /// 72 (`VolumeLength`, 8), 80 (`FatOffset`), 84 (`FatLength`), 88
    /// (`ClusterHeapOffset`), 92 (`ClusterCount`), 96
    /// (`FirstClusterOfRootDirectory`), 100 (`VolumeSerialNumber`), 104
    /// (`FileSystemRevision`, 2), 106 (`VolumeFlags`, 2), 108
    /// (`BytesPerSectorShift`, 1), 109 (`SectorsPerClusterShift`), 110
    /// (`NumberOfFats`), 112 (`PercentInUse`), each checked against the
    /// range [EXFAT] 3.1 gives it.
    fn parse(sector: &[u8]) -> Result<Self> {
        if !detect(sector) {
            return Err(error("Missing exFAT file system name \"EXFAT   \" at 0x3"));
        }
        let jump: [u8; 3] = array(sector, 0)?;
        if jump != JUMP_BOOT {
            return Err(error(format!(
                "Invalid JumpBoot {:02X} {:02X} {:02X}: EB 76 90 expected",
                jump[0], jump[1], jump[2]
            )));
        }
        let must_be_zero = slice(sector, MUST_BE_ZERO_OFFSET, MUST_BE_ZERO_SIZE)?;
        if let Some(at) = must_be_zero.iter().position(|&b| b != 0) {
            return Err(error(format!(
                "Invalid MustBeZero field: byte 0x{:X} is not 0",
                MUST_BE_ZERO_OFFSET + at
            )));
        }
        if array(sector, BOOT_SIGNATURE_OFFSET)? != BOOT_SIGNATURE {
            return Err(error("Missing boot sector signature 55 AA at 0x1FE"));
        }
        let boot = Self {
            partition_offset: le_u64(sector, 64)?,
            volume_length: le_u64(sector, 72)?,
            fat_offset: le_u32(sector, 80)?,
            fat_length: le_u32(sector, 84)?,
            cluster_heap_offset: le_u32(sector, 88)?,
            cluster_count: le_u32(sector, 92)?,
            root_cluster: le_u32(sector, 96)?,
            serial: le_u32(sector, 100)?,
            revision: le_u16(sector, 104)?,
            volume_flags: le_u16(sector, VOLUME_FLAGS_OFFSET)?,
            sector_shift: byte(sector, 108)?,
            cluster_shift: byte(sector, 109)?,
            fat_count: byte(sector, 110)?,
            percent_in_use: byte(sector, PERCENT_IN_USE_OFFSET)?,
        };
        boot.check_revision_and_sizes()?;
        boot.check_regions()?;
        Ok(boot)
    }

    fn check_revision_and_sizes(&self) -> Result<()> {
        let (major, minor) = (self.revision >> 8, self.revision & 0xff);
        if major != REVISION_MAJOR || minor > MAX_REVISION_MINOR {
            return Err(error(format!(
                "Unsupported FileSystemRevision {major}.{minor:02}: major revision 1 expected"
            )));
        }
        if !(MIN_SECTOR_SHIFT..=MAX_SECTOR_SHIFT).contains(&self.sector_shift) {
            return Err(error(format!(
                "Invalid BytesPerSectorShift {}: 9 to 12 expected",
                self.sector_shift
            )));
        }
        if self.cluster_shift > MAX_CLUSTER_SIZE_SHIFT - self.sector_shift {
            return Err(error(format!(
                "Invalid SectorsPerClusterShift {}: clusters larger than 32 MiB",
                self.cluster_shift
            )));
        }
        if !matches!(self.fat_count, 1 | 2) {
            return Err(error(format!(
                "Invalid NumberOfFats {}: 1 or 2 expected",
                self.fat_count
            )));
        }
        if self.volume_length < MIN_VOLUME_SIZE >> self.sector_shift {
            return Err(error(format!(
                "Invalid VolumeLength {}: smaller than 1 MiB",
                self.volume_length
            )));
        }
        Ok(())
    }

    /// The FAT, the cluster heap and the root directory against each other
    /// and against the volume ([EXFAT] 3.1.6-3.1.10, 3.1.13, 3.1.18).
    fn check_regions(&self) -> Result<()> {
        if self.fat_offset < MIN_FAT_OFFSET {
            return Err(error(format!(
                "Invalid FatOffset {}: the boot regions need 24 sectors",
                self.fat_offset
            )));
        }
        let heap_sectors = self
            .volume_length
            .checked_sub(u64::from(self.cluster_heap_offset))
            .ok_or_else(|| {
                error(format!(
                    "Invalid ClusterHeapOffset {}: beyond the {} sectors of the volume",
                    self.cluster_heap_offset, self.volume_length
                ))
            })?;
        let fitting = heap_sectors >> self.cluster_shift;
        if self.cluster_count > MAX_CLUSTER_COUNT || u64::from(self.cluster_count) > fitting {
            return Err(error(format!(
                "Invalid ClusterCount {}: the cluster heap holds {fitting} clusters",
                self.cluster_count
            )));
        }
        let needed = div_round_up(
            (u64::from(self.cluster_count) + 2) * 4,
            1 << self.sector_shift,
        );
        if u64::from(self.fat_length) < needed {
            return Err(error(format!(
                "Invalid FatLength {}: {needed} sectors needed for {} clusters",
                self.fat_length, self.cluster_count
            )));
        }
        let fats_end =
            u64::from(self.fat_offset) + u64::from(self.fat_length) * u64::from(self.fat_count);
        if u64::from(self.cluster_heap_offset) < fats_end {
            return Err(error(format!(
                "Invalid ClusterHeapOffset {}: the FATs end at sector {fats_end}",
                self.cluster_heap_offset
            )));
        }
        if !(2..=u64::from(self.cluster_count) + 1).contains(&u64::from(self.root_cluster)) {
            return Err(error(format!(
                "Invalid FirstClusterOfRootDirectory {}: not a cluster of the heap",
                self.root_cluster
            )));
        }
        if self.percent_in_use > 100 && self.percent_in_use != PERCENT_UNKNOWN {
            return Err(error(format!(
                "Invalid PercentInUse {}",
                self.percent_in_use
            )));
        }
        if self.volume_flags & ACTIVE_FAT != 0 && self.fat_count != 2 {
            return Err(error(
                "Invalid VolumeFlags: ActiveFat names the second FAT of a volume with one",
            ));
        }
        Ok(())
    }

    fn sector_size(&self) -> usize {
        1 << self.sector_shift
    }

    fn cluster_size(&self) -> u64 {
        1 << (self.sector_shift + self.cluster_shift)
    }

    fn sector_offset(&self, sector: u64) -> u64 {
        sector << self.sector_shift
    }

    fn volume_size(&self) -> u64 {
        // At most 2^64 - 1 sectors; a size past u64 saturates and cannot
        // fit in the input.
        self.volume_length.saturating_mul(1 << self.sector_shift)
    }

    /// The active FAT: the second when `ActiveFat` is set.
    fn active_fat(&self) -> u32 {
        u32::from(self.volume_flags & ACTIVE_FAT)
    }
}

/// `BootChecksum` ([EXFAT] Figure 1): a 32-bit rotate right and add over
/// the first 11 sectors, skipping `VolumeFlags` and `PercentInUse`.
fn boot_checksum(sectors: &[u8]) -> u32 {
    sectors
        .iter()
        .enumerate()
        .filter(|&(i, _)| !is_checksum_skipped(i))
        .fold(0u32, |sum, (_, &b)| {
            sum.rotate_right(1).wrapping_add(u32::from(b))
        })
}

/// `EntrySetChecksum` ([EXFAT] Figure 2): a 16-bit rotate right and add
/// over the entries of a set, skipping the `SetChecksum` field itself.
fn set_checksum(entries: &[&[u8]]) -> u16 {
    entries
        .iter()
        .flat_map(|entry| entry.iter())
        .enumerate()
        .filter(|&(i, _)| i != 2 && i != 3)
        .fold(0u16, |sum, (_, &b)| {
            sum.rotate_right(1).wrapping_add(u16::from(b))
        })
}

/// `TableChecksum` ([EXFAT] Figure 3): a 32-bit rotate right and add over
/// the up-case table.
fn table_checksum(table: &[u8]) -> u32 {
    table.iter().fold(0u32, |sum, &b| {
        sum.rotate_right(1).wrapping_add(u32::from(b))
    })
}

/// The main boot region, which must be in the input, with its checksum
/// verified.
fn check_main_region(data: &[u8], boot: &BootSector) -> Result<()> {
    let size = boot.sector_size();
    let region = slice(data, 0, BOOT_REGION_SECTORS * size).map_err(|_| {
        error(format!(
            "Truncated main boot region: {} B needed, {} B present",
            BOOT_REGION_SECTORS * size,
            data.len()
        ))
    })?;
    let computed = boot_checksum(&region[..CHECKSUMMED_SECTORS * size]);
    let checksum_sector = &region[CHECKSUMMED_SECTORS * size..];
    if let Some(stored) = checksum_sector
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("4-byte chunk")))
        .find(|&word| word != computed)
    {
        return Err(error(format!(
            "Invalid main boot checksum 0x{stored:08X} (computed 0x{computed:08X})"
        )));
    }
    Ok(())
}

/// The backup boot region: its checksum, and whether its boot sector
/// matches the main one apart from the fields the checksum skips.
fn backup_region_note(data: &[u8], boot: &BootSector) -> String {
    let size = boot.sector_size();
    let Ok(region) = slice(data, BOOT_REGION_SECTORS * size, BOOT_REGION_SECTORS * size) else {
        return "The backup boot region is not in the input".to_string();
    };
    let computed = boot_checksum(&region[..CHECKSUMMED_SECTORS * size]);
    let verified = region[CHECKSUMMED_SECTORS * size..]
        .chunks_exact(4)
        .all(|word| u32::from_le_bytes(word.try_into().expect("4-byte chunk")) == computed);
    if !verified {
        return "The backup boot region checksum does not match; the backup is not used"
            .to_string();
    }
    // The backup's VolumeFlags and PercentInUse are stale ([EXFAT] 3.1).
    let main = &data[..CHECKSUMMED_SECTORS * size];
    let matches = main
        .iter()
        .zip(&region[..CHECKSUMMED_SECTORS * size])
        .enumerate()
        .all(|(i, (a, b))| a == b || is_checksum_skipped(i));
    if matches {
        "Backup boot region checksum verified; it matches the main boot region".to_string()
    } else {
        "Backup boot region checksum verified; it differs from the main boot region".to_string()
    }
}

/// `VolumeFlags` and `PercentInUse`, which the boot checksum skips.
fn is_checksum_skipped(offset: usize) -> bool {
    offset == VOLUME_FLAGS_OFFSET
        || offset == VOLUME_FLAGS_OFFSET + 1
        || offset == PERCENT_IN_USE_OFFSET
}

/// The extended boot sectors without their signature, as a note.
fn extended_boot_note(data: &[u8], boot: &BootSector) -> Option<String> {
    let size = boot.sector_size();
    let unsigned: Vec<String> = EXTENDED_BOOT_SECTORS
        .filter(|&sector| {
            let signature = (sector + 1) * size - 4;
            le_u32(data, signature).ok() != Some(EXTENDED_BOOT_SIGNATURE)
        })
        .map(|sector| sector.to_string())
        .collect();
    (!unsigned.is_empty()).then(|| {
        format!(
            "Extended boot sectors {} lack the signature 0xAA550000",
            unsigned.join(", ")
        )
    })
}

/// The boot code of the extended boot sectors that hold any: children
/// classified as code. [EXFAT] 3.2 does not fix their processor (firmware
/// or alternate BIOS implementations may run them), so they carry no
/// target.
fn extended_boot_code<'a>(data: &'a [u8], boot: &BootSector, c: &mut Container<'a>) {
    let size = boot.sector_size();
    for sector in EXTENDED_BOOT_SECTORS {
        let at = sector * size;
        let code = &data[at..at + size - 4];
        if code.iter().any(|&b| b != code[0]) {
            c.notes.push(format!(
                "Extended boot sector {sector} at 0x{at:X} holds boot code; its processor is \
                 not specified"
            ));
            c.children
                .push(Child::stored(format!("Extended boot sector {sector}"), at, code).as_code());
        }
    }
}

/// Parse an exFAT volume.
///
/// # Errors
///
/// [`ClassifierError::FatParseError`] for a boot sector outside the
/// ranges of [EXFAT] 3.1, a main boot checksum mismatch, a volume much
/// larger than the input, a FAT not in the input, or a root directory that
/// cannot be read or lacks its allocation bitmaps and up-case table.
pub(super) fn parse(data: &[u8]) -> Result<Container<'_>> {
    let boot = BootSector::parse(data)?;
    check_main_region(data, &boot)?;
    let coverage = check_volume_size(boot.volume_size(), data.len())?;
    let fat_start = boot.sector_offset(
        u64::from(boot.fat_offset) + u64::from(boot.active_fat()) * u64::from(boot.fat_length),
    );
    let fat_size = EntryKind::ExFat.table_size(u64::from(boot.cluster_count) + 2);
    let fat = usize::try_from(fat_start)
        .ok()
        .zip(usize::try_from(fat_size).ok())
        .and_then(|(start, size)| slice(data, start, size).ok())
        .ok_or_else(|| {
            error(format!(
                "Truncated FAT at 0x{fat_start:X} + {fat_size} B: {} B present",
                data.len()
            ))
        })?;
    let table = Table::new(fat, EntryKind::ExFat, boot.cluster_count);
    let heap = Heap {
        data,
        offset: boot.sector_offset(u64::from(boot.cluster_heap_offset)),
        cluster_size: boot.cluster_size(),
    };

    let mut c = Container::new(FileFormat::ExFat, Layout::ExFat.label(), "exfat");
    c.consumed =
        usize::try_from(boot.volume_size()).map_or(data.len(), |size| size.min(data.len()));
    describe(&boot, coverage, data, &table, &mut c);
    let boot_code = boot_code(data, BOOT_CODE_OFFSET)?;
    c.notes.push(boot_code.note);

    let mut walker = Walker::new(&table, &heap, CHAIN_TRANSFORM);
    let root = walker
        .directory(
            boot.root_cluster,
            Span::Chain {
                max_size: MAX_DIRECTORY_SIZE,
            },
        )
        .map_err(|defect| error(format!("Invalid root directory: {defect}")))?;
    let mut walk = ExFatWalk {
        walker: &mut walker,
        root: RootEntries::default(),
    };
    let mut pending = walk
        .directory(&root, Location { node: 0, depth: 0 }, &mut c)
        .map_err(|defect| error(format!("Invalid root directory: {defect}")))?;
    pending.reverse();
    while let Some(directory) = pending.pop() {
        let path = walk.walker.path(directory.node, "");
        let span = Span::Sized {
            size: directory.size,
            contiguous: directory.contiguous,
        };
        let subdirectories = walk
            .walker
            .directory(directory.first_cluster, span)
            .and_then(|contents| walk.directory(&contents, directory.at(), &mut c));
        match subdirectories {
            // Reversed, so that subdirectories are walked in entry order.
            Ok(subdirectories) => pending.extend(subdirectories.into_iter().rev()),
            Err(defect) => walk.walker.problem(format!("Skipped {path}: {defect}")),
        }
    }
    let root = std::mem::take(&mut walk.root);
    root.check(&boot)?;
    root.report(&mut c);
    walker.census.report(&mut c);
    // The volume's files come first; see the FAT parser.
    c.children.extend(boot_code.child);
    extended_boot_code(data, &boot, &mut c);
    Ok(c)
}

/// Summary notes and metadata from the boot region and the FAT.
fn describe(
    boot: &BootSector,
    coverage: Coverage,
    data: &[u8],
    table: &Table<'_>,
    c: &mut Container<'_>,
) {
    let fats = counted(usize::from(boot.fat_count), "FAT", "FATs");
    c.notes.push(format!(
        "exFAT volume, revision {}.{:02}: {} of {}; {} B sectors; {fats} of {}; root \
         directory at cluster {}",
        boot.revision >> 8,
        boot.revision & 0xff,
        counted(boot.cluster_count as usize, "cluster", "clusters"),
        size_text(boot.cluster_size()),
        boot.sector_size(),
        counted(boot.fat_length as usize, "sector", "sectors"),
        boot.root_cluster
    ));
    if let Some(note) = coverage_note(coverage, boot.volume_size(), data) {
        c.notes.push(note);
    }
    c.notes
        .push("Main boot region checksum verified (sectors 0-10)".to_string());
    c.notes.push(backup_region_note(data, boot));
    if let Some(note) = extended_boot_note(data, boot) {
        c.notes.push(note);
    }
    let mut flags = Vec::new();
    if boot.active_fat() == 1 {
        flags.push("the second FAT and allocation bitmap are active");
    }
    if boot.volume_flags & VOLUME_DIRTY != 0 {
        flags.push("the volume is marked dirty");
    }
    if boot.volume_flags & MEDIA_FAILURE != 0 {
        flags.push("media failures are recorded");
    }
    if !flags.is_empty() {
        c.notes.push(format!("VolumeFlags: {}", flags.join("; ")));
    }
    let reserved = (table.entry(0), table.entry(1));
    if reserved != (Some(FAT_ENTRY_0), Some(FAT_ENTRY_1)) {
        c.notes.push(format!(
            "FatEntry[0] and FatEntry[1] are 0x{:08X} and 0x{:08X}, not 0xFFFFFFF8 and \
             0xFFFFFFFF",
            reserved.0.unwrap_or(0),
            reserved.1.unwrap_or(0)
        ));
    }
    c.notes.push(
        "Entry set checksums are verified for every set read; name hashes and the allocation \
         bitmap are not verified"
            .to_string(),
    );
    c.notes.push(
        "exFAT names no processor for its files; members are classified from their own bytes"
            .to_string(),
    );
    c.push_metadata(
        "exfat_bytes_per_sector",
        "Bytes per sector",
        boot.sector_size() as u64,
    );
    c.push_metadata(
        "exfat_cluster_size",
        "Cluster size (B)",
        boot.cluster_size(),
    );
    c.push_metadata(
        "exfat_cluster_count",
        "Clusters",
        u64::from(boot.cluster_count),
    );
    c.push_metadata(
        "exfat_volume_length",
        "Volume length (sectors)",
        boot.volume_length,
    );
    c.push_metadata(
        "exfat_fat_offset",
        "FAT offset (sectors)",
        u64::from(boot.fat_offset),
    );
    c.push_metadata(
        "exfat_fat_length",
        "FAT length (sectors)",
        u64::from(boot.fat_length),
    );
    c.push_metadata("exfat_fat_count", "FATs", u64::from(boot.fat_count));
    c.push_metadata(
        "exfat_cluster_heap_offset",
        "Cluster heap offset (sectors)",
        u64::from(boot.cluster_heap_offset),
    );
    c.push_metadata(
        "exfat_root_cluster",
        "Root directory cluster",
        u64::from(boot.root_cluster),
    );
    c.push_metadata(
        "exfat_volume_serial",
        "Volume serial number",
        serial_text(boot.serial),
    );
    c.push_metadata(
        "exfat_partition_offset",
        "Partition offset (sectors)",
        boot.partition_offset,
    );
    if boot.percent_in_use != PERCENT_UNKNOWN {
        c.push_metadata(
            "exfat_percent_in_use",
            "Clusters in use (%)",
            u64::from(boot.percent_in_use),
        );
    }
}

/// A subdirectory waiting to be read.
struct Pending {
    first_cluster: u32,
    /// `DataLength` of its stream.
    size: u64,
    contiguous: bool,
    node: usize,
    depth: usize,
}

impl Pending {
    fn at(&self) -> Location {
        Location {
            node: self.node,
            depth: self.depth,
        }
    }
}

/// The directory an entry is in: its path node and depth below the root.
#[derive(Debug, Clone, Copy)]
struct Location {
    node: usize,
    depth: usize,
}

/// The critical entries of the root directory besides files.
#[derive(Debug, Default)]
struct RootEntries {
    /// Allocation bitmap entries describing the first and the second
    /// bitmap (`BitmapIdentifier` 0 and 1).
    bitmaps: [usize; 2],
    /// Up-case table entries.
    upcase_tables: usize,
    /// The first up-case table's checksum result, as a note.
    upcase_note: Option<String>,
    /// The volume label, if any.
    label: Option<String>,
}

impl RootEntries {
    /// [EXFAT] 7.1 and 7.2: one allocation bitmap per FAT (the first, and
    /// the second with two FATs) and one up-case table.
    fn check(&self, boot: &BootSector) -> Result<()> {
        let expected = if boot.fat_count == 2 { [1, 1] } else { [1, 0] };
        if self.bitmaps != expected {
            return Err(error(format!(
                "Invalid root directory: {} for {}",
                counted(
                    self.bitmaps[0] + self.bitmaps[1],
                    "allocation bitmap entry",
                    "allocation bitmap entries"
                ),
                counted(usize::from(boot.fat_count), "FAT", "FATs")
            )));
        }
        if self.upcase_tables != 1 {
            return Err(error(format!(
                "Invalid root directory: {}, 1 expected",
                counted(
                    self.upcase_tables,
                    "up-case table entry",
                    "up-case table entries"
                )
            )));
        }
        Ok(())
    }

    fn report(self, c: &mut Container<'_>) {
        c.notes.extend(self.upcase_note);
        if let Some(label) = self.label {
            c.push_metadata("exfat_volume_label", "Volume label", label);
        }
    }
}

/// Look for a critical primary entry that does not belong in a directory
/// ([EXFAT] 8.2): in the root, any but the allocation bitmap, up-case
/// table, volume label and File entries; elsewhere any but File entries.
/// File and benign primary entries are skipped with their secondaries, as
/// the walk skips them.
fn check_primary_entries(contents: &DirectoryData<'_>, is_root: bool) -> Walk<()> {
    let mut entries = walk::entries(&contents.extents);
    while let Some((offset, entry)) = entries.next() {
        let entry_type = entry[0];
        if entry_type == END_OF_DIRECTORY {
            break;
        }
        // Unused entries, the invalid 0x80, and secondaries outside a set.
        if entry_type & TYPE_IN_USE == 0
            || entry_type == TYPE_IN_USE
            || entry_type & TYPE_SECONDARY != 0
        {
            continue;
        }
        let root_entry = matches!(
            entry_type,
            ENTRY_ALLOCATION_BITMAP | ENTRY_UPCASE_TABLE | ENTRY_VOLUME_LABEL
        );
        if root_entry && is_root {
            continue;
        }
        if entry_type == ENTRY_FILE || entry_type & TYPE_BENIGN != 0 {
            entries.by_ref().take(usize::from(entry[1])).for_each(drop);
            continue;
        }
        return Err(format!(
            "critical primary entry 0x{entry_type:02X} at 0x{offset:X} is not recognized in \
             this directory"
        ));
    }
    Ok(())
}

/// The walk of an exFAT directory tree.
struct ExFatWalk<'w, 'v, 'a> {
    walker: &'w mut Walker<'v, 'a>,
    root: RootEntries,
}

impl<'a> ExFatWalk<'_, '_, 'a> {
    /// Read the entry sets of one directory, list its members and return
    /// its subdirectories in entry order. A critical primary entry that
    /// does not belong in the directory invalidates all of it ([EXFAT]
    /// 8.2), so it is looked for before any member is listed: an error.
    fn directory(
        &mut self,
        contents: &DirectoryData<'a>,
        at: Location,
        c: &mut Container<'a>,
    ) -> Walk<Vec<Pending>> {
        let is_root = at.node == 0;
        check_primary_entries(contents, is_root)?;
        self.walker.census.directories += 1;
        let mut subdirectories = Vec::new();
        let mut entries = walk::entries(&contents.extents);
        while let Some((offset, entry)) = entries.next() {
            let entry_type = entry[0];
            if entry_type == END_OF_DIRECTORY {
                break;
            }
            if entry_type & TYPE_IN_USE == 0 {
                if entry_type == ENTRY_DELETED_FILE {
                    self.walker.census.deleted += 1;
                }
                continue;
            }
            // 0x80 is invalid; a secondary entry belongs to a set.
            if entry_type == TYPE_IN_USE || entry_type & TYPE_SECONDARY != 0 {
                self.walker.census.invalid_entries += 1;
                continue;
            }
            match entry_type {
                // Only in the root, as `check_primary_entries` ensured.
                ENTRY_ALLOCATION_BITMAP | ENTRY_UPCASE_TABLE | ENTRY_VOLUME_LABEL => {
                    self.root_entry(entry, offset);
                }
                ENTRY_FILE => {
                    let count = usize::from(entry[1]);
                    let mut set = Vec::with_capacity(count + 1);
                    set.push(entry);
                    set.extend(entries.by_ref().take(count).map(|(_, entry)| entry));
                    if set.len() != count + 1 {
                        self.walker.census.invalid_entries += 1;
                        break;
                    }
                    self.file_set(&set, at, &mut subdirectories, c);
                }
                // Benign primary entries (volume GUID, TexFAT padding, later
                // revisions) and their secondaries are not interpreted.
                _ => entries.by_ref().take(usize::from(entry[1])).for_each(drop),
            }
        }
        Ok(subdirectories)
    }

    /// An allocation bitmap, up-case table or volume label entry of the
    /// root directory.
    fn root_entry(&mut self, entry: &[u8], offset: usize) {
        match entry[0] {
            ENTRY_ALLOCATION_BITMAP => {
                self.root.bitmaps[usize::from(entry[1] & BITMAP_SECOND)] += 1;
            }
            ENTRY_UPCASE_TABLE => {
                self.root.upcase_tables += 1;
                // Only one table is valid; a volume with more is an error.
                if self.root.upcase_note.is_none() {
                    self.root.upcase_note = Some(self.upcase_table_note(entry));
                }
            }
            _ => {
                let count = usize::from(entry[1]);
                if count > MAX_LABEL_CHARS {
                    self.walker.problem(format!(
                        "Volume label entry at 0x{offset:X}: CharacterCount {count} exceeds 11"
                    ));
                    return;
                }
                let units: Vec<u16> = entry[2..2 + 2 * count]
                    .chunks_exact(2)
                    .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
                    .collect();
                if self.root.label.is_none() {
                    self.root.label = Some(String::from_utf16_lossy(&units));
                }
            }
        }
    }

    /// Verify the up-case table's `TableChecksum`: `FirstCluster` (20, 4)
    /// and `DataLength` (24, 8) locate the table along its FAT chain.
    fn upcase_table_note(&self, entry: &[u8]) -> String {
        let stored = u32::from_le_bytes(entry[4..8].try_into().expect("4-byte slice"));
        let size = u64::from_le_bytes(entry[24..32].try_into().expect("8-byte slice"));
        if size == 0 || size > MAX_UPCASE_TABLE_SIZE {
            return format!(
                "Up-case table checksum not verified: DataLength {size} B is outside 1 B to \
                 128 KiB"
            );
        }
        let table = FileRef {
            first_cluster: u32::from_le_bytes(entry[20..24].try_into().expect("4-byte slice")),
            size,
            valid_size: size,
            contiguous: false,
        };
        match self.walker.contents(&table) {
            Ok(bytes) if table_checksum(&bytes) == stored => {
                format!("Up-case table checksum 0x{stored:08X} verified")
            }
            Ok(bytes) => format!(
                "Up-case table checksum 0x{stored:08X} does not match (computed 0x{:08X})",
                table_checksum(&bytes)
            ),
            Err(defect) => format!("Up-case table checksum not verified: {defect}"),
        }
    }

    /// One File entry set: `set[0]` is the File entry, then its
    /// secondaries. The set must pass its checksum and hold a Stream
    /// Extension followed by its File Name entries ([EXFAT] 7.4, 7.6, 7.7).
    fn file_set(
        &mut self,
        set: &[&[u8]],
        at: Location,
        subdirectories: &mut Vec<Pending>,
        c: &mut Container<'a>,
    ) {
        let stored = u16::from_le_bytes([set[0][2], set[0][3]]);
        if set_checksum(set) != stored {
            self.walker.census.checksum_failures += 1;
            return;
        }
        let Some(file) = parse_file_set(set) else {
            self.walker.census.invalid_entries += 1;
            return;
        };
        // Benign secondaries (vendor extensions) are ignored; a critical
        // one that is not recognized makes the set unrecognized.
        if set[1 + file.known_secondaries..]
            .iter()
            .any(|entry| entry[0] & TYPE_BENIGN == 0)
        {
            self.walker.census.unrecognized_sets += 1;
            return;
        }
        if file.is_directory {
            if at.depth >= MAX_DEPTH {
                self.walker.census.too_deep += 1;
                return;
            }
            let node = self.walker.add_node(at.node, &file.name);
            self.walker.census.directories += usize::from(file.data.size == 0);
            if file.data.size > MAX_DIRECTORY_SIZE {
                let path = self.walker.path(node, "");
                self.walker.problem(format!(
                    "Skipped {path}: DataLength {} B exceeds the 256 MiB directory limit",
                    file.data.size
                ));
            } else if file.data.size > 0 {
                subdirectories.push(Pending {
                    first_cluster: file.data.first_cluster,
                    size: file.data.size,
                    contiguous: file.data.contiguous,
                    node,
                    depth: at.depth + 1,
                });
            }
            return;
        }
        let path = self.walker.path(at.node, &file.name);
        self.walker.file(path, &file.data, c);
    }
}

/// A File entry set that validated.
struct FileSet {
    name: String,
    is_directory: bool,
    data: FileRef,
    /// The Stream Extension and File Name entries, the secondaries that
    /// were interpreted.
    known_secondaries: usize,
}

/// The name and stream of a File entry set: `FileAttributes` (File entry
/// offset 4, 2); Stream Extension `GeneralSecondaryFlags` (1),
/// `NameLength` (3), `ValidDataLength` (8, 8), `FirstCluster` (20, 4) and
/// `DataLength` (24, 8); then `ceil(NameLength / 15)` File Name entries of
/// 15 UTF-16 characters from offset 2. `None` when the set breaks a rule
/// of [EXFAT] 6.3-7.7.
fn parse_file_set(set: &[&[u8]]) -> Option<FileSet> {
    // Only in-use secondary entries may follow the primary entry.
    let in_use_secondary = TYPE_IN_USE | TYPE_SECONDARY;
    if set[1..]
        .iter()
        .any(|entry| entry[0] & in_use_secondary != in_use_secondary)
    {
        return None;
    }
    let stream = *set.get(1)?;
    if stream[0] != ENTRY_STREAM_EXTENSION || stream[1] & ALLOCATION_POSSIBLE == 0 {
        return None;
    }
    let name_length = usize::from(stream[3]);
    let name_entries =
        name_length / NAME_CHARS_PER_ENTRY + usize::from(name_length % NAME_CHARS_PER_ENTRY != 0);
    let names = set.get(2..2 + name_entries)?;
    if name_length == 0 || names.iter().any(|entry| entry[0] != ENTRY_FILE_NAME) {
        return None;
    }
    let units: Vec<u16> = names
        .iter()
        .flat_map(|entry| entry[NAME_OFFSET..].chunks_exact(2))
        .take(name_length)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .collect();
    let name = String::from_utf16_lossy(&units);
    let is_valid_name = name != "."
        && name != ".."
        && !name
            .chars()
            .any(|ch| ch.is_control() || ILLEGAL_NAME_CHARS.contains(&ch));
    let valid_size = u64::from_le_bytes(stream[8..16].try_into().ok()?);
    let first_cluster = u32::from_le_bytes(stream[20..24].try_into().ok()?);
    let size = u64::from_le_bytes(stream[24..32].try_into().ok()?);
    let contiguous = stream[1] & NO_FAT_CHAIN != 0;
    // FirstCluster is 0 exactly when DataLength is 0; ValidDataLength is at
    // most DataLength.
    let is_valid_stream = (first_cluster == 0) == (size == 0) && valid_size <= size;
    if !is_valid_name || !is_valid_stream {
        return None;
    }
    let attributes = u16::from_le_bytes([set[0][4], set[0][5]]);
    Some(FileSet {
        name,
        is_directory: attributes & ATTRIBUTE_DIRECTORY != 0,
        data: FileRef {
            first_cluster,
            size,
            valid_size,
            contiguous,
        },
        known_secondaries: 1 + name_entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_rotate_right_and_add() {
        assert_eq!(table_checksum(&[1, 2]), 0x8000_0002);
        let mut entry = [0u8; 32];
        entry[0] = ENTRY_FILE;
        entry[2] = 0xaa;
        entry[3] = 0xbb;
        // The SetChecksum bytes do not count.
        let without = set_checksum(&[&entry]);
        entry[2] = 0;
        entry[3] = 0;
        assert_eq!(set_checksum(&[&entry]), without);
        // One nonzero byte, then 29 more bytes that only rotate the sum.
        assert_eq!(without, u16::from(ENTRY_FILE).rotate_right(29));
        let mut sectors = vec![0u8; 512 * 11];
        sectors[VOLUME_FLAGS_OFFSET] = 0xff;
        sectors[PERCENT_IN_USE_OFFSET] = 0x42;
        assert_eq!(boot_checksum(&sectors), 0);
    }

    #[test]
    fn the_file_system_name_is_the_magic() {
        let mut sector = vec![0u8; 512];
        sector[3..11].copy_from_slice(b"EXFAT   ");
        assert!(detect(&sector));
        assert!(!detect(&sector[..10]));
        sector[3..11].copy_from_slice(b"NTFS    ");
        assert!(!detect(&sector));
    }
}
