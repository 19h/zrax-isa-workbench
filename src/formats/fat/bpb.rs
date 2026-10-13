//! The FAT12, FAT16 and FAT32 boot sector: the BIOS parameter block, the
//! geometry derived from it and the FAT type by cluster count ([FATGEN]
//! "Boot Sector and BPB", "FAT Data Structure", "FAT Type
//! Determination"), the reserved FAT entries, and the FAT32 `FSInfo` and
//! backup boot sectors ([FATGEN] "FAT32 `FSInfo` Sector Structure and Backup
//! Boot Sector").

use super::table::{EntryKind, Table};
use super::*;

/// The values `BPB_BytsPerSec` may take.
const SECTOR_SIZES: [u16; 4] = [512, 1024, 2048, 4096];

/// The legal `BPB_Media` values other than 0xF8-0xFF.
const MEDIA_REMOVABLE: u8 = 0xf0;
const MEDIA_LOWEST_FIXED: u8 = 0xf8;

/// Cluster counts from which a volume is FAT16 and FAT32.
const FAT16_MIN_CLUSTERS: u32 = 4085;
const FAT32_MIN_CLUSTERS: u32 = 65525;

/// `BS_BootSig`: the volume ID, label and file system type follow.
const EXTENDED_BOOT_SIGNATURE: u8 = 0x29;

/// Where the drive number and extended fields start: offset 36 for FAT12
/// and FAT16, after the FAT32 fields at 64 for FAT32.
const FAT16_EXTENDED_OFFSET: usize = 36;
const FAT32_EXTENDED_OFFSET: usize = 64;

/// Extended fields after `BS_DrvNum`: `BS_BootSig` (2), `BS_VolID` (3),
/// `BS_VolLab` (7, 11 bytes), `BS_FilSysType` (18, 8 bytes); 26 bytes in
/// all.
const EXTENDED_FIELDS_SIZE: usize = 26;

/// `BPB_ExtFlags`: bit 7 disables mirroring, bits 0-3 name the active FAT.
const EXT_FLAGS_NO_MIRRORING: u16 = 0x0080;
const EXT_FLAGS_ACTIVE_FAT: u16 = 0x000f;

/// FAT[1] bits: 1 means the volume was cleanly unmounted (`ClnShutBitMask`)
/// and no disk errors were seen (`HrdErrBitMask`).
const FAT16_CLEAN_SHUTDOWN: u32 = 0x8000;
const FAT16_HARD_ERROR: u32 = 0x4000;
const FAT32_CLEAN_SHUTDOWN: u32 = 0x0800_0000;
const FAT32_HARD_ERROR: u32 = 0x0400_0000;

/// `FSInfo`: `FSI_LeadSig` (0), `FSI_StrucSig` (484), `FSI_Free_Count`
/// (488), `FSI_Nxt_Free` (492), `FSI_TrailSig` (508).
const FSI_LEAD_SIG: u32 = 0x4161_5252;
const FSI_STRUC_SIG: u32 = 0x6141_7272;
const FSI_TRAIL_SIG: u32 = 0xaa55_0000;
const FSI_STRUC_SIG_OFFSET: usize = 484;
const FSI_FREE_COUNT_OFFSET: usize = 488;
const FSI_NXT_FREE_OFFSET: usize = 492;
const FSI_TRAIL_SIG_OFFSET: usize = 508;

/// `FSI_Free_Count` and `FSI_Nxt_Free` value for "unknown".
const FSI_UNKNOWN: u32 = u32::MAX;

/// The FAT32 fields at offsets 36-63.
#[derive(Debug, Clone, Copy)]
pub(super) struct Fat32Fields {
    /// `BPB_ExtFlags`.
    ext_flags: u16,
    /// `BPB_FSVer`.
    version: u16,
    /// `BPB_RootClus`.
    pub(super) root_cluster: u32,
    /// `BPB_FSInfo`: a sector number in the reserved region.
    fs_info: u16,
    /// `BPB_BkBootSec`: a sector number in the reserved region.
    backup_boot: u16,
}

/// The fields after `BS_BootSig` 0x29.
#[derive(Debug, Clone, Copy)]
struct ExtendedFields {
    /// `BS_VolID`.
    volume_id: u32,
    /// `BS_VolLab`.
    label: [u8; 11],
    /// `BS_FilSysType`, informational only.
    fs_type: [u8; 8],
}

/// A boot sector whose BPB validated, and the geometry it implies.
/// Sector numbers count `bytes_per_sector` bytes from the start of the
/// volume.
#[derive(Debug, Clone)]
pub(super) struct Geometry {
    /// The FAT type the cluster count decides.
    pub(super) layout: Layout,
    pub(super) bytes_per_sector: u32,
    pub(super) sectors_per_cluster: u32,
    pub(super) reserved_sectors: u32,
    pub(super) fat_count: u32,
    /// Sectors per FAT (`BPB_FATSz16` or `BPB_FATSz32`).
    pub(super) fat_sectors: u32,
    /// `BPB_RootEntCnt`: root directory entries (FAT12 and FAT16).
    pub(super) root_entries: u32,
    /// `BPB_TotSec16`, or `BPB_TotSec32` when it is 0.
    pub(super) total_sectors: u32,
    /// `BPB_TotSec32` when `BPB_TotSec16` is used and it differs.
    unused_total_sectors: Option<u32>,
    /// The first sector of cluster 2.
    first_data_sector: u32,
    /// `CountofClusters`.
    pub(super) cluster_count: u32,
    /// `BPB_Media`.
    media: u8,
    /// `BPB_HiddSec`.
    hidden_sectors: u32,
    /// `BS_OEMName`.
    oem_name: [u8; 8],
    /// The FAT32 fields.
    pub(super) fat32: Option<Fat32Fields>,
    /// The extended boot fields, when `BS_BootSig` is 0x29.
    extended: Option<ExtendedFields>,
    /// The volume against the input.
    pub(super) coverage: Coverage,
    /// FAT[0] of the first FAT.
    fat0: u32,
}

/// The FAT type the count of clusters decides.
fn layout_for(cluster_count: u32) -> Layout {
    if cluster_count < FAT16_MIN_CLUSTERS {
        Layout::Fat12
    } else if cluster_count < FAT32_MIN_CLUSTERS {
        Layout::Fat16
    } else {
        Layout::Fat32
    }
}

fn is_media(value: u8) -> bool {
    value == MEDIA_REMOVABLE || value >= MEDIA_LOWEST_FIXED
}

/// Printable ASCII of a fixed-size text field, other bytes as `_`, without
/// trailing spaces and NULs.
pub(super) fn field_text(bytes: &[u8]) -> String {
    let text: String = bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                char::from(b)
            } else if b == 0 {
                ' '
            } else {
                '_'
            }
        })
        .collect();
    text.trim_end().to_string()
}

/// The BPB fields every FAT type shares (offsets 11-35), each within its
/// legal range.
#[derive(Debug, Clone, Copy)]
struct Bpb {
    /// `BPB_BytsPerSec` (offset 11).
    bytes_per_sector: u16,
    /// `BPB_SecPerClus` (13).
    sectors_per_cluster: u8,
    /// `BPB_RsvdSecCnt` (14).
    reserved_sectors: u16,
    /// `BPB_NumFATs` (16).
    fat_count: u8,
    /// `BPB_RootEntCnt` (17).
    root_entries: u16,
    /// `BPB_TotSec16` (19).
    total_sectors_16: u16,
    /// `BPB_Media` (21).
    media: u8,
    /// `BPB_FATSz16` (22).
    fat_size_16: u16,
    /// `BPB_TotSec32` (32).
    total_sectors_32: u32,
    /// `BPB_TotSec16`, or `BPB_TotSec32` when it is 0.
    total_sectors: u32,
    /// `BPB_FATSz16`, or `BPB_FATSz32` (36) when it is 0.
    fat_sectors: u32,
}

impl Bpb {
    /// Read the BPB, checking `BPB_BytsPerSec`, `BPB_SecPerClus`,
    /// `BPB_RsvdSecCnt`, `BPB_NumFATs`, `BPB_Media`, the total sectors and
    /// the FAT size in that order.
    fn read(data: &[u8]) -> Result<Self> {
        let bytes_per_sector = le_u16(data, 11)?;
        if !SECTOR_SIZES.contains(&bytes_per_sector) {
            return Err(error(format!(
                "Invalid BPB_BytsPerSec {bytes_per_sector}: 512, 1024, 2048 or 4096 expected"
            )));
        }
        let sectors_per_cluster = byte(data, 13)?;
        if !sectors_per_cluster.is_power_of_two() {
            return Err(error(format!(
                "Invalid BPB_SecPerClus {sectors_per_cluster}: not a power of two"
            )));
        }
        let reserved_sectors = le_u16(data, 14)?;
        if reserved_sectors == 0 {
            return Err(error("Invalid BPB_RsvdSecCnt 0"));
        }
        let fat_count = byte(data, 16)?;
        match fat_count {
            0 => return Err(error("Invalid BPB_NumFATs 0")),
            1 | 2 => {}
            _ => {
                return Err(error(format!(
                    "Unsupported BPB_NumFATs {fat_count}: 1 or 2 FATs are accepted"
                )))
            }
        }
        let media = byte(data, 21)?;
        if !is_media(media) {
            return Err(error(format!("Invalid BPB_Media 0x{media:02X}")));
        }
        let total_sectors_16 = le_u16(data, 19)?;
        let total_sectors_32 = le_u32(data, 32)?;
        let total_sectors = if total_sectors_16 != 0 {
            u32::from(total_sectors_16)
        } else {
            total_sectors_32
        };
        if total_sectors == 0 {
            return Err(error("Invalid BPB_TotSec16 and BPB_TotSec32: both are 0"));
        }
        let fat_size_16 = le_u16(data, 22)?;
        let fat_sectors = if fat_size_16 != 0 {
            u32::from(fat_size_16)
        } else {
            le_u32(data, 36)?
        };
        if fat_sectors == 0 {
            return Err(error("Invalid BPB_FATSz16 and BPB_FATSz32: both are 0"));
        }
        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            fat_count,
            root_entries: le_u16(data, 17)?,
            total_sectors_16,
            media,
            fat_size_16,
            total_sectors_32,
            total_sectors,
            fat_sectors,
        })
    }

    /// `FirstDataSector` and `CountofClusters` ([FATGEN] "FAT Type
    /// Determination"): the sectors of the reserved region, the FATs and
    /// the root directory region, and the whole clusters after them.
    fn regions(&self) -> Result<(u32, u32)> {
        let root_dir_sectors = div_round_up(
            u64::from(self.root_entries) * DIRECTORY_ENTRY_SIZE as u64,
            u64::from(self.bytes_per_sector),
        );
        let first_data_sector = u64::from(self.reserved_sectors)
            + u64::from(self.fat_count) * u64::from(self.fat_sectors)
            + root_dir_sectors;
        let cluster_count = u64::from(self.total_sectors)
            .checked_sub(first_data_sector)
            .map(|data_sectors| data_sectors / u64::from(self.sectors_per_cluster))
            .filter(|&clusters| clusters > 0)
            .ok_or_else(|| {
                error(format!(
                    "Invalid geometry: the reserved sectors, FATs and root directory \
                     ({first_data_sector} sectors) leave no cluster in the {} sectors of the \
                     volume",
                    self.total_sectors
                ))
            })?;
        // Both are below the 32-bit total sector count.
        Ok((
            u32::try_from(first_data_sector).expect("less than the total sectors"),
            u32::try_from(cluster_count).expect("fewer clusters than sectors"),
        ))
    }
}

/// The boot sector's size, its jump field and its signature.
fn check_boot_sector(data: &[u8]) -> Result<()> {
    if data.len() < MIN_SECTOR_SIZE {
        return Err(error(format!(
            "Truncated boot sector: {} B, {MIN_SECTOR_SIZE} B needed",
            data.len()
        )));
    }
    let jump: [u8; 3] = array(data, 0)?;
    if jump_target(jump).is_none() {
        return Err(error(format!(
            "Invalid BS_jmpBoot {:02X} {:02X} {:02X}: not an x86 short or near jump",
            jump[0], jump[1], jump[2]
        )));
    }
    if array(data, BOOT_SIGNATURE_OFFSET)? != BOOT_SIGNATURE {
        return Err(error("Missing boot sector signature 55 AA at 0x1FE"));
    }
    Ok(())
}

/// The fields whose value the FAT type fixes: FAT32 has no fixed root
/// directory and counts its sectors only in `BPB_TotSec32`; FAT12 and
/// FAT16 need a root directory region.
fn check_type_fields(bpb: &Bpb, layout: Layout) -> Result<()> {
    if layout != Layout::Fat32 {
        if bpb.root_entries == 0 {
            return Err(error(format!(
                "Invalid BPB_RootEntCnt 0: {} needs a root directory region",
                layout.label()
            )));
        }
        return Ok(());
    }
    if bpb.root_entries != 0 {
        return Err(error(format!(
            "Invalid BPB_RootEntCnt {}: FAT32 has no fixed root directory",
            bpb.root_entries
        )));
    }
    if bpb.total_sectors_16 != 0 {
        return Err(error(format!(
            "Invalid BPB_TotSec16 {}: 0 expected on FAT32",
            bpb.total_sectors_16
        )));
    }
    Ok(())
}

/// FAT[0] of the first FAT: a media descriptor in the low 8 bits and
/// every other bit of the entry set ([FATGEN] "FAT Type Determination").
/// The FAT region is in `data`.
fn check_fat0(data: &[u8], bpb: &Bpb, kind: EntryKind, cluster_count: u32) -> Result<u32> {
    let fat_start = usize::from(bpb.reserved_sectors) * usize::from(bpb.bytes_per_sector);
    let fat0 = data
        .get(fat_start..)
        .and_then(|fat| Table::new(fat, kind, cluster_count).entry(0))
        .ok_or_else(|| error(format!("Truncated FAT at 0x{fat_start:X}")))?;
    let media_bits = u32::from(u8::MAX);
    let media = u8::try_from(fat0 & media_bits).expect("masked to 8 bits");
    if fat0 | media_bits != kind.mask() || !is_media(media) {
        return Err(error(format!(
            "Invalid FAT[0] 0x{fat0:X}: not a media descriptor with every other bit set"
        )));
    }
    Ok(fat0)
}

impl Geometry {
    /// Read and validate the boot sector of `data`, checking in this
    /// order: the jump field and the boot signature; `BPB_BytsPerSec`,
    /// `BPB_SecPerClus`, `BPB_RsvdSecCnt`, `BPB_NumFATs` and `BPB_Media`;
    /// the total sectors and FAT size; the regions that precede the data
    /// region; the FAT type by cluster count against the BPB layout; the
    /// FAT size; the metadata region against the input; and FAT[0]. How
    /// the volume relates to the input is recorded, not checked; weak
    /// detection checks it.
    ///
    /// # Errors
    ///
    /// [`ClassifierError::FatParseError`] naming the first check that
    /// failed.
    pub(super) fn parse(data: &[u8]) -> Result<Self> {
        check_boot_sector(data)?;
        let bpb = Bpb::read(data)?;
        let (first_data_sector, cluster_count) = bpb.regions()?;
        let layout = layout_for(cluster_count);
        let fat32 = check_layout(data, layout, cluster_count, &bpb)?;
        check_type_fields(&bpb, layout)?;

        let kind = entry_kind(layout);
        let bytes = u64::from(bpb.bytes_per_sector);
        let entries = u64::from(cluster_count) + 2;
        if u64::from(bpb.fat_sectors) * bytes < kind.table_size(entries) {
            return Err(error(format!(
                "Invalid BPB_FATSz: {} sectors hold fewer than the {entries} entries of \
                 {cluster_count} clusters",
                bpb.fat_sectors
            )));
        }
        let metadata_size = u64::from(first_data_sector) * bytes;
        if metadata_size > data.len() as u64 {
            return Err(error(format!(
                "Truncated volume: the reserved sectors, FATs and root directory need \
                 {metadata_size} B, {} B present",
                data.len()
            )));
        }
        let coverage = Coverage::of(u64::from(bpb.total_sectors) * bytes, data.len());
        let fat0 = check_fat0(data, &bpb, kind, cluster_count)?;

        let extended_offset = if layout == Layout::Fat32 {
            FAT32_EXTENDED_OFFSET
        } else {
            FAT16_EXTENDED_OFFSET
        };
        let unused_total_sectors = (bpb.total_sectors_16 != 0
            && bpb.total_sectors_32 != 0
            && bpb.total_sectors_32 != bpb.total_sectors)
            .then_some(bpb.total_sectors_32);
        Ok(Self {
            layout,
            bytes_per_sector: u32::from(bpb.bytes_per_sector),
            sectors_per_cluster: u32::from(bpb.sectors_per_cluster),
            reserved_sectors: u32::from(bpb.reserved_sectors),
            fat_count: u32::from(bpb.fat_count),
            fat_sectors: bpb.fat_sectors,
            root_entries: u32::from(bpb.root_entries),
            total_sectors: bpb.total_sectors,
            unused_total_sectors,
            first_data_sector,
            cluster_count,
            media: bpb.media,
            hidden_sectors: le_u32(data, 28)?,
            oem_name: array(data, 3)?,
            fat32,
            extended: extended_fields(data, extended_offset)?,
            coverage,
            fat0,
        })
    }

    pub(super) fn layout(&self) -> Layout {
        self.layout
    }

    pub(super) fn entry_kind(&self) -> EntryKind {
        entry_kind(self.layout)
    }

    /// File offset of sector `sector`.
    fn sector_offset(&self, sector: u32) -> u64 {
        u64::from(sector) * u64::from(self.bytes_per_sector)
    }

    pub(super) fn cluster_size(&self) -> u64 {
        u64::from(self.sectors_per_cluster) * u64::from(self.bytes_per_sector)
    }

    /// Volume size in bytes.
    pub(super) fn volume_size(&self) -> u64 {
        self.sector_offset(self.total_sectors)
    }

    /// File offset of cluster 2.
    pub(super) fn heap_offset(&self) -> u64 {
        self.sector_offset(self.first_data_sector)
    }

    /// The active FAT: the first, unless FAT32 mirroring is disabled.
    fn active_fat(&self) -> u32 {
        match self.fat32 {
            Some(fields) if fields.ext_flags & EXT_FLAGS_NO_MIRRORING != 0 => {
                u32::from(fields.ext_flags & EXT_FLAGS_ACTIVE_FAT)
            }
            _ => 0,
        }
    }

    /// The used bytes of FAT `index`: the entries of clusters 0 to
    /// `cluster_count + 1`. [`Self::parse`] checked that they are in the
    /// input.
    fn fat_bytes<'a>(&self, data: &'a [u8], index: u32) -> &'a [u8] {
        let start = self.sector_offset(self.reserved_sectors + index * self.fat_sectors);
        let used = self
            .entry_kind()
            .table_size(u64::from(self.cluster_count) + 2);
        let start = usize::try_from(start).expect("in the input");
        let end = usize::try_from(used).expect("in the input") + start;
        &data[start..end]
    }

    /// The active FAT.
    pub(super) fn table<'a>(&self, data: &'a [u8]) -> Table<'a> {
        Table::new(
            self.fat_bytes(data, self.active_fat()),
            self.entry_kind(),
            self.cluster_count,
        )
    }

    /// The FAT12/FAT16 root directory region: its file offset and bytes.
    pub(super) fn root_region<'a>(&self, data: &'a [u8]) -> (usize, &'a [u8]) {
        let start = self.sector_offset(self.reserved_sectors + self.fat_count * self.fat_sectors);
        let start = usize::try_from(start).expect("in the input");
        let size = usize::try_from(self.root_entries).expect("16-bit count") * DIRECTORY_ENTRY_SIZE;
        (start, &data[start..start + size])
    }

    /// Where boot code may start: after the BPB and the boot sector fields
    /// that the layout and `BS_BootSig` define.
    pub(super) fn boot_code_start(&self) -> usize {
        let base = if self.layout == Layout::Fat32 {
            FAT32_EXTENDED_OFFSET
        } else {
            FAT16_EXTENDED_OFFSET
        };
        if self.extended.is_some() {
            base + EXTENDED_FIELDS_SIZE
        } else {
            base
        }
    }
}

/// Entry width of a FAT type.
fn entry_kind(layout: Layout) -> EntryKind {
    match layout {
        Layout::Fat12 => EntryKind::Fat12,
        Layout::Fat16 => EntryKind::Fat16,
        Layout::Fat32 | Layout::ExFat => EntryKind::Fat32,
    }
}

/// Check that the BPB layout agrees with the FAT type the cluster count
/// decides: a FAT32 BPB (`BPB_FATSz16` 0) exactly when the volume is FAT32.
/// Returns the FAT32 fields (`BPB_ExtFlags` at 40, `BPB_FSVer` 42,
/// `BPB_RootClus` 44, `BPB_FSInfo` 48, `BPB_BkBootSec` 50), which must name
/// version 0.0, a root cluster in the heap and an existing active FAT.
fn check_layout(
    data: &[u8],
    layout: Layout,
    cluster_count: u32,
    bpb: &Bpb,
) -> Result<Option<Fat32Fields>> {
    match (layout == Layout::Fat32, bpb.fat_size_16 == 0) {
        (true, true) => {}
        (true, false) => {
            return Err(error(format!(
                "Invalid BPB: {cluster_count} clusters make the volume FAT32, but \
                 BPB_FATSz16 is not 0"
            )))
        }
        (false, true) => {
            return Err(error(format!(
                "Invalid BPB: FAT32 fields (BPB_FATSz16 0) on a volume of {cluster_count} \
                 clusters, which the cluster count makes {}",
                layout.label()
            )))
        }
        (false, false) => return Ok(None),
    }
    let fields = Fat32Fields {
        ext_flags: le_u16(data, 40)?,
        version: le_u16(data, 42)?,
        root_cluster: le_u32(data, 44)?,
        fs_info: le_u16(data, 48)?,
        backup_boot: le_u16(data, 50)?,
    };
    if fields.version != 0 {
        return Err(error(format!(
            "Unsupported BPB_FSVer {}.{}: only version 0.0 is defined",
            fields.version >> 8,
            fields.version & 0xff
        )));
    }
    if !(2..=cluster_count + 1).contains(&fields.root_cluster) {
        return Err(error(format!(
            "Invalid BPB_RootClus {}: not a cluster of the volume",
            fields.root_cluster
        )));
    }
    let fat_count = u16::from(bpb.fat_count);
    let active = fields.ext_flags & EXT_FLAGS_ACTIVE_FAT;
    if fields.ext_flags & EXT_FLAGS_NO_MIRRORING != 0 && active >= fat_count {
        return Err(error(format!(
            "Invalid BPB_ExtFlags 0x{:04X}: the active FAT index is {active}, the volume has \
             {}",
            fields.ext_flags,
            counted(usize::from(fat_count), "FAT", "FATs")
        )));
    }
    Ok(Some(fields))
}

/// The extended boot fields after `BS_DrvNum` at `offset`, when
/// `BS_BootSig` is 0x29.
fn extended_fields(data: &[u8], offset: usize) -> Result<Option<ExtendedFields>> {
    if byte(data, offset + 2)? != EXTENDED_BOOT_SIGNATURE {
        return Ok(None);
    }
    Ok(Some(ExtendedFields {
        volume_id: le_u32(data, offset + 3)?,
        label: array(data, offset + 7)?,
        fs_type: array(data, offset + 18)?,
    }))
}

/// Summary notes and metadata from the boot sector, the FATs and, on
/// FAT32, the `FSInfo` and backup boot sectors.
pub(super) fn describe(g: &Geometry, data: &[u8], c: &mut Container<'_>) {
    let fats = counted(g.fat_count as usize, "FAT", "FATs");
    let root = match g.fat32 {
        Some(fields) => format!("root directory at cluster {}", fields.root_cluster),
        None => format!("{} root directory entries", g.root_entries),
    };
    c.notes.push(format!(
        "{} volume: {} of {} (the cluster count decides the FAT type); {} B sectors; {fats} \
         of {}; {root}",
        g.layout.label(),
        counted(g.cluster_count as usize, "cluster", "clusters"),
        size_text(g.cluster_size()),
        g.bytes_per_sector,
        counted(g.fat_sectors as usize, "sector", "sectors")
    ));
    if let Some(note) = coverage_note(g.coverage, g.volume_size(), data) {
        c.notes.push(note);
    }
    if let Some(total) = g.unused_total_sectors {
        c.notes.push(format!(
            "BPB_TotSec32 {total} differs from BPB_TotSec16 {}, which is used",
            g.total_sectors
        ));
    }
    c.notes.push(fat_copies_note(g, data));
    if let Some(note) = reserved_entries_note(g, data) {
        c.notes.push(note);
    }
    if let Some(fields) = g.fat32 {
        let fs_info = fs_info_note(g, fields, data, c);
        c.notes.push(fs_info);
        c.notes.push(backup_boot_note(g, fields, data));
    }
    if let Some(extended) = g.extended {
        let fs_type = field_text(&extended.fs_type);
        let named = match g.layout {
            Layout::Fat12 => ["FAT12", "FAT"].contains(&fs_type.as_str()),
            Layout::Fat16 => ["FAT16", "FAT"].contains(&fs_type.as_str()),
            Layout::Fat32 | Layout::ExFat => fs_type == "FAT32",
        };
        if !named {
            c.notes.push(format!(
                "BS_FilSysType \"{fs_type}\" does not name the FAT type; it is informational, \
                 and the cluster count makes the volume {}",
                g.layout.label()
            ));
        }
    }
    c.notes.push(
        "FAT has no metadata checksums; long-name checksums were checked against their short \
         names"
            .to_string(),
    );
    c.notes.push(
        "FAT names no processor for its files; members are classified from their own bytes"
            .to_string(),
    );
    push_metadata(g, c);
}

/// Whether the FAT copies agree, or which one is active.
fn fat_copies_note(g: &Geometry, data: &[u8]) -> String {
    let active = g.active_fat();
    if g.fat32
        .is_some_and(|fields| fields.ext_flags & EXT_FLAGS_NO_MIRRORING != 0)
    {
        return format!(
            "FAT mirroring is disabled (BPB_ExtFlags); FAT {} is active",
            active + 1
        );
    }
    if g.fat_count == 1 {
        return "One FAT, no copy".to_string();
    }
    let first = g.fat_bytes(data, 0);
    let differing: Vec<String> = (1..g.fat_count)
        .filter(|&i| g.fat_bytes(data, i) != first)
        .map(|i| (i + 1).to_string())
        .collect();
    if differing.is_empty() {
        format!("The {} FAT copies are identical", g.fat_count)
    } else {
        format!(
            "FAT copy {} differs from FAT 1, which is used",
            differing.join(", ")
        )
    }
}

/// FAT[0]'s media byte against `BPB_Media`, and the FAT16/FAT32 volume
/// state bits in FAT[1].
fn reserved_entries_note(g: &Geometry, data: &[u8]) -> Option<String> {
    let mut facts = Vec::new();
    let fat0_media = g.fat0 & u32::from(u8::MAX);
    if fat0_media != u32::from(g.media) {
        facts.push(format!(
            "FAT[0] holds media descriptor 0x{fat0_media:02X}, BPB_Media is 0x{:02X}",
            g.media
        ));
    }
    let (clean, hard_error) = match g.layout {
        Layout::Fat16 => (FAT16_CLEAN_SHUTDOWN, FAT16_HARD_ERROR),
        Layout::Fat32 => (FAT32_CLEAN_SHUTDOWN, FAT32_HARD_ERROR),
        Layout::Fat12 | Layout::ExFat => return (!facts.is_empty()).then(|| facts.join("; ")),
    };
    let fat1 = g.table(data).entry(1).unwrap_or(0);
    if fat1 & clean == 0 {
        facts.push("FAT[1] marks the volume dirty (not cleanly unmounted)".to_string());
    }
    if fat1 & hard_error == 0 {
        facts.push("FAT[1] records disk I/O errors".to_string());
    }
    (!facts.is_empty()).then(|| facts.join("; "))
}

/// The `FSInfo` sector's signatures and hints.
fn fs_info_note(g: &Geometry, fields: Fat32Fields, data: &[u8], c: &mut Container<'_>) -> String {
    let sector = u32::from(fields.fs_info);
    if sector == 0 || sector >= g.reserved_sectors {
        return format!("BPB_FSInfo {sector} names no sector of the reserved region");
    }
    let Ok(at) = usize::try_from(g.sector_offset(sector)) else {
        return format!("FSInfo sector {sector} is not in the input");
    };
    let Ok(info) = slice(data, at, MIN_SECTOR_SIZE) else {
        return format!("FSInfo sector {sector} is not in the input");
    };
    let word = |offset: usize| {
        u32::from_le_bytes(
            info[offset..offset + 4]
                .try_into()
                .expect("slice has 4 bytes"),
        )
    };
    if word(0) != FSI_LEAD_SIG
        || word(FSI_STRUC_SIG_OFFSET) != FSI_STRUC_SIG
        || word(FSI_TRAIL_SIG_OFFSET) != FSI_TRAIL_SIG
    {
        return format!("FSInfo sector {sector} has invalid signatures; not used");
    }
    let free = word(FSI_FREE_COUNT_OFFSET);
    let next = word(FSI_NXT_FREE_OFFSET);
    let hint = |value: u32| {
        if value == FSI_UNKNOWN {
            "unknown".to_string()
        } else {
            value.to_string()
        }
    };
    if free != FSI_UNKNOWN {
        c.push_metadata(
            "fat_fsinfo_free_count",
            "FSInfo free clusters (hint)",
            u64::from(free),
        );
    }
    format!(
        "FSInfo sector {sector}: free cluster count {} and next free cluster {} are hints, not \
         verified",
        hint(free),
        hint(next)
    )
}

/// The backup boot sector against sector 0.
fn backup_boot_note(g: &Geometry, fields: Fat32Fields, data: &[u8]) -> String {
    let sector = u32::from(fields.backup_boot);
    if sector == 0 {
        return "No backup boot sector (BPB_BkBootSec 0)".to_string();
    }
    if sector >= g.reserved_sectors {
        return format!("BPB_BkBootSec {sector} names no sector of the reserved region");
    }
    let size = g.bytes_per_sector as usize;
    let backup = usize::try_from(g.sector_offset(sector))
        .ok()
        .and_then(|at| slice(data, at, size).ok());
    match (backup, slice(data, 0, size)) {
        (Some(backup), Ok(boot)) if backup == boot => {
            format!("The backup boot sector at sector {sector} matches sector 0")
        }
        (Some(_), Ok(_)) => {
            format!("The backup boot sector at sector {sector} differs from sector 0")
        }
        _ => format!("The backup boot sector at sector {sector} is not in the input"),
    }
}

fn push_metadata(g: &Geometry, c: &mut Container<'_>) {
    c.push_metadata(
        "fat_bytes_per_sector",
        "Bytes per sector",
        u64::from(g.bytes_per_sector),
    );
    c.push_metadata("fat_cluster_size", "Cluster size (B)", g.cluster_size());
    c.push_metadata("fat_cluster_count", "Clusters", u64::from(g.cluster_count));
    c.push_metadata(
        "fat_reserved_sectors",
        "Reserved sectors",
        u64::from(g.reserved_sectors),
    );
    c.push_metadata("fat_fat_count", "FATs", u64::from(g.fat_count));
    c.push_metadata(
        "fat_fat_sectors",
        "Sectors per FAT",
        u64::from(g.fat_sectors),
    );
    c.push_metadata(
        "fat_total_sectors",
        "Total sectors",
        u64::from(g.total_sectors),
    );
    match g.fat32 {
        Some(fields) => c.push_metadata(
            "fat_root_cluster",
            "Root directory cluster",
            u64::from(fields.root_cluster),
        ),
        None => c.push_metadata(
            "fat_root_entry_count",
            "Root directory entries",
            u64::from(g.root_entries),
        ),
    }
    c.push_metadata(
        "fat_media_descriptor",
        "Media descriptor",
        format!("0x{:02X}", g.media),
    );
    c.push_metadata(
        "fat_hidden_sectors",
        "Hidden sectors",
        u64::from(g.hidden_sectors),
    );
    c.push_metadata("fat_oem_name", "OEM name", field_text(&g.oem_name));
    if let Some(extended) = g.extended {
        c.push_metadata(
            "fat_volume_serial",
            "Volume serial number",
            serial_text(extended.volume_id),
        );
        c.push_metadata(
            "fat_volume_label",
            "Volume label (boot sector)",
            field_text(&extended.label),
        );
        c.push_metadata(
            "fat_filesystem_type",
            "BS_FilSysType",
            field_text(&extended.fs_type),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cluster_count_alone_decides_the_type() {
        assert_eq!(layout_for(1), Layout::Fat12);
        assert_eq!(layout_for(4084), Layout::Fat12);
        assert_eq!(layout_for(4085), Layout::Fat16);
        assert_eq!(layout_for(65524), Layout::Fat16);
        assert_eq!(layout_for(65525), Layout::Fat32);
    }

    #[test]
    fn media_descriptors_are_f0_and_f8_to_ff() {
        assert!(is_media(0xf0));
        assert!(is_media(0xf8));
        assert!(is_media(0xff));
        assert!(!is_media(0xf7));
        assert!(!is_media(0x00));
    }

    #[test]
    fn text_fields_drop_padding_and_mask_other_bytes() {
        assert_eq!(field_text(b"FAT12   "), "FAT12");
        assert_eq!(field_text(b"MSWIN4.1"), "MSWIN4.1");
        assert_eq!(field_text(b"A\x01B\0\0"), "A_B");
    }
}
