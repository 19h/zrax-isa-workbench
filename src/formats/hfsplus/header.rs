//! The volume header ([TN1150] "Volume Header", [HFS]
//! `HFSPlusVolumeHeader`), fork data records (`HFSPlusForkData`) and the
//! HFS wrapper's master directory block ([TN1150] "HFS Wrapper", [HFS]
//! `HFSMasterDirectoryBlock`).

use super::*;

/// Extent descriptors in a fork data or extent record
/// (`kHFSPlusExtentDensity`).
pub(super) const EXTENT_DENSITY: usize = 8;

/// Size of an `HFSPlusForkData` record.
pub(super) const FORK_DATA_SIZE: usize = 80;

/// Size of an `HFSPlusExtentDescriptor`.
const EXTENT_DESCRIPTOR_SIZE: usize = 8;

/// Fork data records in the volume header; the allocation file's, at 112,
/// is not read.
const EXTENTS_FILE_FIELD: usize = 192;
const CATALOG_FILE_FIELD: usize = 272;
const ATTRIBUTES_FILE_FIELD: usize = 352;
const STARTUP_FILE_FIELD: usize = 432;

/// HFS allocation blocks are a multiple of 512-byte sectors, and
/// `drAlBlSt` counts such sectors ([TN1150] "HFS Wrapper").
const HFS_SECTOR_SIZE: usize = 512;

/// Master directory block fields read for the wrapper.
const MDB_ALLOCATION_BLOCK_COUNT: usize = 0x12;
const MDB_ALLOCATION_BLOCK_SIZE: usize = 0x14;
const MDB_ALLOCATION_BLOCK_START: usize = 0x1c;
const MDB_VOLUME_NAME: usize = 0x24;
const MDB_EMBED_SIG_WORD: usize = 0x7c;
const MDB_EMBED_START_BLOCK: usize = 0x7e;
const MDB_EMBED_BLOCK_COUNT: usize = 0x80;

/// Longest HFS volume name (`kHFSMaxVolumeNameChars`).
const HFS_MAX_VOLUME_NAME_CHARS: usize = 27;

/// A run of allocation blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct Extent {
    /// First allocation block.
    pub(super) start_block: u32,
    /// Allocation blocks in the run.
    pub(super) block_count: u32,
}

/// An `HFSPlusForkData` record: a fork's size and its first eight extents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ForkData {
    /// `logicalSize`: bytes of valid data in the fork.
    pub(super) logical_size: u64,
    /// `totalBlocks`: allocation blocks in all of the fork's extents.
    pub(super) total_blocks: u32,
    /// `extents`; unused descriptors are zero.
    pub(super) extents: [Extent; EXTENT_DENSITY],
}

impl ForkData {
    /// Parse the 80-byte record at `at`: `logicalSize` (8), `clumpSize`
    /// (4), `totalBlocks` (4), then eight `startBlock`/`blockCount` pairs.
    pub(super) fn parse(data: &[u8], at: usize) -> Result<Self> {
        let record = slice(data, at, FORK_DATA_SIZE)?;
        Ok(Self {
            logical_size: be_u64(record, 0)?,
            total_blocks: be_u32(record, 12)?,
            extents: extent_record(record, 16)?,
        })
    }
}

/// An `HFSPlusExtentRecord`: eight descriptors at `at`.
pub(super) fn extent_record(data: &[u8], at: usize) -> Result<[Extent; EXTENT_DENSITY]> {
    let mut extents = [Extent::default(); EXTENT_DENSITY];
    for (i, extent) in extents.iter_mut().enumerate() {
        let descriptor = at + i * EXTENT_DESCRIPTOR_SIZE;
        *extent = Extent {
            start_block: be_u32(data, descriptor)?,
            block_count: be_u32(data, descriptor + 4)?,
        };
    }
    Ok(extents)
}

/// The volume header fields the reader uses.
#[derive(Debug, Clone)]
pub(super) struct VolumeHeader {
    /// `signature`: `H+` or `HX`.
    pub(super) signature: u16,
    /// `version`.
    pub(super) version: u16,
    /// `attributes`.
    pub(super) attributes: u32,
    /// `lastMountedVersion`, a four-character code.
    pub(super) last_mounted_version: u32,
    /// `journalInfoBlock`: allocation block of the journal info block.
    pub(super) journal_info_block: u32,
    /// `fileCount`.
    pub(super) file_count: u32,
    /// `folderCount`, not counting the root folder.
    pub(super) folder_count: u32,
    /// `blockSize`: allocation block size in bytes.
    pub(super) block_size: u32,
    /// `totalBlocks`.
    pub(super) total_blocks: u32,
    /// `freeBlocks`.
    pub(super) free_blocks: u32,
    /// The extents overflow B-tree.
    pub(super) extents_file: ForkData,
    /// The catalog B-tree.
    pub(super) catalog_file: ForkData,
    /// The attributes B-tree.
    pub(super) attributes_file: ForkData,
    /// The startup file (a boot loader for systems without HFS Plus
    /// support).
    pub(super) startup_file: ForkData,
}

impl VolumeHeader {
    /// Read and check the volume header of the volume at file offset
    /// `volume_offset`. Layout ([TN1150] "Volume Header"): `signature`
    /// (0), `version` (2), `attributes` (4), `lastMountedVersion` (8),
    /// `journalInfoBlock` (12), four dates (16), `fileCount` (32),
    /// `folderCount` (36), `blockSize` (40), `totalBlocks` (44),
    /// `freeBlocks` (48), then clump sizes, `nextCatalogID`, `writeCount`,
    /// `encodingsBitmap` and `finderInfo`, and five fork data records from
    /// 112.
    pub(super) fn read(data: &[u8], volume_offset: usize) -> Result<Self> {
        let at = volume_offset
            .checked_add(VOLUME_HEADER_OFFSET)
            .ok_or_else(|| error(format!("Invalid volume offset 0x{volume_offset:X}")))?;
        let bytes = slice(data, at, VOLUME_HEADER_SIZE)?;
        let signature = be_u16(bytes, 0)?;
        let version = be_u16(bytes, 2)?;
        let known = match signature {
            HFS_PLUS_SIG_WORD => version == HFS_PLUS_VERSION,
            // A later HFSX version is still an HFSX volume; parsing refuses
            // it ([TN1150] "HFSX").
            HFSX_SIG_WORD => version >= HFSX_VERSION,
            _ => false,
        };
        if !known {
            return Err(error(format!(
                "Missing volume header signature at 0x{at:X} (0x{signature:04X} version \
                 {version})"
            )));
        }
        let header = Self {
            signature,
            version,
            attributes: be_u32(bytes, 4)?,
            last_mounted_version: be_u32(bytes, 8)?,
            journal_info_block: be_u32(bytes, 12)?,
            file_count: be_u32(bytes, 32)?,
            folder_count: be_u32(bytes, 36)?,
            block_size: be_u32(bytes, 40)?,
            total_blocks: be_u32(bytes, 44)?,
            free_blocks: be_u32(bytes, 48)?,
            extents_file: ForkData::parse(bytes, EXTENTS_FILE_FIELD)?,
            catalog_file: ForkData::parse(bytes, CATALOG_FILE_FIELD)?,
            attributes_file: ForkData::parse(bytes, ATTRIBUTES_FILE_FIELD)?,
            startup_file: ForkData::parse(bytes, STARTUP_FILE_FIELD)?,
        };
        header.check(at)?;
        Ok(header)
    }

    /// The geometry and special-file checks detection relies on.
    fn check(&self, at: usize) -> Result<()> {
        // "a power of two, greater than or equal to 512" ([TN1150]).
        if self.block_size < 512 || !self.block_size.is_power_of_two() {
            return Err(error(format!(
                "Invalid volume header at 0x{at:X}: blockSize {} is not a power of two of at \
                 least 512",
                self.block_size
            )));
        }
        if self.total_blocks == 0 || self.free_blocks > self.total_blocks {
            return Err(error(format!(
                "Invalid volume header at 0x{at:X}: freeBlocks {} of totalBlocks {}",
                self.free_blocks, self.total_blocks
            )));
        }
        // The volume always has a catalog and an extents overflow B-tree,
        // each starting with a header node in its first extent.
        for (name, fork) in [
            ("catalog", &self.catalog_file),
            ("extents overflow", &self.extents_file),
        ] {
            if fork.logical_size == 0 || fork.extents[0].block_count == 0 {
                return Err(error(format!(
                    "Invalid volume header at 0x{at:X}: empty {name} file"
                )));
            }
            if fork.logical_size > self.size() {
                return Err(error(format!(
                    "Invalid volume header at 0x{at:X}: {name} file of {} B exceeds the volume",
                    fork.logical_size
                )));
            }
            for extent in &fork.extents {
                let end = u64::from(extent.start_block) + u64::from(extent.block_count);
                if end > u64::from(self.total_blocks) {
                    return Err(error(format!(
                        "Invalid volume header at 0x{at:X}: {name} extent 0x{:X} + {} beyond \
                         the {} blocks of the volume",
                        extent.start_block, extent.block_count, self.total_blocks
                    )));
                }
            }
        }
        Ok(())
    }

    /// The layout this header starts.
    pub(super) fn layout(&self) -> Layout {
        if self.signature == HFSX_SIG_WORD {
            Layout::Hfsx
        } else {
            Layout::HfsPlus
        }
    }

    /// Volume size in bytes: `totalBlocks` allocation blocks.
    pub(super) fn size(&self) -> u64 {
        u64::from(self.total_blocks) * u64::from(self.block_size)
    }
}

/// An HFS wrapper: a master directory block whose embedded volume holds
/// an HFS Plus volume.
#[derive(Debug, Clone)]
pub(super) struct Wrapper {
    /// File offset of the embedded volume:
    /// `drAlBlSt * 512 + drEmbedExtent.startBlock * drAlBlkSiz`.
    pub(super) offset: usize,
    /// Size of the embedded extent in bytes.
    pub(super) size: usize,
    /// `drVN`, the wrapper's volume name (Mac OS Roman; non-ASCII bytes as
    /// `?`).
    pub(super) volume_name: String,
}

impl Wrapper {
    /// Parse the master directory block at 1024 ([HFS]
    /// `HFSMasterDirectoryBlock`): `drSigWord` (0), `drNmAlBlks` (0x12),
    /// `drAlBlkSiz` (0x14), `drAlBlSt` (0x1C), `drVN` (0x24),
    /// `drEmbedSigWord` (0x7C) and `drEmbedExtent` (0x7E).
    pub(super) fn parse(data: &[u8]) -> Result<Self> {
        let mdb = slice(data, VOLUME_HEADER_OFFSET, VOLUME_HEADER_SIZE)?;
        if be_u16(mdb, 0)? != HFS_SIG_WORD || be_u16(mdb, MDB_EMBED_SIG_WORD)? != HFS_PLUS_SIG_WORD
        {
            return Err(error(
                "Missing HFS wrapper signatures (BD with an embedded H+)",
            ));
        }
        let block_count = be_u16(mdb, MDB_ALLOCATION_BLOCK_COUNT)?;
        let block_size = be_u32(mdb, MDB_ALLOCATION_BLOCK_SIZE)?;
        let first_sector = be_u16(mdb, MDB_ALLOCATION_BLOCK_START)?;
        let embed_start = be_u16(mdb, MDB_EMBED_START_BLOCK)?;
        let embed_count = be_u16(mdb, MDB_EMBED_BLOCK_COUNT)?;
        if block_size == 0 || block_size as usize % HFS_SECTOR_SIZE != 0 {
            return Err(error(format!(
                "Invalid HFS wrapper: drAlBlkSiz {block_size} is not a multiple of 512"
            )));
        }
        if embed_count == 0
            || u32::from(embed_start) + u32::from(embed_count) > u32::from(block_count)
        {
            return Err(error(format!(
                "Invalid HFS wrapper: embedded extent {embed_start} + {embed_count} beyond the \
                 {block_count} allocation blocks"
            )));
        }
        let block_size = u64::from(block_size);
        let offset =
            u64::from(first_sector) * HFS_SECTOR_SIZE as u64 + u64::from(embed_start) * block_size;
        let size = u64::from(embed_count) * block_size;
        let (Ok(offset), Ok(size)) = (usize::try_from(offset), usize::try_from(size)) else {
            return Err(error(
                "Invalid HFS wrapper: embedded extent beyond the address space",
            ));
        };
        let name_length = usize::from(mdb[MDB_VOLUME_NAME]).min(HFS_MAX_VOLUME_NAME_CHARS);
        let volume_name = mdb[MDB_VOLUME_NAME + 1..MDB_VOLUME_NAME + 1 + name_length]
            .iter()
            .map(|&b| if b.is_ascii() { char::from(b) } else { '?' })
            .collect();
        Ok(Self {
            offset,
            size,
            volume_name,
        })
    }
}
