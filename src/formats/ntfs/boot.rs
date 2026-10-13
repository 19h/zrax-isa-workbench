//! The boot sector ([LAYOUT] `NTFS_BOOT_SECTOR`, `BIOS_PARAMETER_BLOCK`;
//! [DOCS] `files/boot.html`) with the checks of [NTFS-3G]
//! `ntfs_boot_sector_is_ntfs` and `ntfs_boot_sector_parse`, all of which
//! detection requires.

use super::*;

/// The OEM ID at offset 3 ([LAYOUT] `magicNTFS`).
const OEM_ID: &[u8; 8] = b"NTFS    ";

/// The end-of-sector marker `55 AA` at offset 510. ntfs-3g only warns when
/// it is missing; detection requires it.
const END_OF_SECTOR_MARKER: u16 = 0xaa55;

/// Sector sizes ntfs-3g accepts.
const MIN_SECTOR_SIZE: u32 = 256;
const MAX_SECTOR_SIZE: u32 = 4096;

/// `sectors_per_cluster` above 128 encodes `1 << (256 - value)` sectors;
/// ntfs-3g accepts 240 to 253.
const MAX_PLAIN_SECTORS_PER_CLUSTER: u8 = 128;
const MIN_SHIFTED_SECTORS_PER_CLUSTER: u8 = 240;
const MAX_SHIFTED_SECTORS_PER_CLUSTER: u8 = 253;

/// `NTFS_MAX_CLUSTER_SIZE` ([LAYOUT] `param.h`: "Windows 10 Creators allows
/// 2MB").
const MAX_CLUSTER_SIZE: u32 = 2 << 20;

/// Record size encodings ntfs-3g accepts: 1 to 64 clusters, a power of two,
/// or a negative value -31 to -9 meaning `1 << -value` bytes.
const MAX_CLUSTERS_PER_RECORD: i8 = 0x40;
const MIN_NEGATIVE_RECORD_SHIFT: i8 = -31;
const MAX_NEGATIVE_RECORD_SHIFT: i8 = -9;

/// MFT and index records hold update sequence strides of 512 B, so they
/// are at least that large ([NTFS-3G] `is_valid_record`, `dir.c`).
const MIN_RECORD_SIZE: usize = 512;

/// The largest MFT record read. Windows writes 1 KiB records (4 KiB on
/// 4096-byte sectors); the bound is ours, so that a hostile encoding of 64
/// clusters of 2 MiB is not read as one record.
const MAX_RECORD_SIZE: usize = 64 << 10;

/// The boot sector's geometry and the location of the MFT.
#[derive(Debug, Clone)]
pub(super) struct BootSector {
    /// `bytes_per_sector`.
    pub(super) bytes_per_sector: u32,
    /// Cluster size in bytes.
    pub(super) cluster_size: u32,
    /// `number_of_sectors`: sectors in the volume, without the backup boot
    /// sector after them.
    pub(super) total_sectors: u64,
    /// Clusters in the volume: `number_of_sectors` divided by the sectors
    /// per cluster ([NTFS-3G] `ntfs_boot_sector_parse`).
    pub(super) cluster_count: u64,
    /// `mft_lcn`: the cluster of `$MFT` VCN 0.
    pub(super) mft_lcn: u64,
    /// `mftmirr_lcn`: the cluster of `$MFTMirr` VCN 0.
    pub(super) mft_mirror_lcn: u64,
    /// MFT record size in bytes.
    pub(super) record_size: usize,
    /// Index record size in bytes.
    pub(super) index_record_size: usize,
    /// `volume_serial_number`.
    pub(super) serial_number: u64,
}

impl BootSector {
    /// Read and check the boot sector at the start of `data`.
    ///
    /// Layout: jump (3), OEM ID (8), `bytes_per_sector` (2) at 0x0B,
    /// `sectors_per_cluster` (1) at 0x0D, `reserved_sectors` (2) at 0x0E,
    /// `fats` (1) at 0x10, `root_entries` (2) at 0x11, `sectors` (2) at
    /// 0x13, media type (1), `sectors_per_fat` (2) at 0x16, track, head and
    /// hidden-sector fields, `large_sectors` (4) at 0x20, drive fields (4),
    /// `number_of_sectors` (8) at 0x28, `mft_lcn` (8) at 0x30,
    /// `mftmirr_lcn` (8) at 0x38, `clusters_per_mft_record` (1) at 0x40,
    /// `clusters_per_index_record` (1) at 0x44, `volume_serial_number` (8)
    /// at 0x48, the boot sector checksum (4, not verified: its algorithm is
    /// not documented) at 0x50, boot code, and the end marker (2) at 0x1FE.
    ///
    /// # Errors
    ///
    /// A missing OEM ID or end marker, or a field ntfs-3g rejects.
    pub(super) fn read(data: &[u8]) -> Result<Self> {
        let sector = data.get(..BOOT_SECTOR_SIZE).ok_or_else(|| {
            error(format!(
                "Truncated boot sector: {BOOT_SECTOR_SIZE} B needed, {} B present",
                data.len()
            ))
        })?;
        if &sector[3..11] != OEM_ID {
            return Err(error("Missing NTFS OEM ID at offset 3"));
        }
        if le_u16(sector, 0x1fe)? != END_OF_SECTOR_MARKER {
            return Err(error("Missing boot sector end marker 55 AA at 0x1FE"));
        }
        let bytes_per_sector = u32::from(le_u16(sector, 0x0b)?);
        if !(MIN_SECTOR_SIZE..=MAX_SECTOR_SIZE).contains(&bytes_per_sector)
            || !bytes_per_sector.is_power_of_two()
        {
            return Err(error(format!(
                "Invalid bytes per sector {bytes_per_sector}"
            )));
        }
        let sectors_per_cluster = sectors_per_cluster(sector[0x0d])?;
        let cluster_size = bytes_per_sector * sectors_per_cluster;
        if cluster_size > MAX_CLUSTER_SIZE {
            return Err(error(format!(
                "Invalid cluster size {cluster_size} B: more than {}",
                size_text(MAX_CLUSTER_SIZE as usize)
            )));
        }
        let reserved_fields = [
            le_u16(sector, 0x0e)?,
            u16::from(sector[0x10]),
            le_u16(sector, 0x11)?,
            le_u16(sector, 0x13)?,
            le_u16(sector, 0x16)?,
        ];
        if reserved_fields.iter().any(|&field| field != 0) || le_u32(sector, 0x20)? != 0 {
            return Err(error(
                "Invalid boot sector: the FAT fields of the BIOS parameter block are not zero",
            ));
        }
        let record_size = decode_record_size(sector[0x40], cluster_size, "MFT")?;
        if !(MIN_RECORD_SIZE..=MAX_RECORD_SIZE).contains(&record_size) {
            return Err(error(format!(
                "Unsupported MFT record size {record_size} B"
            )));
        }
        let index_record_size = decode_record_size(sector[0x44], cluster_size, "index")?;
        if index_record_size < MIN_RECORD_SIZE {
            return Err(error(format!(
                "Unsupported index record size {index_record_size} B"
            )));
        }
        let total_sectors = le_i64(sector, 0x28)?;
        if total_sectors <= 0 {
            return Err(error(format!("Invalid number of sectors {total_sectors}")));
        }
        let total_sectors = total_sectors.unsigned_abs();
        // Every byte offset in the volume then fits in 64 bits.
        if total_sectors
            .checked_mul(u64::from(bytes_per_sector))
            .is_none()
        {
            return Err(error(format!(
                "Invalid number of sectors {total_sectors}: the volume size overflows"
            )));
        }
        let cluster_count = total_sectors >> sectors_per_cluster.trailing_zeros();
        let mft_lcn = le_i64(sector, 0x30)?;
        let mft_mirror_lcn = le_i64(sector, 0x38)?;
        // $MFT and $MFTMirr may not overlap the boot sector or each other,
        // and must lie in the volume ([NTFS-3G]).
        let inside = |lcn: i64| lcn > 0 && lcn.unsigned_abs() < cluster_count;
        if !inside(mft_lcn) || !inside(mft_mirror_lcn) || mft_lcn == mft_mirror_lcn {
            return Err(error(format!(
                "Invalid $MFT cluster 0x{mft_lcn:X} or $MFTMirr cluster 0x{mft_mirror_lcn:X} for \
                 a volume of {cluster_count} clusters"
            )));
        }
        Ok(Self {
            bytes_per_sector,
            cluster_size,
            total_sectors,
            cluster_count,
            mft_lcn: mft_lcn.unsigned_abs(),
            mft_mirror_lcn: mft_mirror_lcn.unsigned_abs(),
            record_size,
            index_record_size,
            serial_number: le_u64(sector, 0x48)?,
        })
    }

    /// The volume's size in bytes: `number_of_sectors` times
    /// `bytes_per_sector`, which [`BootSector::read`] checked fits.
    pub(super) fn volume_size(&self) -> u64 {
        self.total_sectors * u64::from(self.bytes_per_sector)
    }
}

/// Decode `sectors_per_cluster`: a power of two up to 128, or 240 to 253
/// for `1 << (256 - value)` sectors.
fn sectors_per_cluster(value: u8) -> Result<u32> {
    if value <= MAX_PLAIN_SECTORS_PER_CLUSTER && value.is_power_of_two() {
        return Ok(u32::from(value));
    }
    if (MIN_SHIFTED_SECTORS_PER_CLUSTER..=MAX_SHIFTED_SECTORS_PER_CLUSTER).contains(&value) {
        return Ok(1 << (256 - u32::from(value)));
    }
    Err(error(format!("Invalid sectors per cluster 0x{value:02X}")))
}

/// Decode a `clusters_per_*_record` field ([LAYOUT]: "When
/// `clusters_per_mft_record` is negative ..."): a power of two of 1 to 64
/// clusters, or -31 to -9 for `1 << -value` bytes.
fn decode_record_size(value: u8, cluster_size: u32, what: &str) -> Result<usize> {
    let signed = i8::from_le_bytes([value]);
    let size = if (MIN_NEGATIVE_RECORD_SHIFT..=MAX_NEGATIVE_RECORD_SHIFT).contains(&signed) {
        1u64 << signed.unsigned_abs()
    } else if signed > 0
        && signed <= MAX_CLUSTERS_PER_RECORD
        && signed.unsigned_abs().is_power_of_two()
    {
        u64::from(signed.unsigned_abs()) * u64::from(cluster_size)
    } else {
        return Err(error(format!(
            "Invalid clusters per {what} record 0x{value:02X}"
        )));
    };
    usize::try_from(size).map_err(|_| error(format!("Unsupported {what} record size {size} B")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_and_record_encodings_follow_ntfs_3g() {
        assert_eq!(sectors_per_cluster(8).unwrap(), 8);
        assert_eq!(sectors_per_cluster(128).unwrap(), 128);
        assert_eq!(sectors_per_cluster(0xf4).unwrap(), 4096);
        assert!(sectors_per_cluster(0).is_err());
        assert!(sectors_per_cluster(3).is_err());
        assert!(sectors_per_cluster(0xfe).is_err());
        assert_eq!(decode_record_size(0xf6, 4096, "MFT").unwrap(), 1024);
        assert_eq!(decode_record_size(0xf4, 4096, "MFT").unwrap(), 4096);
        assert_eq!(decode_record_size(2, 512, "MFT").unwrap(), 1024);
        assert!(decode_record_size(0, 4096, "MFT").is_err());
        assert!(decode_record_size(3, 4096, "MFT").is_err());
        assert!(decode_record_size(0xf8, 4096, "MFT").is_err());
        assert_eq!(decode_record_size(1, 256, "index").unwrap(), 256);
    }
}
